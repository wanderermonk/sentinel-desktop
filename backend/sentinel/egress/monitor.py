"""Egress Watch: per-app upload accounting + behavioural exfiltration detection.

Every tick (~5 s) the monitor:
  1. samples cumulative bytes per PID from the OS collector,
  2. turns them into deltas (handles new PIDs, PID reuse and counter resets),
  3. groups helpers under their parent app bundle (".../Google Chrome.app/..."),
  4. stores 5-minute buckets per app in SQLite (14-day history = the baseline),
  5. runs the rules below on each app's sliding 5-minute upload window.

Rules (all thresholds live in policy["egress"]):
  spike      - upload in the window is far above the app's own 95th percentile
  new        - an app with no history uploads a meaningful amount (after learning)
  ratio      - mostly sending, barely receiving (typical of bulk exfiltration)
  hour       - uploading at an hour of day the app has never been active
  modifiers  - unsigned / ad-hoc signed binaries, programs in Temp/Downloads
Nothing is blocked automatically; alerts offer Block IP / Kill / Trust.
"""
from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque

import psutil

from .. import store
from ..platform_utils import IS_MAC, run
from .collectors import Collector, get_collector

BUCKET = 300                    # seconds per stored bucket
WINDOW = 300                    # sliding window the rules look at
KEEP_DAYS = 14

DEFAULTS = {
    "enabled": True,
    "interval": 5,                      # seconds between samples
    "learning_hours": 24,               # global learning period after first start
    "min_alert_mb": 10,                 # never alert below this much upload in 5 min
    "spike_factor": 5,                  # x the app's own p95 5-minute upload
    "new_app_mb": 5,                    # upload by an app with no history
    "ratio": 4,                         # out/in ratio considered upload-heavy
    "cooldown_min": 30,                 # per-app alert cooldown
    "trusted_factor": 4,                # trusted apps need this much more to alert
}
SUSPICIOUS_DIRS = re.compile(r"(/tmp/|/private/var/folders/|/downloads/|/users/shared/|\\temp\\|\\downloads\\)", re.I)
MB = 1024 * 1024


def settings() -> dict:
    s = dict(DEFAULTS)
    s.update(store.load_policy().get("egress") or {})
    return s


def _db():
    con = store.db()
    con.execute("""CREATE TABLE IF NOT EXISTS egress_buckets (
        app TEXT, bucket INTEGER, bytes_out INTEGER, bytes_in INTEGER, PRIMARY KEY (app, bucket))""")
    con.execute("""CREATE TABLE IF NOT EXISTS egress_apps (
        app TEXT PRIMARY KEY, exe TEXT, first_seen REAL, signature TEXT)""")
    return con


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ---------------------------------------------------------------- process identity
_identity: dict[int, tuple[float, str, str | None]] = {}   # pid -> (create_time, app, exe)


def app_identity(pid: int, name: str) -> tuple[str, str | None, float]:
    """Group helper processes under their outermost .app bundle."""
    try:
        p = psutil.Process(pid)
        ct = p.create_time()
        cached = _identity.get(pid)
        if cached and cached[0] == ct:
            return cached[1], cached[2], ct
        try:
            exe = p.exe()
        except Exception:
            exe = None
    except Exception:
        return name, None, 0.0
    app = name
    if exe and ".app/" in exe:
        app = exe.split(".app/", 1)[0].rsplit("/", 1)[-1]
    _identity[pid] = (ct, app, exe)
    return app, exe, ct


_sig_cache: dict[str, str] = {}


def signature(exe: str | None) -> str:
    """'apple' | 'developer:<Team>' | 'adhoc' | 'unsigned' | 'unknown'."""
    if not exe or not IS_MAC:
        return "unknown"
    target = exe.split(".app/", 1)[0] + ".app" if ".app/" in exe else exe
    if target in _sig_cache:
        return _sig_cache[target]
    _, _, err = run(["codesign", "-dv", "--verbose=2", target], timeout=10)
    if "not signed at all" in err:
        sig = "unsigned"
    elif "Signature=adhoc" in err:
        sig = "adhoc"
    elif "Authority=Software Signing" in err or "Authority=Apple Mac OS Application Signing" in err:
        sig = "apple"
    else:
        m = re.search(r"Authority=Developer ID Application: (.+)", err) or re.search(r"Authority=Apple Development: (.+)", err)
        sig = f"developer:{m.group(1).strip()}" if m else "unknown"
    _sig_cache[target] = sig
    return sig


def destinations(pids: set[int], limit: int = 5) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for pid in pids:
        try:
            conns = psutil.Process(pid).net_connections(kind="inet")
        except Exception:
            continue
        for c in conns:
            if not c.raddr:
                continue
            k = (c.raddr.ip, c.raddr.port)
            if k[0].startswith("127.") or k[0] in ("::1",):
                continue
            seen.setdefault(k, {"ip": k[0], "port": k[1], "pid": pid})
    return list(seen.values())[:limit]


# ---------------------------------------------------------------- monitor
class EgressMonitor:
    def __init__(self, collector: Collector | None = None, clock=time.time, identify=None):
        self.collector = collector or get_collector()
        self.clock = clock
        self.identify = identify or app_identity
        self.interval = DEFAULTS["interval"]
        self.sig: dict[str, str] = {}
        self.resumed = False             # set by the UI on wake so the next sample is treated as a gap
        self.lock = threading.Lock()
        self.prev: dict[int, tuple[float, int, int]] = {}            # pid -> (create_time, in, out)
        self.window: dict[str, deque] = defaultdict(deque)            # app -> deque[(ts, out, in)]
        self.pids: dict[str, set[int]] = defaultdict(set)             # app -> live pids
        self.exe: dict[str, str | None] = {}
        self.pending: dict[tuple[str, int], list[int]] = defaultdict(lambda: [0, 0])  # (app,bucket)->[out,in]
        self.last_alert: dict[str, tuple[float, int]] = {}
        self.baseline_cache: dict[str, tuple[float, dict]] = {}
        self.last_sample = 0.0
        self.last_flush = 0.0
        self.started = self._start_time()
        self.ticks = 0

    def _start_time(self) -> float:
        t = store.meta_get("egress_start")
        if t is None:
            t = str(self.clock())
            store.meta_set("egress_start", t)
        return float(t)

    # ---- sampling
    def tick(self) -> list[dict]:
        now = self.clock()
        cfg = settings()
        self.interval = cfg["interval"]
        if not cfg["enabled"]:
            return []
        rows = self.collector.sample() if self.collector.available() else []
        live: dict[str, set[int]] = defaultdict(set)
        seen_pids = set()
        # After sleep (or any long pause) the first deltas cover the whole gap. Record them in the
        # history buckets, but keep them out of the 5-minute window so a wake-up isn't a fake "spike".
        gap = bool(self.last_sample) and (now - self.last_sample > max(60, 6 * self.interval) or self.resumed)
        if gap:
            with self.lock:
                self.window.clear()
            store.log_event("egress", "low", "Egress Watch resumed",
                            f"Monitoring resumed after a {int(now - self.last_sample)} s pause (sleep or restart).")
            self.resumed = False
        for r in rows:
            app, exe, ct = self.identify(r.pid, r.name)
            seen_pids.add(r.pid)
            live[app].add(r.pid)
            self.exe.setdefault(app, exe)
            prev = self.prev.get(r.pid)
            if prev and prev[0] == ct and r.bytes_out >= prev[2] and r.bytes_in >= prev[1]:
                d_in, d_out = r.bytes_in - prev[1], r.bytes_out - prev[2]          # same process, normal delta
            elif prev and prev[0] != ct:
                d_in, d_out = r.bytes_in, r.bytes_out                            # PID was reused by a new process
            elif prev is None and self.last_sample and ct and ct >= self.last_sample - 2 * self.interval:
                d_in, d_out = r.bytes_in, r.bytes_out                            # process started since last sample
            else:
                d_in = d_out = 0   # first sight of an old process (or counter reset): prime, don't count history
            self.prev[r.pid] = (ct, r.bytes_in, r.bytes_out)
            if d_in or d_out:
                if not gap:
                    self.window[app].append((now, d_out, d_in))
                b = self.pending[(app, int(now // BUCKET))]
                b[0] += d_out; b[1] += d_in
        for pid in list(self.prev):
            if pid not in seen_pids:
                del self.prev[pid]
        with self.lock:
            self.pids = live
            for a in list(self.window):
                dq = self.window[a]
                while dq and dq[0][0] < now - WINDOW:
                    dq.popleft()
                if not dq:
                    del self.window[a]
        self.last_sample = now
        self.ticks += 1
        if now - self.last_flush >= 60:
            self.flush()
        return self.evaluate(now)

    def flush(self):
        if not self.pending:
            self.last_flush = self.clock()
            return
        con = _db()
        for (app, bucket), (o, i) in self.pending.items():
            con.execute("""INSERT INTO egress_buckets VALUES (?,?,?,?)
                ON CONFLICT(app,bucket) DO UPDATE SET bytes_out=bytes_out+excluded.bytes_out, bytes_in=bytes_in+excluded.bytes_in""",
                        (app, bucket, o, i))
            con.execute("INSERT OR IGNORE INTO egress_apps VALUES (?,?,?,?)", (app, self.exe.get(app), self.clock(), None))
        con.execute("DELETE FROM egress_buckets WHERE bucket < ?", (int((self.clock() - KEEP_DAYS * 86400) // BUCKET),))
        con.commit(); con.close()
        self.pending.clear()
        self.last_flush = self.clock()

    # ---- baseline
    def baseline(self, app: str) -> dict:
        now = self.clock()
        hit = self.baseline_cache.get(app)
        if hit and now - hit[0] < 600:
            return hit[1]
        con = _db()
        cur_bucket = int(now // BUCKET)
        rows = con.execute("SELECT bucket, bytes_out FROM egress_buckets WHERE app=? AND bucket < ? AND bytes_out > 0",
                           (app, cur_bucket - 1)).fetchall()
        con.close()
        outs = sorted(r[1] for r in rows)
        p95 = outs[min(len(outs) - 1, int(len(outs) * 0.95))] if outs else 0
        hours = {time.localtime(r[0] * BUCKET).tm_hour for r in rows}
        b = {"buckets": len(outs), "p95": p95, "hours": hours, "max": outs[-1] if outs else 0}
        self.baseline_cache[app] = (now, b)
        return b

    # ---- rules
    def evaluate(self, now: float) -> list[dict]:
        cfg = settings()
        learning = now < self.started + cfg["learning_hours"] * 3600
        trusted = {a.lower() for a in store.load_policy().get("trusted_apps", [])}
        alerts = []
        for app, dq in list(self.window.items()):
            w_out = sum(x[1] for x in dq); w_in = sum(x[2] for x in dq)
            floor = cfg["min_alert_mb"] * MB
            if w_out < min(floor, cfg["new_app_mb"] * MB):
                continue
            base = self.baseline(app)
            exe = self.exe.get(app)
            reasons, score = [], 0.0
            known = base["buckets"] >= 12
            factor = cfg["trusted_factor"] if app.lower() in trusted else 1

            if known:
                thr = max(floor, cfg["spike_factor"] * base["p95"]) * factor
                if w_out >= thr:
                    mult = w_out / max(base["p95"], 1)
                    reasons.append(f"uploaded {fmt_bytes(w_out)} in 5 min - {mult:.0f}x its usual peak ({fmt_bytes(base['p95'])})")
                    score = 75 if mult >= 20 or w_out >= 100 * MB else 55
            elif not learning and w_out >= cfg["new_app_mb"] * MB * factor:
                reasons.append(f"app with no upload history sent {fmt_bytes(w_out)} in 5 min")
                score = 50
            if not reasons:
                continue

            if w_out >= 20 * MB and w_out > cfg["ratio"] * max(w_in, 1):
                reasons.append(f"upload-heavy: sent {fmt_bytes(w_out)} vs received {fmt_bytes(w_in)}")
                score += 10
            if known and time.localtime(now).tm_hour not in base["hours"]:
                reasons.append(f"active at {time.localtime(now).tm_hour:02d}:00, an hour this app has never uploaded before")
                score += 10
            sig = signature(exe)
            self.sig[app] = sig
            if sig in ("unsigned", "adhoc"):
                reasons.append(f"binary is {sig} (no verified developer)")
                score += 15
            if exe and SUSPICIOUS_DIRS.search(exe):
                reasons.append(f"runs from a temporary/download folder ({exe})")
                score += 15

            last = self.last_alert.get(app)
            if last and now - last[0] < cfg["cooldown_min"] * 60 and w_out < 2 * last[1]:
                continue
            self.last_alert[app] = (now, w_out)
            sev = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 45 else "low"
            with self.lock:
                pids = set(self.pids.get(app, ()))
            dests = destinations(pids)
            alert = {
                "ts": now, "kind": "egress", "verdict": "exfil", "severity": sev, "score": min(100, round(score)),
                "app": app, "exe": exe, "signature": sig, "pids": sorted(pids),
                "bytes_out": w_out, "bytes_in": w_in, "destinations": dests,
                "title": f"{app} sent {fmt_bytes(w_out)} out in 5 min",
                "detail": "; ".join(reasons) + ".",
                "reasons": reasons,
            }
            store.log_event("egress", sev, alert["title"], alert["detail"])
            alerts.append(alert)
        return alerts

    # ---- views
    def snapshot(self) -> dict:
        now = self.clock()
        self.flush()
        con = _db()
        cur = int(now // BUCKET)
        h1 = dict(con.execute("SELECT app, SUM(bytes_out) FROM egress_buckets WHERE bucket >= ? GROUP BY app", (cur - 11,)).fetchall())
        d1 = con.execute("SELECT app, SUM(bytes_out), SUM(bytes_in) FROM egress_buckets WHERE bucket >= ? GROUP BY app", (cur - 287,)).fetchall()
        timeline = con.execute("SELECT bucket, SUM(bytes_out), SUM(bytes_in) FROM egress_buckets WHERE bucket >= ? GROUP BY bucket ORDER BY bucket",
                               (cur - 287,)).fetchall()
        con.close()
        with self.lock:
            win = {a: (sum(x[1] for x in dq), sum(x[2] for x in dq)) for a, dq in self.window.items()}
        apps = {a for a, *_ in d1} | set(win)
        out = []
        for a in apps:
            b = self.baseline(a)
            day = next((r for r in d1 if r[0] == a), (a, 0, 0))
            out.append({"app": a, "exe": self.exe.get(a), "out_5m": win.get(a, (0, 0))[0], "in_5m": win.get(a, (0, 0))[1],
                        "out_1h": h1.get(a, 0) or 0, "out_24h": day[1] or 0, "in_24h": day[2] or 0,
                        "p95_5m": b["p95"], "history_buckets": b["buckets"], "signature": self.sig.get(a)})
        out.sort(key=lambda x: (-x["out_5m"], -x["out_24h"]))
        cfg = settings()
        return {
            "collector": {"name": self.collector.name, "available": self.collector.available(), "note": self.collector.note},
            "learning": now < self.started + cfg["learning_hours"] * 3600,
            "learning_until": self.started + cfg["learning_hours"] * 3600,
            "interval": cfg["interval"], "ticks": self.ticks,
            "apps": out[:100],
            "timeline": [{"ts": b * BUCKET, "out": o or 0, "in": i or 0} for b, o, i in timeline],
            "settings": cfg,
        }
