"""Egress Watch tests with a fake collector and fake clock (no real network needed).
Run: python backend/tests/test_egress.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["SENTINEL_DATA"] = tempfile.mkdtemp()

from sentinel import store  # noqa: E402
from sentinel.egress import monitor as M  # noqa: E402
from sentinel.egress.collectors import Collector, ProcTraffic, parse_nettop  # noqa: E402

MB = 1024 * 1024
NETTOP = """time,,bytes_in,bytes_out,
14:02:11.123456,Google Chrome H.4123,1048576,52311,
14:02:11.123456,weird,name.77,10,20,
14:02:11.123456,launchd.1,0,0,
garbage line
"""


def test_parse_nettop():
    rows = parse_nettop(NETTOP)
    assert [(r.name, r.pid, r.bytes_in, r.bytes_out) for r in rows] == [
        ("Google Chrome H", 4123, 1048576, 52311), ("weird,name", 77, 10, 20), ("launchd", 1, 0, 0)]


class Fake(Collector):
    name = "fake"
    def __init__(self): self.rows = {}
    def available(self): return True
    def sample(self): return [ProcTraffic(pid, n, i, o) for pid, (n, i, o) in self.rows.items()]


class Clock:
    def __init__(self, t): self.t = t
    def __call__(self): return self.t


def make(start_offset_h=48):
    clk = Clock(1_800_000_000.0)
    store.meta_set("egress_start", str(clk.t - start_offset_h * 3600))
    col = Fake()
    created = {}
    ident = lambda pid, name: (name, f"/Applications/{name}.app/Contents/MacOS/{name}", created.setdefault(pid, clk.t - 10_000))
    mon = M.EgressMonitor(collector=col, clock=clk, identify=ident)
    M.signature = lambda exe: "developer:Test"
    return mon, col, clk, created


def run_history(mon, col, clk, app, pid, per_bucket, buckets):
    """Feed `buckets` x 5-min periods of steady traffic to build a baseline."""
    total_out = 0
    for _ in range(buckets):
        for _ in range(60):                       # 60 ticks of 5 s = 5 min
            total_out += per_bucket // 60
            col.rows[pid] = (app, total_out // 4, total_out)
            mon.tick(); clk.t += 5
    mon.flush()
    return total_out


def test_first_sample_primes_counters():
    mon, col, clk, _ = make()
    col.rows[1] = ("Old", 5 * 1024 * MB, 50 * 1024 * MB)       # lifetime counters, already huge
    assert mon.tick() == []
    clk.t += 5
    assert mon.tick() == [] and not mon.window.get("Old")


def test_spike_over_baseline_alerts_and_cooldown():
    mon, col, clk, _ = make()
    total = run_history(mon, col, clk, "Notes", 10, 200 * 1024, 30)   # ~200 KB per 5 min, normal
    mon.baseline_cache.clear()
    total += 300 * MB                                                # sudden 300 MB upload
    col.rows[10] = ("Notes", total // 40, total)
    alerts = mon.tick()
    assert len(alerts) == 1 and alerts[0]["app"] == "Notes", alerts
    a = alerts[0]
    assert a["severity"] in ("high", "critical") and a["bytes_out"] >= 300 * MB
    assert any("usual peak" in r for r in a["reasons"]) and any("upload-heavy" in r for r in a["reasons"])
    clk.t += 5
    assert mon.tick() == []                                          # cooldown suppresses repeats


def test_normal_heavy_uploader_not_flagged():
    mon, col, clk, _ = make()
    run_history(mon, col, clk, "Dropbox", 20, 40 * MB, 30)           # always uploads ~40 MB / 5 min
    mon.baseline_cache.clear()
    found = []
    total = col.rows[20][2]
    for _ in range(60):
        total += (45 * MB) // 60
        col.rows[20] = ("Dropbox", total // 4, total)
        found += mon.tick(); clk.t += 5
    assert found == [], found


def test_new_app_after_learning_vs_during_learning():
    mon, col, clk, created = make(start_offset_h=48)
    mon.tick(); clk.t += 5                                           # prime
    created[99] = clk.t                                              # process starts now
    col.rows[99] = ("curl", 0, 8 * MB)
    alerts = mon.tick()
    assert alerts and alerts[0]["app"] == "curl" and "no upload history" in alerts[0]["detail"]

    mon2, col2, clk2, created2 = make(start_offset_h=1)              # still learning
    mon2.tick(); clk2.t += 5
    created2[98] = clk2.t
    col2.rows[98] = ("curl2", 0, 8 * MB)
    assert mon2.tick() == []


def test_trusted_app_needs_more():
    mon, col, clk, created = make()
    store.save_policy({"trusted_apps": ["rsync"]})
    mon.tick(); clk.t += 5
    created[77] = clk.t
    col.rows[77] = ("rsync", 0, 8 * MB)
    assert mon.tick() == []
    store.save_policy({"trusted_apps": []})


def test_sleep_gap_is_not_a_spike():
    mon, col, clk, _ = make()
    total = run_history(mon, col, clk, "Mail", 30, 100 * 1024, 20)
    mon.baseline_cache.clear()
    clk.t += 8 * 3600                                                # Mac slept 8 h (Power Nap synced 200 MB)
    total += 200 * MB
    col.rows[30] = ("Mail", total // 4, total)
    assert mon.tick() == [] and not mon.window.get("Mail")
    mon.flush()
    con = M._db(); got = con.execute("SELECT SUM(bytes_out) FROM egress_buckets WHERE app='Mail'").fetchone()[0]; con.close()
    assert got >= 200 * MB                                           # still counted in history
    clk.t += 5; total += 300 * MB                                    # but a real spike right after wake alerts
    col.rows[30] = ("Mail", col.rows[30][1] + MB, total)
    assert mon.tick(), "spike after wake should alert"


def test_snapshot_shape():
    mon, col, clk, _ = make()
    run_history(mon, col, clk, "Slack", 5, MB, 3)
    snap = mon.snapshot()
    assert snap["collector"]["available"] and snap["apps"][0]["app"] == "Slack"
    assert snap["apps"][0]["out_24h"] > 0 and snap["timeline"]


if __name__ == "__main__":
    for k, v in list(globals().items()):
        if k.startswith("test_"):
            v(); print("ok", k)
