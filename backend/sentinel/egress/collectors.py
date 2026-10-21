"""Per-process network byte collectors.

Every OS exposes per-process traffic counters differently, so each one gets a
small Collector subclass that returns *cumulative* bytes in/out per live PID.
The monitor diffs consecutive samples, so collectors stay dumb and stateless.

  macOS   -> NettopCollector     (implemented; `nettop` ships with macOS, no root needed)
  Windows -> WindowsCollector    (stub: planned via ETW Microsoft-Windows-Kernel-Network
                                  or GetPerTcpConnectionEStats)
  Linux   -> LinuxCollector      (stub: planned via eBPF (bcc/libbpf) or `nethogs -t -v 2`)

To add an OS: subclass Collector, implement available() and sample(), and
register it in get_collector().
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass

from ..platform_utils import IS_LINUX, IS_MAC, IS_WIN, run


@dataclass
class ProcTraffic:
    pid: int
    name: str
    bytes_in: int      # cumulative since the process (or its sockets) started
    bytes_out: int


class Collector:
    name = "none"
    note = ""

    def available(self) -> bool:
        return False

    def sample(self) -> list[ProcTraffic]:
        raise NotImplementedError


# ---------------------------------------------------------------- macOS
class NettopCollector(Collector):
    """`nettop -P -L 1 -x -n -J bytes_in,bytes_out` prints one CSV snapshot:

        time,,bytes_in,bytes_out,
        14:02:11.123456,Google Chrome H.4123,1048576,52311,
    """
    name = "macos-nettop"
    CMD = ["nettop", "-P", "-L", "1", "-x", "-n", "-J", "bytes_in,bytes_out"]

    def available(self) -> bool:
        return bool(shutil.which("nettop"))

    def sample(self) -> list[ProcTraffic]:
        code, out, err = run(self.CMD, timeout=15)
        if code != 0:
            self.note = f"nettop failed: {err.strip()[:200]}"
            return []
        self.note = ""
        return parse_nettop(out)


def parse_nettop(text: str) -> list[ProcTraffic]:
    rows: list[ProcTraffic] = []
    for line in text.splitlines():
        parts = line.rstrip().split(",")
        while parts and parts[-1].strip() == "":
            parts.pop()
        if len(parts) < 4 or parts[0] == "time":
            continue
        # process names may contain commas; the bytes are always the last two fields
        label = ",".join(parts[1:-2]).strip()
        name, _, pid = label.rpartition(".")
        try:
            bi, bo, pid_i = int(parts[-2]), int(parts[-1]), int(pid)
        except ValueError:
            continue
        rows.append(ProcTraffic(pid=pid_i, name=name or label, bytes_in=bi, bytes_out=bo))
    return rows


# ---------------------------------------------------------------- future OSes
class WindowsCollector(Collector):
    name = "windows-etw"
    note = "Per-process byte accounting on Windows is not implemented yet (planned: ETW kernel network provider)."


class LinuxCollector(Collector):
    name = "linux-ebpf"
    note = "Per-process byte accounting on Linux is not implemented yet (planned: eBPF or nethogs)."


def get_collector() -> Collector:
    if IS_MAC:
        return NettopCollector()
    if IS_WIN:
        return WindowsCollector()
    if IS_LINUX:
        return LinuxCollector()
    return Collector()
