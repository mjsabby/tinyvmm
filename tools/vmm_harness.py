"""Shared plumbing for the guest-booting interrupt harnesses (irq_test.py,
irq_bench.py): build the test initramfs, run tinyvmm while stamping every
output line with the host clock (and, at chosen markers, tinyvmm's CPU time),
and query the WHP capabilities the checks compare against."""
from __future__ import annotations

import ctypes
import re
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "target" / "release" / "tinyvmm.exe"
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_BUSYBOX = REPO / "busybox-x86_64"
DEFAULT_INITRD = REPO / "initramfs-blk.cpio.gz"
SENTINEL = "=== tinyvmm shutdown requested ==="
GUEST_CMDLINE = ["console=hvc0", "pci=conf1,nocrs,lastbus=0"]

_K32 = ctypes.WinDLL("kernel32", use_last_error=True)
_K32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
_K32.GetProcessTimes.restype = wintypes.BOOL


def build_initramfs(busybox: Path, out: Path) -> None:
    subprocess.run([sys.executable, str(REPO / "tools" / "make_initramfs.py"),
                    "--busybox", str(busybox), "--out", str(out)], check=True)


def whp_interrupt_clock_hz() -> int | None:
    """WHvCapabilityCodeInterruptClockFrequency: the rate WHP's LAPIC timer
    counts at. None if WHP (or the capability) is unavailable."""
    try:
        whp = ctypes.WinDLL("WinHvPlatform.dll")
    except OSError:
        return None
    whp.WHvGetCapability.restype = ctypes.c_long
    value = ctypes.c_uint64(0)
    written = wintypes.UINT(0)
    hr = whp.WHvGetCapability(0x1005, ctypes.byref(value), 8, ctypes.byref(written))
    return value.value if hr >= 0 and value.value else None


def process_cpu_seconds(proc: subprocess.Popen) -> float:
    """User + kernel CPU time consumed so far by `proc` (all threads)."""
    times = [wintypes.FILETIME() for _ in range(4)]
    if not _K32.GetProcessTimes(wintypes.HANDLE(int(proc._handle)),
                                *(ctypes.byref(t) for t in times)):
        return float("nan")
    secs = [((t.dwHighDateTime << 32) | t.dwLowDateTime) / 1e7 for t in times]
    return secs[2] + secs[3]


@dataclass
class VmRun:
    argv: list[str]
    timed_out: bool = False
    wall: float = 0.0
    # (host seconds since launch, decoded line)
    lines: list[tuple[float, str]] = field(default_factory=list)
    # marker -> tinyvmm CPU seconds when the first line containing it arrived
    cpu_at: dict[str, float] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return "\n".join(line for _, line in self.lines)

    def first(self, needle: str) -> float | None:
        """Host time of the first line containing `needle`."""
        return next((t for t, line in self.lines if needle in line), None)

    def exits(self) -> dict[str, int]:
        """VM-exit totals from tinyvmm's `stopped: ... exits[...]` line."""
        m = re.search(r"stopped: .*exits\[([^\]]*)\]", self.text)
        return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", m.group(1))} if m else {}


def run_vmm(argv: list[str], timeout_sec: float, echo: bool = True,
            cpu_markers: tuple[str, ...] = ()) -> VmRun:
    """Run tinyvmm to completion (or `timeout_sec`), timestamping each line."""
    run = VmRun(argv=argv)
    t0 = time.monotonic()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    sentinel_at: list[float] = []

    def reader() -> None:
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            now = time.monotonic() - t0
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            run.lines.append((now, line))
            for marker in cpu_markers:
                if marker in line and marker not in run.cpu_at:
                    run.cpu_at[marker] = process_cpu_seconds(proc)
            if SENTINEL in line and not sentinel_at:
                sentinel_at.append(now)
            if echo:
                # Raw bytes: a cp1252 console can't re-encode U+FFFD.
                try:
                    sys.stdout.buffer.write(raw)
                    sys.stdout.buffer.flush()
                except (ValueError, OSError):
                    pass

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    while proc.poll() is None:
        now = time.monotonic() - t0
        if now > timeout_sec:
            run.timed_out = True
            print(f"\n[harness] timeout after {timeout_sec:.0f}s; killing tinyvmm",
                  file=sys.stderr)
            proc.kill()
            break
        # The sentinel makes tinyvmm stop the vCPUs; don't wait forever on it.
        if sentinel_at and now - sentinel_at[0] > 15:
            proc.kill()
            break
        time.sleep(0.2)
    proc.wait()
    th.join(timeout=10)
    run.wall = time.monotonic() - t0
    return run
