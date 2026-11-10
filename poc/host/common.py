"""Shared plumbing for the host-side PoCs: run a tinyvmm under a memory cap
with a timeout, measure its peak commit, build small ISO images and
initramfs archives."""
from __future__ import annotations

import ctypes
import gzip
import subprocess
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in
                ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                 "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


k32.CreateJobObjectW.restype = wintypes.HANDLE
k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
k32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(IO_COUNTERS)]
ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]

CREATE_SUSPENDED = 0x4
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000


def commit_bytes(handle) -> tuple[int, int]:
    """(current, peak) committed bytes of a process."""
    pmc = PROCESS_MEMORY_COUNTERS()
    pmc.cb = ctypes.sizeof(pmc)
    if not psapi.GetProcessMemoryInfo(int(handle), ctypes.byref(pmc), pmc.cb):
        return 0, 0
    return pmc.PagefileUsage, pmc.PeakPagefileUsage


def bytes_written(handle) -> int:
    """Bytes a process has written so far, to files and to anything else."""
    io = IO_COUNTERS()
    if not k32.GetProcessIoCounters(int(handle), ctypes.byref(io)):
        return 0
    return io.WriteTransferCount


@dataclass
class Run:
    rc: int | None
    seconds: float
    timed_out: bool
    peak_commit: int
    output: str
    samples: list


def run_capped(argv, *, timeout: float, memory_limit: int | None = None, cwd=None, env=None,
               stdin=None, feed=None, sample_every: float = 0.25, log: Path | None = None) -> Run:
    """Run `argv` to its end or `timeout`, under a per-process commit cap if
    given (a tinyvmm that tries to allocate past it aborts instead of taking
    the machine down with it). `feed(proc)` may drive the process meanwhile.
    Output goes to `log` (or a temp file) and its tail is returned."""
    import tempfile
    logf = open(log, "wb") if log else tempfile.TemporaryFile()
    flags = CREATE_SUSPENDED if memory_limit else 0
    proc = subprocess.Popen([str(x) for x in argv], stdout=logf, stderr=subprocess.STDOUT,
                            stdin=stdin, cwd=cwd, env=env, creationflags=flags)
    job = None
    if memory_limit:
        job = k32.CreateJobObjectW(None, None)
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        info.ProcessMemoryLimit = memory_limit
        if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not k32.AssignProcessToJobObject(job, int(proc._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        ntdll.NtResumeProcess(int(proc._handle))
    t0 = time.monotonic()
    peak, samples, timed_out = 0, [], False
    feeder = None
    if feed:
        import threading
        feeder = threading.Thread(target=feed, args=(proc,), daemon=True)
        feeder.start()
    while proc.poll() is None:
        cur, pk = commit_bytes(proc._handle)
        peak = max(peak, pk)
        samples.append((time.monotonic() - t0, cur))
        if time.monotonic() - t0 > timeout:
            timed_out = True
            proc.kill()
            break
        time.sleep(sample_every)
    proc.wait()
    seconds = time.monotonic() - t0
    _, pk = commit_bytes(proc._handle)
    peak = max(peak, pk)
    if job:
        k32.CloseHandle(job)
    logf.flush()
    logf.seek(0, 2)
    size = logf.tell()
    logf.seek(max(0, size - 6000))
    tail = logf.read().decode("utf-8", "replace")
    logf.close()
    return Run(proc.returncode, seconds, timed_out, peak, tail, samples)


# ---- ISO 9660 (as src/convenience/iso9660.rs's test builder lays it out)
SECTOR = 2048


def _record(iso_name: bytes, rr: str | None, lba: int, size: int, is_dir: bool) -> bytes:
    r = bytearray(33)
    r[2:6] = lba.to_bytes(4, "little")
    r[10:14] = size.to_bytes(4, "little")
    r[25] = 2 if is_dir else 0
    r[32] = len(iso_name)
    r += iso_name
    if len(iso_name) % 2 == 0:
        r.append(0)
    if rr is not None:
        half = len(rr) // 2
        for part, flags in ((rr[:half], 1), (rr[half:], 0)):
            r += b"NM" + bytes([5 + len(part), 1, flags]) + part.encode()
    r[0] = len(r)
    return bytes(r)


def build_iso(tree: dict) -> bytes:
    """`tree` maps names to bytes (a file), a dict (a directory) or
    ("alias", lba_of, size) tuples are not supported: keep it simple."""
    sectors: list[bytes] = [bytes(SECTOR)] * 18

    def alloc(data: bytes) -> int:
        lba = len(sectors)
        for i in range(0, max(len(data), 1), SECTOR):
            sectors.append(data[i:i + SECTOR].ljust(SECTOR, b"\0"))
        return lba

    def directory(nodes: dict) -> int:
        body = _record(b"\x00", None, 0, SECTOR, True) + _record(b"\x01", None, 0, SECTOR, True)
        for name, node in nodes.items():
            if isinstance(node, dict):
                body += _record(name.upper().encode(), name, directory(node), SECTOR, True)
            else:
                iso = (name.upper().replace(".", "_") + ".;1").encode()
                body += _record(iso, name, alloc(node), len(node), False)
        assert len(body) <= SECTOR
        return alloc(body)

    root = directory(tree)
    pvd = bytearray(SECTOR)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[128:130] = SECTOR.to_bytes(2, "little")
    rec = _record(b"\x00", None, root, SECTOR, True)
    pvd[156:156 + len(rec)] = rec
    term = bytearray(SECTOR)
    term[0] = 255
    term[1:6] = b"CD001"
    sectors[16], sectors[17] = bytes(pvd), bytes(term)
    return b"".join(sectors)


def build_initramfs(out: Path, init: bytes, extra_files: dict | None = None) -> Path:
    sys.path.insert(0, str(REPO / "tools"))
    import make_initramfs as m
    cb = m.CpioBuilder()
    for d in [".", "bin", "dev", "proc", "sys", "tmp", "mnt"]:
        cb.add_dir(d, mode=0o755)
    cb.add_chrdev("dev/console", major=5, minor=1, mode=0o600)
    cb.add_chrdev("dev/null", major=1, minor=3, mode=0o666)
    cb.add_chrdev("dev/kmsg", major=1, minor=11, mode=0o644)
    cb.add_chrdev("dev/urandom", major=1, minor=9, mode=0o666)
    cb.add_file("bin/busybox", (REPO / "busybox-x86_64").read_bytes(), mode=0o755)
    cb.add_symlink("bin/sh", "busybox")
    cb.add_file("bin/cpuid_trigger", m.build_cpuid_trigger_binary(), mode=0o755)
    for name, data in (extra_files or {}).items():
        cb.add_file(name, data, mode=0o755)
    cb.add_file("init", init, mode=0o755)
    with gzip.open(out, "wb", compresslevel=6) as f:
        f.write(cb.finalize())
    return out


def takes_sentinel_flag(exe: Path) -> bool:
    out = subprocess.run([str(exe)], capture_output=True, text=True, errors="replace")
    return "--shutdown-sentinel" in out.stdout + out.stderr
