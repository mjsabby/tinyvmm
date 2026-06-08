#!/usr/bin/env python3
"""Drive the tinyvmm virtio-blk real-workload test end-to-end.

Builds two test disks, launches tinyvmm with the `tinyvmm.test=blk`
initramfs mode, captures the guest log, and asserts:

  1. The guest's six-phase blk-test (A..F) reported all phases pass via
     ``BLK SUMMARY: N/N phases passed``.
  2. tinyvmm's per-disk shutdown summary line reported
     ``max_inflight > 1`` on the writable drive (proves the concurrent-
     writer phase actually reached parallel queue depth from the host
     backend's point of view).
  3. The host backing file for the writable drive contains the
     ``TINYVMM_BLK_TEST_MARKER_v1`` sentinel that Phase E wrote into a
     mounted ext2 fs. Finding the literal bytes in the raw file proves
     the data made it past the guest page cache *and* the host page
     cache to the actual backing file before VM shutdown.

Usage:
  python tools\\blk_test.py
    [--tinyvmm <path>]
    [--vmlinux <path>] (default repo/vmlinux)
    [--initrd  <path>] (default repo/initramfs-blk.cpio.gz)
    [--workdir <path>] (default %TEMP%\\tinyvmm-blk-test)
    [--timeout-sec <N>] (default 180)
    [--keep-workdir]
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "target" / "release" / "tinyvmm.exe"
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_INITRD = REPO / "initramfs-blk.cpio.gz"

VDB_SIZE_BYTES = 256 * 1024 * 1024   # writable target: 256 MiB sparse
VDC_SIZE_BYTES = 1 * 1024 * 1024     # readonly target: 1 MiB fixed-content

MARKER = b"TINYVMM_BLK_TEST_MARKER_v1"


# ---------------------------------------------------------------------------
# Sparse file creation (Windows-specific; same gotcha as ubuntu_iso_boot)
# ---------------------------------------------------------------------------
def _set_eof(path: Path, size_bytes: int) -> None:
    """Move EOF without writing data (so NTFS leaves the extension sparse).

    Python's ``file.truncate`` on Windows calls MSVCRT ``_chsize_s``
    which writes zeros across the extension and defeats the sparse
    flag. Call ``SetEndOfFile`` directly.
    """
    import ctypes
    from ctypes import wintypes

    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_BEGIN = 0
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    k32.SetFilePointerEx.restype = wintypes.BOOL
    k32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE, ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD,
    ]
    k32.SetEndOfFile.restype = wintypes.BOOL
    k32.SetEndOfFile.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    h = k32.CreateFileW(str(path), GENERIC_WRITE, FILE_SHARE_READ, None,
                        OPEN_EXISTING, 0, None)
    if h == INVALID_HANDLE_VALUE or h == 0:
        err = ctypes.get_last_error()
        raise OSError(err, f"CreateFileW({path}) failed", str(path))
    try:
        if not k32.SetFilePointerEx(h, size_bytes, None, FILE_BEGIN):
            err = ctypes.get_last_error()
            raise OSError(err, f"SetFilePointerEx({size_bytes}) failed")
        if not k32.SetEndOfFile(h):
            err = ctypes.get_last_error()
            raise OSError(err, "SetEndOfFile failed")
    finally:
        k32.CloseHandle(h)


def make_sparse(path: Path, size_bytes: int) -> None:
    if path.exists():
        path.unlink()
    with open(path, "wb"):
        pass
    # Set sparse flag BEFORE the extend; otherwise NTFS already
    # committed clusters for the file's range.
    subprocess.run(["fsutil.exe", "sparse", "setflag", str(path)],
                   check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    _set_eof(path, size_bytes)


def make_fixed(path: Path, size_bytes: int, fill: int) -> None:
    if path.exists():
        path.unlink()
    # 1 MiB is small enough to write directly.
    payload = bytes([fill & 0xFF]) * size_bytes
    path.write_bytes(payload)


# ---------------------------------------------------------------------------
# Subprocess driver with combined stdout/stderr capture + 180 s deadline
# ---------------------------------------------------------------------------
def run_vmm(argv: list[str], timeout_sec: int) -> tuple[int, str]:
    """Run tinyvmm and return (returncode, combined_stdout_stderr)."""
    print("[blk-test] launching: " + " ".join(argv))
    t_start = time.monotonic()
    # On Windows we capture stdout/stderr together; tinyvmm prints the
    # blk-test guest log via virtio-console (hvc0) which goes to stdout,
    # and the [pvh-run] / [loop] host log via stderr.
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=0,
    )
    out: list[bytes] = []
    done = threading.Event()
    summary_seen = threading.Event()
    SUMMARY_RE = re.compile(rb"^.*BLK SUMMARY:\s+(\d+)/(\d+) phases", re.M)

    def reader():
        try:
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.readline()
                if not chunk:
                    break
                out.append(chunk)
                sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                sys.stdout.flush()
                blob = b"".join(out[-50:])
                if SUMMARY_RE.search(blob):
                    summary_seen.set()
        finally:
            done.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    # Wait up to timeout_sec for process exit. The guest /init runs
    # `poweroff -f` after printing the BLK SUMMARY line, so a clean
    # run terminates within a few seconds of the summary appearing.
    while proc.poll() is None:
        if time.monotonic() - t_start > timeout_sec:
            print(f"\n[blk-test] timeout after {timeout_sec}s; killing tinyvmm",
                  file=sys.stderr)
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            break
        # Speed up shutdown a bit if guest already announced the summary
        # but the host hasn't reaped vCPU threads yet.
        if summary_seen.is_set() and time.monotonic() - t_start > 30:
            # Give the host another 30 s to drain its shutdown summary.
            pass
        time.sleep(0.5)

    done.wait(timeout=10)
    t.join(timeout=5)
    blob = b"".join(out).decode("utf-8", errors="replace")
    return (proc.returncode or 0), blob


# ---------------------------------------------------------------------------
# Assertions on captured output
# ---------------------------------------------------------------------------
def assert_blk_summary(log: str) -> None:
    m = re.search(r"BLK SUMMARY:\s+(\d+)/(\d+) phases passed", log)
    if not m:
        raise SystemExit("[blk-test] FAIL: no 'BLK SUMMARY:' line in guest log")
    passed, total = int(m.group(1)), int(m.group(2))
    if total == 0 or passed != total:
        # Surface any individual phase failures we can find.
        fails = re.findall(r"^.*BLK \w+:\s+FAIL.*$", log, flags=re.M)
        for f in fails:
            print("[blk-test] >>>", f.strip())
        raise SystemExit(f"[blk-test] FAIL: BLK SUMMARY {passed}/{total}")
    print(f"[blk-test] guest reports {passed}/{total} phases PASS")


def assert_max_inflight(log: str, disk_index: int = 0) -> int:
    """Look for the per-disk shutdown summary printed by --pvh-run.

    Format:
      [pvh-run] virtio-blk[<i>] stats: submitted=A completed=B errors=C
                max_inflight=D (virtio in=... out=... flush=... err=...)
    """
    needle = rf"virtio-blk\[{disk_index}\].*?max_inflight=(\d+)"
    m = re.search(needle, log)
    if not m:
        raise SystemExit(
            f"[blk-test] FAIL: no max_inflight line for disk[{disk_index}]")
    n = int(m.group(1))
    if n <= 1:
        raise SystemExit(
            f"[blk-test] FAIL: max_inflight={n} on disk[{disk_index}] "
            "(want > 1; Phase C should have parallelized 8 writers)")
    print(f"[blk-test] disk[{disk_index}] max_inflight={n} (>1 OK)")
    return n


def assert_marker_in_file(vdb_path: Path) -> None:
    """Scan the raw vdb file for the marker Phase E wrote inside ext2.

    Finding the literal bytes proves Phase E's mkfs+mount+write+sync
    actually flushed to the host backing file, past *both* guest and
    host page caches.
    """
    size = vdb_path.stat().st_size
    print(f"[blk-test] scanning {vdb_path} ({size} bytes) for marker...")
    CHUNK = 4 * 1024 * 1024
    overlap = len(MARKER)
    found = False
    with open(vdb_path, "rb") as f:
        prev_tail = b""
        offset = 0
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            blob = prev_tail + chunk
            idx = blob.find(MARKER)
            if idx != -1:
                print(f"[blk-test] marker found at host file "
                      f"offset 0x{offset + idx - len(prev_tail):x}")
                found = True
                break
            prev_tail = chunk[-overlap:] if len(chunk) >= overlap else chunk
            offset += len(chunk)
    if not found:
        raise SystemExit(
            "[blk-test] FAIL: marker not found in raw vdb image; "
            "Phase E flush/barrier did not persist to host file")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--initrd",  type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--workdir", type=Path, default=None)
    ap.add_argument("--timeout-sec", type=int, default=180)
    ap.add_argument("--keep-workdir", action="store_true")
    args = ap.parse_args()

    for p, label in [(args.tinyvmm, "tinyvmm.exe"),
                     (args.vmlinux, "vmlinux"),
                     (args.initrd,  "initrd")]:
        if not p.exists():
            print(f"[blk-test] FAIL: {label} not found at {p}",
                  file=sys.stderr)
            return 2

    if args.workdir is None:
        args.workdir = Path(tempfile.gettempdir()) / "tinyvmm-blk-test"
    args.workdir.mkdir(parents=True, exist_ok=True)
    vdb = args.workdir / "blk-test-vdb.img"
    vdc = args.workdir / "blk-test-vdc.img"

    print(f"[blk-test] workdir: {args.workdir}")
    print(f"[blk-test] vdb: {vdb} ({VDB_SIZE_BYTES // (1024*1024)} MiB sparse)")
    make_sparse(vdb, VDB_SIZE_BYTES)
    print(f"[blk-test] vdc: {vdc} ({VDC_SIZE_BYTES // 1024} KiB filled 0x42)")
    make_fixed(vdc, VDC_SIZE_BYTES, 0x42)

    argv = [
        str(args.tinyvmm),
        "--pvh-run",
        "--ram-mb", "256",
        "--drive", str(vdb),
        "--drive", f"{vdc},readonly",
        "--initrd", str(args.initrd),
        str(args.vmlinux),
        "--",
        "tinyvmm.test=blk",
        "console=hvc0",
        "pci=conf1,nocrs,lastbus=0",
    ]
    rc, log = run_vmm(argv, args.timeout_sec)

    print(f"\n[blk-test] tinyvmm exited rc={rc}")
    # Even when tinyvmm exits with a non-zero rc (because the guest
    # poweroff path returns a WHvCancelled), we should still see
    # BLK SUMMARY in the log. Don't gate on rc; gate on log content.

    try:
        assert_blk_summary(log)
        assert_max_inflight(log, disk_index=0)
        assert_marker_in_file(vdb)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 1

    print("[blk-test] PASS: guest blk test, max_inflight > 1, "
          "marker found in host file")
    if not args.keep_workdir:
        for p in (vdb, vdc):
            try:
                p.unlink()
            except OSError:
                pass
        try:
            args.workdir.rmdir()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
