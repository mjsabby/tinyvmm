#!/usr/bin/env python3
"""Validate tinyvmm multi-vCPU (SMP) bring-up end-to-end.

tinyvmm runs a software-emulated per-vCPU LAPIC when the host is itself a
VM (nested), because WHP's in-hypervisor APIC virtualization is not
available to a nested partition. This driver proves that path actually
works: the BSP brings up the secondary CPUs via INIT/SIPI, they come
ONLINE (not merely "started"), work is scheduled onto every CPU, and the
software LAPIC routes reschedule IPIs to the secondaries.

It launches tinyvmm with `--emulate-lapic on` (forces the software LAPIC
regardless of whether THIS box is detected as nested, so the test is
deterministic on bare metal and nested alike) for several vCPU counts,
running the `tinyvmm.test=smp` initramfs self-test, and asserts every
phase passes with `SMP SUMMARY: N/N`. It then runs the virtio-blk
self-test under 2 vCPUs to prove device interrupts still reach the guest
correctly with SMP enabled (MSI/LAPIC destination routing).

Usage:
  python tools\\smp_test.py
    [--tinyvmm <path>]   (default target/release/tinyvmm.exe)
    [--vmlinux <path>]   (default repo/vmlinux)
    [--busybox <path>]   (default repo/busybox-x86_64)
    [--initrd  <path>]   (default repo/initramfs-blk.cpio.gz; rebuilt from
                          busybox unless --no-build)
    [--vcpus 2,4]        (comma list of SMP counts to test)
    [--no-build]         (use the existing --initrd as-is)
    [--skip-blk]         (skip the virtio-blk-under-SMP run)
    [--timeout-sec 180]
"""
from __future__ import annotations

import argparse
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
DEFAULT_BUSYBOX = REPO / "busybox-x86_64"
DEFAULT_INITRD = REPO / "initramfs-blk.cpio.gz"
MAKE_INITRAMFS = REPO / "tools" / "make_initramfs.py"

BLK_VDB_BYTES = 256 * 1024 * 1024
BLK_VDC_BYTES = 1 * 1024 * 1024
BLK_MARKER = b"TINYVMM_BLK_TEST_MARKER_v1"


# --------------------------------------------------------------------------
# Sparse / fixed backing files (Windows SetEndOfFile to keep NTFS sparse;
# Python truncate() zero-fills on Windows and defeats the sparse flag).
# --------------------------------------------------------------------------
def _set_eof(path: Path, size_bytes: int) -> None:
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
        raise OSError(ctypes.get_last_error(), f"CreateFileW({path}) failed")
    try:
        if not k32.SetFilePointerEx(h, size_bytes, None, FILE_BEGIN):
            raise OSError(ctypes.get_last_error(), "SetFilePointerEx failed")
        if not k32.SetEndOfFile(h):
            raise OSError(ctypes.get_last_error(), "SetEndOfFile failed")
    finally:
        k32.CloseHandle(h)


def make_sparse(path: Path, size_bytes: int) -> None:
    if path.exists():
        path.unlink()
    with open(path, "wb"):
        pass
    subprocess.run(["fsutil.exe", "sparse", "setflag", str(path)],
                   check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    _set_eof(path, size_bytes)


def make_fixed(path: Path, size_bytes: int, fill: int) -> None:
    if path.exists():
        path.unlink()
    path.write_bytes(bytes([fill & 0xFF]) * size_bytes)


# --------------------------------------------------------------------------
# Subprocess driver: capture combined stdout/stderr, kill at deadline.
# --------------------------------------------------------------------------
def run_vmm(argv: list[str], timeout_sec: int, stop_marker: bytes) -> str:
    print("[smp-test] launching: " + " ".join(argv))
    t_start = time.monotonic()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    out: list[bytes] = []
    done = threading.Event()
    marker_seen = threading.Event()

    def reader():
        try:
            assert proc.stdout is not None
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                out.append(line)
                # Echo raw bytes straight to our stdout buffer: the guest log
                # can contain bytes that decode to U+FFFD, which the Windows
                # console's cp1252 stdout then cannot *encode* back (it raises
                # UnicodeEncodeError and kills this thread). Writing bytes
                # sidesteps the decode/encode round-trip entirely.
                try:
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                except (ValueError, OSError):
                    pass
                if stop_marker in line:
                    marker_seen.set()
        finally:
            done.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    while proc.poll() is None:
        if time.monotonic() - t_start > timeout_sec:
            print(f"\n[smp-test] timeout after {timeout_sec}s; killing tinyvmm",
                  file=sys.stderr)
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            break
        # The guest prints the shutdown sentinel then poweroff -f; if the
        # host hasn't reaped vCPU threads within ~15 s of the summary,
        # stop waiting and kill so the driver doesn't hang.
        if marker_seen.is_set() and time.monotonic() - t_start > 15:
            proc.kill()
            break
        time.sleep(0.5)

    done.wait(timeout=10)
    t.join(timeout=5)
    return b"".join(out).decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Assertions
# --------------------------------------------------------------------------
def assert_summary(log: str, kind: str, want_total: int | None = None) -> None:
    """Gate on `<KIND> SUMMARY: P/T phases passed` with P == T (and T>0)."""
    m = re.search(rf"{kind} SUMMARY:\s+(\d+)/(\d+) phases passed", log)
    if not m:
        for line in re.findall(rf"^.*{kind} \w[\w-]*:\s+FAIL.*$", log, re.M):
            print("[smp-test] >>>", line.strip())
        raise SystemExit(f"[smp-test] FAIL: no '{kind} SUMMARY:' line")
    passed, total = int(m.group(1)), int(m.group(2))
    if total == 0 or passed != total:
        for line in re.findall(rf"^.*{kind} \w[\w-]*:\s+FAIL.*$", log, re.M):
            print("[smp-test] >>>", line.strip())
        raise SystemExit(f"[smp-test] FAIL: {kind} SUMMARY {passed}/{total}")
    if want_total is not None and total < want_total:
        raise SystemExit(
            f"[smp-test] FAIL: {kind} ran {total} phases, want >= {want_total}")
    print(f"[smp-test] {kind} {passed}/{total} phases PASS")


def build_initramfs(busybox: Path, out: Path) -> None:
    argv = [sys.executable, str(MAKE_INITRAMFS),
            "--busybox", str(busybox), "--out", str(out)]
    print("[smp-test] building initramfs: " + " ".join(argv))
    subprocess.run(argv, check=True)


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--busybox", type=Path, default=DEFAULT_BUSYBOX)
    ap.add_argument("--initrd", type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--vcpus", default="2,4")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--skip-blk", action="store_true")
    ap.add_argument("--timeout-sec", type=int, default=180)
    args = ap.parse_args()

    for p, label in [(args.tinyvmm, "tinyvmm.exe"), (args.vmlinux, "vmlinux")]:
        if not p.exists():
            print(f"[smp-test] FAIL: {label} not found at {p}", file=sys.stderr)
            return 2

    if not args.no_build:
        if not args.busybox.exists():
            print(f"[smp-test] FAIL: busybox not found at {args.busybox} "
                  "(pass --busybox or --no-build)", file=sys.stderr)
            return 2
        build_initramfs(args.busybox, args.initrd)
    if not args.initrd.exists():
        print(f"[smp-test] FAIL: initrd not found at {args.initrd}",
              file=sys.stderr)
        return 2

    counts = [int(x) for x in args.vcpus.split(",") if x.strip()]
    sentinel = b"=== tinyvmm shutdown requested ==="

    # --- SMP self-test at each requested vCPU count ----------------------
    for n in counts:
        print(f"\n========== SMP self-test: --vcpus {n} ==========")
        argv = [
            str(args.tinyvmm), "--pvh-run",
            "--emulate-lapic", "on",
            "--vcpus", str(n),
            "--ram-mb", "256",
            "--initrd", str(args.initrd),
            str(args.vmlinux), "--",
            "tinyvmm.test=smp", f"tinyvmm.smp.expect={n}",
            "console=hvc0", "pci=conf1,nocrs,lastbus=0",
        ]
        log = run_vmm(argv, args.timeout_sec, sentinel)
        # 2-vCPU exercises 4 phases (count, expect, all-cpus-busy, ipi);
        # 1 vCPU would only run count+expect, but we only test n>=2 here.
        assert_summary(log, "SMP", want_total=4 if n >= 2 else 2)
        if f"online $NPROC" in log:  # paranoia: shell var leaked unexpanded
            raise SystemExit("[smp-test] FAIL: init script var did not expand")

    # --- virtio-blk under SMP (MSI/LAPIC routing to a 2-vCPU guest) ------
    if not args.skip_blk:
        print("\n========== virtio-blk under --vcpus 2 ==========")
        workdir = Path(tempfile.gettempdir()) / "tinyvmm-smp-test"
        workdir.mkdir(parents=True, exist_ok=True)
        vdb = workdir / "smp-blk-vdb.img"
        vdc = workdir / "smp-blk-vdc.img"
        make_sparse(vdb, BLK_VDB_BYTES)
        make_fixed(vdc, BLK_VDC_BYTES, 0x42)
        try:
            argv = [
                str(args.tinyvmm), "--pvh-run",
                "--emulate-lapic", "on",
                "--vcpus", "2",
                "--ram-mb", "256",
                "--drive", str(vdb),
                "--drive", f"{vdc},readonly",
                "--initrd", str(args.initrd),
                str(args.vmlinux), "--",
                "tinyvmm.test=blk",
                "console=hvc0", "pci=conf1,nocrs,lastbus=0",
            ]
            log = run_vmm(argv, args.timeout_sec, sentinel)
            assert_summary(log, "BLK")
            if BLK_MARKER not in vdb.read_bytes()[:BLK_VDB_BYTES]:
                # Cheap scan: the marker lives inside the ext2 fs Phase E made.
                data = vdb.read_bytes()
                if BLK_MARKER not in data:
                    raise SystemExit("[smp-test] FAIL: blk marker not persisted "
                                     "under SMP")
            print("[smp-test] virtio-blk under SMP: marker persisted")
        finally:
            for p in (vdb, vdc):
                try:
                    p.unlink()
                except OSError:
                    pass
            try:
                workdir.rmdir()
            except OSError:
                pass

    print("\n[smp-test] PASS: multi-vCPU bring-up + IPI routing + "
          "device IRQs all verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
