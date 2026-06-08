#!/usr/bin/env python3
"""Concurrent virtio-9p throughput benchmark for tinyvmm.

Stages N large files under workdir/p9-share/bench/, launches tinyvmm with
--virtio-9p-share + `tinyvmm.test=9p-bench`, and has the guest read every
file IN PARALLEL (one dd per file). The guest reports raw /proc/uptime
start/end; this driver computes the aggregate MB/s and also captures the
teardown `exits[...]` line.

The point: a serial p9 engine (one request at a time on the doorbell pump
thread) caps aggregate throughput near single-stream regardless of reader
count; a concurrent (worker-pool) engine should scale aggregate up with the
reader count until the host read path saturates. Run this before/after the
engine change to quantify the win.

Usage:
  python tools\\p9_bench.py
    [--tinyvmm <path>]   (default tinyvmm-rs/target/debug/tinyvmm.exe)
    [--vmlinux <path>]   (default repo/vmlinux)
    [--initrd  <path>]   (default repo/initramfs-p9.cpio.gz)
    [--readers N]        (default 8)
    [--file-mib M]       (default 128, per-file size)
    [--ram-mb N]         (default 512)
    [--timeout-sec N]    (default 180)
    [--keep-workdir]
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "tinyvmm-rs" / "target" / "debug" / "tinyvmm.exe"
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_INITRD = REPO / "initramfs-p9.cpio.gz"


def stage_files(bench_dir: Path, readers: int, file_mib: int) -> int:
    """Write `readers` files of `file_mib` MiB each. Returns total bytes."""
    if bench_dir.exists():
        shutil.rmtree(bench_dir)
    bench_dir.mkdir(parents=True)
    # 1 MiB pattern tile; content is irrelevant, only the byte count matters.
    chunk = (b"tinyvmm-9p-bench" * (1024 * 1024 // 16))
    assert len(chunk) == 1024 * 1024
    for i in range(readers):
        with open(bench_dir / f"big{i:03d}.bin", "wb") as f:
            for _ in range(file_mib):
                f.write(chunk)
    return readers * file_mib * 1024 * 1024


def run_vmm(argv: list[str], timeout_sec: int) -> str:
    print("[p9-bench] launching: " + " ".join(argv))
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out: list[bytes] = []
    done = threading.Event()

    def reader():
        try:
            assert proc.stdout is not None
            for line in iter(proc.stdout.readline, b""):
                out.append(line)
                sys.stdout.write(line.decode("utf-8", errors="replace"))
                sys.stdout.flush()
        finally:
            done.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t0 = time.monotonic()
    while proc.poll() is None:
        if time.monotonic() - t0 > timeout_sec:
            print(f"\n[p9-bench] timeout after {timeout_sec}s; killing",
                  file=sys.stderr)
            proc.kill()
            break
        time.sleep(0.5)
    done.wait(timeout=10)
    t.join(timeout=5)
    return b"".join(out).decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--initrd", type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--readers", type=int, default=8)
    ap.add_argument("--file-mib", type=int, default=128)
    ap.add_argument("--ram-mb", type=int, default=512)
    ap.add_argument("--cache", default="none",
                    help="9p guest cache mode (none|loose|fscache|mmap). "
                         "none = no readahead (latency-bound single stream).")
    ap.add_argument("--timeout-sec", type=int, default=180)
    ap.add_argument("--workdir", type=Path, default=None)
    ap.add_argument("--keep-workdir", action="store_true")
    args = ap.parse_args()

    for p, label in [(args.tinyvmm, "tinyvmm.exe"),
                     (args.vmlinux, "vmlinux"), (args.initrd, "initrd")]:
        if not p.exists():
            print(f"[p9-bench] FAIL: {label} not found at {p}", file=sys.stderr)
            return 2

    if args.workdir is None:
        args.workdir = Path(tempfile.gettempdir()) / "tinyvmm-p9-bench"
    args.workdir.mkdir(parents=True, exist_ok=True)
    share = args.workdir / "p9-share"
    bench = share / "bench"

    print(f"[p9-bench] staging {args.readers} x {args.file_mib} MiB under {bench}")
    total_bytes = stage_files(bench, args.readers, args.file_mib)
    print(f"[p9-bench] staged {total_bytes:,} bytes")

    argv = [
        str(args.tinyvmm), "--pvh-run",
        "--ram-mb", str(args.ram_mb),
        "--virtio-9p-share", f"host={share}",
        "--initrd", str(args.initrd),
        str(args.vmlinux), "--",
        "tinyvmm.test=bench-9p", f"p9cache={args.cache}",
        "console=hvc0", "pci=conf1,nocrs,lastbus=0",
    ]
    log = run_vmm(argv, args.timeout_sec)

    m = re.search(r"9P-BENCH readers=(\d+) start=([\d.]+) end=([\d.]+)", log)
    if not m:
        if "9P-BENCH: mount FAILED" in log:
            print("[p9-bench] FAIL: guest could not mount the 9p share",
                  file=sys.stderr)
        else:
            print("[p9-bench] FAIL: no '9P-BENCH readers=' line in guest log",
                  file=sys.stderr)
        if not args.keep_workdir:
            shutil.rmtree(args.workdir, ignore_errors=True)
        return 1

    readers, start, end = int(m.group(1)), float(m.group(2)), float(m.group(3))
    secs = max(end - start, 1e-6)
    mbps = total_bytes / secs / 1e6
    exits = re.search(r"exits\[([^\]]*)\]", log)

    print("\n================ 9P-BENCH RESULT ================")
    print(f"  readers      : {readers}")
    print(f"  per-file     : {args.file_mib} MiB")
    print(f"  total bytes  : {total_bytes:,} ({total_bytes/1024/1024:.0f} MiB)")
    print(f"  wall time    : {secs:.2f} s  (guest /proc/uptime delta)")
    print(f"  AGGREGATE    : {mbps:.0f} MB/s   ({mbps/readers:.0f} MB/s per reader)")
    if exits:
        print(f"  exits        : {exits.group(1)}")
    print("=================================================")

    if not args.keep_workdir:
        shutil.rmtree(args.workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
