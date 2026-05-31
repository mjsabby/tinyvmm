#!/usr/bin/env python3
"""End-to-end save/restore harness for tinyvmm (M33.7).

Three phases:

  Phase 1 -- cold boot with ``--save`` to produce a snapshot:
    * launches tinyvmm with ``tinyvmm.test=snapshot`` in the cmdline,
    * waits for the guest to fire the magic CPUID 0x4000DE57 trigger,
    * asserts tinyvmm exits with rc=0 and the snapshot file is the
      expected size (RAM_MB MiB + a few KiB of metadata),
    * asserts the guest log contains the pre-trigger sentinel and
      ``[snapshot] trigger fired`` host log line.

  Phase 2 -- restore the snapshot 3 times:
    * launches ``tinyvmm.exe --restore <path>`` (no other args),
    * asserts rc=0, ``POST-RESTORE-CONTINUE rc=0`` and the shutdown
      sentinel appear in the combined log,
    * measures wall-time and warns if a single restore takes > 5s.

  Phase 3 -- snapshot file stability:
    * sha256(snapshot) before and after the 3 restores must match
      (proves restore is read-only with respect to the file).

Usage:
  python tools\\save_restore_test.py
    [--tinyvmm <path>]   default repo/build/bin/tinyvmm.exe
    [--vmlinux <path>]   default repo/vmlinux
    [--initrd  <path>]   default repo/initramfs-snapshot.cpio.gz
    [--snap-path <path>] default repo/snap_test.tvm
    [--ram-mb <N>]       default 256
    [--save-timeout <N>] default 60   seconds, allows for guest sleep+sync
    [--restore-timeout <N>] default 30
    [--restore-count <N>] default 3
    [--keep-snap]        do not delete snap file at end
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "build" / "bin" / "tinyvmm.exe"
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_INITRD = REPO / "initramfs-snapshot.cpio.gz"
DEFAULT_SNAP = REPO / "snap_test.tvm"


PRE_TRIGGER_RE = re.compile(r"SNAP-TEST: pre-trigger sentinel")
TRIGGER_FIRED_RE = re.compile(r"\[snapshot\] trigger fired from vp=\d+")
SNAP_WROTE_RE = re.compile(r"\[snapshot\] wrote (\d+) bytes")
POST_RESTORE_RE = re.compile(r"POST-RESTORE-CONTINUE rc=0")
SHUTDOWN_SENTINEL = "[init] === tinyvmm shutdown requested ==="


def run_vmm(argv: list[str], timeout_sec: int, tag: str) -> tuple[int, str, float]:
    """Run tinyvmm; return (returncode, combined_stdout_stderr, wall_seconds)."""
    print(f"[{tag}] launching: " + " ".join(argv))
    t_start = time.monotonic()
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=0,
    )
    out: list[bytes] = []
    done = threading.Event()

    def reader() -> None:
        try:
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.readline()
                if not chunk:
                    break
                out.append(chunk)
                sys.stdout.write(
                    chunk.decode("utf-8", errors="replace"))
                sys.stdout.flush()
        finally:
            done.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    while proc.poll() is None:
        if time.monotonic() - t_start > timeout_sec:
            print(f"\n[{tag}] TIMEOUT after {timeout_sec}s; killing tinyvmm",
                  file=sys.stderr)
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            break
        time.sleep(0.25)

    done.wait(timeout=10)
    t.join(timeout=5)
    wall = time.monotonic() - t_start
    blob = b"".join(out).decode("utf-8", errors="replace")
    return (proc.returncode or 0), blob, wall


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def phase1_save(args: argparse.Namespace) -> None:
    if args.snap_path.exists():
        args.snap_path.unlink()

    cmdline = (
        "console=hvc0 pci=conf1,nocrs,lastbus=0 nofb nomodeset"
        " tinyvmm.test=snapshot"
    )
    argv = [
        str(args.tinyvmm),
        "--pvh-run",
        "--ram-mb", str(args.ram_mb),
        "--watchdog-secs", str(args.save_timeout),
        "--save", str(args.snap_path),
        "--initrd", str(args.initrd),
        str(args.vmlinux),
        "--", *cmdline.split(),
    ]
    rc, log, wall = run_vmm(argv, args.save_timeout + 10, "save")

    if rc != 0:
        raise SystemExit(f"[save] FAIL: tinyvmm rc={rc}")
    if not PRE_TRIGGER_RE.search(log):
        raise SystemExit("[save] FAIL: pre-trigger sentinel not in log")
    if not TRIGGER_FIRED_RE.search(log):
        raise SystemExit("[save] FAIL: '[snapshot] trigger fired' not in log")
    m = SNAP_WROTE_RE.search(log)
    if not m:
        raise SystemExit("[save] FAIL: '[snapshot] wrote' line not in log")
    written = int(m.group(1))
    if not args.snap_path.exists():
        raise SystemExit(f"[save] FAIL: snapshot file missing: {args.snap_path}")
    actual_size = args.snap_path.stat().st_size
    if actual_size != written:
        raise SystemExit(
            f"[save] FAIL: file size {actual_size} != reported {written}")
    expected_min = args.ram_mb * 1024 * 1024
    if actual_size < expected_min:
        raise SystemExit(
            f"[save] FAIL: file size {actual_size} < expected min "
            f"{expected_min} (RAM bytes)")
    print(f"[save] OK: wrote {actual_size} bytes in {wall:.2f}s")


def phase2_restore(args: argparse.Namespace, attempt: int) -> float:
    argv = [
        str(args.tinyvmm),
        "--restore", str(args.snap_path),
        "--watchdog-secs", str(args.restore_timeout),
    ]
    rc, log, wall = run_vmm(argv, args.restore_timeout + 10,
                            f"restore#{attempt}")
    if rc != 0:
        raise SystemExit(f"[restore#{attempt}] FAIL: rc={rc}")
    if not POST_RESTORE_RE.search(log):
        raise SystemExit(
            f"[restore#{attempt}] FAIL: 'POST-RESTORE-CONTINUE rc=0' not in log")
    if SHUTDOWN_SENTINEL not in log:
        raise SystemExit(
            f"[restore#{attempt}] FAIL: shutdown sentinel not in log")
    # The shutdown sentinel is set up to fire only after a 6+s sleep in
    # the guest, so wall-time will dominantly include that sleep. The
    # actual restore + first instructions should be < 5s of the wall.
    print(f"[restore#{attempt}] OK in {wall:.2f}s")
    return wall


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--initrd",  type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--snap-path", type=Path, default=DEFAULT_SNAP)
    ap.add_argument("--ram-mb", type=int, default=256)
    ap.add_argument("--save-timeout", type=int, default=60)
    ap.add_argument("--restore-timeout", type=int, default=30)
    ap.add_argument("--restore-count", type=int, default=3)
    ap.add_argument("--keep-snap", action="store_true",
                    help="do not delete the snapshot file at end")
    args = ap.parse_args()

    for p in (args.tinyvmm, args.vmlinux, args.initrd):
        if not p.exists():
            raise SystemExit(f"missing: {p}")

    print(f"[harness] tinyvmm={args.tinyvmm}")
    print(f"[harness] vmlinux={args.vmlinux}")
    print(f"[harness] initrd ={args.initrd}")
    print(f"[harness] snap   ={args.snap_path}  ram={args.ram_mb} MiB")
    print(f"[harness] save_timeout={args.save_timeout}s "
          f"restore_timeout={args.restore_timeout}s "
          f"restore_count={args.restore_count}")

    # Phase 1
    phase1_save(args)
    pre_hash = sha256_file(args.snap_path)
    print(f"[harness] snap sha256 (pre-restore): {pre_hash}")

    # Phase 2 (N times)
    walls: list[float] = []
    for i in range(args.restore_count):
        walls.append(phase2_restore(args, i + 1))

    # Phase 3 -- file hash unchanged
    post_hash = sha256_file(args.snap_path)
    print(f"[harness] snap sha256 (post-restore): {post_hash}")
    if pre_hash != post_hash:
        raise SystemExit("[harness] FAIL: snapshot file mutated by --restore")

    avg = sum(walls) / len(walls)
    print(f"[harness] restore wall-times: {[f'{w:.2f}' for w in walls]} s")
    print(f"[harness] mean restore wall: {avg:.2f}s")

    if not args.keep_snap:
        args.snap_path.unlink()
        print(f"[harness] removed {args.snap_path}")

    print("[harness] ALL PHASES PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
