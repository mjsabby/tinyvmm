#!/usr/bin/env python3
"""End-to-end virtio-9p save/restore harness for tinyvmm (Rust).

Combines tools/p9_test.py (host-side 9p share staging) with
tools/save_restore_test.py (snapshot save then restore). It proves that an
**open 9p fid survives a snapshot**: the guest mounts the share, opens a fixture
file (FD 3) so the host holds an open 9p fid, fires the magic snapshot CPUID
while the fid is held, and after --restore reads the file back through the same
FD -- which only works if the fid table was captured and the host handle
reopened by ``P9Device::apply_device_state``.

Phases
------
  0. Stage a host dir with ``snapfile.txt`` (a known marker) exposed as 9p
     tag ``host``.
  1. --save: boot ``--pvh-run --virtio-9p-share host=<dir> --save <snap>`` with
     ``tinyvmm.test=p9snapshot``. The guest mounts, opens FD 3, fires the
     trigger. Assert rc=0, the guest ``P9SNAP: pre-trigger sentinel``, the host
     ``[snapshot] trigger fired`` + ``[snapshot] wrote N bytes``, and that the
     snapshot file is >= RAM bytes.
  2. --restore: ``--restore <snap>``. The 9p share root is reconstructed FROM
     THE SNAPSHOT HEADER, so no ``--virtio-9p-share`` is needed. Assert
     ``P9SNAP: POST-RESTORE-CONTINUE rc=0``, that BOTH the reopened-fid read
     (``post-restore read [<marker>]``) and the fresh-open read
     (``post-restore fresh-read [<marker>]``) return the marker, and the
     shutdown sentinel.
  3. sha256(snapshot) unchanged across the restore (restore is read-only wrt the
     file).

Usage
-----
  python tools\\p9_save_restore_test.py
    [--tinyvmm <path>]   default repo/target/release/tinyvmm.exe
    [--vmlinux <path>]   default repo/vmlinux
    [--initrd  <path>]   default repo/initramfs-p9snap.cpio.gz
    [--snap-path <path>] default repo/p9snap_test.tvm
    [--workdir <path>]   default %TEMP%/tinyvmm-p9snap-test
    [--ram-mb <N>]       default 256
    [--save-timeout <N>]    default 60
    [--restore-timeout <N>] default 30
    [--keep]             keep the snapshot + workdir for inspection

Build the initramfs first (it must include the ``tinyvmm.test=p9snapshot``
/init block added to tools/make_initramfs.py, plus /bin/cpuid_trigger):

  python tools/make_initramfs.py --busybox busybox-x86_64 --out initramfs-p9snap.cpio.gz
"""
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "target" / "release" / "tinyvmm.exe"
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_INITRD = REPO / "initramfs-p9snap.cpio.gz"
DEFAULT_SNAP = REPO / "p9snap_test.tvm"

# Must match the bytes the harness writes into snapfile.txt (sans trailing NL).
MARKER = "P9SNAPSHOT_MARKER_OK"

PRE_SENTINEL_RE = re.compile(r"P9SNAP: pre-trigger sentinel")
TRIGGER_FIRED_RE = re.compile(r"\[snapshot\] trigger fired from vp=\d+")
SNAP_WROTE_RE = re.compile(r"\[snapshot\] wrote (\d+) bytes")
POST_CONTINUE_RE = re.compile(r"P9SNAP: POST-RESTORE-CONTINUE rc=0")
POST_READ_RE = re.compile(r"P9SNAP: post-restore read \[" + re.escape(MARKER) + r"\]")
FRESH_READ_RE = re.compile(r"P9SNAP: post-restore fresh-read \[" + re.escape(MARKER) + r"\]")
SHUTDOWN_SENTINEL = "=== tinyvmm shutdown requested ==="


def run_vmm(argv: list[str], timeout_sec: int, tag: str) -> tuple[int, str, float]:
    """Run tinyvmm; return (returncode, combined_stdout_stderr, wall_seconds)."""
    print(f"[{tag}] launching: " + " ".join(argv))
    t_start = time.monotonic()
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
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
                sys.stdout.write(chunk.decode("utf-8", errors="replace"))
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


def stage_share(share_dir: Path) -> None:
    if share_dir.exists():
        shutil.rmtree(share_dir)
    share_dir.mkdir(parents=True)
    # A single-line marker; the guest reads it with `head -c 64` and `$(...)`
    # strips the trailing newline, so the logged value is exactly MARKER.
    (share_dir / "snapfile.txt").write_bytes((MARKER + "\n").encode("ascii"))


def phase1_save(args: argparse.Namespace, share: Path) -> None:
    if args.snap_path.exists():
        args.snap_path.unlink()
    argv = [
        str(args.tinyvmm),
        "--pvh-run",
        "--ram-mb", str(args.ram_mb),
        "--virtio-9p-share", f"host={share}",
        "--watchdog-secs", str(args.save_timeout),
        "--save", str(args.snap_path),
        "--initrd", str(args.initrd),
        str(args.vmlinux),
        "--",
        "console=hvc0", "pci=conf1,nocrs,lastbus=0", "nofb", "nomodeset",
        "tinyvmm.test=p9snapshot",
    ]
    rc, log, wall = run_vmm(argv, args.save_timeout + 10, "save")
    if rc != 0:
        raise SystemExit(f"[save] FAIL: tinyvmm rc={rc}")
    if not PRE_SENTINEL_RE.search(log):
        raise SystemExit("[save] FAIL: 'P9SNAP: pre-trigger sentinel' not in log")
    if not TRIGGER_FIRED_RE.search(log):
        raise SystemExit("[save] FAIL: '[snapshot] trigger fired' not in log")
    m = SNAP_WROTE_RE.search(log)
    if not m:
        raise SystemExit("[save] FAIL: '[snapshot] wrote N bytes' not in log")
    written = int(m.group(1))
    if not args.snap_path.exists():
        raise SystemExit(f"[save] FAIL: snapshot file missing: {args.snap_path}")
    actual = args.snap_path.stat().st_size
    if actual != written:
        raise SystemExit(f"[save] FAIL: file size {actual} != reported {written}")
    if actual < args.ram_mb * 1024 * 1024:
        raise SystemExit(
            f"[save] FAIL: file size {actual} < RAM bytes {args.ram_mb * 1024 * 1024}")
    # The post-trigger lines must NOT appear in the save invocation (the host
    # exits at the cpuid boundary before they run).
    if POST_CONTINUE_RE.search(log):
        raise SystemExit("[save] FAIL: POST-RESTORE-CONTINUE appeared during --save")
    print(f"[save] OK: wrote {actual} bytes in {wall:.2f}s")


def phase2_restore(args: argparse.Namespace) -> None:
    argv = [
        str(args.tinyvmm),
        "--restore", str(args.snap_path),
        "--watchdog-secs", str(args.restore_timeout),
    ]
    rc, log, wall = run_vmm(argv, args.restore_timeout + 10, "restore")
    if rc != 0:
        raise SystemExit(f"[restore] FAIL: rc={rc}")
    if not POST_CONTINUE_RE.search(log):
        raise SystemExit("[restore] FAIL: 'P9SNAP: POST-RESTORE-CONTINUE rc=0' not in log")
    if not POST_READ_RE.search(log):
        raise SystemExit(
            f"[restore] FAIL: reopened-fid read did not return [{MARKER}] "
            "(the open 9p fid was not reopened on restore)")
    if not FRESH_READ_RE.search(log):
        raise SystemExit(
            f"[restore] FAIL: fresh-open read did not return [{MARKER}] "
            "(the 9p share is not usable after restore)")
    if SHUTDOWN_SENTINEL not in log:
        raise SystemExit("[restore] FAIL: shutdown sentinel not in log")
    print(f"[restore] OK in {wall:.2f}s (open fid reopened + fresh open both read the marker)")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--initrd", type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--snap-path", type=Path, default=DEFAULT_SNAP)
    ap.add_argument("--workdir", type=Path, default=None)
    ap.add_argument("--ram-mb", type=int, default=256)
    ap.add_argument("--save-timeout", type=int, default=60)
    ap.add_argument("--restore-timeout", type=int, default=30)
    ap.add_argument("--keep", action="store_true",
                    help="keep the snapshot + workdir after the run")
    args = ap.parse_args()

    for label, p in (("tinyvmm", args.tinyvmm), ("vmlinux", args.vmlinux),
                     ("initrd", args.initrd)):
        if not p.exists():
            raise SystemExit(f"missing {label}: {p}")

    if args.workdir is None:
        args.workdir = Path(tempfile.gettempdir()) / "tinyvmm-p9snap-test"
    args.workdir.mkdir(parents=True, exist_ok=True)
    share = args.workdir / "p9-share"

    print(f"[harness] tinyvmm={args.tinyvmm}")
    print(f"[harness] vmlinux={args.vmlinux}")
    print(f"[harness] initrd ={args.initrd}")
    print(f"[harness] share  ={share}")
    print(f"[harness] snap   ={args.snap_path}  ram={args.ram_mb} MiB")

    # Phase 0 + 1
    stage_share(share)
    print(f"[harness] staged snapfile.txt marker='{MARKER}'")
    phase1_save(args, share)
    pre_hash = sha256_file(args.snap_path)
    print(f"[harness] snap sha256 (pre-restore):  {pre_hash}")

    # Phase 2 -- NOTE: the share dir must still exist (the restore reopens fids
    # from the captured host path), so do NOT delete it before restoring.
    phase2_restore(args)

    # Phase 3
    post_hash = sha256_file(args.snap_path)
    print(f"[harness] snap sha256 (post-restore): {post_hash}")
    if pre_hash != post_hash:
        raise SystemExit("[harness] FAIL: snapshot file mutated by --restore")

    if not args.keep:
        args.snap_path.unlink()
        shutil.rmtree(share, ignore_errors=True)
        print(f"[harness] removed {args.snap_path} and {share}")

    print("[harness] ALL PHASES PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
