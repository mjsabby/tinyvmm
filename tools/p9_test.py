#!/usr/bin/env python3
"""Drive the tinyvmm virtio-9p end-to-end test harness.

Stages a deterministic file tree under workdir/p9-share/, writes a
sha256sum manifest, launches tinyvmm with --virtio-9p-share, captures
the guest log, and asserts:

  1. The guest's 9p harness reported all phases pass via
     ``9P SUMMARY: N/N phases passed``. The /init block in
     tools/make_initramfs.py exercises 15 phases covering mount,
     bulk sha256 verification, per-feature reads (empty, 1 MiB
     stream, 100-entry readdir, nested-dir walk), and per-feature
     mutations (write+sha-roundtrip, create+delete, mkdir+rmdir,
     rename, truncate, append, clean umount).

  2. Every fixture file on the host still hashes to its manifest
     value AFTER the run -- proves the guest did not mutate any
     read-only fixture file.

  3. ``guest_wrote.txt`` exists on the host with the exact bytes
     the guest wrote (``guest-wrote\\n``) -- proves the guest write
     flushed through tinyvmm's WriteFile() path and is visible on
     the host file system.

  4. No debris files remain under p9-share/ except the manifest +
     fixture + guest_wrote.txt -- proves every create/delete /
     mkdir/rmdir / rename phase cleaned up after itself.

Usage:
  python tools\\p9_test.py
    [--tinyvmm <path>]     (default repo/target/release/tinyvmm.exe)
    [--vmlinux <path>]     (default repo/vmlinux)
    [--initrd  <path>]     (default repo/initramfs-p9.cpio.gz)
    [--workdir <path>]     (default %TEMP%/tinyvmm-p9-test)
    [--timeout-sec <N>]    (default 180)
    [--keep-workdir]       (keep workdir after run for inspection)

Build initramfs (one-time, or whenever make_initramfs.py changes):

  python tools/make_initramfs.py \\
      --busybox busybox-x86_64 --out initramfs-p9.cpio.gz
"""
from __future__ import annotations

import argparse
import hashlib
import os
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
DEFAULT_INITRD = REPO / "initramfs-p9.cpio.gz"

# ---------------------------------------------------------------------------
# Deterministic fixture spec
# ---------------------------------------------------------------------------
#
# The /init block (tools/make_initramfs.py, tinyvmm.test=9p) expects
# EXACTLY 105 manifest lines covering this exact layout. Adjust
# EXPECTED_MANIFEST_LINES in BOTH places if you change the spec.
EXPECTED_MANIFEST_LINES = 105

# Pre-known guest-side write content. The /init block writes this
# exact byte sequence to guest_wrote.txt and hash-checks it on the
# guest before umount; the host harness re-asserts the content here.
GUEST_WROTE_BYTES = b"guest-wrote\n"

# Debris files that the guest creates and removes during phases
# 10..14. After a clean run, none of these should exist on the host.
GUEST_DEBRIS = [
    "guest_tmp.txt",      # phase 10 (create-delete)
    "new_dir",            # phase 11 (mkdir-rmdir)
    "rename_a.txt",       # phase 12 (rename-roundtrip source)
    "rename_b.txt",       # phase 12 (rename-roundtrip target)
    "trunc.txt",          # phase 13 (truncate)
    "append.txt",         # phase 14 (append)
]


def make_large_pattern(n_bytes: int) -> bytes:
    """Deterministic 1 MiB stream: tile a 16-byte token until full.

    The exact content doesn't matter for correctness -- only that
    the guest sees the same byte stream we wrote and the sha256 is
    reproducible. Using a fixed pattern (rather than os.urandom) keeps
    rerun output identical and lets debug dumps be hand-eyeballed.
    """
    token = b"tinyvmm-9p-large"      # 16 bytes
    full, rem = divmod(n_bytes, len(token))
    return token * full + token[:rem]


def stage_fixture(share_dir: Path) -> dict[str, bytes]:
    """Recreate the share directory and write every fixture file.

    Returns a dict { posix_relpath : exact_bytes } that the caller
    can independently sha256 for the manifest and for post-run
    integrity verification.

    The directory is WIPED first per the rubber-duck recommendation
    so a stale guest_wrote.txt / leftover debris from a prior run
    cannot mask a real failure.
    """
    if share_dir.exists():
        shutil.rmtree(share_dir)
    share_dir.mkdir(parents=True)

    contents: dict[str, bytes] = {}

    # Phase-5 target: 0 bytes.
    contents["empty.bin"] = b""

    # Single-byte file: catches off-by-one in Tread/Twrite size
    # accounting that 0-byte files would not trip.
    contents["one.bin"] = b"X"

    # Page-sized file: 4 KiB of 0x42, exercising one full-page Tread.
    contents["small.bin"] = b"\x42" * 4096

    # 1 MiB file: at msize=512000 (Linux's hard cap), needs > 1
    # Tread cycle per kernel-side readahead block. With cache=none
    # default, sha256sum's 4 KiB read syscalls each become a
    # 4 KiB Tread (~ 256 round-trips for the full 1 MiB), proving
    # large.bin sha256 over many positional reads.
    contents["large.bin"] = make_large_pattern(1 * 1024 * 1024)

    # Many files: 100 entries in one directory. Each entry has a
    # 13-byte qid + 8-byte offset + 1-byte type + 2-byte name_len
    # + ~12-byte name = ~36 bytes per Treaddir entry; 100 entries
    # all fit in one Treaddir reply at msize=512000.
    (share_dir / "many").mkdir()
    for i in range(100):
        rel = f"many/file{i:03d}.bin"
        # 14 bytes each: "many-file-NNN\n"
        contents[rel] = f"many-file-{i:03d}\n".encode("ascii")

    # Nested dir: walk + sha256 in a subdirectory.
    (share_dir / "subdir").mkdir()
    contents["subdir/nested.bin"] = b"tinyvmm-9p-nested ok\n"

    # Write all bytes via WriteAllBytes-equivalent (no PowerShell
    # CRLF gotcha: Path.write_bytes is byte-exact on Windows).
    for rel, blob in contents.items():
        full = share_dir / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(blob)

    if len(contents) != EXPECTED_MANIFEST_LINES:
        raise SystemExit(
            f"[p9-test] internal error: staged {len(contents)} files "
            f"but EXPECTED_MANIFEST_LINES={EXPECTED_MANIFEST_LINES}")

    return contents


def write_manifest(share_dir: Path, contents: dict[str, bytes]) -> None:
    """Write .manifest.sha256 in busybox sha256sum -c format.

    busybox `sha256sum -c <file>` parses lines of the form
        <64 hex chars><two spaces><relative path>
    and opens each path relative to the current working directory.
    """
    lines: list[str] = []
    for rel in sorted(contents.keys()):
        sha = hashlib.sha256(contents[rel]).hexdigest()
        # Path separator MUST be '/' for busybox under Linux.
        posix = rel.replace("\\", "/")
        lines.append(f"{sha}  {posix}\n")
    # Use write_bytes with explicit LF: Path.write_text on Windows
    # emits CRLF by default, and busybox sha256sum -c then treats
    # the trailing \r as part of the filename ("foo.bin\r"), so
    # every line FAILEDs.
    blob = "".join(lines).encode("ascii")
    (share_dir / ".manifest.sha256").write_bytes(blob)


# ---------------------------------------------------------------------------
# Subprocess driver (mirror of blk_test.py with a different summary needle)
# ---------------------------------------------------------------------------
def run_vmm(argv: list[str], timeout_sec: int) -> tuple[int, str]:
    print("[p9-test] launching: " + " ".join(argv))
    t_start = time.monotonic()
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=0,
    )
    out: list[bytes] = []
    done = threading.Event()
    summary_seen = threading.Event()
    SUMMARY_RE = re.compile(rb"^.*9P SUMMARY:\s+(\d+)/(\d+) phases", re.M)

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

    while proc.poll() is None:
        if time.monotonic() - t_start > timeout_sec:
            print(f"\n[p9-test] timeout after {timeout_sec}s; killing tinyvmm",
                  file=sys.stderr)
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            break
        time.sleep(0.5)

    done.wait(timeout=10)
    t.join(timeout=5)
    blob = b"".join(out).decode("utf-8", errors="replace")
    return (proc.returncode or 0), blob


# ---------------------------------------------------------------------------
# Assertions on captured output / on-host post-conditions
# ---------------------------------------------------------------------------
def assert_p9_summary(log: str) -> None:
    m = re.search(r"9P SUMMARY:\s+(\d+)/(\d+) phases passed", log)
    if not m:
        raise SystemExit(
            "[p9-test] FAIL: no '9P SUMMARY:' line in guest log "
            "(VM may have crashed before reaching the summary)")
    passed, total = int(m.group(1)), int(m.group(2))
    if total == 0 or passed != total:
        fails = re.findall(r"^.*P9 \S+:\s+FAIL.*$", log, flags=re.M)
        for f in fails:
            print("[p9-test] >>>", f.strip())
        raise SystemExit(f"[p9-test] FAIL: 9P SUMMARY {passed}/{total}")
    print(f"[p9-test] guest reports {passed}/{total} phases PASS")


def assert_fixture_intact(share_dir: Path,
                          contents: dict[str, bytes]) -> None:
    """Re-hash every fixture file and compare to original.

    Catches: any guest mutation of a fixture file (would be a
    correctness bug in the read-only-fixture contract of the
    /init block), and any data corruption introduced by the
    Win32 backend.
    """
    for rel, expected in contents.items():
        p = share_dir / rel
        if not p.is_file():
            raise SystemExit(
                f"[p9-test] FAIL: fixture file {rel} missing after run")
        actual = p.read_bytes()
        if actual != expected:
            raise SystemExit(
                f"[p9-test] FAIL: fixture {rel} mutated "
                f"(host len={len(actual)} expected={len(expected)})")
    print(f"[p9-test] all {len(contents)} fixture files intact byte-for-byte")


def assert_guest_wrote(share_dir: Path) -> None:
    gw = share_dir / "guest_wrote.txt"
    if not gw.is_file():
        raise SystemExit(
            "[p9-test] FAIL: guest_wrote.txt missing on host "
            "(guest -> host write did not flush)")
    actual = gw.read_bytes()
    if actual != GUEST_WROTE_BYTES:
        raise SystemExit(
            f"[p9-test] FAIL: guest_wrote.txt = {actual!r} "
            f"(want {GUEST_WROTE_BYTES!r})")
    print("[p9-test] guest_wrote.txt visible on host with expected content")


def assert_no_debris(share_dir: Path) -> None:
    """Verify every debris path the guest created has been removed."""
    leaked = []
    for rel in GUEST_DEBRIS:
        p = share_dir / rel
        if p.exists():
            leaked.append(rel)
    if leaked:
        raise SystemExit(
            f"[p9-test] FAIL: debris on host (create/delete cleanup "
            f"failed): {', '.join(leaked)}")
    print(f"[p9-test] no debris left on host (all {len(GUEST_DEBRIS)} "
          "transient paths cleaned up)")


def assert_no_unexpected_files(share_dir: Path,
                               contents: dict[str, bytes]) -> None:
    """Enumerate p9-share/ and reject anything we didn't expect.

    Expected set:
      - every key in `contents`
      - `.manifest.sha256`
      - `guest_wrote.txt` (the one persistent guest mutation)
      - any parent directory of the above

    Anything else is debris from a guest phase that did not clean up,
    or a host fixture-stager bug. Either way: fail loud.
    """
    expected: set[str] = set()
    expected.add(".manifest.sha256")
    expected.add("guest_wrote.txt")
    for rel in contents.keys():
        expected.add(rel.replace("\\", "/"))
        parts = rel.split("/")
        for i in range(1, len(parts)):
            expected.add("/".join(parts[:i]))

    actual: set[str] = set()
    for p in share_dir.rglob("*"):
        rel = p.relative_to(share_dir).as_posix()
        actual.add(rel)

    extra = actual - expected
    if extra:
        raise SystemExit(
            f"[p9-test] FAIL: unexpected files under p9-share: "
            f"{sorted(extra)}")
    print(f"[p9-test] no unexpected files under p9-share "
          f"({len(actual)} entries, all accounted for)")


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
            print(f"[p9-test] FAIL: {label} not found at {p}",
                  file=sys.stderr)
            return 2

    if args.workdir is None:
        args.workdir = Path(tempfile.gettempdir()) / "tinyvmm-p9-test"
    args.workdir.mkdir(parents=True, exist_ok=True)
    share = args.workdir / "p9-share"

    print(f"[p9-test] workdir: {args.workdir}")
    print(f"[p9-test] share:   {share}")
    contents = stage_fixture(share)
    write_manifest(share, contents)
    n_fixture_bytes = sum(len(v) for v in contents.values())
    print(f"[p9-test] staged {len(contents)} files "
          f"({n_fixture_bytes:,} bytes total) + .manifest.sha256")

    argv = [
        str(args.tinyvmm),
        "--pvh-run",
        "--ram-mb", "256",
        "--virtio-9p-share", f"host={share}",
        "--initrd", str(args.initrd),
        str(args.vmlinux),
        "--",
        "tinyvmm.test=9p",
        "console=hvc0",
        "pci=conf1,nocrs,lastbus=0",
    ]
    rc, log = run_vmm(argv, args.timeout_sec)

    print(f"\n[p9-test] tinyvmm exited rc={rc}")
    # Mirror blk_test.py: don't gate on rc, because the guest reaches
    # the summary line BEFORE poweroff and tinyvmm's poweroff path
    # often returns WHvCancelled (non-zero rc). Gate on log content.

    try:
        # Order recommended by the rubber-duck pass: validate the
        # primary signal (summary) first so a VM crash produces a
        # clear failure instead of being masked by a subsequent
        # host-side check.
        assert_p9_summary(log)
        assert_fixture_intact(share, contents)
        assert_guest_wrote(share)
        assert_no_debris(share)
        assert_no_unexpected_files(share, contents)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        if not args.keep_workdir:
            try:
                shutil.rmtree(args.workdir)
            except OSError:
                pass
        return 1

    print("[p9-test] PASS: 15-phase guest test + 4 host post-conditions")
    if not args.keep_workdir:
        try:
            shutil.rmtree(args.workdir)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
