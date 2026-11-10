#!/usr/bin/env python3
"""Build the PoC guest: compile vhostile.c to a static Linux binary with zig
and pack it, busybox and init.sh into an initramfs.

    python poc\\guest\\build.py [--force]

Outputs go to poc/out/ (ignored by git) and are reused until an input changes:
    poc/out/vhostile             static x86_64-linux-musl binary
    poc/out/poc-initramfs.cpio.gz

zig is taken from $ZIG, else PATH, else %LOCALAPPDATA%\\tinyvmm-toolchain.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

GUEST = Path(__file__).resolve().parent
POC = GUEST.parent
REPO = POC.parent
OUT = POC / "out"
INITRAMFS = OUT / "poc-initramfs.cpio.gz"
VHOSTILE = OUT / "vhostile"
STAMP = OUT / "build.stamp"
BUSYBOX = REPO / "busybox-x86_64"
SOURCES = [GUEST / "vhostile.c", GUEST / "init.sh", Path(__file__).resolve()]


def find_zig() -> str:
    env = os.environ.get("ZIG")
    if env and Path(env).exists():
        return env
    on_path = shutil.which("zig")
    if on_path:
        return on_path
    local = os.environ.get("LOCALAPPDATA")
    if local:
        found = sorted(Path(local, "tinyvmm-toolchain").glob("zig-*/zig.exe"))
        if found:
            return str(found[-1])
    raise SystemExit("zig not found: set ZIG to zig.exe (0.13 or later), or put zig on PATH")


def inputs_digest(busybox: Path) -> str:
    h = hashlib.sha256()
    for p in [*SOURCES, busybox]:
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def build(force: bool = False, busybox: Path = BUSYBOX, quiet: bool = False) -> Path:
    """Build if needed; returns the initramfs path."""
    if not busybox.exists():
        raise SystemExit(f"{busybox} not found (the static busybox the guest runs)")
    OUT.mkdir(parents=True, exist_ok=True)
    digest = inputs_digest(busybox)
    if (not force and INITRAMFS.exists() and VHOSTILE.exists() and STAMP.exists()
            and STAMP.read_text().strip() == digest):
        return INITRAMFS

    zig = find_zig()
    env = dict(os.environ)
    env.setdefault("ZIG_LOCAL_CACHE_DIR", str(OUT / "zig-cache"))
    cmd = [zig, "cc", "-target", "x86_64-linux-musl", "-static", "-O2", "-s", "-Wall",
           "-Wextra", "-Wno-unused-parameter", "-o", str(VHOSTILE), str(GUEST / "vhostile.c")]
    if not quiet:
        print("[build] " + " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=str(OUT), env=env)

    sys.path.insert(0, str(REPO / "tools"))
    import make_initramfs as m  # noqa: E402

    cb = m.CpioBuilder()
    for d in [".", "bin", "dev", "proc", "sys", "tmp", "mnt"]:
        cb.add_dir(d, mode=0o1777 if d == "tmp" else 0o755)
    # The kernel opens /dev/console for init before /init mounts devtmpfs.
    cb.add_chrdev("dev/console", major=5, minor=1, mode=0o600)
    cb.add_chrdev("dev/null", major=1, minor=3, mode=0o666)
    cb.add_chrdev("dev/kmsg", major=1, minor=11, mode=0o644)
    cb.add_file("bin/busybox", busybox.read_bytes(), mode=0o755)
    cb.add_symlink("bin/sh", "busybox")
    cb.add_file("bin/vhostile", VHOSTILE.read_bytes(), mode=0o755)
    # Whatever the checkout did to line endings, the guest wants LF.
    init = (GUEST / "init.sh").read_bytes().replace(b"\r\n", b"\n")
    cb.add_file("init", init, mode=0o755)
    with gzip.open(INITRAMFS, "wb", compresslevel=6) as f:
        f.write(cb.finalize())
    STAMP.write_text(digest + "\n")
    if not quiet:
        print(f"[build] wrote {INITRAMFS} ({INITRAMFS.stat().st_size} bytes)")
    return INITRAMFS


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true", help="rebuild even if nothing changed")
    ap.add_argument("--busybox", type=Path, default=BUSYBOX)
    args = ap.parse_args()
    build(force=args.force, busybox=args.busybox)
    return 0


if __name__ == "__main__":
    sys.exit(main())
