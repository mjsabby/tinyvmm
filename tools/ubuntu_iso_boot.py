#!/usr/bin/env python3
"""Boot an Ubuntu ISO with an optional VHDX installation target.

Example:
    python tools\\ubuntu_iso_boot.py --iso ubuntu-26.04.1-desktop-amd64.iso \
        --disk install.vhdx --disk-size-gb 64

tinyvmm loads the ISO's kernel and initrd directly. No extraction or host
ISO mount is needed. The ISO appears as /dev/vda; the target is /dev/vdb.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

from vhdx import make_vhdx


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", required=True, type=Path)
    parser.add_argument("--disk", type=Path, help="VHDX target; created if missing")
    parser.add_argument("--disk-size-gb", type=int, default=20)
    parser.add_argument("--ram-mb", type=int, default=3072)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--net-backend", choices=["nat", "wintun", "loopback"], default="nat")
    parser.add_argument("--tinyvmm", type=Path,
                        default=Path(__file__).resolve().parent.parent
                        / "target" / "release" / "tinyvmm.exe")
    parser.add_argument("--cmdline-extra", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.ram_mb < 128 or not 1 <= args.vcpus <= 32 or args.disk_size_gb <= 0:
        parser.error("RAM must be >=128 MiB, vcpus 1..32, and disk size positive")
    for path in (args.iso, args.tinyvmm):
        if not path.is_file():
            print(f"[iso-boot] file not found: {path}", file=sys.stderr)
            return 2
    if args.disk is not None:
        if args.disk.suffix.lower() != ".vhdx":
            parser.error("--disk must name a .vhdx file")
        if not args.disk.exists():
            args.disk.parent.mkdir(parents=True, exist_ok=True)
            make_vhdx(args.disk, args.disk_size_gb * 1024 ** 3, args.tinyvmm)

    argv = [str(args.tinyvmm), "--pvh-run", "--iso", str(args.iso.resolve()),
            "--vcpus", str(args.vcpus), "--ram-mb", str(args.ram_mb),
            "--net", "--net-backend", args.net_backend]
    if args.disk is not None:
        argv.extend(["--drive", str(args.disk.resolve())])
    if args.cmdline_extra:
        argv.extend(["--", args.cmdline_extra])
    print("[iso-boot] " + subprocess.list2cmdline(argv), flush=True)
    if args.dry_run:
        return 0
    return subprocess.call(argv)


if __name__ == "__main__":
    raise SystemExit(main())
