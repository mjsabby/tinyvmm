#!/usr/bin/env python3
"""Boot an Ubuntu live-server ISO under tinyvmm via PVH.

tinyvmm only does PVH boot (kernel + initramfs via Xen ELF note), not
BIOS or UEFI. Ubuntu's `casper/vmlinuz` is a bzImage (legacy 16-bit
setup header + compressed-payload ELF), so this script also extracts
the inner ELF -- which carries the PVH note when the kernel is built
with `CONFIG_PVH=y` (default-on for upstream and Canonical builds).

Flow:
  1. Mount the ISO via PowerShell `Mount-DiskImage` (no admin needed).
  2. Copy `casper/vmlinuz` + `casper/initrd` to a workspace.
  3. Dismount the ISO.
  4. Convert the bzImage to ELF in-place (probe for gzip/xz/bz2/zstd
     payload magic, decompress, verify `\\x7FELF`).
  5. Create the target disk as a sparse file if missing.
  6. Spawn `tinyvmm.exe --pvh-run --drive <iso>,readonly --drive <disk>
     --initrd <initrd> <vmlinux>` with a casper-friendly cmdline.

Example:
    python tools/ubuntu_iso_boot.py ^
        --iso ubuntu-26.04-live-server-amd64.iso ^
        --disk install.img ^
        --disk-size-gb 20 ^
        --ram-mb 3072 ^
        --vcpus 2
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# zstd is stdlib on Python 3.14+ (PEP 784). Older Pythons may have the
# `zstandard` third-party package on PyPI; we'll happily use either.
# IMPORTANT: Linux kernel bzImages compress with zstd in streaming mode
# without setting Frame_Content_Size in the frame header. The single-shot
# `compression.zstd.decompress()` / `zstandard.decompress()` helpers fail
# on such frames ("Unknown frame descriptor" / "Destination buffer is too
# small"). We must use the streaming decompressor classes.
try:
    from compression import zstd as _zstd_stdlib  # type: ignore[attr-defined]
    def _zstd_decompress(buf: bytes) -> bytes:
        dec = _zstd_stdlib.ZstdDecompressor()
        out = dec.decompress(buf)
        if not dec.eof:
            raise ValueError("zstd frame is incomplete")
        return out
except Exception:
    try:
        import zstandard as _zstd_pkg  # type: ignore[import-not-found]
        def _zstd_decompress(buf: bytes) -> bytes:
            # zstandard's ZstdDecompressor.stream_reader handles
            # missing-FCS frames the same way.
            import io
            dec = _zstd_pkg.ZstdDecompressor()
            with dec.stream_reader(io.BytesIO(buf)) as r:
                return r.read()
    except Exception:
        _zstd_decompress = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Boot an Ubuntu live-server ISO under tinyvmm via PVH "
            "(extracts casper kernel + initrd, decompresses bzImage to "
            "PVH ELF, attaches the ISO as read-only virtio-blk for "
            "casper to find its squashfs)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--iso", required=True, type=Path,
                   help="Path to the Ubuntu live-server amd64 ISO.")
    p.add_argument("--disk", type=Path, default=None,
                   help=(
                       "Install target disk image. Created as a sparse "
                       "file of --disk-size-gb if missing. Omit to run "
                       "live-only with no second virtio-blk."))
    p.add_argument("--disk-size-gb", type=int, default=20,
                   help="Size of the target disk to create if missing.")
    p.add_argument("--ram-mb", type=int, default=3072,
                   help=(
                       "Guest RAM in MiB (128..3584). Subiquity + snap "
                       "+ squashfs overlay needs ~2 GiB minimum; we "
                       "default to 3 GiB."))
    p.add_argument("--vcpus", type=int, default=2,
                   help="Number of guest vCPUs (1..32).")
    p.add_argument("--net-backend", default="usernet",
                   choices=["usernet", "wintun", "wintun-svc", "xdp",
                            "loopback"],
                   help="virtio-net backend for apt-mirror traffic.")
    p.add_argument("--tinyvmm", type=Path, default=None,
                   help=(
                       "Path to tinyvmm.exe. Defaults to "
                       "<repo>/build/bin/tinyvmm.exe based on this "
                       "script's location."))
    p.add_argument("--workspace", type=Path, default=None,
                   help=(
                       "Directory for extracted vmlinux/initrd. "
                       "Defaults to a per-ISO directory under %%TEMP%%. "
                       "Reused between runs."))
    p.add_argument("--keep-workspace", action="store_true",
                   help=("Don't delete the auto-created workspace on "
                         "exit. User-supplied --workspace is never "
                         "auto-deleted."))
    p.add_argument("--force-extract", action="store_true",
                   help=("Re-extract kernel/initrd even if the "
                         "workspace already has them. Useful after "
                         "swapping ISOs into the same workspace."))
    p.add_argument("--cmdline-extra", default="",
                   help=(
                       "Extra kernel cmdline appended after the "
                       "built-in casper args. E.g. 'autoinstall "
                       "ds=nocloud' for unattended install. Don't "
                       "pass these unless you also seed user-data."))
    p.add_argument("--dry-run", action="store_true",
                   help=("Print the tinyvmm command and exit without "
                         "launching the VM. Still mounts/extracts the "
                         "ISO so you can inspect the workspace."))
    return p.parse_args()


# ---------------------------------------------------------------------------
# PowerShell helpers -- minimal wrappers around Mount-DiskImage. We don't
# require admin (Mount-DiskImage on ISOs runs in user context) but we DO
# need to handle: drive-letter race, an already-mounted ISO, and Ctrl-C
# leaving a mount behind.
# ---------------------------------------------------------------------------
def _run_ps(script: str, *, check: bool = True) -> str:
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", script],
        check=False, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if check and result.returncode != 0:
        sys.stderr.write(result.stdout or "")
        sys.stderr.write(result.stderr or "")
        raise SystemExit(
            f"powershell exited {result.returncode} on script {script!r}"
        )
    return (result.stdout or "").strip()


def _iso_already_mounted(iso: Path) -> bool:
    """Best-effort check: does Get-DiskImage say this ISO is attached?"""
    out = _run_ps(
        f"(Get-DiskImage -ImagePath '{iso}').Attached", check=False)
    return out.lower().startswith("true")


def _wait_for_letter(iso: Path, attempts: int = 20) -> str:
    """Poll Get-Volume until the mounted ISO has a drive letter."""
    import time
    for _ in range(attempts):
        out = _run_ps(
            f"(Get-DiskImage -ImagePath '{iso}' | Get-Volume).DriveLetter",
            check=False,
        )
        if out and len(out) == 1 and out.isalpha():
            return out
        time.sleep(0.25)
    return ""


def mount_iso(iso: Path) -> tuple[str, bool]:
    """Mount the ISO; return (drive_letter, we_mounted_it).

    If the ISO is already attached we reuse the existing mount and
    return we_mounted_it=False so the cleanup path leaves it alone.
    """
    iso_abs = iso.resolve()
    we_mounted = False
    if not _iso_already_mounted(iso_abs):
        _run_ps(f"Mount-DiskImage -ImagePath '{iso_abs}' | Out-Null")
        we_mounted = True
    letter = _wait_for_letter(iso_abs)
    if not letter:
        # Mounted but Windows didn't assign a letter. Dismount our own
        # mount so we don't leak; bail with a helpful message.
        if we_mounted:
            dismount_iso(iso_abs)
        raise SystemExit(
            f"Mount-DiskImage succeeded but no drive letter was "
            f"assigned for {iso_abs}. Group Policy may block automount "
            f"for new volumes -- try `mountvol /e` or mount the ISO "
            f"once in Explorer and re-run."
        )
    return letter, we_mounted


def dismount_iso(iso: Path) -> None:
    _run_ps(f"Dismount-DiskImage -ImagePath '{iso}' | Out-Null",
            check=False)


# ---------------------------------------------------------------------------
# Casper extraction
# ---------------------------------------------------------------------------
# Candidate locations for kernel + initrd inside Ubuntu live-server ISOs.
# Path layout has been stable since 20.04; we accept a few variants in case
# Canonical reshuffles things. Listed in priority order.
_CASPER_KERNEL_CANDIDATES = ("casper/vmlinuz", "casper/vmlinuz.efi")
_CASPER_INITRD_CANDIDATES = (
    "casper/initrd",
    "casper/initrd.lz",
    "casper/initrd.img",
)


def _find_first(root: Path, candidates: tuple[str, ...]) -> Path:
    for rel in candidates:
        p = root / rel
        if p.exists() and p.is_file():
            return p
    raise SystemExit(
        f"Could not find any of {list(candidates)} under {root}. "
        f"Is this an Ubuntu live-server ISO? (desktop ISOs use a "
        f"different layout.)"
    )


def extract_casper(drive_letter: str, workspace: Path) -> tuple[Path, Path]:
    """Copy vmlinuz + initrd from the mounted ISO to workspace."""
    root = Path(f"{drive_letter}:/")
    kernel_src = _find_first(root, _CASPER_KERNEL_CANDIDATES)
    initrd_src = _find_first(root, _CASPER_INITRD_CANDIDATES)

    workspace.mkdir(parents=True, exist_ok=True)
    bz_dst = workspace / "vmlinuz.bzimage"
    initrd_dst = workspace / "initrd"
    shutil.copyfile(kernel_src, bz_dst)
    shutil.copyfile(initrd_src, initrd_dst)
    print(f"[iso-boot] extracted: {kernel_src.name} "
          f"({bz_dst.stat().st_size} bytes), "
          f"{initrd_src.name} ({initrd_dst.stat().st_size} bytes)")
    return bz_dst, initrd_dst


# ---------------------------------------------------------------------------
# bzImage -> ELF vmlinux (PVH note carrier)
# ---------------------------------------------------------------------------
# When CONFIG_PVH=y the inner ELF carries a Xen PT_NOTE with type 18
# (XEN_ELFNOTE_PHYS32_ENTRY); tinyvmm's loader requires that note.
# Mirrors what Linux's scripts/extract-vmlinux does: scan the bzImage
# for each compressor's magic bytes, attempt decompression, and accept
# the first output that begins with \x7FELF.
_ELF_MAGIC = b"\x7FELF"


def _try_gzip(buf: bytes, off: int) -> bytes | None:
    # We probe at every magic-byte hit, so most invocations fail. Swallow
    # any decompressor error (zlib.error, EOFError, OSError, MemoryError,
    # ValueError) and let the scanner move on to the next match.
    try:
        return gzip.decompress(buf[off:])
    except Exception:
        return None


def _try_xz(buf: bytes, off: int) -> bytes | None:
    try:
        return lzma.decompress(buf[off:], format=lzma.FORMAT_XZ)
    except Exception:
        return None


def _try_bz2(buf: bytes, off: int) -> bytes | None:
    try:
        return bz2.decompress(buf[off:])
    except Exception:
        return None


def _try_lzma_alone(buf: bytes, off: int) -> bytes | None:
    try:
        return lzma.decompress(buf[off:], format=lzma.FORMAT_ALONE)
    except Exception:
        return None


def _try_zstd(buf: bytes, off: int) -> bytes | None:
    if _zstd_decompress is None:
        return None
    try:
        return _zstd_decompress(buf[off:])
    except Exception:
        return None


# Compressor magic -> trial decompressor. lzma "alone" has a permissive
# 5-byte header that overlaps with arbitrary data, so we put it last and
# accept it only if it produces an ELF.
_COMPRESSORS: tuple[tuple[bytes, callable], ...] = (
    (b"\x1F\x8B\x08", _try_gzip),                  # gzip
    (b"\xFD7zXZ\x00",   _try_xz),                  # xz
    (b"BZh",            _try_bz2),                 # bzip2
    (b"\x28\xB5\x2F\xFD", _try_zstd),              # zstd frame magic
    (b"\x5D\x00\x00",   _try_lzma_alone),          # lzma "alone"
)


def bzimage_to_elf(bz_path: Path, out_path: Path) -> Path:
    """Find and decompress the embedded ELF inside a bzImage.

    Idempotent: if the input is already an ELF, just copies it.
    """
    data = bz_path.read_bytes()
    if data.startswith(_ELF_MAGIC):
        if bz_path != out_path:
            shutil.copyfile(bz_path, out_path)
        print(f"[iso-boot] {bz_path.name} is already an ELF "
              f"({len(data)} bytes); no decompression needed")
        return out_path

    n = len(data)
    print(f"[iso-boot] scanning bzImage ({n} bytes) for compressed payload...")
    for magic, decompressor in _COMPRESSORS:
        off = 0
        while True:
            off = data.find(magic, off)
            if off < 0:
                break
            payload = decompressor(data, off)
            off += 1   # advance in case the same compressor recurs
            if payload is None:
                continue
            if not payload.startswith(_ELF_MAGIC):
                continue
            out_path.write_bytes(payload)
            print(f"[iso-boot] bzImage -> ELF: {magic!r} payload at "
                  f"offset {off - 1}, decompressed {len(payload)} bytes "
                  f"({decompressor.__name__})")
            return out_path

    raise SystemExit(
        f"Could not find a decompressible ELF inside {bz_path}. The "
        f"kernel may use an unsupported compressor (we try gzip/xz/"
        f"bz2/zstd/lzma) or this isn't a Linux bzImage. zstd support "
        f"requires Python 3.14+ stdlib or the 'zstandard' pip package."
    )


# ---------------------------------------------------------------------------
# Sparse disk creation
# ---------------------------------------------------------------------------
def _set_eof(path: Path, size_bytes: int) -> None:
    """Move the file's EOF without writing data.

    Python's ``file.truncate(size)`` on Windows calls MSVCRT's
    ``_chsize_s`` which extends sparse files by writing zeros, defeating
    the sparse flag we just set. We need to call ``SetEndOfFile``
    directly so NTFS leaves the extension unallocated.
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


def ensure_target_disk(path: Path, size_gb: int) -> None:
    if path.exists():
        print(f"[iso-boot] target disk: reusing existing {path} "
              f"({path.stat().st_size} bytes)")
        return
    size_bytes = size_gb * (1024 ** 3)
    parent = path.parent if str(path.parent) else Path(".")
    parent.mkdir(parents=True, exist_ok=True)

    print(f"[iso-boot] creating sparse target disk {path} "
          f"({size_gb} GiB logical)")
    # IMPORTANT ORDER:
    #   1. create the file at length 0
    #   2. set the sparse flag (so subsequent zero-ranges don't allocate)
    #   3. extend via raw SetEndOfFile (NOT Python's truncate, which on
    #      Windows calls _chsize_s and writes zeros across the extension,
    #      allocating the entire range and defeating the sparse flag)
    with open(path, "wb"):
        pass
    subprocess.run(["fsutil.exe", "sparse", "setflag", str(path)],
                   check=True)
    _set_eof(path, size_bytes)


# ---------------------------------------------------------------------------
# tinyvmm dispatch
# ---------------------------------------------------------------------------
def default_tinyvmm_path() -> Path:
    return (Path(__file__).resolve().parent.parent
            / "build" / "bin" / "tinyvmm.exe")


def build_tinyvmm_argv(
    *,
    tinyvmm: Path,
    kernel: Path,
    initrd: Path,
    iso: Path,
    disk: Path | None,
    ram_mb: int,
    vcpus: int,
    net_backend: str,
    cmdline_extra: str,
) -> list[str]:
    # Casper boots when the kernel sees a block device with `.disk/info`
    # + `casper/filesystem.squashfs`. We attach the raw ISO bytes as
    # virtio-blk #0 (vda), so `live-media=/dev/vda` is a robustness win
    # over relying on casper's autodetection. `iso-scan/filename=` is
    # for the case where the ISO is a file on a separate FS; we don't
    # need it here.
    cmdline_parts = [
        "console=hvc0",
        "boot=casper",
        "live-media=/dev/vda",
        "pci=conf1,nocrs,lastbus=0",
        "nofb", "nomodeset",
        "fsck.mode=skip",
        # Don't bother probing the IPv6 router solicitation on usernet
        # (we don't yet emit RA). Saves ~3s during NetworkManager init.
        "ipv6.disable=1",
    ]
    if cmdline_extra:
        cmdline_parts.append(cmdline_extra)
    cmdline = " ".join(cmdline_parts)

    argv: list[str] = [
        str(tinyvmm),
        "--pvh-run",
        "--vcpus", str(vcpus),
        "--ram-mb", str(ram_mb),
        "--net", "--net-backend", net_backend,
        "--initrd", str(initrd),
        "--drive", f"{iso},readonly",
    ]
    if disk is not None:
        argv.extend(["--drive", str(disk)])
    argv.append(str(kernel))
    argv.append("--")
    argv.append(cmdline)
    return argv


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------
def main() -> int:
    args = parse_args()

    if not args.iso.is_file():
        sys.stderr.write(f"--iso: {args.iso} not found or not a file\n")
        return 2

    tinyvmm = args.tinyvmm or default_tinyvmm_path()
    if not tinyvmm.is_file():
        sys.stderr.write(
            f"tinyvmm.exe not found at {tinyvmm}. Pass --tinyvmm or "
            f"build first (cmake --build build).\n")
        return 2

    if not (128 <= args.ram_mb <= 3584):
        sys.stderr.write("--ram-mb must be in [128, 3584]\n")
        return 2
    if not (1 <= args.vcpus <= 32):
        sys.stderr.write("--vcpus must be in [1, 32]\n")
        return 2

    if args.workspace is not None:
        workspace = args.workspace
        workspace.mkdir(parents=True, exist_ok=True)
        keep = True
    else:
        sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", args.iso.stem)
        workspace = (Path(tempfile.gettempdir())
                     / f"tinyvmm-iso-{sanitized}")
        workspace.mkdir(parents=True, exist_ok=True)
        keep = args.keep_workspace

    print(f"[iso-boot] workspace: {workspace} (keep={keep})")

    vmlinux = workspace / "vmlinux"
    initrd_path = workspace / "initrd"

    need_extract = (args.force_extract
                    or not vmlinux.exists()
                    or not initrd_path.exists())

    if need_extract:
        drive_letter, we_mounted = mount_iso(args.iso)
        print(f"[iso-boot] mounted {args.iso} -> {drive_letter}:/ "
              f"(ours={we_mounted})")
        try:
            bz, _ = extract_casper(drive_letter, workspace)
        finally:
            if we_mounted:
                dismount_iso(args.iso.resolve())
                print(f"[iso-boot] dismounted {args.iso}")
            else:
                print(f"[iso-boot] left existing mount of {args.iso} "
                      f"alone (we didn't attach it)")
        bzimage_to_elf(bz, vmlinux)
    else:
        print(f"[iso-boot] reusing extracted vmlinux + initrd in "
              f"{workspace} (pass --force-extract to redo)")

    if args.disk is not None:
        ensure_target_disk(args.disk, args.disk_size_gb)

    argv = build_tinyvmm_argv(
        tinyvmm=tinyvmm,
        kernel=vmlinux,
        initrd=initrd_path,
        iso=args.iso.resolve(),
        disk=(args.disk.resolve() if args.disk is not None else None),
        ram_mb=args.ram_mb,
        vcpus=args.vcpus,
        net_backend=args.net_backend,
        cmdline_extra=args.cmdline_extra,
    )

    print("[iso-boot] launching tinyvmm:")
    print("  " + " ".join(f'"{a}"' if (" " in a or "," in a) else a
                          for a in argv))

    if args.dry_run:
        return 0

    try:
        rc = subprocess.call(argv)
    except KeyboardInterrupt:
        rc = 130

    if not keep:
        try:
            shutil.rmtree(workspace, ignore_errors=True)
        except Exception as e:
            sys.stderr.write(f"[iso-boot] workspace cleanup failed: {e}\n")

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
