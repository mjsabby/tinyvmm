"""
Build a minimal busybox-based initramfs.cpio.gz with no external tools.

Format: cpio newc (ASCII header, magic 070701), gzip-compressed.
The Linux kernel unpacks this into the initial rootfs (rootfs is tmpfs)
before running /init.
"""
from __future__ import annotations

import argparse
import gzip
import io
import sys
from pathlib import Path

CPIO_MAGIC = b"070701"
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000
S_IFCHR = 0o020000


def hex8(n: int) -> bytes:
    return f"{n:08x}".encode("ascii")


def pad4(buf: io.BytesIO) -> None:
    n = buf.tell()
    rem = (-n) & 3
    if rem:
        buf.write(b"\0" * rem)


class CpioBuilder:
    def __init__(self) -> None:
        self.buf = io.BytesIO()
        self.next_ino = 1

    def _entry(self, name: str, mode: int, data: bytes, nlink: int,
               rdev_major: int = 0, rdev_minor: int = 0) -> None:
        ino = self.next_ino
        self.next_ino += 1
        name_b = name.encode("ascii") + b"\0"
        hdr = (
            CPIO_MAGIC
            + hex8(ino)
            + hex8(mode)
            + hex8(0)            # uid
            + hex8(0)            # gid
            + hex8(nlink)
            + hex8(0)            # mtime
            + hex8(len(data))    # filesize
            + hex8(0)            # devmajor
            + hex8(0)            # devminor
            + hex8(rdev_major)   # rdevmajor
            + hex8(rdev_minor)   # rdevminor
            + hex8(len(name_b))  # namesize (with NUL)
            + hex8(0)            # check
        )
        assert len(hdr) == 110, len(hdr)
        self.buf.write(hdr)
        self.buf.write(name_b)
        pad4(self.buf)
        self.buf.write(data)
        pad4(self.buf)

    def add_dir(self, name: str, mode: int = 0o755) -> None:
        self._entry(name, S_IFDIR | mode, b"", nlink=2)

    def add_file(self, name: str, data: bytes, mode: int = 0o644) -> None:
        self._entry(name, S_IFREG | mode, data, nlink=1)

    def add_symlink(self, name: str, target: str) -> None:
        self._entry(name, S_IFLNK | 0o777, target.encode("ascii"), nlink=1)

    def add_chrdev(self, name: str, major: int, minor: int,
                   mode: int = 0o600) -> None:
        self._entry(name, S_IFCHR | mode, b"", nlink=1,
                    rdev_major=major, rdev_minor=minor)

    def finalize(self) -> bytes:
        name_b = b"TRAILER!!!\0"
        hdr = (
            CPIO_MAGIC
            + hex8(0)   # ino
            + hex8(0)   # mode
            + hex8(0)   # uid
            + hex8(0)   # gid
            + hex8(1)   # nlink (>=1 required)
            + hex8(0)   # mtime
            + hex8(0)   # filesize
            + hex8(0)   # devmajor
            + hex8(0)   # devminor
            + hex8(0)   # rdevmajor
            + hex8(0)   # rdevminor
            + hex8(len(name_b))
            + hex8(0)   # check
        )
        assert len(hdr) == 110, len(hdr)
        self.buf.write(hdr)
        self.buf.write(name_b)
        pad4(self.buf)
        return self.buf.getvalue()


INIT_SCRIPT = b"""#!/bin/busybox sh
# tinyvmm initramfs entrypoint.
#
# NOTE: this is intentionally NON-INTERACTIVE. Until M19c.5 (8250 IRQ-driven
# TX) is solved, the kernel's tty path can't drain userspace writes to
# /dev/console -- so we log everything through /dev/kmsg (which uses the
# kernel's polled console_write path and works today) and never block on
# user input.

/bin/busybox --install -s /bin
mount -t proc     proc  /proc    2>/dev/kmsg
mount -t sysfs    sysfs /sys     2>/dev/kmsg
mount -t devtmpfs devfs /dev     2>/dev/kmsg

log() { echo "[init] $*" > /dev/kmsg; }

log "=== tinyvmm init starting ==="
log "uname: $(uname -a)"

# --- virtio-console verification (M20) -----------------------------------
# Write a unique marker to /dev/hvc0 directly. Kernel printk lines also land
# on hvc0 if `console=hvc0` is set, so to disambiguate we use a distinctive
# tag here that no other code path emits.
if [ -c /dev/hvc0 ]; then
    log "/dev/hvc0 present"
    echo "[init] HVC0_MARKER_BEGIN: virtio-console direct write works" > /dev/hvc0
    echo "[init] HVC0_MARKER_END" > /dev/hvc0
else
    log "/dev/hvc0 NOT present"
fi

# --- /sys snapshot ------------------------------------------------------
log "--- /sys/bus contents ---"
log "$(ls /sys/bus 2>/dev/kmsg)"
log "--- /sys/bus/pci/devices ---"
log "$(ls /sys/bus/pci/devices 2>/dev/kmsg)"
log "--- /sys/bus/virtio/devices ---"
log "$(ls /sys/bus/virtio/devices 2>/dev/kmsg)"
log "--- /proc/bus/pci/devices ---"
log "$(cat /proc/bus/pci/devices 2>/dev/kmsg | head -n 10)"
log "--- /proc/iomem (head) ---"
log "$(cat /proc/iomem 2>/dev/kmsg | head -n 20)"

# --- network interfaces -----------------------------------------------
log "--- /sys/class/net ---"
for n in /sys/class/net/*; do
    [ -e "$n" ] || continue
    iface=$(basename "$n")
    addr=$(cat "$n/address" 2>/dev/null)
    log "iface $iface mac=$addr"
done

# --- bring up loopback (always works) -----------------------------------
ip link set lo up        2>/dev/kmsg
log "lo: $(ip -4 addr show lo | tr -d '\\n')"

# --- bring up eth0 (if virtio-net bound) --------------------------------
if [ -e /sys/class/net/eth0 ]; then
    ip link set eth0 up                       2>/dev/kmsg
    ip addr add 10.0.0.2/24 dev eth0          2>/dev/kmsg
    ip route add default via 10.0.0.1         2>/dev/kmsg
    log "eth0 up: $(ip -4 addr show eth0 | tr -d '\\n')"
else
    log "no eth0 (virtio-net driver did not bind)"
fi

# --- entropy from virtio-rng (sanity) ------------------------------------
if [ -c /dev/hwrng ]; then
    log "hwrng: $(head -c 16 /dev/hwrng | od -An -tx1 | tr -d '\\n ')"
fi

log "=== init complete; entering idle ==="

# Don't drop to shell (no working userspace TTY yet). Park in a kernel-
# blocking wait that doesn't depend on clockevents (we deliberately turned
# off PIT IRQ 0 to avoid the LAPIC stale-ISR issue, and tsc-deadline
# clockevent isn't being installed by Linux -- so 'sleep' would hang).
# read on a fifo or /dev/console blocks in the kernel's tty code without
# burning CPU.
exec cat
"""


BUSYBOX_APPLETS = [
    "sh", "ash", "ls", "cat", "echo", "mount", "umount", "uname", "dmesg",
    "ip", "ping", "ifconfig", "hostname", "sleep", "true", "false", "head",
    "tail", "ps", "kill", "mkdir", "rm", "cp", "mv", "ln", "find", "grep",
    "sed", "awk", "vi", "more", "less", "poweroff", "reboot", "halt",
    "modprobe", "insmod", "lsmod", "rmmod", "switch_root", "init", "free",
    "mknod", "chmod", "chown", "df", "du", "route", "ifup", "ifdown",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--busybox", required=True,
                    help="Path to the static busybox-x86_64 binary.")
    ap.add_argument("--out", required=True,
                    help="Output path. Use .cpio for uncompressed (works "
                         "with any kernel) or .cpio.gz for gzip (needs "
                         "CONFIG_RD_GZIP=y in the kernel).")
    ap.add_argument("--compress", choices=["none", "gzip"], default=None,
                    help="Compression. Default: infer from output extension "
                         "(.gz -> gzip, anything else -> none).")
    args = ap.parse_args()

    busybox_path = Path(args.busybox)
    out_path = Path(args.out)
    busybox_blob = busybox_path.read_bytes()
    if not busybox_blob.startswith(b"\x7fELF"):
        print(f"error: {busybox_path} is not an ELF binary", file=sys.stderr)
        return 1

    cb = CpioBuilder()
    cb.add_dir(".", mode=0o755)
    cb.add_dir("bin", mode=0o755)
    cb.add_dir("dev", mode=0o755)
    cb.add_dir("proc", mode=0o755)
    cb.add_dir("sys", mode=0o755)
    cb.add_dir("etc", mode=0o755)
    cb.add_dir("root", mode=0o700)

    # Pre-populated device nodes. The kernel opens /dev/console as
    # stdin/stdout/stderr for the init process BEFORE running /init, so this
    # node must exist before /init mounts devtmpfs. Linux's TTY major numbers
    # come from Documentation/admin-guide/devices.txt.
    cb.add_chrdev("dev/console", major=5, minor=1, mode=0o600)
    cb.add_chrdev("dev/null",    major=1, minor=3, mode=0o666)
    cb.add_chrdev("dev/zero",    major=1, minor=5, mode=0o666)
    cb.add_chrdev("dev/tty",     major=5, minor=0, mode=0o666)
    cb.add_chrdev("dev/ttyS0",   major=4, minor=64, mode=0o600)
    cb.add_chrdev("dev/random",  major=1, minor=8, mode=0o666)
    cb.add_chrdev("dev/urandom", major=1, minor=9, mode=0o666)
    cb.add_chrdev("dev/kmsg",    major=1, minor=11, mode=0o644)

    cb.add_file("bin/busybox", busybox_blob, mode=0o755)
    seen = {"busybox"}
    for app in BUSYBOX_APPLETS:
        if app in seen:
            continue
        seen.add(app)
        cb.add_symlink(f"bin/{app}", "busybox")

    cb.add_file("init", INIT_SCRIPT, mode=0o755)

    cpio_blob = cb.finalize()
    print(f"[make_initramfs] cpio archive: {len(cpio_blob)} bytes")

    compress = args.compress
    if compress is None:
        compress = "gzip" if out_path.suffix == ".gz" else "none"

    if compress == "gzip":
        with gzip.open(out_path, "wb", compresslevel=9) as f:
            f.write(cpio_blob)
    else:
        out_path.write_bytes(cpio_blob)
    size = out_path.stat().st_size
    print(f"[make_initramfs] wrote {out_path} ({size} bytes, compress={compress})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
