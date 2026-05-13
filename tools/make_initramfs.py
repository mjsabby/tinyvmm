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
# Output goes to /dev/kmsg (kernel polled-console) for boot logs and to
# /dev/hvc0 for the interactive shell session. With `console=hvc0` on the
# kernel cmdline, printk and shell stdout share the virtio-console TX queue.

/bin/busybox --install -s /bin
mount -t proc     proc  /proc    2>/dev/kmsg
mount -t sysfs    sysfs /sys     2>/dev/kmsg
mount -t devtmpfs devfs /dev     2>/dev/kmsg

log() { echo "[init] $*" > /dev/kmsg; }

log "=== tinyvmm init starting ==="
log "uname: $(uname -a)"

# --- /sys snapshot ------------------------------------------------------
log "--- /sys/bus/virtio/devices ---"
log "$(ls /sys/bus/virtio/devices 2>/dev/kmsg)"

# --- network interfaces -------------------------------------------------
ip link set lo up        2>/dev/kmsg
if [ -e /sys/class/net/eth0 ]; then
    ip link set eth0 up                       2>/dev/kmsg
    ip addr add 10.0.0.2/24 dev eth0          2>/dev/kmsg
    ip route add default via 10.0.0.1         2>/dev/kmsg
    log "eth0 up: $(ip -4 addr show eth0 | tr -d '\\n')"
    # Best-effort DNS via the gateway (NAT'd, see `New-NetNat` on host).
    echo 'nameserver 1.1.1.1' > /etc/resolv.conf
    echo 'nameserver 8.8.8.8' >> /etc/resolv.conf
else
    log "no eth0 (virtio-net driver did not bind)"
fi

# --- entropy from virtio-rng (sanity) -----------------------------------
if [ -c /dev/hwrng ]; then
    log "hwrng: $(head -c 16 /dev/hwrng | od -An -tx1 | tr -d '\\n ')"
fi

log "=== init complete; dropping to shell on hvc0 ==="

# --- interactive shell on /dev/hvc0 -------------------------------------
# Respawn-on-exit loop. PID 1 must never exit (kernel panics if it does).
# `setsid -c` makes the shell the session leader and grabs hvc0 as its
# controlling TTY so Ctrl+C / job control work.
if [ ! -c /dev/hvc0 ]; then
    log "FATAL: /dev/hvc0 missing, parking PID 1"
    exec cat
fi

# Friendly banner / prompt setup on first use.
cat > /etc/profile <<'EOF'
export PS1='tinyvmm# '
export PATH=/bin:/usr/bin:/sbin:/usr/sbin
alias ll='ls -la'
EOF

while true; do
    # Use `sh -l` so /etc/profile is sourced (PS1, PATH, aliases).
    setsid -c /bin/busybox sh -l </dev/hvc0 >/dev/hvc0 2>&1
    log "shell exited; respawning"
    sleep 1 2>/dev/kmsg || /bin/busybox usleep 200000 2>/dev/kmsg
done
"""


BUSYBOX_APPLETS = [
    "sh", "ash", "ls", "cat", "echo", "mount", "umount", "uname", "dmesg",
    "ip", "ping", "ifconfig", "hostname", "sleep", "usleep", "true", "false",
    "head", "tail", "ps", "kill", "mkdir", "rm", "cp", "mv", "ln", "find",
    "grep", "sed", "awk", "vi", "more", "less", "poweroff", "reboot", "halt",
    "modprobe", "insmod", "lsmod", "rmmod", "switch_root", "init", "free",
    "mknod", "chmod", "chown", "df", "du", "route", "ifup", "ifdown",
    "setsid", "tty", "stty", "env", "printenv", "clear", "od", "nslookup",
    "wget", "telnet", "nc", "ftpget", "tar", "gzip", "gunzip", "date",
    "uptime", "id", "whoami", "tee", "xargs", "which", "basename", "dirname",
    "sort", "uniq", "wc", "cut", "expr", "test", "[",
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
    cb.add_dir("tmp", mode=0o1777)
    cb.add_dir("usr", mode=0o755)
    cb.add_dir("usr/bin", mode=0o755)
    cb.add_dir("sbin", mode=0o755)
    cb.add_dir("usr/sbin", mode=0o755)

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
