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
    # WinTun backend (host=10.0.0.1, M16, local only).
    ip addr add 10.0.0.2/24  dev eth0         2>/dev/kmsg
    # Default route via the gateway. Both wintun (host=10.0.0.1) and
    # usernet (synthetic gateway=10.0.0.1) sit at .1, so this works
    # for both backends.
    ip route add default via 10.0.0.1         2>/dev/kmsg
    log "eth0 up: $(ip -4 addr show eth0 | tr -d '\\n')"
    # Best-effort DNS for any outbound traffic (NAT'd if the host has
    # a New-NetNat rule, see README).
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

# --- optional automated network test mode -------------------------------
# Enabled via kernel cmdline marker `tinyvmm.test=net`. Runs through ICMP,
# UDP DNS, and HTTP/TCP fetches against well-known endpoints, then halts
# so a watchdog-less host run can verify the usernet/wintun datapath
# without an interactive shell.
if grep -q 'tinyvmm.test=net' /proc/cmdline 2>/dev/null; then
    log "--- NETTEST start ---"

    log "+ ping -c 2 -W 2 10.0.0.1 (gateway)"
    ping -c 2 -W 2 10.0.0.1 2>&1 | while IFS= read -r line; do log "  $line"; done

    log "+ ping -c 2 -W 4 8.8.8.8 (real)"
    ping -c 2 -W 4 8.8.8.8 2>&1 | while IFS= read -r line; do log "  $line"; done

    log "+ nslookup example.com 1.1.1.1"
    nslookup example.com 1.1.1.1 2>&1 | while IFS= read -r line; do log "  $line"; done

    log "+ wget -q -O - -T 8 http://example.com/ | head -c 256"
    wget -q -O - -T 8 http://example.com/ 2>&1 | head -c 256 | \
        while IFS= read -r line; do log "  $line"; done
    log "wget exit=$?"

    log "--- NETTEST end ---"
    sync
    sleep 1
    poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
    # If those somehow returned, park.
    exec cat
fi

# --- optional inbound port-forward test mode ----------------------------
# Enabled via kernel cmdline marker `tinyvmm.test=portfwd`. Runs a tiny
# busybox httpd on guest port 8080 serving a known-body sentinel, parks
# for ~25s so the host side can curl http://<HOST_LISTEN>:<HOST_PORT>/
# and verify the sentinel, then halts.
if grep -q 'tinyvmm.test=portfwd' /proc/cmdline 2>/dev/null; then
    log "--- PORTFWD-TEST start ---"
    mkdir -p /tmp/www
    cat > /tmp/www/index.html <<EOF
tinyvmm portfwd ok
EOF
    log "+ httpd -p 8080 -h /tmp/www"
    httpd -p 8080 -h /tmp/www
    log "httpd started: $(pidof httpd)"
    # Park for 25s; host driver curls during this window.
    sleep 25
    log "--- PORTFWD-TEST end ---"
    sync
    poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
    exec cat
fi

# --- optional TSC-watchdog stress mode ----------------------------------
# Enabled via kernel cmdline marker `tinyvmm.test=tsc`. Spins one busy
# `yes`-into-/dev/null loop on every online CPU for ~20s to give Linux's
# clocksource watchdog (`clocksource_watchdog`, fires every 0.5 s) plenty
# of opportunities to observe TSC vs the secondary clocksource. Then
# dumps any watchdog/unstable/skew complaints in dmesg and the current
# clocksource selection, and powers off. With the Hyper-V Reference TSC
# page + HV_ACCESS_TSC_INVARIANT advertised, the kernel sets
# X86_FEATURE_TSC_RELIABLE and the watchdog leaves TSC alone.
if grep -q 'tinyvmm.test=tsc' /proc/cmdline 2>/dev/null; then
    log "--- TSC-WATCHDOG-TEST start ---"
    ncpu=$(nproc 2>/dev/null || echo 1)
    log "+ spawning $ncpu busy loops"
    for i in $(seq 1 "$ncpu"); do
        ( while :; do : ; done ) &
    done
    # Wait long enough for several watchdog cycles (default 0.5s tick).
    sleep 20
    log "--- TSC-WATCHDOG-TEST checking dmesg ---"
    # Look for the actual kernel watchdog complaints. Filter out our own
    # `[init]` log lines (which match 'WATCHDOG' as part of the banner)
    # before applying the substantive regex.
    if dmesg \
            | grep -v 'TSC-WATCHDOG-TEST' \
            | grep -iE 'clocksource_watchdog|Marking .*tsc.* unstable|skew is too large|tsc: Marking' \
            > /tmp/wd.log 2>&1; then
        log "TSC-WATCHDOG: FAIL (kernel watchdog complaints below)"
        while IFS= read -r line; do log "  $line"; done < /tmp/wd.log
    else
        log "TSC-WATCHDOG: no watchdog/unstable complaints (PASS)"
    fi
    log "current_clocksource=$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null)"
    log "available=$(cat /sys/devices/system/clocksource/clocksource0/available_clocksource 2>/dev/null)"
    log "--- TSC-WATCHDOG-TEST end ---"
    sync
    poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
    exec cat
fi

# --- optional virtio-blk real-workload test mode ------------------------
# Enabled via kernel cmdline marker `tinyvmm.test=blk`. The host harness
# attaches:
#   --drive <writable>           -> /dev/vda   (target for mkfs/dd/etc)
#   --drive <readonly>,readonly  -> /dev/vdb   (EROFS error-path test)
# Skips RO-specific phases if vdb isn't present. Exercises:
#   A. Raw R/W round-trip      (md5sum-verified integrity)
#   B. Seq throughput          (1 MiB writes + reads, conv=fsync)
#   C. Concurrent queue depth  (8 parallel dd writers; IOCP backpressure)
#   D. Random small-block I/O  (4 KiB writes at random offsets, fsync each)
#   E. ext2 round-trip         (mkfs + mount + write + sync + umount +
#                                remount + verify -- flush/barrier)
#   F. Read-only EROFS         (write to RO block dev -> EIO; mount RO +
#                                attempt write -> EROFS)
# Each phase logs `BLK <PHASE>: PASS` or `BLK <PHASE>: FAIL <reason>`.
# Final line is `BLK SUMMARY: <pass>/<total> phases passed`. The host
# driver greps for `BLK SUMMARY:` and asserts the counts match.
if grep -q 'tinyvmm.test=blk' /proc/cmdline 2>/dev/null; then
    log "--- BLK-TEST start ---"

    BLK_PASS=0
    BLK_FAIL=0
    pass() { log "BLK $1: PASS${2:+ ($2)}"; BLK_PASS=$((BLK_PASS+1)); }
    fail() { log "BLK $1: FAIL $2"; BLK_FAIL=$((BLK_FAIL+1)); }

    # Best-effort drive discovery.
    DRV_RW=/dev/vda
    DRV_RO=/dev/vdb

    if [ ! -b "$DRV_RW" ]; then
        log "BLK FATAL: no writable virtio-blk at $DRV_RW"
        log "available block devices: $(ls /dev/vd? 2>/dev/null)"
        log "BLK SUMMARY: 0/0 phases passed (no target disk)"
        sync
        poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
        exec cat
    fi

    RW_SIZE_BYTES=$(blockdev --getsize64 "$DRV_RW" 2>/dev/null || echo 0)
    RW_SIZE_MB=$((RW_SIZE_BYTES / 1024 / 1024))
    log "target: $DRV_RW ($RW_SIZE_MB MiB)"
    if [ -b "$DRV_RO" ]; then
        RO_SIZE_BYTES=$(blockdev --getsize64 "$DRV_RO" 2>/dev/null || echo 0)
        log "ro-target: $DRV_RO ($((RO_SIZE_BYTES/1024/1024)) MiB, sysfs ro=$(cat /sys/class/block/vdb/ro 2>/dev/null))"
    else
        log "ro-target: <none> (phase F partially skipped)"
    fi

    # ---- Phase A: Raw R/W round-trip ----
    # Write 16 MiB pseudo-random pattern, fsync, drop the guest page
    # cache, then read back -- so the readback bytes must come from
    # virtio-blk IN requests rather than the guest cache. busybox dd in
    # this build does not support iflag/oflag=direct, so we use
    # drop_caches instead of O_DIRECT.
    log "+ phase A: raw R/W round-trip (16 MiB, drop_caches readback)"
    A_BYTES=$((16 * 1024 * 1024))
    if [ "$RW_SIZE_BYTES" -lt "$A_BYTES" ]; then
        fail A "disk too small ($RW_SIZE_BYTES < $A_BYTES)"
    else
        dd if=/dev/urandom of=/tmp/A.pat bs=1M count=16 status=none 2>/dev/kmsg
        SRC_MD5=$(md5sum /tmp/A.pat | awk '{print $1}')
        if ! dd if=/tmp/A.pat of="$DRV_RW" bs=1M count=16 conv=fsync \
                status=none 2>/dev/kmsg; then
            fail A "write to $DRV_RW errored"
        else
            sync
            echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
            DST_MD5=$(dd if="$DRV_RW" bs=1M count=16 \
                        status=none 2>/dev/kmsg | md5sum | awk '{print $1}')
            if [ "$SRC_MD5" = "$DST_MD5" ]; then
                pass A "md5=$SRC_MD5"
            else
                fail A "md5 mismatch src=$SRC_MD5 dst=$DST_MD5"
            fi
        fi
        rm -f /tmp/A.pat
    fi

    # ---- Phase B: Sequential throughput ----
    # 64 MiB seq write with conv=fsync then drop_caches + read.
    log "+ phase B: sequential throughput (conv=fsync + drop_caches)"
    B_TARGET_MB=64
    if [ "$RW_SIZE_MB" -lt "$B_TARGET_MB" ]; then B_TARGET_MB=$RW_SIZE_MB; fi
    if [ "$B_TARGET_MB" -lt 4 ]; then
        fail B "disk too small ($B_TARGET_MB MiB)"
    else
        WSTART=$(cat /proc/uptime | awk '{print $1}')
        if dd if=/dev/zero of="$DRV_RW" bs=1M count="$B_TARGET_MB" \
                conv=fsync status=none 2>/dev/kmsg; then
            WEND=$(cat /proc/uptime | awk '{print $1}')
            WMS=$(awk -v a="$WSTART" -v b="$WEND" 'BEGIN{printf "%.0f", (b-a)*1000}')

            sync
            echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
            RSTART=$(cat /proc/uptime | awk '{print $1}')
            if dd if="$DRV_RW" of=/dev/null bs=1M count="$B_TARGET_MB" \
                    status=none 2>/dev/kmsg; then
                REND=$(cat /proc/uptime | awk '{print $1}')
                RMS=$(awk -v a="$RSTART" -v b="$REND" 'BEGIN{printf "%.0f", (b-a)*1000}')
                # Avoid divide-by-zero in busybox awk integer mode.
                WMBS=$(awk -v mb="$B_TARGET_MB" -v ms="$WMS" \
                        'BEGIN{if(ms<=0)ms=1; printf "%.1f", mb*1000/ms}')
                RMBS=$(awk -v mb="$B_TARGET_MB" -v ms="$RMS" \
                        'BEGIN{if(ms<=0)ms=1; printf "%.1f", mb*1000/ms}')
                pass B "w=${WMBS}MB/s r=${RMBS}MB/s (${B_TARGET_MB}MiB)"
            else
                fail B "read errored"
            fi
        else
            fail B "write errored"
        fi
    fi

    # ---- Phase C: Concurrent queue-depth stress ----
    # 8 parallel dd writers, each writes 4 MiB at a distinct offset with
    # conv=fsync. All 8 fsyncs land roughly together, so the host
    # backend should see multiple in-flight FLUSH ops -- and the
    # writeback ops behind them may also be concurrent. The host
    # backend's max-outstanding-requests counter is logged at shutdown
    # so the host harness can assert `max_inflight > 1` actually
    # happened.
    log "+ phase C: concurrent writers (queue depth)"
    NPAR=8
    SLICE_MB=4
    NEED_MB=$((NPAR * SLICE_MB))
    if [ "$RW_SIZE_MB" -lt "$NEED_MB" ]; then
        fail C "disk too small (need $NEED_MB MiB)"
    else
        mkdir -p /tmp/C
        rm -f /tmp/C/*
        for i in $(seq 0 $((NPAR-1))); do
            (
                dd if=/dev/urandom of="/tmp/C/p$i.bin" bs=1M count="$SLICE_MB" \
                    status=none 2>/dev/null
                dd if="/tmp/C/p$i.bin" of="$DRV_RW" bs=1M count="$SLICE_MB" \
                    seek="$((i * SLICE_MB))" conv=fsync \
                    status=none 2>/dev/null
                echo "$?" > "/tmp/C/exit$i"
            ) &
        done
        wait
        sync
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        C_FAIL=""
        for i in $(seq 0 $((NPAR-1))); do
            ec=$(cat "/tmp/C/exit$i" 2>/dev/null)
            if [ "$ec" != "0" ]; then C_FAIL="$C_FAIL writer$i=$ec"; fi
        done
        if [ -n "$C_FAIL" ]; then
            fail C "writer error:$C_FAIL"
        else
            C_MISMATCH=""
            for i in $(seq 0 $((NPAR-1))); do
                src_md5=$(md5sum "/tmp/C/p$i.bin" | awk '{print $1}')
                dst_md5=$(dd if="$DRV_RW" bs=1M count="$SLICE_MB" \
                            skip="$((i * SLICE_MB))" \
                            status=none 2>/dev/null | \
                          md5sum | awk '{print $1}')
                if [ "$src_md5" != "$dst_md5" ]; then
                    C_MISMATCH="$C_MISMATCH slice$i"
                fi
            done
            if [ -n "$C_MISMATCH" ]; then
                fail C "verify mismatch:$C_MISMATCH"
            else
                pass C "$NPAR writers @ ${SLICE_MB}MiB each, all md5 OK"
            fi
        fi
        rm -rf /tmp/C
    fi

    # ---- Phase D: Random small-block I/O ----
    # 64 random 4 KiB writes at fsync'd offsets, each verified after a
    # cache drop. Random offsets come from /dev/urandom (not awk's
    # srand() which can return the same value within a single second).
    log "+ phase D: random 4 KiB writes (64 ops)"
    if [ "$RW_SIZE_BYTES" -lt $((1024 * 1024)) ]; then
        fail D "disk too small"
    else
        D_NUMOPS=64
        D_BLK_BYTES=4096
        D_NUM_BLOCKS=$((RW_SIZE_BYTES / D_BLK_BYTES))
        # Generate $D_NUMOPS random 4-byte values from /dev/urandom, convert
        # each to an offset in [0, D_NUM_BLOCKS).
        D_OFFSETS=$(dd if=/dev/urandom bs=4 count=$D_NUMOPS status=none 2>/dev/null \
                    | od -An -tu4 -w4 \
                    | awk -v n="$D_NUM_BLOCKS" '{print $1 % n}')
        D_FAIL=""
        i=0
        for OFF in $D_OFFSETS; do
            i=$((i+1))
            dd if=/dev/urandom of=/tmp/D.blk bs="$D_BLK_BYTES" count=1 \
                status=none 2>/dev/null
            if ! dd if=/tmp/D.blk of="$DRV_RW" bs="$D_BLK_BYTES" count=1 \
                    seek="$OFF" conv=fsync status=none 2>/dev/null; then
                D_FAIL="op$i:write_err_at_$OFF"; break
            fi
            echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
            S=$(md5sum /tmp/D.blk | awk '{print $1}')
            D=$(dd if="$DRV_RW" bs="$D_BLK_BYTES" count=1 skip="$OFF" \
                    status=none 2>/dev/null | md5sum | awk '{print $1}')
            if [ "$S" != "$D" ]; then
                D_FAIL="op$i:mismatch_at_$OFF"; break
            fi
        done
        rm -f /tmp/D.blk
        if [ -n "$D_FAIL" ]; then
            fail D "$D_FAIL"
        else
            pass D "$D_NUMOPS random 4KiB writes verified"
        fi
    fi

    # ---- Phase E: ext2 mkfs + mount + flush + remount + verify ----
    # Tests filesystem-level flush/barrier: any data we wrote then
    # synced must survive an umount + remount cycle. The host harness
    # additionally verifies the marker.txt content in the raw disk
    # image after VM exit (proves data made it past the host page cache
    # to the BlockFile backing file).
    log "+ phase E: ext2 mkfs + flush + remount round-trip"
    if ! mkfs.ext2 -F -q "$DRV_RW" > /dev/null 2>/tmp/E.err; then
        fail E "mkfs.ext2 failed: $(cat /tmp/E.err | head -1)"
    else
        mkdir -p /mnt/E
        if ! mount -t ext2 "$DRV_RW" /mnt/E 2>/tmp/E.err; then
            fail E "mount: $(cat /tmp/E.err | head -1)"
        else
            # Marker is a fixed sentinel the host harness can grep for in
            # the raw disk image (proves data hit the host file, not just
            # the guest cache).
            echo 'TINYVMM_BLK_TEST_MARKER_v1' > /mnt/E/marker.txt
            dd if=/dev/urandom of=/mnt/E/payload.bin bs=1M count=4 \
                status=none 2>/dev/null
            MARK_MD5=$(md5sum /mnt/E/marker.txt | awk '{print $1}')
            PAY_MD5=$(md5sum /mnt/E/payload.bin | awk '{print $1}')
            sync
            if ! umount /mnt/E 2>/tmp/E.err; then
                fail E "umount: $(cat /tmp/E.err | head -1)"
            else
                if ! mount -t ext2 "$DRV_RW" /mnt/E 2>/tmp/E.err; then
                    fail E "remount: $(cat /tmp/E.err | head -1)"
                else
                    MARK2=$(md5sum /mnt/E/marker.txt 2>/dev/null | awk '{print $1}')
                    PAY2=$(md5sum /mnt/E/payload.bin 2>/dev/null | awk '{print $1}')
                    if [ "$MARK_MD5" != "$MARK2" ] || [ "$PAY_MD5" != "$PAY2" ]; then
                        fail E "verify mismatch marker=$MARK_MD5/$MARK2 pay=$PAY_MD5/$PAY2"
                    else
                        if ! umount /mnt/E 2>/dev/null; then
                            fail E "second umount"
                        elif ! mount -t ext2 -o ro "$DRV_RW" /mnt/E 2>/tmp/E.err; then
                            fail E "ro-mount: $(cat /tmp/E.err | head -1)"
                        else
                            if echo x > /mnt/E/should_fail.txt 2>/dev/null; then
                                fail E "write succeeded on -o ro mount"
                            else
                                pass E "remount verified + -o ro -> EROFS"
                            fi
                            umount /mnt/E 2>/dev/null
                        fi
                    fi
                fi
            fi
        fi
        rm -f /tmp/E.err
    fi

    # ---- Phase F: Read-only block-device error paths (guest-visible) ----
    # NOTE: virtio-blk advertises the RO feature bit so Linux's block
    # layer marks /dev/vdc read-only and refuses writes there BEFORE
    # they reach virtio. The actual backend reject path
    # (`type == OUT && backend.readonly()`) is covered by the host-side
    # `--virtio-blk-ro-test` mode, not here. This phase only validates
    # guest-visible RO surfaces.
    log "+ phase F: read-only error paths (guest-visible)"
    if [ ! -b "$DRV_RO" ]; then
        log "  $DRV_RO absent; phase F skipped (no RO drive)"
        log "BLK F: SKIP (no RO drive)"
    else
        F_SYSFS_RO=$(cat /sys/class/block/vdb/ro 2>/dev/null)
        if [ "$F_SYSFS_RO" != "1" ]; then
            fail F "sysfs ro=$F_SYSFS_RO (expected 1)"
        else
            F_ERR=""
            # Raw write to the RO block device must fail. Linux gates on
            # the RO bit in the block-layer submit path.
            if dd if=/dev/zero of="$DRV_RO" bs=512 count=1 status=none 2>/dev/null; then
                F_ERR="${F_ERR}direct-write-succeeded "
            fi
            # blockdev --getro must also report 1.
            BD_RO=$(blockdev --getro "$DRV_RO" 2>/dev/null)
            if [ "$BD_RO" != "1" ]; then
                F_ERR="${F_ERR}blockdev-getro=$BD_RO "
            fi
            # A READ from the RO device must succeed (just verifies the
            # backend's IN path still works on a RO file).
            if ! dd if="$DRV_RO" of=/dev/null bs=512 count=1 status=none 2>/dev/null; then
                F_ERR="${F_ERR}read-failed "
            fi
            if [ -n "$F_ERR" ]; then
                fail F "$F_ERR"
            else
                pass F "sysfs-ro=1 + blockdev-getro=1 + write refused + read OK"
            fi
        fi
    fi

    log "--- BLK-TEST end ---"
    log "BLK SUMMARY: ${BLK_PASS}/$((BLK_PASS + BLK_FAIL)) phases passed"
    sync
    sleep 1
    # Ask tinyvmm to shut down cleanly via the host-side hvc0 sentinel
    # detector. This works even when the kernel was built without ACPI
    # (i.e. `poweroff` falls back to STI;HLT and never produces a real
    # halt VM-exit, leaving tinyvmm spinning idle indefinitely).
    log "=== tinyvmm shutdown requested ==="
    sleep 1
    poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
    exec cat
fi

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
export TERM=xterm-256color
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
    "sort", "uniq", "wc", "cut", "expr", "test", "[", "httpd",
    # virtio-blk test surface
    "dd", "md5sum", "sha256sum", "cmp", "sync", "fsync", "mkfs.ext2",
    "mke2fs", "mountpoint", "stat", "truncate", "blkid", "blockdev",
    "nproc", "seq", "time", "printf",
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
