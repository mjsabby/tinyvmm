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

# --- optional outbound usernet-TSI HTTP test mode -----------------------
# Enabled via kernel cmdline marker `tinyvmm.test=usernet-tsi`. Runs a
# chain of HTTP GETs against the host Python server at
# <TINYVMM_USERNET_TSI_HOST>:<TINYVMM_USERNET_TSI_PORT> (passed via the
# kernel cmdline by tools/usernet_tsi_test.py) and asserts byte counts +
# concurrent connections. See tools/usernet_tsi_test.py for the host-
# side driver (M34.7).
#
# Phases:
#   A   GET /hello              exact body match (small)
#   B   GET /echo/1024          byte count check (medium)
#   C   GET /echo/65536         byte count check (64 KiB, segments + WS)
#   D   GET /echo/524288        byte count check (512 KiB, many segments)
#   E   4 parallel GET /echo/16384  concurrent conns
#   F   GET to a closed port    expect failure (RST / abort path)
if grep -q 'tinyvmm.test=usernet-tsi' /proc/cmdline 2>/dev/null; then
    log "--- USERNET-TSI-TEST start ---"
    host=$(cat /proc/cmdline | tr ' ' '\\n' | grep '^TINYVMM_USERNET_TSI_HOST=' | cut -d= -f2)
    port=$(cat /proc/cmdline | tr ' ' '\\n' | grep '^TINYVMM_USERNET_TSI_PORT=' | cut -d= -f2)
    closed_port=$(cat /proc/cmdline | tr ' ' '\\n' | grep '^TINYVMM_USERNET_TSI_CLOSED_PORT=' | cut -d= -f2)
    log "host=${host} port=${port} closed_port=${closed_port}"
    if [ -z "${host}" ] || [ -z "${port}" ] || [ -z "${closed_port}" ]; then
        log "USERNET-TSI SUMMARY: 0/0 phases passed (missing cmdline args)"
        sync
        poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
        exec cat
    fi
    base="http://${host}:${port}"
    pass=0
    total=0

    # Phase A: tiny GET, exact body match.
    total=$((total + 1))
    bodyA=$(wget -q -O - -T 8 -t 1 "${base}/hello" 2>/dev/null)
    if [ "${bodyA}" = "tinyvmm-tsi-hello" ]; then
        log "USERNET-TSI A: hello OK"
        pass=$((pass + 1))
    else
        log "USERNET-TSI A: hello FAIL (got '${bodyA}')"
    fi

    # Phase B: medium GET, byte count.
    total=$((total + 1))
    szB=$(wget -q -O - -T 8 -t 1 "${base}/echo/1024" 2>/dev/null | wc -c)
    if [ "${szB}" = "1024" ]; then
        log "USERNET-TSI B: echo/1024 OK"
        pass=$((pass + 1))
    else
        log "USERNET-TSI B: echo/1024 FAIL (got ${szB} bytes)"
    fi

    # Phase C: 64 KiB, exercises segments + window scaling.
    total=$((total + 1))
    szC=$(wget -q -O - -T 16 -t 1 "${base}/echo/65536" 2>/dev/null | wc -c)
    if [ "${szC}" = "65536" ]; then
        log "USERNET-TSI C: echo/65536 OK"
        pass=$((pass + 1))
    else
        log "USERNET-TSI C: echo/65536 FAIL (got ${szC} bytes)"
    fi

    # Phase D: 512 KiB, many segments + many ACKs.
    total=$((total + 1))
    szD=$(wget -q -O - -T 30 -t 1 "${base}/echo/524288" 2>/dev/null | wc -c)
    if [ "${szD}" = "524288" ]; then
        log "USERNET-TSI D: echo/524288 OK"
        pass=$((pass + 1))
    else
        log "USERNET-TSI D: echo/524288 FAIL (got ${szD} bytes)"
    fi

    # Phase E: 4 parallel GETs to exercise concurrent conns.
    total=$((total + 1))
    rm -f /tmp/par_* 2>/dev/null
    for i in 1 2 3 4; do
        ( wget -q -O /tmp/par_${i} -T 16 -t 1 "${base}/echo/16384" 2>/dev/null \
            && echo ok > /tmp/par_${i}.flag ) &
    done
    wait
    par_ok=0
    for i in 1 2 3 4; do
        if [ -f /tmp/par_${i}.flag ]; then
            sz=$(wc -c < /tmp/par_${i})
            if [ "${sz}" = "16384" ]; then
                par_ok=$((par_ok + 1))
            fi
        fi
    done
    if [ "${par_ok}" = "4" ]; then
        log "USERNET-TSI E: 4-parallel-16K OK"
        pass=$((pass + 1))
    else
        log "USERNET-TSI E: 4-parallel-16K FAIL (${par_ok}/4)"
    fi

    # Phase F: connect to a port we KNOW is closed -> expect failure.
    # The host driver binds + closes a port pre-launch and passes it as
    # TINYVMM_USERNET_TSI_CLOSED_PORT. The engine's Winsock connect()
    # will get ECONNREFUSED and call AbortConn(), which queues a RST in
    # the TCB's TX ring and emits it to the guest. wget sees that as a
    # failed fetch. -t 1 keeps wget from retrying.
    total=$((total + 1))
    if wget -q -O /dev/null -T 6 -t 1 "http://${host}:${closed_port}/x" 2>/dev/null; then
        log "USERNET-TSI F: connect-refused FAIL (wget unexpectedly succeeded)"
    else
        log "USERNET-TSI F: connect-refused OK (wget failed as expected)"
        pass=$((pass + 1))
    fi

    log "USERNET-TSI SUMMARY: ${pass}/${total} phases passed"
    sync
    # Park ~65 s so TSI's 2*MSL TIME_WAIT (60 s) elapses and the engine's
    # graceful-close reconcile (M34.6) reaps every TCB before tinyvmm
    # shuts down. Without this the engine summary would show live>0 and
    # graceful_closes=0 -- the wgets finish way faster than TIME_WAIT.
    log "USERNET-TSI: parking 65 s for TIME_WAIT drain"
    sleep 65
    log "=== tinyvmm shutdown requested ==="
    sleep 1
    poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
    exec cat
fi

# --- optional usernet networking benchmark ------------------------------
# Enabled via kernel cmdline marker `tinyvmm.test=usernet-bench`.
# Driven by tools/usernet_bench.py. Three measurements per run:
#   1. Ping latency: busybox ping -c N -i 0.01 against the gateway
#      (10.0.0.1, terminated by the usernet ARP responder). Reports
#      min/avg/max round-trip; computes p99 from the per-packet lines.
#   2. TCP single-stream throughput: 3 back-to-back wget downloads of
#      a synthetic /bytes/SIZE endpoint on the host's Python bench
#      server. Computed as (size * 8000) / delta_ns Mbps.
#   3. (Implicit) engine counters via the [usernet-tsi] summary line
#      that tinyvmm prints on shutdown.
#
# Cmdline vars (set by the host driver):
#   TINYVMM_BENCH_HOST       host LAN IPv4 the bench HTTP server binds to
#   TINYVMM_BENCH_PORT       bench HTTP server port
#   TINYVMM_BENCH_SIZE       per-run TCP transfer size in bytes
#   TINYVMM_BENCH_PINGCOUNT  number of pings (default 100)
if grep -q 'tinyvmm.test=usernet-bench' /proc/cmdline 2>/dev/null; then
    log "--- USERNET-BENCH start ---"
    host=$(cat /proc/cmdline | tr ' ' '\\n' | grep '^TINYVMM_BENCH_HOST=' | cut -d= -f2)
    port=$(cat /proc/cmdline | tr ' ' '\\n' | grep '^TINYVMM_BENCH_PORT=' | cut -d= -f2)
    sizebytes=$(cat /proc/cmdline | tr ' ' '\\n' | grep '^TINYVMM_BENCH_SIZE=' | cut -d= -f2)
    pingcount=$(cat /proc/cmdline | tr ' ' '\\n' | grep '^TINYVMM_BENCH_PINGCOUNT=' | cut -d= -f2)
    [ -z "${pingcount}" ] && pingcount=100
    log "host=${host} port=${port} size=${sizebytes} pingcount=${pingcount}"
    if [ -z "${host}" ] || [ -z "${port}" ] || [ -z "${sizebytes}" ]; then
        log "BENCH SUMMARY: 0/0 (missing cmdline args)"
        sync
        poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
        exec cat
    fi

    # ---- Phase 1: ping latency ----------------------------------------
    # 10 ms inter-packet spacing keeps the test under a second for
    # pingcount=100. busybox ping emits one "time=X ms" line per reply
    # plus a final "min/avg/max" summary line.
    log "BENCH PING start (count=${pingcount})"
    ping_log=/tmp/bench_ping.log
    ping -c "${pingcount}" -i 0.01 10.0.0.1 > "${ping_log}" 2>&1
    # Forward per-packet RTT lines + summary so the host driver can
    # compute p99 (busybox doesn't).
    grep 'time=' "${ping_log}" | while IFS= read -r line; do
        log "BENCH PING RTT $line"
    done
    summary=$(grep 'min/avg/max' "${ping_log}")
    log "BENCH PING SUMMARY ${summary}"

    # ---- Phase 2: TCP single-stream throughput ------------------------
    # busybox `date +%s%N` does NOT support %N -- returns the literal "N",
    # giving delta_ns=0. Use /proc/uptime via awk for microsecond
    # precision instead. We do 1 untimed warm-up run (drops some bytes
    # consistently due to TCP slow-start / first-TCB cold cache /
    # Python BaseHTTPServer first-request overhead) before the 3 measured
    # runs.
    url="http://${host}:${port}/bytes/${sizebytes}"
    log "BENCH TCP url=${url}"
    log "BENCH TCP warmup ..."
    wget -q -O /tmp/bench_dl -T 60 -t 1 "${url}" >/dev/null 2>&1
    rm -f /tmp/bench_dl
    for i in 1 2 3; do
        rm -f /tmp/bench_dl /tmp/bench_wget.err
        t0=$(awk '{print int($1 * 1000000)}' /proc/uptime)
        wget -O /tmp/bench_dl -T 60 -t 1 "${url}" 2>/tmp/bench_wget.err
        rc=$?
        t1=$(awk '{print int($1 * 1000000)}' /proc/uptime)
        delta_us=$((t1 - t0))
        got=$(wc -c < /tmp/bench_dl 2>/dev/null)
        [ -z "${got}" ] && got=0
        if [ "${delta_us}" -gt 0 ] && [ "${rc}" = "0" ] && [ "${got}" = "${sizebytes}" ]; then
            # bytes * 8 bits/byte / delta_us = Mbps
            #   (since 1 bit/us == 1 Mbps)
            mbps=$((sizebytes * 8 / delta_us))
        else
            mbps=0
        fi
        log "BENCH TCP run=${i} rc=${rc} bytes=${sizebytes} got=${got} delta_us=${delta_us} mbps=${mbps}"
        if [ "${rc}" != "0" ] || [ "${got}" != "${sizebytes}" ]; then
            log "BENCH TCP run=${i} wget_err: $(tr '\\n' '|' < /tmp/bench_wget.err | cut -c1-200)"
        fi
        rm -f /tmp/bench_dl /tmp/bench_wget.err
    done

    log "BENCH SUMMARY: done"
    log "--- USERNET-BENCH end ---"
    sync
    # Park 65 s so TSI's 2*MSL TIME_WAIT (60 s) elapses; otherwise the
    # engine summary shows live>0 / graceful=0 because the wget TCBs
    # haven't reached CLOSED yet.
    log "USERNET-BENCH: parking 65 s for TIME_WAIT drain"
    sleep 65
    log "=== tinyvmm shutdown requested ==="
    sleep 1
    poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
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

# --- optional snapshot save/restore round-trip test ---------------------
# Enabled via kernel cmdline marker `tinyvmm.test=snapshot`. The host
# harness drives two distinct tinyvmm invocations against the same
# initramfs + kernel:
#
#   Phase 1 (--save): tinyvmm --pvh-run --save snap.tvm ...
#     - Guest /init logs "SNAP-TEST: pre-trigger sentinel".
#     - Guest sleeps briefly to let the console TX queue drain past the
#       sentinel BEFORE we trigger snapshot capture. The snapshot
#       captures whatever bytes are still queued in the virtio-console
#       state, so without the drain the sentinel could re-appear on
#       restore even though /init does not re-execute that line.
#     - Guest execs /bin/cpuid_trigger, a 136-byte hand-rolled static
#       ELF that issues:   mov eax, 0x4000DE57 ; cpuid ; sys_exit(0).
#     - The host catches the magic-leaf CPUID, drains blk, calls
#       WriteSnapshotFile() (which captures vCPU regs at post-CPUID
#       RIP), and exits 0. /init never logs POST-RESTORE-CONTINUE
#       during the save phase.
#
#   Phase 2 (--restore): tinyvmm --restore snap.tvm
#     - vCPU resumes at post-CPUID RIP inside /bin/cpuid_trigger.
#     - cpuid_trigger executes sys_exit(0); the parent /init shell's
#       wait() returns rc=0; /init prints POST-RESTORE-CONTINUE.
#     - /init prints the shutdown sentinel so the host's serial
#       watcher (see main.cpp:2585 and 3744) tears down gracefully
#       even though there is no ACPI poweroff path in tinyvmm.
if grep -q 'tinyvmm.test=snapshot' /proc/cmdline 2>/dev/null; then
    log "--- SNAP-TEST start ---"
    sync
    log "SNAP-TEST: pre-trigger sentinel"
    # Drain the virtio-console TX queue past the sentinel before we
    # snapshot. Without this, the sentinel can survive the round-trip
    # via the captured console state and re-appear in Phase 2 output,
    # confusing assertions about "post-restore continue is the only
    # line".
    sleep 1
    /bin/cpuid_trigger
    rc=$?
    # Reachable only after restore; the save run captures state at the
    # CPUID instruction boundary and exits the host process before
    # this line ever executes in the save invocation.
    log "SNAP-TEST: POST-RESTORE-CONTINUE rc=$rc"
    sync
    sleep 1
    log "=== tinyvmm shutdown requested ==="
    sleep 1
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

# --- optional virtio-9p Phase-2 file-ops smoke ----------------------------
# Enabled via kernel cmdline marker `tinyvmm.test=p9`. The host harness
# attaches one --virtio-9p-share host=p9-test/ exposing a fixture with:
#   foo.txt           - hello-from-host text
#   bar.txt           - second-file text
#   subdir/nested.txt - nested text
# Phase 2 implements the full Win32-backed protocol; this block exercises
# ls/cat/echo/mkdir/rm/rename round-trip in both directions.
if grep -q 'tinyvmm.test=p9' /proc/cmdline 2>/dev/null; then
    log "--- P9-TEST start ---"

    P9_PASS=0
    P9_FAIL=0
    p9_pass() { log "P9 $1: PASS${2:+ ($2)}"; P9_PASS=$((P9_PASS+1)); }
    p9_fail() { log "P9 $1: FAIL $2"; P9_FAIL=$((P9_FAIL+1)); }

    # Phase 1: driver bind.
    if [ -d /sys/bus/virtio/drivers/9pnet_virtio ]; then
        BOUND_COUNT=$(ls -1 /sys/bus/virtio/drivers/9pnet_virtio 2>/dev/null | \
                      grep -c '^virtio' || echo 0)
        p9_pass driver-bind "9pnet_virtio bound to $BOUND_COUNT device(s)"
    else
        p9_fail driver-bind "/sys/bus/virtio/drivers/9pnet_virtio missing"
    fi

    # Phase 2: mount.
    mkdir -p /mnt/p9
    log "+ mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 host /mnt/p9"
    if mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 \
              host /mnt/p9 2>/dev/kmsg; then
        p9_pass mount "tag=host -> /mnt/p9"
        log "mount table:"
        mount | grep -F '/mnt/p9' | while IFS= read -r line; do log "  $line"; done

        # Phase 3: ls must show the fixture entries.
        LS_OUT=$(ls /mnt/p9 2>&1)
        log "+ ls /mnt/p9:"
        echo "$LS_OUT" | while IFS= read -r line; do log "  $line"; done
        if echo "$LS_OUT" | grep -q foo.txt && \
           echo "$LS_OUT" | grep -q bar.txt && \
           echo "$LS_OUT" | grep -q subdir; then
            p9_pass readdir "foo.txt + bar.txt + subdir all visible"
        else
            p9_fail readdir "missing one or more fixture entries"
        fi

        # Phase 4: cat must read host file content correctly.
        FOO=$(cat /mnt/p9/foo.txt 2>/dev/kmsg)
        if [ "$FOO" = "hello from host" ]; then
            p9_pass read-host "foo.txt content matches"
        else
            p9_fail read-host "got [$FOO]"
        fi

        # Phase 5: recursive read of subdir.
        NESTED=$(cat /mnt/p9/subdir/nested.txt 2>/dev/kmsg)
        if [ "$NESTED" = "nested" ]; then
            p9_pass walk-subdir "subdir/nested.txt readable via Twalk"
        else
            p9_fail walk-subdir "got [$NESTED]"
        fi

        # Phase 6: guest creates a file; host should see it. We also
        # remove it at end so this whole test is rerunnable on the
        # same host fixture without permanently mutating it.
        if echo "guest-wrote" > /mnt/p9/guest.txt 2>/dev/kmsg && \
           [ "$(cat /mnt/p9/guest.txt 2>/dev/null)" = "guest-wrote" ]; then
            p9_pass write-create "guest.txt created + readback ok"
        else
            p9_fail write-create "could not create or readback guest.txt"
        fi

        # Phase 7: mkdir + rmdir.
        if mkdir /mnt/p9/newdir 2>/dev/kmsg && \
           [ -d /mnt/p9/newdir ] && \
           rmdir /mnt/p9/newdir 2>/dev/kmsg && \
           [ ! -d /mnt/p9/newdir ]; then
            p9_pass mkdir-rmdir "newdir create+remove ok"
        else
            p9_fail mkdir-rmdir "mkdir/rmdir round-trip failed"
        fi

        # Phase 8: rename via mv, then rm (round-trip; leaves no debris).
        if [ -f /mnt/p9/guest.txt ] && \
           mv /mnt/p9/guest.txt /mnt/p9/renamed.txt 2>/dev/kmsg && \
           [ -f /mnt/p9/renamed.txt ] && \
           [ ! -f /mnt/p9/guest.txt ] && \
           rm /mnt/p9/renamed.txt 2>/dev/kmsg && \
           [ ! -f /mnt/p9/renamed.txt ]; then
            p9_pass rename-unlink "guest.txt -> renamed.txt + rm ok"
        else
            p9_fail rename-unlink "rename or unlink failed"
            rm -f /mnt/p9/guest.txt /mnt/p9/renamed.txt 2>/dev/null || true
        fi

        # Phase 9: clean umount (no -l: requires real Tclunk on each fid).
        if umount /mnt/p9 2>/dev/kmsg; then
            p9_pass umount "clean umount"
        else
            p9_fail umount "umount failed (likely a fid leak)"
            umount -l /mnt/p9 2>/dev/null || true
        fi
    else
        p9_fail mount "mount syscall failed"
    fi

    log "--- P9-TEST end ---"
    log "P9 SUMMARY: ${P9_PASS}/$((P9_PASS + P9_FAIL)) phases passed"
    sync
    sleep 1
    log "=== tinyvmm shutdown requested ==="
    sleep 1
    poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
    exec cat
fi

# --- optional virtio-9p end-to-end harness mode ---------------------------
# Enabled via kernel cmdline marker `tinyvmm.test=9p` (note: distinct from
# the older `tinyvmm.test=p9` smoke block, which targets the hand-staged
# p9-test/ fixture). This block is driven by tools/p9_test.py which stages
# a deterministic tree under workdir/p9-share/ plus a sha256sum manifest
# at .manifest.sha256:
#
#   .manifest.sha256                  -- 105 lines, busybox sha256sum -c format
#   empty.bin                         -- 0 bytes
#   one.bin                           -- 1 byte
#   small.bin                         -- 4096 bytes (page boundary)
#   large.bin                         -- 1 MiB (crosses msize=512000 cap)
#   many/file000.bin .. file099.bin   -- 100 files (readdir + open stress)
#   subdir/nested.bin                 -- nested-dir walk target
#
# Test phases (15 total):
#   1.  driver-bind     -- 9pnet_virtio bound to >= 1 device
#   2.  mount           -- mount -t 9p succeeds
#   3.  manifest-readable -- .manifest.sha256 exists and is non-empty
#   4.  sha256-bulk     -- sha256sum -c .manifest.sha256 returns 0 +
#                          ": OK$" line count == 105
#   5.  empty-file      -- stat size == 0
#   6.  large-file      -- re-hash 1 MiB file matches manifest
#   7.  many-files      -- ls many/ count == 100
#   8.  nested-dir      -- sha256 of subdir/nested.bin matches manifest
#   9.  write-create    -- echo > guest_wrote.txt + readback (host-visible)
#   10. create-delete   -- touch + rm round-trip
#   11. mkdir-rmdir     -- mkdir + rmdir round-trip
#   12. rename-roundtrip-- mv a -> b + rm b
#   13. truncate        -- printf > f; : > f; stat size == 0 (Tsetattr size)
#   14. append          -- printf > f; printf >> f; readback (O_APPEND)
#   15. umount          -- clean umount, no -l fallback
#
# Prints `9P SUMMARY: X/Y phases passed` and the tinyvmm shutdown sentinel.
if grep -q 'tinyvmm.test=9p' /proc/cmdline 2>/dev/null; then
    log "--- 9P-HARNESS start ---"

    NP_PASS=0
    NP_FAIL=0
    np_pass() { log "P9 $1: PASS${2:+ ($2)}"; NP_PASS=$((NP_PASS+1)); }
    np_fail() { log "P9 $1: FAIL $2"; NP_FAIL=$((NP_FAIL+1)); }

    EXPECTED_MANIFEST_LINES=105

    # Phase 1: driver-bind.
    if [ -d /sys/bus/virtio/drivers/9pnet_virtio ]; then
        BOUND=$(ls -1 /sys/bus/virtio/drivers/9pnet_virtio 2>/dev/null | \
                grep -c '^virtio' || echo 0)
        if [ "$BOUND" -ge 1 ]; then
            np_pass driver-bind "$BOUND device(s)"
        else
            np_fail driver-bind "0 devices bound"
        fi
    else
        np_fail driver-bind "/sys/bus/virtio/drivers/9pnet_virtio missing"
    fi

    # Phase 2: mount.
    mkdir -p /mnt/p9
    log "+ mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 host /mnt/p9"
    if mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 \
              host /mnt/p9 2>/dev/kmsg; then
        np_pass mount "tag=host -> /mnt/p9"
    else
        np_fail mount "mount syscall failed"
        log "9P SUMMARY: ${NP_PASS}/$((NP_PASS + NP_FAIL)) phases passed"
        sync
        sleep 1
        log "=== tinyvmm shutdown requested ==="
        sleep 1
        poweroff -f 2>/dev/kmsg || halt -f 2>/dev/kmsg
        exec cat
    fi

    cd /mnt/p9 || true

    # Phase 3: manifest-readable.
    if [ -s /mnt/p9/.manifest.sha256 ]; then
        MLINES=$(wc -l < /mnt/p9/.manifest.sha256)
        if [ "$MLINES" -eq "$EXPECTED_MANIFEST_LINES" ]; then
            np_pass manifest-readable "$MLINES lines"
        else
            np_fail manifest-readable \
                "got $MLINES lines (want $EXPECTED_MANIFEST_LINES)"
        fi
    else
        np_fail manifest-readable ".manifest.sha256 missing or empty"
    fi

    # Phase 4: sha256-bulk. Adopt rubber-duck recommendation: gate on
    # BOTH busybox sha256sum -c exit status AND ": OK$" line count.
    # That catches missing files, hash mismatches, and read errors that
    # busybox might report without the literal "FAILED" token.
    SHA_RC=0
    sha256sum -c /mnt/p9/.manifest.sha256 > /tmp/sha.out 2>&1 || SHA_RC=$?
    if [ "$SHA_RC" -eq 0 ]; then
        OK_COUNT=$(grep -c ': OK$' /tmp/sha.out || true)
        if [ "$OK_COUNT" -eq "$EXPECTED_MANIFEST_LINES" ]; then
            np_pass sha256-bulk "$OK_COUNT/$EXPECTED_MANIFEST_LINES OK"
        else
            np_fail sha256-bulk \
                "got $OK_COUNT OK lines (want $EXPECTED_MANIFEST_LINES)"
            head -n 10 /tmp/sha.out | while IFS= read -r line; do log "  $line"; done
        fi
    else
        np_fail sha256-bulk "sha256sum -c exit=$SHA_RC"
        head -n 10 /tmp/sha.out | while IFS= read -r line; do log "  $line"; done
    fi

    # Phase 5: empty-file.
    if [ -f /mnt/p9/empty.bin ] && \
       [ "$(stat -c %s /mnt/p9/empty.bin)" = "0" ] && \
       [ -z "$(cat /mnt/p9/empty.bin)" ]; then
        np_pass empty-file "size=0"
    else
        np_fail empty-file "stat or cat unexpected"
    fi

    # Phase 6: large-file (1 MiB). The manifest already covers this in
    # sha256-bulk, but re-hash explicitly so failures are attributed
    # to the large-file path (Tread chunking past 512000 msize cap).
    LARGE_EXPECT=$(grep '  large.bin$' /mnt/p9/.manifest.sha256 | awk '{print $1}')
    LARGE_ACTUAL=$(sha256sum /mnt/p9/large.bin | awk '{print $1}')
    if [ -n "$LARGE_EXPECT" ] && [ "$LARGE_EXPECT" = "$LARGE_ACTUAL" ]; then
        np_pass large-file "1 MiB sha256 matches"
    else
        np_fail large-file "expect=$LARGE_EXPECT actual=$LARGE_ACTUAL"
    fi

    # Phase 7: many-files (100 entries).
    if [ -d /mnt/p9/many ]; then
        MANY_COUNT=$(ls -1 /mnt/p9/many 2>/dev/null | wc -l)
        if [ "$MANY_COUNT" -eq 100 ]; then
            np_pass many-files "100 entries"
        else
            np_fail many-files "ls count=$MANY_COUNT (want 100)"
        fi
    else
        np_fail many-files "/mnt/p9/many missing"
    fi

    # Phase 8: nested-dir.
    NESTED_EXPECT=$(grep '  subdir/nested.bin$' /mnt/p9/.manifest.sha256 | \
                    awk '{print $1}')
    NESTED_ACTUAL=$(sha256sum /mnt/p9/subdir/nested.bin 2>/dev/null | \
                    awk '{print $1}')
    if [ -n "$NESTED_EXPECT" ] && [ "$NESTED_EXPECT" = "$NESTED_ACTUAL" ]; then
        np_pass nested-dir "subdir/nested.bin sha256 matches"
    else
        np_fail nested-dir "expect=$NESTED_EXPECT actual=$NESTED_ACTUAL"
    fi

    # Phase 9: write-create (guest -> host visibility). Host harness
    # asserts the file exists with the exact expected content after
    # the VM exits. The known sha256 of "guest-wrote\\n" is checked
    # here too so a flush failure is caught immediately.
    GUEST_WROTE_SHA="faed973bf80505e70fc0dd5ebcd1bacc7d1af74c686d285160d3531ef1d13f1a"
    rm -f /mnt/p9/guest_wrote.txt 2>/dev/null || true
    if echo "guest-wrote" > /mnt/p9/guest_wrote.txt 2>/dev/kmsg && \
       [ "$(cat /mnt/p9/guest_wrote.txt)" = "guest-wrote" ] && \
       [ "$(sha256sum /mnt/p9/guest_wrote.txt | awk '{print $1}')" = \
         "$GUEST_WROTE_SHA" ]; then
        np_pass write-create "guest_wrote.txt sha256 matches"
    else
        np_fail write-create "echo/cat/sha256 unexpected"
    fi

    # Phase 10: create-delete cycle. Host post-check requires the
    # file is gone after the run.
    if touch /mnt/p9/guest_tmp.txt 2>/dev/kmsg && \
       [ -f /mnt/p9/guest_tmp.txt ] && \
       rm /mnt/p9/guest_tmp.txt 2>/dev/kmsg && \
       [ ! -f /mnt/p9/guest_tmp.txt ]; then
        np_pass create-delete "touch + rm ok"
    else
        np_fail create-delete "create or delete failed"
        rm -f /mnt/p9/guest_tmp.txt 2>/dev/null || true
    fi

    # Phase 11: mkdir-rmdir.
    if mkdir /mnt/p9/new_dir 2>/dev/kmsg && \
       [ -d /mnt/p9/new_dir ] && \
       rmdir /mnt/p9/new_dir 2>/dev/kmsg && \
       [ ! -d /mnt/p9/new_dir ]; then
        np_pass mkdir-rmdir "ok"
    else
        np_fail mkdir-rmdir "mkdir or rmdir failed"
        rmdir /mnt/p9/new_dir 2>/dev/null || true
    fi

    # Phase 12: rename-roundtrip.
    if echo a > /mnt/p9/rename_a.txt 2>/dev/kmsg && \
       mv /mnt/p9/rename_a.txt /mnt/p9/rename_b.txt 2>/dev/kmsg && \
       [ -f /mnt/p9/rename_b.txt ] && \
       [ ! -f /mnt/p9/rename_a.txt ] && \
       rm /mnt/p9/rename_b.txt 2>/dev/kmsg && \
       [ ! -f /mnt/p9/rename_b.txt ]; then
        np_pass rename-roundtrip "mv a->b + rm ok"
    else
        np_fail rename-roundtrip "rename or unlink failed"
        rm -f /mnt/p9/rename_a.txt /mnt/p9/rename_b.txt 2>/dev/null || true
    fi

    # Phase 13: truncate (exercises Tsetattr size). `: > f` triggers
    # truncate(2) -> Tsetattr with kP9SetattrSize and size=0.
    if printf 'abcdef' > /mnt/p9/trunc.txt 2>/dev/kmsg && \
       [ "$(stat -c %s /mnt/p9/trunc.txt)" = "6" ] && \
       : > /mnt/p9/trunc.txt 2>/dev/kmsg && \
       [ "$(stat -c %s /mnt/p9/trunc.txt)" = "0" ] && \
       rm /mnt/p9/trunc.txt 2>/dev/kmsg; then
        np_pass truncate "abcdef -> 0 bytes ok"
    else
        np_fail truncate "size transition unexpected"
        rm -f /mnt/p9/trunc.txt 2>/dev/null || true
    fi

    # Phase 14: append (exercises Twrite with O_APPEND -> backend
    # honors OVERLAPPED.Offset = 0xFFFFFFFFu).
    if printf 'aaa' > /mnt/p9/append.txt 2>/dev/kmsg && \
       printf 'bbb' >> /mnt/p9/append.txt 2>/dev/kmsg && \
       [ "$(cat /mnt/p9/append.txt)" = "aaabbb" ] && \
       rm /mnt/p9/append.txt 2>/dev/kmsg; then
        np_pass append "aaa + bbb = aaabbb"
    else
        np_fail append "append did not concatenate correctly"
        rm -f /mnt/p9/append.txt 2>/dev/null || true
    fi

    cd / || true
    sync

    # Phase 15: umount. No -l fallback in the primary assertion --
    # a clean umount requires all fids were Tclunked, which proves
    # we did not leak any references.
    if umount /mnt/p9 2>/dev/kmsg; then
        np_pass umount "clean umount"
    else
        np_fail umount "umount failed (likely fid leak)"
        umount -l /mnt/p9 2>/dev/null || true
    fi

    log "--- 9P-HARNESS end ---"
    log "9P SUMMARY: ${NP_PASS}/$((NP_PASS + NP_FAIL)) phases passed"
    sync
    sleep 1
    log "=== tinyvmm shutdown requested ==="
    sleep 1
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


def build_cpuid_trigger_binary() -> bytes:
    """Hand-roll a 136-byte x86-64 static ET_EXEC ELF that triggers the
    tinyvmm magic snapshot CPUID leaf 0x4000DE57 and then exits cleanly.

    Used by the `tinyvmm.test=snapshot` /init block. Placed at
    /bin/cpuid_trigger inside the initramfs.

    Layout:
        offset    size  contents
        0x00      64    Elf64_Ehdr
        0x40      56    one PT_LOAD Elf64_Phdr (R+X, vaddr=0x400000,
                                                filesz=memsz=0x88)
        0x78      16    code (entry point = 0x400078):
                          B8 57 DE 00 40   mov   eax, 0x4000DE57
                          0F A2            cpuid
                          B8 3C 00 00 00   mov   eax, 60     ; sys_exit
                          31 FF            xor   edi, edi
                          0F 05            syscall

    Total: 0x88 = 136 bytes. The file contains no .data, no .bss, no
    dynamic section, no PT_GNU_STACK, no PT_INTERP -- pure code that
    fits inside a single PT_LOAD.

    The 'cpuid' instruction is unprivileged in x86-64 userspace, so this
    is reachable from ring 3. tinyvmm's --pvh-run enables CPUID exits
    via WHvPartitionPropertyCodeExtendedVmExits, and the magic-leaf
    handler advances RIP past the cpuid before returning
    StopReason::SnapshotRequested -- so the saved-and-restored RIP
    points at the 'mov eax, 60' instruction. On restore the syscall
    runs and the binary exits cleanly.
    """
    import struct

    # Elf64_Ehdr
    e_ident = (
        b"\x7fELF"          # EI_MAG
        b"\x02"             # EI_CLASS = ELFCLASS64
        b"\x01"             # EI_DATA = ELFDATA2LSB
        b"\x01"             # EI_VERSION = EV_CURRENT
        b"\x00"             # EI_OSABI = ELFOSABI_NONE (System V)
        + b"\x00" * 8       # EI_ABIVERSION + EI_PAD
    )
    assert len(e_ident) == 16

    e_type    = 2           # ET_EXEC
    e_machine = 0x3e        # EM_X86_64
    e_version = 1           # EV_CURRENT
    e_entry   = 0x400078    # virtual address of code
    e_phoff   = 0x40        # program-header table offset
    e_shoff   = 0           # no section headers (not needed for exec)
    e_flags   = 0
    e_ehsize    = 64
    e_phentsize = 56
    e_phnum     = 1
    e_shentsize = 0
    e_shnum     = 0
    e_shstrndx  = 0

    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
    )
    assert len(ehdr) == 64, len(ehdr)

    # Elf64_Phdr (one PT_LOAD that covers the whole file)
    p_type   = 1            # PT_LOAD
    p_flags  = 5            # PF_R | PF_X
    p_offset = 0
    p_vaddr  = 0x400000
    p_paddr  = 0x400000
    p_filesz = 0x88         # whole file
    p_memsz  = 0x88
    p_align  = 0x1000

    phdr = struct.pack(
        "<IIQQQQQQ",
        p_type, p_flags, p_offset, p_vaddr, p_paddr,
        p_filesz, p_memsz, p_align,
    )
    assert len(phdr) == 56, len(phdr)

    # Code (16 bytes, entry point = file offset 0x78 = vaddr 0x400078)
    code = (
        b"\xB8\x57\xDE\x00\x40"   # mov   eax, 0x4000DE57
        b"\x0F\xA2"               # cpuid
        b"\xB8\x3C\x00\x00\x00"   # mov   eax, 60        ; __NR_exit
        b"\x31\xFF"               # xor   edi, edi       ; status = 0
        b"\x0F\x05"               # syscall
    )
    assert len(code) == 16, len(code)

    blob = ehdr + phdr + code
    assert len(blob) == 0x88, len(blob)
    # Self-checks that catch the most common ELF-layout mistakes if
    # someone tweaks the byte layout above.
    assert blob[:4] == b"\x7fELF"
    assert (p_vaddr % p_align) == (p_offset % p_align), \
        "PT_LOAD vaddr/offset not congruent mod align"
    assert e_entry == p_vaddr + 0x78, "entry point not in PT_LOAD"
    return blob


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

    # M33.7: snapshot save/restore trigger binary. Used by the
    # `tinyvmm.test=snapshot` /init block to issue the magic CPUID
    # leaf 0x4000DE57 from ring 3.
    cb.add_file("bin/cpuid_trigger", build_cpuid_trigger_binary(),
                mode=0o755)

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
