#!/usr/bin/env python3
"""Check how a user-mode NAT backend (`--net-backend nat` by default; also
smoltcp, slirp or gvisor via --backend) ends TCP connections.

Boots the `tinyvmm.test=nat` initramfs mode against host servers on
127.0.0.1 (reached at the guest's gateway, 172.29.255.1) and asserts all
twelve guest phases pass (`NATTEST SUMMARY: 12/12`):

  A  connect() to a host port with nothing listening is refused
     (ECONNREFUSED) at once, not accepted and then reset;
  B  a server that resets the connection mid-response makes the guest's
     download fail, instead of ending it as a clean, truncated EOF;
  C  300 sequential HTTP/1.0 connections that the host closes first all
     succeed (each leaves the NAT's guest-facing TCB in TIME_WAIT);
  D  300 UDP request/response exchanges, each from a fresh guest port (as a
     DNS resolver sends its queries), are all answered;
  E  downloads of sizes around segment, GSO-frame, ring and window
     boundaries (1 B to 64 MiB) arrive intact (SHA-256);
  F  uploads of such sizes (to 32 MiB) arrive intact;
  G  8 parallel 8 MiB downloads arrive intact;
  H  the host downloads 24 MiB from the guest's httpd through --portfwd,
     intact, over 127.0.0.1 and (nat, smoltcp) [::1];
  I  UDP datagrams of 1473 B to 8 KiB, and 4000-byte pings to the gateway,
     echo intact (they cross the NAT in IPv4 fragments, both ways);
  J  a datagram for a multicast group stays on the guest's link: the host,
     a member of the group, gets none;
  K  when the guest resets a connection the host has finished sending on,
     the host sees a reset, not a clean end (B the other way);
  L  5 connections in a row from one guest source port, each closed by the
     host first, are all answered (the stack may still hold the 4-tuple in
     TIME_WAIT; the guest, the passive closer, holds nothing and reuses it).

Usage:
  python tools\\nat_test.py
    [--tinyvmm <path>]   (default target/release/tinyvmm.exe)
    [--vmlinux <path>]   (default repo/vmlinux)
    [--busybox <path>]   (default repo/busybox-x86_64)
    [--initrd  <path>]   (default repo/initramfs-blk.cpio.gz; rebuilt from
                          busybox unless --no-build)
    [--no-build]
    [--timeout-sec 240]
    [--backend nat|smoltcp|slirp|gvisor]
"""
from __future__ import annotations

import argparse
import hashlib
import random
import re
import socket
import struct
import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vmm_harness as h  # noqa: E402

SUMMARY_RE = re.compile(r"NATTEST SUMMARY: (\d+)/(\d+) phases passed")
PHASES = 12
# Organization-local scope (RFC 2365): what the guest sends here must not
# leave its link.
MCAST_GROUP = "239.255.42.99"


def blob(size: int, seed: int) -> bytes:
    """`size` pseudo-random bytes, the same for the same seed."""
    return random.Random(seed).randbytes(size)


def reply(c: socket.socket, body: bytes) -> None:
    c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
              % len(body))
    c.sendall(body)


def serve(listener: socket.socket, mcast_seen: list[int], backend: str) -> None:
    """GET /ok: a tiny HTTP/1.0 reply, then the server closes first.
    GET /rst: headers and part of a body, then a reset (SO_LINGER 0).
    GET /blob/<size>/<seed>: pseudo-random bytes; /sum/<size>/<seed>: their
    SHA-256. POST /up: the SHA-256 of the body. GET /pf/<port>/<path>: the
    SHA-256 of http://127.0.0.1:<port>/<path> (the NAT's port forward to the
    guest), fetched over [::1] too for the NAT backends, which must agree.
    GET /mcast: how many datagrams the host got for MCAST_GROUP.
    GET /hold: headers and 256 KiB, a half-close, then wait for the client to
    end the connection; GET /hold-end: how it did: "reset", "eof" or
    "pending"."""
    held: list[str] = []
    held_done = threading.Event()

    def handle(c: socket.socket) -> None:
        try:
            req = b""
            while b"\r\n\r\n" not in req:
                d = c.recv(65536)
                if not d:
                    return
                req += d
            head, body = req.split(b"\r\n\r\n", 1)
            path = head.split(b" ")[1].decode()
            parts = path.strip("/").split("/")
            if req.startswith(b"GET /rst"):
                c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\npartial")
                time.sleep(0.2)
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            elif parts[0] == "blob":
                reply(c, blob(int(parts[1]), int(parts[2])))
            elif parts[0] == "sum":
                reply(c, hashlib.sha256(blob(int(parts[1]), int(parts[2]))).hexdigest().encode())
            elif req.startswith(b"POST /up"):
                m = re.search(rb"(?i)content-length:\s*(\d+)", head)
                want = int(m.group(1)) if m else 0
                sha = hashlib.sha256(body)
                got = len(body)
                while got < want:
                    d = c.recv(1 << 20)
                    if not d:
                        break
                    sha.update(d)
                    got += len(d)
                reply(c, sha.hexdigest().encode())
            elif parts[0] == "pf":
                # The NAT forwards both loopbacks, so `localhost` reaches the
                # guest at once (libslirp and gVisor forward only 127.0.0.1).
                hosts = ["127.0.0.1"]
                if backend in ("nat", "smoltcp"):
                    hosts.append("[::1]")
                digests = set()
                for host in hosts:
                    url = f"http://{host}:{parts[1]}/{'/'.join(parts[2:])}"
                    try:
                        with urllib.request.urlopen(url, timeout=60) as r:
                            digests.add(hashlib.sha256(r.read()).hexdigest())
                    except OSError as e:
                        digests.add(f"error: {host}: {e}")
                digest = digests.pop() if len(digests) == 1 else " / ".join(sorted(digests))
                reply(c, digest.encode())
            elif parts[0] == "mcast":
                reply(c, str(mcast_seen[0]).encode())
            elif parts[0] == "hold":
                c.sendall(b"HTTP/1.0 200 OK\r\n\r\n" + bytes(256 * 1024))
                c.shutdown(socket.SHUT_WR)
                c.settimeout(30)
                try:
                    while c.recv(65536):
                        pass
                    held.append("eof")
                except ConnectionError:
                    held.append("reset")
                held_done.set()
            elif parts[0] == "hold-end":
                held_done.wait(5)
                reply(c, (held[0] if held else "pending").encode())
            else:
                c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n"
                          b"Connection: close\r\n\r\nok")
        except OSError:
            pass
        finally:
            c.close()

    while True:
        try:
            c, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def closed_port() -> int:
    """A loopback port nothing listens on (bound, then released)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def udp_echo(sock: socket.socket) -> None:
    """Send every datagram back to where it came from."""
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            sock.sendto(data, addr)
        except OSError:
            # A closed socket ends the loop; an ICMP-unreachable from a
            # guest port that has gone away (WSAECONNRESET) doesn't.
            if sock.fileno() == -1:
                return


def mcast_member() -> socket.socket | None:
    """A UDP socket on a free port, in MCAST_GROUP on the host's default
    interface (None if the host has none for multicast)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.bind(("", 0))
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     socket.inet_aton(MCAST_GROUP) + socket.inet_aton("0.0.0.0"))
    except OSError:
        s.close()
        return None
    return s


def count_datagrams(sock: socket.socket, seen: list[int]) -> None:
    while True:
        try:
            sock.recvfrom(65535)
            seen[0] += 1
        except OSError:
            if sock.fileno() == -1:
                return


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", type=Path, default=h.DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=h.DEFAULT_VMLINUX)
    ap.add_argument("--busybox", type=Path, default=h.DEFAULT_BUSYBOX)
    ap.add_argument("--initrd", type=Path, default=h.DEFAULT_INITRD)
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--timeout-sec", type=float, default=240)
    ap.add_argument("--backend", default="nat",
                    help="--net-backend to test: nat, smoltcp, slirp or gvisor")
    args = ap.parse_args()

    if not args.no_build:
        h.build_initramfs(args.busybox, args.initrd)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    port = listener.getsockname()[1]
    mcast_seen = [0]
    threading.Thread(target=serve, args=(listener, mcast_seen, args.backend), daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp_port = udp.getsockname()[1]
    threading.Thread(target=udp_echo, args=(udp,), daemon=True).start()
    mcast = mcast_member()
    if mcast:
        mcast_port = mcast.getsockname()[1]
        threading.Thread(target=count_datagrams, args=(mcast, mcast_seen), daemon=True).start()
    else:
        mcast_port = closed_port()
        print("[nat-test] note: no multicast on this host; phase J can't fail")
    closed = closed_port()
    fwd = closed_port()
    print(f"[nat-test] host server 127.0.0.1:{port}, UDP echo {udp_port}, closed port {closed}, "
          f"forward {fwd} -> guest 8080, multicast {MCAST_GROUP}:{mcast_port}")

    argv = [str(args.tinyvmm), "--pvh-run", "--ram-mb", "1024",
            "--net", "--net-backend", args.backend, "--portfwd", f"{fwd}:8080",
            "--initrd", str(args.initrd), str(args.vmlinux), "--",
            *h.GUEST_CMDLINE, "tinyvmm.test=nat",
            f"NATTEST_PORT={port}", f"NATTEST_CLOSED_PORT={closed}",
            f"NATTEST_UDP_PORT={udp_port}", f"NATTEST_FWD_PORT={fwd}",
            f"NATTEST_MCAST={MCAST_GROUP}:{mcast_port}"]
    run = h.run_vmm(argv, args.timeout_sec)
    listener.close()
    udp.close()
    if mcast:
        mcast.close()

    for _, line in run.lines:
        if "NATTEST " in line:
            print(f"[nat-test] {line.strip()}")
    m = SUMMARY_RE.search(run.text)
    if run.timed_out or not m:
        print("[nat-test] FAIL: no NATTEST SUMMARY (timed out or the guest test did not run)")
        return 1
    passed, total = int(m.group(1)), int(m.group(2))
    if total != PHASES or passed != total:
        print(f"[nat-test] FAIL: {passed}/{total} phases passed (expected {PHASES}/{PHASES})")
        return 1
    print(f"[nat-test] PASS: {passed}/{total} phases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
