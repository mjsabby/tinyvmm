#!/usr/bin/env python3
"""Check how the user-mode NAT (`--net-backend nat`) ends TCP connections.

Boots the `tinyvmm.test=nat` initramfs mode against a host server on
127.0.0.1 (the guest's gateway, 10.0.0.1) and asserts all three guest phases
pass (`NATTEST SUMMARY: 3/3`):

  A  connect() to a host port with nothing listening is refused
     (ECONNREFUSED), not accepted and then reset;
  B  a server that resets the connection mid-response makes the guest's
     download fail, instead of ending it as a clean, truncated EOF;
  C  300 sequential HTTP/1.0 connections that the host closes first all
     succeed (each leaves the NAT's guest-facing TCB in TIME_WAIT).

Usage:
  python tools\\nat_test.py
    [--tinyvmm <path>]   (default target/release/tinyvmm.exe)
    [--vmlinux <path>]   (default repo/vmlinux)
    [--busybox <path>]   (default repo/busybox-x86_64)
    [--initrd  <path>]   (default repo/initramfs-blk.cpio.gz; rebuilt from
                          busybox unless --no-build)
    [--no-build]
    [--timeout-sec 120]
"""
from __future__ import annotations

import argparse
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vmm_harness as h  # noqa: E402

SUMMARY_RE = re.compile(r"NATTEST SUMMARY: (\d+)/(\d+) phases passed")
PHASES = 3


def serve(listener: socket.socket) -> None:
    """GET /ok: a tiny HTTP/1.0 reply, then the server closes first.
    GET /rst: headers and part of a body, then a reset (SO_LINGER 0)."""
    def handle(c: socket.socket) -> None:
        try:
            req = b""
            while b"\r\n\r\n" not in req:
                d = c.recv(4096)
                if not d:
                    return
                req += d
            if req.startswith(b"GET /rst"):
                c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\npartial")
                time.sleep(0.2)
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", type=Path, default=h.DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=h.DEFAULT_VMLINUX)
    ap.add_argument("--busybox", type=Path, default=h.DEFAULT_BUSYBOX)
    ap.add_argument("--initrd", type=Path, default=h.DEFAULT_INITRD)
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--timeout-sec", type=float, default=120)
    args = ap.parse_args()

    if not args.no_build:
        h.build_initramfs(args.busybox, args.initrd)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    port = listener.getsockname()[1]
    threading.Thread(target=serve, args=(listener,), daemon=True).start()
    closed = closed_port()
    print(f"[nat-test] host server 127.0.0.1:{port}, closed port {closed}")

    argv = [str(args.tinyvmm), "--pvh-run", "--net", "--net-backend", "nat",
            "--initrd", str(args.initrd), str(args.vmlinux), "--",
            *h.GUEST_CMDLINE, "tinyvmm.test=nat",
            f"NATTEST_PORT={port}", f"NATTEST_CLOSED_PORT={closed}"]
    run = h.run_vmm(argv, args.timeout_sec)
    listener.close()

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
