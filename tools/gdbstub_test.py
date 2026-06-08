#!/usr/bin/env python3
"""Test the M35 GDB stub Phase 1 (TCP + RSP framing + handshake).

Mimics what `gdb` sends in `target remote`:
  1. ``+`` ack on connect.
  2. ``$qSupported:multiprocess+;swbreak+...#xx``
  3. ``$vMustReplyEmpty#xx``
  4. ``$Hg0#xx`` / ``$Hc-1#xx``
  5. ``$qfThreadInfo#xx`` / ``$qsThreadInfo#xx``
  6. ``$qC#xx``
  7. ``$qAttached#xx``
  8. ``$?#xx``       (stop reason -- expect T05 / S05)
  9. ``$c#63``        (continue -- releases the vCPU)

Asserts each reply matches the expected pattern. Skips
QStartNoAckMode for the v1 test (we exercise it separately).

Usage:
  python tools\\gdbstub_test.py
"""
from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "target" / "release" / "tinyvmm.exe"
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_INITRD  = REPO / "initramfs-net.cpio"


def cksum(payload: bytes) -> int:
    return sum(payload) & 0xFF


def pack(payload: bytes) -> bytes:
    return b"$" + payload + b"#" + f"{cksum(payload):02x}".encode("ascii")


class RspClient:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("RSP client: EOF")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_packet(self, payload: bytes) -> None:
        self.sock.sendall(pack(payload))

    def recv_packet(self) -> bytes:
        # Eat ack(s) if any.
        while True:
            b = self._read(1)
            if b in (b"+", b"-"):
                continue
            if b == b"$":
                break
            # Other garbage -- keep looking.
        payload = b""
        while True:
            b = self._read(1)
            if b == b"#":
                break
            payload += b
        ck = self._read(2)
        assert int(ck, 16) == cksum(payload), \
            f"checksum mismatch: got {ck!r}, want {cksum(payload):02x}, " \
            f"payload {payload!r}"
        # Send ack (we're not in no-ack mode).
        self.sock.sendall(b"+")
        return payload


def run_stub_test(tinyvmm: Path, vmlinux: Path, initrd: Path,
                  port: int, timeout_sec: int) -> int:
    argv = [
        str(tinyvmm),
        "--pvh-run",
        "--ram-mb", "256",
        "--gdb-port", str(port),
        "--initrd", str(initrd),
        "--watchdog-secs", "30",
        str(vmlinux),
        "--",
        "console=hvc0",
        "pci=conf1,nocrs,lastbus=0",
        "nofb",
        "nomodeset",
    ]
    print(f"[gdbstub-test] spawning tinyvmm: {' '.join(argv)}", flush=True)
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    out_lines: list[bytes] = []

    def reader() -> None:
        try:
            assert proc.stdout is not None
            for line in iter(proc.stdout.readline, b""):
                out_lines.append(line)
                sys.stdout.write(line.decode("utf-8", errors="replace"))
                sys.stdout.flush()
        except Exception:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    # Wait for the [gdbstub] listening message.
    t0 = time.monotonic()
    listening = False
    while time.monotonic() - t0 < 15:
        blob = b"".join(out_lines).decode("utf-8", errors="replace")
        if f"[gdbstub] listening on 127.0.0.1:{port}" in blob:
            listening = True
            break
        time.sleep(0.1)
    if not listening:
        print("[gdbstub-test] FAIL: never saw 'listening' line", file=sys.stderr)
        proc.kill()
        return 1
    # Tiny pause so listen() is fully in place.
    time.sleep(0.2)

    # Connect.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect(("127.0.0.1", port))
        sock.sendall(b"+")  # initial ack from "client"
        client = RspClient(sock)
        print(f"[gdbstub-test] connected to 127.0.0.1:{port}")

        def expect(packet: bytes, validator) -> None:
            client.send_packet(packet)
            r = client.recv_packet()
            if not validator(r):
                raise AssertionError(
                    f"unexpected reply to {packet!r}: got {r!r}")
            print(f"[gdbstub-test] {packet.decode()!s:30s} -> {r!r}")

        # qSupported
        expect(b"qSupported:multiprocess+;swbreak+;hwbreak+;"
               b"qRelocInsn+;fork-events+;vfork-events+;exec-events+;"
               b"vContSupported+",
               lambda r: b"PacketSize=" in r and b"swbreak+" in r and
                         b"qXfer:features:read+" in r)
        # vMustReplyEmpty -> empty
        expect(b"vMustReplyEmpty", lambda r: r == b"")
        # H g 0 / H c -1 -> OK
        expect(b"Hg0",  lambda r: r == b"OK")
        expect(b"Hc-1", lambda r: r == b"OK")
        # qfThreadInfo -> m1
        expect(b"qfThreadInfo", lambda r: r == b"m1")
        expect(b"qsThreadInfo", lambda r: r == b"l")
        # qC -> QC1
        expect(b"qC", lambda r: r == b"QC1")
        # qAttached -> 1
        expect(b"qAttached", lambda r: r == b"1")
        # qOffsets
        expect(b"qOffsets", lambda r: b"Text=0" in r)
        # vCont? -> vCont;c;s
        expect(b"vCont?", lambda r: r == b"vCont;c;s")
        # ?: stop reason  -- on first connection the stub seeded
        # pending_stop_flag, so once we send a packet that the I/O
        # thread can service, the run loop's ReportStop(0xFF, rip)
        # has fired and the T-packet will be sent. We don't strictly
        # need to send ? here -- the next packet (c) will be acted on
        # only after the stop is surfaced. But sending ? is harmless.
        expect(b"?", lambda r: r.startswith(b"T") or r.startswith(b"S"))

        # Now release the vCPU with "c". Expect no reply yet (vCPU
        # runs free until next stop). We just check the socket stays
        # open and the guest output keeps streaming.
        client.send_packet(b"c")
        print("[gdbstub-test] sent c -- guest should resume")
        # Verify guest actually booted by waiting for a kernel log line.
        t1 = time.monotonic()
        booted = False
        while time.monotonic() - t1 < 25:
            blob = b"".join(out_lines).decode("utf-8", errors="replace")
            if "tinyvmm init starting" in blob or "/init started" in blob:
                booted = True
                break
            time.sleep(0.1)
        if not booted:
            print("[gdbstub-test] FAIL: guest did not boot after c",
                  file=sys.stderr)
            sock.close()
            proc.kill()
            return 1
        print("[gdbstub-test] PASS: handshake OK + guest boots after c")
        # Detach so the watchdog teardown is clean.
        client.send_packet(b"D")
        try:
            r = client.recv_packet()
            print(f"[gdbstub-test] D -> {r!r}")
        except Exception:
            pass
        sock.close()
    except Exception as e:
        print(f"[gdbstub-test] EXC: {e}", file=sys.stderr)
        proc.kill()
        return 1
    finally:
        # Give tinyvmm time to wind down.
        try:
            proc.wait(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--initrd",  type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--port", type=int, default=1234)
    ap.add_argument("--timeout-sec", type=int, default=60)
    args = ap.parse_args()

    for p, label in [(args.tinyvmm, "tinyvmm.exe"),
                     (args.vmlinux, "vmlinux"),
                     (args.initrd,  "initrd")]:
        if not p.exists():
            print(f"[gdbstub-test] FAIL: {label} not found at {p}",
                  file=sys.stderr)
            return 2
    return run_stub_test(args.tinyvmm, args.vmlinux, args.initrd,
                         args.port, args.timeout_sec)


if __name__ == "__main__":
    sys.exit(main())
