#!/usr/bin/env python3
"""Drive the tinyvmm usernet-TSI HTTP test end-to-end (M34.7).

Launches a Python HTTP server on the host's primary LAN IP, boots
tinyvmm with --net-backend usernet --net-usernet-tcp tsi, and asserts:

  1. The guest's six-phase HTTP test (A..F) reported all phases pass
     via ``USERNET-TSI SUMMARY: N/N phases passed``. The phases:
       A   GET /hello                exact body match
       B   GET /echo/1024            byte count check
       C   GET /echo/65536           byte count (64 KiB, segments + WS)
       D   GET /echo/524288          byte count (512 KiB, many segments)
       E   4 parallel /echo/16384    concurrent conns
       F   GET to a closed port      expect failure (RST / abort path)

  2. The engine's per-shutdown ``[usernet-tsi] summary:`` line shows the
     expected counter ranges:
       - total_conns >= 5 (one per A-D + at least one of E)
       - live == 0 (no leaks; the M34.6 reconcile path must reap all)
       - aborts >= 1 (Phase F connect-refused)
       - graceful_closes >= 5 (A-D + at least one of E)
       - segments_rx > 0, segments_tx > 0

Mirror of blk_test.py / p9_test.py.

Usage:
  python tools\\usernet_tsi_test.py
    [--tinyvmm <path>]
    [--vmlinux <path>] (default repo/vmlinux)
    [--initrd  <path>] (default repo/initramfs-net.cpio)
    [--timeout-sec <N>] (default 180)
    [--host-ip <a.b.c.d>] (default auto-discover)
"""
from __future__ import annotations

import argparse
import http.server
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "build" / "bin" / "tinyvmm.exe"
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_INITRD = REPO / "initramfs-net.cpio"

PHASE_TOTAL = 6
ECHO_RE = re.compile(r"^/echo/(\d+)$")


# ---------------------------------------------------------------------------
# IP discovery + port allocation
# ---------------------------------------------------------------------------
def discover_host_ipv4(explicit: str | None) -> str:
    """Find a non-loopback IPv4 the guest can connect to.

    The Linux guest routes anything outside its 10.0.0.0/24 subnet via
    the usernet gateway (10.0.0.1 -> tinyvmm engine), so the engine
    sees a packet with dst=<host_ip>. The engine Winsock-connect()s to
    that IP, which the host kernel routes to the bound HTTP server (we
    bind 0.0.0.0:<port> so it accepts on all interfaces).

    The UDP-connect-to-8.8.8.8:80 idiom returns the preferred source
    address the kernel would use to reach 8.8.8.8 (i.e. the default
    route's preferred src); no packets are sent on UDP "connect" and
    no internet is required for the routing decision to be made.
    """
    if explicit:
        return explicit
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = ""
    finally:
        s.close()
    if not ip or ip.startswith("127."):
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = ""
    if not ip or ip.startswith("127."):
        raise SystemExit(
            "[usernet-tsi-test] FAIL: could not discover a non-loopback "
            "IPv4 address; pass --host-ip <a.b.c.d>")
    return ip


def alloc_closed_port() -> int:
    """Bind + immediately close a TCP socket to claim & release a port.

    A short race window exists where another process could grab the
    port between our close() and the guest's wget. On a quiet test
    host this is extremely rare and the guest's Winsock connect() to
    the released port gets ECONNREFUSED instantly.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args, **_kw) -> None:  # quiet stderr
        return

    def do_GET(self) -> None:
        if self.path == "/hello":
            self._send(b"tinyvmm-tsi-hello")
            return
        m = ECHO_RE.match(self.path)
        if m:
            n = int(m.group(1))
            if n > 64 * 1024 * 1024:
                self.send_error(400, "echo too big")
                return
            self._send(b"\xab" * n)
            return
        self.send_error(404)

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_http_server(bind_ip: str = "0.0.0.0") -> tuple[_Server, int]:
    srv = _Server((bind_ip, 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True,
                         name="tsi-test-http")
    t.start()
    return srv, port


# ---------------------------------------------------------------------------
# tinyvmm launch
# ---------------------------------------------------------------------------
def run_vmm(argv: list[str], timeout_sec: int) -> tuple[int, str]:
    t_start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    out: list[bytes] = []
    done = threading.Event()
    summary_seen = threading.Event()
    SUMMARY_RE = re.compile(
        rb"USERNET-TSI SUMMARY:\s+(\d+)/(\d+) phases", re.M)

    def reader() -> None:
        try:
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.readline()
                if not chunk:
                    break
                out.append(chunk)
                sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                sys.stdout.flush()
                blob = b"".join(out[-50:])
                if SUMMARY_RE.search(blob):
                    summary_seen.set()
        finally:
            done.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    while proc.poll() is None:
        if time.monotonic() - t_start > timeout_sec:
            print(f"\n[usernet-tsi-test] timeout after {timeout_sec}s; "
                  "killing tinyvmm", file=sys.stderr)
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            break
        time.sleep(0.5)

    done.wait(timeout=10)
    t.join(timeout=5)
    blob = b"".join(out).decode("utf-8", errors="replace")
    return (proc.returncode or 0), blob


# ---------------------------------------------------------------------------
# Assertions on captured output
# ---------------------------------------------------------------------------
def assert_guest_summary(log: str) -> None:
    m = re.search(r"USERNET-TSI SUMMARY:\s+(\d+)/(\d+) phases passed", log)
    if not m:
        raise SystemExit(
            "[usernet-tsi-test] FAIL: no 'USERNET-TSI SUMMARY' in guest log")
    passed, total = int(m.group(1)), int(m.group(2))
    print(f"[usernet-tsi-test] guest reports {passed}/{total} phases PASS")
    if total != PHASE_TOTAL or passed != PHASE_TOTAL:
        fails = re.findall(r"^.*USERNET-TSI [A-F]:\s+FAIL.*$",
                           log, flags=re.M)
        for f in fails:
            print("[usernet-tsi-test] >>>", f.strip())
        raise SystemExit(
            f"[usernet-tsi-test] FAIL: expected {PHASE_TOTAL}/{PHASE_TOTAL}, "
            f"got {passed}/{total}")


def assert_engine_summary(log: str) -> None:
    """The engine emits ``[usernet-tsi] summary: total=N live=M ...`` in
    ``State::Stop`` (M34.6). Asserts the counter values."""
    m = re.search(
        r"\[usernet-tsi\]\s*summary:\s*"
        r"total=(\d+)\s+"
        r"live=(\d+)\s+"
        r"seg_rx=(\d+)\s+"
        r"seg_tx=(\d+)\s+"
        r"aborts=(\d+)\s+"
        r"graceful=(\d+)\s+"
        r"rsts=(\d+)", log)
    if not m:
        raise SystemExit(
            "[usernet-tsi-test] FAIL: no [usernet-tsi] summary line "
            "in host log")
    total    = int(m.group(1))
    live     = int(m.group(2))
    seg_rx   = int(m.group(3))
    seg_tx   = int(m.group(4))
    aborts   = int(m.group(5))
    graceful = int(m.group(6))
    rsts     = int(m.group(7))
    print(f"[usernet-tsi-test] engine summary: total={total} live={live} "
          f"seg_rx={seg_rx} seg_tx={seg_tx} aborts={aborts} "
          f"graceful={graceful} rsts={rsts}")
    fails: list[str] = []
    # Expectations: 4 single-conn phases (A-D) + 4 parallel (E) +
    # 1 failed (F) = 9 conns nominally; allow slack for retry behavior.
    if total < 5:
        fails.append(f"total<5 (got {total})")
    # The M34.6 shim-Closed reconcile must reap everything: zero leaks.
    if live != 0:
        fails.append(f"live!=0 (got {live}; M34.6 reap regression?)")
    if aborts < 1:
        fails.append(f"aborts<1 (got {aborts}; Phase F should have aborted)")
    # Graceful closes for A-D + at least one of E.
    if graceful < 5:
        fails.append(f"graceful<5 (got {graceful})")
    if seg_rx == 0:
        fails.append("seg_rx==0 (engine saw no guest TCP)")
    if seg_tx == 0:
        fails.append("seg_tx==0 (engine emitted no TCP to guest)")
    if fails:
        raise SystemExit(
            f"[usernet-tsi-test] FAIL engine counters: {'; '.join(fails)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--initrd",  type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--timeout-sec", type=int, default=180)
    ap.add_argument("--host-ip", type=str, default=None,
                    help="Override host IPv4 (default: auto-discover via "
                         "UDP-connect-to-8.8.8.8 trick)")
    args = ap.parse_args()

    for p, label in [(args.tinyvmm, "tinyvmm.exe"),
                     (args.vmlinux, "vmlinux"),
                     (args.initrd,  "initrd")]:
        if not p.exists():
            print(f"[usernet-tsi-test] FAIL: {label} not found at {p}",
                  file=sys.stderr)
            return 2

    host_ip = discover_host_ipv4(args.host_ip)
    print(f"[usernet-tsi-test] host IP: {host_ip}")
    closed_port = alloc_closed_port()
    print(f"[usernet-tsi-test] Phase-F closed port: {closed_port}")
    srv, port = start_http_server("0.0.0.0")
    print(f"[usernet-tsi-test] HTTP server: 0.0.0.0:{port}")

    try:
        argv = [
            str(args.tinyvmm),
            "--pvh-run",
            "--ram-mb", "256",
            "--net",
            "--net-backend", "usernet",
            "--initrd", str(args.initrd),
            "--watchdog-secs", str(max(30, args.timeout_sec - 10)),
            str(args.vmlinux),
            "--",
            "console=hvc0",
            "pci=conf1,nocrs,lastbus=0",
            "nofb",
            "nomodeset",
            "tinyvmm.test=usernet-tsi",
            f"TINYVMM_USERNET_TSI_HOST={host_ip}",
            f"TINYVMM_USERNET_TSI_PORT={port}",
            f"TINYVMM_USERNET_TSI_CLOSED_PORT={closed_port}",
        ]
        rc, log = run_vmm(argv, args.timeout_sec)
        print(f"\n[usernet-tsi-test] tinyvmm exited rc={rc}")
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass

    # rc is intentionally not gated (the watchdog tears down the guest
    # so tinyvmm may exit non-zero); the SUMMARY line is the source of
    # truth, same convention as blk_test.py / p9_test.py.
    try:
        assert_guest_summary(log)
        assert_engine_summary(log)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 1

    print("[usernet-tsi-test] PASS: 6 guest phases + engine counters OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
