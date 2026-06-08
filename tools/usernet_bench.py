#!/usr/bin/env python3
"""Benchmark the tinyvmm usernet (TSI) network path end-to-end.

Launches a Python HTTP server on the host's primary LAN IP, boots
tinyvmm with --net-backend usernet, and drives the guest through:

  1. Ping latency (busybox ping -c 100 -i 0.01 against gateway).
     - busybox reports min/avg/max round-trip.
     - This driver also computes p99 from the per-packet ``time=`` lines
       the guest forwards.
  2. TCP single-stream throughput: 3 back-to-back wget downloads of
     ``/bytes/<SIZE>`` (default 64 MiB). Mean / stdev / min / max.

Final report includes the engine counter summary that tinyvmm prints
on shutdown (``[usernet-tsi] summary: total=N live=M ...``).

Usage:
  python tools\\usernet_bench.py
    [--tinyvmm <path>]
    [--vmlinux <path>] (default repo/vmlinux)
    [--initrd  <path>] (default repo/initramfs-net.cpio)
    [--timeout-sec <N>] (default 180)
    [--host-ip <a.b.c.d>] (default auto-discover via UDP-connect)
    [--size-mib <N>] (per-run TCP transfer size, default 64)
    [--ping-count <N>] (default 100)
"""
from __future__ import annotations

import argparse
import http.server
import re
import socket
import socketserver
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "target" / "release" / "tinyvmm.exe"
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_INITRD  = REPO / "initramfs-net.cpio"

BYTES_RE = re.compile(r"^/bytes/(\d+)$")


# ---------------------------------------------------------------------------
# IP discovery
# ---------------------------------------------------------------------------
def discover_host_ipv4(explicit: str | None) -> str:
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
            "[usernet-bench] FAIL: could not discover non-loopback IPv4; "
            "pass --host-ip <a.b.c.d>")
    return ip


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
class _Handler(http.server.BaseHTTPRequestHandler):
    # 1 MiB write buffer; reused across requests via class attribute to
    # avoid per-request allocation.
    _CHUNK = b"\xab" * (1024 * 1024)

    def log_message(self, *_args, **_kw) -> None:
        return

    def do_GET(self) -> None:
        m = BYTES_RE.match(self.path)
        if not m:
            self.send_error(404)
            return
        n = int(m.group(1))
        if n > 1024 * 1024 * 1024:  # 1 GiB hard cap
            self.send_error(400, "bytes too large")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(n))
        self.send_header("Connection", "close")
        self.end_headers()
        sent = 0
        buf = _Handler._CHUNK
        try:
            while sent < n:
                chunk = min(len(buf), n - sent)
                self.wfile.write(buf[:chunk])
                sent += chunk
        except (BrokenPipeError, ConnectionResetError):
            return


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_http_server(bind_ip: str = "0.0.0.0") -> tuple[_Server, int]:
    srv = _Server((bind_ip, 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True,
                         name="usernet-bench-http")
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
        finally:
            done.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    while proc.poll() is None:
        if time.monotonic() - t_start > timeout_sec:
            print(f"\n[usernet-bench] timeout after {timeout_sec}s; "
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
# Parsing + reporting
# ---------------------------------------------------------------------------
PING_RTT_RE = re.compile(r"BENCH PING RTT .*time=([\d.]+) ms")
PING_SUMMARY_RE = re.compile(
    r"BENCH PING SUMMARY .*min/avg/max\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)\s*ms")
TCP_RE = re.compile(
    r"BENCH TCP run=(\d+) rc=(\d+) bytes=(\d+) got=(\d+) delta_us=(\d+) mbps=(\d+)")
TCP_ERR_RE = re.compile(r"BENCH TCP run=(\d+) wget_err: (.+)$")
ENGINE_SUMMARY_RE = re.compile(
    r"\[usernet-tsi\]\s*summary:\s*"
    r"total=(\d+)\s+live=(\d+)\s+seg_rx=(\d+)\s+seg_tx=(\d+)\s+"
    r"aborts=(\d+)\s+graceful=(\d+)\s+rsts=(\d+)")


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    # nearest-rank
    k = max(0, min(len(s) - 1, int(round(pct / 100.0 * (len(s) - 1)))))
    return s[k]


def report(log: str, size_bytes: int, ping_count: int) -> bool:
    print("\n" + "=" * 72)
    print(f"[usernet-bench] REPORT (tcp_engine=tcp-sans-io)")
    print("=" * 72)

    # ---- Ping latency ----
    rtts = [float(m.group(1)) for m in PING_RTT_RE.finditer(log)]
    summ = PING_SUMMARY_RE.search(log)
    if summ:
        bb_min = float(summ.group(1))
        bb_avg = float(summ.group(2))
        bb_max = float(summ.group(3))
    else:
        bb_min = bb_avg = bb_max = 0.0
    p50  = percentile(rtts, 50) if rtts else 0.0
    p95  = percentile(rtts, 95) if rtts else 0.0
    p99  = percentile(rtts, 99) if rtts else 0.0
    print(f"\nPing latency (gateway 10.0.0.1, {len(rtts)}/{ping_count} replies)")
    print(f"  busybox min/avg/max : {bb_min:.3f} / {bb_avg:.3f} / "
          f"{bb_max:.3f} ms")
    print(f"  driver p50/p95/p99  : {p50:.3f} / {p95:.3f} / "
          f"{p99:.3f} ms")
    if rtts:
        # stddev (sample); requires at least 2 values
        stdev = statistics.stdev(rtts) if len(rtts) >= 2 else 0.0
        print(f"  driver mean (stdev) : {statistics.mean(rtts):.3f} "
              f"({stdev:.3f}) ms")

    # ---- TCP throughput ----
    tcp_runs = list(TCP_RE.finditer(log))
    if not tcp_runs:
        print("\nTCP single-stream: NO RUNS FOUND")
        return False
    mbps_list = []
    print(f"\nTCP single-stream throughput "
          f"(size={size_bytes // (1024 * 1024)} MiB per run)")
    for m in tcp_runs:
        run = int(m.group(1))
        rc = int(m.group(2))
        bytes_ = int(m.group(3))
        got = int(m.group(4))
        delta_us = int(m.group(5))
        mbps = int(m.group(6))
        if rc != 0 or got != bytes_:
            print(f"  run {run}: rc={rc} got={got}/{bytes_} FAILED")
        else:
            delta_s = delta_us / 1e6
            print(f"  run {run}: {mbps:>6} Mbps "
                  f"({bytes_ / (1024 * 1024):.1f} MiB in {delta_s:.3f} s)")
            mbps_list.append(mbps)
    for m in TCP_ERR_RE.finditer(log):
        print(f"  run {m.group(1)} stderr: {m.group(2).strip()}")
    if mbps_list:
        stdev = statistics.stdev(mbps_list) if len(mbps_list) >= 2 else 0
        print(f"\n  mean : {statistics.mean(mbps_list):.0f} Mbps "
              f"(stdev {stdev:.0f})")
        print(f"  min  : {min(mbps_list)} Mbps")
        print(f"  max  : {max(mbps_list)} Mbps")

    # ---- Engine summary ----
    es = ENGINE_SUMMARY_RE.search(log)
    if es:
        print(f"\nTSI engine counters")
        print(f"  total_conns      : {es.group(1)}")
        print(f"  live_at_shutdown : {es.group(2)}")
        print(f"  segments_rx      : {es.group(3)} (guest->engine)")
        print(f"  segments_tx      : {es.group(4)} (engine->guest)")
        print(f"  aborts           : {es.group(5)}")
        print(f"  graceful_closes  : {es.group(6)}")
        print(f"  synthetic_rsts   : {es.group(7)}")
        if int(es.group(2)) != 0:
            print(f"  WARN: live!=0 (engine had {es.group(2)} TCB(s) at "
                  "shutdown; TIME_WAIT may not have drained)")
    else:
        print("\nWARN: no [usernet-tsi] summary line in log")

    print("=" * 72)
    return bool(mbps_list)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--initrd",  type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--timeout-sec", type=int, default=180)
    ap.add_argument("--host-ip", type=str, default=None)
    ap.add_argument("--size-mib", type=int, default=64,
                    help="per-run TCP transfer size in MiB (default 64)")
    ap.add_argument("--ping-count", type=int, default=100,
                    help="ping packet count (default 100)")
    args = ap.parse_args()

    for p, label in [(args.tinyvmm, "tinyvmm.exe"),
                     (args.vmlinux, "vmlinux"),
                     (args.initrd,  "initrd")]:
        if not p.exists():
            print(f"[usernet-bench] FAIL: {label} not found at {p}",
                  file=sys.stderr)
            return 2

    size_bytes = args.size_mib * 1024 * 1024
    host_ip = discover_host_ipv4(args.host_ip)
    print(f"[usernet-bench] host IP: {host_ip}")
    srv, port = start_http_server("0.0.0.0")
    print(f"[usernet-bench] HTTP bench server: 0.0.0.0:{port}")
    print(f"[usernet-bench] per-run size: {args.size_mib} MiB "
          f"({size_bytes} bytes)")
    print(f"[usernet-bench] ping count: {args.ping_count}")

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
            "tinyvmm.test=usernet-bench",
            f"TINYVMM_BENCH_HOST={host_ip}",
            f"TINYVMM_BENCH_PORT={port}",
            f"TINYVMM_BENCH_SIZE={size_bytes}",
            f"TINYVMM_BENCH_PINGCOUNT={args.ping_count}",
        ]
        rc, log = run_vmm(argv, args.timeout_sec)
        print(f"\n[usernet-bench] tinyvmm exited rc={rc}")
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass

    ok = report(log, size_bytes, args.ping_count)
    if not ok:
        print("[usernet-bench] FAIL: no successful TCP runs", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
