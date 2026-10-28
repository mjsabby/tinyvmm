#!/usr/bin/env python3
"""Compare user-mode NAT networking: tinyvmm (`--net-backend nat`) vs OpenVMM
(`--virtio-net consomme`).

Both VMMs boot the SAME vmlinux + initramfs with a virtio-net NIC whose
backend is the VMM's slirp-style user-mode NAT (guest 10.0.0.2/24, gateway
10.0.0.1 in both). The guest runs the `tinyvmm.test=netcmp` /init mode
(tools/make_initramfs.py) against a host server bound to the host's LAN IP,
so every byte traverses the VMM's virtio-net device + NAT + host TCP stack.

Phases (guest-driven; throughput is timed HOST-side by the server because the
guest's /proc/uptime only has 10 ms resolution):
  ping  ICMP echo to the host IP through the NAT (busybox ping -i 0.01)
  rr    N sequential HTTP GETs of 1 byte, each a fresh TCP connection
        (connect + request + response + close) -> transactions/s
  dl    single-stream download host->guest, RUNS x SIZE
  ul    single-stream upload guest->host (wget --post-file from tmpfs)
  par   PAR concurrent download streams, RUNS rounds, aggregate throughput
For every phase the driver also records the VMM process's host CPU time
(user+kernel via GetProcessTimes) to report CPU-seconds per GiB moved.

Usage:
  python tools\\net_compare.py
    [--vmm tinyvmm,openvmm-vpci,openvmm-pcie]  VMM configs (default all)
    [--iterations 1]             full boots per VMM (results aggregated)
    [--tinyvmm <exe>] [--openvmm <exe>]
    [--vmlinux <path>] [--initrd <path>] [--no-build]
    [--vcpus 1] [--ram-mb 1024]
    [--size-mib 256] [--runs 3] [--rr 200] [--par 4] [--ping 200]
    [--host-ip a.b.c.d] [--timeout-sec 600] [--json out.json] [--verbose]
"""
from __future__ import annotations

import argparse
import ctypes
import json
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_TINYVMM = REPO / "target" / "release" / "tinyvmm.exe"
DEFAULT_OPENVMM = Path(r"C:\openvmm\target\release\openvmm.exe")
DEFAULT_VMLINUX = REPO / "vmlinux"
DEFAULT_INITRD = REPO / "initramfs-netcmp.cpio.gz"
DEFAULT_BUSYBOX = REPO / "busybox-x86_64"

CHUNK = memoryview(b"\xab" * (1 << 20))


# ---------------------------------------------------------------------------
# Host server: GET /bytes/<n>/<tag> and POST /upload/<tag>, timed per tag.
# ---------------------------------------------------------------------------
@dataclass
class Xfer:
    tag: str
    nbytes: int
    t0: float
    t1: float


class Server:
    def __init__(self, bind_ip: str) -> None:
        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.bind((bind_ip, 0))
        self.lsock.listen(128)
        self.port = self.lsock.getsockname()[1]
        self.lock = threading.Lock()
        self.xfers: list[Xfer] = []
        self.errors: list[str] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def take(self) -> list[Xfer]:
        with self.lock:
            out, self.xfers = self.xfers, []
            return out

    def _accept(self) -> None:
        while True:
            try:
                c, _ = self.lsock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c: socket.socket) -> None:
        try:
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.settimeout(120)
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(65536)
                if not d:
                    return
                buf += d
            head, rest = buf.split(b"\r\n\r\n", 1)
            t0 = time.perf_counter()
            lines = head.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            hdrs = {k.strip().lower(): v.strip()
                    for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
            parts = path.strip("/").split("/")
            if method == "GET" and parts[0] == "bytes":
                n = int(parts[1])
                tag = parts[2] if len(parts) > 2 else ""
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                          b"Content-Length: %d\r\nConnection: close\r\n\r\n" % n)
                left = n
                while left:
                    k = min(left, len(CHUNK))
                    c.sendall(CHUNK[:k])
                    left -= k
                # Done when the guest has consumed everything and closed.
                c.shutdown(socket.SHUT_WR)
                while c.recv(65536):
                    pass
                t1 = time.perf_counter()
            elif method == "POST" and parts[0] == "upload":
                tag = parts[1] if len(parts) > 1 else ""
                n = int(hdrs.get("content-length", "0"))
                got = len(rest)
                rb = bytearray(1 << 20)
                while got < n:
                    k = c.recv_into(rb)
                    if not k:
                        break
                    got += k
                t1 = time.perf_counter()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                if got != n:
                    raise OSError(f"upload {tag}: got {got}/{n}")
            else:
                c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                return
            with self.lock:
                self.xfers.append(Xfer(tag, n, t0, t1))
        except Exception as e:  # noqa: BLE001 - record + keep serving
            with self.lock:
                self.errors.append(repr(e))
        finally:
            c.close()


def discover_host_ipv4(explicit: str | None) -> str:
    if explicit:
        return explicit
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Process CPU time (user + kernel) via GetProcessTimes.
# ---------------------------------------------------------------------------
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
_k32.GetProcessTimes.restype = wintypes.BOOL
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x2


class _PE32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


_k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PE32)]
_k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PE32)]


def _descendants(root: int) -> list[int]:
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    kids: dict[int, list[int]] = {}
    pe = _PE32(dwSize=ctypes.sizeof(_PE32))
    ok = _k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        kids.setdefault(pe.th32ParentProcessID, []).append(pe.th32ProcessID)
        ok = _k32.Process32NextW(snap, ctypes.byref(pe))
    _k32.CloseHandle(snap)
    out, todo = [], [root]
    while todo:
        p = todo.pop()
        out.append(p)
        todo.extend(k for k in kids.get(p, []) if k not in out)
    return out


def _cpu_of(h: int) -> float:
    c, e, k, u = (wintypes.FILETIME() for _ in range(4))
    if not _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                ctypes.byref(k), ctypes.byref(u)):
        return 0.0
    ft = lambda f: ((f.dwHighDateTime << 32) | f.dwLowDateTime) / 1e7  # noqa: E731
    return ft(k) + ft(u)


def proc_cpu_seconds(proc: subprocess.Popen) -> float:
    """User+kernel CPU of the VMM and all its descendants (OpenVMM runs the VM
    in a mesh child process; tinyvmm is a single process)."""
    total = 0.0
    for pid in _descendants(proc.pid):
        h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h:
            total += _cpu_of(h)
            _k32.CloseHandle(h)
    return total


# ---------------------------------------------------------------------------
# VMM launch
# ---------------------------------------------------------------------------
def guest_cmdline(a: argparse.Namespace, host: str, port: int, console: str) -> str:
    return " ".join([
        f"console={console}",
        "pci=conf1,nocrs,lastbus=0" if console == "hvc0" else "",
        "tinyvmm.test=netcmp",
        f"NETCMP_HOST={host}", f"NETCMP_PORT={port}",
        f"NETCMP_SIZE={a.size_mib << 20}", f"NETCMP_RUNS={a.runs}",
        f"NETCMP_RR={a.rr}", f"NETCMP_PAR={a.par}", f"NETCMP_PING={a.ping}",
    ]).replace("  ", " ")


def vmm_argv(name: str, a: argparse.Namespace, host: str, port: int) -> list[str]:
    if name == "tinyvmm":
        return [str(a.tinyvmm), "--pvh-run", "--ram-mb", str(a.ram_mb),
                "--vcpus", str(a.vcpus), "--net", "--net-backend", "nat",
                "--initrd", str(a.initrd), "--watchdog-secs", str(a.timeout_sec),
                str(a.vmlinux), "--", guest_cmdline(a, host, port, "hvc0")]
    if name.startswith("openvmm"):
        argv = [str(a.openvmm), "--kernel", str(a.vmlinux), "--initrd", str(a.initrd),
                "--memory", f"{a.ram_mb}MB", "--processors", str(a.vcpus),
                "--com1", "stderr",
                "--cmdline", guest_cmdline(a, host, port, "ttyS0")]
        if name == "openvmm-vpci":
            # OpenVMM's default for this kernel: virtio-pci behind Hyper-V VPCI
            # (vmbus + hypercall MSI), auto-selected when --hv is on.
            return argv + ["--hv", "--virtio-net", "consomme"]
        if name == "openvmm-pcie":
            # Emulated PCIe root port with ECAM (ACPI MCFG): plain virtio-pci +
            # MSI-X, the closest match to tinyvmm's device model.
            return argv + ["--pcie-root-complex", "rc0", "--pcie-root-port", "rc0:rc0rp0",
                           "--virtio-net", "pcie_port=rc0rp0:consomme"]
    raise SystemExit(f"unknown vmm {name}")


PHASE_RE = re.compile(r"NETCMP PHASE (\w+) (begin|end)")


@dataclass
class RunResult:
    vmm: str
    ok: bool = False
    phases: dict = field(default_factory=dict)   # name -> {wall, cpu}
    xfers: dict = field(default_factory=dict)    # phase -> [Xfer]
    ping: str = ""
    rr: tuple | None = None                     # (n, ok, us)
    log: str = ""


def run_one(name: str, a: argparse.Namespace, srv: Server, host: str) -> RunResult:
    argv = vmm_argv(name, a, host, srv.port)
    print(f"\n[net-compare] === {name} ===\n[net-compare] {' '.join(argv)}", flush=True)
    srv.take()
    res = RunResult(vmm=name)
    # stdin stays an open, never-written pipe: OpenVMM's REPL stops the VM on
    # stdin EOF (so DEVNULL would kill it immediately).
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    marks: dict[str, tuple[float, float]] = {}
    lines: list[str] = []
    done = threading.Event()

    def reader() -> None:
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip()
            lines.append(line)
            if a.verbose or "NETCMP" in line:
                print(f"  | {line}", flush=True)
            m = PHASE_RE.search(line)
            if m:
                now, cpu = time.perf_counter(), proc_cpu_seconds(proc)
                if m.group(2) == "begin":
                    marks[m.group(1)] = (now, cpu)
                else:
                    t0, c0 = marks.get(m.group(1), (now, cpu))
                    res.phases[m.group(1)] = {"wall": now - t0, "cpu": cpu - c0}
                    res.xfers[m.group(1)] = srv.take()
            if "NETCMP PING" in line:
                res.ping = line
            mm = re.search(r"NETCMP RR n=(\d+) ok=(\d+) us=(\d+)", line)
            if mm:
                res.rr = tuple(int(x) for x in mm.groups())
            if "NETCMP DONE" in line:
                res.ok = True
                done.set()
        done.set()

    threading.Thread(target=reader, daemon=True).start()
    if not done.wait(a.timeout_sec):
        print(f"[net-compare] {name}: timeout after {a.timeout_sec}s", flush=True)
    # Give the guest a moment to power off cleanly, then make sure it's gone.
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       capture_output=True)
        proc.wait(timeout=10)
    res.log = "\n".join(lines)
    if not res.ok and not a.verbose:
        print("\n".join(lines[-40:]))
    return res


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def gbps(nbytes: int, secs: float) -> float:
    return nbytes * 8 / secs / 1e9 if secs > 0 else 0.0


def summarize(rs: list[RunResult]) -> dict:
    s: dict = {}
    rtts, losses, rr_tps = [], [], []
    dl, ul, par = [], [], []
    cpu = {k: [0.0, 0] for k in ("dl", "ul", "par")}  # cpu secs, bytes
    for r in rs:
        m = re.search(r"min/avg/max = ([\d.]+)/([\d.]+)/([\d.]+)", r.ping)
        if m:
            rtts.append(tuple(float(x) for x in m.groups()))
        m = re.search(r"(\d+)% packet loss", r.ping)
        if m:
            losses.append(int(m.group(1)))
        if r.rr and r.rr[2] > 0:
            rr_tps.append(r.rr[1] / (r.rr[2] / 1e6))
        for ph, lst in (("dl", dl), ("ul", ul)):
            for x in r.xfers.get(ph, []):
                if x.tag.startswith(ph) and x.tag[len(ph):].isdigit():
                    lst.append(gbps(x.nbytes, x.t1 - x.t0))
        rounds: dict[str, list[Xfer]] = {}
        for x in r.xfers.get("par", []):
            if x.tag.startswith("par"):
                rounds.setdefault(x.tag.split("_")[0], []).append(x)
        for xs in rounds.values():
            t0, t1 = min(x.t0 for x in xs), max(x.t1 for x in xs)
            par.append(gbps(sum(x.nbytes for x in xs), t1 - t0))
        for ph in cpu:
            if ph in r.phases:
                cpu[ph][0] += r.phases[ph]["cpu"]
                cpu[ph][1] += sum(x.nbytes for x in r.xfers.get(ph, []))
    s["ping_avg_ms"] = statistics.mean(t[1] for t in rtts) if rtts else None
    s["ping_min_ms"] = min(t[0] for t in rtts) if rtts else None
    s["ping_max_ms"] = max(t[2] for t in rtts) if rtts else None
    s["ping_loss_pct"] = max(losses) if losses else None
    s["rr_tps"] = statistics.mean(rr_tps) if rr_tps else None
    for k, v in (("dl", dl), ("ul", ul), ("par", par)):
        s[f"{k}_gbps"] = statistics.mean(v) if v else None
        s[f"{k}_gbps_min"] = min(v) if v else None
        s[f"{k}_gbps_max"] = max(v) if v else None
        s[f"{k}_n"] = len(v)
        c, b = cpu[k]
        s[f"{k}_cpu_s_per_gib"] = c / (b / (1 << 30)) if b else None
    return s


def fmt(v, spec: str) -> str:
    return "n/a" if v is None else format(v, spec)


def report(results: dict[str, list[RunResult]], a: argparse.Namespace) -> dict:
    sums = {k: summarize(v) for k, v in results.items()}
    names = list(sums)
    rows = [
        ("ping avg (ms)            lower=better", "ping_avg_ms", ".3f"),
        ("ping min/max (ms)", None, None),
        ("ping loss (%)", "ping_loss_pct", "d"),
        ("TCP conn+req/resp (txn/s) higher=better", "rr_tps", ".1f"),
        (f"download 1 stream (Gbps)", "dl_gbps", ".3f"),
        (f"upload 1 stream (Gbps)", "ul_gbps", ".3f"),
        (f"download x{a.par} streams (Gbps)", "par_gbps", ".3f"),
        ("VMM CPU s/GiB download   lower=better", "dl_cpu_s_per_gib", ".3f"),
        ("VMM CPU s/GiB upload", "ul_cpu_s_per_gib", ".3f"),
        (f"VMM CPU s/GiB x{a.par} download", "par_cpu_s_per_gib", ".3f"),
    ]
    w = 42
    print("\n" + "=" * (w + 18 * len(names)))
    print(f"NAT networking comparison  (vcpus={a.vcpus}, ram={a.ram_mb} MiB, "
          f"size={a.size_mib} MiB x {a.runs} runs, iterations={a.iterations})")
    print("=" * (w + 18 * len(names)))
    print(" " * w + "".join(f"{n:>18}" for n in names))
    for label, key, spec in rows:
        if key is None:
            cells = [f"{fmt(s['ping_min_ms'], '.3f')}/{fmt(s['ping_max_ms'], '.3f')}"
                     for s in sums.values()]
        else:
            cells = []
            for s in sums.values():
                v = s[key]
                cell = fmt(v, spec)
                if key.endswith("_gbps") and v is not None:
                    cell += f" ({s[key + '_min']:.2f}-{s[key + '_max']:.2f})"
                cells.append(cell)
        print(f"{label:<{w}}" + "".join(f"{c:>18}" for c in cells))
    print("  (Gbps cells: mean (min-max) over all runs; CPU = VMM process user+kernel)")
    return sums


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vmm", default="tinyvmm,openvmm-vpci,openvmm-pcie")
    ap.add_argument("--iterations", type=int, default=1)
    ap.add_argument("--tinyvmm", type=Path, default=DEFAULT_TINYVMM)
    ap.add_argument("--openvmm", type=Path, default=DEFAULT_OPENVMM)
    ap.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    ap.add_argument("--initrd", type=Path, default=DEFAULT_INITRD)
    ap.add_argument("--busybox", type=Path, default=DEFAULT_BUSYBOX)
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--ram-mb", type=int, default=1024)
    ap.add_argument("--size-mib", type=int, default=256)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--rr", type=int, default=200)
    ap.add_argument("--par", type=int, default=4)
    ap.add_argument("--ping", type=int, default=200)
    ap.add_argument("--host-ip")
    ap.add_argument("--timeout-sec", type=int, default=600)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    if not a.no_build:
        subprocess.run([sys.executable, str(REPO / "tools" / "make_initramfs.py"),
                        "--busybox", str(a.busybox), "--out", str(a.initrd)], check=True)
    host = discover_host_ipv4(a.host_ip)
    srv = Server(host)
    print(f"[net-compare] host server {host}:{srv.port}")
    vmms = [v.strip() for v in a.vmm.split(",") if v.strip()]
    results: dict[str, list[RunResult]] = {v: [] for v in vmms}
    # Interleave VMMs per iteration so host-state drift affects both equally.
    for it in range(a.iterations):
        for v in vmms:
            print(f"[net-compare] iteration {it + 1}/{a.iterations}: {v}")
            results[v].append(run_one(v, a, srv, host))
    if srv.errors:
        print(f"[net-compare] server errors: {srv.errors[:5]}")
    sums = report(results, a)
    if a.json:
        a.json.write_text(json.dumps({"args": {k: str(v) for k, v in vars(a).items()},
                                      "summary": sums}, indent=2))
    failed = [v for v, rs in results.items() if not all(r.ok for r in rs)]
    if failed:
        print(f"[net-compare] FAIL: incomplete runs for {failed}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
