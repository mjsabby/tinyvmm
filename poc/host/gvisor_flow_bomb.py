"""PoC, finding 10 (gVisor shim): a guest pins host memory and sockets with
flows.

With `--net-backend gvisor`, a guest opens 20,000 UDP flows (one datagram
each, from as many ports) and then 12,000 TCP connections to a host server
and holds them. An unbounded shim relays every one: each UDP flow holds two
64 KiB buffers and a host socket for a minute, each TCP connection two
256 KiB relay buffers, so tinyvmm's commit grows by gigabytes. A bounded shim
keeps 256 UDP flows (least recently used out first) and 4096 TCP connections
(the rest are refused), the crowd on small buffers.

The bounds are in the shim (gvisor/main.go), so what is judged is the DLL
passed in, with whichever tinyvmm.exe. Needs zig, to build the guest's tool.
"""
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

from .common import REPO, build_initramfs, commit_bytes, run_capped, takes_sentinel_flag

UDP_FLOWS, TCP_FLOWS = 20000, 12000
GATEWAY = "172.29.255.1"


def run(exe: Path, dll: Path, work: Path, zig: str | None = None) -> dict:
    zig = zig or shutil.which("zig")
    if not zig:
        return {"vulnerable": None, "skipped": True,
                "evidence": "zig not found (needed to build the guest tool)"}
    work.mkdir(parents=True, exist_ok=True)
    tool = work / "flowbomb"
    subprocess.run([zig, "cc", "-target", "x86_64-linux-musl", "-static", "-O2", "-o", str(tool),
                    str(Path(__file__).resolve().parent / "flowbomb.c")], check=True, capture_output=True)

    # Host side: a UDP sink and a TCP server that accepts and holds.
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1024)
    held, stop = [], threading.Event()

    def accept():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                held.append(c)
            except OSError:
                continue

    threading.Thread(target=accept, daemon=True).start()
    init = f"""#!/bin/busybox sh
bb=/bin/busybox
$bb mount -t proc proc /proc
$bb mount -t sysfs sys /sys
$bb mount -t devtmpfs dev /dev
log() {{ echo "[poc] $*" > /dev/kmsg; }}
$bb ip link set eth0 up
$bb ip addr add 172.29.255.2/29 dev eth0
$bb ip route add default via {GATEWAY}
echo 1024 65535 > /proc/sys/net/ipv4/ip_local_port_range
# The host measures tinyvmm at rest before the flows start.
$bb sleep 7
log "udp begin"
log "$(/bin/flowbomb udp {GATEWAY} {udp.getsockname()[1]} {UDP_FLOWS} 8)"
log "tcp begin"
log "$(/bin/flowbomb tcp {GATEWAY} {srv.getsockname()[1]} {TCP_FLOWS} 8)"
log "done"
$bb poweroff -f
exec $bb cat
""".encode()
    initrd = build_initramfs(work / "flowbomb.cpio.gz", init, {"bin/flowbomb": tool.read_bytes()})
    env = dict(os.environ, TINYVMM_GVISOR=str(dll))
    marks = {}

    def watch(proc):
        # Commit once the guest is up, then the peak in each phase.
        time.sleep(4)
        marks["idle"] = commit_bytes(proc._handle)[0]
        while proc.poll() is None:
            cur = commit_bytes(proc._handle)[0]
            phase = "tcp" if len(held) > 0 else "udp"
            marks[phase] = max(marks.get(phase, 0), cur)
            marks["held"] = max(marks.get("held", 0), len(held))
            time.sleep(0.2)

    argv = [exe, "--pvh-run", "--ram-mb", "1024", "--watchdog-secs", "200"]
    if takes_sentinel_flag(exe):
        argv.append("--shutdown-sentinel")
    argv += ["--net", "--net-backend", "gvisor", "--nat-host-local", "--initrd", initrd, REPO / "vmlinux", "--",
             "console=hvc0", "pci=conf1,nocrs,lastbus=0"]
    r = run_capped(argv, timeout=320, memory_limit=12 << 30, env=env, feed=watch)
    stop.set()
    for c in held:
        c.close()
    srv.close()
    udp.close()
    guest_udp = re.search(r"udp opened=(\d+) sent=(\d+)", r.output)
    guest_tcp = re.search(r"tcp opened=(\d+) connected=(\d+) failed=(\d+) unanswered=(\d+)", r.output)
    idle = marks.get("idle", 0)
    udp_growth = max(0, marks.get("udp", idle) - idle)
    tcp_growth = max(0, marks.get("tcp", idle) - idle)
    accepted = marks.get("held", 0)
    vulnerable = udp_growth > (512 << 20) or tcp_growth > (1500 << 20) or accepted > 4096 + 64
    evidence = (f"UDP: guest sent from {guest_udp.group(2) if guest_udp else '?'} ports, commit grew "
                f"{udp_growth >> 20} MiB; TCP: guest {guest_tcp.group(0) if guest_tcp else '?'}, the host server held "
                f"{accepted} connections at once, commit grew {tcp_growth >> 20} MiB; exit code {r.rc}"
                f"{' (timed out)' if r.timed_out else ''}")
    if not guest_udp or not guest_tcp:
        return {"vulnerable": None, "evidence": "guest did not finish: " + r.output[-400:]}
    return {"vulnerable": vulnerable, "evidence": evidence}
