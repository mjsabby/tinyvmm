"""PoC, finding 14: a save that does not finish destroys the snapshot that was
at its path.

A good snapshot is saved to a path. A second save to the same path (of a
guest holding a couple of GiB of random data, so that writing takes a moment)
is killed while the file is being written. A vulnerable build wrote in place:
the good snapshot is gone, a truncated file is all that is left. A fixed build
writes beside the path and renames when whole: the good snapshot is still
there, byte for byte.
"""
import hashlib
import subprocess
import time
from pathlib import Path

from .common import REPO, build_initramfs, bytes_written, takes_sentinel_flag

INIT = rb"""#!/bin/busybox sh
bb=/bin/busybox
$bb mount -t proc proc /proc
$bb mount -t devtmpfs dev /dev
$bb mount -t tmpfs -o size=90% tmpfs /tmp
log() { echo "[poc] $*" > /dev/kmsg; }
fill=$($bb tr ' ' '\n' < /proc/cmdline | $bb grep '^fill=' | $bb cut -d= -f2)
$bb dd if=/dev/urandom of=/tmp/fill bs=1M count=${fill:-1} 2>/dev/null
log "filled ${fill:-1} MiB; asking for the snapshot"
/bin/cpuid_trigger
log "resumed after the snapshot"
$bb poweroff -f
exec $bb cat
"""


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def run(exe: Path, work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    initrd = build_initramfs(work / "snap.cpio.gz", INIT)
    snap = work / "vm.tvm"
    for f in work.glob("vm.tvm*"):
        f.unlink()

    def save(fill: int, ram: int, out=subprocess.PIPE):
        argv = [str(exe), "--pvh-run", "--ram-mb", str(ram), "--watchdog-secs", "120", "--save", str(snap),
                "--initrd", str(initrd), str(REPO / "vmlinux"), "--", "console=hvc0",
                "pci=conf1,nocrs,lastbus=0", f"fill={fill}"]
        return subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT)

    p = save(4, 512)
    out, _ = p.communicate(timeout=180)
    if p.returncode != 0 or not snap.exists():
        return {"vulnerable": None, "evidence": "could not make the first snapshot: " + out.decode("utf-8", "replace")[-300:]}
    good, good_size = sha(snap), snap.stat().st_size

    # The second save: kill it once it has written a good part of the file,
    # going by what the process itself has written (all else it writes is a
    # boot log). The file can't be asked: a build that marks its partial file
    # to go with its handle lets nobody else open it.
    with open(work / "second-save.log", "wb") as log:
        p = save(2500, 4096, log)
        killed_at = None
        deadline = time.monotonic() + 240
        while p.poll() is None and time.monotonic() < deadline:
            written = bytes_written(p._handle)
            if written > (256 << 20):
                killed_at = written
                p.kill()
                break
            time.sleep(0.005)
        p.wait()
    if killed_at is None:
        return {"vulnerable": None, "evidence": "the second save finished before it could be interrupted "
                                                f"(rc={p.returncode}); nothing shown"}
    intact = snap.exists() and snap.stat().st_size == good_size and sha(snap) == good
    left = sorted(f.name for f in work.glob("vm.tvm*"))
    now = snap.stat().st_size if snap.exists() else None
    evidence = (f"first snapshot {good_size} bytes; second save killed after writing {killed_at >> 20} MiB; "
                f"file at the path afterwards: {'the first snapshot, unchanged' if intact else f'{now} bytes, not the first snapshot'}; "
                f"files left: {left}")
    if intact:
        # And it still restores.
        argv = [str(exe), "--restore", str(snap), "--watchdog-secs", "60"]
        if takes_sentinel_flag(exe):
            argv.append("--shutdown-sentinel")
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=180)
        restored = "resumed after the snapshot" in r.stdout + r.stderr
        evidence += f"; it restores: {restored}"
        intact = intact and restored
    for f in work.glob("vm.tvm*"):
        f.unlink()
    return {"vulnerable": not intact, "evidence": evidence}
