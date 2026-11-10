#!/usr/bin/env python3
"""Parallel 9p directory walks, one tinyvmm build against another.

    python poc\\bench\\p9_dirwalk.py                                   # 2,000 small directories
    python poc\\bench\\p9_dirwalk.py --subdirs 1 --files 1 --big 20000  # 8 long listings
    python poc\\bench\\p9_dirwalk.py --exe old=OLD.exe --exe new=NEW.exe --rounds 5

A read-only 9p share holds `--tops` top directories. The guest walks them
with `dirwalk` (bench/dirwalk.c: readdir only, d_type decides what to descend
into), first with one thread and then with one thread per top, and then both
again; the share is remounted before each walk, so the guest's own dentry
cache starts empty. A device that lists one directory at a time shows no
gain from the threads; one that lists directories side by side does.

Each build named by --exe is booted `--rounds` times, in turn; the median
of each walk is printed. Without --exe: the builds poc\\run.py uses.

--cold empties the host's standby list and working sets before each boot (as
RAMMap's Empty menu does: the whole machine's file cache, so everything else
runs slower for a moment; needs an elevated prompt), so that directory
metadata comes off the disk. --parallel-first then walks with all threads
first: the first walk after a boot is the one that finds the cache empty.

The tree and the guest are built once under poc/out/bench (ignored by git);
zig builds the walker, as it builds the PoC guest.
"""
from __future__ import annotations

import argparse
import ctypes
import gzip
import os
import re
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

BENCH = Path(__file__).resolve().parent
POC = BENCH.parent
REPO = POC.parent
OUT = POC / "out" / "bench"
sys.path.insert(0, str(POC / "guest"))
sys.path.insert(0, str(REPO / "tools"))
import build as guest_build  # noqa: E402
import make_initramfs as m  # noqa: E402

TEMP = Path(os.environ.get("TEMP") or tempfile.gettempdir())
WALK = re.compile(r"\[dirbench\] walk threads=(\d+) dirs=(\d+) entries=(\d+) errors=(\d+) ms=([\d.]+)")


def default_exes() -> list[tuple[str, Path]]:
    shared = TEMP / "tinyvmm-work" / "bin"
    fixed = shared / "fixed" / "tinyvmm.exe"
    exes = [("baseline", shared / "baseline" / "tinyvmm.exe"),
            ("fixed", fixed if fixed.exists() else REPO / "target" / "release" / "tinyvmm.exe")]
    return [(name, exe) for name, exe in exes if exe.exists()]


def build_tree(tops: int, subdirs: int, files: int, big: int) -> Path:
    """`tops` directories of `subdirs` directories of `files` empty files,
    and under each top one directory of `big` files (if any)."""
    tree = OUT / f"dirtree-{tops}x{subdirs}x{files}-big{big}"
    if (tree / ".done").exists():
        return tree
    t0 = time.time()
    for t in range(tops):
        for s in range(subdirs):
            d = tree / f"t{t}" / f"d{s:04d}"
            d.mkdir(parents=True, exist_ok=True)
            for f in range(files):
                (d / f"file{f:03d}.txt").touch()
        if big:
            d = tree / f"t{t}" / "big"
            d.mkdir(parents=True, exist_ok=True)
            for f in range(big):
                (d / f"entry-{f:07d}.dat").touch()
    (tree / ".done").touch()
    print(f"[dirbench] built {tree} in {time.time() - t0:.1f}s")
    return tree


def build_guest(tops: int, parallel_first: bool) -> Path:
    walker = OUT / "dirwalk"
    source = BENCH / "dirwalk.c"
    if not walker.exists() or walker.stat().st_mtime < source.stat().st_mtime:
        env = dict(os.environ)
        env.setdefault("ZIG_LOCAL_CACHE_DIR", str(POC / "out" / "zig-cache"))
        subprocess.run([guest_build.find_zig(), "cc", "-target", "x86_64-linux-musl", "-static",
                        "-O2", "-s", "-o", str(walker), str(source)], check=True, cwd=str(OUT),
                       env=env)
    roots = " ".join(f"/mnt/t{t}" for t in range(tops))
    order = f"{tops} 1 {tops} 1" if parallel_first else f"1 {tops} 1 {tops}"
    init = f"""#!/bin/busybox sh
bb=/bin/busybox
$bb mount -t proc proc /proc
$bb mount -t sysfs sys /sys
$bb mount -t devtmpfs dev /dev
log() {{ echo "[dirbench] $*" > /dev/kmsg; }}
opts=trans=virtio,version=9p2000.L,msize=512000
for n in {order}; do
    $bb mount -t 9p -o $opts host /mnt || {{ log "mount failed"; $bb poweroff -f; }}
    log "walk $(/bin/dirwalk $n {roots})"
    $bb umount /mnt
done
log "DONE"
$bb poweroff -f
exec $bb cat
""".encode()
    cb = m.CpioBuilder()
    for d in [".", "bin", "dev", "proc", "sys", "mnt"]:
        cb.add_dir(d, mode=0o755)
    cb.add_chrdev("dev/console", major=5, minor=1, mode=0o600)
    cb.add_chrdev("dev/null", major=1, minor=3, mode=0o666)
    cb.add_chrdev("dev/kmsg", major=1, minor=11, mode=0o644)
    cb.add_file("bin/busybox", (REPO / "busybox-x86_64").read_bytes(), mode=0o755)
    cb.add_symlink("bin/sh", "busybox")
    cb.add_file("bin/dirwalk", walker.read_bytes(), mode=0o755)
    cb.add_file("init", init, mode=0o755)
    initrd = OUT / "dirbench.cpio.gz"
    with gzip.open(initrd, "wb", compresslevel=6) as f:
        f.write(cb.finalize())
    return initrd


def purge_host_caches() -> list[int]:
    """Empty the working sets, flush the modified list and purge the standby
    list (what RAMMap's Empty menu does). Returns the three NTSTATUSes."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class TP(ctypes.Structure):
        _fields_ = [("Count", wintypes.DWORD), ("Luid", LUID), ("Attr", wintypes.DWORD)]

    tok = wintypes.HANDLE()
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.HANDLE)]
    advapi.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                             ctypes.POINTER(LUID)]
    advapi.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TP),
                                             wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    if not advapi.OpenProcessToken(k32.GetCurrentProcess(), 0x28, ctypes.byref(tok)):
        raise ctypes.WinError(ctypes.get_last_error())
    for name in ("SeProfileSingleProcessPrivilege", "SeIncreaseQuotaPrivilege"):
        luid = LUID()
        advapi.LookupPrivilegeValueW(None, name, ctypes.byref(luid))
        tp = TP(1, luid, 2)
        advapi.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None)
    results = []
    # SystemMemoryListInformation = 80: 2 empty working sets, 3 flush the
    # modified list, 4 purge the standby list.
    for cmd in (2, 3, 4):
        v = ctypes.c_int(cmd)
        results.append(ntdll.NtSetSystemInformation(80, ctypes.byref(v), ctypes.sizeof(v))
                       & 0xFFFFFFFF)
    return results


def boot(exe: Path, tree: Path, initrd: Path, vcpus: int) -> list[tuple[int, int, int, int, float]]:
    """One VM: its four walks as (threads, dirs, entries, errors, ms)."""
    argv = [str(exe), "--pvh-run", "--vcpus", str(vcpus), "--ram-mb", "1024",
            "--watchdog-secs", "600", "--virtio-9p-share", f"host={tree},ro", "--initrd",
            str(initrd), str(REPO / "vmlinux"), "--", "console=hvc0", "pci=conf1,nocrs,lastbus=0"]
    out = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=900)
    text = out.stdout + out.stderr
    walks = [(int(t), int(d), int(e), int(err), float(ms))
             for t, d, e, err, ms in WALK.findall(text)]
    if len(walks) != 4 or "DONE" not in text:
        print(text[-2000:])
        raise SystemExit(f"{exe}: incomplete run ({len(walks)} walks)")
    return walks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", action="append", default=[], metavar="NAME=PATH",
                    help="a build to measure (repeatable; default: the builds poc\\run.py uses)")
    ap.add_argument("--rounds", type=int, default=3, help="boots per build (default 3)")
    ap.add_argument("--cold", action="store_true",
                    help="empty the host's file cache before each boot (elevated; see above)")
    ap.add_argument("--parallel-first", action="store_true",
                    help="walk with all threads first, then with one")
    ap.add_argument("--tops", type=int, default=8, help="top directories, and threads (default 8)")
    ap.add_argument("--subdirs", type=int, default=250, help="directories per top (default 250)")
    ap.add_argument("--files", type=int, default=20, help="files per directory (default 20)")
    ap.add_argument("--big", type=int, default=0,
                    help="also one directory of this many files under each top")
    ap.add_argument("--vcpus", type=int, default=4)
    a = ap.parse_args()

    exes = [(s.split("=", 1)[0], Path(s.split("=", 1)[1])) for s in a.exe] or default_exes()
    missing = [str(exe) for _, exe in exes if not exe.exists()]
    if missing or not exes:
        print("error: no tinyvmm to measure" + (": " + ", ".join(missing) if missing else ""),
              file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    tree = build_tree(a.tops, a.subdirs, a.files, a.big)
    initrd = build_guest(a.tops, a.parallel_first)

    keys = (("firstN", "first1", "againN", "again1") if a.parallel_first
            else ("first1", "firstN", "again1", "againN"))
    res: dict[str, dict[str, list[float]]] = {name: {k: [] for k in keys} for name, _ in exes}
    for r in range(a.rounds):
        for name, exe in exes:
            note = ""
            if a.cold:
                status = purge_host_caches()
                note = f" purge={['%x' % s for s in status]}"
                time.sleep(1)
            walks = boot(exe, tree, initrd, a.vcpus)
            if any(w[3] for w in walks):
                raise SystemExit(f"{name}: a walk met errors: {walks}")
            for key, w in zip(keys, walks):
                res[name][key].append(w[4])
            print(f"[dirbench] round {r + 1} {name}: "
                  + " ".join(f"{k}={w[4]:.0f}ms" for k, w in zip(keys, walks))
                  + f" (dirs={walks[0][1]} entries={walks[0][2]}){note}", flush=True)

    print(f"\n[dirbench] {'cold' if a.cold else 'warm'} host cache, {a.vcpus} vCPUs, median of "
          f"{a.rounds} boots, ms (1 thread / {a.tops} threads; 'first' is the first walk after "
          "boot, 'again' after a remount)")
    for name, _ in exes:
        med = {k: sorted(v)[len(v) // 2] for k, v in res[name].items()}
        print(f"  {name:14} first: {med['first1']:8.0f} / {med['firstN']:8.0f}    "
              f"again: {med['again1']:8.0f} / {med['againN']:8.0f}    "
              f"speedup with threads (again): {med['again1'] / med['againN']:.2f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
