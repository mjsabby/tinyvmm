#!/usr/bin/env python3
"""Capture + aggregate tinyvmm heap allocations from an xperf trace.

tinyvmm ships an ETW-logging global allocator (src/diag/alloc_trace.rs): every
Rust alloc/realloc/free emits an event on the `Tinyvmm-Core` provider under the
`HEAP` keyword (0x800) at VERBOSE. This driver starts an xperf session on that
provider with per-event stack walking, plus a kernel logger (PROC_THREAD+LOADER)
so the stacks symbolicate, runs a workload (which may spawn tinyvmm as a child),
then merges + dumps the trace with symbols and rolls every HeapAlloc/HeapRealloc
up by call site -- so you can see *where* allocations come from and how hot each
site is.

Use a DEBUG build of tinyvmm (it ships a PDB next to the exe, which is what makes
the stacks symbolicate to function names).

Usage:
  # capture a workload (note the `--` before the command):
  python tools\\alloc_report.py --label p9 -- \\
      python tools\\p9_bench.py --tinyvmm target\\debug\\tinyvmm.exe ...

  # re-analyze a dump captured earlier (no admin / no re-run needed):
  python tools\\alloc_report.py --label p9 --dump %TEMP%\\tinyvmm-alloc\\p9_dump.txt

Requires: xperf (Windows Performance Toolkit) on PATH, and Administrator rights
to start the kernel logger.
"""
from __future__ import annotations

import argparse
import collections
import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_DEBUG_DIR = REPO / "target" / "debug"

# Provider GUID + keyword/level must match crates/winsys/src/etw.rs.
GUID = "0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d"
HEAP_KEYWORD = "0x800"
VERBOSE_LEVEL = "5"
SESSION = "tinyheap"

# Allocator-entry frames: everything inward of (and including) the outermost
# match is plumbing (our ETW emit + the GlobalAlloc shim); the real call site is
# the frame just outward of it.
ALLOC_ENTRY = ("__rust_alloc", "__rust_dealloc", "__rust_realloc")
# Generic runtime entry frames trimmed from the kept stack tail.
TAIL_NOISE = (
    "lang_start", "__rust_begin_short_backtrace", "FnOnce::call_once",
    "invoke_main", "BaseThreadInitThunk", "RtlUserThreadStart",
    "__scrt_common_main", "mainCRTStartup",
)


def stop_sessions() -> None:
    for cmd in (["xperf", "-stop", SESSION], ["xperf", "-stop"]):
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def capture(label: str, outdir: pathlib.Path, debug_dir: pathlib.Path,
            cmd: list[str]) -> pathlib.Path:
    u = outdir / f"{label}_u.etl"
    k = outdir / f"{label}_k.etl"
    m = outdir / f"{label}_m.etl"
    dump = outdir / f"{label}_dump.txt"
    stop_sessions()
    # Bare GUID (no braces); ":'stack'" requests a walked stack per event.
    prov = f"{GUID}:{HEAP_KEYWORD}:{VERBOSE_LEVEL}:'stack'"
    subprocess.check_call(["xperf", "-start", SESSION, "-on", prov, "-f", str(u)])
    subprocess.check_call(["xperf", "-on", "PROC_THREAD+LOADER", "-f", str(k)])
    try:
        if cmd:
            print(f"[alloc_report] running: {' '.join(cmd)}", flush=True)
            subprocess.run(cmd)
    finally:
        stop_sessions()
    subprocess.check_call(["xperf", "-merge", str(u), str(k), str(m)])
    env = dict(os.environ)
    # Local PDB only -- no network symbol server (system DLL frames stay raw,
    # which is fine; we only care about tinyvmm.exe frames).
    env["_NT_SYMBOL_PATH"] = str(debug_dir)
    subprocess.run(
        ["xperf", "-i", str(m), "-symbols", "-o", str(dump), "-a", "dumper"],
        env=env,
    )
    return dump


def parse_size(event_line: str) -> int | None:
    last = event_line.rsplit(",", 1)[-1].strip()
    try:
        return int(last)
    except ValueError:
        return None  # column-header row


def site_key(frames: list[str]) -> tuple[str, ...]:
    cut = -1
    for i, f in enumerate(frames):
        if any(s in f for s in ALLOC_ENTRY):
            cut = i
    tail = frames[cut + 1:] if cut >= 0 else frames
    tail = [f for f in tail if not any(n in f for n in TAIL_NOISE)]
    return tuple(tail[:6])


def analyze(dump: pathlib.Path, top: int) -> None:
    by_count: collections.Counter = collections.Counter()
    by_bytes: collections.Counter = collections.Counter()
    n_alloc = n_free = 0
    b_alloc = b_free = 0

    cur_kind = None
    cur_size = 0
    cur_frames: list[str] = []

    def flush():
        nonlocal n_alloc, b_alloc
        if cur_kind in ("HeapAlloc", "HeapRealloc"):
            key = site_key(cur_frames)
            by_count[key] += 1
            by_bytes[key] += cur_size
            n_alloc += 1
            b_alloc += cur_size

    with open(dump, "r", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            s = line.strip()
            if s.startswith("Tinyvmm-Core/Heap"):
                flush()
                cur_frames = []
                kind = s.split("/", 2)[1]
                size = parse_size(line)
                if size is None:  # header row
                    cur_kind = None
                    continue
                cur_kind = kind
                cur_size = size
                if kind == "HeapFree":
                    n_free += 1
                    b_free += size
            elif s.startswith("Stack,") and cur_kind:
                cur_frames.append(line.rsplit(",", 1)[-1].strip())
            else:
                flush()
                cur_kind = None
                cur_frames = []
    flush()

    print()
    print(f"=== {dump.name} ===")
    print(f"allocations (alloc+realloc): {n_alloc:>8}  bytes={b_alloc:,}")
    print(f"frees                      : {n_free:>8}  bytes={b_free:,}")
    print(f"distinct alloc sites       : {len(by_count):>8}")

    print(f"\n--- top {top} allocation sites by COUNT ---")
    for key, cnt in by_count.most_common(top):
        print(f"\n  count={cnt}  bytes={by_bytes[key]:,}")
        for f in key:
            print(f"      {f}")

    print(f"\n--- top {top} allocation sites by BYTES ---")
    for key, b in sorted(by_bytes.items(), key=lambda kv: kv[1], reverse=True)[:top]:
        print(f"\n  bytes={b:,}  count={by_count[key]}")
        for f in key:
            print(f"      {f}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Capture + aggregate tinyvmm heap allocations via xperf.")
    ap.add_argument("--label", required=True, help="prefix for the .etl/.txt artifacts")
    ap.add_argument("--outdir", default=str(pathlib.Path(os.environ.get("TEMP", ".")) / "tinyvmm-alloc"))
    ap.add_argument("--debug-dir", default=str(DEFAULT_DEBUG_DIR),
                    help="dir containing tinyvmm.exe + tinyvmm.pdb (for symbols)")
    ap.add_argument("--dump", help="analyze an existing dump.txt instead of capturing")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="workload to run, after a literal --")
    args = ap.parse_args()

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if args.dump:
        dump = pathlib.Path(args.dump)
    else:
        cmd = args.cmd
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            print("error: provide a workload after `--`, or use --dump", file=sys.stderr)
            return 2
        dump = capture(args.label, outdir, pathlib.Path(args.debug_dir), cmd)
    analyze(dump, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
