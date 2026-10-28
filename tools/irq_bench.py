#!/usr/bin/env python3
"""A/B micro-benchmark of tinyvmm's interrupt paths (needs WHP; nested is fine).

Boots the `tinyvmm.test=bench-irq` initramfs mode (2 vCPUs + a sparse scratch
disk) once per build per round, interleaving the builds round-robin so host
noise lands on each alike, and prints the median (min..max) of:

  timer wake-up    SCHED_FIFO 1 ms `read -t` timeout: latency beyond the 1 ms
  blk QD1 read     4 KiB virtio-blk read at queue depth 1 (one MSI round trip)
  same-CPU RTT     fifo ping-pong between two tasks on CPU0 (no IPIs)
  cross-CPU RTT    the same between CPU0 and CPU1 (two cross-CPU wake-ups)
  idle host CPU    tinyvmm's CPU use while the guest idles for 10 s
  BSP exits        VM exits vCPU 0 took over the whole run (msr / halt / all)

Usage:
  python tools\\irq_bench.py --tinyvmm base=C:\\old\\tinyvmm.exe
                             --tinyvmm new=target\\release\\tinyvmm.exe
    [--rounds 3] [--vcpus 2] [--json results.json] [--no-build]
    [--vmlinux <path>] [--initrd <path>] [--busybox <path>] [--verbose]
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import tempfile
from pathlib import Path

import vmm_harness as vh
from blk_test import make_sparse

SCRATCH_BYTES = 64 * 1024 * 1024
IDLE = ("IRQBENCH idle begin", "IRQBENCH idle end")
# (result key, table label, guest metric in ns or None, format)
METRICS = [
    ("timer_wake_us", "timer wake-up latency (us)", "timer_wake_ns", "{:.1f}"),
    ("blk_qd1_us", "virtio-blk QD1 4 KiB read (us)", "blk_qd1_ns", "{:.1f}"),
    ("pipe_rtt_us", "same-CPU ping-pong RTT (us)", "pipe_rtt_ns", "{:.1f}"),
    ("ipi_rtt_us", "cross-CPU ping-pong RTT (us)", "ipi_rtt_ns", "{:.1f}"),
    ("idle_cpu_pct", "idle host CPU (% of one core)", None, "{:.2f}"),
    ("exits_msr", "BSP MSR exits", None, "{:.0f}"),
    ("exits_halt", "BSP HLT exits", None, "{:.0f}"),
    ("exits_total", "BSP exits, all", None, "{:.0f}"),
]


def one_run(exe: str, args: argparse.Namespace, scratch: Path) -> dict[str, float]:
    make_sparse(scratch, SCRATCH_BYTES)
    argv = [exe, "--pvh-run", "--vcpus", str(args.vcpus), "--ram-mb", "256",
            "--drive", str(scratch), "--initrd", str(args.initrd), str(args.vmlinux),
            "--", "tinyvmm.test=bench-irq", *vh.GUEST_CMDLINE]
    run = vh.run_vmm(argv, args.timeout_sec, echo=args.verbose, cpu_markers=IDLE)
    if run.timed_out:
        raise RuntimeError(f"{exe}: run timed out")
    res: dict[str, float] = {}
    for key, _, guest, _ in METRICS:
        if guest:
            m = re.search(rf"IRQBENCH {guest} (-?\d+)", run.text)
            if m:
                res[key] = int(m.group(1)) / 1000.0
    t0, t1 = run.first(IDLE[0]), run.first(IDLE[1])
    c0, c1 = run.cpu_at.get(IDLE[0]), run.cpu_at.get(IDLE[1])
    if None not in (t0, t1, c0, c1) and t1 > t0:
        res["idle_cpu_pct"] = 100.0 * (c1 - c0) / (t1 - t0)
    exits = run.exits()
    if exits:
        res["exits_msr"] = exits.get("msr", 0)
        res["exits_halt"] = exits.get("halt", 0)
        res["exits_total"] = sum(exits.values())
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", action="append", required=True,
                    help="LABEL=path to a tinyvmm.exe (repeat to compare builds)")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--vcpus", type=int, default=2)
    ap.add_argument("--vmlinux", type=Path, default=vh.DEFAULT_VMLINUX)
    ap.add_argument("--busybox", type=Path, default=vh.DEFAULT_BUSYBOX)
    ap.add_argument("--initrd", type=Path, default=vh.DEFAULT_INITRD)
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--timeout-sec", type=int, default=180)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--verbose", action="store_true", help="echo the guest log")
    args = ap.parse_args()

    builds: list[tuple[str, str]] = []
    for spec in args.tinyvmm:
        label, sep, path = spec.partition("=")
        if not sep:
            label, path = Path(spec).parent.name or spec, spec
        if not Path(path).exists():
            print(f"[irq-bench] {path} not found", file=sys.stderr)
            return 2
        builds.append((label, path))
    if not args.no_build:
        vh.build_initramfs(args.busybox, args.initrd)

    scratch = Path(tempfile.gettempdir()) / "tinyvmm-irq-bench.img"
    results: dict[str, list[dict[str, float]]] = {label: [] for label, _ in builds}
    for rnd in range(1, args.rounds + 1):
        for label, path in builds:
            print(f"[irq-bench] round {rnd}/{args.rounds}: {label}", flush=True)
            r = one_run(path, args, scratch)
            print(f"[irq-bench]   {r}", flush=True)
            results[label].append(r)
    scratch.unlink(missing_ok=True)

    labels = [label for label, _ in builds]
    print(f"\n[irq-bench] median (min..max) over {args.rounds} round(s), "
          f"--vcpus {args.vcpus}\n")
    width = max(len(m[1]) for m in METRICS)
    print(f"{'metric':<{width}}  " + "  ".join(f"{label:>24}" for label in labels))
    for key, name, _, fmt in METRICS:
        cells = []
        for label in labels:
            vals = [r[key] for r in results[label] if key in r]
            if not vals:
                cells.append(f"{'-':>24}")
                continue
            med = fmt.format(statistics.median(vals))
            rng = f"({fmt.format(min(vals))}..{fmt.format(max(vals))})"
            cells.append(f"{med + ' ' + rng:>24}")
        print(f"{name:<{width}}  " + "  ".join(cells))

    if args.json:
        args.json.write_text(json.dumps({"vcpus": args.vcpus, "rounds": args.rounds,
                                         "builds": dict(builds), "results": results},
                                        indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
