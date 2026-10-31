#!/usr/bin/env python3
"""End-to-end interrupt-delivery regression test (needs WHP; nested is fine).

Boots the `tinyvmm.test=irq` initramfs mode at each --vcpus count and fails if
a guest phase fails or the run hangs. On top of the guest's own checks (COM1
IRQs arrive through the PIC as ExtINT, virtio-blk MSIs still complete
afterwards, `sleep 2` lasts 2 s, on the BSP and on an AP) it asserts against
the host that:

  * the guest calibrated its LAPIC timer to WHP's interrupt clock: the
    `Hyper-V: LAPIC Timer Frequency` it logs (ticks per jiffy) must divide
    WHvCapabilityCodeInterruptClockFrequency into a kernel HZ value, and
  * each guest `sleep 2` also took ~2 s of host wall time.

Together these catch the regressions that once hung nested guests: PIC IRQs
delivered as Fixed LAPIC interrupts (never EOI'd, so every MSI behind them is
blocked) and a LAPIC timer calibrated against the TSC (~16x slow timers).

Usage:
  python tools\\irq_test.py
    [--tinyvmm <path>] [--vmlinux <path>] [--busybox <path>]
    [--initrd <path>]   (default repo/initramfs-blk.cpio.gz; rebuilt from
                         busybox unless --no-build)
    [--vcpus 1,2]       (comma list of vCPU counts)
    [--extra-arg <flag>]...  (passed through to tinyvmm --pvh-run)
    [--no-build] [--timeout-sec 120] [--quiet]
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

import vmm_harness as vh
from vhdx import make_vhdx

SCRATCH_BYTES = 64 * 1024 * 1024
KERNEL_HZ = {100, 250, 300, 1000}


def check_run(run: vh.VmRun, vcpus: int, clock_hz: int | None) -> list[str]:
    """Return the list of failures for one boot (empty = pass)."""
    failures: list[str] = []
    text = run.text
    if run.timed_out:
        failures.append("run timed out (interrupt delivery wedged?)")

    want = 6 if vcpus >= 2 else 3
    m = re.search(r"IRQ SUMMARY:\s+(\d+)/(\d+) phases passed", text)
    if not m:
        failures.append("no 'IRQ SUMMARY:' line")
    elif int(m.group(1)) != int(m.group(2)) or int(m.group(2)) != want:
        failures.append(f"guest phases {m.group(1)}/{m.group(2)} passed (want {want}/{want})")
    failures += [line.strip() for line in re.findall(r"^.*IRQ [\w-]+: FAIL.*$", text, re.M)]

    for phase in ["timer", "timer-ap"] if vcpus >= 2 else ["timer"]:
        begin = run.first(f"IRQ TIMER begin {phase}")
        end = run.first(f"IRQ TIMER end {phase}")
        if begin is None or end is None:
            failures.append(f"{phase}: no host timing markers")
        elif not 1.8 <= end - begin <= 3.0:
            failures.append(f"{phase}: guest `sleep 2` took {end - begin:.2f} s of host time")
        else:
            print(f"[irq-test] {phase}: sleep 2 = {end - begin:.2f} s host wall time")

    m = re.search(r"LAPIC Timer Frequency: (0x[0-9a-fA-F]+)", text)
    if not m:
        failures.append("guest never logged its LAPIC timer frequency")
    elif clock_hz is None:
        print("[irq-test] WARN: WHP interrupt clock unavailable; skipping LAPIC calibration check")
    else:
        per_jiffy = int(m.group(1), 16)
        hz, rem = divmod(clock_hz, per_jiffy) if per_jiffy else (0, 1)
        if rem or hz not in KERNEL_HZ:
            failures.append(
                f"guest LAPIC timer calibrated to {per_jiffy} ticks/jiffy, which doesn't "
                f"divide WHP's {clock_hz} Hz interrupt clock into a kernel HZ")
        else:
            print(f"[irq-test] LAPIC timer: {per_jiffy} ticks/jiffy x HZ={hz} == "
                  f"WHP interrupt clock {clock_hz} Hz")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tinyvmm", type=Path, default=vh.DEFAULT_TINYVMM)
    ap.add_argument("--vmlinux", type=Path, default=vh.DEFAULT_VMLINUX)
    ap.add_argument("--busybox", type=Path, default=vh.DEFAULT_BUSYBOX)
    ap.add_argument("--initrd", type=Path, default=vh.DEFAULT_INITRD)
    ap.add_argument("--vcpus", default="1,2")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--timeout-sec", type=int, default=120)
    ap.add_argument("--extra-arg", action="append", default=[],
                    help="extra tinyvmm --pvh-run flag (repeatable), e.g. --extra-arg=--cpu-affinity")
    ap.add_argument("--quiet", action="store_true", help="don't echo the guest log")
    args = ap.parse_args()

    for p in (args.tinyvmm, args.vmlinux):
        if not p.exists():
            print(f"[irq-test] FAIL: {p} not found", file=sys.stderr)
            return 2
    if not args.no_build:
        vh.build_initramfs(args.busybox, args.initrd)

    clock_hz = vh.whp_interrupt_clock_hz()
    workdir = Path(tempfile.gettempdir()) / "tinyvmm-irq-test"
    workdir.mkdir(parents=True, exist_ok=True)
    scratch = workdir / "irq-scratch.vhdx"

    failed = False
    for n in [int(x) for x in args.vcpus.split(",") if x.strip()]:
        print(f"\n========== irq test: --vcpus {n} ==========")
        make_vhdx(scratch, SCRATCH_BYTES, args.tinyvmm)
        argv = [str(args.tinyvmm), "--pvh-run", "--vcpus", str(n), "--ram-mb", "256",
                *args.extra_arg,
                "--drive", str(scratch), "--initrd", str(args.initrd), str(args.vmlinux),
                "--", "tinyvmm.test=irq", *vh.GUEST_CMDLINE]
        print("[irq-test] launching: " + " ".join(argv))
        run = vh.run_vmm(argv, args.timeout_sec, echo=not args.quiet)
        failures = check_run(run, n, clock_hz)
        for f in failures:
            print(f"[irq-test] FAIL (--vcpus {n}): {f}")
        if failures:
            failed = True
        else:
            print(f"[irq-test] --vcpus {n}: PASS ({run.wall:.1f} s)")
    scratch.unlink(missing_ok=True)

    print("\n[irq-test] " + ("FAIL" if failed else "PASS: interrupt delivery healthy"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
