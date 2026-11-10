# Proof-of-concept attacks

Most PoCs boot a real guest under one tinyvmm binary and attack the VMM from
inside it; a few attack what tinyvmm reads or loads on the host. The runner
judges every outcome on the host and prints `VULNERABLE` or `NOT VULNERABLE`
with the numbers it measured, for a pre-fix build and for a fixed build.

```
python poc\run.py                               # every PoC, both builds
python poc\run.py --only avail-bomb,p9-reset    # some of them
python poc\run.py --no-extras                   # only the review's eleven
python poc\run.py --skip-gpu                    # gpu-backing opens a window
python poc\run.py --baseline OLD.exe --fixed NEW.exe
python poc\run.py --no-baseline                 # the fixed build only
python poc\run.py --list
```

Defaults: baseline `%TEMP%\tinyvmm-work\bin\baseline\tinyvmm.exe` (left out,
with a note, if it isn't there), fixed `%TEMP%\tinyvmm-work\bin\fixed\tinyvmm.exe`,
else `target\release\tinyvmm.exe`. The guest kernel is `vmlinux` in the repo
root. The exit code is 1 if the **fixed** build is vulnerable to anything or a
PoC could not be judged, 0 otherwise (2: bad arguments; 3: a tinyvmm could not
be killed); a PoC skipped for want of an optional DLL fails nothing. The
review's eleven take about three minutes on both builds (`--no-extras`), most
of it waiting for the pre-fix build's hangs to be shown; the whole set takes
about nine.

Needs: Windows with the Hypervisor Platform, Python 3.10+, and zig (0.13 or
later; `$ZIG`, `PATH`, or `%LOCALAPPDATA%\tinyvmm-toolchain`) to build the
guest the first time, and for `dll-plant` and `gvisor-flow-bomb`.

A pre-fix build to compare with is any commit before the fixes, built beside
the working tree:

```
git worktree add ..\tinyvmm-base 18d91fa
cargo build --release --manifest-path ..\tinyvmm-base\Cargo.toml
python poc\run.py --baseline ..\tinyvmm-base\target\release\tinyvmm.exe
```

Run a build from a copy rather than from `target\release` if you mean to
rebuild afterwards: see the last paragraph of [Safety](#safety).

## The review's PoCs

| PoC | Attack (from guest root unless said) | Vulnerable when |
|---|---|---|
| `avail-bomb` | virtio-rng: one chain published, `avail.idx` stored 65,535 ahead, one kick | `used.idx` advances by more than the queue's 64 entries |
| `console-flood` | console TX: one chain naming 200 MiB of guest RAM; then a full ring of 1 GiB chains while the watchdog comes due | more than 2 MiB of the first chain reaches stdout, or the VMM is still running 12 s after its watchdog |
| `input-status-bomb` | `--input` keyboard statusq: 64 chains x 64 descriptors x 1 GiB | the kick never returns and the watchdog cannot stop the VM |
| `gpu-backing` | `--gpu`: a 65,536-entry backing list on each of 1,024 resources; 16 transfers of a 2x8192 resource behind 65,535 empty entries | more than 2^20 entries accepted or memory grows over 256 MiB, or a transfer takes over 50 ms |
| `net-reset-deadlock` | loopback NIC: 256 TX frames, doorbell kick, device reset at once; 2,000 rounds | the guest freezes in a reset and the watchdog cannot stop the VM |
| `p9-flush-order` | 9P spoken directly: Treaddir of a 100,000-entry directory and the Tflush of its tag in one kick, 8 times | an Rflush is on the used ring before the Rreaddir it flushes |
| `p9-reset` | 5 requests, device reset, fresh rings, one kick with nothing queued | the device writes used entries or a reply for requests nobody made |
| `p9-fid-memory` | a fid walked 340 directories down (an 87 KiB path), then cloned 12,000 times | over 96 MiB of fid paths accepted or memory grows over 200 MiB (fixed: ENOMEM at 64 MiB) |
| `blk-whole-disk-stop` | one read of 250 x 2 GiB segments (one guest buffer) from a sparse 512 GiB VHDX, run by the doorbell pump, then power off | the VMM takes more than 5 s to exit after the guest powered off |
| `bar-remap` | functional: COMMAND.memory cleared and set 300 times on a virtio-blk device with kernel-driver I/O after each, then BAR 0 moved away and back | any I/O fails, or the VM hangs or exits uncleanly (passes on both builds) |
| `sentinel-unprivileged` | uid 65534 puts `=== tinyvmm shutdown requested ===` on hvc0: written to a console it has open, and via the kernel's segfault message for a program whose file it named that | the VM stops before the guest's next line |

## Extras

| PoC | Attack | Vulnerable when |
|---|---|---|
| `blk-stop-variants` | the whole-disk read (250 x 1 GiB) where the device does not run it a segment at a time on its pump: published twice, and with `--no-doorbells` (the drain is on the vCPU's thread; the watchdog asks for the stop) | the VMM takes more than 5 s to exit after the stop was asked for |
| `blk-snapshot-wait` | `--save`: eight of those reads queued, then the guest's snapshot trigger (CPUID 0x4000DE57), which waits for the guest's queued disk work; then the same with two reads of 250 x 128 MiB, a few seconds of work | the VMM is still running 25 s after the trigger (fixed: the snapshot is refused after 15 s). The second snapshot has to be written: an error on the fixed build if it isn't |
| `p9-flush-stress` | functional: 300 batches of a Treaddir and 40 Tflushes naming it, each other, themselves and nothing; a device reset mid-flight every 7th batch | an Rflush precedes the reply it flushes, a reply is lost or wrong, or the device does not come back from a reset |
| `net-host-local` | without `--nat-host-local`, the guest (kernel driver) fetches a token from a host server on one of the host's own addresses (nat) and on 127.0.0.1 through the gateway (slirp, gvisor; skipped unless `libslirp-0.dll` / `tinyvmm_gvisor.dll` is next to the binary, named by `TINYVMM_LIBSLIRP` / `TINYVMM_GVISOR`, or in `%TEMP%\tinyvmm-work`) | the token is read or the host's server sees a connection |
| `grub-var-bomb` | the guest writes a 343-byte `grub.cfg` to its disk in which a variable doubles itself 24 times; then `tinyvmm --drive <disk>` with no kernel reads it on the host | the VMM's private memory peaks more than 192 MiB above its guest RAM |

## Host-side PoCs

These need no hostile driver: the attack is in a file tinyvmm reads, a DLL it
loads, or what its user does. They are extras too (`--no-extras` leaves them
out), and live in `host/`.

| PoC | Attack | Vulnerable when |
|---|---|---|
| `grub-iso-bomb` | `--iso` with a `grub.cfg` whose variable grows sixteenfold on each of 11 lines (16 TiB expanded), and one whose `initrd` line names a 32 MiB file 64 times; tinyvmm runs under a 6 GiB commit cap | the configuration is not refused by name (the pre-fix build allocates up to the cap and aborts, and reads all 64 copies) |
| `dll-plant` | a DLL whose `DllMain` writes a marker file, under the names `wintun.dll`, `libslirp-0.dll` and `tinyvmm_gvisor.dll`, in the directory tinyvmm is started from; the binary is a private copy with no DLL beside it | the marker appears: the planted DLL ran inside tinyvmm |
| `snapshot-clobber` | a good snapshot at a path; a second `--save` to the same path, of a guest holding 2.5 GiB of random data, is killed while the file is being written | the good snapshot is no longer at the path, byte for byte, or no longer restores |
| `console-input-memory` | 512 MiB piped into tinyvmm's stdin while the guest never reads hvc0; under a 6 GiB commit cap | tinyvmm's commit grows by more than 64 MiB (fixed: it holds 16 MiB and drops the rest) |
| `gvisor-flow-bomb` | `--net-backend gvisor`: the guest sends one datagram from each of 20,000 UDP ports, then opens 12,000 TCP connections to a host server and holds them; under a 12 GiB commit cap | commit grows by more than 512 MiB (UDP) or 1.5 GiB (TCP), or the host's server holds more than 4,160 connections at once |

`gvisor-flow-bomb` judges the shim, not the binary: the bounds are in
`gvisor/main.go`. The fixed build uses the DLL tinyvmm would find
(`TINYVMM_GVISOR`, next to the binary, or `%TEMP%\tinyvmm-work\gvisor`); the
baseline uses a shim built from the pre-fix source, named by
`TINYVMM_GVISOR_BASELINE` or at
`%TEMP%\tinyvmm-work\gvisor\tinyvmm_gvisor_baseline.dll`. Either is skipped
when its DLL isn't there.

## Benchmark: parallel directory walks

Not an attack: `bench\p9_dirwalk.py` measures whether a 9p share lists
directories side by side, which the fix for the directory-listing memory
(a listing is built a stretch at a time, under a lock) could have cost. The
guest walks eight directories of a read-only share with one thread and then
with eight, remounting in between; each build is booted several times in
turn and the medians are printed.

```
python poc\bench\p9_dirwalk.py                                    # 2,000 small directories
python poc\bench\p9_dirwalk.py --subdirs 1 --files 1 --big 20000   # 8 listings of 20,000
python poc\bench\p9_dirwalk.py --subdirs 1 --files 1 --big 20000 --cold --parallel-first
python poc\bench\p9_dirwalk.py --exe old=OLD.exe --exe new=NEW.exe --rounds 5
```

`--cold` empties the host's file cache before each boot (the whole
machine's, from an elevated prompt), so that the listings come off the disk.
Eight listings of 20,000 entries, 8 threads on 4 vCPUs, on the machine the
fixes were made on:

| Build | 1 thread | 8 threads | 8 threads, host cache cold |
|---|---|---|---|
| before the fixes | 196 ms | 41 ms | 449 ms |
| one listing lock per share (the first fix) | 205 ms | 140 ms | 2,637 ms |
| one lock per open directory (as it is now) | 186 ms | 44 ms | 458 ms |

With 2,000 small directories the three are alike: a listing that fits one
reply holds its lock for no time.

## How it works

* `host/` holds the host-side PoCs, one module each, and `common.py`: a
  tinyvmm run under a job object's commit cap with its peak commit sampled, a
  small ISO 9660 writer, and an initramfs packer over `tools/make_initramfs.py`.
* `guest/vhostile.c` is a hostile virtio-pci driver in guest user space. It
  unbinds the kernel's driver through sysfs, maps `resource0`, finds the
  virtio structures from the PCI vendor capabilities, negotiates VERSION_1
  and drives split virtqueues that live in its own 2 MiB hugepages, whose
  guest-physical addresses come from `/proc/self/pagemap`. It polls the used
  ring; no interrupts. One subcommand per PoC; each reports `[poc] ...` lines
  on `/dev/kmsg`, which reach the VMM's stdout through hvc0. Huge buffers are
  descriptors that name guest RAM the kernel does not use (`mem=1024M` on a
  larger VM).
* `guest/init.sh` is the guest's `/init`: it runs `vhostile <poc>` as named
  on the kernel command line (`poc=... pocargs=...`) and powers off.
* `guest/build.py` compiles `vhostile` with `zig cc` and packs the initramfs
  (`python poc\guest\build.py [--force]`). `run.py` calls it; outputs are
  cached in `poc/out/`, as is the 100,000-file share the 9p flush PoCs read
  (made once, shared read-only).
* `run.py` runs one VM at a time with `--watchdog-secs`, a hard timeout and
  `taskkill /F`, counts the VMM's output without keeping it, samples its
  private bytes, and writes each VM's log to a fresh directory under `%TEMP%`
  (printed at the start and end; the disks and shares made there are deleted
  afterwards).

## Safety

`vhostile` refuses to notify a queue more than 50,000 times per run (the most
any PoC uses is about 12,000, with `--no-doorbells`; about 2,000 with
doorbells), and every PoC that does not need the doorbell pump thread runs
with `--no-doorbells`: Windows' vid.sys can hang for good when a doorbell
that was rung tens of millions of times is unregistered, which is finding 1
and is deliberately not reproduced here. `console-flood` sends gigabytes to a
pipe the runner drains; nothing is stored. `gpu-backing` opens a window for a
few seconds. The memory PoCs make the pre-fix build hold about 1 GiB;
`grub-var-bomb`'s configuration is bounded (and the runner kills a VMM that
passes 8 GiB there). `net-host-local` listens on ephemeral ports of 127.0.0.1
and of the host's own address for the second it takes.

The host-side PoCs that make a pre-fix tinyvmm allocate run it in a job
object with a commit cap (6 or 12 GiB), so it aborts rather than exhausts the
machine; `gvisor-flow-bomb` makes the pre-fix shim hold about 7 GiB and
12,000 loopback connections for half a minute. `dll-plant`'s DLL does nothing
but write a marker file into the temporary directory it is planted in, and
no network driver is installed or touched: the planted `wintun.dll` has no
exports, so a build that loads it stops there. `snapshot-clobber` writes
about 3 GiB to the work directory and removes it.

Even so, one hazard is not the PoCs' to avoid: Hyper-V's vid.sys can fail to
tear a partition down (see `crates/whpsys/src/doorbell.rs`), after which the
tinyvmm process stays, unkillable, until the host restarts, and keeps the
executable it ran from locked (it can be renamed, not replaced). The runner
stops with exit code 3 if a tinyvmm does not die.
