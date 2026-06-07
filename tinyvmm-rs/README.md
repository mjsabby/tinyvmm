# tinyvmm-rs

A Rust rewrite of [tinyvmm](../README.md), the tiny user-mode VMM on the
**Windows Hypervisor Platform**. Dependency-minimal: the core depends only on
[`windows-sys`](https://crates.io/crates/windows-sys) (which itself pulls in
only `windows-link`); the user-mode NAT additionally uses the `tcp-sans-io`
crate for its TCP state machine.

This is a **phased** port. The C++ tree under `../src` is left intact during
the transition.

## Status — Phase 3: virtio-net + user-mode NAT ✅

`--net` adds a virtio-net PCI device. The guest's `virtio_net` driver binds,
`eth0` appears with the advertised MAC (52:54:00:12:34:56) and link UP.

Two pluggable backends (`--net-backend`):

- **`loopback`** — TX frames echoed back as RX; no host networking and no
  dependencies. Validates the device/queues end-to-end (eth0 binds, TX/RX
  counters increment).
- **`nat`** (default) — a **slirp-style user-mode NAT** that bridges the guest
  onto the host's network with no admin rights and no virtual adapter. The
  guest is `10.0.0.2/24`, the gateway/NAT is `10.0.0.1`. Implemented from raw
  frames:
  - **ARP** for the gateway.
  - **ICMP echo** — `ping 10.0.0.1` is answered locally; pings to any other
    host are **proxied** to the real network (`ping 8.8.8.8` works) via a small
    pool of `IcmpSendEcho` threads.
  - **UDP** NAT (per-4-tuple connected socket) — DNS resolves; idle entries are
    reaped after 60 s.
  - **TCP** terminate-and-proxy via the `tcp-sans-io` crate (guest-facing TCB)
    + `ConnectEx` (host socket): `wget http://…` fetches real pages, including
    HTTPS pass-through. Connection-cap overflow returns a RST; connect-deadline,
    idle, and half-close watchdogs reap stuck flows.
  - **Inbound port-forwarding** (`--portfwd HOSTPORT:GUESTPORT`) — a host
    listener accepts clients and the NAT originates a SYN toward the guest, so
    you can reach a server running inside the guest (e.g. `--portfwd 8080:80`).

  Verified live: `ping` (gateway + internet) 0% loss, DNS, HTTP/HTTPS downloads,
  and host→guest port-forwarding.

### NAT runtime

Per the agreed design, the NAT is a single **precreated** worker thread that
owns all flow state and an **IOCP**; it is lock-free by virtue of
single-threading. vCPU threads hand off guest frames via
`PostQueuedCompletionStatus`, and **all** host socket I/O is overlapped on the
same port — TCP connect (`ConnectEx`), recv, and send, plus UDP recv — so a
slow or backpressured peer never blocks the worker. At most one TCP send is in
flight per flow (the next chunk is posted from its completion), which preserves
stream order and bounds memory; the guest-facing window closes once the
per-flow send queue hits its cap (backpressure). The only synchronous send is
the UDP datagram path, which can't block on peer flow-control. The per-flow TCP
timers (retransmit / delayed-ACK) are driven on a coarse ~20 ms cadence rather
than on every completion, keeping the sweep off the hot path. No tokio, no async
runtime.

Two operations can't use the IOCP and run on small **precreated** helper-thread
pools instead, posting their results back to the worker (so guest injection
stays single-threaded): blocking `IcmpSendEcho` for the ICMP proxy, and
`accept()` for each port-forward listener. The TCBs use the crate's default
1 MiB rings (so the nat-worker is given a 16 MiB stack to construct them).

The data plane is **allocation-free on the hot path**: guest TX frames come from
a preallocated, lock-free frame pool (Treiber free-list); inbound frames are
copied into a preallocated RX slot pool (no `Vec` per frame); the worker builds
guest-bound frames into reusable scratch buffers via write-into-buffer wire
helpers; and the virtqueue's `pop_into` refills a reused descriptor chain. Only
cold paths (ARP, ICMP/ping, RST) still allocate.

### Doorbells (no-exit notify path)

The virtio-PCI transport installs a **WHP MMIO doorbell**
(`WHvRegisterPartitionDoorbellEvent`) on each queue's notify register when the
BAR is mapped. A matching guest kick then signals an event **instead of taking a
VM exit**; a per-device pump thread waits on the events and drives the normal
`notify_queue` path. It is opt-in per device (`transport::Options::doorbells`)
and now **on for both virtio-net and virtio-console**. The win was first
measured on net (a 56 KB download: **0** MMIO-exit notifies with doorbells vs
**182** on the console before it was enabled); a 20 MB transfer runs at line
rate. Enabling it for the console removes its per-keystroke/per-chunk VM exits
too (the console queues are drained under a mutex, so servicing them off the
vCPU on the pump thread is safe).

The pump waits with **no periodic sweep** (unlike the C++, whose 5 ms timeout is
really its WSAPoll socket-poll cadence): our sockets are on IOCP, and the
virtqueue closes the EVENT_IDX notification race itself (Acquire re-read of
`avail.idx` + Release of `avail_event`), with the MMIO handler as the fallback
for any non-matching write.

Deferred: sharding flows across worker threads — RX/TX are serialized by the
single virtio queue pair + the RX-inject path regardless, so the principled
multi-core lever would be multiqueue virtio-net, not NAT sharding.

### ETW diagnostics

Built-in **ETW TraceLogging** for low-overhead, out-of-process tracing (mirrors
the C++ `src/diag/etw.h`). The provider is **`Tinyvmm-Core`**
(`{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}`); the TraceLogging metadata is
**hand-rolled** so there is **no new dependency** (just the raw `EventRegister`/
`EventWriteTransfer` APIs already in `windows-sys`). An enable callback caches
the session level + keyword mask in atomics, so the hot-path gate is a single
atomic check — disabled events cost essentially nothing.

Keywords (bit mask, mirroring the C++): `VMEXIT=0x1`, `DOORBELL=0x2`,
`VIRTIO=0x4`, `NET=0x8`, `MMIO=0x10`, `IO=0x20`, `BOOT=0x40`, `LIFECYCLE=0x80`,
`BLOCK=0x100`, `CPUID=0x200`, `MSI=0x400`. Levels are `CRITICAL=1`…`VERBOSE=5`.
Instrumented today: `VmStart`/`VmStop` (Lifecycle; `VmStop` carries the
io/cpuid/msr exit counters + uart-tx), `VmExit` (VMEXIT), `NetTx`/`NetRx` (NET),
and `Doorbell` (DOORBELL).

Capture (no admin needed), e.g. Lifecycle|Net|Doorbell at level 5:

```
logman start tv -p "{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}" 0x8a 5 -ets -o tv.etl
  …run the VM…
logman stop tv -ets
tracerpt tv.etl -o tv.csv -of CSV -y
```

## Status — virtio-9p (host directory sharing) ✅

`--virtio-9p-share <tag>=<host_path>[,ro]` (repeatable ×8) adds a virtio-9p PCI
device exposing one host directory. The guest mounts it with:

```
mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 <tag> /mnt/...
```

A faithful port of the C++ **9P2000.L** Win32 backend: 19 message handlers
(Tversion/Tattach/Twalk/Tlopen/Tlcreate/Tread/Twrite/Tgetattr/Tsetattr/
Treaddir/Tclunk/Tremove/Tfsync/Tflush/Tmkdir/Trename/Trenameat/Tunlinkat/
Tstatfs) over one requestq. Fids map to host paths (and an open `HANDLE` after
Tlopen/Tlcreate); the mount tag lives in PCI device-config space. Reads/writes
use overlapped `ReadFile`/`WriteFile` at the requested offset; `O_APPEND` maps
to `FILE_APPEND_DATA`.

Security: the share root is canonicalised once, each wire path component is
sanitised (separators / NUL / `:` / reserved DOS names rejected), `..`/`.` are
resolved against the share with a clamp-to-root, and a lexical containment
check is the backstop — so a guest can't path-walk out of the share. All Win32
calls go through `\\?\` long paths.

Verified by `tools/p9_test.py` against the Rust binary: **15/15 phases**
(mount, 105-file sha256 manifest byte-for-byte, empty/large/many/nested files,
write+create, touch+unlink, mkdir+rmdir, rename, truncate, append, clean
umount) plus host-side post-conditions (fixtures intact, guest write visible on
host, no debris). Read-only shares (`,ro`) reject writes with EROFS.

### Concurrency, throughput, and where the locks are

Every virtio device owns its virtqueue behind a `Mutex<Virtqueue>`; the hot
notify path is taken off the vCPU by WHP doorbells (net/console/blk/9p), and the
set-once IRQ callback is a lock-free `OnceLock`.

**virtio-9p** drives its requestq with a small **worker pool**: an IOCP used
purely as a thread-safe work queue + a preallocated slot pool + precreated
worker threads. `drain` (on the doorbell-pump thread) pops a request, copies it
into a slot, and `PostQueuedCompletionStatus`es the slot index; a worker runs
the blocking `dispatch`, writes the reply into guest RAM, pushes the used ring
and raises the IRQ. 9p tags every request, so out-of-order completion is legal
and reads/writes run concurrently across workers.

Measured with `tools/p9_bench.py` (1 GiB of cached host data, `--readers N`):

| readers            | 1  | 8   | 16  | 32      |
| ------------------ | -- | --- | --- | ------- |
| serial (pre-pool)  | 16 | 83  | —   | —       |
| **worker pool**    | 16 | 118 | 183 | **190** MB/s |

- **Single-stream is latency-bound (~16 MB/s), and `cache=none` ≡ `cache=loose`.**
  9p is request-response: one waiting stream keeps **a single Tread in flight**,
  so throughput ≈ `Tread / round-trip-latency`. Guest readahead does not change
  it — only concurrency hides the latency. For contrast, virtio-blk single-stream
  read is ~**533 MB/s** because the guest *block* layer pipelines many async
  requests per stream (`max_inflight` ≈ 14), which blk's IOCP backend services
  concurrently. So the slow single stream is the 9p protocol, not the device.
- **Concurrent throughput plateaus ≈185 MB/s** and is unchanged from 8→16 workers,
  so the ceiling is **not** worker count. The two shared serialization points on
  the request path are:
  1. the **single doorbell-pump thread** running `drain` (it submits *every*
     request), and
  2. the per-queue **`Mutex<Virtqueue>`**, contended by every `drain` pop **and**
     every worker `push`.

  Going past it would need multiple submit threads and/or sharded/batched
  used-ring updates. (A definitive split between the two would want lock-*wait*
  profiling — e.g. xperf CSwitch/ReadyThread — since host CPU sampling shows ~0.2%
  in our code and won't surface lock waits.)

## Status — virtio-rng + virtio-blk ✅

Two more virtio devices, both faithful ports of the C++ originals.

### virtio-rng (`--rng`)

The simplest virtio device (spec §5.4): a single requestq of device-writable
buffers that we fill with cryptographically-strong bytes from Windows CNG
(`BCryptGenRandom` with the system-preferred RNG — no algorithm handle, no new
crate, just the `Win32_Security_Cryptography` binding of `windows-sys`). The
fill is cheap (no I/O) so it runs inline on the notifying vCPU (no doorbell); a
`Mutex<Virtqueue>` serialises concurrent kicks. The guest binds it as
`/dev/hwrng` (`rng_current = virtio_rng.0`) and seeds its CRNG from it.

### virtio-blk (`--drive <path>[,readonly]`)

A real async block device (spec §5.2), repeatable up to 8 disks (drive N shows
up as `/dev/vd{a,b,…}`). Each disk is backed by a host **`BlockFile`**: a
`FILE_FLAG_OVERLAPPED` handle bound to a **per-disk IOCP** with one
**precreated** worker thread. `notify_queue` (on the vCPU) drains the avail
ring, decodes each `virtio_blk_req`, and submits the data segments with
overlapped `ReadFile`/`WriteFile` (or posts a `FlushFileBuffers` job); the IOCP
worker runs the per-request state machine and, after the final segment + status
byte, retires the used ring and raises the queue interrupt — so all blocking
work stays off the vCPU. At most one segment per request is in flight at a time
(the next is submitted from the completion), preserving order.

Features: `VERSION_1 | RING_EVENT_IDX | BLK_SIZE | FLUSH | SEG_MAX | SIZE_MAX`,
plus `RO` on `,readonly` drives, and `DISCARD | WRITE_ZEROES` on writable
drives. DISCARD / WRITE_ZEROES are serviced synchronously via the backend's
`ZeroRange` (`FSCTL_SET_SPARSE` once, then `FSCTL_SET_ZERO_DATA`), which on a
sparse NTFS file both zeroes the bytes and **deallocates** the backing clusters.
A per-disk shutdown summary reports `submitted/completed/errors/max_inflight`
and the virtio op tallies (in/out/flush/discard/wz/err).

> Note: the discard/write-zeroes **config offsets** in the C++ reference are 4
> bytes too low (a latent bug — the block lives at offset 36+, after
> `writeback`/`unused0`/`num_queues`, not 32); the Rust port uses the correct
> spec offsets so the guest sees the real `discard_max_bytes`.

Verified by `tools/blk_test.py` against the Rust binary: all six guest phases
pass (raw R/W md5, sequential throughput, 8-way concurrent writers, random
4 KiB I/O, ext2 mkfs+mount+flush+remount, read-only EROFS), the host backend
reaches `max_inflight` well above 1 (proving real parallel queue depth through
the IOCP), and the ext2 marker is found in the raw backing file (data flushed
past both guest and host page caches). The DISCARD / WRITE_ZEROES paths — which
the busybox test tooling can't issue — are covered by a host-side self-test
(`tinyvmm --blk-selftest`) that drives both request types straight through a
real device + backend and checks the targeted ranges are zeroed on the host
file while neighbours are preserved.

### Clean shutdown sentinel

Harnesses stop the VM by having the guest print `=== tinyvmm shutdown
requested ===` on hvc0: a console TX byte-observer scans for it and stops every
vCPU. This is needed because an ACPI-less `poweroff` falls back to STI;HLT and
never produces a halt VM-exit, so without the sentinel a watchdog-less run
would spin idle forever.

### Boot fast-path, timing, and CPU affinity

- **Memory-mapped loader** — vmlinux / initramfs are brought in with
  `CreateFileMapping` + `MapViewOfFile` (`host::MappedFile`) so their pages go
  straight to a memcpy into guest RAM, ~1/3 the cost of reading into a `Vec`.
- **BootTimer** — `host`/`diag::BootTimer` records QPC waypoints (`pvh-run
  start` → `WHP probe done` → `guest RAM mapped` → `vmlinux+initramfs loaded`
  → `entering guest` → `guest exited` → `teardown done`), printing
  `[boot] <total> ms (+<delta> ms) <phase>` and emitting an ETW `BootMark`
  event per mark (keyword `BOOT`) for the WPA timeline.
- **`--cpu-affinity all|p|e|p-physical`** — pins every vCPU thread (BSP + APs)
  to a CPU set via `SetThreadSelectedCpuSets`, classing P/E cores by
  `EfficiencyClass` from `GetSystemCpuSetInformation`. On hybrid Intel hosts
  this keeps vCPUs on one core type so they don't bounce across the P/E
  boundary and trip Linux's TSC `clocksource_watchdog`. On a non-hybrid host
  `p` is every logical processor and `e` is a no-op (warns, runs unpinned).

## Status — Phase 2: PCI + virtio-console ✅

Interactive shell over **hvc0** (virtio-console). The guest enumerates a
virtio-console PCI device, switches its console to hvc0, and `/init` drops to a
shell whose I/O round-trips through the virtio-console: host stdin → RX queue →
guest, and guest → TX queue → host stdout. Verified live (`uname -sr` →
`Linux 7.0.0+`, etc.).

Added on top of phase 1:

- **PCI host bridge** — Configuration Mechanism #1 (0xCF8/0xCFC), Type-0 config
  space with BAR sizing + COMMAND.MEM_SPACE → BAR (un)map, capability list.
- **MSI-X** — capability + table/PBA in a BAR, per-vector mask/PBA replay,
  message decode → `WHvRequestInterrupt`.
- **virtio** — split virtqueue (desc/avail/used rings, indirect + EVENT_IDX),
  the modern virtio-pci transport (common/notify/isr/device-cfg caps over
  BAR0), and the virtio-console device.
- **Interactive console** — raw VT stdin reader thread feeding the RX queue
  (also accepts redirected/piped stdin); Ctrl+A X to quit.

## Status — Phase 1: bootable core ✅

Boots an unmodified **PVH** Linux kernel to a serial console (kernel log +
userspace `/init` over `ttyS0`). Verified against the repo's `vmlinux` +
`initramfs.cpio`: the boot log and VM-exit counters (`io=20618 cpuid=486
msr=15`, `mmio=0`) match the C++ binary exactly.

Implemented:

- **WHP core** — partition, guest RAM (large pages when `SeLockMemoryPrivilege`
  is held), vCPU, register get/set, the VM-exit run loop with the
  `WHvEmulator*` IO/MMIO completion callbacks.
- **CPUID policy** — invariant TSC, ARAT, TSC frequency (leaf 0x15/0x16),
  per-vCPU x2APIC topology, and the Hyper-V vendor/feature leaves.
- **Hyper-V enlightenment** — Reference TSC page + the handful of MSRs Linux
  writes once it detects Hyper-V.
- **Legacy devices** — 8250 UART (TX → host stdout), i8259 PIC, 8254 PIT
  (counters; IRQ0 intentionally not wired), CMOS/0x80/0x92 stubs.
- **PVH boot** — ELF loader + `hvm_start_info`/e820/cmdline/modlist, minimal
  ACPI (RSDP/XSDT/MADT), 32-bit protected-mode entry.
- **SMP** — `--vcpus N` spawns one host thread per AP; WHP services INIT+SIPI
  in-hypervisor.

Deferred to later phases: the rest of the virtio suite (rng/blk/9p), the GDB
stub, snapshot/restore, and the `--*-test` harness suite.

## Build

```cmd
cd tinyvmm-rs
cargo build --release
```

Requires the **Windows Hypervisor Platform** feature enabled and a recent
Windows SDK (for `WinHvPlatform.dll` / `WinHvEmulation.dll`, linked
automatically via `windows-sys`).

## Run

```cmd
:: smoke-test the WHP plumbing
.\target\release\tinyvmm.exe --smoke

:: inspect a kernel's PVH entry
.\target\release\tinyvmm.exe --pvh-info ..\vmlinux

:: boot to a serial console (Ctrl+C to stop, or use --watchdog-secs N)
.\target\release\tinyvmm.exe --pvh-run --initrd ..\initramfs.cpio ..\vmlinux
```

`--pvh-run` flags: `--initrd <cpio>`, `--ram-mb N` (128–3584, default 256),
`--vcpus N` (1–32), `--net` (virtio-net),
`--net-backend loopback|nat` (default `nat` — user-mode NAT; `loopback` echoes
TX→RX with no host networking), `--portfwd HOSTPORT:GUESTPORT` (forward a host
`127.0.0.1:HOSTPORT` listener to the guest's `10.0.0.2:GUESTPORT`; repeatable),
`--watchdog-secs N` (0 = run until stopped), `--debug-boot` (adds
`earlyprintk=ttyS0`). Everything after a bare `--` becomes the kernel cmdline;
the default routes the console to `hvc0` (the virtio-console) so the shell is
interactive. `Ctrl+A X` quits.

## Layout

```
src/
  main.rs          CLI dispatch + device wiring + interactive console
  error.rs         minimal Result/Error
  host.rs          SeLockMemoryPrivilege + large-page query
  whp/             partition, memory, vcpu, regs, run_loop, cpuid, hv, msi
  devices/         io_bus, mmio_bus, serial, pic, pit, legacy
  pci/             config (Type-0 space), bus (0xCF8/0xCFC), msix
  virtio/          queue, device, transport (virtio-pci modern), console, net
  net/             user-mode NAT: wire (parse/build), sys (Winsock/IOCP), nat
  boot/            acpi, loader (PVH ELF + start_info)
```
