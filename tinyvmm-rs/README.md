# tinyvmm-rs

A **tiny, opinionated user-mode Virtual Machine Monitor** (microVM monitor) for
Windows. It brings up a single 64‑bit Linux microVM on the **Windows Hypervisor
Platform** (WHP), boots it through the **PVH** entry point, and exposes a curated
set of paravirtualized devices over a PCI bus with MSI‑X — then gets out of the
way.

It is deliberately *not* a general-purpose emulator (no BIOS, no legacy boot, no
ACPI power management, no device hot-plug, no PCI passthrough). Like
firecracker/cloud-hypervisor it targets the **microVM** sweet spot: the smallest
amount of machine a modern Linux needs to reach an init process fast, with a
hand-picked virtio device set and a sub-300 ms boot. Everything in the feature
list below exists because a microVM needs exactly that and nothing more.

```
.\target\release\tinyvmm.exe --pvh-run --vcpus 4 --ram-mb 1024 --rng \
    --net --drive disk.img --virtio-9p-share share=C:\host\dir \
    --initrd initramfs.cpio vmlinux
```

* **Host:** Windows 11 / Server 2022 with the *Windows Hypervisor Platform*
  feature enabled. Builds with stable Rust (built & tested on `rustc 1.95`).
* **Guest:** an unmodified PVH-capable `vmlinux` (`CONFIG_PVH=y`) + an initramfs.
* **Dependencies:** `windows-sys` (which only pulls `windows-link`) and the
  user's private `tcp-sans-io` crate for the NAT's TCP state machine. A release
  build compiles **3 external crates in ~21 s**. No tokio, no async runtime.

The codebase is ~16,000 lines of Rust across 60 files. This document is written
for a **systems programmer who does not necessarily read Rust**: alongside the
feature/CLI reference it spells out exactly where the project uses `unsafe`,
where it allocates (and where it deliberately does not), which locks exist and
why, and which Rust language feature is doing the job a C programmer would do
with a raw pointer, a `static`, or a hand-rolled free-list.

---

## Table of contents

1. [Build & run](#1-build--run)
2. [Feature set & full CLI reference](#2-feature-set--full-cli-reference)
3. [Devices in detail](#3-devices-in-detail)
4. [Architecture & source layout](#4-architecture--source-layout)
5. [Safety model — where `unsafe` lives and how it's bounded](#5-safety-model--where-unsafe-lives-and-how-its-bounded)
6. [Performance model — allocation, pinned buffers, hot-path overhead](#6-performance-model--allocation-pinned-buffers-hot-path-overhead)
7. [Rust features for systems programmers (with a histogram)](#7-rust-features-for-systems-programmers-with-a-histogram)
8. [Concurrency: every lock, and why it exists](#8-concurrency-every-lock-and-why-it-exists)
9. [Hostile-guest hardening](#9-hostile-guest-hardening)
10. [ETW diagnostics](#10-etw-diagnostics)
11. [VM exits & counters](#11-vm-exits--counters)
12. [Boot trace](#12-boot-trace)
13. [Save / restore](#13-save--restore)

---

## 1. Build & run

```cmd
cd tinyvmm-rs
cargo build --release
```

The WHP import libraries (`WinHvPlatform.dll` / `WinHvEmulation.dll`) are linked
automatically through `windows-sys`. Verify the plumbing with the smoke test (no
guest kernel needed):

```cmd
> .\target\release\tinyvmm.exe --smoke
[smoke] WHP available
[mem] WARN: large-page alloc failed (SeLockMemoryPrivilege not held?); falling back to 4 KiB pages
[smoke] mapped 16 MiB guest RAM (4 KiB pages)
[smoke] partition + vCPU created OK (tsc_hz=3187140338)
```

Boot a kernel:

```cmd
:: inspect a kernel's PVH entry
.\target\release\tinyvmm.exe --pvh-info vmlinux

:: boot to an interactive hvc0 shell (Ctrl+A X to quit)
.\target\release\tinyvmm.exe --pvh-run --initrd initramfs.cpio vmlinux
```

### Large pages (recommended)

Guest RAM is allocated with `MEM_LARGE_PAGES` (2 MiB) when the process holds
**SeLockMemoryPrivilege** ("Lock pages in memory" in `gpedit.msc` → User Rights
Assignment; sign out/in to apply). Large pages let Hyper‑V back the SLAT/EPT
with 2 MiB super-pages, cutting second-level page-walk cost on the I/O path. If
the privilege is absent, tinyvmm prints the warning above and falls back to
4 KiB pages — functional, slower.

---

## 2. Feature set & full CLI reference

### Top-level modes (`argv[1]`)

| Mode | Purpose |
|------|---------|
| `--smoke` | Probe WHP, create a throwaway partition + 16 MiB RAM + 1 vCPU. |
| `--pvh-info <vmlinux>` | Parse and print a kernel's PVH ELF Note entry point. |
| `--pvh-run [flags] <vmlinux> [-- <cmdline>]` | Boot a microVM (the main mode). |
| `--restore <path>` | Resume a microVM from a snapshot file (instant resume). |
| `--blk-selftest` | Host-side virtio-blk DISCARD/WRITE_ZEROES self-test (no guest). |

### `--pvh-run` flags

| Flag | Default | Range / notes |
|------|---------|---------------|
| `--initrd <cpio>` | none | initramfs, memory-mapped and copied into guest RAM. |
| `--ram-mb <N>` | `256` | Clamped to **128–3584**. Upper bound is hard: the PCI MMIO window opens at `0xE000_0000` (3584 MiB); a bigger contiguous region would collide with device BARs. |
| `--vcpus <N>` | `1` | Clamped to **1–32**. BSP on the main thread; each AP on its own host thread. |
| `--rng` | off | Add a virtio-rng device (`/dev/hwrng`). |
| `--net` | off | Add a virtio-net NIC. **Repeatable** — each `--net` starts a new NIC; the NIC-scoped flags below modify the most recent NIC. |
| `--net-backend loopback\|nat\|wintun` | `nat` | Backend for the current NIC (see [§3](#3-devices-in-detail)). |
| `--portfwd HOSTPORT:GUESTPORT` | — | Forward `127.0.0.1:HOSTPORT` (host) → `10.0.0.2:GUESTPORT` (guest). NAT only. Repeatable per NIC. |
| `--wintun-name <adapter>` | — | WinTun adapter name (wintun backend). |
| `--wintun-host <ipv4>` | — | Host-side IPv4 for the wintun backend's gateway. |
| `--drive <path>[,readonly\|ro]` | — | Add a virtio-blk disk. **Repeatable up to 8** (`/dev/vda`, `/dev/vdb`, …). |
| `--virtio-9p-share <tag>=<host_dir>[,ro]` | — | Share a host directory over virtio-9p (9P2000.L). **Repeatable up to 8.** Tag 1–256 bytes; host path is canonicalized and must be a directory; duplicate tags rejected. |
| `--cpu-affinity all\|p\|e\|p-physical` | `all` | Pin every vCPU thread to a CPU-set class (P/E cores via `EfficiencyClass`). |
| `--save <path>` | — | Arm snapshot-on-trigger: when the guest issues `CPUID(0x4000DE57)`, capture the quiesced machine to `<path>` and exit. |
| `--unsafe-save-mutable-drive` | off | Allow `--save` even with a writable `--drive` attached (otherwise refused — the disk is not part of the snapshot, so a mutated disk diverges from restored RAM). |
| `--watchdog-secs <N>` | `0` | `0` = run until stopped; else stop after N s, printing `io/cpuid/msr` counters each second. |
| `--debug-boot` | off | Prepend `earlyprintk=ttyS0,115200` so early boot streams to the 8250 UART before hvc0 is up. |
| `-- <cmdline>` | see below | Everything after a bare `--` is the kernel cmdline. |

**Default cmdline** (when none supplied): `console=hvc0 pci=conf1,nocrs,lastbus=0
nofb nomodeset` — routes the console to virtio-console (hvc0) so `/init` lands an
interactive shell, and forces Configuration-Mechanism-#1 PCI access.

### Examples

```cmd
:: 4 vCPUs, 1 GiB, RNG, NAT networking, a disk, and a host folder share
tinyvmm --pvh-run --vcpus 4 --ram-mb 1024 --rng ^
    --net --net-backend nat --portfwd 8080:80 ^
    --drive ubuntu.img --virtio-9p-share host=C:\work,ro ^
    --cpu-affinity p-physical --initrd initramfs.cpio vmlinux

:: two NICs, each with its own backend
tinyvmm --pvh-run --net --net-backend nat --net --net-backend loopback ... vmlinux

:: snapshot on guest trigger, then instant-resume
tinyvmm --pvh-run --save vm.snap --initrd initramfs.cpio vmlinux
tinyvmm --restore vm.snap
```

---

## 3. Devices in detail

All paravirtual devices are **virtio 1.0 (modern) over a virtio-pci transport**
on a single PCI host bridge (Configuration Mechanism #1, ports `0xCF8/0xCFC`),
with MSI‑X interrupts. Vendor ID `0x1AF4` (Red Hat). Each device sits at its own
PCI slot in the order it is created.

| Device | Flag | Guest node | Notes |
|--------|------|-----------|-------|
| virtio-console | always (hvc0) | `/dev/hvc0` | Interactive shell. 3 MSI‑X vectors (rx/tx/config). |
| virtio-net | `--net` (×N) | `eth0…` | MAC `52:54:00:12:34:56` (+1 per extra NIC). 3 vectors. |
| virtio-rng | `--rng` | `/dev/hwrng` | Filled from Windows CNG `BCryptGenRandom`. 2 vectors. |
| virtio-blk | `--drive` (×8) | `/dev/vd{a…}` | Async IOCP backend. 2 vectors. |
| virtio-9p | `--virtio-9p-share` (×8) | `mount -t 9p` | 9P2000.L, Win32 backend. 2 vectors. |

**Legacy/emulated devices** (always present, for boot correctness):

* **8250/16550 UART** at `0x3F8` — TX→host stdout; raises IRQ4 via the PIC when
  the guest enables ETBEI. Used for `earlyprintk` before hvc0.
* **i8259 PIC pair** (`0x20/0x21`, `0xA0/0xA1`) — the only ISA‑IRQ→guest‑IDT path
  in virtual-wire mode; injects vectors with `WHvRequestInterrupt`.
* **8254 PIT** (`0x40–0x43`, `0x61`) — counters only; IRQ0 intentionally not
  wired (Linux uses the in-hypervisor LAPIC timer).
* **CMOS/RTC** (`0x70/0x71`) returns a fixed `2024-01-01` wall clock; POST port
  `0x80` and port‑A `0x92` are stubs.

### virtio-net backends (`--net-backend`)

* **`loopback`** — TX frames echoed straight back as RX. No host networking, no
  dependencies; proves the device/queues end-to-end.
* **`nat`** (default) — a **slirp-style user-mode NAT**: guest `10.0.0.2/24`,
  gateway `10.0.0.1`, no admin rights and no virtual adapter. Implements ARP,
  local + proxied **ICMP echo** (`ping 8.8.8.8` works via an `IcmpSendEcho`
  thread pool), **UDP** NAT (per-4-tuple connected socket, 60 s idle reap), and
  **TCP** terminate-and-proxy (guest-facing TCB in `tcp-sans-io`, host socket via
  `ConnectEx`). `--portfwd` adds inbound forwarding (the VMM originates a SYN
  toward the guest). The data plane is **allocation-free** (see [§6](#6-performance-model--allocation-pinned-buffers-hot-path-overhead)).
* **`wintun`** — bridges onto a real WinTun adapter (`wintun.dll` loaded at
  runtime; requires elevation to create the adapter).

### Doorbells (the no-VM-exit notify path)

The virtio-pci transport installs a **WHP MMIO doorbell**
(`WHvRegisterPartitionDoorbellEvent`) on each queue's notify register. A guest
kick then **signals an OS event instead of taking a VM exit**; a per-device pump
thread wakes and drives the normal `notify_queue` path. Enabled for
console/net/blk/9p (rng stays inline — its fill is cheap). The pump waits
`INFINITE` with **no periodic sweep**: the virtqueue itself closes the EVENT_IDX
race (Acquire re-read of `avail.idx`, Release of `avail_event`), and the MMIO
handler is the fallback for any non-matching write.

---

## 4. Architecture & source layout

The repo is a **Cargo workspace**. All FFI is quarantined in two auditable
crates; the binary keeps thin facade modules that re-export from them so internal
paths stay stable.

```
crates/
  winsys/        Win32 FFI ONLY (no WHP):
    error, host, host/block_file (async IOCP disk), host/mapped_file (mmap loader),
    sock (Winsock + IOCP), etw (TraceLogging), fs (9p file ops), cpu_affinity,
    wintun (wintun.dll loader), qpc (QueryPerformanceCounter), ptr (SharedPtr)
  whpsys/        Windows Hypervisor Platform FFI ONLY:
    partition, memory (GuestMemory), vcpu (run loop exits), regs, msi,
    emulator (WHvEmulator* + EmulatorBus trait), doorbell
src/
  main.rs        CLI dispatch, device wiring, interactive console, save/restore
  boot/          acpi (RSDP/XSDT/MADT), loader (PVH ELF + hvm_start_info/e820)
  devices/       io_bus, mmio_bus, serial(8250), pic(i8259), pit(8254), legacy
  pci/           config (Type-0 space), bus (0xCF8/0xCFC), msix
  virtio/        queue, device(trait), transport(virtio-pci modern),
                 console, net, rng, blk, p9
  net/           wire (parse/build), nat (user-mode NAT), wintun, sys (facade)
  whp/           run_loop, cpuid, hv (Hyper-V enlightenment), cpu_affinity(facade),
                 snapshot + snapshot_file + vcpu_state (save/restore)
  diag/          boot_timer, etw (facade)
```

The point of the split: **`unsafe` lives in `winsys`/`whpsys`** (raw Win32/WHP
calls) and in a short list of audited hot-path device structs. The `pci/`,
`devices/`, `boot/`, `virtio/queue`, and `net/wire` logic is essentially
`unsafe`-free.

### Device traits

Four `trait` objects (`dyn`) decouple the moving parts:

| Trait | Defined in | Used for |
|-------|-----------|----------|
| `VirtioDevice: Send + Sync` | `virtio/device.rs` | console/net/rng/blk/9p behind one `Arc<dyn>` the transport drives. |
| `PciFunction: Send + Sync` | `pci/mod.rs` | anything the PCI bus can enumerate (the transports). |
| `NetBackend: Send + Sync` | `virtio/net.rs` | loopback/nat/wintun data-plane peers. |
| `EmulatorBus` | `whpsys/emulator.rs` | the run loop's IO/MMIO dispatch handed to the WHP instruction emulator. |

---

## 5. Safety model — where `unsafe` lives and how it's bounded

There are **318 `unsafe` occurrences**, but they are not spread evenly. The
distribution is the whole story — `unsafe` clusters in the FFI crates and a few
audited device structs; the protocol logic is safe:

```
crates/winsys/fs.rs                 41   ← Win32 file ops for 9p
crates/winsys/sock.rs               38   ← Winsock / IOCP
src/net/nat.rs                      31   ← lock-free frame pool + raw socket FFI
crates/winsys/wintun.rs             27   ← GetProcAddress + fn-ptr calls
crates/whpsys/vcpu.rs               21   ← WHvGet/SetVirtualProcessorRegisters
crates/winsys/host/block_file.rs    18   ← OVERLAPPED ReadFile/WriteFile
src/virtio/blk.rs                   17   ← *status writes into guest RAM
crates/winsys/host/mapped_file.rs   15   ← MapViewOfFile
crates/whpsys/memory.rs             15   ← THE guest-RAM translation (audited)
crates/whpsys/emulator.rs           10   ← 5 extern "system" callbacks
...                                       (queue.rs=2, pci/*, devices/*, wire.rs ≈ 0)
```

### The idiom: a *little* unsafe to get a pointer, then slices — never pointer math

Every guest-RAM access funnels through **one audited module**,
`whpsys/memory.rs`. Its own comment states the doctrine:

> *These concentrate ALL of the guest-RAM raw-pointer access into this one
> audited place: every method bounds-checks the `[gpa, gpa+N)` range via
> `host_range` and then performs a single small `copy_nonoverlapping` to/from a
> stack buffer. Callers (the virtqueue, devices) use them with NO `unsafe`.*

The bounds check is written in subtraction form so a near-`u64::MAX` guest
address can't wrap the bound:

```rust
pub fn host_range(&self, gpa: u64, len: u64) -> Option<*mut u8> {
    if gpa < self.gpa { return None; }
    let off = gpa - self.gpa;
    let size = self.size as u64;
    if off >= size || len > size - off { return None; }   // no wrap
    Some(unsafe { self.base.get().add(off as usize) })
}
```

A raw pointer is produced **once**, validated, and immediately turned into a
fixed-size array, a slice, or an `AtomicU16`. Callers then operate on safe Rust
types. The virtqueue popper is explicit about this — it reads each 16-byte
descriptor with the bounds-checked `read_array::<16>()` and notes *"individual
descriptors are then read with bounds-checked `read_array` (no raw pointer
math)."* The few raw `*mut u8` that escape (in `ChainBuf`) are wrapped with
`as_slice()/as_mut_slice()` at the point of use.

Two distinct kinds of access live here, and the distinction matters for
performance ([§6](#6-performance-model--allocation-pinned-buffers-hot-path-overhead)):
the **copying accessors** (`read_array`/`read_into`/`write_bytes`/`read_u*`) do a
small fixed `copy_nonoverlapping` to/from a stack buffer and are used **only for
ring metadata** — the 16-byte descriptors and the 2/8-byte ring indices, whose
guest-controlled addresses make an in-place typed read an alignment hazard. The
**pointer accessor** (`host_range`) is used for **bulk data buffers**: it returns
a validated pointer the device operates on *in place* (disk DMA, rng fill, the
status byte), so guest *data* is never copied host-side.

### `SharedPtr<T>`: localizing the `unsafe impl Send`

A C programmer would slap `unsafe impl Send for BigStruct {}` on anything
holding a raw pointer. This project refuses to, because that blanket assertion
*also* silently vouches for every other field. Instead it wraps the one
offending pointer in a newtype (`crates/winsys/ptr.rs`):

```rust
#[repr(transparent)]
pub struct SharedPtr<T>(pub *mut T);
unsafe impl<T> Send for SharedPtr<T> {}
unsafe impl<T> Sync for SharedPtr<T> {}
```

Now the containing struct (`GuestMemory`, `Emulator`, …) **auto-derives**
`Send`/`Sync`, compiler-checked. If someone later adds an `Rc` to that struct,
the build breaks loudly instead of being silently waved through. This is the
project's preferred pattern; the remaining hand-written `unsafe impl Send/Sync`
(17 `Send`, 7 `Sync`) are confined to the pools and FFI handle wrappers where the
external invariant is documented inline (e.g. *"the free-list guarantees a slot
is owned by at most one party at a time"*).

### Panics are setup-only, never guest-reachable

`panic!` appears **4 times**, all at *configuration* time: device-registration
overlap in `io_bus`/`mmio_bus`, and BAR-window exhaustion / "IO BARs not
supported" in `pci/bus`. The `.expect()` calls are in the blk self-test and one
IOCP-creation-at-startup. **No guest action reaches a panic**: the guest-facing
paths return `Option`/`bool`/an error status byte (a malformed virtio descriptor
just gets dropped or `BLK_S_IOERR`, an out-of-range gpa returns `None`). See
[§9](#9-hostile-guest-hardening).

> ⚠️ The one residual abort surface is `Mutex::lock().unwrap()` (most of the 218
> `unwrap()`s). With `panic = "abort"`, a *poisoned* mutex aborts the process.
> Poisoning only happens if a thread already panicked while holding the lock —
> and the lock-holding critical sections do not panic on guest input — so in
> practice this is a "should never happen" assertion, not a guest-triggerable
> crash.

---

## 6. Performance model — allocation, pinned buffers, hot-path overhead

The guiding principle (verified by `xperf` CPU-sampling under load: tinyvmm's own
code is **~0.2 %** of samples; the rest is the hypervisor + Windows kernel I/O):
**optimize VM-exit *count*, not host-side handler code.** Doorbells and the
async backends exist to remove exits; the data planes are allocation-free so the
GC-free, malloc-free hot path never stalls.

### Where it allocates — and where it deliberately does not

| Path | Allocation behavior |
|------|---------------------|
| Boot / device setup | Allocates freely (Vecs, Strings, Boxes). One-time. |
| Kernel + initramfs load | **Memory-mapped** (`MapViewOfFile`), copied straight into guest RAM — no read-into-`Vec`, ~⅓ the cost. Mapping dropped right after. |
| virtio TX/RX, blk submit/complete, 9p dispatch | **Zero heap allocation on the hot path** — everything comes from preallocated pools and reused scratch buffers (below). |
| NAT cold paths (ARP, ICMP/ping, RST) | Still allocate — rare, not worth pooling. |

### The four preallocated pools (this is the "partitioned memory" a systems programmer expects)

| Pool | Where | Backing | Free-list | Sizing |
|------|-------|---------|-----------|--------|
| **FramePool** (guest-TX frames) | `net/nat.rs` | `Box<[FrameSlot]>`, each `UnsafeCell<[u8; 2048]>` | **lock-free Treiber stack**, ABA-tagged in the high 32 bits of an `AtomicU64`, MPMC | `POOL_SLOTS = 1024` |
| **RxPool** (inbound frames) | `virtio/net.rs` | `Vec<[u8; 2048]>` | `Vec<u32>` index free-list under the device mutex | `RX_POOL_SLOTS = 512` |
| **ReqPool** (in-flight blk requests) | `virtio/blk.rs` | `Vec<Box<BlkReq>>` | `Vec<u16>` | virtqueue depth (256) |
| **SlotPool** (in-flight 9p requests) | `virtio/p9.rs` | `Vec<UnsafeCell<P9Slot>>` | preallocated slots + precreated workers | per-queue depth |

Plus **reused scratch buffers** with no per-event allocation: the NAT keeps
`tx_scratch`/`l3_scratch` `Vec`s (built into via `build_*_into` write-into-buffer
wire helpers); virtio-net keeps a `TxScratch { frame, chain }`; the virtqueue's
`pop_into(&mut PoppedChain)` reuses the `bufs` `Vec` across pops.

### Pinned / address-stable buffers for async IOCP

The async block backend (`winsys/host/block_file.rs`) overlaps `ReadFile`/
`WriteFile` on a per-disk IOCP. Overlapped I/O requires the `OVERLAPPED` and its
buffer to **stay put** until completion. Two deliberate choices make that safe
without a GC or pinning API:

1. **`OVERLAPPED` is the first field of a `#[repr(C)]` request struct.** The
   worker recovers the whole request from the completion's `OVERLAPPED*` by a
   pointer cast — `OVERLAPPED* == Request* == BlkReq*`, all three addresses
   coincide:

   ```rust
   #[repr(C)]
   pub struct Request { pub ovl: OVERLAPPED, pub op: Op, /* ... */ pub buf: *mut u8, pub bytes: u32 }
   ```

2. **The request slots are `Box`ed and pooled** so their addresses are stable for
   the slab's lifetime — the `ReqPool` comment is explicit: *"Box (not inline) is
   REQUIRED: each slot's address is handed to the IOCP backend as the completion
   context and must stay stable; `Vec<BlkReq>` would move slots on realloc."*

At most **one segment per request is in flight**; the next is submitted from the
completion, which preserves order and bounds memory. The NAT applies the same
"one send in flight, next posted from completion" discipline to TCP.

### "If you were OK with `unsafe`, what does the safe version cost you?" — per-hot-event overhead

This is the tax the safety model adds versus a C VMM that derefs guest pointers
directly and trusts its own buffers:

* **Per queue kick (doorbell path):** an OS event wake on the pump thread +
  `ResetEvent` + **one `Mutex<Virtqueue>` lock/unlock** per drain. The mutex is
  *uncontested* in the steady state (only the pump drains) so it's ~10–20 ns. The
  big win dwarfs it: a kick costs **0 VM exits** instead of one (measured on a
  56 KB download: 0 vs 182 MMIO-exit notifies; the per-exit cost is microseconds
  of hypervisor round-trip).
* **Per descriptor decode (control-plane only):** a bounds check (2–3 branches in
  `host_range`) + a **16-byte** `copy_nonoverlapping` of the *descriptor itself*
  (not the data it points at) into a stack `[u8;16]` — a const-generic local
  (`let b = [0u8; 16]`) returned by value, so **no heap allocation** (`queue.rs`
  via `read_array::<16>`). The stack copy — rather than reading the descriptor
  through a typed pointer in place — is for **alignment safety**: the guest
  controls the descriptor-table address, so a misaligned/torn typed read would be
  UB, whereas copying 16 bytes to an aligned stack array is always sound. The
  `next`/`idx` fields are then re-validated against `size` to bound malicious
  chains. The avail/used ring indices (2 B) and the used-ring element (8 B) are
  the only other guest-*metadata* touches, read/written as `AtomicU16`
  Acquire/Release or an 8-byte write through a validated pointer.
* **Per data buffer — ZERO copy.** The bulk payload a descriptor points at is
  **never** staged through a host buffer by the safety layer. `host_range` hands
  back a bounds-checked pointer wrapped in a `ChainBuf { ptr, len }`, and the
  device works on it **in place**: virtio-blk sets `req.buf = seg_ptr` and lets
  `ReadFile`/`WriteFile` DMA **straight into/out of guest RAM** (`blk.rs:565`);
  virtio-rng fills the guest-writable buffer in place via `as_mut_slice()`
  (`rng.rs:85`); the status byte is written through `*status_ptr` in place. So a
  disk read of a megabyte copies **zero** bytes host-side beyond the OS page
  cache — exactly as a C VMM that DMAs into guest pages would.
* **Per guest TX frame (net):** **two CAS** (`compare_exchange_weak` acquire +
  release on the Treiber frame-pool stack) to borrow/return a slot, then an IOCP
  post — no allocation, no lock, fully concurrent across vCPUs. virtio-net is
  also the one device that *gathers* guest bytes: `frame_into` assembles the
  (possibly multi-descriptor) chain into a contiguous reused scratch `frame`
  because the backend wants one contiguous `&[u8]`. That gather is a
  **protocol/device requirement** (a NIC hands up whole frames), not a
  per-guest-touch safety tax.
* **Per inbound RX frame (net):** RX is the mirror — received bytes must be
  *placed into* the guest's RX descriptors, so a copy into guest RAM is
  **inherent to any NIC model** (the guest provides the destination buffers).
  On top of that delivery copy there is one **ownership-boundary** staging copy:
  the backend worker memcpys the frame into a pooled 2 KiB slot (under
  `Mutex<RxPool>`) so the vCPU/pump can deliver it later (under `Mutex<rxq>`),
  decoupling the network thread from the guest. The staging copy *could* be
  elided with a more intricate single-locked hand-off; it's kept for the clean
  thread boundary. (9p is similar — a message protocol assembles each reply and
  scatters it into the guest buffers.)
* **Per block request:** `Mutex<ReqPool>` lock (pop a slot) + `extend_from_slice`
  of the descriptor *list* (the `ChainBuf` pointers, not the data) into the
  slot's *reused* `data_segs` `Vec` (no realloc after warm-up) +
  `Mutex<Virtqueue>` lock. All uncontested in steady state.

The honest summary: **guest data is zero-copy.** Disk bytes DMA directly in/out
of guest RAM and rng/status writes land in place; the device never re-stages bulk
payload host-side. The only fixed memcpy the safety model imposes is
**control-plane** — a 16-byte descriptor (plus 2/8-byte ring indices) copied to
the stack per request, for alignment safety on guest-controlled addresses — and
**one uncontended mutex per drain**. The TX gather and the RX delivery+staging
copies belong to virtio-net/9p (a NIC/message protocol moves whole frames), not
to the guest-memory-access layer. All of it is nanoseconds and off the critical
path that actually matters (the VM exit), which is why profiling shows our code
at noise level.

### Measured throughput (representative, Intel i9‑14900K)

| Workload | Result |
|----------|--------|
| Boot (enter guest → `/init` complete) | **~298 ms** (≈ unchanged at 1/2/4 vCPUs) |
| virtio-blk single-stream read | **~533 MB/s** (guest block layer pipelines ~14 in-flight) |
| virtio-9p single-stream read | ~16 MB/s (request-response latency-bound; `cache=none` ≡ `cache=loose`) |
| virtio-9p concurrent (32 readers) | **~190 MB/s** (ceiling = single submit pump + the per-queue `Mutex<Virtqueue>`) |
| virtio-net | 20 MB guest→host transfer at line rate with the periodic sweep disabled |

---

## 7. Rust features for systems programmers (with a histogram)

If you build "actual homes for low-level programming" — fixed sizes,
preallocation, explicit ownership — here is the Rust feature that does each job,
how often it appears, and the C analogue. Counts are raw occurrences across all
60 files.

```
unsafe (keyword)        318  ████████████████████████████████  (FFI + audited hot paths)
.unwrap()               218  ██████████████████████  (mostly Mutex::lock; see note)
Atomic* types           169  █████████████████  lock-free counters/flags/state
Arc<T>                  122  ████████████  shared ownership across threads
*mut/*const casts        87  █████████  raw ptr at FFI / guest-RAM boundary
OnceLock<T>              47  █████  set-once globals & handles
dyn Trait                42  ████  the 4 device traits, vtable dispatch
Mutex<T>                 33  ███  cross-thread device state
Box<T>                   20  ██  heap-stable / trait objects / callbacks
unsafe impl Send         17  ██  pools + FFI handle wrappers
impl Drop                15  ██  RAII teardown (handles, mappings, threads)
transmute                12  █  GetProcAddress fn-pointer casts only
UnsafeCell<T>             8  █  interior mutability in 2 pools (frame, 9p slot)
#[repr(C)]                8  █  ABI-stable structs at the FFI boundary
unsafe impl Sync          7  █
from_raw_parts            5  ▌  the slice materializers
panic!                    4  ▌  setup-time invariants only
trait (defined)           4  ▌  VirtioDevice/PciFunction/NetBackend/EmulatorBus
RwLock<T>                 2  ▌  the read-mostly MMIO dispatch table
Rc / RefCell / Cow /      0     ← deliberately ABSENT (see below)
Pin / PhantomData /
static mut / Box::leak
```

### What each feature is doing here

* **`Arc<T>` (122)** — shared, refcounted, thread-safe ownership. Guest RAM, the
  vCPUs, the HV enlightenment, every device, and every backend are `Arc`-shared
  because multiple host threads (vCPUs, the doorbell pump, IOCP workers, the
  watchdog) hold them at once. This is the C "shared object with a refcount"
  pattern, but the refcount is correct by construction.
* **`Weak<T>` + `Arc`** — the device→transport IRQ callback uses
  `Arc::downgrade` to avoid a **reference cycle** (the transport owns the device
  via `Arc`; the device's interrupt closure points *back* at the transport). A C
  programmer would use a raw back-pointer; `Weak` makes the "might be gone"
  explicit and the `upgrade()` checked.
* **`Atomic*` (169) + `OnceLock` (47)** — this is how the project does **global
  and shared mutable state without `static mut`**. Counters (VM-exit tallies, blk
  op stats), flags (`driver_ok`, `backend_detached`, snapshot `ARMED/REQUESTED`),
  and the ETW enable/level/keyword cache are all atomics. Set-once handles and
  caches (the IRQ callback, the cached TSC Hz, the ETW provider-metadata blob,
  the CRC table) use `OnceLock` — a lock-free `get()` after one `set()`. This
  replaces the C "global, written once at init, read forever" idiom with
  something the compiler proves is race-free. (Memory note from this codebase:
  `OnceLock::get` is a single Acquire load vs `Mutex::lock`'s two futex RMWs.)
* **`UnsafeCell<T>` (8)** — interior mutability *without* a lock, used in exactly
  two pools (`FramePool`, the 9p `SlotPool`). The slot's bytes are mutated
  through a raw pointer while the **free-list / IOCP guarantees exclusive
  ownership** between acquire and release. This is the principled version of
  "I know nobody else touches this slot right now" — `UnsafeCell` is the *only*
  legal way to tell the Rust compiler that, and the safety argument is documented
  at each site.
* **`Mutex<T>` (33) / `RwLock` (2)** — see [§8](#8-concurrency-every-lock-and-why-it-exists). Yes, there are
  locks even though memory is preallocated — be suspicious, then read §8 for why
  each one exists and what contends it.
* **`Box<T>` (20)** — heap-stable addresses for IOCP completion contexts
  (`Box<BlkReq>`), trait objects (`Box<dyn Fn>` callbacks), and the PIC's
  interrupt closure.
* **`impl Drop` (15)** — **RAII** is how every OS resource is released:
  `GuestMemory` (`VirtualFree` + unmap), `Vcpu`/`Partition`/`Emulator`/`Doorbell`
  (WHP handle delete), `BlockFile`/`Inner` (`CloseHandle` of file + IOCP),
  `MappedFile` (`UnmapViewOfFile`), `PciTransport` (tear down doorbell pump +
  join), `SnapshotWriter` (delete a half-written file). Teardown order is
  explicit in `main.rs` (quiesce IOCP workers *before* their owners drop, so no
  completion lands on freed memory).
* **`Send`/`Sync` + `unsafe impl` (17/7)** — see [§5](#5-safety-model--where-unsafe-lives-and-how-its-bounded). The preferred form is the
  `SharedPtr` newtype so structs auto-derive; hand-written impls are the
  documented exceptions.
* **`#[repr(C)]` (8) + `transmute` (12)** — ABI control at the FFI line. `repr(C)`
  guarantees field order for the `OVERLAPPED`-first request structs and the
  frame slot. Every `transmute` is a `GetProcAddress` result → typed function
  pointer (the `wintun.dll` entry points and Winsock's `ConnectEx`) — the one
  thing you cannot express without it.
* **`trait` + `dyn` (4 traits / 42 uses)** — vtable dispatch for the device model
  (above). The cost is one indirect call per kick — negligible next to the exit
  it replaces.
* **Deliberately ABSENT (`0`):** **`Rc`/`RefCell`** (single-threaded interior
  mutability) have no place in a multi-threaded VMM — everything shared is `Arc`
  + atomics/`Mutex`/`UnsafeCell` instead. **`Pin`/`PhantomData`** aren't needed
  because there is no self-referential async state machine (the runtime is a
  hand-rolled IOCP loop, not `Future`s). **`static mut`** is replaced by atomics
  and `OnceLock`. **`Cow`** isn't used because the hot paths don't
  clone-on-write — they reuse fixed buffers.

### The "deliberate leak" (process-lifetime statics) & raw ownership handoff

Two things a systems reader should know:

* **Process-lifetime `OnceLock` statics are never freed** — and that's
  intentional. The ETW provider-metadata `Vec<u8>`, the CRC32 table `[u32;256]`,
  the cached TSC Hz, the cached large-page size, and the host CPU topology are
  set once and live until the process exits. They are effectively *leaked on
  purpose*: there is exactly one of each, it is read for the whole run, and
  reclaiming it at exit would be pure ceremony (`panic = "abort"` means there is
  no unwinding teardown anyway).
* **Raw ownership handoff across the IOCP** uses `Box::into_raw` →
  `Box::from_raw`, not a leak: the NAT boxes an ICMP/accept message, posts the
  raw pointer through `PostQueuedCompletionStatus`, and the worker **reclaims**
  it with `Box::from_raw` on the other side. Ownership moves through the OS queue
  exactly once; no aliasing, no double free.

---

## 8. Concurrency: every lock, and why it exists

A systems programmer sees "preallocated, partitioned buffers" and rightly asks
*why are there locks at all?* Because **multiple host threads** touch shared
device state: the vCPU threads (1 per `--vcpus`), the per-device **doorbell pump**
threads, the per-disk **IOCP worker** threads, the **9p worker pool**, the NAT
worker + its ICMP/accept helper threads, and the watchdog. The locks serialize
*host-thread* access; they are **not** about the guest. Where single-ownership
can be proven instead, there is no lock (the Treiber free-list, the `OnceLock`
IRQ callback, the `UnsafeCell` slots).

| Lock | Guards | Who contends | Why it can't be lock-free |
|------|--------|--------------|---------------------------|
| `Mutex<Virtqueue>` (per queue, every device) | desc/avail/used ring cursors | vCPU (MMIO fallback) **and** the doorbell pump / IOCP worker that drains+retires | ring head/tail advance + used-ring publish must be atomic as a unit |
| `Mutex<ReqPool>` (blk) | in-flight slot free-list | submit (pump) vs completion (IOCP worker) | small critical section; a CAS stack was unnecessary at depth 256 |
| `Mutex<RxPool>` + `Mutex<TxScratch>` (net) | RX slot pool + reused scratch | backend worker injecting vs vCPU/pump draining | hand-off boundary between the network thread and the device |
| `Mutex<Common>` + `Mutex<PciConfigSpace>` + `Mutex<Option<DoorbellState>>` (transport) | virtio common-cfg, PCI config space, the live doorbell set | vCPU MMIO writes vs BAR (un)map vs pump lifecycle | config writes mutate multiple fields consistently |
| fid-table `Mutex` + slot-pool (9p) | open fid→handle map | 9p workers running concurrent reads/writes | shared mutable map across the worker pool |
| `Mutex`/`Condvar` (NAT ICMP handoff) | the bounded ping handoff queue | vCPU enqueues, helper threads dequeue | classic bounded producer/consumer |
| `RwLock<Vec<Entry>>` (MMIO bus) | the GPA→device dispatch table | written once at setup, read on every MMIO | read-mostly; readers never block readers |
| `OnceLock` (IRQ callbacks, backends) | set-once handles | setup writer, then lock-free readers | **not a lock in the steady state** — `get()` is a plain Acquire load |

Lock-free structures where ownership *is* provable: the **FramePool** Treiber
free-list (ABA-guarded `AtomicU64`), all the **atomic counters/flags**, and the
`UnsafeCell` slot bodies (exclusive between acquire/release).

---

## 9. Hostile-guest hardening

The guest is **untrusted**. Hardening is the validation layer, kept separate from
the locking story above.

* **Guest RAM:** every translation goes through `host_range()` with the wrap-safe
  subtraction check ([§5](#5-safety-model--where-unsafe-lives-and-how-its-bounded)); out-of-range returns `None` and the access is
  dropped. No guest address ever forms an unchecked host pointer.
* **Virtqueue (`queue.rs`):** the avail ring head is rejected if `>= size`; the
  descriptor table mapping is validated before traversal; the chain walk is
  **bounded by `size`** and every `next` index (direct and indirect) is checked
  `< size` / `< inner_count` so a cyclic or oversized chain can't loop or run
  off the ring. Descriptor payloads are only accepted if their `[addr, addr+len)`
  maps.
* **virtio-blk (`blk.rs`):** requires ≥ header+status descriptors, header
  readable ≥ 16 B, status writable ≥ 1 B; rejects an out-of-range sector
  *before* the `sector * 512` multiply; DISCARD/WRITE_ZEROES totals must be a
  multiple of 16 and within `BLK_MAX_RANGE_SEG`. Bad requests get a status byte
  (`BLK_S_IOERR`/`BLK_S_UNSUPP`), never a panic.
* **PCI (`config.rs`/`msix.rs`):** config reads/writes bounded by
  `CFG_SPACE_SIZE`; BAR writes masked to the BAR size so the guest can't program
  bits outside the window; MSI‑X table/PBA access checks alignment and
  `vec < num_vectors`; interrupt trigger refuses `vector >= num_vectors`.
* **virtio-9p path security (`p9.rs`):** the share root is canonicalized once;
  each wire path component is sanitized (rejects separators, NUL/control chars,
  `:` and the other reserved Win32 chars, trailing dot/space, reserved DOS
  names like `CON`/`PRN`); `.`/`..` are resolved against the share with a
  **clamp-to-root**; a lexical containment check (lowercased, `\`-terminated
  prefix) is the backstop; and all Win32 calls go through `\\?\` long paths. A
  guest cannot path-walk out of the share. Read-only shares reject writes with
  `EROFS`.
* **Backpressure, not unbounded buffering:** the NAT's per-flow guest→host queue
  caps at 64 KiB (closes the guest TCP window); the net RX pool drops inbound
  frames when the guest isn't draining; the ICMP handoff queue is bounded.

---

## 10. ETW diagnostics

Built-in **ETW TraceLogging** for low-overhead, out-of-process tracing
(`crates/winsys/etw.rs`). The TraceLogging metadata blob is **hand-rolled** so
there is **no extra dependency** — just the raw `EventRegister`/
`EventWriteTransfer` APIs already in `windows-sys`.

* **Provider:** `Tinyvmm-Core`, GUID `{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}`.
* **Hot-path gate:** an enable callback caches the session level + keyword mask
  in atomics, so a disabled event costs a **single relaxed atomic check**
  (`lvl != 0 && level <= lvl && (keyword & EN_KW) != 0`) — no API call, no
  formatting. Disabled tracing is essentially free.
* **Metadata quirk** (documented in the source): the per-event metadata prepends
  a required `0x00` event-tags byte before the name; omitting it shifts the
  decoded event name by one character.

**Keywords** (bit mask): `VMEXIT=0x1`, `DOORBELL=0x2`, `VIRTIO=0x4`, `NET=0x8`,
`MMIO=0x10`, `IO=0x20`, `BOOT=0x40`, `LIFECYCLE=0x80`, `BLOCK=0x100`,
`CPUID=0x200`, `MSI=0x400`. **Levels:** `CRITICAL=1`, `ERROR=2`, `WARN=3`,
`INFO=4`, `VERBOSE=5`.

**Instrumented events:**

| Event | Level / Keyword | Fields |
|-------|-----------------|--------|
| `VmStart` | INFO / LIFECYCLE | kernel, ram_mb, vcpus, nics, rng, drives |
| `VmStop` | INFO / LIFECYCLE | reason, io, cpuid, msr, uart_tx, total_ms |
| `NetBackendStart` / `NetBackendStop` | INFO / LIFECYCLE | backend, mac |
| `BootMark` | INFO / BOOT | phase, total_ms, delta_ms |
| `VmExit` | VERBOSE / VMEXIT | reason, vp, rip |
| `NetTx` / `NetRx` | VERBOSE / NET | len |
| `NetTxDrop` / `NetRxDrop` | VERBOSE / NET | len |
| `MsiInject` | VERBOSE / MSI | vector, addr, data |
| `RngFill` | VERBOSE / VIRTIO | ops, bytes |
| `BlkSubmit` | VERBOSE / BLOCK | type, sector, segs, head |
| `BlkComplete` | VERBOSE / BLOCK | type, used_len, failed, head |
| `Doorbell` | VERBOSE / DOORBELL | queue |

**Capture** (no admin needed), e.g. Lifecycle | Net | Doorbell at VERBOSE:

```
logman start tv -p "{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}" 0x8a 5 -ets -o tv.etl
  ...run the VM...
logman stop tv -ets
tracerpt tv.etl -o tv.csv -of CSV -y
```

---

## 11. VM exits & counters

The run loop (`whp/run_loop.rs`) dispatches each exit via a typed `ExitReason`
(`Halt`, `IoPort`, `Memory`, `Cpuid`, `Msr`, `InterruptWindow`, `ApicEoi`,
`Canceled`, `Other(u32)`) decoded in `whpsys/vcpu.rs`. IO/MMIO are completed by
the WHP instruction emulator through the `EmulatorBus` (the IO and MMIO buses);
CPUID and MSR are resolved by the CPUID policy / Hyper‑V enlightenment.

Per-vCPU `AtomicU64` **counters** — `io`, `mmio`, `halt`, `cpuid`, `msr`,
`other` — are bumped per exit. At teardown `main.rs` prints the summary (this is
the exact format string):

```
[pvh-run] stopped: reason=GuestHalted uart_tx=1234 exits[io=20618 mmio=0 cpuid=486 msr=15 halt=1 other=0]
```

Representative phase‑1 boot (matches the C++ reference exactly): `io=20618
cpuid=486 msr=15`, `mmio=0`. The headline result of doorbells: on a 9p workload
they cut MMIO notify exits **~15×** (3173 → 205). The `--watchdog-secs` path
prints a live `io/cpuid/msr` line each second.

`HLT` with interrupts disabled (`RFLAGS.IF=0`) is treated as terminal
(`GuestHalted`) — needed because an ACPI-less `poweroff` falls back to `STI;HLT`
and never produces a clean halt; harnesses also use a console **shutdown
sentinel** (`=== tinyvmm shutdown requested ===` on hvc0) to stop every vCPU.

---

## 12. Boot trace

`diag/boot_timer.rs` records **QPC** waypoints and prints
`[boot] {total:8.3} ms (+{delta:7.3} ms) {phase}` at each, and emits a `BootMark`
ETW event per mark (keyword `BOOT`). The seven waypoints, in order:

```
pvh-run start          ← argv parsed, run begins
WHP probe done         ← hypervisor present confirmed
guest RAM mapped       ← VirtualAlloc + WHvMapGpaRange + HV enlightenment ready
vmlinux+initramfs loaded   ← mmap + memcpy into guest RAM, PVH structures built
entering guest         ← devices wired, run loops about to start
guest exited           ← BSP run loop returned (the dominant phase: actual boot)
teardown done          ← APs joined, IOCP workers quiesced, console restored
```

Representative trace (Intel i9‑14900K, 256 MiB, 1 vCPU — **timings are
machine-specific**; the dominant cost is the guest reaching `/init`, everything
host-side is a few ms):

```
[boot]    0.000 ms (+  0.000 ms) pvh-run start
[boot]    4.7   ms (+  4.7   ms) WHP probe done
[boot]    9.1   ms (+  4.4   ms) guest RAM mapped
[boot]   22.6   ms (+ 13.5   ms) vmlinux+initramfs loaded
[boot]   23.4   ms (+  0.8   ms) entering guest
[boot]  297.9   ms (+274.5   ms) guest exited
[boot]  298.6   ms (+  0.7   ms) teardown done
```

Total ≈ **298 ms**, essentially unchanged at 1/2/4 vCPUs (the per-component
mutexes added for AP safety are uncontended at low vCPU counts and cost
~10–20 ns each).

---

## 13. Save / restore

`--save <path>` arms a snapshot trigger; the guest requests a checkpoint by
issuing the **magic leaf `CPUID(0x4000DE57)`**, which the run loop surfaces as
`StopReason::SnapshotRequested`. The VMM then quiesces (stops + joins APs, drains
blk IOCP workers, quiesces net backends) and writes a self-describing file:

```
[24-byte header] "TVMMSAVE" | version u32 | reserved u32 | header_json_size u64
[sections...]    type u32 | reserved u32 | length u64 | payload[length]
[trailer]        CRC32 (IEEE-802.3) over all preceding bytes
```

Sections cover per-vCPU register state (GPRs, control/segment/descriptor regs,
EFER, XSAVE, APIC, interrupt-controller state, TSC last), the Hyper‑V
enlightenment, the legacy devices, every PCI device, and **guest RAM last**. Each
PCI device section is tagged with its `device_index` (PCI-add order: console=0,
then NICs, rng, blk*, 9p*). **Save and restore must construct devices in the
same order** or indices misalign — `run_restore` rebuilds them from the header in
that exact sequence. A virtio device snapshots through just four
`VirtioDevice` hooks (`capture_queue`/`apply_queue`/`capture_device_state`/
`apply_device_state`); the transport handles the rest of the ordering (PCI
config / BAR remap → common-cfg → MSI‑X table → queues → device-state).

`--save` is refused with an attached *writable* `--drive` (the disk isn't in the
snapshot, so a mutated disk would diverge from restored RAM) unless you pass
`--unsafe-save-mutable-drive`. A device with a live host backend (e.g. the NAT)
snapshots only its *model*; on restore a **fresh** backend is wired from the
header (live flows reset, new flows work). The `SnapshotWriter`'s `Drop` deletes
a half-written file if `finalize()` didn't run.

---

*tinyvmm-rs is a Rust rewrite of the C++ `tinyvmm` (see [`../README.md`](../README.md)).
The C++ tree under `../src` remains as the reference implementation.*
