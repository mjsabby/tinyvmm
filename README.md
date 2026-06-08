# tinyvmm

A **tiny, opinionated, user-mode Virtual Machine Monitor** (a *microVM* monitor)
for Windows. It does exactly one thing: bring up a single 64-bit Linux microVM on
the **Windows Hypervisor Platform** (WHP), boot it through the **PVH** entry
point, hand it a curated set of paravirtualized (virtio) devices on one PCI bus
with MSI-X — and then get out of the way.

It is deliberately **not** a general-purpose machine emulator. There is no BIOS,
no legacy/real-mode boot, no ACPI power management, no device hot-plug, no PCI
passthrough, no SMM. Like firecracker / cloud-hypervisor it targets the
**microVM** sweet spot: the smallest amount of virtual machine a modern Linux
needs to reach its `init` quickly, with a hand-picked device set and a host-side
setup measured in **tens of milliseconds**. Every feature below exists because a
microVM needs *that* and nothing more — that is what "opinionated" means here.

```cmd
.\target\release\tinyvmm.exe --pvh-run --vcpus 4 --ram-mb 1024 --rng ^
    --net --drive disk.img --virtio-9p-share share=C:\host\dir ^
    --gpu 1280x800 --input --initrd initramfs.cpio vmlinux
```

* **Host:** Windows 11 / Server 2022 with the *Windows Hypervisor Platform*
  feature enabled. Builds with stable Rust.
* **Guest:** an unmodified PVH-capable `vmlinux` (`CONFIG_PVH=y`) + an initramfs.
* **External dependencies:** `windows-sys` (which only pulls `windows-link`) and
  `tcp-sans-io` (a git dependency, `github.com/mjsabby/tcp-sans-io`) that supplies
  the NAT's TCP state machine. No tokio, no async runtime, no other third-party
  crates.

The repo is a Cargo workspace: **~21,400 lines of Rust across 64 files** (the
binary in `src/`, plus two FFI crates under `crates/`). This document is written
for a **systems programmer who does not necessarily read Rust**. Alongside the
feature/CLI reference it spells out, with file and line citations, exactly where
the project uses `unsafe`, where it allocates (and where it deliberately does
not), which locks exist and why, what each per-hot-event operation costs versus a
C VMM that just dereferences guest pointers, and which Rust language feature is
doing the job a C programmer would do with a raw pointer, a `static`, or a
hand-rolled free-list.

---

## Table of contents

1. [Build & run](#1-build--run)
2. [Feature set & full CLI reference](#2-feature-set--full-cli-reference)
3. [Devices in detail](#3-devices-in-detail)
4. [Architecture & source layout](#4-architecture--source-layout)
5. [Safety model — where `unsafe` lives and how it is bounded](#5-safety-model--where-unsafe-lives-and-how-it-is-bounded)
6. [Performance model — allocation, pinned buffers, hot-path overhead](#6-performance-model--allocation-pinned-buffers-hot-path-overhead)
7. [Rust features for systems programmers (with a histogram)](#7-rust-features-for-systems-programmers-with-a-histogram)
8. [Concurrency: every lock, and why it exists](#8-concurrency-every-lock-and-why-it-exists)
9. [Hostile-guest hardening](#9-hostile-guest-hardening)
10. [ETW diagnostics](#10-etw-diagnostics)
11. [VM exits & counters](#11-vm-exits--counters)
12. [Boot trace (measured)](#12-boot-trace-measured)
13. [Save / restore](#13-save--restore)

---

## 1. Build & run

```cmd
cargo build --release
```

The WHP import libraries (`WinHvPlatform.dll` / `WinHvEmulation.dll`) link
automatically through `windows-sys`. A release build compiles three external
crates (`windows-link`, `windows-sys`, `tcp-sans-io`) plus the two in-tree FFI
crates in **~30 s** on the reference machine. The release profile is tuned for a
shippable single binary (`Cargo.toml`):

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
panic = "abort"     # no unwinding; a panic aborts the process (see §5)
```

There are four self-tests that need **no guest kernel**:

```cmd
> .\target\release\tinyvmm.exe --smoke
[smoke] WHP available
[smoke] mapped 16 MiB guest RAM (4 KiB pages)
[smoke] partition + vCPU created OK (tsc_hz=3187134557)
[smoke] running vCPU until next exit...
[smoke] exit reason = X64Halt RIP=0x1
[smoke] PASS
```

* `--smoke` — create a throwaway partition + 16 MiB RAM + one vCPU and run it to
  its first `HLT`.
* `--pci-selftest` — exercise the PCI host-bridge config mechanism, BAR sizing,
  and 64-bit BAR assignment against a synthetic `PciFunction`.
* `--blk-selftest` — drive virtio-blk DISCARD / WRITE_ZEROES against a temp file.
* `--pvh-info <vmlinux>` — parse and print a kernel's PVH ELF-Note entry point.

Boot a kernel:

```cmd
.\target\release\tinyvmm.exe --pvh-run --initrd initramfs.cpio vmlinux
```

### Large pages (recommended)

Guest RAM is allocated with `MEM_LARGE_PAGES` (2 MiB pages) when the process can
hold **SeLockMemoryPrivilege** ("Lock pages in memory" in `gpedit.msc` → *User
Rights Assignment*; sign out/in to apply). The `--pvh-run` / `--restore` paths
call `enable_lock_memory_privilege()` (`crates/winsys/src/host.rs:53`) at startup
and print `[host] SeLockMemoryPrivilege: enabled` when it succeeds. Large pages
let Hyper-V back the second-level address translation (SLAT/EPT) with 2 MiB
super-pages, cutting page-walk cost on the I/O path. Without the privilege,
tinyvmm prints a warning and falls back to 4 KiB pages — functional, just slower.

---

## 2. Feature set & full CLI reference

The first argument selects a **mode** (`main.rs:3500`):

| Mode | Purpose |
|------|---------|
| `--smoke` | Probe WHP; create a throwaway partition + 16 MiB RAM + 1 vCPU and run to `HLT`. |
| `--pci-selftest` | Host-side PCI host-bridge + BAR-sizing self-test (no guest). |
| `--blk-selftest` | Host-side virtio-blk DISCARD/WRITE_ZEROES self-test (no guest). |
| `--pvh-info <vmlinux>` | Parse and print a kernel's PVH ELF-Note entry point. |
| `--pvh-run [flags] <vmlinux> [-- <cmdline>]` | Boot a microVM (the main mode). |
| `--restore <path> [flags]` | Resume a microVM from a snapshot file (instant resume). |

### `--pvh-run` flags

Parsed in `parse_pvh_args` (`main.rs:590`). Defaults and clamps are exact.

| Flag | Default | Range / behaviour |
|------|---------|-------------------|
| `--initrd <cpio>` | none | initramfs; memory-mapped and copied into guest RAM. |
| `--ram-mb <N>` | `256` | **Clamped to 128–3584.** The upper bound is hard: the PCI MMIO window opens at `0xE000_0000` (3584 MiB), so more contiguous RAM would collide with device BARs. |
| `--vcpus <N>` | `1` | **Clamped to 1–32.** BSP runs on the main thread; each AP gets its own host thread. |
| `--rng` | off | Add a virtio-rng device (`/dev/hwrng`). |
| `--net` | off | Add a virtio-net NIC. **Repeatable** — each `--net` appends a NIC; the NIC-scoped flags below modify the *most recent* NIC. |
| `--net-backend loopback\|nat\|wintun` | `nat` | Backend for the current NIC (see [§3](#3-devices-in-detail)). |
| `--portfwd HOSTPORT:GUESTPORT` | — | Forward `127.0.0.1:HOSTPORT` (host) → `10.0.0.2:GUESTPORT` (guest). NAT only. Repeatable per NIC. |
| `--wintun-name <adapter>` / `--wintun-host <ipv4>` | — | WinTun adapter name / host-side gateway IPv4 (wintun backend). |
| `--drive <path>[,readonly\|ro]` | — | Add a virtio-blk disk. **Repeatable up to 8** (`/dev/vda`, `/dev/vdb`, …). |
| `--virtio-9p-share <tag>=<host_dir>[,ro]` | — | Share a host directory over virtio-9p (9P2000.L). **Repeatable up to 8.** Tag 1–256 bytes; host path canonicalized and must be a directory; duplicate tags rejected. |
| `--gpu [WxH]` | off | Add a virtio-gpu 2D device and open a Win32 window showing its scanout (CPU blit). Optional `WxH` (e.g. `--gpu 1024x768`) sets the preferred size (default **1280×800**). Dropping `nofb nomodeset` from the default cmdline so the guest DRM driver mode-sets. With `--input`, the window is also the host input source. |
| `--input` | off | Add **two** virtio-input devices — a keyboard and an absolute tablet (pointer + scroll + buttons). With `--gpu`, the host source is the GPU window (1:1 pixel coordinates); otherwise it falls back to the interactive console. Needs a guest kernel with `CONFIG_VIRTIO_INPUT`. |
| `--cpu-affinity all\|p\|e\|p-physical` | `all` | Pin every vCPU thread to a CPU-set class (P/E cores via `EfficiencyClass`). |
| `--save <path>` | — | Arm snapshot-on-trigger: when the guest issues `CPUID(0x4000DE57)`, quiesce the machine, write `<path>`, and exit. |
| `--unsafe-save-mutable-drive` | off | Allow `--save` with a *writable* `--drive` attached (otherwise refused — the disk is not part of the snapshot, so a mutated disk would diverge from restored RAM). |
| `--watchdog-secs <N>` | `0` | `0` = run until stopped; else stop after N seconds, printing `io/cpuid/msr` exit counters each second. |
| `--debug-boot` | off | Prepend `earlyprintk=ttyS0,115200` so early boot streams to the 8250 UART before hvc0 is up. |
| `-- <cmdline>` | see below | Everything after a bare `--` becomes the kernel command line. |

**Default kernel cmdline** (`main.rs:842`): `console=hvc0 pci=conf1,nocrs,lastbus=0
nofb nomodeset` — routes the console to virtio-console (hvc0) so `/init` lands an
interactive shell and forces PCI Configuration-Mechanism-#1 access. With `--gpu`
the `nofb nomodeset` suffix is dropped so the guest's virtio-gpu DRM driver can
mode-set; with `--debug-boot` the `earlyprintk` prefix is added.

### `--restore` flags

The restore path (`main.rs:2001`) rebuilds the machine from the snapshot header
and accepts a small set of overrides:

| Flag | Behaviour |
|------|-----------|
| `--drive <path>[,ro\|rw]` | Re-attach disks (blk content is not in the snapshot, so the operator supplies the backing files in the same order). |
| `--unsafe-restore-mutable-drive` | Permit re-attaching a writable disk whose size differs from save time. |
| `--cpu-affinity …` / `--watchdog-secs N` | Same as `--pvh-run`. |

### Examples

```cmd
:: 4 vCPUs, 1 GiB, RNG, NAT with a port-forward, a disk, a host share, a GPU window + input
tinyvmm --pvh-run --vcpus 4 --ram-mb 1024 --rng ^
    --net --net-backend nat --portfwd 8080:80 ^
    --drive ubuntu.img --virtio-9p-share host=C:\work,ro ^
    --gpu 1280x800 --input ^
    --cpu-affinity p-physical --initrd initramfs.cpio vmlinux

:: snapshot on guest trigger, then instant-resume (disk re-attached read-only)
tinyvmm --pvh-run --save vm.snap --drive disk.img,ro --initrd initramfs.cpio vmlinux
tinyvmm --restore vm.snap --drive disk.img,ro
```

The text console forwards raw stdin to the virtio-console RX queue; **Ctrl+A then
X** quits. The guest can also request a clean shutdown by printing a sentinel on
hvc0, which a watcher thread detects to stop the VM.

---

## 3. Devices in detail

All paravirtual devices are **virtio 1.0 ("modern") over a virtio-pci transport**
(`src/virtio/transport.rs`) on a single PCI host bridge using Configuration
Mechanism #1 (ports `0xCF8/0xCFC`), with MSI-X interrupts. PCI vendor ID is
`0x1AF4`. BAR0 is a `0x4000`-byte MMIO region carved into common-cfg / ISR /
notify / device-cfg / MSI-X table+PBA windows. Devices occupy PCI slots in the
order they are created — that order is fixed (it is also the snapshot
`device_index`): **console(0) → net* → rng → blk* → input(keyboard, tablet) →
9p* → gpu(last)**.

| Device | Flag | Guest node | virtio ID | MSI-X | Doorbell |
|--------|------|-----------|-----------|-------|----------|
| virtio-console | always (hvc0) | `/dev/hvc0` | 3 | 3 (rx/tx/cfg) | yes |
| virtio-net | `--net` (×N) | `eth0…` | 1 | 3 (rx/tx/cfg) | yes |
| virtio-rng | `--rng` | `/dev/hwrng` | 4 | 2 (rq/cfg) | **no** (inline) |
| virtio-blk | `--drive` (×8) | `/dev/vd{a…}` | 2 | 2 (rq/cfg) | yes |
| virtio-input | `--input` | `/dev/input/event*` | 18 | 3 each | **no** (inline) |
| virtio-9p | `--virtio-9p-share` (×8) | `mount -t 9p` | 9 | 2 (rq/cfg) | yes |
| virtio-gpu | `--gpu` | `/dev/dri/card0`, `/dev/fb0` | 16 | 3 (ctrl/cursor/cfg) | **no** (inline) |

* **virtio-console** — always present so `/init` has a console.
* **virtio-net** — MAC `52:54:00:12:34:56`, `+1` in the last octet per extra NIC
  (`nic_mac`). Owns an RX and a TX virtqueue; backends decide what to do with
  guest TX frames and may inject RX frames.
* **virtio-rng** — fills each device-writable buffer from Windows CNG
  (`BCryptGenRandom` with the system-preferred RNG, `crates/winsys/src/host.rs:29`).
  The fill is pure CPU, so it runs **inline on the vCPU thread** — no doorbell.
* **virtio-blk** — async backend: one Win32 file opened `FILE_FLAG_OVERLAPPED`,
  bound to a per-disk IOCP with one worker thread. READ / WRITE / FLUSH plus a RO
  feature bit and DISCARD / WRITE_ZEROES (via `FSCTL_SET_ZERO_DATA` on a sparse
  NTFS file).
* **virtio-input** — `--input` adds two devices (`src/virtio/input.rs`): a
  **keyboard** and an **absolute tablet** (pointer motion, buttons, scroll
  wheel). Two queues each (`eventq=0`, `statusq=1`); the host injects events with
  `submit_frame(&[InputEvent])`, which appends an `EV_SYN`/`SYN_REPORT` and raises
  one IRQ per frame. Tablet absolute axes are `0..=ABS_AXIS_MAX` (`0x7fff`).
* **virtio-9p** — 9P2000.L file-share with a **concurrent worker-pool** engine
  (an IOCP used as a work queue + preallocated slots + up to 8 precreated
  workers), backed by Win32 file APIs through `winsys::fs`.
* **virtio-gpu** — basic 2D scanout (`src/virtio/gpu.rs`). Two queues
  (`controlq=0`, `cursorq=1`); single scanout (`NUM_SCANOUTS=1`); 32-bpp
  resources. It handles `GET_DISPLAY_INFO`, `RESOURCE_CREATE_2D` / `UNREF`,
  `SET_SCANOUT`, `RESOURCE_ATTACH`/`DETACH_BACKING`, `TRANSFER_TO_HOST_2D`, and
  `RESOURCE_FLUSH`; on flush it swizzles the bound resource to BGRA into a reused
  shadow buffer and presents it to a **Win32 GDI window** (`src/display.rs`) via a
  CPU blit.

**Legacy / emulated devices** (always present, for boot correctness only):

* **8250/16550 UART** at `0x3F8` — TX → host stdout; raises ISA IRQ4 through the
  PIC when the guest enables transmit interrupts (ETBEI). Used for `earlyprintk`.
* **i8259 PIC pair** at `0x20/0x21`, `0xA0/0xA1` — the only ISA-IRQ → guest-IDT
  path; injects vectors with `WHvRequestInterrupt`. Holds its mapping behind a
  `Mutex<Inner>` and a `Box<dyn Fn(u8,u32)->bool>` injection closure.
* **8254 PIT** at `0x40–0x43`, `0x61` — counters only; **IRQ0 intentionally not
  wired** (Linux uses the in-hypervisor LAPIC timer).
* **CMOS/RTC** at `0x70/0x71` returns a fixed `2024-01-01` wall clock; POST port
  `0x80` and port-A `0x92` are stubs (`src/devices/legacy.rs`).

The vCPU local APIC is emulated by WHP in **x2APIC mode**, and a minimal ACPI
surface (RSDP / XSDT / MADT with one x2APIC entry per vCPU, LAPIC at
`0xFEE0_0000`) is staged into guest RAM by `src/boot/acpi.rs` (`MAX_VCPUS = 32`).

### The GPU window & host input (`src/display.rs`)

`Display` owns a Win32 window on **its own message-pump thread**
(`WNDCLASSW` + `CreateWindowExW`, non-resizable, client area == scanout, 1:1
pixel mapping). `Display::present(bgra, w, h)` copies the frame into a shared
`Mutex<Frame>` and posts `WM_APP_PAINT`; the window thread draws it with
`StretchDIBits` from a top-down DIB. The window translates Win32 input messages
(`WM_KEYDOWN/UP`, `WM_MOUSEMOVE`, the button + wheel messages, focus/resize/close)
into a `WindowEvent` enum delivered through an installable
`InputSink = Box<dyn FnMut(WindowEvent) + Send>`. When both `--gpu` and `--input`
are present, `wire_window_input` routes those events into the keyboard/tablet
virtio-input devices (pointer pixels map straight onto the tablet's absolute
axes).

### virtio-net backends (`--net-backend`)

* **`loopback`** — TX frames echoed straight back as RX. No host networking.
* **`nat`** (default) — a **slirp-style user-mode NAT** in `src/net/nat.rs`: guest
  `10.0.0.2/24`, gateway `10.0.0.1` (MAC `02:53:54:00:00:01`). No admin rights, no
  virtual adapter. Implements **ARP**, local + proxied **ICMP echo** (`ping`
  works via an `IcmpSendEcho` helper-thread pool), **UDP** NAT (one connected host
  socket per 4-tuple), and **TCP** terminate-and-proxy (the guest-facing TCB is
  the `tcp-sans-io` crate; the host side dials out with `ConnectEx`). `--portfwd`
  adds inbound forwarding — the VMM originates a SYN toward the guest. A **single
  precreated worker thread** owns all flow state and a single IOCP.
* **`wintun`** — bridges onto a real WinTun L3 adapter (`wintun.dll` loaded at
  runtime via `GetProcAddress`; requires elevation to create the adapter).

### Doorbells — the "notify without a VM exit" path

The transport can install a **WHP MMIO doorbell**
(`WHvRegisterPartitionDoorbellEvent`, `crates/whpsys/src/doorbell.rs`) on each
queue-notify register. A guest *kick* then **signals an OS event instead of taking
a VM exit**; a per-device **pump thread** wakes and drives the normal
`notify_queue` path. Doorbells are enabled for **console, net, blk, and 9p** (a
hot notify path with a downstream worker) and left **off for rng, input, and gpu**
(low-rate; serviced inline on the vCPU thread). The pump waits `INFINITE` with
**no periodic sweep** (`SWEEP_MS = u32::MAX`): the virtqueue itself closes the
`EVENT_IDX` notification race (an Acquire re-read of `avail.idx` + a Release of
`avail_event` per drain), and any non-matching write still falls through to the
MMIO handler as a backstop.

---

## 4. Architecture & source layout

The repo is a **Cargo workspace**. All FFI is quarantined in two
separately-auditable crates; the binary keeps thin facade modules that re-export
from them so internal paths stay stable.

```
crates/
  winsys/      Win32 FFI ONLY (no WHP):
    error, host (privilege + large-page + CNG random), host/block_file (async
    IOCP disk), host/mapped_file (mmap loader), sock (Winsock + IOCP), etw
    (hand-rolled TraceLogging), fs (9p file ops), cpu_affinity, wintun
    (wintun.dll loader), qpc (QueryPerformanceCounter), ptr (SharedPtr)
  whpsys/      Windows Hypervisor Platform FFI ONLY:
    partition, memory (GuestMemory + typed accessors), vcpu (run loop + decoded
    exits + XSAVE/APIC save-restore), regs, msi, emulator (WHvEmulator* +
    EmulatorBus trait), doorbell
src/
  main.rs      CLI dispatch, device wiring, interactive console, save/restore
  display.rs   Win32 GDI window host for virtio-gpu + host-input seam
  boot/        acpi (RSDP/XSDT/MADT), loader (PVH ELF + hvm_start_info + e820)
  devices/     io_bus, mmio_bus, serial(8250), pic(i8259), pit(8254), legacy
  pci/         config (Type-0 space), bus (0xCF8/0xCFC), msix
  virtio/      queue, device(trait), transport(virtio-pci modern),
               console, net, rng, blk, p9, input, gpu
  net/         wire (parse/build), nat (user-mode NAT), wintun, sys (facade)
  whp/         run_loop, cpuid, hv (Hyper-V enlightenment),
               snapshot + snapshot_file + vcpu_state (save/restore)
  diag/        boot_timer, etw (facade), alloc_trace (global-allocator ETW shim)
```

The whole point of the split: **`unsafe` lives in `winsys`/`whpsys`** (raw
Win32/WHP calls) plus a short list of audited hot-path device structs. The
`pci/`, `devices/`, `boot/`, `virtio/queue`, and `net/wire` logic is essentially
`unsafe`-free.

### The device traits (4 public + 1 private)

| Trait | Defined in | Role |
|-------|-----------|------|
| `VirtioDevice: Send + Sync` | `src/virtio/device.rs:25` | console/net/rng/blk/9p/input/gpu, each behind one `Arc<dyn VirtioDevice>` the transport drives (feature negotiation, queue lifecycle, notify, plus four save/restore hooks). |
| `PciFunction: Send + Sync` | `src/pci/mod.rs:82` | anything the PCI bus enumerates (the transports): config read/write, BAR layout/assign. |
| `NetBackend: Send + Sync` | `src/virtio/net.rs:37` | loopback / nat / wintun data-plane peers: `on_guest_frame(&[u8])` + `stop()`. |
| `EmulatorBus` | `crates/whpsys/src/emulator.rs:41` | the run loop's IO/MMIO dispatch handed to the WHP instruction emulator. |
| `TcbDyn` (private) | `src/net/nat.rs` | an object-safe wrapper so the NAT can store the `tcp-sans-io` generic TCB as `Box<dyn TcbDyn>` per flow. |

Cost of `dyn` dispatch: one indirect call per kick — negligible next to the VM
exit it replaces.

---

## 5. Safety model — where `unsafe` lives and how it is bounded

`unsafe` is **not** spread evenly; the distribution *is* the story. Raw textual
occurrences across the whole tree:

```
unsafe (keyword, total)        ~347
  ├─ unsafe { … } blocks        266   raw OS / guest-RAM calls
  ├─ unsafe extern "system"      18   FFI callbacks (WHP emulator, ETW, IOCP, wndproc)
  ├─ unsafe fn                   11   the few caller-unsafe async primitives
  ├─ unsafe impl Send            19   pools + FFI handle wrappers (see below)
  └─ unsafe impl Sync             8
```

They cluster in the FFI crates (`winsys::fs`, `winsys::sock`, `winsys::wintun`,
`crates/whpsys/src/{vcpu,memory,emulator}.rs`, `winsys/host/block_file.rs`) and a
handful of audited device structs (`net/nat.rs`, `virtio/blk.rs`, `virtio/p9.rs`,
`virtio/queue.rs`, `display.rs`). The protocol logic — `pci/*`, `devices/*`,
`boot/*`, `net/wire.rs`, the virtqueue traversal, and the gpu/input command
decoders — is safe.

### The idiom: a *little* `unsafe` to get a pointer, then slices — never pointer math

**Every** guest-RAM access funnels through one audited module,
`crates/whpsys/src/memory.rs`, whose own comment states the doctrine:

> *These concentrate ALL of the guest-RAM raw-pointer access into this one
> audited place: every method bounds-checks the `[gpa, gpa+N)` range via
> `host_range` and then performs a single small `copy_nonoverlapping` to/from a
> stack buffer. Callers (the virtqueue, devices) use them with NO `unsafe`.*

The bounds check is written in **subtraction form** so a near-`u64::MAX` guest
address cannot wrap the bound (`memory.rs:139`):

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
fixed-size array, a slice, or an `AtomicU16`. Two distinct kinds of access live
here, and the distinction drives the performance story in [§6](#6-performance-model--allocation-pinned-buffers-hot-path-overhead):

* **Copying accessors** (`read_array::<N>` / `read_into` / `write_bytes` /
  `read_u*` / `load_acquire_u16` / `store_release_u16`) do a small fixed
  `copy_nonoverlapping` to/from a **stack** buffer. They are used **only for ring
  metadata** — the 16-byte descriptors and the 2/8-byte ring indices — whose
  guest-controlled addresses make an in-place typed read an alignment hazard.
* **The pointer accessor** (`host_range`) is used for **bulk data buffers**: it
  returns a validated pointer the device operates on *in place* (disk DMA, rng
  fill, the status byte, gpu backing pages), so guest *data* is never copied
  through a host staging buffer by this layer.

The virtqueue popper is explicit about this: it reads each 16-byte descriptor
with `read_array::<16>()` and notes *"individual descriptors are then read with
bounds-checked `read_array` (no raw pointer math)"* (`src/virtio/queue.rs`). The
only raw `*mut u8` that escape live in `ChainBuf { ptr, len, write }`, wrapped
with `as_slice()` / `as_mut_slice()` at the point of use.

### `SharedPtr<T>`: localizing the `unsafe impl Send`

A C programmer would slap `unsafe impl Send for BigStruct {}` on anything holding
a raw pointer. This project refuses to, because that blanket assertion *also*
silently vouches for every other field. Instead the one offending pointer is
wrapped in a `#[repr(transparent)]` newtype (`crates/winsys/src/ptr.rs`):

```rust
#[repr(transparent)]
pub struct SharedPtr<T>(pub *mut T);
unsafe impl<T> Send for SharedPtr<T> {}
unsafe impl<T> Sync for SharedPtr<T> {}
```

Now the containing struct (`GuestMemory`, `Emulator`, …) **auto-derives**
`Send`/`Sync`, compiler-checked. If someone later adds an `Rc` to that struct, the
build breaks loudly instead of being waved through. This is the preferred
pattern; the remaining hand-written `unsafe impl Send/Sync` (**19** `Send`, **8**
`Sync`) are confined to the pools and FFI handle wrappers, each with the external
invariant documented inline — e.g. `Doorbell` (*"the only raw field is a
manual-reset OS event HANDLE … only ever waited on by the pump thread, joined
before drop"*), `BlkReq` (*"ownership of a request is handed off linearly … no two
threads touch the same BlkReq concurrently"*), and the 9p `SlotPool`.

### Panics & `.unwrap()` — setup-only, never guest-reachable

`panic!(` appears **exactly 4 times**, all at *configuration* time:

* `src/devices/io_bus.rs:43` and `src/devices/mmio_bus.rs:43` — a device
  registered over an already-claimed port/GPA range (a wiring bug).
* `src/pci/bus.rs:46` — `"PciBus: ran out of MMIO BAR window"`.
* `src/pci/bus.rs:53` — `"PciBus: IO BARs not supported in phase 2"`.

`.expect(` appears **6 times** — in the `--blk-selftest`/`--pci-selftest`
harnesses and when a device engine creates its IOCP at startup
(`src/virtio/p9.rs`). **No guest action reaches a panic or an `.expect()`**: the
guest-facing paths return `Option` / `bool` / an error status byte. A malformed
virtio descriptor is dropped or answered `BLK_S_IOERR`; an out-of-range gpa
returns `None`; a bad 9p path returns an errno; an out-of-range gpu resource id is
rejected. See [§9](#9-hostile-guest-hardening).

> ⚠️ **The one residual abort surface** is `Mutex::lock().unwrap()` — most of the
> **336** `.unwrap()`s. With `panic = "abort"`, a *poisoned* mutex aborts the
> process. Poisoning only happens if a thread already panicked while holding the
> lock, and the lock-holding critical sections do not panic on guest input — so in
> practice this is a "should never happen" assertion, not a guest-triggerable
> crash.

---

## 6. Performance model — allocation, pinned buffers, hot-path overhead

Guiding principle: **optimize the number of VM exits, not the host-side handler
code.** Under CPU profiling the VMM's own code is at noise level; the cost is the
hypervisor round-trip and Windows kernel I/O. So doorbells and the async backends
exist to *remove exits*, and the data planes are allocation-free so the
malloc-free hot path never stalls.

### Where it allocates — and where it deliberately does not

| Path | Allocation behaviour |
|------|----------------------|
| Boot / device setup | Allocates freely (`Vec`/`String`/`Box`). One-time. |
| Kernel + initramfs load | **Memory-mapped** (`MapViewOfFile`) and copied straight into guest RAM via `GuestMemory::write_at` — *no* read-into-`Vec`. The mappings are dropped right after (`src/boot/loader.rs`, wired at `main.rs:980`). |
| virtio TX/RX, blk submit+complete, 9p dispatch, input frames, gpu present | **Zero heap allocation on the steady-state hot path** — preallocated pools and reused scratch buffers (below). |
| NAT cold paths (ARP, ICMP/ping, RST, new-flow creation) | Still allocate (`Box<UdpOp>`, `Box<TcpOp>`, `Box<dyn TcbDyn>`, an ICMP `to_vec()`). Rare, not worth pooling. |
| gpu resource lifecycle (`RESOURCE_CREATE_2D`, attach-backing) | Allocates the per-resource pixel store + SG list once per resource (a control-plane op), not per frame. |

### The preallocated pools (the "partitioned memory" a systems programmer expects)

| Pool | Where | Backing | Free-list | Sizing |
|------|-------|---------|-----------|--------|
| **FramePool** (guest-TX frames) | `src/net/nat.rs` | `Box<[FrameSlot]>`, each `#[repr(C)]` with a `UnsafeCell<[u8; 2048]>` body | **lock-free Treiber stack**, ABA-guarded by a tag in the high 32 bits of an `AtomicU64`, `compare_exchange_weak` | `POOL_SLOTS = 1024` |
| **RxPool** (inbound frames) | `src/virtio/net.rs` | `Vec<[u8; 2048]>` | `Vec<u32>` index free-list, under the device mutex | `RX_POOL_SLOTS = 512` |
| **ReqPool** (in-flight blk requests) | `src/virtio/blk.rs` | `Vec<Box<BlkReq>>` | `Vec<u16>` | virtqueue depth |
| **SlotPool** (in-flight 9p requests) | `src/virtio/p9.rs` | `Vec<UnsafeCell<P9Slot>>` | `Mutex<Vec<u16>>` + precreated workers | `P9_QUEUE_MAX = 128` |

Plus **reused scratch buffers** with no per-event allocation: the virtqueue's
`pop_into(&mut PoppedChain)` reuses its `bufs` `Vec`; blk and 9p hold the
`PoppedChain` inside a `Mutex<ChainScratch>` (`drain_chain`); virtio-net keeps a
`TxScratch { frame, chain }`; the NAT keeps `tx_scratch`/`l3_scratch` `Vec`s the
`build_*_into` wire helpers write into; **virtio-input** reuses an `event_scratch`
/ `status_scratch` and builds its config image into a fixed `[u8; 8+128]` stack
buffer; **virtio-gpu** reuses a single `present_buf: Vec<u8>` BGRA shadow (resized
once, reused every flush) and reused `req`/`resp` buffers.

### Pinned / address-stable buffers for async IOCP

The async block backend (`crates/winsys/src/host/block_file.rs`) overlaps
`ReadFile`/`WriteFile` on a per-disk IOCP. Overlapped I/O requires the
`OVERLAPPED` and its buffer to **stay put** until completion. Two deliberate
choices make that safe without a GC or a pinning API:

1. **`OVERLAPPED` is the first field of a `#[repr(C)]` request struct.** The
   worker recovers the whole request from the completion's `OVERLAPPED*` by a
   pointer cast — `OVERLAPPED* == Request* == BlkReq*`, all three addresses
   coincide:

   ```rust
   #[repr(C)]
   pub struct Request { pub ovl: OVERLAPPED, pub op: Op, /* … */ pub buf: *mut u8, pub bytes: u32 }
   ```

2. **The request slots are `Box`ed and pooled** so their addresses are stable for
   the slab's lifetime. The `ReqPool` comment: *"Box (not inline) is REQUIRED:
   each slot's address is handed to the IOCP backend as the completion context and
   must stay stable; `Vec<BlkReq>` would move slots on realloc."*

At most **one segment per request is in flight**; the next is submitted from the
completion. The NAT applies the same "one send in flight, next posted from
completion" discipline to TCP.

### "If you were OK with `unsafe`, what does the safe version cost you?" — per-hot-event overhead

The tax the safety model adds versus a C VMM that derefs guest pointers directly:

* **Per queue kick (doorbell path):** an OS-event wake on the pump thread +
  `ResetEvent` + **one `Mutex<Virtqueue>` lock/unlock** per drain (uncontested in
  steady state, ~10–20 ns). The win dwarfs it: a kick costs **0 VM exits** instead
  of one (microseconds of hypervisor round-trip).
* **Per descriptor decode (control-plane only):** a bounds check (2–3 branches in
  `host_range`) + a **16-byte** `copy_nonoverlapping` of the *descriptor itself*
  into a stack `[u8; 16]` — a const-generic local returned by value, **no heap
  allocation**. The stack copy (vs a typed in-place read) is for **alignment
  safety**: the guest controls the descriptor-table address. Every `next` index
  (direct *and* indirect) is re-validated `< size` to bound a malicious chain.
* **Per data buffer — ZERO copy.** The bulk payload a descriptor points at is
  **never** staged through a host buffer by the safety layer: virtio-blk sets
  `req.buf = seg_ptr` and lets `ReadFile`/`WriteFile` DMA **straight into/out of
  guest RAM**; virtio-rng fills the guest-writable buffer in place; the status
  byte is written through `*status_ptr`. A megabyte disk read copies **zero**
  bytes host-side beyond the OS page cache.
* **Per guest TX frame (net):** **two CAS** on the lock-free FramePool, then an
  IOCP post — no allocation, no lock, fully concurrent across vCPUs. virtio-net is
  the one device that *gathers* a multi-descriptor chain into a reused contiguous
  scratch `frame` (a NIC backend wants one `&[u8]`) — a protocol requirement, not
  a per-guest-touch safety tax.
* **Per inbound RX frame (net):** RX is the mirror — bytes are *placed into* the
  guest's RX descriptors (inherent to any NIC), plus one **ownership-boundary**
  staging copy into a pooled 2 KiB slot (under `Mutex<RxPool>`) so the network
  thread is decoupled from the vCPU/pump.
* **Per host input event (gpu+input):** the window's `InputSink` runs on the
  message-pump thread and reuses the device's `event_scratch`, so a steady input
  stream allocates nothing after warm-up; one IRQ per `submit_frame`.
* **Per gpu flush:** swizzle the bound resource into the reused `present_buf` BGRA
  shadow, then a single CPU blit (`StretchDIBits`) on the window thread — no
  per-frame allocation.

**Honest summary:** guest *data* is zero-copy — disk bytes DMA directly in/out of
guest RAM and rng/status writes land in place. The only fixed memcpy the safety
model imposes is **control-plane** (a 16-byte descriptor plus 2/8-byte indices to
the stack, for alignment safety) plus **one uncontended mutex per drain**. The TX
gather, RX delivery+staging, and the gpu BGRA swizzle belong to the
NIC/display protocol, not to the guest-memory-access layer.

### Measured throughput (representative, reference machine)

| Workload | Result |
|----------|--------|
| virtio-blk single-stream read | ~533 MB/s (guest pipelines ~14 requests in flight) |
| virtio-9p single-stream read | ~16 MB/s (request-response latency-bound) |
| virtio-9p concurrent (32 readers) | ~190 MB/s (ceiling = one submit pump + the per-queue `Mutex<Virtqueue>`) |
| virtio-net guest→host | 20 MB transfer at line rate with the pump's periodic sweep disabled |

---

## 7. Rust features for systems programmers (with a histogram)

If you build "actual homes for low-level programming" — fixed sizes,
preallocation, explicit ownership — here is the Rust feature that does each job,
how often it appears, and the C analogue. Counts are **raw occurrences** measured
across the current tree (`src/` + `crates/`, 64 files).

```
unsafe (keyword)        347  ████████████████████████████████  FFI + audited hot paths
.unwrap()               336  ███████████████████████████████  mostly Mutex::lock; see §5
Atomic* types           207  ███████████████████  lock-free counters / flags / state
Arc<T>                  167  ███████████████  shared ownership across host threads
dyn Trait                61  ██████  the device traits, vtable dispatch
OnceLock<T>              55  █████  set-once globals & handles (lock-free reads)
Mutex<T>                 52  █████  cross-thread device state
Box<T>                   42  ████  heap-stable / trait objects / callbacks
unsafe impl Send         19  ██  pools + FFI handle wrappers
impl Drop                16  █▌ RAII teardown (handles, mappings, threads)
transmute                12  █▌ OS-symbol → typed-fn-pointer casts (FFI crates only)
UnsafeCell<T>             8  █  interior mutability in 2 pools (frame, 9p slot)
#[repr(C)]                8  █  ABI-stable structs at the FFI boundary
unsafe impl Sync          8  █
from_raw_parts            6  ▌  the slice materializers
Weak<T>                   6  ▌  break the device↔transport Arc cycle
panic!                    4  ▌  setup-time invariants only
trait (defined)           5  ▌  4 public device traits + private TcbDyn
Condvar                   3  ▌  the NAT ICMP bounded handoff
RwLock<T>                 1  ▏  the read-mostly MMIO dispatch table (one site)
Rc / RefCell / Cow /      0     ← deliberately ABSENT (see below)
Pin / PhantomData /
static mut / Box::leak
```

### What each feature is doing here

* **`Arc<T>` (167)** — shared, refcounted, thread-safe ownership. Guest RAM, the
  vCPUs, the HV enlightenment, every device, every backend, and the display are
  `Arc`-shared because multiple host threads (vCPUs, doorbell pumps, IOCP workers,
  the 9p pool, the NAT worker, the window thread, the watchdog) hold them at once.
  This is the C "shared object with a refcount" pattern, but the refcount is
  correct by construction.
* **`Weak<T>` (6) + `Arc::downgrade`** — breaks a **reference cycle**: the
  transport owns the device via `Arc`, and the device's interrupt/completion
  closure points *back* (e.g. virtio-blk's IOCP completion upgrades a
  `Weak<BlockDevice>` so the backend doesn't keep the device alive). A C
  programmer would use a raw back-pointer; `Weak` makes "might be gone" explicit
  and the `upgrade()` checked.
* **`Atomic*` (207) + `OnceLock` (55)** — how the project does **global and shared
  mutable state without `static mut`**. Counters (per-vCPU exit tallies, blk/gpu
  op stats), flags (`driver_ok`, the snapshot `ARMED`/`REQUESTED`), and the ETW
  enable/level/keyword cache are atomics. Set-once handles and caches — the IRQ /
  present callbacks, the cached TSC Hz, the ETW provider-metadata blob, the CRC32
  table, the cached large-page size — use `OnceLock`, whose `get()` is a single
  Acquire load after one `set()` (vs a `Mutex`'s two futex RMWs). This is the C
  "global, written once at init, read forever" idiom, proven race-free.
* **`UnsafeCell<T>` (8)** — interior mutability *without* a lock, used in exactly
  two pools (the NAT `FrameSlot` body and the 9p `P9Slot`). The slot's bytes are
  mutated through a raw pointer while the **free-list / IOCP guarantees exclusive
  ownership** between acquire and release. `UnsafeCell` is the *only* legal way to
  tell the compiler "nobody else touches this slot right now", documented at each
  site.
* **`Mutex<T>` (52) / `RwLock` (1) / `Condvar` (3)** — see
  [§8](#8-concurrency-every-lock-and-why-it-exists). Yes, there are locks even
  though memory is preallocated — be suspicious, then read §8 for what each one
  serializes (host threads, never the guest).
* **`Box<T>` (42)** — heap-stable addresses for IOCP completion contexts
  (`Box<BlkReq>`), trait objects (`Box<dyn Fn>` IRQ / present / input-sink
  callbacks, `Box<dyn TcbDyn>` per TCP flow), and the PIC's injection closure. The
  NAT also moves ownership of small op structs through the IOCP with
  `Box::into_raw` (×2) → `Box::from_raw` (×4).
* **`impl Drop` (16)** — **RAII** releases every OS resource: `GuestMemory`
  (`WHvUnmapGpaRange` + `VirtualFree`), `Vcpu`/`Partition`/`Emulator`/`Doorbell`
  (WHP handle delete + event close), `BlockFile`/`Inner` (`CloseHandle` of the
  file + IOCP), `MappedFile` (`UnmapViewOfFile`), `PciTransport` (tear down the
  doorbell pump + join), the `Display` window thread, and `SnapshotWriter` (delete
  a half-written file). Teardown order is explicit in `main.rs` — IOCP workers are
  quiesced *before* their owners drop, so no completion lands on freed memory.
* **`#[repr(C)]` (8) + `transmute` (12)** — ABI control at the FFI line. `repr(C)`
  guarantees field order for the `OVERLAPPED`-first request structs and the NAT
  frame slot. Every `transmute` turns an OS-resolved symbol into a typed function
  pointer — the `wintun.dll` entry points (via `GetProcAddress`) and Winsock's
  `ConnectEx` (via `WSAIoctl`/`SIO_GET_EXTENSION_FUNCTION_POINTER`). All 12 live in
  the FFI crates; `src/` contains none.
* **`trait` + `dyn` (5 traits / 61 uses)** — vtable dispatch for the device model.
* **Deliberately ABSENT (all `0`):** **`Rc`/`RefCell`** (single-threaded interior
  mutability) have no place in a multi-threaded VMM — everything shared is `Arc` +
  atomics/`Mutex`/`UnsafeCell`. **`Pin`/`PhantomData`** aren't needed because there
  is no self-referential `async` state machine (the runtime is a hand-rolled IOCP
  loop, not `Future`s). **`static mut`** is replaced by atomics and `OnceLock`.
  **`Cow`** is unused because the hot paths reuse fixed buffers. **`Box::leak`** is
  unused — see the next note for how process-lifetime data is handled instead.

### The "deliberate leak" (process-lifetime statics) & raw ownership handoff

* **Process-lifetime `OnceLock` statics are never freed — on purpose.** The ETW
  provider-metadata `Vec<u8>`, the CRC32 table `[u32; 256]`, the cached TSC Hz, and
  the cached large-page size are set once and read for the whole run. They are
  effectively *leaked deliberately*: there is exactly one of each, and reclaiming
  it at exit would be pure ceremony (`panic = "abort"` means there is no unwinding
  teardown anyway). This is the safe analogue of a C file-scope `static` you never
  `free`.
* **Raw ownership handoff across the IOCP** uses `Box::into_raw` → `Box::from_raw`,
  which is **not** a leak: the NAT boxes an op, posts the raw pointer through
  `PostQueuedCompletionStatus`, and the worker *reclaims* it with `Box::from_raw`
  on the other side. Ownership moves through the OS queue exactly once — no
  aliasing, no double free. (The `Display` window passes its shared state to the
  wndproc the same way, but via `GWLP_USERDATA` holding an `Arc` pointer rather
  than a leaked `Box`.)

---

## 8. Concurrency: every lock, and why it exists

A systems programmer sees "preallocated, partitioned buffers" and rightly asks
*why are there locks at all?* Because **multiple host threads** touch shared
device state: the vCPU threads (one per `--vcpus`), the per-device **doorbell
pump** threads, the per-disk **IOCP worker** threads, the **9p worker pool**, the
NAT worker + its ICMP helpers, the **display window** message-pump thread, and the
watchdog. The locks serialize *host-thread* access; they are **not** about the
guest. Where single-ownership can be proven instead, there is no lock (the Treiber
free-list, the `OnceLock` callbacks, the `UnsafeCell` slot bodies).

| Lock | Guards | Who contends | Why it is not lock-free |
|------|--------|--------------|-------------------------|
| `Mutex<Virtqueue>` (per queue, every device) | desc/avail/used ring cursors | the vCPU (MMIO fallback) **and** the pump / IOCP / 9p worker that drains+retires | the head/tail advance + used-ring publish must be atomic as a unit |
| `Mutex<ReqPool>` (blk) | in-flight slot free-list | submit (pump) vs completion (IOCP worker) | tiny critical section; a CAS stack was unnecessary at this depth |
| `Mutex<ChainScratch>` `drain_chain` (blk, 9p, gpu) | the reused popped-chain scratch | rare concurrent drains | serializes drains without extending the queue-lock hold time |
| `Mutex<RxPool>` + `Mutex<TxScratch>` (net) | RX slot pool + reused TX scratch | the backend worker injecting vs the vCPU/pump draining | hand-off boundary between the network thread and the device |
| transport mutexes (`Common`, `PciConfigSpace`, `Option<DoorbellState>`) | virtio common-cfg, PCI config space, the live doorbell set | vCPU MMIO writes vs BAR (un)map vs pump lifecycle | a config write mutates several fields consistently |
| 9p `Mutex<Fids>` + `SlotPool` free-list `Mutex<Vec<u16>>` | the open fid→handle map; free slot indices | the 9p workers running concurrent reads/writes | a shared mutable map + index pool across the pool |
| gpu `Mutex<GpuState>` + queue/scratch mutexes | resources map, scanout, present shadow | the vCPU draining controlq vs the present path | resource table + scanout mutate together |
| input `Mutex<Virtqueue>` + `Mutex<ChainScratch>` (event/status) | eventq/statusq + reused scratch | the window thread injecting vs the vCPU | host-event injection vs guest kicks |
| display `Mutex<Frame>` + `Mutex<Option<InputSink>>` | the shared BGRA frame; the installed input sink | `present()` (vCPU/gpu) vs the window thread's `WM_PAINT` | the frame buffer is produced and consumed on different threads |
| NAT `Mutex<VecDeque<IcmpJob>>` + `Condvar` | the bounded ping handoff queue | the vCPU enqueues, helper threads dequeue | classic bounded producer/consumer |
| `RwLock<Vec<Entry>>` (MMIO bus, **the single site**) | the GPA→device dispatch table | written once at setup, read on every MMIO | read-mostly; readers never block readers |
| `OnceLock` (IRQ / present callbacks, backends) | set-once handles | the setup writer, then lock-free readers | **not a lock in steady state** — `get()` is a plain Acquire load |

**Lock-free** where ownership *is* provable: the NAT **FramePool** Treiber
free-list (ABA-guarded `AtomicU64`), every **atomic counter/flag**, and the
**`UnsafeCell` slot bodies** (exclusive between acquire and release).

---

## 9. Hostile-guest hardening

The guest is **untrusted**. Hardening is the validation layer, kept separate from
the locking story above.

* **Guest RAM:** every translation goes through `host_range()` with the wrap-safe
  subtraction check ([§5](#5-safety-model--where-unsafe-lives-and-how-it-is-bounded));
  out-of-range returns `None` and the access is dropped.
* **Virtqueue (`src/virtio/queue.rs`):** the avail-ring head is rejected if
  `>= size`; the descriptor table is validated mapped before traversal; the chain
  walk is **bounded by `size`** and every `next` index — direct *and* indirect — is
  checked `< size` / `< inner_count`, so a cyclic or oversized chain can neither
  loop nor run off the ring.
* **virtio-blk (`src/virtio/blk.rs`):** requires ≥ header+status descriptors, a
  device-readable header ≥ 16 B and a device-writable status ≥ 1 B; rejects an
  out-of-range sector **before** the `sector * 512` multiply (and bounds each
  segment against the file with a subtraction-form check); DISCARD/WRITE_ZEROES
  totals must be a multiple of 16 and within range. Bad requests get a status byte,
  never a panic.
* **virtio-gpu (`src/virtio/gpu.rs`):** resource IDs are checked before lookup;
  geometry is capped at `MAX_DIM`; scanout id and rectangle are bounds-checked;
  `RESOURCE_ATTACH_BACKING` caps the SG-entry count and validates the request
  length before parsing; `read_backing()` fails if the SG list does not fully cover
  the transfer. Malformed commands are answered with an error response, not a
  panic.
* **virtio-input (`src/virtio/input.rs`):** config select/subselect indices are
  range-checked; `InputEvent::decode` is only fed the fixed 8-byte records the
  driver path produces; the host-event hot path bounds the absolute axes to
  `0..=ABS_AXIS_MAX`.
* **PCI (`src/pci/config.rs`, `src/pci/msix.rs`):** config reads/writes bounded by
  `CFG_SPACE_SIZE` (out-of-range reads return all-ones, writes ignored); BAR writes
  masked to the BAR size; MSI-X table/PBA access checks 4-byte alignment and
  `vec < num_vectors`; `trigger()` refuses `vector >= num_vectors`.
* **virtio-9p path security (`src/virtio/p9.rs`):** the share root is canonicalized
  once; each path component is checked by `is_safe_name_component` — rejecting
  empty / `.` / `..`, length > 255, control chars `< 0x20`, the separators and
  Win32 metacharacters `/ \ : * ? " < > |`, a trailing dot or space, and the
  reserved DOS names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`).
  `.`/`..` in a `Twalk` are resolved with **clamp-to-root**; a lexical containment
  check is the backstop; all Win32 calls go through `\\?\` long paths. Read-only
  shares reject writes with `EROFS`.
* **Backpressure, not unbounded buffering:** the NAT's per-flow guest→host queue
  caps at `TO_HOST_CAP = 64 KiB` (closing the guest TCP window); the net RX pool
  **drops** inbound frames when the guest is not draining; the ICMP handoff queue
  is bounded.

---

## 10. ETW diagnostics

Built-in **ETW TraceLogging** for low-overhead, out-of-process tracing
(`crates/winsys/src/etw.rs`). The TraceLogging metadata blob is **hand-rolled** so
there is **no extra dependency** — just the raw `EventRegister` /
`EventWriteTransfer` APIs already in `windows-sys`.

* **Provider:** `Tinyvmm-Core`, GUID `{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}`,
  TraceLogging channel 11.
* **Levels:** `CRITICAL`(1) … `VERBOSE`(5). **Keywords** (bitmask): `VMEXIT`,
  `DOORBELL`, `VIRTIO`, `NET`, `MMIO`, `IO`, `BOOT`, `LIFECYCLE`, `BLOCK`,
  `CPUID`, `MSI`, and `HEAP`(0x800, Rust-only allocation tracing).
* **Hot-path gate:** an enable callback caches the session's level + keyword mask
  in atomics, so a disabled event costs a **single relaxed atomic check**
  (`enabled()` = `lvl != 0 && level <= lvl && (keyword & EN_KW) != 0`) — no API
  call, no allocation.
* **`Event` is stack-only:** field methods write into fixed `[u8; 256]` /
  `[u8; 512]` arrays, then `write()` hands the descriptors to
  `EventWriteTransfer`. Because it never routes back through Rust's allocator, it
  is safe to call from inside the global-allocator hook.
* **Allocation tracing:** `src/diag/alloc_trace.rs` installs a
  `#[global_allocator]` (`TracingAllocator`) that wraps `System` and emits a
  `HeapAlloc` / `HeapRealloc` / `HeapFree` event under the `HEAP` keyword at
  `VERBOSE`. With per-event stack walking you get the call stack of *every*
  allocation — that is how the hot-path "alloc-free" claims in §6 were verified.

Capture, e.g.:

```text
logman start tinyvmm -p "{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}" 0xFFFF 5 -ets -o trace.etl
... run tinyvmm ...
logman stop tinyvmm -ets

:: per-allocation walked stacks (HEAP keyword 0x800, VERBOSE level 5):
xperf -start tinyheap -on {0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}:0x800:5:'stack' -f heap.etl
```

Open the `.etl` in WPA / PerfView, or `tracerpt … -of csv`. A ready-made WPR
profile lives at `tools/tinyvmm.wprp`.

---

## 11. VM exits & counters

The exit loop is `crates/whpsys/src/vcpu.rs` (`run_exit` → a decoded `Exit`) and
`src/whp/run_loop.rs` (dispatch). WHP is told to take **extended exits** for
**CPUID and MSR** (`Partition::enable_extended_exits(true, true, false)`,
`main.rs:948`); IO and MMIO exit by hardware necessity; the rest are handled
in-hypervisor.

`ExitReason` is decoded into a small enum the loop acts on: `Halt`, `IoPort`,
`Memory` (MMIO), `Cpuid`, `Msr`, `InterruptWindow`, `ApicEoi`, `Canceled`,
`Other(u32)`. Each non-trivial reason bumps a per-run-loop counter (`Counters`:
six `AtomicU64` — `io`, `mmio`, `halt`, `cpuid`, `msr`, `other`):

* **IoPort / Memory** → routed through the WHP instruction emulator
  (`Emulator::try_io` / `try_mmio`) into the IO/MMIO device buses.
* **Cpuid** → the magic snapshot leaf is intercepted first ([§13](#13-save--restore)),
  otherwise `resolve_cpuid` applies the static result list (including the Hyper-V
  leaves `0x4000_0000..0x4000_0006`).
* **Msr** → handled by the Hyper-V enlightenment (`src/whp/hv.rs`): the hypercall
  page, Reference-TSC page, `GUEST_OS_ID`, `VP_INDEX`, the TSC-invariant control,
  etc. An unhandled MSR injects `#GP(0)` rather than crashing.
* **Halt** with interrupts enabled just resumes; HLT with `IF=0` is terminal.

**Why doorbells matter to the counters:** a queue notify that hits a doorbell
([§3](#3-devices-in-detail)) signals an OS event and takes **0 VM exits**. The
residual `io`/`mmio` counts are device *config / setup* traffic, not the hot
notify path.

**Two places report counters** (this explains an apparent mismatch):

* The `--watchdog-secs` thread prints the **sum across all vCPUs** every second:
  `[pvh-run] @Ns io=… cpuid=… msr=…`.
* Teardown prints only the **BSP** (vCPU 0): `exits[io=… mmio=… cpuid=… msr=…
  halt=… other=…]`.

Measured (`--rng`, 4 vCPUs, 1 GiB; see §12): the watchdog reported `io=1107` (all
four vCPUs) while teardown reported the BSP's `io=775 mmio=16 cpuid=486 msr=15
halt=0 other=0`. With a single vCPU the two agree by definition.

---

## 12. Boot trace (measured)

`src/diag/boot_timer.rs` records QPC waypoints and prints `[boot] <total> ms
(+<delta> ms) <phase>` to stderr (and an ETW `BootMark` per phase). The marks
(`pvh-run start`, `WHP probe done`, `guest RAM mapped`, `vmlinux+initramfs
loaded`, `entering guest`, `guest exited`, `teardown done`) cover **host-side
setup**; the guest's own boot (kernel → `/init`) runs between `entering guest` and
the hvc0 shell. **These numbers are machine-specific** (reference: an Intel
i9-14900K-class host, `tsc_hz ≈ 3.187 GHz`, large pages enabled) but the *shape*
is the point.

**Default config — 256 MiB, 1 vCPU:**

```
[boot]    0.000 ms (+  0.000 ms) pvh-run start
[boot]    0.714 ms (+  0.714 ms) WHP probe done
[boot]   58.767 ms (+ 58.053 ms) guest RAM mapped
[boot]   71.698 ms (+ 12.931 ms) vmlinux+initramfs loaded
[boot]   72.446 ms (+  0.749 ms) entering guest
...guest kernel boots, /init runs, drops to hvc0 shell (well within 1 s)...
[pvh-run] stopped: reason=Cancelled uart_tx=0 \
          exits[io=657 mmio=117 cpuid=486 msr=15 halt=0 other=0]
```

**Larger config — 1 GiB, 4 vCPUs, `--rng`:**

```
[boot]    0.000 ms (+  0.000 ms) pvh-run start
[boot]    0.750 ms (+  0.750 ms) WHP probe done
[boot]   70.916 ms (+ 70.165 ms) guest RAM mapped
[boot]  105.070 ms (+ 34.154 ms) vmlinux+initramfs loaded
[boot]  107.382 ms (+  2.312 ms) entering guest
```

Reading it:

* **WHP probe** is sub-millisecond.
* **guest RAM mapped** dominates host setup and **scales with RAM size** — ~59 ms
  to commit + map 256 MiB, ~70 ms for 1 GiB (committing pages and building the
  SLAT mapping). This is the single biggest host-setup cost and the main reason a
  microVM keeps RAM small.
* **vmlinux+initramfs loaded** is the mmap-and-copy of the ELF `PT_LOAD` segments
  plus the cpio into guest RAM (~13–34 ms here for a ~16 MB kernel image).
* **entering guest** is where the BSP starts executing at the PVH entry; from here
  the *guest* boots Linux and reaches its `/init` shell within the first watchdog
  second.

So host-side "time to first guest instruction" is **~72 ms** for the default
microVM and grows mainly with `--ram-mb`. (`--gpu`/`--input` add their device
setup but do not change this host-RAM-dominated path.)

---

## 13. Save / restore

`--save <path>` arms a snapshot trigger; the guest requests a checkpoint by
issuing the **magic leaf `CPUID(0x4000DE57)`** (a Hyper-V leaf, so a real host
returns nothing for it). The run loop always returns the signature (so the guest
can detect support), and when *armed* it records the requesting vp and surfaces
`StopReason::SnapshotRequested`, advancing RIP first so restore resumes *past* the
CPUID (`src/whp/snapshot.rs`, `src/whp/run_loop.rs`). The VMM then quiesces (stops
+ joins APs, drains the blk IOCP workers, stops net backends, quiesces 9p) and
writes a self-describing file (`src/whp/snapshot_file.rs`):

```
[24-byte header]  "TVMMSAVE" | version u32 (=1) | reserved u32 | header_json_size u64
[ JSON header ]   machine description (vcpus, ram, large_pages, with_gpu/width/height,
                  with_input, device list …)
[ sections... ]   type u32 | reserved u32 | length u64 | payload[length]
[ trailer ]       CRC32 (IEEE-802.3, poly 0xEDB88320) over all preceding bytes
```

Section types cover per-vCPU register state (GPRs, control/segment/descriptor +
debug regs, EFER + syscall MSRs, XSAVE, the APIC + interrupt-controller state,
TSC), the **Hyper-V enlightenment** (4 MSR caches), the **legacy devices**
(PIC/PIT/serial/ISA-stubs/PCI-bus), every **PCI device**, and **guest RAM last**.
The CRC32 table is a `OnceLock<[u32; 256]>`.

Each PCI device section is tagged with its `device_index` (the PCI-add order:
console=0, then NICs, rng, blk*, **input keyboard+tablet**, 9p*, **gpu last**).
**Save and restore construct devices in the same order** or the indices misalign;
`run_restore` rebuilds them from the JSON header in that exact sequence. A virtio
device snapshots through just four `VirtioDevice` hooks — `capture_queue` /
`apply_queue` / `capture_device_state` / `apply_device_state` — and the transport
handles the ordering of the rest (PCI config / BAR remap → common-cfg → MSI-X
table → queues → device-state).

What is and isn't snapshottable:

* **The only `--save` refusal is a *writable* `--drive`** (unless you pass
  `--unsafe-save-mutable-drive`) — the disk content is not in the snapshot, so a
  mutated disk would diverge from restored RAM (`main.rs:911`). On restore you
  re-attach the disks with `--drive` (and `--unsafe-restore-mutable-drive` if a
  size changed).
* **virtio-net IS snapshottable:** only the *device model* is captured; on restore
  a **fresh** backend is wired in (live external flows reset, new flows work).
* **virtio-9p IS snapshottable:** its `capture_device_state` serializes the fid
  table (paths + open modes + qid) and **reopens the host handles** on restore.
* **virtio-input IS snapshottable:** queues + device-state (features/status,
  config select, LED state, last absolute position) round-trip, so the pointer
  resumes where it was.
* **virtio-gpu IS snapshot-aware:** `capture_device_state` serializes a `"GPU1"`
  blob — driver flags, the scanout, and **every resource** (geometry + backing SG
  list + the host pixel shadow); restore re-presents the bound scanout. The GPU is
  added **last** in PCI order specifically so its device_index doesn't perturb the
  others.
* The Hyper-V hypercall + Reference-TSC pages live *inside* guest RAM, so they
  restore with it; the enlightenment is then re-applied so a fresh host
  `tsc_scale` wins.
* `SnapshotWriter`'s `Drop` deletes a half-written file if `finalize()` (which
  writes the CRC trailer) did not run — no truncated snapshot is ever left behind.
