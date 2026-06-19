# tinyvmm internals & reimplementation guide

This document explains **how tinyvmm works** and, layer by layer, **what you would
have to build to write a VMM like it from scratch**. It is the companion to
[`README.md`](README.md): the README is the user-facing *reference* (CLI, feature
matrix, safety/perf/concurrency justification); this file is the *builder's
guide* — the mechanics, the host-API call sequences, the on-the-wire byte
layouts, the core algorithms, and the non-obvious lessons, presented in the order
you would actually implement them.

It assumes you can read systems code but **not** that you know the Windows
Hypervisor Platform (WHP), the PVH boot protocol, or virtio. Citations are
`path:line` into this tree and are clickable.

---

## Table of contents

1. [What a microVM monitor is](#1-what-a-microvm-monitor-is)
2. [The substrate: what WHP gives you and what it makes you do](#2-the-substrate-what-whp-gives-you-and-what-it-makes-you-do)
3. [Reimplementation roadmap (milestones)](#3-reimplementation-roadmap-milestones)
   - [M0 — A partition with RAM and a CPU that halts](#m0--a-partition-with-ram-and-a-cpu-that-halts)
   - [M1 — PVH boot to the first guest instruction](#m1--pvh-boot-to-the-first-guest-instruction)
   - [M2 — The exit loop: IO, MMIO, CPUID, MSR](#m2--the-exit-loop-io-mmio-cpuid-msr)
   - [M3 — Making time and interrupts work](#m3--making-time-and-interrupts-work)
   - [M4 — The PCI host bridge](#m4--the-pci-host-bridge)
   - [M5 — The virtio-PCI transport, virtqueues, MSI-X](#m5--the-virtio-pci-transport-virtqueues-msi-x)
   - [M6 — Real devices and the doorbell fast path](#m6--real-devices-and-the-doorbell-fast-path)
   - [M7 — The rest: gpu, input, sound, save/restore](#m7--the-rest-gpu-input-sound-saverestore)
4. [Cross-cutting concerns](#4-cross-cutting-concerns)
5. [The full bring-up sequence, annotated](#5-the-full-bring-up-sequence-annotated)
6. [Porting away from WHP (KVM / Hypervisor.framework)](#6-porting-away-from-whp-kvm--hypervisorframework)
7. [Gotchas — the non-obvious lessons](#7-gotchas--the-non-obvious-lessons)
8. [Reimplementation checklist](#8-reimplementation-checklist)
9. [Appendix: memory map, constants, file map](#9-appendix-memory-map-constants-file-map)

---

## 1. What a microVM monitor is

A **VMM** (virtual machine monitor / hypervisor) presents a synthetic machine to
a guest OS: some RAM, one or more CPUs, a clock, an interrupt controller, and a
handful of devices. A **microVM monitor** (firecracker, cloud-hypervisor, and
tinyvmm) deliberately presents the *smallest* such machine that a modern Linux
needs to reach its `init` — no BIOS, no legacy real-mode boot, no ACPI power
management, no PCI enumeration of physical hardware, no SMM. Everything is
paravirtual (virtio) and the host-side setup is measured in tens of milliseconds.

The feature set, framed as capabilities you must provide:

| Capability | What it means | Where in tinyvmm |
|---|---|---|
| **CPU virtualization** | Create vCPUs, run them, field the exits they take (IO/MMIO/CPUID/MSR/HLT) | `crates/whpsys/src/vcpu.rs`, `src/whp/run_loop.rs` |
| **Guest physical memory** | A flat slab of host RAM mapped into the guest's physical address space | `crates/whpsys/src/memory.rs` |
| **Boot protocol** | Get a kernel image into RAM and the CPU pointed at its entry point with the right machine state | `src/boot/loader.rs` (PVH) |
| **Firmware tables** | The minimal ACPI a modern Linux expects (so it finds the LAPIC) | `src/boot/acpi.rs` |
| **A clock & invariant TSC** | The guest must be able to calibrate time without legacy timers | `src/whp/cpuid.rs`, `src/whp/hv.rs` |
| **An interrupt controller** | Deliver device interrupts to the guest (LAPIC/x2APIC + MSI) | `crates/whpsys/src/lapic.rs`, `src/whp/msi`/`crates/whpsys/src/msi.rs` |
| **A PCI host bridge** | The `0xCF8/0xCFC` config mechanism and a BAR allocator | `src/pci/` |
| **A device transport** | virtio-PCI "modern" + the virtqueue ring protocol | `src/virtio/transport.rs`, `src/virtio/queue.rs` |
| **Devices** | console, net, block, rng, 9p, gpu, input, sound | `src/virtio/*.rs`, `src/net/`, `src/display.rs` |
| **Legacy glue** | 8250 UART, i8259 PIC, 8254 PIT, CMOS — present for boot correctness | `src/devices/` |
| **Lifecycle** | Multi-vCPU launch/teardown, quiesce, snapshot/restore | `src/main.rs`, `src/whp/snapshot*.rs` |

The block diagram of a running machine:

```
                       ┌───────────────────────────────────────────────┐
   host threads        │                  WHP partition                 │
   ───────────         │   (Windows Hypervisor Platform kernel object)  │
                       │                                                │
  BSP thread  ───run──▶│  vCPU0 ─┐                                       │
  AP threads  ───run──▶│  vCPU1  ├─ guest RAM (one VirtualAlloc slab,    │
                       │  ...    │   mapped at GPA 0 [+ above 4 GiB])    │
                       │         └─ SLAT/EPT, hardware LAPIC (opt)       │
                       └─────▲───────────────────────┬──────────────────┘
                             │ exits (IO/MMIO/CPUID/  │ interrupts
                             │       MSR/HLT)         │ (MSI / IRQ inject)
                       ┌─────┴────────────────────────▼──────────────────┐
                       │  run loop  →  IO bus / MMIO bus  →  devices      │
                       │  CPUID/MSR policy, (software) LAPIC, HV MSRs     │
                       │  PCI host bridge → virtio-PCI transports         │
                       │  virtqueues → console/net/blk/rng/9p/gpu/...     │
                       └─────┬───────────────┬───────────────┬───────────┘
   doorbell pumps ──────────┘               │               │
   IOCP workers (blk/net) ──────────────────┘               │
   9p worker pool, WASAPI threads, window message pump ──────┘
```

The two ideas that make it tractable: **all guest I/O is virtio over one PCI bus
with MSI-X**, and **the host hypervisor (WHP) does the genuinely hard parts**
(VT-x/AMD-V, second-level address translation, instruction decode for trapped
MMIO). You are writing the *user-mode* half.

---

## 2. The substrate: what WHP gives you and what it makes you do

tinyvmm targets WHP, but every hypervisor backend (KVM, Hypervisor.framework,
WHP) draws the same line. Knowing which side of the line each task is on is the
single most useful map for a reimplementer.

| The host hypervisor does… | …so you must do |
|---|---|
| VT-x/AMD-V root mode, VMCS/VMCB, world switches | nothing — you call `WHvRunVirtualProcessor` |
| Second-level address translation (EPT/NPT) from your GPA→HVA map | provide the map (`WHvMapGpaRange`), and keep the host buffer pinned |
| Decoding the faulting instruction on an MMIO/IO exit | provide the *data* (what the device returns), via the WHP **instruction emulator** callbacks |
| Optionally emulating the LAPIC in hardware (APICv) | decide hardware vs software LAPIC; on nested hosts, emulate it yourself |
| Delivering an MSI you hand it (`WHvRequestInterrupt`) | decode the MSI message and route it; or, with a software LAPIC, inject it at VM-entry yourself |
| CPUID/MSR *default* values (host passthrough) | override the leaves/MSRs the guest needs (TSC freq, x2APIC, Hyper-V) |
| Nothing about boot, firmware, devices, or time | **all of it** |

WHP's public surface is a flat C API in `windows-sys`
(`Win32::System::Hypervisor`). The whole job of the two FFI crates is to wrap it
safely:

- **`crates/whpsys/`** — WHP only: `partition`, `memory`, `vcpu` (+ run/exit
  decode + XSAVE/APIC save-restore), `emulator` (the instruction-completion
  callbacks), `msi`, `doorbell`, `lapic` (the software LAPIC), `vpci` (the
  undocumented passthrough APIs).
- **`crates/winsys/`** — every *other* Win32 call: async disk IOCP, mmap loader,
  Winsock, CNG random, ETW, 9p file ops, WASAPI audio, the wintun loader.

The binary (`src/`) keeps thin facades that re-export from these, so all `unsafe`
is quarantined in two auditable crates. If you port to KVM you rewrite `whpsys`
and the Win32 half of `winsys`; the `src/` protocol logic (PCI, virtqueue, boot,
device models, NAT) is almost entirely OS-agnostic and `unsafe`-free.

---

## 3. Reimplementation roadmap (milestones)

Each milestone is independently testable and leaves you with something that
visibly works. tinyvmm ships the first as `--smoke`
(`src/main.rs:181`); the rest accrete into `--pvh-run`.

### M0 — A partition with RAM and a CPU that halts

**Goal:** create the VM object, give it 16 MiB, create one vCPU, place a single
`HLT` instruction in RAM, run, and observe the halt exit. This proves the host
hypervisor is reachable and your memory mapping is correct.

**1. Create and configure the partition** (`crates/whpsys/src/partition.rs`):

```
WHvCreatePartition(&handle)
WHvSetPartitionProperty(ProcessorCount, n)
// optional knobs, all BEFORE setup:
WHvSetPartitionProperty(ExtendedVmExits, bits)        // bit0=cpuid bit1=msr bit2=exception
WHvSetPartitionProperty(CpuidResultList, &entries)    // static CPUID overrides
WHvSetPartitionProperty(LocalApicEmulationMode, mode) // X2Apic | None
WHvSetupPartition(handle)                             // finalizes; properties locked after
```

The partition is a kernel object; wrap it in RAII so `WHvDeletePartition` runs on
drop (`partition.rs:120`). **Order matters:** every property must be set before
`WHvSetupPartition`; `set_allow_device_assignment` likewise (`partition.rs:74`).

**2. Allocate and map guest RAM** (`crates/whpsys/src/memory.rs:50`):

```
base = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE[|MEM_LARGE_PAGES], PAGE_READWRITE)
WHvMapGpaRange(part, base, gpa=0, size, Read|Write|Execute)
```

Two subtleties that are easy to get wrong and painful to debug:

- **The host buffer must stay put for the partition's life.** It backs the guest
  via SLAT; you never hand the guest a copy. `Drop` does
  `WHvUnmapGpaRange` then `VirtualFree` (`memory.rs:419`).
- **The 32-bit PCI MMIO hole.** Device BARs live in `[0xE000_0000, 0xFEC0_0000)`
  (just under the IOAPIC). Guest RAM may not overlap it. So RAM larger than
  `0xE000_0000` (3584 MiB) is **split**: the first 3584 MiB map at GPA 0 and the
  remainder maps at `0x1_0000_0000` (4 GiB), leaving the window free
  (`memory.rs:103` `new_split`, constants in `src/mem_layout.rs`). The host
  backing store stays one contiguous allocation; only the *GPA* mapping has a
  hole.

**3. Funnel all guest-RAM access through one audited accessor.** This is the
single most important design decision for a safe VMM. `GuestMemory` exposes
`host_range(gpa, len) -> Option<*mut u8>` with a **wrap-safe** bounds check
written in subtraction form so a near-`u64::MAX` address can't overflow the bound
(`memory.rs:300`):

```rust
if gpa < self.gpa { return None; }
let off = gpa - self.gpa;
if off >= size || len > size - off { return None; }   // never `off + len > size` (can wrap)
```

Everything else — typed reads, ring-index atomics, bulk copies — is built on top
(`read_array::<N>`, `load_acquire_u16`, `write_bytes`). Devices use these with
**no `unsafe`**; the only raw pointers that escape are bulk DMA buffers wrapped in
a `ChainBuf` (see M5).

**4. Create a vCPU and run it** (`crates/whpsys/src/vcpu.rs`):

```
WHvCreateVirtualProcessor(part, index, 0)
loop {
    WHvRunVirtualProcessor(part, index, &exit, sizeof exit)   // blocks in the guest
    match decode(exit.ExitReason) { Halt => break, ... }
}
```

Set RIP to the address of your `HLT`, run, and you should get
`WHvRunVpExitReasonX64Halt`. That is M0. (`run_smoke` does exactly this and
prints the exit reason and RIP.)

> **Gotcha that will cost you a day:** `WHV_REGISTER_VALUE` is declared
> `DECLSPEC_ALIGN(16)` in the WHP headers (WHP reads it with aligned SSE
> `movaps`), but the `windows-sys` binding drops the alignment to 8. Passing a
> raw array to `WHvGet/SetVirtualProcessorRegisters` faults inside WHP whenever
> the buffer lands on an 8-but-not-16 boundary. tinyvmm copies through a
> `#[repr(C, align(16))]` wrapper (`vcpu.rs:27`). If your bindings are similar,
> do the same.

### M1 — PVH boot to the first guest instruction

**Goal:** load an unmodified `vmlinux` and get it to print to the serial port.

tinyvmm uses the **PVH** boot protocol (the Xen/Linux paravirtual-hardware entry
point, `CONFIG_PVH=y`). PVH is the microVM-friendly choice: the kernel enters in
**32-bit protected mode** at a known physical address with a single pointer to a
`hvm_start_info` struct — no BIOS, no real mode, no decompressor stub. The whole
loader is `src/boot/loader.rs`.

**1. Find the entry point.** Parse the ELF64 header, walk the program headers,
and in the `PT_NOTE` segment find the note with name `"Xen"` and type `18`
(`ELF_NOTE_PHYS32_ENTRY`); its descriptor is the 32-bit entry address
(`loader.rs:81` `find_pvh_note`). If absent, the kernel isn't PVH-capable.

**2. Load the image.** Copy each `PT_LOAD` segment's file bytes to its `p_paddr`
in guest RAM (`loader.rs:256`). The BSS tail (`memsz > filesz`) is already zero
because `VirtualAlloc(MEM_COMMIT)` hands back zeroed pages — don't memset it.
tinyvmm memory-maps the kernel file (`MapViewOfFile`) and copies straight into
guest RAM, so there's no intermediate `Vec` (`crates/winsys/src/host/mapped_file.rs`).

**3. Stage the boot structures in low memory.** The PVH contract is "EBX points
at a `hvm_start_info`." tinyvmm lays them out at fixed low GPAs (`loader.rs:18`):

```
0x1000  GDT          (null, code32=0x00CF9A000000FFFF, data32=0x00CF92000000FFFF)
0x2000  hvm_start_info (56 bytes)
0x2100  e820 memmap  (array of 24-byte entries)
0x2400  module list  (initramfs descriptor: paddr, size)
0x2800  kernel cmdline (NUL-terminated)
0x3000  ACPI tables  (RSDP/XSDT/MADT — see M3)
```

The `hvm_start_info` fields you must fill (`loader.rs:352`): magic
`0x336ec578`, version 1, `nr_modules`, `modlist_paddr`, `cmdline_paddr`,
`rsdp_paddr`, `memmap_paddr`, `memmap_entries`.

The **e820 map** (`loader.rs:313`) is the guest's view of physical RAM. tinyvmm
emits: reserved `[0,0x10000)` (boot artifacts), RAM `[0x10000,0xA0000)`, reserved
ISA hole `[0xA0000,0x100000)`, RAM `[0x100000, min(ram, 0xE000_0000))`, and — if
RAM exceeds the MMIO hole — RAM `[0x1_0000_0000, …)` for the relocated high half.
This map and the GPA split from M0 must agree exactly.

**4. Program the BSP for PVH entry** (`loader.rs:377` `setup_pvh_entry`): flat
32-bit code/data segments, `GDTR` → your GDT, `CR0 = PE|ET`, `RFLAGS = 0x2`,
`RBX = start_info_gpa`, `RIP = entry_point`. Run, and the kernel takes over.

To *see* it, you need M2's serial port: add the default cmdline
`console=hvc0 ...` (or `--debug-boot` to prepend `earlyprintk=ttyS0,115200` so the
8250 UART streams before virtio-console is up).

### M2 — The exit loop: IO, MMIO, CPUID, MSR

**Goal:** field the exits the booting kernel takes. This is the heart of the VMM
(`src/whp/run_loop.rs`).

The loop is: check the stop flag, deliver any pending interrupt (M3), run the
vCPU, then `match` on the decoded exit reason (`run_loop.rs:154`). tinyvmm decodes
the raw WHP union into a small enum (`vcpu.rs:374`): `Halt, IoPort, Memory
(MMIO), Cpuid, Msr, InterruptWindow, ApicEoi, Canceled, Other`.

**IO and MMIO exits → the instruction emulator.** When the guest does `IN/OUT`
or touches an unmapped GPA, hardware exits but does *not* tell you the decoded
operand. You hand the exit to WHP's **instruction emulator**, which decodes the
faulting instruction and calls you back for the data
(`crates/whpsys/src/emulator.rs`):

```
WHvEmulatorCreateEmulator(&callbacks)   // 5 callbacks, once per run loop
WHvEmulatorTryIoEmulation(emu, ctx, vp_context, io_access, &status)
WHvEmulatorTryMmioEmulation(emu, ctx, vp_context, mem_access, &status)
```

The five callbacks (`emulator.rs:165`): `io_port`, `memory`, `get_registers`,
`set_registers`, and `translate_gva`. The first two are where you plug your
device buses; the register ones just forward to
`WHvGet/SetVirtualProcessorRegisters`; `translate_gva` forwards to
`WHvTranslateGva` (needed for string I/O like `rep insb` and RMW MMIO — **don't**
stub it to `E_NOTIMPL`, that turns a benign instruction into a VMM-killing
emulation failure, `emulator.rs:234`).

**The device buses.** Two trivial range-dispatch tables
(`src/devices/io_bus.rs`, `src/devices/mmio_bus.rs`): register `[base, base+size)
→ handler`, dispatch by address, and return all-ones for unclaimed reads (the ISA
floating-bus convention). The IO bus is built once and shared immutably; the MMIO
bus uses an `RwLock` because device BARs *remap at runtime* (M4) — reads never
block reads, and registration must **never panic on overlap** (a guest can
reprogram a BAR over another's range), so it returns `false` instead
(`mmio_bus.rs:44`).

**CPUID exits** (`run_loop.rs:276`): advance RIP past the instruction, then write
`RAX/RBX/RCX/RDX`. tinyvmm intercepts one magic leaf for snapshots (M7) and
otherwise applies a policy layer (M3). WHP hands you its host-passthrough default
in the exit; you override selectively.

**MSR exits** (`run_loop.rs:383`): route to the software LAPIC (if active) or the
Hyper-V enlightenment (M3); an unhandled MSR injects `#GP(0)` rather than killing
the VM (`run_loop.rs:458`). On a read, write back `RAX:RDX`; always advance RIP.

**HLT** (`run_loop.rs:195`): if `RFLAGS.IF=1` the guest is just idle — re-run
(hardware LAPIC) or **park** until a device/timer queues a vector (software LAPIC,
M3). `HLT` with `IF=0` is a deliberate dead-end (no more interrupts can wake it) —
treat it as terminal.

At this point the kernel boots to the UART. Wire the **8250** (`src/devices/serial.rs`)
at `0x3F8`: TX bytes → host stdout, and raise IRQ4 through the PIC when the guest
enables transmit interrupts.

### M3 — Making time and interrupts work

This milestone is the one that surprises people: a microVM with no PIT IRQ0, no
HPET, and no PM timer has **no legacy way to calibrate time**, and on a nested
host **interrupts don't reach an idle guest** unless you emulate the LAPIC.
Getting Linux past `calibrate_delay()` and delivering a virtio completion to a
halted vCPU are the two hard problems here.

**1. CPUID policy** (`src/whp/cpuid.rs:105`). Layer these overrides on WHP's
host-passthrough defaults:

- **Force x2APIC on** (leaf 1, ECX[21]) and set the **hypervisor present** bit
  (ECX[31]). Pack `(vcpu_count, vcpu_index)` into EBX[23:16]/[31:24].
- **Advertise invariant TSC** (leaf `0x80000007` EDX[8]) and **ARAT** (leaf 6
  EAX[2]) so the LAPIC timer is "always running."
- **Publish the TSC frequency** via leaves `0x15` (TSC/crystal ratio) and `0x16`
  (base MHz). tinyvmm measures it once at startup (`cpuid.rs:74` — from leaf 0x15,
  else 0x16, else a 50 ms RDTSC calibration) and caches it in a `OnceLock`.
- **Emulate the Hyper-V vendor leaves** `0x40000000`–`0x40000006`: vendor
  `"Microsoft Hv"`, interface `"Hv#1"`, and a feature bitmask advertising the
  hypercall page, VP index, reference TSC, and the **frequency MSRs**
  (`cpuid.rs:39`).
- **Hide TSC-deadline** (leaf 1 ECX[24]) — the software LAPIC only implements the
  count-based timer.

These also go in the *static* `CpuidResultList` set on the partition
(`cpuid.rs:248`) so leaves that don't take an extended exit still get the override.

**Why the Hyper-V leaves?** Linux's `ms_hyperv_init_platform`, on seeing the
frequency-MSR feature bits, sets `x86_platform.calibrate_tsc = hv_get_tsc_khz` and
**skips legacy timer calibration entirely**. Without them it falls back to PIT
calibration, which — with no IRQ0/HPET/PM-timer — wedges `calibrate_delay()`
forever (`cpuid.rs:46`). This is *the* trick that makes a deviceless microVM boot.

**2. The Hyper-V enlightenment** (`src/whp/hv.rs`). A handful of MSRs the guest
writes once it detects Hyper-V:

- `GUEST_OS_ID`, `VP_INDEX` — bookkeeping.
- `HYPERCALL` (`0x40000001`): on enable, write a tiny stub page into guest RAM
  (`mov eax, 2; ret` — "invalid hypercall", since tinyvmm implements no
  hypercalls, `hv.rs:99`).
- `REFERENCE_TSC` (`0x40000021`): write a page holding the **TSC scale**
  `(10^7 << 64) / tsc_hz`, so the guest reads a 100 ns reference clock straight
  from the TSC with no exit (`hv.rs:83`).
- `TSC_FREQUENCY` / `APIC_FREQUENCY`: just return the measured TSC Hz (`hv.rs:182`).
- Unhandled Hyper-V MSR → inject `#GP`.

**3. The interrupt controller.** You have two paths, and the choice is dictated by
whether your *host* is itself a VM (`src/main.rs:1250` auto-detects):

- **Bare-metal host → WHP's hardware LAPIC** (`LocalApicEmulationMode = X2Apic`).
  APIC virtualization (APICv / posted interrupts) lets WHP preempt a running vCPU
  to deliver an interrupt. You deliver an MSI by decoding the message and calling
  `WHvRequestInterrupt` (`crates/whpsys/src/msi.rs:44`).
- **Nested host → a software LAPIC** (`LocalApicEmulationMode = None`,
  `crates/whpsys/src/lapic.rs`). The L1 hypervisor doesn't expose APICv to WHP's
  L2 partition, so WHP can only deliver a pending interrupt **at the next exit** —
  it can't preempt. A guest that halts waiting for a virtio-blk completion would
  then **hang forever**. The fix (mirroring OpenVMM's user-mode APIC) is to
  emulate the LAPIC yourself.

The software LAPIC is single-vCPU (BSP), x2APIC-only, and worth understanding
because it's the subtle part:

- It traps the x2APIC MSR range `0x800–0x83F` plus `IA32_APIC_BASE` (`0x1B`),
  keeping a 256-bit **IRR** (requested) and **ISR** (in-service) bitmap, the LVTs,
  and a count-based timer (`lapic.rs:70`).
- `IA32_APIC_BASE` comes up pre-enabled with the x2APIC bit set — Linux's
  `check_x2apic()` reads it early; without that bit it stays in xAPIC mode, sends
  LAPIC accesses to MMIO `0xFEE00000` (which you don't handle), and the timer is
  never armed → jiffies freeze (`lapic.rs:99`).
- **Delivery:** an MSI or timer tick sets an IRR bit and (a) notifies a run loop
  parked on a halted guest via a condvar, and (b) `WHvCancelRunVirtualProcessor`s
  a running vCPU so it exits promptly (`lapic.rs:246`). The run loop, before each
  re-entry, peeks the highest-priority deliverable vector against the live TPR
  (`CR8`) and injects it with `WHvRegisterPendingInterruption` — *but only when
  the guest is injectable* (RFLAGS.IF set, no interrupt shadow, nothing already
  pending), or the VM-entry is invalid and WHP faults (`vcpu.rs:159`).
- **The timer** runs on its own thread, counting in host-TSC ticks (the APIC bus
  frequency is *defined* as the TSC frequency, so the guest's calibration cancels
  out), and fires the LVT timer vector at the deadline (`lapic.rs:421`).

MSI routing therefore forks on `lapic::active()`: queue-in-software-LAPIC vs
`WHvRequestInterrupt` (`crates/whpsys/src/msi.rs:25`).

**4. The legacy PIC** (`src/devices/pic.rs`) is the *only* ISA-IRQ → guest-IDT
path (used by the 8250 UART in virtual-wire mode). Its injection closure calls
`WHvRequestInterrupt` with a fixed/physical/edge message (`main.rs:1484`). The
8254 PIT is present as counters but IRQ0 is intentionally **not** wired — Linux
uses the LAPIC timer.

### M4 — The PCI host bridge

**Goal:** let the guest enumerate one PCI bus and program device BARs. No real
hardware — a synthetic Type-0 config space per device (`src/pci/`).

**1. Configuration Mechanism #1** (`src/pci/bus.rs`). Two IO ports: write a
`bus/dev/fn/reg` selector to `0xCF8` (`CONFIG_ADDRESS`), then read/write the
selected dword at `0xCFC` (`CONFIG_DATA`). Decode is bit-twiddling
(`src/pci/mod.rs:72`); the bus finds the addressed function and forwards the
config access, returning all-ones for absent functions (`bus.rs:146`).

**2. Type-0 config space** (`src/pci/config.rs`). A 256-byte buffer plus a
parallel **writable-mask** (so reads of read-only fields are stable and writes to
them are ignored), six BAR descriptors, and a capability list. You implement:

- **IDs/class/caps** at construction.
- **The BAR sizing dance** (`config.rs:214`, test at `:407`): the OS writes
  all-ones to a BAR, reads it back, and infers the region size from the returned
  size-mask (low bits forced to the type encoding). You return
  `value & ~(size-1) | type_bits`; the OS computes `size = ~(readback & ~0xF) + 1`.
  A 64-bit BAR spans two dwords; the high dword reads back all-ones.
- **The COMMAND.MEM_SPACE → map/unmap state machine** (`config.rs:272`
  `recompute_mappings`): toggling `MEMORY_SPACE`, or reprogramming a BAR base
  while enabled, emits `BarEvent::Mapped/Unmapped` that the transport acts on to
  (de)register its MMIO handlers. This is what makes a device "appear" at a GPA.

**3. The BAR allocator** (`bus.rs:34`). tinyvmm *pre-assigns* BAR bases from the
MMIO window `[0xE000_0000, 0xFEC0_0000)` at device-add time (bump allocator,
size-aligned), so the guest sees BARs already placed and just flips
`MEMORY_SPACE`. (A more general VMM would honor whatever base the guest programs;
tinyvmm's `recompute_mappings` already supports moves.)

You can validate all of this with **no guest** via `--pci-selftest`
(`main.rs:824`), which drives the config mechanism and BAR sizing against a
synthetic function.

### M5 — The virtio-PCI transport, virtqueues, MSI-X

**Goal:** the generic machinery every virtio device sits behind. Get this right
once and every device is small. Three files: `src/virtio/transport.rs` (the
PCI/virtio glue), `src/virtio/queue.rs` (the ring), `src/pci/msix.rs` (interrupts).

**1. The device interface** (`src/virtio/device.rs:26`). Each device implements a
small trait — `device_id`, `device_features`, `set_driver_features`,
`queue_count`/`queue_max`, `enable_queue`/`disable_queue`, `notify_queue`,
`driver_ok`, `reset`, device-config read/write, and four save/restore hooks. The
**transport owns the register state machine; the device owns its virtqueues.**

**2. The virtio-PCI "modern" BAR layout** (`transport.rs:22`). One 16 KiB MMIO BAR
(BAR0) carved into windows, each advertised by a vendor capability in config space
(`transport.rs:204` `append_virtio_cap`):

```
0x0000  common_cfg   (feature negotiation, queue programming, status)
0x0040  ISR status   (legacy interrupt-reason read)
0x1000  notify       (queue-kick doorbell region, 4 bytes per queue)
0x2000  device_cfg   (device-specific config space)
0x3000  MSI-X table
0x3800  MSI-X PBA
```

**3. The common-cfg state machine** (`transport.rs:490`). The driver:

1. reads `device_feature` (in 32-bit halves via a select register), writes back
   the `driver_feature` it accepts;
2. sets `FEATURES_OK` in the status byte — you call `set_driver_features` and, if
   the device rejects them, clear `FEATURES_OK` and set `NEEDS_RESET`
   (`transport.rs:709`);
3. for each queue: writes size, descriptor/avail/used physical addresses and an
   MSI-X vector, then writes `queue_enable=1` — you validate alignment (desc
   16-byte, avail 2-byte, used 4-byte) and power-of-two size, then call the
   device's `enable_queue` (`transport.rs:651`);
4. sets `DRIVER_OK` — you call `driver_ok()`.

A status write of 0 is a full reset.

**4. The split virtqueue** (`src/virtio/queue.rs`) — the actual data ring
(virtio spec §2.7). Three guest-RAM structures per queue: a **descriptor table**
(16-byte entries: `addr,len,flags,next`), an **avail ring** (driver → device), and
a **used ring** (device → driver). The device side:

- `pop_into(&mut chain)` (`queue.rs:269`): read the avail index (Acquire), walk
  the descriptor chain following `NEXT`, resolve each `addr/len` through
  `host_range` into a `ChainBuf { ptr, len, write }`, and collect read-only vs
  device-writable buffers. **It reuses the chain's `Vec`, so the hot path
  allocates nothing.**
- `push(head, used_len)` (`queue.rs:367`): write the used-ring element, then
  publish `used.idx` after a `Release` fence.
- **EVENT_IDX suppression** (`queue.rs:379`): when negotiated, the device writes
  `avail_event` to ask for the next kick and reads `used_event` to decide whether
  to actually raise an interrupt — this is what lets a busy queue run with almost
  no interrupts/exits.

This is also your **primary attack surface**. The guest controls every byte of
those rings. The popper therefore: rejects an avail head `≥ size`; validates the
descriptor table is mapped before walking; **bounds the walk by `size`** and
re-checks every `next` (direct *and* indirect) `< size`, so a cyclic or
oversized chain can neither loop nor quadratically inflate your buffers
(`queue.rs:297`). There's a fuzz test that scribbles random bytes over the rings
and asserts `pop()` never panics, never loops, never returns a buffer outside RAM
(`queue.rs:427`). **Write this test early.**

**5. Reads/writes are zero-copy.** `host_range` returns a validated pointer the
device operates on *in place*: virtio-blk hands `req.buf = seg_ptr` straight to
`ReadFile`/`WriteFile` (disk DMA into guest RAM), rng fills the guest buffer
directly. The only fixed copy the safety layer imposes is the 16-byte descriptor
to a stack buffer (alignment safety, since the guest controls the table address).

**6. MSI-X** (`src/pci/msix.rs`). The capability + a table of
`(addr_lo, addr_hi, data, ctrl)` entries + a pending-bit array. To raise a queue
interrupt the device calls `transport.raise_queue_interrupt(qidx)`
(`transport.rs:318`), which looks up the queue's vector and calls
`msix.trigger(vector)`. `trigger` (`msix.rs:273`): if MSI-X or the vector is
masked, latch the PBA bit and return; otherwise `do_inject` → `inject_msi(addr,
data)`. Unmasking a pending vector replays it. Restoring the MSI-X table on
snapshot-restore is **mandatory** or completions stop routing.

### M6 — Real devices and the doorbell fast path

With M5 done, a device is just: declare features and queues, implement
`notify_queue` to drain the ring and do the work, and raise an interrupt when
done. Build them in this order:

- **virtio-console** (`src/virtio/console.rs`, id 3) — always present so `/init`
  has a console (`hvc0`). RX/TX queues; host stdin → RX, guest TX → stdout. This
  is your end-to-end smoke test for M5.
- **virtio-rng** (`src/virtio/rng.rs`, id 4) — fill each device-writable buffer
  from the host CSPRNG (`BCryptGenRandom`). Pure CPU, so it's serviced **inline on
  the vCPU thread** — no worker, no doorbell.
- **virtio-blk** (`src/virtio/blk.rs`, id 2) — the first *async* device, and the
  template for the rest. A request is `header + data segments + status byte`. The
  backend (`crates/winsys/src/host/block_file.rs`) opens the file
  `FILE_FLAG_OVERLAPPED`, bound to a per-disk **IOCP** with a worker thread, and
  overlaps `ReadFile`/`WriteFile` **directly into/out of guest RAM**. On
  completion the worker pushes the used element and raises the MSI-X vector.
- **virtio-net** (`src/virtio/net.rs`, id 1) + a backend
  (`NetBackend`: loopback / user-mode NAT / wintun). The NAT
  (`src/net/nat.rs`) is a slirp-style terminate-and-proxy stack (ARP, ICMP, UDP,
  TCP via the `tcp-sans-io` crate) on a single IOCP worker — no admin rights, no
  virtual adapter.
- **virtio-9p** (`src/virtio/p9.rs`, id 9) — a 9P2000.L file share with a worker
  pool. Note the **path-security** layer: every component is validated
  (reject `..`, control chars, Win32 metacharacters, reserved DOS names), `..` is
  resolved clamp-to-root, and all host I/O goes through `\\?\` long paths
  (`README.md` §9).

**The doorbell fast path** (`crates/whpsys/src/doorbell.rs`,
`transport.rs:381`). A queue kick is a guest write to the notify register, which
normally takes a VM exit. For hot-path devices you can eliminate that exit
entirely: `WHvRegisterPartitionDoorbellEvent` installs a write-match `(gpa,
value, length)` so a matching store **signals an OS event instead of exiting**. A
per-device **pump thread** waits on `{stop, per-queue doorbells}` and calls
`notify_queue` off the event (`transport.rs:158`). tinyvmm enables doorbells for
console/net/blk/9p (hot notify + downstream worker) and leaves them off for
rng/input/gpu (low-rate, serviced inline). The pump waits `INFINITE` with no
periodic sweep — the virtqueue's Acquire re-read of `avail.idx` plus the Release
of `avail_event` closes the EVENT_IDX race, and any non-matching write still falls
through to the MMIO handler as a backstop (`transport.rs:144`).

> **The performance philosophy** in one line: *optimize the number of VM exits,
> not the handler code.* The VMM's own code is at noise level under profiling; the
> cost is the hypervisor round-trip and kernel I/O. Doorbells remove exits; the
> async backends remove blocking; preallocated pools keep the malloc-free hot path
> from stalling. (README §6 quantifies this.)

### M7 — The rest: gpu, input, sound, save/restore

These are optional and don't change the core, but each teaches one more piece:

- **virtio-gpu** (`src/virtio/gpu.rs`, id 16) — 2D scanout. Control queue handles
  `RESOURCE_CREATE_2D`, `SET_SCANOUT`, `TRANSFER_TO_HOST_2D`, `RESOURCE_FLUSH`; on
  flush it swizzles the bound resource to BGRA in a reused shadow buffer and blits
  to a Win32 GDI window on its own message-pump thread (`src/display.rs`).
- **virtio-input** (`src/virtio/input.rs`, id 18) — a keyboard + an absolute
  tablet; the host injects event frames (`EV_*` + `SYN_REPORT`) and raises one IRQ
  per frame. With `--gpu`, the window is the input source (pixel coords → absolute
  axes).
- **virtio-snd** (`src/virtio/snd.rs`, id 25) — a PCM sound card over WASAPI
  shared mode; two worker threads pace render/capture off the buffer-ready event.
- **Save / restore** (`src/whp/snapshot*.rs`, README §13). A self-describing file
  (`"TVMMSAVE"` header + JSON machine description + typed sections + CRC32) holding
  per-vCPU register/XSAVE/APIC state, the HV MSR cache, the legacy devices, every
  PCI device (config/BAR/MSI-X/common-cfg/queues/device-state via the four
  `VirtioDevice` hooks), and **guest RAM last**. The crucial discipline:
  **devices are constructed in a fixed order** (console=0, net*, rng, snd, blk*,
  input kbd+tablet, 9p*, gpu last) and save/restore must use the *same* order or
  the `device_index` tags misalign (`transport.rs:1119` documents the restore
  ordering). The trigger is a magic `CPUID(0x4000DE57)` from the guest, caught in
  the run loop (`run_loop.rs:285`).

---

## 4. Cross-cutting concerns

**Concurrency model.** Memory is preallocated, but locks still exist because
**multiple host threads** touch shared device state: the vCPU threads, the
per-device doorbell pumps, the per-disk IOCP workers, the 9p pool, the NAT worker,
the display message pump, the watchdog. The locks serialize *host threads*, never
the guest. The pattern:

- `Arc<T>` for everything shared across threads (guest RAM, vCPUs, devices,
  backends), `Weak<T>` to break the transport↔device cycle (the device's IRQ
  closure upgrades a `Weak<PciTransport>`).
- `Mutex<Virtqueue>` per queue (the head/tail advance + used-ring publish must be
  atomic as a unit), small `Mutex` free-lists for request pools, `RwLock` for the
  read-mostly MMIO dispatch table.
- `Atomic*` + `OnceLock` instead of `static mut` for counters, flags, and
  set-once handles.
- Lock-free only where single-ownership is *provable*: the NAT frame pool's
  Treiber stack, the `UnsafeCell` slot bodies (exclusive between acquire and
  release via the IOCP/free-list). (README §7–§8 enumerate every lock.)

**Hostile-guest hardening.** The guest is untrusted. The discipline is: a thin
validation layer at every guest→host boundary, and **no guest action can reach a
panic.** Guest-facing paths return `Option`/`bool`/an error status byte — a bad
descriptor is dropped, an out-of-range GPA returns `None`, a bad 9p path returns
an errno, a bad blk sector answers `IOERR`. The few `panic!`s are all
setup-time wiring assertions (`README.md` §5, §9). With `panic = "abort"` the only
residual abort surface is a *poisoned* mutex, which requires a prior panic that
the guest can't trigger.

**Allocation discipline.** Boot allocates freely; the steady-state hot paths
allocate **nothing** — preallocated pools (net frames, blk requests, 9p slots, RX
buffers) and reused scratch buffers (the popped chain, the TX gather frame, the
gpu BGRA shadow). For IOCP, request slots are `Box`ed and pooled so their
addresses stay stable, and the `OVERLAPPED` is the *first* field of a `#[repr(C)]`
request so the completion's `OVERLAPPED*` casts back to the request
(`block_file.rs`, README §6).

---

## 5. The full bring-up sequence, annotated

This is the exact order `run_pvh_run` (`src/main.rs:1312`) wires a machine — a
useful template because the ordering constraints are real:

```
1.  parse args; validate snapshot preconditions
2.  enable SeLockMemoryPrivilege (for 2 MiB large pages)
3.  Partition::new(vcpus)
      enable_extended_exits(cpuid, msr)          // take CPUID+MSR exits
      set_cpuid_result_list(static overrides)
      set_local_apic_emulation(X2Apic | None)    // hardware vs software LAPIC
      setup()                                     // <-- properties locked here
4.  if software LAPIC: lapic::init(part, vp0, tsc_hz)
5.  GuestMemory::new_split(ram, MMIO_WINDOW_BASE, HIGH_RAM_BASE)   // RAM + SLAT map
6.  HvEnlightenment::new(ram, tsc_hz)             // Reference-TSC + MSRs
7.  load_pvh(ram, vmlinux, cmdline, initrd)       // ELF + start_info + e820 + ACPI
8.  for i in 0..vcpus: Vcpu::new(part, i)
    setup_pvh_entry(vcpu0, load)                  // 32-bit PM entry on the BSP
9.  build IO bus + MMIO bus
    attach 8250 UART, 8254 PIT, CMOS/POST stubs, i8259 PIC
10. PciBus::new(); add virtio devices in FIXED order:
       console(0) → net* → rng → snd → blk* → input(kbd,tablet) → 9p* → gpu(last)
    each: PciTransport::new(...) → set IRQ callback (Weak) → pci_bus.add_device → start backend
11. pci_bus.attach_io_bus(&mut io_bus)            // 0xCF8/0xCFC handlers
12. one RunLoop per vCPU (sharing io_bus, mmio_bus, hv)
13. spawn watchdog (optional), wire interactive console + shutdown sentinel
14. arm snapshot trigger (if --save)
15. BSP runs on the main thread; each AP runs on its own thread (CPU-pinned)
16. teardown: stop_all → cancel + join APs → join watchdog
       quiesce blk IOCP workers, net backends, 9p pool (BEFORE owners drop)
       if snapshot armed+requested: write the file
       print exit counters
```

The teardown ordering is not optional: **IOCP workers are quiesced before their
owning devices drop**, or a completion lands on freed memory. RAII (`impl Drop`)
releases every OS handle/mapping; `panic = "abort"` means there's no unwinding, so
process-lifetime `OnceLock` statics (TSC Hz, CRC table, ETW metadata) are
deliberately never freed.

---

## 6. Porting away from WHP (KVM / Hypervisor.framework)

Most of this guide is portable. The line from §2 is the porting map — only the
left column changes. Concretely, to retarget the backend you rewrite `whpsys` and
the Win32 half of `winsys`; the equivalents are:

| tinyvmm / WHP | KVM (Linux) | Hypervisor.framework (macOS) |
|---|---|---|
| `WHvCreatePartition` + properties | `KVM_CREATE_VM` + `KVM_SET_*` | `hv_vm_create` |
| `WHvMapGpaRange` | `KVM_SET_USER_MEMORY_REGION` | `hv_vm_map` |
| `WHvCreateVirtualProcessor` | `KVM_CREATE_VCPU` | `hv_vcpu_create` |
| `WHvRunVirtualProcessor` + exit union | `KVM_RUN` + `struct kvm_run` | `hv_vcpu_run` + manual VMCS reads |
| WHP instruction emulator (IO/MMIO) | KVM decodes for you; `KVM_EXIT_MMIO/IO` give the operand | you decode the instruction yourself |
| `WHvRequestInterrupt` / `Set...InterruptControllerState` | `KVM_IRQ_LINE` / `KVM_SIGNAL_MSI` / in-kernel irqchip | `hv_vcpu_interrupt` + your own LAPIC |
| `WHvRegisterPartitionDoorbellEvent` | `KVM_IOEVENTFD` (the eventfd doorbell) | no equivalent — poll/own thread |
| `CpuidResultList` | `KVM_SET_CPUID2` | trap `CPUID` exits |
| software LAPIC (`lapic.rs`) | usually unnecessary (in-kernel irqchip) | **required** — HVF has no in-kernel APIC |

The biggest single difference: **KVM decodes the faulting MMIO/IO instruction for
you** (you just read `kvm_run.mmio`), whereas WHP and HVF make you run an
instruction emulator. tinyvmm leans on WHP's; on HVF you'd port or vendor a
decoder. Conversely, KVM's in-kernel irqchip + `ioeventfd` mean you may not need
the software LAPIC or the doorbell pump at all.

The PVH loader, ACPI builder, CPUID *policy*, virtqueue, PCI, MSI-X, and every
device model are reusable as-is.

---

## 7. Gotchas — the non-obvious lessons

A consolidated list of things that are invisible until they bite you. Most cost
real debugging time in this project.

1. **Register alignment.** `WHV_REGISTER_VALUE` needs 16-byte alignment; an
   8-aligned buffer faults WHP intermittently. (§M0)
2. **No legacy timer = no boot.** Without the Hyper-V frequency MSRs, Linux spins
   in `calibrate_delay()` forever — there's no IRQ0/HPET/PM-timer to fall back to.
   (§M3)
3. **x2APIC must be pre-enabled.** If `IA32_APIC_BASE` doesn't come up with the
   x2APIC bit, Linux stays in xAPIC and routes the LAPIC to unhandled MMIO; the
   timer never arms and the first `msleep` hangs. (§M3)
4. **Nested hosts need a software LAPIC.** No APICv → WHP can't preempt a running
   or halted vCPU → a virtio completion never reaches an idle guest. Auto-detect
   the host-is-a-VM case. (§M3)
5. **Inject only when injectable.** `WHvRegisterPendingInterruption` over a
   cleared IF / active interrupt shadow / already-pending event is an *invalid VM
   entry* and faults WHP. Gate on all four. (§M3)
6. **Don't stub `translate_gva`.** String I/O and RMW MMIO ask the emulator for a
   GVA→GPA walk; failing it closed turns a normal instruction into a
   VMM-terminating emulation error. Forward to `WHvTranslateGva`. (§M2)
7. **The PCI MMIO hole.** Pick a device-BAR window and keep guest RAM out of it;
   split RAM above 4 GiB. The e820 map and the GPA mapping must agree. (§M0–M1)
8. **BAR remap must never panic.** A guest can reprogram a BAR over another
   device's range; the MMIO bus must reject the overlap, not abort. (§M2, M4)
9. **The virtqueue is attacker-controlled.** Bound the chain walk by queue size,
   re-validate every `next` (direct and indirect), reject heads `≥ size`. Fuzz it.
   (§M5)
10. **Wrap-safe bounds checks.** Use subtraction form (`len > size - off`), never
    `off + len > size`, which overflows for hostile addresses. (§M0)
11. **Quiesce before drop.** Stop IOCP/worker threads before their owning device
    is dropped, or a completion writes to freed memory. (§5)
12. **Snapshot device order is load-bearing.** Construct devices in the same fixed
    order on save and restore, or the per-device snapshot indices misalign. (§M7)
13. **A microVM can't `poweroff` cleanly.** With no ACPI, Linux's `poweroff` falls
    back to `STI;HLT` and produces no terminal exit; tinyvmm watches the hvc0
    stream for a shutdown sentinel instead. (§5)

---

## 8. Reimplementation checklist

The minimum to boot an unmodified PVH Linux to a shell:

- [ ] Partition: create, set processor count, **extended exits for CPUID+MSR**,
      CPUID result list, LAPIC mode, setup.
- [ ] Guest RAM: one host allocation, mapped R/W/X; split around the PCI MMIO
      hole; **one audited bounds-checked accessor** for all guest-RAM access.
- [ ] vCPU: create, get/set registers (mind the alignment), run, decode exits,
      inject interrupts.
- [ ] PVH loader: ELF parse + PHYS32 note, `PT_LOAD` copy, `hvm_start_info` +
      e820 + cmdline + GDT, 32-bit PM entry on the BSP.
- [ ] ACPI: RSDP → XSDT → MADT (one x2APIC entry per vCPU).
- [ ] Exit loop: HLT-park, IO/MMIO via an instruction emulator + device buses,
      CPUID policy, MSR routing, `#GP` on unknown MSR.
- [ ] Time: measure TSC Hz; CPUID leaves 1/6/0x15/0x16/0x80000007/0x40000000-06;
      Hyper-V MSRs incl. the frequency MSRs and reference-TSC page.
- [ ] Interrupts: hardware LAPIC + `WHvRequestInterrupt`, **and** a software LAPIC
      + VM-entry injection for nested hosts; MSI message decode.
- [ ] Legacy: 8250 UART (→ stdout, IRQ4 via PIC), i8259 PIC, 8254 PIT counters,
      CMOS/POST stubs.
- [ ] PCI: `0xCF8/0xCFC` mechanism, Type-0 config space, BAR sizing, COMMAND→map
      state machine, a BAR allocator.
- [ ] virtio-PCI transport: capability chain, common-cfg state machine, notify,
      ISR, MSI-X table/PBA, optional doorbells.
- [ ] virtqueue: split-ring pop/push, indirect descriptors, EVENT_IDX, **hostile
      input bounds + a fuzz test.**
- [ ] Devices: console + rng (inline), then blk/net/9p (async + doorbells).
- [ ] Lifecycle: multi-vCPU launch/teardown, quiesce-before-drop, exit counters;
      optionally snapshot/restore.

---

## 9. Appendix: memory map, constants, file map

**Guest physical address space** (`src/mem_layout.rs`, `src/boot/loader.rs`):

```
0x0000_0000  +-- guest RAM (low) -------------------------------+
0x0000_1000  | GDT                                              |
0x0000_2000  | hvm_start_info / e820 / modlist / cmdline / ACPI |
0x0010_0000  | kernel image (PT_LOAD by p_paddr), initramfs     |
   ...       | ... usable RAM ...                               |
0xE000_0000  +-- PCI MMIO BAR window ---------------------------+   (3584 MiB)
   ...       | virtio device BARs (16 KiB each), MSI-X tables   |
0xFEC0_0000  +-- IOAPIC region (window end) -------------------+
0xFEE0_0000  +-- LAPIC (x2APIC; MADT advertises this) ---------+
0x1_0000_0000+-- guest RAM (high half, only if RAM > 3584 MiB)-+   (4 GiB)
```

**Key constants:**

| Constant | Value | Where |
|---|---|---|
| MMIO window base / end | `0xE000_0000` / `0xFEC0_0000` | `src/mem_layout.rs` |
| High-RAM base | `0x1_0000_0000` | `src/mem_layout.rs` |
| PVH magic / note type | `0x336ec578` / `18` ("Xen") | `src/boot/loader.rs` |
| LAPIC base | `0xFEE0_0000` | `src/boot/acpi.rs`, `lapic.rs` |
| MAX_VCPUS | `32` | `src/boot/acpi.rs` |
| virtio vendor ID | `0x1AF4` (Red Hat) | `src/main.rs` device wiring |
| virtio BAR0 size | `0x4000` (16 KiB) | `src/virtio/transport.rs` |
| Snapshot magic / trigger leaf | `"TVMMSAVE"` / `CPUID 0x4000DE57` | `src/whp/snapshot*.rs` |
| TSC scale | `(10^7 << 64) / tsc_hz` | `src/whp/hv.rs` |

**Where each subsystem lives:**

```
crates/whpsys/   WHP FFI:  partition, memory, vcpu, emulator, msi, doorbell,
                           lapic (software LAPIC), vpci (passthrough), regs
crates/winsys/   Win32 FFI: host (privilege/large-page/CNG rng), host/block_file
                           (async IOCP disk), host/mapped_file (mmap), sock
                           (Winsock+IOCP), etw, fs (9p), audio (WASAPI), wintun
src/whp/         run_loop, cpuid (policy), hv (Hyper-V MSRs), snapshot*
src/boot/        loader (PVH ELF + start_info + e820), acpi (RSDP/XSDT/MADT)
src/devices/     io_bus, mmio_bus, serial (8250), pic (i8259), pit (8254), legacy
src/pci/         mod (CF8/CFC), bus, config (Type-0 + BAR), msix, passthrough
src/virtio/      device (trait), transport (virtio-pci), queue (virtqueue),
                 console, net, rng, blk, p9, input, gpu, snd
src/net/         wire (parse/build), nat (user-mode NAT), wintun, sys
src/display.rs   Win32 GDI window for virtio-gpu + host-input seam
src/main.rs      CLI dispatch, the full machine wiring, save/restore driver
```

For the *reference* angle — exhaustive CLI, the safety/perf/concurrency
justification with histograms, ETW capture, measured boot traces, and the
save/restore file format — see [`README.md`](README.md).
