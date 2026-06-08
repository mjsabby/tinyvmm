# tinyvmm vs OpenVMM — WHP core comparison & findings

**Scope.** This document compares **tinyvmm**'s use of the **Windows Hypervisor
Platform (WHP / `WHvXxx`)** as its core hypervisor backend against
**OpenVMM**'s WHP backend (`C:\openvmm\vmm_core\virt_whp`, on top of the
`whp` binding crate `C:\openvmm\vm\whp`). It answers three questions:

1. Are we doing the *right things* at the WHP layer for the feature set we
   support (a single PVH Linux microVM)?
2. What is actually missing to run a **Windows guest**, framed at the WHP layer?
3. Where can we improve **performance** — split into *simple*, *medium*, and
   *complex* changes.

Everything below is scoped to **WHVP core infrastructure**. Device-internal
data-path tuning (virtio queue formats, NAT, 9p) is only mentioned where it
touches the hypervisor interface. Citations use `path:line`.

> **Bottom line.** For its stated mission — boot one PVH Linux microVM fast —
> tinyvmm's WHP usage is already close to optimal and, in several places,
> matches what OpenVMM does. It already has the single most important exit
> elimination (MMIO doorbells). The gaps versus OpenVMM are almost entirely
> *features OpenVMM needs because it is a general-purpose VMM* (Windows guests,
> VTL2/OpenHCL, live migration, nested virt, full SynIC/vmbus). The handful of
> genuine improvements are listed in §4 and §5.

---

## 1. WHP feature-usage matrix

| WHP surface | tinyvmm | OpenVMM | Notes |
|---|---|---|---|
| `WHvCreatePartition` / `WHvSetupPartition` | yes (`whpsys/src/partition.rs:23,104`) | yes (`virt_whp/src/lib.rs:1363,1580`) | same lifecycle |
| `ProcessorCount` | yes (`partition.rs:32`) | yes (`lib.rs:1366`) | — |
| `ExtendedVmExits` = CPUID+MSR | yes (`main.rs:964`, `partition.rs:52`) | yes, *plus* GpaAccessFault, Hypercall, Exception, UnknownSynicConnection, RetargetUnknownVpciDevice (`lib.rs:1403-1577`) | OpenVMM takes many more exit classes for the features it supports |
| `LocalApicEmulationMode` | **X2Apic** in-hypervisor (`main.rs:968`) | configurable: None (software APIC) / XApic / X2Apic (`lib.rs:1388-1401`) | tinyvmm's fixed X2Apic-in-hypervisor is the *fast* choice |
| `CpuidResultList` (exitless CPUID) | yes, ~13 static leaves (`cpuid.rs:232`) | **no** (exits on all CPUID, emulates in SW) | different philosophy — see §4 S1 |
| `CpuidExitList` (narrow exits) | **no** (all CPUID exits) | n/a | opportunity (§4 S1) |
| `X64MsrExitBitmap` | **no** (uses broad `X64MsrExit`) | yes, when software APIC (`lib.rs:1406`) | tinyvmm's broad MSR exit is fine for its SW enlightenment |
| `SyntheticProcessorFeatures` (HV enlightenment offload) | **no** — enlightenments emulated in SW (`whp/hv.rs`) | yes, large bank (`lib.rs:1493-1564`) | biggest perf+correctness opportunity (§4 M1) |
| `AllowDeviceAssignment` (VPCI/DDA) | yes, experimental (`main.rs:3768`, `partition.rs:76`) | yes (`lib.rs:1571`) | — |
| `NestedVirtualization` | no | yes (`lib.rs:1373`) | out of scope for a microVM |
| `ReferenceTime` (save/restore time base) | no | yes (`vm_state.rs:74`) | minor save/restore fidelity gap (§4 M3) |
| Guest RAM map | `WHvMapGpaRange`, eager `MEM_COMMIT`, large pages (`memory.rs:76,187`) | `WHvMapGpaRange2` (cross-process), sparse backing, dirty-tracking flag (`vm/whp/src/lib.rs:542`; `abi.rs:178`) | see §4 M4 / C2 |
| MMIO **doorbells** (exitless notify) | **yes** (`whpsys/src/doorbell.rs`, `WHvRegisterPartitionDoorbellEvent`) | yes (`synic.rs:342-410`) | tinyvmm already has the key win |
| MSI injection | `WHvRequestInterrupt` per MSI (`msi.rs:47`) | APIC/retarget + request interrupt | adequate; see §4 M2 |
| Instruction emulator | `WHvEmulator*` for IO/MMIO (`emulator.rs`) | same family | — |
| vCPU run model | 1 host thread / vCPU, CPU-pinned (`main.rs:1586-1596`) | 1 thread / vCPU | same |
| `WHvCreateVirtualProcessor2` | no (uses v1, `vcpu.rs:42`) | yes (`vm/whp/src/lib.rs:336`) | cosmetic |
| Save/restore | registers + XSAVE + `InterruptControllerState2` (`vcpu.rs:144-240`) | full vp state + reference time | tinyvmm's is appropriate for its scope |
| Hypercall handling (`WHvRunVpExitReasonHypercall`) | **no** (guest hypercall page is a stub returning "invalid", `hv.rs:22`) | yes — full dispatcher (`hypercalls.rs`, `vp.rs:585`) | needed for vmbus/Windows, not for Linux microVM |
| SynIC (SINTs, stimers, VP-assist) | **no** | yes (`synic.rs`, `apic.rs`) | needed for Windows fast path |

---

## 2. Are we doing the right things at the WHP layer? (validation)

Mostly **yes**. Concretely, these choices are correct and worth keeping:

* **X2Apic emulated in the hypervisor** (`main.rs:968`). This is the
  low-overhead path: LAPIC register reads/writes, ICR/IPIs, and TSC-deadline
  timer are serviced by the hypervisor with **no exit to tinyvmm**. OpenVMM only
  drops to a *software* APIC (`WHvX64LocalApicEmulationModeNone`,
  `lib.rs:1396`) when it needs VTL2 / full control — which tinyvmm does not.
  Keeping the in-hypervisor APIC is the right call.
* **MMIO doorbells on every virtio queue-notify** (`doorbell.rs`, wired at
  `main.rs:1097` and per device). This eliminates the single hottest exit (the
  per-kick `notify` write) and is exactly what OpenVMM does via its SynIC
  doorbell registration (`synic.rs:350`). This is the most important thing a WHP
  VMM can do for throughput, and tinyvmm already does it.
* **Large pages for guest RAM** (`memory.rs:187`) so SLAT/EPT is backed by 2 MiB
  super-pages — fewer page-walk cycles on every MMIO/DMA translation.
* **Allocation-free hot path + CPU pinning** (README §6; `main.rs:1589`).
* **Broad `X64MsrExit` + software `#GP` on unknown MSRs** (`run_loop.rs:341`,
  `hv.rs:142`). Given tinyvmm emulates the Hyper-V MSRs itself, trapping
  unhandled MSRs and injecting `#GP(0)` is correct and matches how a minimal
  enlightenment surface behaves.
* **Register writes are batched** per exit (e.g. CPUID writes RAX..RIP in one
  `WHvSetVirtualProcessorRegisters`, `run_loop.rs:297-310`) — no per-register
  syscalls.

### Small correctness / robustness notes (within current scope)

1. **CPUID is taken as an exit for *every* leaf even though a static result list
   exists.** `enable_extended_exits(cpuid=true)` forces all CPUID to exit
   (`main.rs:964`), and the run loop re-derives and re-writes results for leaves
   it does not actually modify (`cpuid.rs:200` `other => {}` returns the host
   default unchanged). The `CpuidResultList` is set but, because exits are
   global, it only pre-populates the exit's *default* fields. Net effect: correct
   results, but ~486 avoidable exits at boot (README §11). See §4 S1 — this is
   a free boot-latency win.
2. **MSI decode maps only Fixed/LowestPri/NMI/Init** (`msi.rs:28-34`). That is
   fine for virtio MSI-X, but note ExtINT/SMI are silently dropped (return
   `false`). For the current device set this is correct; worth a comment so a
   future device author does not assume full coverage.
3. **`on_translate_gva` fails closed** (`emulator.rs:243`, returns `E_NOTIMPL`).
   Correct for the current model (no device does GVA-relative DMA), but it means
   any future device that needs the emulator to walk guest page tables will fail.
   Keep this assumption documented.
4. **Save/restore does not capture a partition reference-time base.** OpenVMM
   sets `PartitionProperty::ReferenceTime` on restore (`vm_state.rs:74`) so the
   guest's Hyper-V clock does not jump. tinyvmm re-publishes the reference-TSC
   page with the *restore host's* scale (`hv.rs:197`), which handles TSC
   frequency but not the monotonic reference-time origin. Low impact for Linux;
   noted for completeness (§4 M3).

None of these are bugs for the supported workload; (1) is the only one with a
measurable, easy payoff.

---

## 3. Running a Windows guest — what is actually required

The known shortcoming ("can't run Windows guests") is **mostly a device-model and
firmware gap, not a WHP-core gap.** The WHP partition tinyvmm builds (x2apic,
CPUID/MSR exits, memory map, MSI, emulator) is already capable of hosting
Windows. What is missing falls into two buckets.

### 3a. WHP-layer pieces Windows needs that tinyvmm omits

* **Hyper-V SynIC + enlightenments.** Windows is a *heavily enlightened* guest:
  it expects a working synthetic interrupt controller (SINTx), synthetic timers,
  the VP-assist page, the reference-TSC page, and it issues hypercalls
  (`HvPostMessage`, `HvSignalEvent`, TLB-flush, cluster IPI). tinyvmm's
  enlightenment is a **stub** — the hypercall page just returns
  `HV_STATUS_INVALID_HYPERCALL_CODE` (`hv.rs:22`) and there is no SynIC. The
  clean WHP way to provide this is `SyntheticProcessorFeatures`
  (what OpenVMM does, `lib.rs:1493`), which makes the hypervisor synthesize the
  SynIC/timers/clocks exitlessly. Windows will *install* without all of it, but
  it will be slow and several inbox drivers (vmbus) will not bind.
* **Guest hypercall + unknown-SynIC-connection exits.** For vmbus you must take
  `HypercallExit` and `UnknownSynicConnection` (`lib.rs:1469,1490`) and run a
  dispatcher (`hypercalls.rs`). tinyvmm takes neither.
* **INIT-SIPI-SIPI AP bring-up to a real-mode trampoline.** Windows starts APs
  the architectural way (SIPI → 16-bit trampoline). tinyvmm starts vCPU0 at the
  PVH 32-bit entry and never exercises the reset/real-mode path
  (`boot/loader.rs setup_pvh_entry`). The in-hypervisor APIC handles INIT/SIPI,
  but the guest needs the reset vector + real-mode memory laid out, which the
  PVH loader does not do.

### 3b. Device-model / firmware pieces (the larger blocker)

Windows cannot PVH-boot. To boot at all it needs, none of which tinyvmm has:

* **Firmware**: UEFI (preferred) or legacy PCAT BIOS, plus the reset-vector
  boot flow. OpenVMM ships both (`vm/devices/firmware/firmware_uefi`,
  `.../firmware_pcat`). tinyvmm jumps straight to a Linux PVH entry.
* **Full ACPI**. tinyvmm builds only **RSDP + XSDT + MADT** (`boot/acpi.rs:1`).
  Windows additionally requires **FADT** (with PM1/SCI/PM-timer), a **DSDT**
  (AML device tree incl. PCI `_PRT` routing), **MCFG** (PCIe ECAM), and usually
  **HPET**. OpenVMM generates these (`vm/acpi`).
* **IO-APIC**. tinyvmm routes legacy lines through an 8259 PIC in virtual-wire
  mode (`devices/pic.rs`) and MSI for PCI. Windows' HAL expects an **IO-APIC**
  described in the MADT for line-based interrupts. tinyvmm has none.
* **Legacy chipset Windows pokes**: a *full* RTC/CMOS with periodic/alarm IRQ8
  (tinyvmm has only index/data stubs, `devices/legacy.rs:42`), PM timer,
  i8042 keyboard/mouse controller (none), and 8259+IO-APIC routing.
* **A boot disk with an inbox driver**: emulated **AHCI/SATA**, **IDE**, or
  **NVMe**, or vmbus **storvsp**. tinyvmm offers only **virtio-blk**, for which
  Windows has *no* inbox driver. Same for net (needs **netvsp** or an emulated
  e1000/NVMe-class NIC; virtio-net needs out-of-tree drivers) and display
  (needs VGA/`video_core`, not virtio-gpu).
* **Performant path** (optional but expected): **vmbus** channel protocol +
  **storvsp/netvsp/video**, which in turn need the SynIC from 3a.

### 3c. Honest recommendation for Windows

Two tiers:

* **Minimum bring-up (huge effort, ~"build a chunk of OpenVMM"):** UEFI firmware
  + FADT/MADT/DSDT/MCFG/HPET + IO-APIC + RTC/PIT/i8042 + an **NVMe** or **AHCI**
  boot device + a VGA framebuffer + INIT-SIPI real-mode trampoline. NVMe is the
  least new code because Windows has an inbox driver and it is MSI-X/PCI like the
  existing virtio transport.
* **Performant Windows (even larger):** add `SyntheticProcessorFeatures`
  enlightenment offload + hypercall/SynIC plumbing + vmbus + storvsp/netvsp.

This is squarely **against tinyvmm's "opinionated microVM" thesis** (README §0:
"no BIOS, no legacy/real-mode boot, no ACPI power management"). If the goal is
just *some* Windows, the WHP core does not block you — the firmware + ACPI +
NVMe/AHCI + IO-APIC device work does. I would not pursue it unless Windows is a
first-class product requirement; see §5 for a low-commitment spike.

---

## 4. Performance opportunities

tinyvmm already does the high-value things (doorbells, async IOCP block backend,
x2apic-in-hypervisor, large pages, CPU pinning, allocation-free data plane). The
following are incremental. **All are feasible with the current `windows-sys`
dependency** — every property/API named below is already exposed
(`WHvPartitionPropertyCodeCpuidExitList`, `...SyntheticProcessorFeaturesBanks`,
`...X64MsrExitBitmap`, `WHvMapGpaRange2`, `WHvCreateVirtualProcessor2`), so no
new crate is required.

### Simple

**S1 — Narrow CPUID exits with `CpuidExitList`; serve the rest exitlessly.**
Today every CPUID is an exit (~486 at boot, README §11), even for leaves tinyvmm
returns unchanged. Set `WHvPartitionPropertyCodeCpuidExitList` to *only* the
leaves whose result is per-vCPU or runtime-dynamic — `0x1` (APIC id in
EBX[31:24]), `0x6`, `0xB`/`0x1F` (x2apic topology), `0x15`/`0x16` (measured TSC),
the HV leaves `0x4000_0000..6`, and the snapshot magic leaf `0x4000_DE57` — and
move the static leaves into the **existing** `CpuidResultList` (`cpuid.rs:232`)
so the hypervisor answers them with **no exit**. Drop the global
`X64CpuidExit`.
*Benefit:* roughly 10× fewer CPUID exits → faster boot, especially with more
vCPUs. *Effort:* a few lines in `partition.rs` + `main.rs`. *Risk:* low. *Note:*
this trades away the ability to *mask* passthrough leaves (which a microVM does
not need; OpenVMM keeps global CPUID exits precisely because it does need masking
for migration/compat).

**S2 — Skip the redundant per-CPUID register write for unmodified leaves.** Even
if S1 is deferred, the run loop can return early without re-writing RAX..RDX when
`resolve_cpuid` did not change the WHP defaults (only advance RIP). Saves one
`WHvSetVirtualProcessorRegisters` per passthrough CPUID. *Effort:* trivial.
*Risk:* none.

**S3 — Coalesce the HLT/IF=1 spin.** `ExitReason::Halt` with `IF=1` simply
`continue`s (`run_loop.rs:181`). That is one exit per idle entry. It is *not* a
busy loop (the next `WHvRunVirtualProcessor` blocks), so the cost is small, but
it is removable via the guest-idle enlightenment in M1.

### Medium

**M1 — Offload Hyper-V enlightenments to the hypervisor via
`SyntheticProcessorFeatures` (highest-value item).** Replace the software MSR/TSC
emulation in `whp/hv.rs` with a partition property that makes WHP provide the
enlightenment surface **exitlessly**, mirroring OpenVMM (`lib.rs:1493-1564`).
For a Linux microVM the valuable bank-0 bits are:
`HypervisorPresent | Hv1 | AccessPartitionReferenceTsc | AccessFrequencyRegs |
AccessVpIndex | AccessVpRunTimeReg | TbFlushHypercalls | SyntheticClusterIpi |
AccessGuestIdleReg`.
*Benefit, concretely:*
  - `TbFlushHypercalls` + `SyntheticClusterIpi`: multi-vCPU Linux does remote
    **TLB shootdowns and IPIs as hypervisor hypercalls instead of real IPIs** —
    this is the big multi-vCPU scalability win (fewer cross-vCPU exits/interrupts).
  - `AccessPartitionReferenceTsc` + `AccessFrequencyRegs`: the reference-TSC page
    and TSC/APIC frequency come from the hypervisor — deletes tinyvmm's
    `write_reference_tsc_page` / MSR trapping and the boot-time MSR exits.
  - `AccessGuestIdleReg`: removes the HLT round-trip (S3).
*Caveat:* the vmbus-oriented bits (`SignalEvents`, `AccessSynicRegs`,
`AccessSyntheticTimerRegs`) imply VMM plumbing (PostMessage/SignalEvent) and are
**not** needed for Linux — do not enable those unless you build vmbus. When you
turn this on, let the hypervisor own the `0x4000_00xx` CPUID/MSR surface and
retire the corresponding overrides in `cpuid.rs`/`hv.rs`.
*Effort:* medium (gate behind a flag, verify guest still detects HV via CPUID,
delete SW paths once confirmed). *Risk:* medium — validate on your host build;
query `WHvCapabilityCodeSyntheticProcessorFeaturesBanks` first and only set
supported bits (OpenVMM does exactly this, `lib.rs:1476`).

**M2 — Reduce MSI injection syscalls for high-rate IRQs.** Each MSI is a
`WHvRequestInterrupt` syscall (`msi.rs:47`). For the current devices that is
fine, but for fast virtio-net/blk you can (a) honor virtio **EVENT_IDX** /
interrupt suppression so the guest asks for fewer completions, and (b) batch
used-ring updates so you raise one MSI per drain, not per descriptor. This is
device-side but it directly cuts host syscalls. *Effort:* medium. *Risk:* low.

**M3 — Restore a partition reference-time base** with
`WHvPartitionPropertyCodeReferenceTime` (`vm_state.rs:74`) so a restored guest's
Hyper-V clock does not discontinuously jump. *Effort:* small-medium. *Risk:* low.
Mostly matters if/when M1 lands (the guest then trusts the HV clock more).

**M4 — Cut cold-start for large RAM.** `guest RAM mapped` dominates host setup
(~59 ms / 256 MiB, README §12) because large-page RAM is **eagerly committed and
locked** (`memory.rs:187`). Options: (a) only large-page-back the low region the
kernel touches at boot and 4 KiB-back the rest (4 KiB `MEM_COMMIT` is lazy —
pages fault in on first touch, deferring the cost); (b) parallelize the
commit/pre-touch across threads. *Benefit:* faster boot for big VMs.
*Trade-off:* large pages reduce *steady-state* SLAT cost, so this is a
boot-latency-vs-runtime knob, not a strict win — expose it as a policy.

### Complex

**C1 — Dirty-page tracking for incremental snapshot / live migration.** WHP
exposes `WHvMapGpaRangeFlagTrackDirtyPages` (`vm/whp/src/abi.rs:178`) +
`WHvQueryGpaRangeDirtyBitmap`. Today `--save` writes the whole RAM image; dirty
tracking enables iterative/precopy snapshots and would shrink snapshot files and
pause times. *Effort:* high. *Risk:* medium.

**C2 — `WHvMapGpaRange2` + sparse backing.** OpenVMM maps via `WHvMapGpaRange2`
over a sparse allocation (`vm/whp/src/lib.rs:542`; `virt_whp/src/memory.rs:14`
`SharedMem`). This enables demand-committed RAM, cross-process backing, and
overlay pages. Adopting it would generalize M4 and is a prerequisite for some
Windows/VTL features. *Effort:* high (touches the whole `GuestMemory` design).

**C3 — Windows guest enablement** (see §3): firmware + full ACPI + IO-APIC +
RTC/i8042 + NVMe/AHCI + (for speed) SynIC/vmbus/storvsp/netvsp. *Effort:* very
high; arguably out of charter. A scoped first step is in §5.

**C4 — Nested virtualization** (`PartitionProperty::NestedVirtualization`,
`lib.rs:1373`, + enlightened VMCS) if running nested hypervisors ever matters.
*Effort:* high. *Risk:* high. Likely out of charter.

---

## 5. Prioritized recommendations

| # | Change | Bucket | Payoff | Effort | Recommend? |
|---|---|---|---|---|---|
| S1 | `CpuidExitList` + exitless static CPUID | Simple | ~10× fewer boot CPUID exits | hours | **Yes** |
| S2 | Skip redundant CPUID reg writes | Simple | minor, free | minutes | **Yes** |
| M1 | `SyntheticProcessorFeatures` enlightenment offload (TLB/IPI/clock/idle) | Medium | **multi-vCPU scaling**, fewer MSR exits, deletes SW HV code | days | **Yes (highest value)** |
| M2 | virtio EVENT_IDX + IRQ batching | Medium | fewer MSI syscalls on fast I/O | days | Yes, if net/blk perf matters |
| M3 | `ReferenceTime` on restore | Medium | clock fidelity after restore | hours | Nice-to-have |
| M4 | Large-RAM cold-start policy | Medium | faster boot of big VMs | days | If big VMs matter |
| C1 | Dirty-page tracking / incremental snapshot | Complex | smaller/faster snapshots | weeks | Later |
| C2 | `WHvMapGpaRange2` + sparse RAM | Complex | demand RAM, enables more | weeks | Later |
| C3 | Windows guest (firmware/ACPI/IO-APIC/NVMe/vmbus) | Complex | new capability | months | Only if a product goal |
| C4 | Nested virtualization | Complex | nested hypervisors | weeks | Probably no |

**Suggested order:** S2 → S1 → M1 (behind a capability probe + flag) → measure.
S1+M1 together remove most boot-time exits *and* most multi-vCPU steady-state
cross-CPU exits, which are the two things a WHP microVM can still meaningfully
improve.

**If you want to test the Windows waters cheaply:** the smallest informative
spike is **UEFI + FADT/MADT/DSDT/MCFG + IO-APIC + an NVMe boot disk** (NVMe is
PCI/MSI-X like the existing transport and has an inbox Windows driver). That is
enough to see Windows setup start, and it tells you exactly how much of §3b you'd
have to commit to. Leave SynIC/vmbus (the performant path) for later.

---

## Appendix — key citations

**tinyvmm**
- Partition properties / setup: `crates/whpsys/src/partition.rs:32,52,70,76,104`
- Partition wiring (exits, x2apic, static CPUID): `src/main.rs:963-969`
- vCPU + save/restore (xsave, interrupt controller state2): `crates/whpsys/src/vcpu.rs:144,194,242`
- Run loop (exit dispatch, CPUID/MSR/HLT, #GP inject): `src/whp/run_loop.rs:147-381`
- CPUID policy + static result list: `src/whp/cpuid.rs:92,232`
- Software Hyper-V enlightenment (stub hypercall page, ref-TSC, MSRs): `src/whp/hv.rs:22,85,108`
- MMIO doorbell (exitless notify): `crates/whpsys/src/doorbell.rs`
- MSI → interrupt: `crates/whpsys/src/msi.rs:19-58`
- Guest RAM (eager commit, large pages, MMIO-hole split): `crates/whpsys/src/memory.rs:76,101,187`
- Minimal ACPI (RSDP+XSDT+MADT only): `src/boot/acpi.rs:1-92`

**OpenVMM (`C:\openvmm`)**
- Partition setup (all properties, exits, synthetic features): `vmm_core/virt_whp/src/lib.rs:1363-1580`
- Software-or-hypervisor APIC: `vmm_core/virt_whp/src/apic.rs:5`
- SynIC + doorbell registration: `vmm_core/virt_whp/src/synic.rs:342-410`
- Hypercall dispatcher: `vmm_core/virt_whp/src/hypercalls.rs`, `vmm_core/virt_whp/src/vp.rs:585`
- Exit handling: `vmm_core/virt_whp/src/vp.rs:564-609`
- Memory (`WHvMapGpaRange2`, sparse, dirty flag): `vm/whp/src/lib.rs:336,542`; `vm/whp/src/abi.rs:174-178`; `vmm_core/virt_whp/src/memory.rs:14`
- Reference-time on restore: `vmm_core/virt_whp/src/vm_state.rs:74`
- Windows-enabling device crates: `vm/devices/firmware/firmware_uefi`, `.../firmware_pcat`, `vm/acpi`, `vm/devices/storage/{ide,scsidisk,storvsp}`, `vm/devices/net/netvsp`, `vm/devices/video_core`, `vm/devices/chipset`
