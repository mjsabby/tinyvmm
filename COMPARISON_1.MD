# tinyvmm vs OpenVMM WHP comparison

Date: 2026-06-08

Scope: compare tinyvmm's WHP/WHVP core hypervisor infrastructure against OpenVMM at `C:\openvmm`, with emphasis on the features tinyvmm intentionally supports today, the known Windows guest gap, and practical performance improvements.

## Executive summary

tinyvmm is doing the right WHP things for its stated Linux PVH microVM target. The core setup is clean and intentionally small: create a WHP partition, enable CPUID/MSR exits, set a static CPUID result list, use WHP x2APIC emulation, map guest RAM with large pages when possible, run one host thread per vCPU, dispatch PIO/MMIO through the WHP instruction emulator, inject MSI/MSI-X through `WHvRequestInterrupt`, and use WHP MMIO doorbells on hot virtio notify paths.

The main gap versus OpenVMM is not one missing WHP call; it is machine scope. OpenVMM has a general PC/hypervisor stack: richer partition property programming, optional in-VMM APIC, Hyper-V synthetic feature offload, hypercall/SynIC/synthetic timer support, VTL/intercept machinery, GPA fault population, notification ports/triggers, virtual/assigned PCI device flows, and many Windows-specific MSR/CPUID quirks. tinyvmm deliberately omits most of that. That is fine for Linux PVH, but it explains why Windows guests are currently out of scope.

Performance-wise, tinyvmm already has several good choices: large-page RAM, direct host pointers for guest RAM access, preallocated/reused virtqueue scratch, IOCP-based disk/network/9p backends, no Tokio, vCPU affinity support, and WHP doorbells for queue kicks. The best next wins are: use WHP GPA pre-populate/pin where available, add faster direct PIO/MMIO handling for common non-string accesses instead of always going through `WHvEmulatorTry*`, reduce per-interrupt MSI-X locking, and add OpenVMM-style fault-first GPA population before emulation.

## What tinyvmm is doing right for supported features

### WHP partition and vCPU setup

tinyvmm's partition setup is appropriate for a Linux PVH microVM:

- `crates/whpsys/src/partition.rs` wraps `WHvCreatePartition`, `WHvSetPartitionProperty`, `WHvSetupPartition`, `WHvDeletePartition`, processor count, extended exits, exception bitmap, local APIC emulation mode, CPUID result list, and `AllowDeviceAssignment`.
- `src/main.rs` uses the wrapper in both fresh boot and restore: `Partition::new`, `enable_extended_exits(true, true, false)`, `set_cpuid_result_list`, `set_local_apic_emulation(WHvX64LocalApicEmulationModeX2Apic)`, and `setup`.
- `crates/whpsys/src/vcpu.rs` wraps VP create/delete, run/cancel, register get/set, XSAVE state, and interrupt-controller state.
- `src/main.rs` creates one `Vcpu` per virtual CPU and runs APs on named host threads; BSP runs on the main thread. vCPU affinity is supported through `--cpu-affinity` and `winsys::cpu_affinity`.

This matches the OpenVMM basics. OpenVMM's lower-level WHP wrapper has the same core shape in `C:\openvmm\vm\whp\src\lib.rs`: `PartitionConfig::new`, `set_property`, `create`, `create_vp`, `delete_vp`, `map_range`, `unmap_range`, and interrupt injection.

### Guest memory

tinyvmm uses a simple, fast memory model:

- `crates/whpsys/src/memory.rs` allocates one contiguous host VA slab with `VirtualAlloc`.
- It tries `MEM_LARGE_PAGES` when `SeLockMemoryPrivilege` is available.
- `GuestMemory::new_split` maps RAM around the 32-bit PCI MMIO hole: low RAM at GPA 0 and the remainder above 4 GiB.
- Guest memory accessors return direct host pointers after bounds checks, which keeps virtio data paths simple and cheap.

This is exactly the right baseline for a non-isolated, single-process microVM. OpenVMM has a more general mapper (`C:\openvmm\vmm_core\virt_whp\src\memory.rs`) because it supports overlays, deferred mapping, VTL protection, accepted/unaccepted page state, remote process mapping through `WHvMapGpaRange2`, and inspection. tinyvmm does not need that complexity unless it adds Windows/VBS-style features, ROM overlays, or a richer device-assignment model.

### Exit loop and emulation

tinyvmm's run loop is intentionally straightforward:

- `src/whp/run_loop.rs` handles `Halt`, `IoPort`, `Memory`, `Cpuid`, `Msr`, `InterruptWindow`, `ApicEoi`, `Canceled`, and unknown exits.
- `crates/whpsys/src/emulator.rs` centralizes `WHvEmulatorCreateEmulator`, `WHvEmulatorTryIoEmulation`, `WHvEmulatorTryMmioEmulation`, and the emulator register callbacks.
- PIO/MMIO exits dispatch into `IoBus` and `MmioBus`.
- Unknown MSRs inject `#GP(0)` rather than being silently ignored.

That is the correct safe default. The main performance tradeoff is that every IO/MMIO exit goes through the WHP emulator, even for simple scalar accesses where the exit context already contains enough information. OpenVMM avoids that for common port IO: `C:\openvmm\vmm_core\virt_whp\src\vp.rs` handles non-string, non-REP IO directly and only invokes its emulator for string/REP IO.

### CPUID and Hyper-V timing surface

For Linux PVH, tinyvmm has the right minimal CPUID/MSR surface:

- `src/whp/cpuid.rs` advertises invariant TSC, ARAT, topology leaves, TSC frequency leaves, the hypervisor bit, and minimal Hyper-V leaves.
- It deliberately hides TSC deadline in the configured paths, presumably because the LAPIC timer behavior is delegated to WHP and the current stack is conservative.
- `src/whp/hv.rs` implements the Hyper-V guest OS ID, hypercall page, VP index, reference time count, reference TSC page, and TSC invariant control MSRs.
- Reference TSC page generation uses the measured TSC frequency and publishes a stable sequence.

That is enough for Linux to use a good clock source and avoid expensive time MSR exits after it switches to the reference TSC page.

OpenVMM's equivalent is much broader. When enlightenment offload is enabled, `C:\openvmm\vmm_core\virt_whp\src\lib.rs` programs synthetic processor features such as `Hv1`, reference counter/TSC access, hypercall registers, VP index, SynIC, synthetic timers, frequency regs, signal events, synthetic IPI, and retarget-device-interrupt. That broader feature set is part of why Windows works there.

### Interrupts and APIC

tinyvmm has a correct modern interrupt path for virtio:

- `src/pci/msix.rs` implements MSI-X table/PBA behavior and routes active vectors to WHP interrupt injection.
- `crates/whpsys/src/msi.rs` decodes x86 MSI address/data and calls `WHvRequestInterrupt`.
- Legacy PIC support exists for boot correctness and serial IRQs; the PIC also injects through `WHvRequestInterrupt`.
- WHP local APIC emulation is set to x2APIC.

For Linux virtio-pci/MSI-X, this is the right model. OpenVMM has more because it must support both offloaded and user-mode LAPIC modes (`C:\openvmm\vmm_core\virt_whp\src\apic.rs`), APIC MSR interception, interrupt-window exits, SynIC deliverability, and VTL forwarding.

### Virtio and doorbells

tinyvmm's virtio transport is strong for a microVM:

- `src/virtio/transport.rs` implements modern virtio-pci, 64-bit BARs, standard capabilities, MSI-X, and per-queue notification.
- It can install WHP MMIO doorbells for queue notify registers. Matching guest kicks signal a Windows event rather than causing a VM exit.
- The doorbell pump blocks indefinitely with no polling sweep and calls the existing `notify_queue` path.
- `src/virtio/queue.rs` uses split virtqueues, event index, release/acquire ordering, and reusable `ChainScratch` to avoid per-request allocation.

This is a real performance feature. OpenVMM also exposes WHP doorbell registration, plus newer notification ports/triggers. tinyvmm's current doorbell path is simpler and appropriate for its process model.

### Device assignment / DDA groundwork

tinyvmm has useful DDA probe infrastructure:

- `crates/whpsys/src/vpci.rs` wraps VPCI resource allocation, VPCI device creation, BAR/MMIO mapping, interrupt mapping, notifications, config/register access, and power state calls.
- `src/main.rs --dda-probe` sets `AllowDeviceAssignment` before partition setup, creates the VPCI device, probes BARs/MSI-X/config, and tests `WHvMapGpaRange2` for direct device MMIO mapping.

This is aligned with OpenVMM's VPCI support in `C:\openvmm\vm\whp\src\lib.rs` and assigned-device layer in `C:\openvmm\vmm_core\virt_whp\src\device.rs`. tinyvmm's missing piece is not the raw wrappers; it is integrating BAR assignment, ECAM/config access, interrupts, reset/power management, and guest-visible PCI topology into the actual VM run path.

## Main gaps vs OpenVMM

### 1. Windows guests need a PC platform, not just WHP

tinyvmm boots PVH Linux directly. It intentionally has no firmware, no real-mode/UEFI boot path, no ACPI power management, no general ACPI namespace, no HPET/RTC fidelity, no full PIT/PIC/IOAPIC platform, no PCI hotplug, no SMM, and no Windows boot storage/display/input model.

OpenVMM sits above WHP with a complete platform stack. From the WHP/core perspective, the relevant point is that Windows expects much more architectural surface before it ever gets to "normal" driver IO.

### 2. Hyper-V enlightenments are too small for Windows

tinyvmm advertises only a small Hyper-V surface in `src/whp/cpuid.rs` and handles only a handful of Hyper-V MSRs in `src/whp/hv.rs`.

OpenVMM either offloads or emulates a much larger Hyper-V contract:

- hypercall exits and dispatch (`C:\openvmm\vmm_core\virt_whp\src\hypercalls.rs`);
- SynIC, synthetic timers, direct event signaling, VP assist page, and message/event pages;
- synthetic processor feature programming through `PartitionProperty::SyntheticProcessorFeatures`;
- Hyper-V CPUID handling and VBS isolation reporting;
- unknown SynIC connection and VPCI retarget exits.

For Windows, the likely missing core pieces are SynIC, synthetic timers, VP assist page, crash MSRs, a fuller hypercall page/dispatcher, Hyper-V CPUID leaves, and Windows-specific MSR behavior.

### 3. MSR compatibility is too strict for Windows

tinyvmm injects #GP for unknown MSRs. That is architecturally clean and good for Linux, but Windows boot paths touch MSRs that OpenVMM explicitly tolerates:

- `C:\openvmm\vmm_core\virt_whp\src\vp.rs` returns zero for `IA32_PLATFORM_ID` because Windows requires it.
- It returns zero for `MSR_EBL_CR_POWERON`.
- It stubs a list of "mystery MSRs" seen during Windows PCAT BIOS boot.
- It handles Hyper-V crash MSRs.
- It has AMD-specific zero-return paths for several MSRs.

This is probably one concrete source of the "can't run Windows guests" gap, though not the only one.

### 4. No hypercall exit path

tinyvmm writes a hypercall page stub that returns invalid hypercall. That is enough for Linux when only the advertised minimal features are used.

OpenVMM enables `HypercallExit` when needed and dispatches many hypercalls: post/signal event, get/set VP registers, retarget device interrupt, install intercept, translate virtual address, synthetic interrupt, start VP, VTL operations, page acceptance/visibility, and VBS reporting.

Windows expects a meaningful subset of this once Hyper-V enlightenments are advertised.

### 5. No SynIC / synthetic timers

tinyvmm relies on WHP LAPIC emulation and Linux behavior. It does not implement SynIC message/event pages or synthetic timer MSRs.

OpenVMM has SynIC ports, event signaling, notification ports/triggers, SINT deliverability handling, and synthetic timer save/restore. This is central to Hyper-V-compatible Windows guest behavior and to efficient paravirtual device signaling in a Hyper-V-style stack.

### 6. Memory management lacks WHP population/pinning and fault classification

tinyvmm maps all guest RAM up front and then treats memory exits as MMIO. That works for the current RAM/MMIO model.

OpenVMM does more:

- `WHvAdviseGpaRange` populate/pin wrappers in `C:\openvmm\vm\whp\src\lib.rs`;
- `prefetch_range` / `pin_range` hooks in `C:\openvmm\vmm_core\virt_whp\src\memory.rs`;
- memory exit handling first tries `populate_ranges` for mapped RAM that simply missed in SLAT, avoiding emulation;
- range tracking classifies RAM, monitor page, unmapped, VTL-protected, and unaccepted pages.

tinyvmm can borrow the populate/pin pieces without adopting VTL complexity.

### 7. APIC mode is fixed

tinyvmm always chooses WHP x2APIC emulation. That is fine for the current Linux target.

OpenVMM can choose xAPIC, x2APIC, or no WHP APIC when it uses its own user-mode APIC. User-mode APIC is more complex but unlocks intercept/control paths needed by some Hyper-V/VTL flows.

### 8. VPCI/DDA is probe-only

tinyvmm has raw VPCI wrappers and a good probe. OpenVMM has an integrated assigned-device object that handles physical config reads/writes, BAR intercepts, power state, MMIO mappings, MSI mapping/unmapping, retargeting, and command/BAR state.

For passthrough performance, the next step is integration rather than more probing.

## Performance findings and opportunities

### Already-good choices

- **Large pages:** `GuestMemory` tries `MEM_LARGE_PAGES`, reducing EPT/SLAT pressure.
- **Direct guest memory access:** virtio devices get host pointers to guest buffers after bounds checks.
- **Doorbells:** queue notify writes for hot devices can avoid VM exits entirely.
- **Event index:** virtqueues advertise and use `VIRTIO_RING_F_EVENT_IDX`.
- **Reusable scratch:** `ChainScratch` and device queues avoid per-request descriptor allocations.
- **Async Windows IO without a generic runtime:** blk/NAT/9p use IOCP-style workers rather than parking vCPU threads on blocking host IO.
- **Thread affinity:** vCPU threads can be pinned to all/P/E/P-physical CPU sets.
- **ETW/counters:** VM exit, MSI, and doorbell counters give a path to measure regressions.

### Simple improvements

1. **Add WHP capability dump to `--smoke` / startup diagnostics.** tinyvmm checks hypervisor presence and DDA feature bits in probe paths, but OpenVMM queries many capabilities. Dumping `WHvCapabilityCodeFeatures`, `ExtendedVmExits`, GPA populate flags, processor clock frequency, interrupt clock frequency, processor vendor/features, synthetic feature banks, and physical address width would make host-dependent behavior easier to reason about.

2. **Use WHP's processor clock frequency capability before local TSC measurement.** `src/whp/cpuid.rs` currently uses CPUID leaves or a sleep calibration. OpenVMM exposes `processor_clock_frequency()`. If available, prefer WHP's value for the guest CPUID frequency leaves and reference TSC scale; fall back to the current path.

3. **Add Windows MSR telemetry mode.** Before trying to support Windows, add an option that logs unknown MSRs/CPUID leaves and either still injects #GP or optionally returns zero for a narrow allowlist. This would quickly confirm which OpenVMM Windows quirks are hit.

4. **Make the TSC deadline decision explicit.** tinyvmm hides TSC deadline in current setup. Document whether this is due to WHP LAPIC timer behavior or Linux stability. If it is no longer required, exposing TSC deadline could improve timer behavior.

5. **Tighten MSI-X hot path.** `src/pci/msix.rs::trigger` locks the table to test mask/PBA and then locks again in `do_inject` to read address/data. Cache unmasked vector routes in atomics or a small per-vector route snapshot updated on table writes, so hot injections avoid the table mutex.

6. **Use `WHvGetInterruptTargetVpSet` for diagnostics.** OpenVMM wraps it. For difficult MSI routing bugs, exposing a debug-only check would help validate logical/physical destination behavior.

### Medium improvements

1. **Direct-handle simple IO exits.** Borrow OpenVMM's split: direct-emulate scalar, non-string, non-REP port IO using the WHP IO exit context, and reserve the WHP emulator for string/REP or unusual cases. This removes emulator callback overhead from PCI config, serial, PIT, PIC, and port `0x80` traffic.

2. **Try GPA population before MMIO emulation.** On memory exits where WHP says the GPA is mapped but not populated, call `WHvAdviseGpaRange(WHvAdviseGpaRangeCodePopulate)` and resume if it succeeds. OpenVMM does exactly this before falling back to emulation. This can reduce expensive false MMIO paths caused by SLAT population misses.

3. **Prefetch/pin hot RAM ranges.** Add wrappers for `WHvAdviseGpaRange` populate/pin and use them for the kernel/initrd loaded ranges, virtqueue rings, used/avail pages, and possibly high-rate device buffers. This is especially attractive for blk/net/9p microbenchmarks.

4. **Add `WHvMapGpaRange2` wrapper to normal memory mapping.** tinyvmm only exercises `WHvMapGpaRange2` in DDA probe. A general wrapper would prepare for file-backed/remote-process/shared-memory mappings and keep parity with OpenVMM's map API.

5. **Batch register updates with dirty tracking.** CPUID/MSR handlers already batch several registers in one `set_registers` call, which is good. If a real hypercall dispatcher is added, use OpenVMM's dirty-register pattern: track which GP/XMM/RIP registers changed and flush only those.

6. **Improve IO/MMIO bus lookup if device count grows.** Current bus dispatch appears simple and is fine for the current small device set. If GPU/DDA/many devices increase MMIO ranges, move toward sorted ranges or interval lookup like OpenVMM's memory/overlay state.

7. **Per-vector or lock-free MSI-X route cache.** This is the fuller version of the simple MSI-X change: maintain atomically readable route entries and only lock on table/PBA mutation.

8. **Selective Hyper-V offload.** If WHP synthetic processor features are available, experiment with offloading reference time/VP index/hypercall/SynIC pieces instead of emulating all of them. This is complex enough to gate behind a feature flag.

### Complex improvements

1. **Real Windows guest bring-up track.** This is a product-sized feature, not a bug fix. Minimum likely components:
   - UEFI or another Windows-compatible boot path;
   - ACPI tables suitable for Windows, including power/reset/shutdown paths;
   - a Windows-usable boot disk controller path;
   - fuller CPUID/MSR policy;
   - Hyper-V SynIC, synthetic timers, VP assist page, crash MSRs, and a real hypercall dispatcher;
   - APIC/IOAPIC/interrupt model compatible with Windows expectations;
   - device model choices Windows has in-box drivers for, or virtio-win installation assumptions.

2. **OpenVMM-style Hyper-V core layer.** Add an internal layer that owns Hyper-V CPUID/MSR/hypercall/SynIC/synthetic timer state separately from the WHP wrapper and device model. This avoids growing ad hoc MSR handling inside `run_loop.rs`.

3. **User-mode APIC option.** OpenVMM can choose WHP APIC offload or user-mode APIC. A user-mode APIC gives more control over APIC MSRs, EOI, interrupt windows, and VTL/intercept behavior, but it is large and bug-prone. Only do this if Windows/VTL/nested-virt work requires it.

4. **Integrated DDA/VPCI runtime.** Move from `--dda-probe` to an assigned-device implementation:
   - allocate/create VPCI before setup with `AllowDeviceAssignment`;
   - expose ECAM/config space to the guest;
   - manage BAR assignment, high MMIO windows, resizable BARs, and option ROM/VBIOS where needed;
   - map BARs directly into guest GPA with `WHvMapGpaRange2` when supported;
   - map/unmap MSI/MSI-X interrupts;
   - implement FLR/power-state/reset and safe teardown.

5. **Save/restore and migration parity.** tinyvmm has snapshot support. OpenVMM's WHP wrapper additionally exposes partition time suspend/resume and migration handles. If snapshot/migration becomes a performance or correctness focus, compare those APIs directly.

6. **Dirty/access tracking strategy.** WHP does not give a simple complete dirty-page engine in the code inspected. OpenVMM's core uses mapping/protection/acceptance state rather than a plain dirty bitmap in this backend. For tinyvmm, dirty tracking would likely require write-protect/remap techniques, device-level tracking, or a higher-level snapshot strategy.

## Windows guest gap: likely WHP/core checklist

If the goal is to experiment toward Windows while staying WHP-first, a realistic staged checklist is:

1. Log unknown Windows CPUID/MSR exits under the current code.
2. Add the small OpenVMM Windows MSR allowlist: `IA32_PLATFORM_ID`, `MSR_EBL_CR_POWERON`, crash MSRs, and the observed mystery MSRs.
3. Add real Hyper-V hypercall exit support instead of the invalid-hypercall stub.
4. Add SynIC MSRs, message/event pages, SINT deliverability, and synthetic timers.
5. Add VP assist page handling.
6. Expand Hyper-V CPUID leaves and synthetic feature programming, carefully avoiding advertising features until implemented.
7. Decide whether WHP APIC offload is sufficient or whether a user-mode APIC is needed.
8. Only after those core pieces, invest in firmware/ACPI/device model work for actual Windows boot.

The warning is important: Windows support will require features outside WHP core as well. WHP correctness is necessary but not sufficient.

## Prioritized recommendations

1. **Keep the current tinyvmm WHP architecture for Linux PVH.** It is appropriately small and has the right fast paths.
2. **Add WHP capability reporting and `WHvAdviseGpaRange` wrappers.** These are low-risk and useful immediately.
3. **Implement direct scalar PIO handling.** This is a contained performance win copied from OpenVMM's approach.
4. **Optimize MSI-X route lookup.** This should reduce interrupt injection overhead on blk/net/gpu/sound paths.
5. **Use GPA populate/pin for hot memory/ring ranges.** Measure with ETW exit counters and blk/net workloads.
6. **Treat Windows as a separate feature track.** Start with MSR/CPUID telemetry and Hyper-V core pieces; do not try to paper over it with broad zero-return MSR behavior.
7. **Continue DDA by integrating the existing probe into a runtime assigned-device model.** The raw WHP calls are mostly present; the guest-visible PCI/device lifecycle is the missing work.

## Source map

tinyvmm:

- WHP partition wrapper: `crates/whpsys/src/partition.rs`
- WHP vCPU wrapper: `crates/whpsys/src/vcpu.rs`
- guest memory mapping: `crates/whpsys/src/memory.rs`
- WHP instruction emulator wrapper: `crates/whpsys/src/emulator.rs`
- MSI injection: `crates/whpsys/src/msi.rs`
- WHP doorbells: `crates/whpsys/src/doorbell.rs`
- VPCI/DDA wrappers: `crates/whpsys/src/vpci.rs`
- run loop: `src/whp/run_loop.rs`
- CPUID policy: `src/whp/cpuid.rs`
- Hyper-V MSR/reference TSC surface: `src/whp/hv.rs`
- virtio-pci transport and doorbell pump: `src/virtio/transport.rs`
- virtqueue implementation: `src/virtio/queue.rs`
- MSI-X table/PBA: `src/pci/msix.rs`
- boot/restore partition setup and vCPU threading: `src/main.rs`

OpenVMM:

- WHP wrapper and capability/property coverage: `C:\openvmm\vm\whp\src\lib.rs`, `C:\openvmm\vm\whp\src\partition_prop.rs`
- WHP VMM core: `C:\openvmm\vmm_core\virt_whp\src\lib.rs`
- VP run loop and exit handlers: `C:\openvmm\vmm_core\virt_whp\src\vp.rs`
- memory mapping, overlays, GPA classification, populate/pin hooks: `C:\openvmm\vmm_core\virt_whp\src\memory.rs`
- APIC handling: `C:\openvmm\vmm_core\virt_whp\src\apic.rs`
- hypercall dispatcher and dirty register flushing: `C:\openvmm\vmm_core\virt_whp\src\hypercalls.rs`
- VPCI/assigned-device layer: `C:\openvmm\vmm_core\virt_whp\src\device.rs`
- SynIC/doorbell integration: `C:\openvmm\vmm_core\virt_whp\src\synic.rs`
