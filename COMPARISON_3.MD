# OpenVMM vs. TinyVMM: WHP Implementation & Performance Comparison

This document compares the WHP (Windows Hypervisor Platform) integration in `C:\openvmm` and `C:\tinyvmm`. It focuses on core hypervisor infrastructure, the shortcomings preventing Windows guests from booting, and actionable performance improvements for OpenVMM based on TinyVMM's minimalist approach.

## 1. Core Hypervisor Infrastructure (WHVP)

* **OpenVMM (`vmm_core\virt_whp`)**: A highly abstract, multi-backend VMM. Its WHP implementation provides complex features like Virtual Trust Levels (VTLs), nested virtualization, and fine-grained memory/MSR intercepts. To support these, it often relies on heavy user-space emulation for components like the Local APIC and SynIC.
* **TinyVMM (`crates\whpsys` & `src\whp`)**: A minimalistic, purpose-built VMM. It uses a very thin wrapper over the Win32 WHVP APIs (`WHvCreatePartition`, `WHvRunVirtualProcessor`). It relies almost entirely on the in-kernel hypervisor for execution, routing only basic IO port and MMIO exits back to user mode.

## 2. Windows Guest Shortcomings

Neither VMM can currently boot modern Windows guests natively on WHP, but for different reasons:

* **OpenVMM**: It implements a very specific subset of Hyper-V hypercalls required for OpenHCL and Linux (e.g., `HvPostMessage`, `HvSignalEvent`). When Windows attempts to use other core enlightenments—such as synthetic timers, advanced partition capabilities, or nested virtualization SynIC ports (which OpenVMM explicitly marks as unsupported on Windows)—OpenVMM fails to service them, causing the guest to bugcheck.
* **TinyVMM**: Provides virtually zero hypercall emulation. Its Hyper-V enlightenment module (`tinyvmm\src\whp\hv.rs`) intercepts the hypercall MSR and simply injects a 6-byte stub (`mov eax, 2; ret`) which universally returns `HV_STATUS_INVALID_HYPERCALL_CODE`. It lacks VMBus and SynIC entirely, which Windows requires to boot.

## 3. Performance Improvements for OpenVMM

By contrasting OpenVMM with TinyVMM's direct approach, we can identify several performance optimizations for OpenVMM's WHP backend.

### Simple (Low Effort, High Impact)
**Pass-through Harmless MSRs & CPUID**
* **Finding**: TinyVMM manually implements the bare minimum MSRs (Reference TSC, Guest OS ID) and handles CPUID statically. OpenVMM intercepts and processes a vast array of MSRs in user-space (`virt_whp\src\vp.rs`), adding significant context-switch overhead.
* **Fix**: Aggressively filter MSR and CPUID intercepts. Rely on the `WHvPartitionPropertyCodeMsrActionList` to allow the hypervisor to handle or ignore non-critical MSRs directly in-kernel.

### Medium (Moderate Effort)
**Leverage In-Kernel APIC Emulation**
* **Finding**: TinyVMM explicitly sets `WHvX64LocalApicEmulationModeX2Apic` and relies entirely on WHP for APIC handling, bypassing user-mode exits for interrupts. OpenVMM contains logic for this, but frequently falls back to `user_mode_apic = true` (e.g., when offloading enlightenments is disabled, or to support nested virtualization).
* **Fix**: Prioritize the in-kernel WHP APIC emulator in OpenVMM. For scenarios where pure performance is needed (and nested virt isn't), forcefully disable user-mode APIC emulation. User-space APIC processing is one of the highest sources of VM exits in Windows guests.

### Complex (High Effort, High Impact)
**Eliminate User-Space VTL Modeling**
* **Finding**: TinyVMM does not implement VTLs, resulting in a tight, extremely fast run loop (`whp\run_loop.rs`). OpenVMM models VTL 0 and VTL 2 entirely in user-space (`vtl2_mapper.rs` and `vp.rs`). As OpenVMM's own documentation notes: *"Performance is not great due to the extra overhead of OpenVMM modeling VTLs, not the hypervisor."*
* **Fix**: For standard VMs (like a normal Windows guest) that do not require VBS/VTL2, bypass the VTL switching and memory mapping layers entirely. For guests that *do* require VTLs, push VTL state enforcement down into native WHP APIs (if available in newer Windows builds) rather than managing register states and page protections sequentially in user-mode.