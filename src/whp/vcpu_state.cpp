#include "vcpu_state.h"

#include "common.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <exception>
#include <span>
#include <vector>

namespace tinyvmm::whp::snapshot {

// Architectural register set. Order is part of the snapshot ABI in
// VCPU_REGS sections, but each WHV_REGISTER_NAME is tagged on the wire
// so we can safely re-order at read time; the on-write order is just
// "what the writer happened to choose". Keep this list stable so newly
// captured snapshots remain reasonable to diff against older ones.
const WHV_REGISTER_NAME kArchRegNames[] = {
    // GPRs
    WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRbx,
    WHvX64RegisterRsp, WHvX64RegisterRbp, WHvX64RegisterRsi, WHvX64RegisterRdi,
    WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
    WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15,
    WHvX64RegisterRip, WHvX64RegisterRflags,
    // Segments
    WHvX64RegisterEs, WHvX64RegisterCs, WHvX64RegisterSs, WHvX64RegisterDs,
    WHvX64RegisterFs, WHvX64RegisterGs, WHvX64RegisterLdtr, WHvX64RegisterTr,
    // Tables
    WHvX64RegisterIdtr, WHvX64RegisterGdtr,
    // Control
    WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3, WHvX64RegisterCr4,
    WHvX64RegisterCr8, WHvX64RegisterXCr0,
    // Debug
    WHvX64RegisterDr0, WHvX64RegisterDr1, WHvX64RegisterDr2,
    WHvX64RegisterDr3, WHvX64RegisterDr6, WHvX64RegisterDr7,
    // MSR-as-register (excluding TSC family — those live in kTimingRegNames
    // so they can be applied LAST during restore)
    WHvX64RegisterEfer, WHvX64RegisterKernelGsBase, WHvX64RegisterApicBase,
    WHvX64RegisterPat,
    WHvX64RegisterSysenterCs, WHvX64RegisterSysenterEsp, WHvX64RegisterSysenterEip,
    WHvX64RegisterStar, WHvX64RegisterLstar, WHvX64RegisterCstar,
    WHvX64RegisterSfmask,
};

const WHV_REGISTER_NAME kTimingRegNames[] = {
    WHvX64RegisterTsc,
    WHvX64RegisterTscAux,
};

const WHV_REGISTER_NAME kIntrCtlRegNames[] = {
    WHvRegisterPendingInterruption,
    WHvRegisterInterruptState,
    WHvRegisterDeliverabilityNotifications,
    WHvRegisterInternalActivityState,
};

// M33.7: Supervisor MSRs. Order is part of the snapshot ABI but per-
// register name tags on the wire allow safe re-order at read time.
//   - WHvX64RegisterXss (IA32_XSS, 0xDA0): supervisor XSAVE state enable
//   - WHvX64RegisterUCet (IA32_U_CET, 0x6A0): user CET config
//   - WHvX64RegisterSCet (IA32_S_CET, 0x6A2): supervisor CET config
//   - WHvX64RegisterSsp  (IA32_PL3_SSP, mirrors at runtime): user-mode
//     shadow stack pointer (current)
//   - WHvX64RegisterPl0Ssp..Pl3Ssp (IA32_PL0..3_SSP, 0x6A4..0x6A7):
//     per-privilege-level shadow stack pointers
//   - WHvX64RegisterInterruptSspTableAddr (IA32_INTERRUPT_SSP_TABLE_ADDR,
//     0x6A8): interrupt SSP table base
const WHV_REGISTER_NAME kSupervisorMsrNames[] = {
    WHvX64RegisterXss,
    WHvX64RegisterUCet,
    WHvX64RegisterSCet,
    WHvX64RegisterSsp,
    WHvX64RegisterPl0Ssp,
    WHvX64RegisterPl1Ssp,
    WHvX64RegisterPl2Ssp,
    WHvX64RegisterPl3Ssp,
    WHvX64RegisterInterruptSspTableAddr,
};

std::size_t kArchRegCount()    noexcept {
    return sizeof(kArchRegNames)    / sizeof(kArchRegNames[0]);
}
std::size_t kTimingRegCount()  noexcept {
    return sizeof(kTimingRegNames)  / sizeof(kTimingRegNames[0]);
}
std::size_t kIntrCtlRegCount() noexcept {
    return sizeof(kIntrCtlRegNames) / sizeof(kIntrCtlRegNames[0]);
}
std::size_t kSupervisorMsrCount() noexcept {
    return sizeof(kSupervisorMsrNames) / sizeof(kSupervisorMsrNames[0]);
}

void CaptureVcpuState(Vcpu& vp,
                      WHV_PARTITION_HANDLE part,
                      std::uint32_t vp_idx,
                      CapturedVcpuState& out) {
    out.arch.assign(kArchRegCount(), WHV_REGISTER_VALUE{});
    out.timing.assign(kTimingRegCount(), WHV_REGISTER_VALUE{});
    out.intr_ctl.assign(kIntrCtlRegCount(), WHV_REGISTER_VALUE{});
    out.intr_ctl_ok.assign(kIntrCtlRegCount(), false);
    out.sup_msr.assign(kSupervisorMsrCount(), WHV_REGISTER_VALUE{});
    out.sup_msr_ok.assign(kSupervisorMsrCount(), false);
    out.xsave.clear();
    out.apic.clear();

    vp.GetRegisters(
        std::span<const WHV_REGISTER_NAME>(kArchRegNames, kArchRegCount()),
        std::span<WHV_REGISTER_VALUE>(out.arch.data(), out.arch.size()));
    vp.GetRegisters(
        std::span<const WHV_REGISTER_NAME>(kTimingRegNames, kTimingRegCount()),
        std::span<WHV_REGISTER_VALUE>(out.timing.data(), out.timing.size()));
    for (std::size_t i = 0; i < kIntrCtlRegCount(); ++i) {
        try {
            out.intr_ctl[i] = vp.GetRegister(kIntrCtlRegNames[i]);
            out.intr_ctl_ok[i] = true;
        } catch (const std::exception& e) {
            std::fprintf(stderr,
                "[vcpu-state] WARN: get intr_ctl[%zu] (name=0x%08x) failed: %s\n",
                i, static_cast<unsigned>(kIntrCtlRegNames[i]), e.what());
            out.intr_ctl_ok[i] = false;
        }
    }
    // Supervisor MSRs: per-register get with ok bit. WHP rejects names it
    // doesn't implement (older WHP builds without CET support) with
    // HRESULT 0xC0350002 (WHV_E_UNKNOWN_PROPERTY); treat any failure as
    // "register not supported, skip on restore" and continue.
    for (std::size_t i = 0; i < kSupervisorMsrCount(); ++i) {
        try {
            out.sup_msr[i] = vp.GetRegister(kSupervisorMsrNames[i]);
            out.sup_msr_ok[i] = true;
        } catch (const std::exception&) {
            // Silent — these are optional; logging at every probe is noisy.
            out.sup_msr_ok[i] = false;
        }
    }

    UINT32 needed = 0;
    HRESULT hr = WHvGetVirtualProcessorState(
        part, vp_idx, WHvVirtualProcessorStateTypeXsaveState,
        nullptr, 0, &needed);
    if (needed == 0) {
        tinyvmm::Fatal(
            "[vcpu-state] WHvGetVirtualProcessorState(Xsave) query returned 0 bytes");
    }
    (void)hr;
    out.xsave.resize(needed);
    UINT32 actual = 0;
    hr = WHvGetVirtualProcessorState(
        part, vp_idx, WHvVirtualProcessorStateTypeXsaveState,
        out.xsave.data(), needed, &actual);
    tinyvmm::ThrowIfFailed(hr, "WHvGetVirtualProcessorState(Xsave) read");
    out.xsave.resize(actual);

    needed = 0;
    hr = WHvGetVirtualProcessorState(
        part, vp_idx, WHvVirtualProcessorStateTypeInterruptControllerState2,
        nullptr, 0, &needed);
    (void)hr;
    if (needed == 0) {
        out.apic.clear();
        return;
    }
    out.apic.resize(needed);
    hr = WHvGetVirtualProcessorState(
        part, vp_idx, WHvVirtualProcessorStateTypeInterruptControllerState2,
        out.apic.data(), needed, &actual);
    if (FAILED(hr)) {
        std::fprintf(stderr,
            "[vcpu-state] WARN: APIC state read failed (HRESULT=0x%08lX);"
            " skipping APIC capture\n",
            static_cast<unsigned long>(hr));
        out.apic.clear();
        return;
    }
    out.apic.resize(actual);
}

void ApplyVcpuStateNonTiming(Vcpu& vp,
                             WHV_PARTITION_HANDLE part,
                             std::uint32_t vp_idx,
                             const CapturedVcpuState& in) {
    if (in.arch.size() != kArchRegCount() ||
        in.intr_ctl.size() != kIntrCtlRegCount() ||
        in.intr_ctl_ok.size() != kIntrCtlRegCount()) {
        throw std::runtime_error(
            "ApplyVcpuStateNonTiming: CapturedVcpuState vector sizes do not match canonical");
    }
    // M33.7: sup_msr / sup_msr_ok are OPTIONAL. Pre-M33.7 snapshots and
    // pre-M33.7 callers that don't populate the vectors are tolerated:
    // we treat "vectors empty" as "no CET state to restore". When the
    // vectors are present they must match the canonical length so the
    // loop below indexes safely.
    if (in.sup_msr.size() != in.sup_msr_ok.size()) {
        throw std::runtime_error(
            "ApplyVcpuStateNonTiming: sup_msr/sup_msr_ok size mismatch");
    }
    if (!in.sup_msr.empty() && in.sup_msr.size() != kSupervisorMsrCount()) {
        throw std::runtime_error(
            "ApplyVcpuStateNonTiming: sup_msr size does not match canonical");
    }

    // 1. Arch first. Establishes XCR0/CR4/EFER/segments/ApicBase before
    //    XSAVE or APIC blob is applied.
    vp.SetRegisters(
        std::span<const WHV_REGISTER_NAME>(kArchRegNames, kArchRegCount()),
        std::span<const WHV_REGISTER_VALUE>(in.arch.data(), in.arch.size()));

    // 1.5 Supervisor MSRs (M33.7). MUST be applied BEFORE the XSAVE blob
    // so XRSTORS's compact-format validation against IA32_XSS / CET MSRs
    // sees a consistent state. Per-register set with WARN-on-failure so
    // an unsupported name on this WHP build doesn't fail the whole
    // restore. Empty `sup_msr_ok` (e.g. old snapshot without this
    // section) simply skips every register.
    for (std::size_t i = 0; i < in.sup_msr_ok.size(); ++i) {
        if (!in.sup_msr_ok[i]) continue;
        try {
            vp.SetRegister(kSupervisorMsrNames[i], in.sup_msr[i]);
        } catch (const std::exception& e) {
            std::fprintf(stderr,
                "[vcpu-state] WARN: set sup_msr[%zu] (name=0x%08x) failed: %s\n",
                i, static_cast<unsigned>(kSupervisorMsrNames[i]), e.what());
        }
    }

    // 2. XSAVE blob (safe because XCR0 + IA32_XSS + CET MSRs are set).
    //
    // Diagnostic env var (M33.7 keeps for future investigation):
    //   TINYVMM_DEBUG_XSAVE=1   -> log size + first 72 bytes of the blob
    //                              plus XSTATE_BV / XCOMP_BV. Useful when
    //                              kernels start reporting "Bad FPU state"
    //                              after restore on newer hardware that
    //                              advertises new XSAVE components.
    {
        char buf[8] = {};
        if (GetEnvironmentVariableA("TINYVMM_DEBUG_XSAVE", buf, sizeof(buf)) > 0 &&
            buf[0] != '0' && buf[0] != '\0') {
            const std::size_t dump = (std::min)(in.xsave.size(), std::size_t{72});
            std::fprintf(stderr,
                "[vcpu-state] vp=%u xsave size=%zu, first %zu bytes:\n  ",
                vp_idx, in.xsave.size(), dump);
            for (std::size_t k = 0; k < dump; ++k) {
                std::fprintf(stderr, "%02x ",
                             static_cast<unsigned>(in.xsave[k]));
                if ((k & 15) == 15) std::fprintf(stderr, "\n  ");
            }
            std::fprintf(stderr, "\n");
            if (in.xsave.size() >= 576) {
                std::uint64_t xstate_bv = 0, xcomp_bv = 0;
                std::memcpy(&xstate_bv, in.xsave.data() + 512, 8);
                std::memcpy(&xcomp_bv,  in.xsave.data() + 520, 8);
                std::fprintf(stderr,
                    "[vcpu-state] vp=%u XSTATE_BV=0x%016llx XCOMP_BV=0x%016llx\n",
                    vp_idx,
                    static_cast<unsigned long long>(xstate_bv),
                    static_cast<unsigned long long>(xcomp_bv));
            }
        }
    }
    {
        HRESULT hr_x = WHvSetVirtualProcessorState(
            part, vp_idx, WHvVirtualProcessorStateTypeXsaveState,
            in.xsave.data(),
            tinyvmm::util::checked_int_cast<UINT32>(in.xsave.size()));
        tinyvmm::ThrowIfFailed(hr_x, "WHvSetVirtualProcessorState(Xsave)");
    }

    // 3. APIC blob (safe because ApicBase is set; skipped if empty).
    if (!in.apic.empty()) {
        HRESULT hr = WHvSetVirtualProcessorState(
            part, vp_idx, WHvVirtualProcessorStateTypeInterruptControllerState2,
            in.apic.data(),
            tinyvmm::util::checked_int_cast<UINT32>(in.apic.size()));
        tinyvmm::ThrowIfFailed(hr, "WHvSetVirtualProcessorState(APIC)");
    }

    // 4. Interrupt-control synthetic registers, individually.
    for (std::size_t i = 0; i < kIntrCtlRegCount(); ++i) {
        if (!in.intr_ctl_ok[i]) continue;
        try {
            vp.SetRegister(kIntrCtlRegNames[i], in.intr_ctl[i]);
        } catch (const std::exception& e) {
            std::fprintf(stderr,
                "[vcpu-state] WARN: set intr_ctl[%zu] (name=0x%08x) failed: %s\n",
                i, static_cast<unsigned>(kIntrCtlRegNames[i]), e.what());
        }
    }
}

void ApplyVcpuStateTiming(Vcpu& vp,
                          WHV_PARTITION_HANDLE /*part*/,
                          std::uint32_t /*vp_idx*/,
                          const CapturedVcpuState& in) {
    if (in.timing.size() != kTimingRegCount()) {
        throw std::runtime_error(
            "ApplyVcpuStateTiming: CapturedVcpuState.timing size does not match canonical");
    }
    vp.SetRegisters(
        std::span<const WHV_REGISTER_NAME>(kTimingRegNames, kTimingRegCount()),
        std::span<const WHV_REGISTER_VALUE>(in.timing.data(), in.timing.size()));
}

void ApplyVcpuState(Vcpu& vp,
                    WHV_PARTITION_HANDLE part,
                    std::uint32_t vp_idx,
                    const CapturedVcpuState& in) {
    ApplyVcpuStateNonTiming(vp, part, vp_idx, in);
    // Timing registers LAST. Phase 33.6 SMP production restore skips
    // this back-compat wrapper and calls the two helpers separately so
    // it can apply timing back-to-back across every vCPU.
    ApplyVcpuStateTiming(vp, part, vp_idx, in);
}

}  // namespace tinyvmm::whp::snapshot
