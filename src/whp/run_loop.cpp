#include "run_loop.h"

#include "cpuid.h"
#include "diag/etw.h"

#include <cstdio>
#include <cstring>

namespace tinyvmm::whp {

namespace {

// RFLAGS.IF (bit 9). When clear, HLT genuinely halts the CPU forever -- no
// pending or future interrupt can wake it. We treat that case as a terminal
// "guest done" condition for now.
constexpr std::uint64_t kRflagsIf = 1ull << 9;

}  // namespace

const char* ExitReasonName(WHV_RUN_VP_EXIT_REASON reason) noexcept {
    switch (reason) {
        case WHvRunVpExitReasonNone:                    return "None";
        case WHvRunVpExitReasonMemoryAccess:            return "MemoryAccess";
        case WHvRunVpExitReasonX64IoPortAccess:         return "X64IoPortAccess";
        case WHvRunVpExitReasonUnrecoverableException:  return "UnrecoverableException";
        case WHvRunVpExitReasonInvalidVpRegisterValue:  return "InvalidVpRegisterValue";
        case WHvRunVpExitReasonUnsupportedFeature:      return "UnsupportedFeature";
        case WHvRunVpExitReasonX64InterruptWindow:      return "X64InterruptWindow";
        case WHvRunVpExitReasonX64Halt:                 return "X64Halt";
        case WHvRunVpExitReasonX64ApicEoi:              return "X64ApicEoi";
        case WHvRunVpExitReasonX64MsrAccess:            return "X64MsrAccess";
        case WHvRunVpExitReasonX64Cpuid:                return "X64Cpuid";
        case WHvRunVpExitReasonException:               return "Exception";
        case WHvRunVpExitReasonCanceled:                return "Canceled";
        default:                                        return "<unknown>";
    }
}

RunLoop::RunLoop(Vcpu& vcpu, devices::IoBus& io_bus, devices::MmioBus& mmio_bus)
    : vcpu_(vcpu), io_bus_(io_bus), mmio_bus_(mmio_bus) {
    WHV_EMULATOR_CALLBACKS cbs = {};
    cbs.Size = sizeof(cbs);
    cbs.WHvEmulatorIoPortCallback = &RunLoop::OnIoPortThunk;
    cbs.WHvEmulatorMemoryCallback = &RunLoop::OnMemoryThunk;
    cbs.WHvEmulatorGetVirtualProcessorRegisters = &RunLoop::OnGetRegistersThunk;
    cbs.WHvEmulatorSetVirtualProcessorRegisters = &RunLoop::OnSetRegistersThunk;
    cbs.WHvEmulatorTranslateGvaPage = &RunLoop::OnTranslateGvaThunk;

    HRESULT hr = WHvEmulatorCreateEmulator(&cbs, &emulator_);
    ThrowIfFailed(hr, "WHvEmulatorCreateEmulator");
}

RunLoop::~RunLoop() {
    if (emulator_ != nullptr) {
        WHvEmulatorDestroyEmulator(emulator_);
        emulator_ = nullptr;
    }
}

void RunLoop::RequestStop() {
    stop_requested_.store(true, std::memory_order_release);
    // Best-effort: poke the vCPU out of WHvRunVirtualProcessor. If the vCPU
    // isn't actually running this is harmless.
    try {
        vcpu_.Cancel();
    } catch (const HrError&) {
        // Race: vCPU may have already exited. Swallow.
    }
}

StopReason RunLoop::Run() {
    while (true) {
        if (stop_requested_.load(std::memory_order_acquire)) {
            return StopReason::Cancelled;
        }

        last_exit_ = {};
        vcpu_.Run(last_exit_);

        // Per-exit VERBOSE ETW event. Compiled in unconditionally; the
        // TraceLogging macro short-circuits when no session is listening
        // on the VmExit keyword at TRACE_LEVEL_VERBOSE, so the hot-path
        // cost is one pointer-load + compare.
        TINYVMM_ETW_VERBOSE_KW("VmExit", ::tinyvmm::diag::kw::VmExit,
            TraceLoggingUInt32(
                static_cast<std::uint32_t>(last_exit_.ExitReason), "reason"),
            TraceLoggingUInt64(
                static_cast<std::uint64_t>(last_exit_.VpContext.Rip), "rip"),
            TraceLoggingUInt32(
                last_exit_.VpContext.InstructionLength, "ilen"));

        switch (last_exit_.ExitReason) {
            case WHvRunVpExitReasonX64Halt: {
                halt_exits_.fetch_add(1, std::memory_order_relaxed);
                const bool if_set =
                    (last_exit_.VpContext.Rflags & kRflagsIf) != 0;
                if (if_set) {
                    // Normal idle: guest executed sti+hlt waiting for an IRQ.
                    // WHP's APIC emulation usually services pending interrupts
                    // in-hypervisor without exiting to user-mode; if it does
                    // bubble up, just re-enter the run loop and let WHP block
                    // on a pending interrupt.
                    break;
                }
                // IF=0: this is a real terminal halt (panic / shutdown).
                std::printf(
                    "[loop] HLT at RIP=0x%llx (IF=0) -- treating as terminal\n",
                    static_cast<unsigned long long>(last_exit_.VpContext.Rip));
                return StopReason::GuestHalted;
            }

            case WHvRunVpExitReasonX64IoPortAccess: {
                io_exits_.fetch_add(1, std::memory_order_relaxed);
                if (auto stop = HandleIoExit(last_exit_)) {
                    return *stop;
                }
                break;
            }

            case WHvRunVpExitReasonMemoryAccess: {
                mmio_exits_.fetch_add(1, std::memory_order_relaxed);
                if (auto stop = HandleMmioExit(last_exit_)) {
                    return *stop;
                }
                break;
            }

            case WHvRunVpExitReasonX64Cpuid: {
                cpuid_exits_.fetch_add(1, std::memory_order_relaxed);
                if (auto stop = HandleCpuidExit(last_exit_)) {
                    return *stop;
                }
                break;
            }

            case WHvRunVpExitReasonX64MsrAccess: {
                msr_exits_.fetch_add(1, std::memory_order_relaxed);
                if (auto stop = HandleMsrExit(last_exit_)) {
                    return *stop;
                }
                break;
            }

            case WHvRunVpExitReasonX64InterruptWindow:
                intwin_exits_.fetch_add(1, std::memory_order_relaxed);
                // Interrupt window opened; the IRQ injector will deliver on
                // the next loop iteration. No work here.
                break;

            case WHvRunVpExitReasonX64ApicEoi:
                apic_eoi_exits_.fetch_add(1, std::memory_order_relaxed);
                // No service today; APIC EOI plumbing isn't yet wired.
                break;

            case WHvRunVpExitReasonException:
                exception_exits_.fetch_add(1, std::memory_order_relaxed);
                std::fprintf(stderr,
                             "[loop] guest exception at RIP=0x%llx -- "
                             "no handler installed\n",
                             static_cast<unsigned long long>(
                                 last_exit_.VpContext.Rip));
                return StopReason::UnhandledExit;

            case WHvRunVpExitReasonUnsupportedFeature:
                unsupported_exits_.fetch_add(1, std::memory_order_relaxed);
                std::fprintf(stderr,
                             "[loop] WHP UnsupportedFeature at RIP=0x%llx\n",
                             static_cast<unsigned long long>(
                                 last_exit_.VpContext.Rip));
                return StopReason::UnhandledExit;

            case WHvRunVpExitReasonUnrecoverableException:
                unrecoverable_exits_.fetch_add(1, std::memory_order_relaxed);
                std::fprintf(stderr,
                             "[loop] WHP UnrecoverableException at RIP=0x%llx\n",
                             static_cast<unsigned long long>(
                                 last_exit_.VpContext.Rip));
                return StopReason::UnhandledExit;

            case WHvRunVpExitReasonInvalidVpRegisterValue:
                invalid_vp_reg_exits_.fetch_add(
                    1, std::memory_order_relaxed);
                std::fprintf(stderr,
                             "[loop] InvalidVpRegisterValue at RIP=0x%llx\n",
                             static_cast<unsigned long long>(
                                 last_exit_.VpContext.Rip));
                return StopReason::UnhandledExit;

            case WHvRunVpExitReasonCanceled:
                cancelled_exits_.fetch_add(1, std::memory_order_relaxed);
                // External Cancel(). If RequestStop was called, the top-of-loop
                // check will catch it. Otherwise it was an IRQ-injection kick;
                // fall through to next iteration.
                break;

            default:
                other_exits_.fetch_add(1, std::memory_order_relaxed);
                std::fprintf(stderr,
                             "[loop] unhandled exit reason %s (0x%x) at "
                             "RIP=0x%llx\n",
                             ExitReasonName(last_exit_.ExitReason),
                             static_cast<unsigned int>(last_exit_.ExitReason),
                             static_cast<unsigned long long>(
                                 last_exit_.VpContext.Rip));
                return StopReason::UnhandledExit;
        }
    }
}

std::optional<StopReason> RunLoop::HandleIoExit(
    const WHV_RUN_VP_EXIT_CONTEXT& exit) {
    WHV_EMULATOR_STATUS status = {};
    HRESULT hr = WHvEmulatorTryIoEmulation(emulator_, this, &exit.VpContext,
                                           &exit.IoPortAccess, &status);
    if (FAILED(hr)) {
        std::fprintf(stderr,
                     "[loop] WHvEmulatorTryIoEmulation HRESULT=0x%08lX\n",
                     static_cast<unsigned long>(hr));
        return StopReason::EmulationFailure;
    }
    if (!status.EmulationSuccessful) {
        std::fprintf(stderr,
                     "[loop] IO emulation failed (status=0x%08x) at RIP=0x%llx "
                     "port=0x%x\n",
                     status.AsUINT32,
                     static_cast<unsigned long long>(exit.VpContext.Rip),
                     exit.IoPortAccess.PortNumber);
        return StopReason::EmulationFailure;
    }
    return std::nullopt;
}

std::optional<StopReason> RunLoop::HandleMmioExit(
    const WHV_RUN_VP_EXIT_CONTEXT& exit) {
    WHV_EMULATOR_STATUS status = {};
    HRESULT hr = WHvEmulatorTryMmioEmulation(emulator_, this, &exit.VpContext,
                                             &exit.MemoryAccess, &status);
    if (FAILED(hr)) {
        std::fprintf(stderr,
                     "[loop] WHvEmulatorTryMmioEmulation HRESULT=0x%08lX\n",
                     static_cast<unsigned long>(hr));
        return StopReason::EmulationFailure;
    }
    if (!status.EmulationSuccessful) {
        std::fprintf(stderr,
                     "[loop] MMIO emulation failed (status=0x%08x) at "
                     "RIP=0x%llx GPA=0x%llx\n",
                     status.AsUINT32,
                     static_cast<unsigned long long>(exit.VpContext.Rip),
                     static_cast<unsigned long long>(
                         exit.MemoryAccess.Gpa));
        return StopReason::EmulationFailure;
    }
    return std::nullopt;
}

std::optional<StopReason> RunLoop::HandleCpuidExit(
    const WHV_RUN_VP_EXIT_CONTEXT& exit) {
    const auto& ctx = exit.CpuidAccess;
    const auto leaf    = static_cast<std::uint32_t>(ctx.Rax);
    const auto subleaf = static_cast<std::uint32_t>(ctx.Rcx);

    // WHP has already computed what it would natively return; layer our policy
    // on top.
    CpuidResult r = ResolveCpuid(
        leaf, subleaf,
        static_cast<std::uint32_t>(ctx.DefaultResultRax),
        static_cast<std::uint32_t>(ctx.DefaultResultRbx),
        static_cast<std::uint32_t>(ctx.DefaultResultRcx),
        static_cast<std::uint32_t>(ctx.DefaultResultRdx));

    if (verbose_cpuid_) {
        std::fprintf(stderr,
                     "[loop] cpuid leaf=0x%08x sub=0x%08x -> "
                     "eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x\n",
                     leaf, subleaf, r.eax, r.ebx, r.ecx, r.edx);
    }
    TINYVMM_ETW_VERBOSE_KW("Cpuid", ::tinyvmm::diag::kw::Cpuid,
        TraceLoggingUInt32(leaf,    "leaf"),
        TraceLoggingUInt32(subleaf, "subleaf"),
        TraceLoggingUInt32(r.eax,   "eax"),
        TraceLoggingUInt32(r.ebx,   "ebx"),
        TraceLoggingUInt32(r.ecx,   "ecx"),
        TraceLoggingUInt32(r.edx,   "edx"));

    // CPUID exits do not auto-advance RIP -- we must step over the 2-byte
    // CPUID instruction ourselves.
    const std::uint64_t next_rip =
        exit.VpContext.Rip + exit.VpContext.InstructionLength;

    static constexpr WHV_REGISTER_NAME kNames[] = {
        WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx,
        WHvX64RegisterRdx, WHvX64RegisterRip,
    };
    WHV_REGISTER_VALUE vals[5] = {};
    vals[0].Reg64 = r.eax;
    vals[1].Reg64 = r.ebx;
    vals[2].Reg64 = r.ecx;
    vals[3].Reg64 = r.edx;
    vals[4].Reg64 = next_rip;

    try {
        vcpu_.SetRegisters(kNames, vals);
    } catch (const HrError& e) {
        std::fprintf(stderr,
                     "[loop] CPUID set-regs failed at RIP=0x%llx: HRESULT=0x%08lX\n",
                     static_cast<unsigned long long>(exit.VpContext.Rip),
                     static_cast<unsigned long>(e.hr()));
        return StopReason::EmulationFailure;
    }
    return std::nullopt;
}

std::optional<StopReason> RunLoop::HandleMsrExit(
    const WHV_RUN_VP_EXIT_CONTEXT& exit) {
    const auto& ctx = exit.MsrAccess;
    const std::uint32_t msr     = ctx.MsrNumber;
    const bool          is_wr   = (ctx.AccessInfo.IsWrite != 0);
    const std::uint64_t wr_val  = ((ctx.Rdx & 0xFFFFFFFFull) << 32) |
                                  (ctx.Rax & 0xFFFFFFFFull);

    // If no enlightenment object is wired (e.g. unit tests bringing the
    // partition up without a guest), fall through to unhandled so the
    // failure is visible.
    if (hv_ == nullptr) {
        std::fprintf(stderr,
                     "[loop] MSR exit with no enlightenment wired: "
                     "%s msr=0x%08x at RIP=0x%llx\n",
                     is_wr ? "WRMSR" : "RDMSR", msr,
                     static_cast<unsigned long long>(exit.VpContext.Rip));
        return StopReason::UnhandledExit;
    }

    std::uint64_t rd_val = 0;
    MsrHandled result;
    if (is_wr) {
        result = hv_->HandleWrmsr(vcpu_.index(), msr, wr_val);
    } else {
        result = hv_->HandleRdmsr(vcpu_.index(), msr, &rd_val);
    }

    if (verbose_msr_) {
        if (is_wr) {
            std::fprintf(stderr,
                         "[loop] WRMSR msr=0x%08x val=0x%016llx %s\n",
                         msr, static_cast<unsigned long long>(wr_val),
                         result == MsrHandled::Yes ? "(handled)" : "(#GP)");
        } else {
            std::fprintf(stderr,
                         "[loop] RDMSR msr=0x%08x val=0x%016llx %s\n",
                         msr, static_cast<unsigned long long>(rd_val),
                         result == MsrHandled::Yes ? "(handled)" : "(#GP)");
        }
    }
    TINYVMM_ETW_VERBOSE_KW("Msr", ::tinyvmm::diag::kw::VmExit,
        TraceLoggingUInt8(is_wr ? 1u : 0u, "is_write"),
        TraceLoggingUInt32(msr,            "msr"),
        TraceLoggingUInt64(is_wr ? wr_val : rd_val, "value"),
        TraceLoggingUInt8(result == MsrHandled::Yes ? 1u : 0u, "handled"));

    if (result == MsrHandled::NoInjectGp) {
        // Unknown MSR: mimic what WHP would have done without X64MsrExit by
        // injecting #GP(0). Do NOT advance RIP -- the exception is reported
        // as occurring at the RDMSR/WRMSR instruction itself, and Linux's
        // EX_TABLE for `wrmsrl` / `rdmsrl` catches it.
        return InjectGeneralProtectionFault(exit);
    }

    // Handled. For RDMSR, write the value into RAX/RDX. Advance RIP past
    // the 2-byte WRMSR/RDMSR opcode (InstructionLength is set by WHP).
    const std::uint64_t next_rip =
        exit.VpContext.Rip + exit.VpContext.InstructionLength;

    if (is_wr) {
        // Only need to advance RIP.
        static constexpr WHV_REGISTER_NAME kNames[] = { WHvX64RegisterRip };
        WHV_REGISTER_VALUE vals[1] = {};
        vals[0].Reg64 = next_rip;
        try {
            vcpu_.SetRegisters(kNames, vals);
        } catch (const HrError& e) {
            std::fprintf(stderr,
                         "[loop] WRMSR set-regs failed at RIP=0x%llx: "
                         "HRESULT=0x%08lX\n",
                         static_cast<unsigned long long>(exit.VpContext.Rip),
                         static_cast<unsigned long>(e.hr()));
            return StopReason::EmulationFailure;
        }
        return std::nullopt;
    }

    static constexpr WHV_REGISTER_NAME kNames[] = {
        WHvX64RegisterRax, WHvX64RegisterRdx, WHvX64RegisterRip,
    };
    WHV_REGISTER_VALUE vals[3] = {};
    vals[0].Reg64 = rd_val & 0xFFFFFFFFull;
    vals[1].Reg64 = (rd_val >> 32) & 0xFFFFFFFFull;
    vals[2].Reg64 = next_rip;
    try {
        vcpu_.SetRegisters(kNames, vals);
    } catch (const HrError& e) {
        std::fprintf(stderr,
                     "[loop] RDMSR set-regs failed at RIP=0x%llx: "
                     "HRESULT=0x%08lX\n",
                     static_cast<unsigned long long>(exit.VpContext.Rip),
                     static_cast<unsigned long>(e.hr()));
        return StopReason::EmulationFailure;
    }
    return std::nullopt;
}

std::optional<StopReason> RunLoop::InjectGeneralProtectionFault(
    const WHV_RUN_VP_EXIT_CONTEXT& exit) {
    WHV_X64_PENDING_INTERRUPTION_REGISTER pi = {};
    pi.InterruptionPending = 1;
    pi.InterruptionType    = WHvX64PendingException;   // = 3
    pi.DeliverErrorCode    = 1;
    pi.InterruptionVector  = 13;                       // #GP
    pi.ErrorCode           = 0;
    // Do NOT advance RIP -- the exception is reported at the faulting
    // instruction.

    static constexpr WHV_REGISTER_NAME kNames[] = {
        WHvRegisterPendingInterruption,
    };
    WHV_REGISTER_VALUE vals[1] = {};
    vals[0].PendingInterruption = pi;
    try {
        vcpu_.SetRegisters(kNames, vals);
    } catch (const HrError& e) {
        std::fprintf(stderr,
                     "[loop] #GP injection set-regs failed at RIP=0x%llx: "
                     "HRESULT=0x%08lX\n",
                     static_cast<unsigned long long>(exit.VpContext.Rip),
                     static_cast<unsigned long>(e.hr()));
        return StopReason::EmulationFailure;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Emulator callbacks. The emulator is single-threaded with respect to the
// vCPU thread that called WHvEmulatorTry*Emulation, so member-state mutation
// here is safe without locking.
// ---------------------------------------------------------------------------

HRESULT CALLBACK RunLoop::OnIoPortThunk(VOID* ctx,
                                        WHV_EMULATOR_IO_ACCESS_INFO* io) {
    return static_cast<RunLoop*>(ctx)->OnIoPort(io);
}

HRESULT CALLBACK RunLoop::OnMemoryThunk(VOID* ctx,
                                        WHV_EMULATOR_MEMORY_ACCESS_INFO* m) {
    return static_cast<RunLoop*>(ctx)->OnMemory(m);
}

HRESULT CALLBACK RunLoop::OnGetRegistersThunk(
    VOID* ctx, const WHV_REGISTER_NAME* names, UINT32 count,
    WHV_REGISTER_VALUE* values) {
    auto* self = static_cast<RunLoop*>(ctx);
    try {
        self->vcpu_.GetRegisters({names, count}, {values, count});
    } catch (const HrError& e) {
        return e.hr();
    }
    return S_OK;
}

HRESULT CALLBACK RunLoop::OnSetRegistersThunk(
    VOID* ctx, const WHV_REGISTER_NAME* names, UINT32 count,
    const WHV_REGISTER_VALUE* values) {
    auto* self = static_cast<RunLoop*>(ctx);
    try {
        self->vcpu_.SetRegisters({names, count}, {values, count});
    } catch (const HrError& e) {
        return e.hr();
    }
    return S_OK;
}

HRESULT CALLBACK RunLoop::OnTranslateGvaThunk(
    VOID* /*ctx*/, WHV_GUEST_VIRTUAL_ADDRESS /*gva*/,
    WHV_TRANSLATE_GVA_FLAGS /*flags*/,
    WHV_TRANSLATE_GVA_RESULT_CODE* result_code,
    WHV_GUEST_PHYSICAL_ADDRESS* /*out_gpa*/) {
    // The emulator only calls this for instructions that touch guest memory
    // through GVAs (e.g. INS/OUTS, REP MOVS to MMIO). For our minimal device
    // model none of those paths are exercised yet -- when they are, M3+ will
    // wire this up via WHvTranslateGva. For now, fail closed so the emulator
    // returns EmulationSuccessful=0 with TranslateGvaPageCallbackFailed set.
    *result_code = WHvTranslateGvaResultPrivilegeViolation;
    return E_NOTIMPL;
}

HRESULT RunLoop::OnIoPort(WHV_EMULATOR_IO_ACCESS_INFO* io) {
    devices::IoAccess acc = {};
    acc.port = io->Port;
    acc.access_size = io->AccessSize;
    acc.is_write = (io->Direction == 1);
    acc.value = io->Data;

    // Per-port dispatch.
    bool claimed = io_bus_.Dispatch(acc);

    if (verbose_io_) {
        std::fprintf(stderr,
                     "[loop] io %s port=0x%04x size=%u value=0x%08x %s\n",
                     acc.is_write ? "OUT" : "IN ", acc.port, acc.access_size,
                     acc.value, claimed ? "(claimed)" : "(unclaimed)");
    } else if (!claimed) {
        // Floating-bus convention applied by IoBus::Dispatch already; just
        // log the miss so devices we forgot to register are obvious.
        std::fprintf(stderr,
                     "[loop] unhandled IO %s port=0x%04x size=%u "
                     "value=0x%08x\n",
                     acc.is_write ? "OUT" : "IN", acc.port, acc.access_size,
                     acc.value);
    }
    TINYVMM_ETW_VERBOSE_KW("Io", ::tinyvmm::diag::kw::Io,
        TraceLoggingUInt8(acc.is_write ? 1u : 0u, "is_write"),
        TraceLoggingUInt16(acc.port,              "port"),
        TraceLoggingUInt16(acc.access_size,       "size"),
        TraceLoggingUInt32(acc.value,             "value"),
        TraceLoggingUInt8(claimed ? 1u : 0u,      "claimed"));

    if (!acc.is_write) {
        io->Data = acc.value;
    }
    return S_OK;
}

HRESULT RunLoop::OnMemory(WHV_EMULATOR_MEMORY_ACCESS_INFO* m) {
    devices::MmioAccess acc = {};
    acc.gpa = m->GpaAddress;
    acc.access_size = m->AccessSize;
    acc.is_write = (m->Direction == 1);
    if (acc.is_write) {
        std::memcpy(acc.data, m->Data, m->AccessSize);
    }

    const bool claimed = mmio_bus_.Dispatch(acc);
    if (!claimed) {
        std::fprintf(stderr,
                     "[loop] unhandled MMIO %s gpa=0x%llx size=%u\n",
                     acc.is_write ? "WR" : "RD",
                     static_cast<unsigned long long>(acc.gpa),
                     acc.access_size);
    }
    TINYVMM_ETW_VERBOSE_KW("Mmio", ::tinyvmm::diag::kw::Mmio,
        TraceLoggingUInt8(acc.is_write ? 1 : 0, "is_write"),
        TraceLoggingUInt64(static_cast<std::uint64_t>(acc.gpa), "gpa"),
        TraceLoggingUInt8(acc.access_size,                     "size"),
        TraceLoggingUInt8(claimed ? 1 : 0,                     "claimed"));

    if (!acc.is_write) {
        std::memcpy(m->Data, acc.data, m->AccessSize);
    }
    return S_OK;
}

std::uint64_t RunLoop::total_exits() const noexcept {
    return io_exits() + mmio_exits() + halt_exits() + cpuid_exits()
         + msr_exits() + intwin_exits() + apic_eoi_exits()
         + exception_exits() + cancelled_exits() + unsupported_exits()
         + unrecoverable_exits() + invalid_vp_reg_exits() + other_exits();
}

void RunLoop::DumpCounters(std::FILE* out) const {
    std::fprintf(out,
                 "[loop] exits: total=%llu io=%llu mmio=%llu halt=%llu "
                 "cpuid=%llu msr=%llu intwin=%llu apiceoi=%llu "
                 "exception=%llu cancelled=%llu unsupported=%llu "
                 "unrecoverable=%llu invalidreg=%llu other=%llu\n",
                 static_cast<unsigned long long>(total_exits()),
                 static_cast<unsigned long long>(io_exits()),
                 static_cast<unsigned long long>(mmio_exits()),
                 static_cast<unsigned long long>(halt_exits()),
                 static_cast<unsigned long long>(cpuid_exits()),
                 static_cast<unsigned long long>(msr_exits()),
                 static_cast<unsigned long long>(intwin_exits()),
                 static_cast<unsigned long long>(apic_eoi_exits()),
                 static_cast<unsigned long long>(exception_exits()),
                 static_cast<unsigned long long>(cancelled_exits()),
                 static_cast<unsigned long long>(unsupported_exits()),
                 static_cast<unsigned long long>(unrecoverable_exits()),
                 static_cast<unsigned long long>(invalid_vp_reg_exits()),
                 static_cast<unsigned long long>(other_exits()));
}

void RunLoop::EmitCountersEtw() const {
    TINYVMM_ETW_INFO_KW("RunLoopStats", ::tinyvmm::diag::kw::Lifecycle,
        TraceLoggingUInt64(total_exits(),         "total"),
        TraceLoggingUInt64(io_exits(),            "io"),
        TraceLoggingUInt64(mmio_exits(),          "mmio"),
        TraceLoggingUInt64(halt_exits(),          "halt"),
        TraceLoggingUInt64(cpuid_exits(),         "cpuid"),
        TraceLoggingUInt64(msr_exits(),           "msr"),
        TraceLoggingUInt64(intwin_exits(),        "intwin"),
        TraceLoggingUInt64(apic_eoi_exits(),      "apic_eoi"),
        TraceLoggingUInt64(exception_exits(),     "exception"),
        TraceLoggingUInt64(cancelled_exits(),     "cancelled"),
        TraceLoggingUInt64(unsupported_exits(),   "unsupported"),
        TraceLoggingUInt64(unrecoverable_exits(), "unrecoverable"),
        TraceLoggingUInt64(invalid_vp_reg_exits(), "invalid_vp_reg"),
        TraceLoggingUInt64(other_exits(),         "other"));
}

}  // namespace tinyvmm::whp
