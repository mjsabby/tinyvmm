#include "run_loop.h"

#include "cpuid.h"

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

        switch (last_exit_.ExitReason) {
            case WHvRunVpExitReasonX64Halt: {
                halt_exits_.fetch_add(1, std::memory_order_relaxed);
                const bool if_set =
                    (last_exit_.VpContext.Rflags & kRflagsIf) != 0;
                std::printf(
                    "[loop] HLT at RIP=0x%llx (IF=%d) -- treating as terminal "
                    "for now\n",
                    static_cast<unsigned long long>(last_exit_.VpContext.Rip),
                    if_set ? 1 : 0);
                // M5 will re-enter the loop here once we can wait for IRQs;
                // for now any HLT ends the run.
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

            case WHvRunVpExitReasonCanceled:
                // External Cancel(). If RequestStop was called, the top-of-loop
                // check will catch it. Otherwise it was an IRQ-injection kick;
                // fall through to next iteration.
                break;

            default:
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

    if (!mmio_bus_.Dispatch(acc)) {
        std::fprintf(stderr,
                     "[loop] unhandled MMIO %s gpa=0x%llx size=%u\n",
                     acc.is_write ? "WR" : "RD",
                     static_cast<unsigned long long>(acc.gpa),
                     acc.access_size);
    }

    if (!acc.is_write) {
        std::memcpy(m->Data, acc.data, m->AccessSize);
    }
    return S_OK;
}

}  // namespace tinyvmm::whp
