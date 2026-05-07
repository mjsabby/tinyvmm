#pragma once

#include "../common.h"
#include "../devices/io_bus.h"
#include "../devices/mmio_bus.h"
#include "vcpu.h"

#include <Windows.h>
#include <WinHvEmulation.h>

#include <atomic>
#include <optional>

namespace tinyvmm::whp {

// Reasons the run loop returned. Useful for `--loop-test` style harnesses to
// distinguish "guest finished cleanly" from "we bailed on an unhandled exit".
enum class StopReason {
    GuestHalted,        // X64Halt with IF=0; guest will never wake up.
    Cancelled,          // External RequestStop().
    UnhandledExit,      // Saw an exit reason we don't yet support.
    EmulationFailure,   // WHvEmulatorTry*Emulation reported failure.
};

// Drives a single vCPU's exit loop. Owns a WHV emulator handle for instruction
// completion of IO/MMIO accesses; routes those accesses through the IO and
// MMIO buses.
//
// Lifecycle: construct with references to the vcpu and buses, call Run() from
// the vCPU's owning thread. Other threads may call RequestStop() to break the
// loop; that triggers WHvCancelRunVirtualProcessor under the hood.
class RunLoop {
public:
    RunLoop(Vcpu& vcpu, devices::IoBus& io_bus, devices::MmioBus& mmio_bus);
    ~RunLoop();

    RunLoop(const RunLoop&) = delete;
    RunLoop& operator=(const RunLoop&) = delete;

    // Loop until a terminal condition is reached. Returns the reason.
    StopReason Run();

    // May be called from any thread. Sets the stop flag and pokes the vCPU
    // out of WHvRunVirtualProcessor via WHvCancelRunVirtualProcessor.
    void RequestStop();

    // Last exit context seen by the loop. Useful for diagnostics in tests.
    const WHV_RUN_VP_EXIT_CONTEXT& last_exit() const noexcept {
        return last_exit_;
    }

    // Counters for tests / diagnostics.
    std::uint64_t io_exits() const noexcept { return io_exits_; }
    std::uint64_t mmio_exits() const noexcept { return mmio_exits_; }
    std::uint64_t halt_exits() const noexcept { return halt_exits_; }

private:
    // Emulator callback thunks — context pointer is `this`.
    static HRESULT CALLBACK OnIoPortThunk(VOID* ctx,
                                          WHV_EMULATOR_IO_ACCESS_INFO* io);
    static HRESULT CALLBACK OnMemoryThunk(VOID* ctx,
                                          WHV_EMULATOR_MEMORY_ACCESS_INFO* m);
    static HRESULT CALLBACK OnGetRegistersThunk(
        VOID* ctx, const WHV_REGISTER_NAME* names, UINT32 count,
        WHV_REGISTER_VALUE* values);
    static HRESULT CALLBACK OnSetRegistersThunk(
        VOID* ctx, const WHV_REGISTER_NAME* names, UINT32 count,
        const WHV_REGISTER_VALUE* values);
    static HRESULT CALLBACK OnTranslateGvaThunk(
        VOID* ctx, WHV_GUEST_VIRTUAL_ADDRESS gva,
        WHV_TRANSLATE_GVA_FLAGS flags,
        WHV_TRANSLATE_GVA_RESULT_CODE* result_code,
        WHV_GUEST_PHYSICAL_ADDRESS* out_gpa);

    HRESULT OnIoPort(WHV_EMULATOR_IO_ACCESS_INFO* io);
    HRESULT OnMemory(WHV_EMULATOR_MEMORY_ACCESS_INFO* m);

    // Returns nullopt to mean "keep looping"; a value means "stop with this
    // reason". Pulling this out of the switch keeps the main loop readable.
    std::optional<StopReason> HandleIoExit(
        const WHV_RUN_VP_EXIT_CONTEXT& exit);
    std::optional<StopReason> HandleMmioExit(
        const WHV_RUN_VP_EXIT_CONTEXT& exit);

    Vcpu& vcpu_;
    devices::IoBus& io_bus_;
    devices::MmioBus& mmio_bus_;
    WHV_EMULATOR_HANDLE emulator_ = nullptr;

    std::atomic<bool> stop_requested_{false};
    WHV_RUN_VP_EXIT_CONTEXT last_exit_ = {};
    std::uint64_t io_exits_ = 0;
    std::uint64_t mmio_exits_ = 0;
    std::uint64_t halt_exits_ = 0;
};

// Render a WHV exit reason as a human-readable name for logging.
const char* ExitReasonName(WHV_RUN_VP_EXIT_REASON reason) noexcept;

}  // namespace tinyvmm::whp
