#pragma once

#include "../common.h"
#include "partition.h"

#include <span>

namespace tinyvmm::whp {

// Thin wrapper around a single virtual processor. Not thread-safe; each VP is
// owned by one host thread that drives its run loop.
class Vcpu {
public:
    Vcpu(Partition& partition, std::uint32_t index);
    ~Vcpu();

    Vcpu(const Vcpu&) = delete;
    Vcpu& operator=(const Vcpu&) = delete;

    std::uint32_t index() const noexcept { return index_; }

    // Get/set helpers for the common register groups. The arrays must be
    // parallel: names[i] corresponds to values[i].
    void GetRegisters(std::span<const WHV_REGISTER_NAME> names,
                      std::span<WHV_REGISTER_VALUE> out_values);
    void SetRegisters(std::span<const WHV_REGISTER_NAME> names,
                      std::span<const WHV_REGISTER_VALUE> values);

    // Convenience: set a single register.
    void SetRegister(WHV_REGISTER_NAME name, WHV_REGISTER_VALUE value);
    WHV_REGISTER_VALUE GetRegister(WHV_REGISTER_NAME name);

    // Run until the next exit; the exit context is filled in.
    void Run(WHV_RUN_VP_EXIT_CONTEXT& exit);

    // Cancels an in-progress Run from another thread. Surfaces as
    // WHvRunVpExitReasonCanceled.
    void Cancel();

    // Configure CS as a real-mode code segment with the given base. All other
    // segments are set up flat with base 0. Used by the M0 smoke test and as a
    // building block for the PVH 32-bit entry helper.
    void SetupRealMode(std::uint64_t cs_base);

private:
    Partition& partition_;
    std::uint32_t index_;
};

}  // namespace tinyvmm::whp
