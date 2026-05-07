#include "partition.h"

namespace tinyvmm::whp {

Partition::Partition(std::uint32_t vcpu_count) : vcpu_count_(vcpu_count) {
    HRESULT hr = WHvCreatePartition(&handle_);
    ThrowIfFailed(hr, "WHvCreatePartition");

    // Set the vCPU count up front. Must happen before WHvSetupPartition.
    SetProperty(WHvPartitionPropertyCodeProcessorCount, vcpu_count_);
}

Partition::~Partition() {
    if (handle_ != nullptr) {
        // Best-effort cleanup; don't throw out of destructor.
        WHvDeletePartition(handle_);
        handle_ = nullptr;
    }
}

template <typename T>
void Partition::SetProperty(WHV_PARTITION_PROPERTY_CODE code, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    HRESULT hr = WHvSetPartitionProperty(handle_, code, &value,
                                         static_cast<UINT32>(sizeof(T)));
    ThrowIfFailed(hr, "WHvSetPartitionProperty");
}

void Partition::EnableExtendedExits(const ExtendedExits& bits) {
    if (setup_done_) {
        Fatal("EnableExtendedExits called after Setup()");
    }
    WHV_EXTENDED_VM_EXITS ext = {};
    ext.X64CpuidExit = bits.cpuid ? 1 : 0;
    ext.X64MsrExit = bits.msr ? 1 : 0;
    ext.ExceptionExit = bits.exception ? 1 : 0;
    ext.HypercallExit = bits.hypercall ? 1 : 0;
    ext.GpaAccessFaultExit = bits.gpa_access_fault ? 1 : 0;
    SetProperty(WHvPartitionPropertyCodeExtendedVmExits, ext);
}

void Partition::SetLocalApicEmulation(WHV_X64_LOCAL_APIC_EMULATION_MODE mode) {
    if (setup_done_) {
        Fatal("SetLocalApicEmulation called after Setup()");
    }
    SetProperty(WHvPartitionPropertyCodeLocalApicEmulationMode, mode);
}

void Partition::Setup() {
    if (setup_done_) {
        return;
    }
    HRESULT hr = WHvSetupPartition(handle_);
    ThrowIfFailed(hr, "WHvSetupPartition");
    setup_done_ = true;
}

}  // namespace tinyvmm::whp
