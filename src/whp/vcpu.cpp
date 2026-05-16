#include "vcpu.h"

#include <array>

namespace tinyvmm::whp {

Vcpu::Vcpu(Partition& partition, std::uint32_t index)
    : partition_(partition), index_(index) {
    HRESULT hr = WHvCreateVirtualProcessor(partition_.handle(), index_, 0);
    ThrowIfFailed(hr, "WHvCreateVirtualProcessor");
}

Vcpu::~Vcpu() {
    WHvDeleteVirtualProcessor(partition_.handle(), index_);
}

void Vcpu::GetRegisters(std::span<const WHV_REGISTER_NAME> names,
                        std::span<WHV_REGISTER_VALUE> out_values) {
    if (names.size() != out_values.size()) {
        Fatal("Vcpu::GetRegisters: name/value span size mismatch");
    }
    HRESULT hr = WHvGetVirtualProcessorRegisters(
        partition_.handle(), index_, names.data(),
        util::checked_int_cast<UINT32>(names.size()), out_values.data());
    ThrowIfFailed(hr, "WHvGetVirtualProcessorRegisters");
}

void Vcpu::SetRegisters(std::span<const WHV_REGISTER_NAME> names,
                        std::span<const WHV_REGISTER_VALUE> values) {
    if (names.size() != values.size()) {
        Fatal("Vcpu::SetRegisters: name/value span size mismatch");
    }
    HRESULT hr = WHvSetVirtualProcessorRegisters(
        partition_.handle(), index_, names.data(),
        util::checked_int_cast<UINT32>(names.size()), values.data());
    ThrowIfFailed(hr, "WHvSetVirtualProcessorRegisters");
}

void Vcpu::SetRegister(WHV_REGISTER_NAME name, WHV_REGISTER_VALUE value) {
    SetRegisters(std::span(&name, 1), std::span(&value, 1));
}

WHV_REGISTER_VALUE Vcpu::GetRegister(WHV_REGISTER_NAME name) {
    WHV_REGISTER_VALUE v = {};
    GetRegisters(std::span(&name, 1), std::span(&v, 1));
    return v;
}

void Vcpu::Run(WHV_RUN_VP_EXIT_CONTEXT& exit) {
    HRESULT hr = WHvRunVirtualProcessor(partition_.handle(), index_, &exit,
                                        sizeof(exit));
    ThrowIfFailed(hr, "WHvRunVirtualProcessor");
}

void Vcpu::Cancel() {
    HRESULT hr = WHvCancelRunVirtualProcessor(partition_.handle(), index_, 0);
    ThrowIfFailed(hr, "WHvCancelRunVirtualProcessor");
}

namespace {

// Real-mode segment attributes. The Attributes field of WHV_X64_SEGMENT_REGISTER
// matches the high word of the segment access rights.
//   Type=11 (code, exec/read, accessed) for CS, Type=3 (data, r/w, accessed)
//   for the others. S=1, DPL=0, P=1, L=0, DB=0, G=0.
constexpr UINT16 kRealModeCodeAttr =
    /* Type */ 0xB
    | /* S=1 */ (1 << 4)
    | /* DPL=0 */ (0 << 5)
    | /* P=1 */ (1 << 7);

constexpr UINT16 kRealModeDataAttr =
    /* Type */ 0x3
    | /* S=1 */ (1 << 4)
    | /* DPL=0 */ (0 << 5)
    | /* P=1 */ (1 << 7);

WHV_X64_SEGMENT_REGISTER MakeRealCodeSeg(std::uint64_t base) {
    WHV_X64_SEGMENT_REGISTER s = {};
    s.Base = base;
    s.Limit = 0xFFFF;
    s.Selector = static_cast<UINT16>(base >> 4);
    s.Attributes = kRealModeCodeAttr;
    return s;
}

WHV_X64_SEGMENT_REGISTER MakeRealDataSeg() {
    WHV_X64_SEGMENT_REGISTER s = {};
    s.Base = 0;
    s.Limit = 0xFFFF;
    s.Selector = 0;
    s.Attributes = kRealModeDataAttr;
    return s;
}

}  // namespace

void Vcpu::SetupRealMode(std::uint64_t cs_base) {
    const std::array<WHV_REGISTER_NAME, 7> names = {
        WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs,
        WHvX64RegisterSs, WHvX64RegisterFs, WHvX64RegisterGs,
        WHvX64RegisterRflags,
    };
    std::array<WHV_REGISTER_VALUE, 7> values = {};
    values[0].Segment = MakeRealCodeSeg(cs_base);
    values[1].Segment = MakeRealDataSeg();
    values[2].Segment = MakeRealDataSeg();
    values[3].Segment = MakeRealDataSeg();
    values[4].Segment = MakeRealDataSeg();
    values[5].Segment = MakeRealDataSeg();
    values[6].Reg64 = 0x2;  // bit 1 reserved-must-be-1, IF=0

    SetRegisters(names, values);
}

void Vcpu::InjectFixedInterrupt(std::uint8_t vector,
                                std::uint32_t dest_logical_id) {
    // WHvRequestInterrupt funnels into the partition's APIC emulation; with
    // x2APIC enabled this lands as a fixed-vector IPI at the destination VP.
    // The call is non-blocking and does not itself force a VM exit on the
    // target -- WHP injects on the next VM entry, or holds the vector if
    // IF=0 and re-checks at IRET.
    WHV_INTERRUPT_CONTROL ctrl = {};
    ctrl.Type = WHvX64InterruptTypeFixed;
    ctrl.DestinationMode = WHvX64InterruptDestinationModePhysical;
    ctrl.TriggerMode = WHvX64InterruptTriggerModeEdge;
    ctrl.Destination = dest_logical_id;
    ctrl.Vector = vector;

    HRESULT hr = WHvRequestInterrupt(partition_.handle(), &ctrl, sizeof(ctrl));
    ThrowIfFailed(hr, "WHvRequestInterrupt");
}

}  // namespace tinyvmm::whp
