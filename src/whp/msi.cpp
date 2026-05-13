#include "msi.h"

#include <atomic>

namespace tinyvmm::whp {

namespace {
std::atomic<std::uint64_t> g_msi_inject_count{0};
}  // namespace

std::uint64_t MsiInjectCount() noexcept {
    return g_msi_inject_count.load(std::memory_order_relaxed);
}

HRESULT InjectMsi(WHV_PARTITION_HANDLE partition,
                  std::uint64_t address,
                  std::uint32_t data) {
    WHV_INTERRUPT_CONTROL ctrl = {};

    const std::uint8_t  vector       = static_cast<std::uint8_t>(data & 0xFFu);
    const std::uint8_t  delivery     =
        static_cast<std::uint8_t>((data >> 8) & 0x7u);
    const bool          trig_level   = (data & (1u << 15)) != 0;
    // Bit 14 (Level) is the assert/deassert flag for level-triggered messages;
    // we let trig_level pull it through implicitly -- WHP infers from trigger.

    const bool          dest_logical = (address & (1ull << 2)) != 0;
    // Pull 8-bit destination from address[19:12] (xAPIC compatibility format).
    // With x2APIC the destination can extend through address[31:12] but our
    // single-vCPU bring-up never exceeds 8 bits, so we keep the simple form.
    const std::uint32_t destination  = static_cast<std::uint32_t>(
        (address >> 12) & 0xFFull);

    // Map MSI delivery mode -> WHV interrupt type. SMI (2) and ExtINT (7)
    // have no WHV equivalent for normal MSI delivery; refuse them.
    WHV_INTERRUPT_TYPE int_type;
    switch (delivery) {
      case 0: int_type = WHvX64InterruptTypeFixed;            break;
      case 1: int_type = WHvX64InterruptTypeLowestPriority;   break;
      case 4: int_type = WHvX64InterruptTypeNmi;              break;
      case 5: int_type = WHvX64InterruptTypeInit;             break;
      default:
        return E_INVALIDARG;
    }

    ctrl.Type            = int_type;
    ctrl.DestinationMode = dest_logical
        ? WHvX64InterruptDestinationModeLogical
        : WHvX64InterruptDestinationModePhysical;
    ctrl.TriggerMode     = trig_level
        ? WHvX64InterruptTriggerModeLevel
        : WHvX64InterruptTriggerModeEdge;
    ctrl.Destination     = destination;
    ctrl.Vector          = vector;

    HRESULT hr = WHvRequestInterrupt(partition, &ctrl, sizeof(ctrl));
    if (SUCCEEDED(hr)) {
        g_msi_inject_count.fetch_add(1, std::memory_order_relaxed);
    }
    return hr;
}

}  // namespace tinyvmm::whp
