#pragma once

// MSI-X capability + table + PBA helper.
//
// Drop-in for a PciDevice (M10) that wants per-vector edge-triggered
// interrupts. Implements PCI Local Bus 3.0 §6.8.2:
//
//   * Capability layout (12 bytes total):
//       +0  : cap_id (0x11)
//       +1  : cap_next
//       +2-3: Message Control [15]=Enable, [14]=FuncMask, [10:0]=N-1
//       +4-7: Table Offset and BIR (BAR Indicator)
//       +8-11: PBA Offset and BIR
//   * Table (in a BAR): 16 bytes per vector
//       +0 : Message Address Low
//       +4 : Message Address High
//       +8 : Message Data
//       +12: Vector Control [0]=mask
//   * PBA (in a BAR, can be same one as table): 1 bit per vector
//
// Usage from a PciDevice subclass:
//   1. Declare a BAR large enough for table + PBA (we publish helper
//      `RequiredBarSize` to compute the smallest power-of-2).
//   2. In the ctor, construct an MsiX(num_vectors, callback) and call
//      AddCapability(*this, bar_idx, table_offset, pba_offset).
//   3. Override OnBarMapped/OnBarUnmapped for that BAR to delegate to
//      MsiX::Install/Uninstall.
//   4. From a device worker, call MsiX::Trigger(vector). The callback runs
//      with (msg_addr, msg_data); typical impl is whp::InjectMsi.

#include "../common.h"
#include "../devices/mmio_bus.h"
#include "pci.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace tinyvmm::pci {

class PciDevice;

class MsiX {
public:
    // Callback signature for delivering an MSI message into a partition. The
    // helper hands the message verbatim -- decoding happens in the WHP
    // adapter (whp::InjectMsi). Returns true if the host considers delivery
    // successful (does not retry on false).
    using InjectFn =
        std::function<bool(std::uint64_t addr, std::uint32_t data)>;

    MsiX(std::uint32_t num_vectors, InjectFn inject);

    // Sizes (bytes). PBA size rounds up to nearest QWORD.
    std::uint32_t TableSize() const { return num_vectors_ * 16; }
    std::uint32_t PbaSize()   const { return ((num_vectors_ + 63) / 64) * 8; }
    std::uint32_t num_vectors() const { return num_vectors_; }

    // Convenience: smallest power-of-2 BAR size that fits `table_offset +
    // table_size` and `pba_offset + pba_size`. The caller usually passes
    // table_offset=0 and pba_offset=0x800 to mimic real-hardware layout.
    static std::uint32_t RequiredBarSize(std::uint32_t num_vectors,
                                         std::uint32_t table_offset = 0,
                                         std::uint32_t pba_offset  = 0x800);

    // Add the MSI-X capability to a PciDevice's config space.
    //   bar_idx        - which BAR holds the table+PBA
    //   table_offset   - byte offset within that BAR for the table (8-byte aligned)
    //   pba_offset     - byte offset within that BAR for the PBA   (8-byte aligned)
    // Returns the cap header offset in config space.
    std::uint32_t AddCapability(PciDevice& dev, std::uint8_t bar_idx,
                                std::uint32_t table_offset,
                                std::uint32_t pba_offset);

    // Register/unregister the table+PBA MMIO handlers when the host BAR is
    // (un)mapped. Call from PciDevice::OnBarMapped / OnBarUnmapped hooks.
    void Install  (devices::MmioBus& bus, std::uint64_t bar_gpa);
    void Uninstall(devices::MmioBus& bus);

    // Submit interrupt for `vector`. Returns true if the message was passed
    // to the inject callback; false if it was suppressed by the function-
    // mask, the per-vector mask, or MSI-X-Enable=0. Suppressed vectors set
    // their PBA bit so unmask can replay.
    bool Trigger(std::uint32_t vector);

    // Diagnostics / tests.
    std::uint64_t injected_count() const { return injected_count_; }
    bool MsiXEnabled()    const;
    bool FunctionMasked() const;
    bool VectorMasked(std::uint32_t vector) const;
    bool PbaBit(std::uint32_t vector) const;
    std::uint64_t entry_addr(std::uint32_t v) const;
    std::uint32_t entry_data(std::uint32_t v) const;

private:
    void HandleTable(devices::MmioAccess& access);
    void HandlePba  (devices::MmioAccess& access);
    void OnVectorCtrlWrite(std::uint32_t vec, std::uint32_t new_ctrl);
    bool DoInject(std::uint32_t vector);

    struct Entry {
        std::uint32_t addr_lo = 0;
        std::uint32_t addr_hi = 0;
        std::uint32_t data    = 0;
        std::uint32_t ctrl    = 1;  // bit 0 = masked; spec init = masked
    };

    std::uint32_t num_vectors_;
    InjectFn      inject_;
    std::vector<Entry>          table_;
    std::vector<std::uint64_t>  pba_;

    PciDevice*    dev_ = nullptr;
    std::uint32_t cap_off_ = 0;
    std::uint8_t  bar_idx_ = 0;
    std::uint32_t table_offset_ = 0;
    std::uint32_t pba_offset_   = 0;
    std::uint64_t bar_base_gpa_ = 0;
    bool          mapped_ = false;

    std::uint64_t injected_count_ = 0;
};

}  // namespace tinyvmm::pci
