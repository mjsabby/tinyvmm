#include "msix.h"

#include "pci_device.h"

#include <cstdio>
#include <cstring>
#include <utility>

namespace tinyvmm::pci {

namespace {

std::uint32_t NextPow2(std::uint32_t v) {
    if (v < 2) return 1;
    std::uint32_t r = 1;
    while (r < v) r <<= 1;
    return r;
}

}  // namespace

MsiX::MsiX(std::uint32_t num_vectors, InjectFn inject)
    : num_vectors_(num_vectors), inject_(std::move(inject)),
      table_(num_vectors), pba_((num_vectors + 63) / 64, 0) {
    if (num_vectors == 0 || num_vectors > 2048) {
        Fatal("MsiX: num_vectors must be in [1, 2048]");
    }
    if (!inject_) {
        Fatal("MsiX: inject callback must be non-null");
    }
}

std::uint32_t MsiX::RequiredBarSize(std::uint32_t num_vectors,
                                    std::uint32_t table_offset,
                                    std::uint32_t pba_offset) {
    const std::uint32_t table_size = num_vectors * 16;
    const std::uint32_t pba_size = ((num_vectors + 63) / 64) * 8;
    const std::uint32_t end_table = table_offset + table_size;
    const std::uint32_t end_pba   = pba_offset + pba_size;
    const std::uint32_t hi = end_table > end_pba ? end_table : end_pba;
    // PCI MMIO BARs must be at least 16 bytes and a power of two.
    return hi < 16 ? 16u : NextPow2(hi);
}

std::uint32_t MsiX::AddCapability(PciDevice& dev, std::uint8_t bar_idx,
                                   std::uint32_t table_offset,
                                   std::uint32_t pba_offset) {
    if ((table_offset & 0x7u) != 0 || (pba_offset & 0x7u) != 0) {
        Fatal("MsiX::AddCapability: table_offset and pba_offset must be"
              " 8-byte aligned");
    }
    dev_           = &dev;
    bar_idx_       = bar_idx;
    table_offset_  = table_offset;
    pba_offset_    = pba_offset;

    // 12-byte capability: 2 header bytes + 2-byte MC + 4-byte table-BIR
    // + 4-byte PBA-BIR.
    cap_off_ = dev.AppendCapability(kCapIdMsiX, /*payload=*/12);
    std::uint8_t* p = dev.mut_cfg_ptr(cap_off_);

    // Message Control (cap+2): table_size = N-1 in bits[10:0]. Reserved
    // bits 13:11 stay zero. Bits 14 (FuncMask) and 15 (Enable) start at 0
    // and are software-writable -- mark them in the writable mask.
    const std::uint16_t mc = static_cast<std::uint16_t>(num_vectors_ - 1);
    p[2] = static_cast<std::uint8_t>(mc & 0xFFu);
    p[3] = static_cast<std::uint8_t>((mc >> 8) & 0x07u);  // bits 10:8 only
    // High byte writable mask: bit 6 (FuncMask) | bit 7 (Enable) = 0xC0.
    dev.set_writable_byte(cap_off_ + 3, 0xC0u);

    // Table Offset + BIR (cap+4): bits[2:0] = BIR, bits[31:3] = offset.
    const std::uint32_t toff = (table_offset_ & ~0x7u) |
                               (static_cast<std::uint32_t>(bar_idx_) & 0x7u);
    p[4] = static_cast<std::uint8_t>(toff & 0xFFu);
    p[5] = static_cast<std::uint8_t>((toff >> 8)  & 0xFFu);
    p[6] = static_cast<std::uint8_t>((toff >> 16) & 0xFFu);
    p[7] = static_cast<std::uint8_t>((toff >> 24) & 0xFFu);

    const std::uint32_t poff = (pba_offset_ & ~0x7u) |
                               (static_cast<std::uint32_t>(bar_idx_) & 0x7u);
    p[8]  = static_cast<std::uint8_t>(poff & 0xFFu);
    p[9]  = static_cast<std::uint8_t>((poff >> 8)  & 0xFFu);
    p[10] = static_cast<std::uint8_t>((poff >> 16) & 0xFFu);
    p[11] = static_cast<std::uint8_t>((poff >> 24) & 0xFFu);

    return cap_off_;
}

bool MsiX::MsiXEnabled() const {
    if (dev_ == nullptr) return false;
    return (dev_->cfg_read16(cap_off_ + 2) & 0x8000u) != 0;
}

bool MsiX::FunctionMasked() const {
    if (dev_ == nullptr) return false;
    return (dev_->cfg_read16(cap_off_ + 2) & 0x4000u) != 0;
}

bool MsiX::VectorMasked(std::uint32_t vector) const {
    if (vector >= num_vectors_) return true;
    return (table_[vector].ctrl & 0x1u) != 0;
}

bool MsiX::PbaBit(std::uint32_t vector) const {
    if (vector >= num_vectors_) return false;
    return (pba_[vector / 64] >> (vector % 64)) & 0x1ull;
}

std::uint64_t MsiX::entry_addr(std::uint32_t v) const {
    if (v >= num_vectors_) return 0;
    return (static_cast<std::uint64_t>(table_[v].addr_hi) << 32) |
            table_[v].addr_lo;
}

std::uint32_t MsiX::entry_data(std::uint32_t v) const {
    if (v >= num_vectors_) return 0;
    return table_[v].data;
}

void MsiX::Install(devices::MmioBus& bus, std::uint64_t bar_gpa) {
    if (mapped_) return;
    bar_base_gpa_ = bar_gpa;
    bus.Register(bar_gpa + table_offset_, TableSize(), "msix-table",
                 [this](devices::MmioAccess& a) { HandleTable(a); });
    bus.Register(bar_gpa + pba_offset_, PbaSize(), "msix-pba",
                 [this](devices::MmioAccess& a) { HandlePba(a); });
    mapped_ = true;
}

void MsiX::Uninstall(devices::MmioBus& bus) {
    if (!mapped_) return;
    bus.Unregister(bar_base_gpa_ + table_offset_);
    bus.Unregister(bar_base_gpa_ + pba_offset_);
    mapped_ = false;
}

void MsiX::HandleTable(devices::MmioAccess& access) {
    const std::uint64_t off =
        access.gpa - (bar_base_gpa_ + table_offset_);
    const std::uint32_t vec   = static_cast<std::uint32_t>(off / 16);
    const std::uint32_t field = static_cast<std::uint32_t>(off % 16);

    // Linux drivers always use aligned readl/writel on MSI-X tables.
    if (access.access_size != 4 || (off & 0x3u) != 0 || vec >= num_vectors_) {
        if (!access.is_write) std::memset(access.data, 0, sizeof(access.data));
        return;
    }

    Entry& e = table_[vec];
    std::uint32_t* p_field = nullptr;
    switch (field) {
      case  0: p_field = &e.addr_lo; break;
      case  4: p_field = &e.addr_hi; break;
      case  8: p_field = &e.data;    break;
      case 12: p_field = &e.ctrl;    break;
      default:
        if (!access.is_write) std::memset(access.data, 0, sizeof(access.data));
        return;
    }

    if (access.is_write) {
        std::uint32_t v = 0;
        std::memcpy(&v, access.data, 4);
        if (field == 12) {
            // Vector Control: bit 0 = mask. Bits 31:1 are RO 0 (spec).
            OnVectorCtrlWrite(vec, v & 0x1u);
        } else {
            *p_field = v;
        }
    } else {
        std::memcpy(access.data, p_field, 4);
    }
}

void MsiX::HandlePba(devices::MmioAccess& access) {
    const std::uint64_t off =
        access.gpa - (bar_base_gpa_ + pba_offset_);
    // PBA is a bit array; reads return the QWORD containing the requested
    // bits. Software writes are ignored (PBA is hardware-managed).
    if (access.is_write) return;
    if (access.access_size != 4 && access.access_size != 8) {
        std::memset(access.data, 0, sizeof(access.data));
        return;
    }
    const std::uint64_t qword_index = off / 8;
    if (qword_index >= pba_.size()) {
        std::memset(access.data, 0, sizeof(access.data));
        return;
    }
    const std::uint64_t value = pba_[qword_index];
    if (access.access_size == 8) {
        std::memcpy(access.data, &value, 8);
    } else {
        // 4-byte read: low or high half of the qword.
        const std::uint32_t shift = (static_cast<std::uint32_t>(off & 4u)) * 8u;
        const std::uint32_t half  = static_cast<std::uint32_t>(value >> shift);
        std::memcpy(access.data, &half, 4);
    }
}

void MsiX::OnVectorCtrlWrite(std::uint32_t vec, std::uint32_t new_ctrl) {
    Entry& e = table_[vec];
    const bool was_masked = (e.ctrl & 0x1u) != 0;
    const bool now_masked = (new_ctrl & 0x1u) != 0;
    e.ctrl = new_ctrl;

    // Replay on unmask (spec §6.8.3.5): if the per-vector mask transitions
    // from set to clear and a pending bit is set, the device must (re)send
    // the message. Function mask still gates everything.
    if (was_masked && !now_masked && MsiXEnabled() && !FunctionMasked() &&
        PbaBit(vec)) {
        pba_[vec / 64] &= ~(1ull << (vec % 64));
        DoInject(vec);
    }
}

bool MsiX::Trigger(std::uint32_t vector) {
    if (vector >= num_vectors_) return false;
    if (!MsiXEnabled() || FunctionMasked() || VectorMasked(vector)) {
        // Latch the pending bit; spec requires replay when unmasked.
        pba_[vector / 64] |= (1ull << (vector % 64));
        return false;
    }
    return DoInject(vector);
}

bool MsiX::DoInject(std::uint32_t vector) {
    const Entry& e = table_[vector];
    const std::uint64_t addr =
        (static_cast<std::uint64_t>(e.addr_hi) << 32) | e.addr_lo;
    ++injected_count_;
    return inject_(addr, e.data);
}

}  // namespace tinyvmm::pci
