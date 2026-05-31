#include "msix.h"

#include "pci_device.h"
#include "whp/snapshot_file.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>
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
    std::lock_guard<std::mutex> lk(mu_);
    return (table_[vector].ctrl & 0x1u) != 0;
}

bool MsiX::PbaBit(std::uint32_t vector) const {
    if (vector >= num_vectors_) return false;
    std::lock_guard<std::mutex> lk(mu_);
    return (pba_[vector / 64] >> (vector % 64)) & 0x1ull;
}

std::uint64_t MsiX::entry_addr(std::uint32_t v) const {
    if (v >= num_vectors_) return 0;
    std::lock_guard<std::mutex> lk(mu_);
    return (static_cast<std::uint64_t>(table_[v].addr_hi) << 32) |
            table_[v].addr_lo;
}

std::uint32_t MsiX::entry_data(std::uint32_t v) const {
    if (v >= num_vectors_) return 0;
    std::lock_guard<std::mutex> lk(mu_);
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

    std::uint32_t replay_vec = 0;
    bool          do_replay  = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Entry& e = table_[vec];
        std::uint32_t* p_field = nullptr;
        switch (field) {
          case  0: p_field = &e.addr_lo; break;
          case  4: p_field = &e.addr_hi; break;
          case  8: p_field = &e.data;    break;
          case 12: p_field = &e.ctrl;    break;
          default:
            if (!access.is_write)
                std::memset(access.data, 0, sizeof(access.data));
            return;
        }

        if (access.is_write) {
            std::uint32_t v = 0;
            std::memcpy(&v, access.data, 4);
            if (field == 12) {
                // Vector Control: bit 0 = mask. Bits 31:1 are RO 0 (spec).
                const std::uint32_t new_ctrl = v & 0x1u;
                const bool was_masked = (e.ctrl & 0x1u) != 0;
                const bool now_masked = (new_ctrl & 0x1u) != 0;
                e.ctrl = new_ctrl;
                // Replay on unmask (spec §6.8.3.5): pending bit set, function
                // unmasked, MSI-X enabled. We perform the replay outside the
                // lock so DoInject's inject_() runs without holding mu_.
                if (was_masked && !now_masked && MsiXEnabled() &&
                    !FunctionMasked() &&
                    ((pba_[vec / 64] >> (vec % 64)) & 0x1ull)) {
                    pba_[vec / 64] &= ~(1ull << (vec % 64));
                    do_replay = true;
                    replay_vec = vec;
                }
            } else {
                *p_field = v;
            }
        } else {
            std::memcpy(access.data, p_field, 4);
        }
    }

    if (do_replay) {
        DoInject(replay_vec);
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
    std::uint64_t value = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (qword_index >= pba_.size()) {
            std::memset(access.data, 0, sizeof(access.data));
            return;
        }
        value = pba_[qword_index];
    }
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
    // Public entry point for tests; HandleTable does its own locked path.
    bool do_replay = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Entry& e = table_[vec];
        const bool was_masked = (e.ctrl & 0x1u) != 0;
        const bool now_masked = (new_ctrl & 0x1u) != 0;
        e.ctrl = new_ctrl;
        if (was_masked && !now_masked && MsiXEnabled() && !FunctionMasked() &&
            ((pba_[vec / 64] >> (vec % 64)) & 0x1ull)) {
            pba_[vec / 64] &= ~(1ull << (vec % 64));
            do_replay = true;
        }
    }
    if (do_replay) DoInject(vec);
}

bool MsiX::Trigger(std::uint32_t vector) {
    if (vector >= num_vectors_) return false;
    if (!MsiXEnabled() || FunctionMasked()) {
        // Latch the pending bit; spec requires replay when unmasked.
        std::lock_guard<std::mutex> lk(mu_);
        pba_[vector / 64] |= (1ull << (vector % 64));
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        if ((table_[vector].ctrl & 0x1u) != 0) {
            pba_[vector / 64] |= (1ull << (vector % 64));
            return false;
        }
    }
    return DoInject(vector);
}

bool MsiX::DoInject(std::uint32_t vector) {
    std::uint64_t addr = 0;
    std::uint32_t data = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        const Entry& e = table_[vector];
        addr = (static_cast<std::uint64_t>(e.addr_hi) << 32) | e.addr_lo;
        data = e.data;
    }
    injected_count_.fetch_add(1, std::memory_order_relaxed);
    return inject_(addr, data);
}

// ----------------------- M33.4 save/restore ---------------------------

MsiX::State MsiX::CaptureState() const {
    State s;
    std::lock_guard<std::mutex> lk(mu_);
    s.num_vectors  = num_vectors_;
    s.bar_base_gpa = bar_base_gpa_;
    s.mapped       = mapped_ ? 1u : 0u;
    s.table.resize(num_vectors_);
    for (std::uint32_t i = 0; i < num_vectors_; ++i) {
        s.table[i].addr_lo = table_[i].addr_lo;
        s.table[i].addr_hi = table_[i].addr_hi;
        s.table[i].data    = table_[i].data;
        s.table[i].ctrl    = table_[i].ctrl;
    }
    s.pba.assign(pba_.begin(), pba_.end());
    return s;
}

void MsiX::ApplyState(const State& s) {
    if (s.num_vectors != num_vectors_) {
        throw std::runtime_error(
            "MsiX::ApplyState: num_vectors mismatch (saved != current)");
    }
    if (s.table.size() != num_vectors_) {
        throw std::runtime_error("MsiX::ApplyState: table length mismatch");
    }
    if (s.pba.size() != pba_.size()) {
        throw std::runtime_error("MsiX::ApplyState: PBA length mismatch");
    }
    std::lock_guard<std::mutex> lk(mu_);
    // Deliberately NOT touching mapped_ / bar_base_gpa_ — those are
    // re-established by PciTransport::InstallBarHandlers_ calling
    // Install() during ApplyState.
    for (std::uint32_t i = 0; i < num_vectors_; ++i) {
        table_[i].addr_lo = s.table[i].addr_lo;
        table_[i].addr_hi = s.table[i].addr_hi;
        table_[i].data    = s.table[i].data;
        table_[i].ctrl    = s.table[i].ctrl;
    }
    std::copy(s.pba.begin(), s.pba.end(), pba_.begin());
}

std::size_t MsiX::EncodeState(const State& s,
                              std::vector<std::uint8_t>& out) {
    using namespace tinyvmm::whp::snapshot;
    const std::size_t want = EncodedSize(s.num_vectors);
    if (s.table.size() != s.num_vectors) {
        throw std::runtime_error(
            "MsiX::EncodeState: table length != num_vectors");
    }
    if (s.pba.size() != (s.num_vectors + 63) / 64) {
        throw std::runtime_error(
            "MsiX::EncodeState: pba length wrong for num_vectors");
    }
    const std::size_t start = out.size();
    out.resize(start + want, 0);
    std::uint8_t* p = out.data() + start;
    WriteLe32(p +  0, s.num_vectors);
    // p[4..7] = u32 reserved=0
    WriteLe64(p +  8, s.bar_base_gpa);
    p[16] = s.mapped;
    // p[17..23] = u8 pad[7]
    std::size_t off = kEncodedHeaderSize;
    for (std::uint32_t i = 0; i < s.num_vectors; ++i) {
        WriteLe32(p + off +  0, s.table[i].addr_lo);
        WriteLe32(p + off +  4, s.table[i].addr_hi);
        WriteLe32(p + off +  8, s.table[i].data);
        WriteLe32(p + off + 12, s.table[i].ctrl);
        off += 16;
    }
    for (std::uint64_t w : s.pba) {
        WriteLe64(p + off, w);
        off += 8;
    }
    return want;
}

MsiX::State MsiX::DecodeState(std::span<const std::uint8_t> bytes) {
    using namespace tinyvmm::whp::snapshot;
    if (bytes.size() < kEncodedHeaderSize) {
        throw std::runtime_error(
            "MsiX::DecodeState: payload smaller than header");
    }
    const std::uint8_t* p = bytes.data();
    State s;
    s.num_vectors  = ReadLe32(p + 0);
    if (ReadLe32(p + 4) != 0) {
        throw std::runtime_error("MsiX::DecodeState: nonzero reserved@4");
    }
    s.bar_base_gpa = ReadLe64(p + 8);
    s.mapped       = p[16];
    for (int i = 17; i < 24; ++i) {
        if (p[i] != 0) {
            throw std::runtime_error(
                "MsiX::DecodeState: nonzero pad in header");
        }
    }
    const std::size_t want = EncodedSize(s.num_vectors);
    if (bytes.size() < want) {
        throw std::runtime_error(
            "MsiX::DecodeState: payload truncated for num_vectors");
    }
    s.table.resize(s.num_vectors);
    std::size_t off = kEncodedHeaderSize;
    for (std::uint32_t i = 0; i < s.num_vectors; ++i) {
        s.table[i].addr_lo = ReadLe32(p + off +  0);
        s.table[i].addr_hi = ReadLe32(p + off +  4);
        s.table[i].data    = ReadLe32(p + off +  8);
        s.table[i].ctrl    = ReadLe32(p + off + 12);
        off += 16;
    }
    const std::size_t pba_words = (s.num_vectors + 63) / 64;
    s.pba.resize(pba_words);
    for (std::size_t i = 0; i < pba_words; ++i) {
        s.pba[i] = ReadLe64(p + off);
        off += 8;
    }
    return s;
}

}  // namespace tinyvmm::pci
