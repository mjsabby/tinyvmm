#include "pci_device.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace tinyvmm::pci {

namespace {

constexpr bool IsPow2(std::uint32_t v) {
    return v != 0 && (v & (v - 1)) == 0;
}

// Reads a little-endian 1/2/4-byte slice out of a byte buffer.
std::uint32_t ReadLe(const std::uint8_t* p, std::uint32_t size) {
    std::uint32_t v = 0;
    for (std::uint32_t i = 0; i < size; ++i) {
        v |= static_cast<std::uint32_t>(p[i]) << (8 * i);
    }
    return v;
}

}  // namespace

void PciDevice::set_ids(std::uint16_t vendor_id, std::uint16_t device_id,
                        std::uint16_t subsys_vendor_id,
                        std::uint16_t subsys_id) {
    cfg_[kCfgVendorId + 0] = static_cast<std::uint8_t>(vendor_id & 0xFF);
    cfg_[kCfgVendorId + 1] = static_cast<std::uint8_t>(vendor_id >> 8);
    cfg_[kCfgDeviceId + 0] = static_cast<std::uint8_t>(device_id & 0xFF);
    cfg_[kCfgDeviceId + 1] = static_cast<std::uint8_t>(device_id >> 8);
    cfg_[kCfgSubsysVendorId + 0] =
        static_cast<std::uint8_t>(subsys_vendor_id & 0xFF);
    cfg_[kCfgSubsysVendorId + 1] =
        static_cast<std::uint8_t>(subsys_vendor_id >> 8);
    cfg_[kCfgSubsysId + 0] = static_cast<std::uint8_t>(subsys_id & 0xFF);
    cfg_[kCfgSubsysId + 1] = static_cast<std::uint8_t>(subsys_id >> 8);

    // Reasonable defaults for the standard header:
    cfg_[kCfgHeaderType] = kHeaderTypeNormal;

    // COMMAND is writable; the spec marks bits 9 and [11..15] as RO 0. We let
    // software toggle the rest. (We accept all 16 bits as writable and just
    // ignore the ones we don't act on.)
    writable_mask_[kCfgCommand + 0] = 0xFF;
    writable_mask_[kCfgCommand + 1] = 0xFF;

    // STATUS is RW1C in hardware; for our purposes RO is fine -- guests
    // don't normally clear it during boot scan.
    // INTERRUPT_LINE is fully writable (software scratch; we don't use INTx).
    writable_mask_[kCfgInterruptLine] = 0xFF;
    // CACHE_LINE_SIZE, LATENCY_TIMER -- writable, side-effect-free.
    writable_mask_[kCfgCacheLineSize] = 0xFF;
    writable_mask_[kCfgLatencyTimer]  = 0xFF;
}

void PciDevice::set_class(std::uint8_t class_code, std::uint8_t subclass,
                          std::uint8_t prog_if, std::uint8_t revision) {
    cfg_[kCfgRevisionId] = revision;
    cfg_[kCfgProgIf]     = prog_if;
    cfg_[kCfgSubclass]   = subclass;
    cfg_[kCfgClassCode]  = class_code;
}

void PciDevice::set_interrupt_pin(std::uint8_t pin) {
    cfg_[kCfgInterruptPin] = pin;
}

void PciDevice::DeclareIoBar(int idx, std::uint32_t size) {
    if (idx < 0 || idx >= 6) Fatal("DeclareIoBar: idx out of range");
    if (!IsPow2(size) || size < 4)
        Fatal("DeclareIoBar: size must be a power of 2 >= 4");
    if (bars_[idx].type != BarType::None)
        Fatal("DeclareIoBar: BAR already declared");
    bars_[idx].type = BarType::Io;
    bars_[idx].size = size;
    // BAR cell is writable; the dword path masks size bits + OR's type bits.
    for (int b = 0; b < 4; ++b) {
        writable_mask_[kCfgBar0 + 4 * idx + b] = 0xFF;
    }
}

void PciDevice::DeclareMmio32Bar(int idx, std::uint32_t size,
                                 bool prefetchable) {
    if (idx < 0 || idx >= 6) Fatal("DeclareMmio32Bar: idx out of range");
    if (!IsPow2(size) || size < 16)
        Fatal("DeclareMmio32Bar: size must be a power of 2 >= 16");
    if (bars_[idx].type != BarType::None)
        Fatal("DeclareMmio32Bar: BAR already declared");
    bars_[idx].type = BarType::Mmio32;
    bars_[idx].size = size;
    bars_[idx].prefetchable = prefetchable;
    for (int b = 0; b < 4; ++b) {
        writable_mask_[kCfgBar0 + 4 * idx + b] = 0xFF;
    }
}

void PciDevice::DeclareMmio64Bar(int idx, std::uint32_t size,
                                 bool prefetchable) {
    if (idx < 0 || idx > 4) Fatal("DeclareMmio64Bar: idx out of range");
    if (!IsPow2(size) || size < 16)
        Fatal("DeclareMmio64Bar: size must be a power of 2 >= 16");
    if (bars_[idx].type != BarType::None ||
        bars_[idx + 1].type != BarType::None)
        Fatal("DeclareMmio64Bar: BAR already declared");
    bars_[idx].type = BarType::Mmio64;
    bars_[idx].size = size;
    bars_[idx].prefetchable = prefetchable;
    // The high half BAR is a continuation; mark it so nobody reuses it but
    // route reads/writes through the low half.
    bars_[idx + 1].type = BarType::None;
    for (int b = 0; b < 8; ++b) {
        writable_mask_[kCfgBar0 + 4 * idx + b] = 0xFF;
    }
}

std::uint32_t PciDevice::AppendCapability(std::uint8_t cap_id,
                                          std::uint32_t payload_size) {
    if (payload_size < 2) {
        // Convention: payload includes the two-byte cap header (id + next).
        Fatal("AppendCapability: payload_size must be >= 2 (cap header)");
    }
    if (cap_next_alloc_ + payload_size > kCfgSpaceSize) {
        Fatal("AppendCapability: capabilities overflow 256-byte config space");
    }
    const std::uint32_t off = cap_next_alloc_;
    // Chain: if there's no head yet, set CapPtr; otherwise patch the previous
    // tail's "next" byte.
    if (cfg_[kCfgCapPtr] == 0) {
        cfg_[kCfgCapPtr] = static_cast<std::uint8_t>(off);
        // Light Status.CapList bit so the spec-driver path knows to walk it.
        const std::uint16_t st = cfg_read16(kCfgStatus) | kStatusCapList;
        cfg_[kCfgStatus + 0] = static_cast<std::uint8_t>(st & 0xFF);
        cfg_[kCfgStatus + 1] = static_cast<std::uint8_t>(st >> 8);
    } else {
        // Walk to the last entry and update its next pointer.
        std::uint32_t cur = cfg_[kCfgCapPtr];
        while (true) {
            const std::uint8_t nxt = cfg_[cur + 1];
            if (nxt == 0) break;
            cur = nxt;
        }
        cfg_[cur + 1] = static_cast<std::uint8_t>(off);
    }
    cfg_[off + 0] = cap_id;
    cfg_[off + 1] = 0;  // next = 0; will be patched when another cap is added
    cap_next_alloc_ += payload_size;
    return off;
}

std::uint32_t PciDevice::cfg_read32(std::uint32_t offset) const {
    return ReadLe(&cfg_[offset], 4);
}
std::uint16_t PciDevice::cfg_read16(std::uint32_t offset) const {
    return static_cast<std::uint16_t>(ReadLe(&cfg_[offset], 2));
}
std::uint8_t PciDevice::cfg_read8(std::uint32_t offset) const {
    return cfg_[offset];
}

std::uint16_t PciDevice::command() const { return cfg_read16(kCfgCommand); }
std::uint16_t PciDevice::status()  const { return cfg_read16(kCfgStatus); }

void PciDevice::SetBarBase(int idx, std::uint64_t gpa) {
    const Bar& b = bars_[idx];
    if (b.type == BarType::None) return;
    switch (b.type) {
      case BarType::Io:
        // Bottom 2 bits are type marker (1 + reserved); top 30 are base.
        bars_[idx].value_lo = static_cast<std::uint32_t>(gpa);
        break;
      case BarType::Mmio32:
        bars_[idx].value_lo = static_cast<std::uint32_t>(gpa);
        break;
      case BarType::Mmio64:
        bars_[idx].value_lo = static_cast<std::uint32_t>(gpa & 0xFFFFFFFFu);
        bars_[idx].value_hi = static_cast<std::uint32_t>(gpa >> 32);
        break;
      case BarType::None:
        break;
    }
}

std::uint32_t PciDevice::BarSizeMaskLow(const Bar& b) {
    if (b.size == 0) return 0;
    switch (b.type) {
      case BarType::Io:
        // IO BAR low 2 bits are RO (01b); size mask covers the rest of dword.
        return ~(b.size - 1) & 0xFFFFFFFCu;
      case BarType::Mmio32:
      case BarType::Mmio64:
        return ~(b.size - 1) & 0xFFFFFFF0u;
      case BarType::None:
        return 0;
    }
    return 0;
}

std::uint32_t PciDevice::BarSizeMaskHigh(const Bar& b) {
    if (b.type != BarType::Mmio64 || b.size == 0) return 0;
    // b.size is uint32_t, so size is at most 4 GiB, and the high 32 bits of
    // the size mask are always all-ones. If we ever support >4 GiB BARs we'd
    // promote Bar::size to uint64_t and compute ~(size-1) >> 32 here.
    return 0xFFFFFFFFu;
}

std::uint32_t PciDevice::ReadBarDword(int idx) const {
    const Bar& b = bars_[idx];
    if (b.type == BarType::None) {
        // Could be either truly unused or the high half of a 64-bit BAR;
        // figure out which.
        if (idx > 0 && bars_[idx - 1].type == BarType::Mmio64) {
            return bars_[idx - 1].value_hi & BarSizeMaskHigh(bars_[idx - 1]);
        }
        return 0;
    }
    std::uint32_t v = b.value_lo & BarSizeMaskLow(b);
    switch (b.type) {
      case BarType::Io:
        v |= kBarIoMarker;
        break;
      case BarType::Mmio32:
        if (b.prefetchable) v |= kBarPrefetchable;
        // bits[2:1] = 00 (32-bit, locate anywhere)
        break;
      case BarType::Mmio64:
        v |= kBarMmio64;
        if (b.prefetchable) v |= kBarPrefetchable;
        break;
      case BarType::None:
        break;
    }
    return v;
}

void PciDevice::WriteBarDword(int idx, std::uint32_t value) {
    Bar& b = bars_[idx];
    if (b.type == BarType::None) {
        // Treat as the high half of a 64-bit BAR if applicable.
        if (idx > 0 && bars_[idx - 1].type == BarType::Mmio64) {
            bars_[idx - 1].value_hi = value & BarSizeMaskHigh(bars_[idx - 1]);
        }
        return;
    }
    b.value_lo = value & BarSizeMaskLow(b);
}

void PciDevice::RecomputeMappings(std::uint16_t /*old_cmd*/,
                                   std::uint16_t new_cmd) {
    const bool mem_on = (new_cmd & kCmdMemorySpace) != 0;
    for (int i = 0; i < 6; ++i) {
        Bar& b = bars_[i];
        if (b.type != BarType::Mmio32 && b.type != BarType::Mmio64) continue;
        std::uint64_t gpa = b.value_lo & ~static_cast<std::uint64_t>(0xF);
        if (b.type == BarType::Mmio64) {
            gpa |= static_cast<std::uint64_t>(b.value_hi) << 32;
        }
        const bool want_mapped = mem_on && gpa != 0;
        if (want_mapped && !b.mapped) {
            b.mapped = true;
            b.mapped_gpa = gpa;
            OnBarMapped(i, gpa, b.size);
        } else if (!want_mapped && b.mapped) {
            const int saved_idx = i;
            b.mapped = false;
            OnBarUnmapped(saved_idx);
        } else if (want_mapped && b.mapped && b.mapped_gpa != gpa) {
            // Driver remapped a BAR while MEM_SPACE was on. Rare; handle by
            // bouncing through unmap+map so the device side cleanly relocates.
            const int saved_idx = i;
            const std::uint64_t new_gpa = gpa;
            OnBarUnmapped(saved_idx);
            b.mapped_gpa = new_gpa;
            OnBarMapped(saved_idx, new_gpa, b.size);
        }
    }
}

void PciDevice::WriteByte(std::uint32_t offset, std::uint8_t value) {
    const std::uint8_t mask = writable_mask_[offset];
    cfg_[offset] = (cfg_[offset] & ~mask) | (value & mask);
}

std::uint8_t PciDevice::ReadByte(std::uint32_t offset) const {
    return cfg_[offset];
}

std::uint32_t PciDevice::ReadConfigImpl(std::uint32_t offset,
                                         std::uint32_t size) {
    // BAR window? Compose from BAR descriptors so sizing works.
    if (offset >= kCfgBar0 && offset + size <= kCfgBar0 + 6 * 4) {
        const std::uint32_t bar_idx_lo = (offset - kCfgBar0) / 4;
        const std::uint32_t bar_idx_hi = (offset + size - 1 - kCfgBar0) / 4;
        if (bar_idx_lo == bar_idx_hi) {
            const std::uint32_t dword = ReadBarDword(static_cast<int>(bar_idx_lo));
            const std::uint32_t byte_off = (offset - kCfgBar0) % 4;
            return (dword >> (8 * byte_off)) &
                   ((size == 4) ? 0xFFFFFFFFu : ((1u << (8 * size)) - 1));
        }
        // Cross-BAR access is exotic; Linux never does it. Fall through to raw.
    }
    return ReadLe(&cfg_[offset], size);
}

void PciDevice::WriteConfigImpl(std::uint32_t offset, std::uint32_t size,
                                 std::uint32_t value) {
    // COMMAND write?
    if (offset <= kCfgCommand + 1 && offset + size > kCfgCommand) {
        // Apply the byte mask first (writable bits), then snapshot pre/post
        // COMMAND for the mapping recompute hook.
        const std::uint16_t old_cmd = command();
        for (std::uint32_t i = 0; i < size; ++i) {
            WriteByte(offset + i,
                      static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
        }
        const std::uint16_t new_cmd = command();
        if (old_cmd != new_cmd) {
            RecomputeMappings(old_cmd, new_cmd);
        }
        return;
    }

    // BAR write?
    if (offset >= kCfgBar0 && offset + size <= kCfgBar0 + 6 * 4) {
        const std::uint32_t bar_idx = (offset - kCfgBar0) / 4;
        const std::uint32_t byte_off = (offset - kCfgBar0) % 4;
        // Build the full dword: keep the unchanged bytes from the existing
        // BAR cell, splice in `value` at byte_off.
        std::uint32_t cur = ReadBarDword(static_cast<int>(bar_idx));
        // Strip the type bits we'd otherwise re-introduce on read-back; the
        // size mask will reapply them.
        cur &= BarSizeMaskLow(bars_[bar_idx]);
        if (size == 4 && byte_off == 0) {
            cur = value;
        } else {
            const std::uint32_t mask = ((size == 4) ? 0xFFFFFFFFu :
                                        ((1u << (8 * size)) - 1)) << (8 * byte_off);
            cur = (cur & ~mask) | ((value << (8 * byte_off)) & mask);
        }
        WriteBarDword(static_cast<int>(bar_idx), cur);
        // We do NOT remap on BAR write -- only on COMMAND.MEM_SPACE
        // transitions. Linux always programs BARs first and then enables.
        return;
    }

    // Default: per-byte writable-mask handling.
    for (std::uint32_t i = 0; i < size; ++i) {
        WriteByte(offset + i,
                  static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

std::uint32_t PciDevice::ConfigRead(std::uint32_t offset, std::uint32_t size) {
    if (offset + size > kCfgSpaceSize) {
        // Beyond legacy 256-byte space -- return all-ones (PCIe extended
        // space not implemented yet).
        return (size == 4) ? 0xFFFFFFFFu : ((1u << (8 * size)) - 1);
    }
    return ReadConfigImpl(offset, size);
}

void PciDevice::ConfigWrite(std::uint32_t offset, std::uint32_t size,
                             std::uint32_t value) {
    if (offset + size > kCfgSpaceSize) return;  // out of range: ignore
    WriteConfigImpl(offset, size, value);
}

}  // namespace tinyvmm::pci
