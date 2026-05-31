#include "legacy_isa.h"

#include <stdexcept>

namespace tinyvmm::devices {

namespace {

// CMOS register layout. Linux reads 0..9 (time), 0x0a (status A) and 0x0b
// (status B) for wall-clock time. Anything else we return 0 for.
constexpr std::uint8_t kCmosSeconds = 0x00;
constexpr std::uint8_t kCmosMinutes = 0x02;
constexpr std::uint8_t kCmosHours   = 0x04;
constexpr std::uint8_t kCmosDayOfMonth = 0x07;
constexpr std::uint8_t kCmosMonth   = 0x08;
constexpr std::uint8_t kCmosYear    = 0x09;
constexpr std::uint8_t kCmosStatusA = 0x0a;
constexpr std::uint8_t kCmosStatusB = 0x0b;
constexpr std::uint8_t kCmosCentury = 0x32;

// BCD encode a 0..99 byte. The CMOS reports time in BCD by default
// (status B bit 2 = 0).
constexpr std::uint8_t Bcd(std::uint8_t v) {
    return static_cast<std::uint8_t>(((v / 10) << 4) | (v % 10));
}

}  // namespace

LegacyIsaStubs::LegacyIsaStubs() = default;

void LegacyIsaStubs::Attach(IoBus& bus) {
    bus.Register(0x70, 1, "cmos-idx",
                 [this](IoAccess& a) { HandleCmosIndex(a); });
    bus.Register(0x71, 1, "cmos-dat",
                 [this](IoAccess& a) { HandleCmosData(a); });
    bus.Register(0x80, 1, "post-diag",
                 [this](IoAccess& a) { HandlePort80(a); });
    bus.Register(0x92, 1, "port92",
                 [this](IoAccess& a) { HandlePort92(a); });
}

void LegacyIsaStubs::HandlePort80(IoAccess& acc) {
    // POST diagnostic port. Linux's outb_p() pokes this for a small
    // delay; the value is debugger-visible on real hardware. We just
    // swallow it.
    if (!acc.is_write) {
        acc.value = 0xff;
    }
}

void LegacyIsaStubs::HandleCmosIndex(IoAccess& acc) {
    std::lock_guard<std::mutex> lk(lock_);
    if (acc.is_write) {
        // Bit 7 of port 0x70 is "NMI disable"; the index itself is bits 6..0.
        cmos_index_ = static_cast<std::uint8_t>(acc.value & 0x7f);
        return;
    }
    // Real hardware: this read is undefined; some chipsets latch it. Return
    // last index.
    acc.value = cmos_index_;
}

void LegacyIsaStubs::HandleCmosData(IoAccess& acc) {
    std::lock_guard<std::mutex> lk(lock_);
    if (acc.is_write) {
        // Writes to status registers are noted but not enforced (our clock
        // has no actual state); writes to time registers are silently
        // dropped.
        return;
    }
    acc.value = ReadCmos(cmos_index_);
}

std::uint8_t LegacyIsaStubs::ReadCmos(std::uint8_t reg) {
    // Fixed wall clock: 2024-01-01 00:00:00 UTC. Anyone who needs better
    // can plumb in QPC -> RFC1123 conversion later.
    switch (reg) {
        case kCmosSeconds:    return Bcd(0);
        case kCmosMinutes:    return Bcd(0);
        case kCmosHours:      return Bcd(0);
        case kCmosDayOfMonth: return Bcd(1);
        case kCmosMonth:      return Bcd(1);
        case kCmosYear:       return Bcd(24);
        case kCmosCentury:    return Bcd(20);
        case kCmosStatusA:    return 0x26;  // 32.768 kHz, rate 1024 Hz, UIP=0
        case kCmosStatusB:    return 0x02;  // 24-hour mode, BCD, no IRQs
        default:              return 0;
    }
}

void LegacyIsaStubs::HandlePort92(IoAccess& acc) {
    std::lock_guard<std::mutex> lk(lock_);
    if (acc.is_write) {
        port92_ = static_cast<std::uint8_t>(acc.value & 0xff);
        return;
    }
    acc.value = port92_;
}

// ---- Phase 33.5 save/restore -------------------------------------------

LegacyIsaStubs::State LegacyIsaStubs::CaptureState() const {
    std::lock_guard<std::mutex> lk(lock_);
    State s;
    s.cmos_index = cmos_index_;
    s.port92     = port92_;
    return s;
}

void LegacyIsaStubs::ApplyState(const LegacyIsaStubs::State& s) {
    std::lock_guard<std::mutex> lk(lock_);
    cmos_index_ = s.cmos_index;
    port92_     = s.port92;
}

std::size_t LegacyIsaStubs::EncodeState(const LegacyIsaStubs::State& s,
                                        std::span<std::uint8_t> out) {
    if (out.size() < kEncodedSize) {
        throw std::runtime_error(
            "LegacyIsaStubs::EncodeState: output span smaller than "
            "kEncodedSize");
    }
    out[0] = s.cmos_index;
    out[1] = s.port92;
    out[2] = 0;
    out[3] = 0;
    return kEncodedSize;
}

LegacyIsaStubs::State LegacyIsaStubs::DecodeState(
    std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kEncodedSize) {
        throw std::runtime_error(
            "LegacyIsaStubs::DecodeState: payload smaller than kEncodedSize");
    }
    State s;
    s.cmos_index = bytes[0];
    s.port92     = bytes[1];
    return s;
}

}  // namespace tinyvmm::devices
