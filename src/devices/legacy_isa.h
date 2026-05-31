#pragma once

#include "common.h"
#include "io_bus.h"

#include <mutex>
#include <span>

namespace tinyvmm::devices {

// Tiny stubs for legacy ISA devices that Linux inevitably touches at boot
// even in a paravirtualised configuration:
//
//   * MC146818 / CMOS RTC: index latch at 0x70, data port at 0x71. The
//     kernel reads the wall clock (registers 0..9) and Status A (0x0a) to
//     check the "Update In Progress" bit. We give it a fixed plausible
//     wall clock (2024-01-01 00:00:00 UTC) and a permanently-clear UIP.
//     M-anything-later can swap this for a real time source.
//
//   * NMI status / system control port A (0x92) -- guests sometimes touch
//     bit 1 (the "fast A20" gate). We accept writes silently.
//
//   * POST diagnostic port 0x80 -- swallowed.
//
// PIC handling has moved to Pic8259 (src/devices/i8259.{h,cpp}) which owns
// ports 0x20/0x21/0xa0/0xa1 and can actually inject interrupts. This stub
// no longer touches them.
//
// All routines log nothing on the hot path; getting these wrong is a boot
// concern, not a perf concern.

class LegacyIsaStubs {
public:
    LegacyIsaStubs();

    // Registers the CMOS index/data, port 0x80, and port 0x92 on the bus.
    void Attach(IoBus& bus);

    // ---- Phase 33.5 save/restore -----------------------------------------
    //
    // Two bytes of guest-visible state: the CMOS index latch and the
    // port 0x92 byte. Persisting these keeps a guest that's mid-CMOS-read
    // (e.g. wall-clock retrieval) byte-identical across save/restore.
    struct State {
        std::uint8_t cmos_index = 0;
        std::uint8_t port92     = 0x02;
    };

    static constexpr std::size_t kEncodedSize = 4u;

    State CaptureState() const;
    void  ApplyState(const State& s);

    static std::size_t EncodeState(const State& s,
                                   std::span<std::uint8_t> out);
    static State       DecodeState(std::span<const std::uint8_t> bytes);

private:
    void HandleCmosIndex(IoAccess& acc);   // 0x70
    void HandleCmosData(IoAccess& acc);    // 0x71
    void HandlePort80(IoAccess& acc);
    void HandlePort92(IoAccess& acc);

    std::uint8_t ReadCmos(std::uint8_t reg);

    // Mutable so CaptureState() can take the lock under const.
    mutable std::mutex lock_;

    std::uint8_t cmos_index_ = 0;
    std::uint8_t port92_ = 0x02;  // bit 1 = A20 gate enabled
};

}  // namespace tinyvmm::devices
