#pragma once

#include "../common.h"
#include "io_bus.h"

#include <cstdio>
#include <mutex>
#include <string>

namespace tinyvmm::devices {

// Minimal 8250/16550-compatible UART. Just enough for Linux's
// `serial8250_early` (a.k.a. earlycon=uart8250) and the regular 8250 driver to
// emit text and stay quiet:
//
//   * Writes to THR (base+0)  -> appended to a sink (default: host stdout)
//   * Reads of LSR (base+5)   -> always TX-empty + TX-shift-empty (0x60); RX
//                                empty unless we've staged a byte (we never
//                                do, the guest is print-only for now).
//   * DLAB (LCR bit 7) handling: when set, base+0/+1 are the divisor latch.
//     We accept and remember writes, but we don't actually time-divide -- the
//     guest just wants to talk and gets no pushback.
//   * IER/IIR/MCR/MSR/SCR    -> bookkeeping only; reads return last-written
//                                or sane defaults so probes don't look at
//                                garbage.
//
// Not implemented:
//   * Receive path (no host-input mode yet)
//   * IRQ generation (M5 + interrupt controller)
//   * FIFO depth / FCR effects beyond storing the byte
//
// All access goes through one mutex so a future RX thread can safely poke
// state. For now the guest is single-threaded so the lock is uncontended.
class Serial8250 {
public:
    // `base_port` is typically 0x3F8 for COM1, 0x2F8 for COM2.
    // `sink` defaults to stdout. Pass nullptr to drop output (useful for tests
    // that capture via a custom sink instead).
    explicit Serial8250(std::uint16_t base_port = 0x3F8,
                        std::FILE* sink = stdout);

    // Register all 8 ports on the bus. The handler is `this`, captured by
    // pointer; the Serial8250 must outlive the IoBus.
    void Attach(IoBus& bus);

    // Override the sink at any time (tests use this to capture output to a
    // string).
    void SetSink(std::FILE* sink);

    // Test hook: snapshot of bytes the guest has written to THR since
    // construction (if `record_to_string=true` was set).
    void EnableStringCapture() { capture_ = true; }
    std::string DrainCapture();

private:
    void Handle(IoAccess& acc);
    void HandleRead(IoAccess& acc);
    void HandleWrite(IoAccess& acc);

    std::uint16_t base_;
    std::FILE* sink_;
    std::mutex lock_;

    // Register state. All bytes; reads return the byte zero-extended into
    // `acc.value`. Names follow the 16550 datasheet.
    std::uint8_t ier_ = 0;     // +1, when LCR.DLAB=0
    std::uint8_t lcr_ = 0;     // +3
    std::uint8_t mcr_ = 0;     // +4
    std::uint8_t scr_ = 0;     // +7 (scratch)
    std::uint8_t fcr_ = 0;     // +2 (write-only; FCR bits stored for fun)
    std::uint8_t dll_ = 0;     // +0 with DLAB=1 (divisor low)
    std::uint8_t dlm_ = 0;     // +1 with DLAB=1 (divisor high)

    bool capture_ = false;
    std::string captured_;
};

}  // namespace tinyvmm::devices
