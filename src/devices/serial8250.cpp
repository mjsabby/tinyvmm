#include "serial8250.h"

#include <cstdio>
#include <mutex>

namespace tinyvmm::devices {

namespace {

constexpr std::uint8_t kLcrDlab = 0x80;

// LSR bits we always assert: TEMT (TX shift empty) | THRE (TX holding empty).
// 16550 puts THRE at bit 5, TEMT at bit 6. Our "transmitter" is host I/O so
// it's always idle.
constexpr std::uint8_t kLsrAlwaysReady = (1u << 5) | (1u << 6);

// IIR encoding for "no interrupt pending" with FIFOs disabled. Bit 0 set means
// "no interrupt pending"; bits 6-7 set means "FIFOs enabled" -- we leave them
// clear because we have no FIFO.
constexpr std::uint8_t kIirNoIntr = 0x01;

// MSR defaults: DSR/CTS/DCD asserted (CTS=bit4, DSR=bit5, DCD=bit7) so a guest
// driver doesn't think the line is dead.
constexpr std::uint8_t kMsrDefault = 0x90 | 0x20 | 0x10;

}  // namespace

Serial8250::Serial8250(std::uint16_t base_port, std::FILE* sink)
    : base_(base_port), sink_(sink) {}

void Serial8250::Attach(IoBus& bus) {
    bus.Register(base_, /*size=*/8, "serial8250",
                 [this](IoAccess& acc) { Handle(acc); });
}

void Serial8250::SetSink(std::FILE* sink) {
    std::lock_guard<std::mutex> g(lock_);
    sink_ = sink;
}

std::string Serial8250::DrainCapture() {
    std::lock_guard<std::mutex> g(lock_);
    std::string out = std::move(captured_);
    captured_.clear();
    return out;
}

void Serial8250::Handle(IoAccess& acc) {
    std::lock_guard<std::mutex> g(lock_);
    if (acc.is_write) {
        HandleWrite(acc);
    } else {
        HandleRead(acc);
    }
}

void Serial8250::HandleWrite(IoAccess& acc) {
    const std::uint16_t off = acc.port - base_;
    const std::uint8_t v = static_cast<std::uint8_t>(acc.value & 0xFF);

    switch (off) {
        case 0:  // THR (DLAB=0) or DLL (DLAB=1)
            if (lcr_ & kLcrDlab) {
                dll_ = v;
            } else {
                if (sink_ != nullptr) {
                    std::fputc(v, sink_);
                    std::fflush(sink_);
                }
                if (capture_) {
                    captured_.push_back(static_cast<char>(v));
                }
            }
            break;
        case 1:  // IER (DLAB=0) or DLM (DLAB=1)
            if (lcr_ & kLcrDlab) {
                dlm_ = v;
            } else {
                ier_ = v;
            }
            break;
        case 2:  // FCR (write side of IIR)
            fcr_ = v;
            break;
        case 3:  // LCR
            lcr_ = v;
            break;
        case 4:  // MCR
            mcr_ = v;
            break;
        case 5:  // LSR (write is normally read-only on real hardware)
            // Ignore: writes to LSR are no-ops on a 16550.
            break;
        case 6:  // MSR (read-only)
            break;
        case 7:  // SCR
            scr_ = v;
            break;
        default:
            break;
    }
}

void Serial8250::HandleRead(IoAccess& acc) {
    const std::uint16_t off = acc.port - base_;
    std::uint8_t v = 0;

    switch (off) {
        case 0:  // RBR (DLAB=0) or DLL (DLAB=1)
            v = (lcr_ & kLcrDlab) ? dll_ : 0u;  // RX always empty for now
            break;
        case 1:  // IER or DLM
            v = (lcr_ & kLcrDlab) ? dlm_ : ier_;
            break;
        case 2:  // IIR
            v = kIirNoIntr;
            break;
        case 3:  // LCR
            v = lcr_;
            break;
        case 4:  // MCR
            v = mcr_;
            break;
        case 5:  // LSR
            v = kLsrAlwaysReady;
            break;
        case 6:  // MSR
            v = kMsrDefault;
            break;
        case 7:  // SCR
            v = scr_;
            break;
        default:
            v = 0;
            break;
    }
    acc.value = v;
}

}  // namespace tinyvmm::devices
