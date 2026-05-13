#include "serial8250.h"

#include <cstdio>
#include <mutex>

namespace tinyvmm::devices {

namespace {

constexpr std::uint8_t kLcrDlab = 0x80;

// IER bits we care about.
constexpr std::uint8_t kIerErbfi = 0x01;  // RX data-available interrupt enable
constexpr std::uint8_t kIerEtbei = 0x02;  // TX holding-register empty interrupt
                                          // enable (drives userspace TX path)

// LSR bits we always assert: TEMT (TX shift empty) | THRE (TX holding empty).
// 16550 puts THRE at bit 5, TEMT at bit 6. Our "transmitter" is host I/O so
// it's always idle.
constexpr std::uint8_t kLsrAlwaysReady = (1u << 5) | (1u << 6);

// IIR encoding for "no interrupt pending" with FIFOs disabled. Bit 0 set means
// "no interrupt pending"; bits 6-7 set means "FIFOs enabled" -- we leave them
// clear because we have no FIFO.
constexpr std::uint8_t kIirNoIntr   = 0x01;
constexpr std::uint8_t kIirThreIntr = 0x02;  // THR empty (TX) interrupt

// Set to true to log every THR write (one stderr line per byte of guest
// console output). Useful when tracing IRQ-driven TX behavior.
constexpr bool k8250TraceTx = false;

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

void Serial8250::SetIrqCallback(IrqRaiseFn fn) {
    std::lock_guard<std::mutex> g(lock_);
    irq_raise_ = std::move(fn);
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

void Serial8250::MaybeRaiseTxIrqLocked() {
    // Caller holds lock_. The transmitter is always "ready" in our model
    // (we never queue bytes), so as long as ETBEI is set we may signal.
    if (!irq_raise_) {
        return;
    }
    if ((ier_ & kIerEtbei) == 0) {
        return;
    }
    if (tx_irq_pending_) {
        // Already queued; guest hasn't acknowledged via IIR read yet.
        return;
    }
    tx_irq_pending_ = true;
    if (k8250TraceTx) {
        std::fprintf(stderr, "[8250] tx-irq raise (IER=0x%02x)\n",
                     static_cast<unsigned>(ier_));
    }
    // Call out with the lock held; the PIC takes its own mutex and
    // doesn't reenter us.
    irq_raise_(kIsaIrq);
}

void Serial8250::HandleWrite(IoAccess& acc) {
    const std::uint16_t off = acc.port - base_;
    const std::uint8_t v = static_cast<std::uint8_t>(acc.value & 0xFF);

    switch (off) {
        case 0:  // THR (DLAB=0) or DLL (DLAB=1)
            if (lcr_ & kLcrDlab) {
                dll_ = v;
                if (k8250TraceTx) {
                    std::fprintf(stderr, "[8250] DLL=0x%02x (DLAB set)\n", v);
                }
            } else {
                ++tx_bytes_;
                if (sink_ != nullptr) {
                    std::fputc(v, sink_);
                    std::fflush(sink_);
                }
                if (capture_) {
                    captured_.push_back(static_cast<char>(v));
                }
                if (k8250TraceTx) {
                    std::fprintf(stderr, "[8250] THR=0x%02x '%c'\n",
                                 v, (v >= 0x20 && v < 0x7f)
                                        ? static_cast<char>(v)
                                        : '.');
                }
                MaybeRaiseTxIrqLocked();
            }
            break;
        case 1:  // IER (DLAB=0) or DLM (DLAB=1)
            if (lcr_ & kLcrDlab) {
                dlm_ = v;
            } else {
                const std::uint8_t prev = ier_;
                ier_ = v;
                if (k8250TraceTx) {
                    std::fprintf(stderr, "[8250] IER 0x%02x -> 0x%02x\n", prev, v);
                }
                if ((prev & kIerEtbei) == 0 && (ier_ & kIerEtbei) != 0) {
                    // 0 -> 1 transition on the TX-IRQ enable. Raise now.
                    MaybeRaiseTxIrqLocked();
                }
                if ((ier_ & kIerEtbei) == 0) {
                    // Disabling TX IRQ clears any queued source.
                    tx_irq_pending_ = false;
                }
            }
            break;
        case 2:  // FCR (write side of IIR)
            fcr_ = v;
            break;
        case 3:  // LCR
            if (k8250TraceTx) {
                std::fprintf(stderr, "[8250] LCR 0x%02x -> 0x%02x (DLAB=%d)\n",
                             lcr_, v, (v & kLcrDlab) ? 1 : 0);
            }
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
            // Real 16550 priority: RX-data > THRE > line-status > modem.
            // We only model THRE (TX). Reading IIR clears the THRE source.
            if (tx_irq_pending_) {
                v = kIirThreIntr;
                tx_irq_pending_ = false;
                if (k8250TraceTx) {
                    std::fprintf(stderr, "[8250] IIR=0x02 (THRE, cleared pending)\n");
                }
            } else {
                v = kIirNoIntr;
                if (k8250TraceTx) {
                    std::fprintf(stderr, "[8250] IIR=0x01 (none, IER=0x%02x)\n",
                                 static_cast<unsigned>(ier_));
                }
            }
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


