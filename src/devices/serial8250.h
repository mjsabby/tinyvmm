#pragma once

#include "common.h"
#include "io_bus.h"

#include <cstdio>
#include <functional>
#include <mutex>
#include <span>
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
//   * Optional IRQ raise callback (M19c). When the guest sets
//     `IER.ETBEI=1` and the transmitter is "ready" (always, in our
//     model), we raise IRQ 4 once. Inside the IRQ handler the guest
//     reads IIR, sees `0x02` (THRE), drains its circ_buf via THR
//     writes, then either issues another transmit (which re-raises) or
//     clears ETBEI. Linux's serial driver is robust to the spurious
//     re-fire that this edge-triggered model occasionally produces.
//
// Not implemented:
//   * Receive path (no host-input mode yet) -- so we never raise IRQ on
//     RX-data-available. Easy follow-up once we wire stdin.
//   * FIFO depth / FCR effects beyond storing the byte.
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

    // Wire up the legacy-PIC IRQ. The callback is invoked with the
    // *ISA* IRQ number (always 4 for COM1). Pass `nullptr` to detach.
    // Without a callback, the 8250 still bookkeeps IER/IIR but never
    // signals an interrupt -- which is fine for polled callers like
    // boot-time printk but stalls userspace `write()` (M19c blocker).
    using IrqRaiseFn = std::function<void(int isa_irq)>;
    void SetIrqCallback(IrqRaiseFn fn);

    // Test hook: snapshot of bytes the guest has written to THR since
    // construction (if `record_to_string=true` was set).
    void EnableStringCapture() { capture_ = true; }
    std::string DrainCapture();

    // ---- Phase 33.5 save/restore -----------------------------------------
    //
    // Guest-visible state: the seven 8250 registers (IER/LCR/MCR/SCR/FCR
    // plus the divisor latch DLL/DLM) and our edge-triggered TX-IRQ
    // pending bit. We also persist `first_byte_fired_` so the boot-time
    // "first byte seen" callback doesn't re-fire after restore.
    //
    // NOT persisted: capture_/captured_/sink_/irq_raise_/first_byte_cb_
    // (host-side wiring; the caller re-wires these BEFORE Apply) and
    // tx_bytes_ (diagnostic counter; resets to 0 on restore).
    //
    // ResumeRuntime() is the deferred half: if the saved state had a TX
    // IRQ pending AND the guest had ETBEI=1, we re-raise IRQ4 once so the
    // guest doesn't deadlock waiting for the THRE interrupt that was in
    // flight when we snapshotted. ApplyState() itself never touches the
    // IRQ line, so it's safe to call before the PIC is wired up.
    struct State {
        std::uint8_t ier               = 0;
        std::uint8_t lcr               = 0;
        std::uint8_t mcr               = 0;
        std::uint8_t scr               = 0;
        std::uint8_t fcr               = 0;
        std::uint8_t dll               = 0;
        std::uint8_t dlm               = 0;
        std::uint8_t tx_irq_pending    = 0;
        std::uint8_t first_byte_fired  = 0;
    };

    static constexpr std::size_t kEncodedSize = 16u;

    State CaptureState() const;
    void  ApplyState(const State& s);

    // Called after ApplyState (and after SetIrqCallback) to re-arm the
    // host-side runtime side-effects. Idempotent.
    void  ResumeRuntime();

    static std::size_t EncodeState(const State& s,
                                   std::span<std::uint8_t> out);
    static State       DecodeState(std::span<const std::uint8_t> bytes);

private:
    void Handle(IoAccess& acc);
    void HandleRead(IoAccess& acc);
    void HandleWrite(IoAccess& acc);

    // Re-evaluate whether the TX-IRQ should be asserted, given current IER
    // and pending state. Caller holds `lock_`. May invoke `irq_raise_`
    // (which itself takes the PIC's lock; safe as long as no PIC method
    // calls back into us).
    void MaybeRaiseTxIrqLocked();

    // The ISA IRQ assignment for COM1. Conventional; not configurable
    // here because Linux hard-codes it for the 0x3F8 base.
    static constexpr int kIsaIrq = 4;

    std::uint16_t base_;
    std::FILE* sink_;
    mutable std::mutex lock_;
    IrqRaiseFn irq_raise_;

    // Register state. All bytes; reads return the byte zero-extended into
    // `acc.value`. Names follow the 16550 datasheet.
    std::uint8_t ier_ = 0;     // +1, when LCR.DLAB=0
    std::uint8_t lcr_ = 0;     // +3
    std::uint8_t mcr_ = 0;     // +4
    std::uint8_t scr_ = 0;     // +7 (scratch)
    std::uint8_t fcr_ = 0;     // +2 (write-only; FCR bits stored for fun)
    std::uint8_t dll_ = 0;     // +0 with DLAB=1 (divisor low)
    std::uint8_t dlm_ = 0;     // +1 with DLAB=1 (divisor high)

    // TX-IRQ bookkeeping. `tx_irq_pending_` is set when we've queued an
    // injection but the guest hasn't read IIR yet; a read of IIR returns
    // the THRE-interrupt code and clears it. We only call `irq_raise_`
    // when transitioning false->true, so we don't burst-inject.
    bool tx_irq_pending_ = false;

    bool capture_ = false;
    std::string captured_;

    // Optional callback invoked on the FIRST byte ever written to THR
    // (after construction). Used by tinyvmm's BootTimer to record when the
    // kernel first emits output via earlyprintk/ttyS0 -- typically far
    // earlier than the virtio-console becomes live.
    using FirstByteFn = std::function<void()>;
    FirstByteFn first_byte_cb_;
    bool first_byte_fired_ = false;

public:
    void SetFirstByteCallback(FirstByteFn fn) { first_byte_cb_ = std::move(fn); }

private:

    // Lifetime statistics: number of bytes the guest wrote to THR. Useful
    // for confirming kernel output is reaching the UART even when stdout is
    // captured/piped and visible bytes get lost.
public:
    std::uint64_t tx_bytes() const noexcept { return tx_bytes_; }
private:
    std::uint64_t tx_bytes_ = 0;
};

}  // namespace tinyvmm::devices
