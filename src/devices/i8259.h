#pragma once

#include "common.h"
#include "io_bus.h"

#include <Windows.h>
#include <WinHvPlatform.h>

#include <cstdint>
#include <functional>
#include <mutex>
#include <span>

namespace tinyvmm::devices {

// Minimal Intel 8259A PIC pair (master @ 0x20/0x21, slave @ 0xa0/0xa1).
//
// Why this exists in a paravirtualised VMM:
//   With no ACPI / IO-APIC, Linux's APIC code drops into "virtual wire mode"
//   where ISA IRQs 0..15 still route through the legacy PIC. The kernel
//   programs vectors 0x30..0x3F (IRQ0..15) and expects IRQ delivery through
//   that vector window. Boot-time printk uses *polled* 8250 TX so it works
//   even with no IRQ source -- but as soon as userspace runs, the serial
//   driver switches to IRQ-driven TX and the console wedges after one byte
//   unless we can deliver IRQ 4.
//
// What's implemented:
//   * Full ICW1..ICW4 init sequence so we observe the vector base the kernel
//     programs (typically 0x30 for the master, 0x38 for the slave).
//   * OCW1 interrupt mask register.
//   * OCW2 non-specific and specific EOI (just absorbed; we don't model
//     priorities). OCW3 reads return a plausible status byte.
//   * `Raise(irq)` that translates an ISA IRQ index into a Fixed-vector
//     `WHvRequestInterrupt(vector = base + (irq & 7), dest = 0)` call.
//     Masked IRQs latch in IRR and are re-delivered when the mask is lifted
//     (1->0 transition), matching the real chip's behaviour.
//
// What's deliberately omitted:
//   * IRR/ISR priority arbitration. Our PIC has at most one steady source
//     (the 8250) plus the very-occasional one-shot, so strict priority
//     handling adds zero value.
//   * EOI bookkeeping vs "auto-EOI" mode. The kernel always issues an
//     explicit EOI; we just don't gate further injections on it.
//   * Spurious-IRQ vector handling. Linux's spurious_interrupt() is robust.
//
// Thread safety: all public methods take the same lock. The serial 8250
// raises from the vCPU thread (write to THR); when we add RX from a host
// thread later it'll need the same lock.
class Pic8259 {
public:
    // Inject a Fixed-vector interrupt at the destination vCPU (typically 0).
    // Returns true on success. Decoupled from `whp::InjectMsi` because we
    // want PIC-style (vector-only) injection; no MSI address decoding.
    using InjectFn = std::function<bool(std::uint8_t vector,
                                        std::uint32_t destination)>;

    explicit Pic8259(InjectFn inject);

    // Registers ports 0x20/0x21 (master) and 0xa0/0xa1 (slave) on the bus.
    void Attach(IoBus& bus);

    // Raise IRQ `irq` (0..15). If the IRQ is unmasked, inject the
    // corresponding vector immediately. If masked, latch in IRR; the
    // injection will replay when the mask is cleared.
    void Raise(int irq);

    // Diagnostic accessors.
    std::uint8_t master_vector_base() const noexcept { return master_.vector_base; }
    std::uint8_t slave_vector_base()  const noexcept { return slave_.vector_base; }
    std::uint8_t master_mask() const noexcept { return master_.mask; }
    std::uint8_t slave_mask()  const noexcept { return slave_.mask; }

    // ---- Phase 33.5 save/restore -----------------------------------------
    //
    // Full PIC state for both chips. Snapshots the ICW programming, OCW1
    // masks, latched IRR bits, and (for safety) the mid-init step machine
    // in case the guest is snapshotted between ICW writes.
    //
    // ResumeRuntime() re-injects deliverable IRR bits (unmasked + cascaded)
    // exactly like ReplayLocked() does on a mask-clear edge, clearing each
    // IRR bit it injects so the same vector is not double-delivered. Called
    // after Apply (and after `inject_` is wired, which is always true since
    // it's set at construction).
    struct ChipState {
        std::uint8_t vector_base  = 0;
        std::uint8_t mask         = 0xFF;
        std::uint8_t irr          = 0;
        std::uint8_t icw1         = 0;
        std::uint8_t icw3         = 0;
        std::uint8_t icw4         = 0;
        std::uint8_t step         = 0;   // IcwStep cast as u8
        std::uint8_t expect_icw4  = 0;   // 0/1
    };
    struct State {
        ChipState master;
        ChipState slave;
    };

    static constexpr std::size_t kEncodedSize = 16u;

    State CaptureState() const;
    void  ApplyState(const State& s);
    void  ResumeRuntime();

    static std::size_t EncodeState(const State& s,
                                   std::span<std::uint8_t> out);
    static State       DecodeState(std::span<const std::uint8_t> bytes);

private:
    // ICW programming state machine. Each chip runs its own state.
    enum class IcwStep : std::uint8_t {
        Idle,     // accept OCW1 (mask) on data port; OCW2/OCW3 on cmd port
        Icw2,     // waiting for ICW2 (vector base) on data port
        Icw3,     // waiting for ICW3 (cascade config) on data port
        Icw4,     // waiting for ICW4 (mode bits) on data port
    };

    struct Chip {
        std::uint8_t vector_base = 0;  // ICW2
        std::uint8_t mask = 0xff;      // OCW1 (after reset: everything masked)
        std::uint8_t irr  = 0;         // pending raises waiting for unmask
        std::uint8_t icw1 = 0;
        std::uint8_t icw3 = 0;
        std::uint8_t icw4 = 0;
        IcwStep step = IcwStep::Idle;
        bool expect_icw4 = false;
    };

    void HandleMaster(IoAccess& acc);
    void HandleSlave(IoAccess& acc);

    // Common dispatch. `cmd_port` is true for 0x20/0xa0 (command), false for
    // 0x21/0xa1 (data).
    void HandleChip(Chip& chip, bool is_slave, bool cmd_port, IoAccess& acc);

    // Initialise a chip on ICW1.
    void BeginInit(Chip& chip, std::uint8_t cw);

    // Inject vector for an unmasked IRQ. Caller holds `lock_`.
    void InjectLocked(Chip& chip, int local_irq);

    // After a mask write, replay any IRR bits that are now unmasked.
    void ReplayLocked(Chip& chip, std::uint8_t prev_mask);

    InjectFn inject_;
    mutable std::mutex lock_;
    Chip master_;
    Chip slave_;
};

}  // namespace tinyvmm::devices
