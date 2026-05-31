#include "i8259.h"
#include "../whp/snapshot_file.h"

#include <cstdio>
#include <stdexcept>

namespace tinyvmm::devices {

namespace {
constexpr bool kPicDebug = false;
}

namespace {

// ICW1 bit definitions (sent to command port, value has bit 4 = "is ICW1").
constexpr std::uint8_t kIcw1IsInit = 0x10;  // bit 4 = 1 marks the byte as ICW1
constexpr std::uint8_t kIcw1Ic4    = 0x01;  // bit 0 = "ICW4 follows"
// Bit 1 = SNGL (single, no slave), bit 3 = LTIM (level-triggered).

// OCW3 shape: command port, bit 4 = 0, bit 3 = 1.
constexpr std::uint8_t kOcw3Mark   = 0x08;

}  // namespace

Pic8259::Pic8259(InjectFn inject) : inject_(std::move(inject)) {}

void Pic8259::Attach(IoBus& bus) {
    bus.Register(0x20, 2, "pic-master",
                 [this](IoAccess& a) { HandleMaster(a); });
    bus.Register(0xa0, 2, "pic-slave",
                 [this](IoAccess& a) { HandleSlave(a); });
}

void Pic8259::HandleMaster(IoAccess& acc) {
    HandleChip(master_, /*is_slave=*/false,
               /*cmd_port=*/(acc.port == 0x20), acc);
}

void Pic8259::HandleSlave(IoAccess& acc) {
    HandleChip(slave_, /*is_slave=*/true,
               /*cmd_port=*/(acc.port == 0xa0), acc);
}

void Pic8259::BeginInit(Chip& chip, std::uint8_t cw) {
    chip.icw1 = cw;
    chip.expect_icw4 = (cw & kIcw1Ic4) != 0;
    chip.mask = 0xff;       // ICW1 resets the mask (real chip behaviour)
    chip.irr  = 0;
    chip.step = IcwStep::Icw2;
    if (kPicDebug) {
        std::fprintf(stderr, "[pic] %s ICW1=0x%02x (expect_icw4=%d)\n",
                     (&chip == &master_) ? "master" : "slave",
                     cw, chip.expect_icw4 ? 1 : 0);
    }
}

void Pic8259::HandleChip(Chip& chip, bool /*is_slave*/, bool cmd_port,
                         IoAccess& acc) {
    std::lock_guard<std::mutex> lk(lock_);

    if (acc.is_write) {
        const std::uint8_t v = static_cast<std::uint8_t>(acc.value & 0xff);
        if (cmd_port) {
            if (v & kIcw1IsInit) {
                BeginInit(chip, v);
            } else if ((v & kOcw3Mark) != 0) {
                // OCW3 - status read configuration. Nothing to track for
                // our minimal implementation; the read side returns plausible
                // values regardless.
                // (We could remember which register the next cmd-port read
                // should return; in practice Linux uses OCW3 mostly for
                // poll mode which we don't implement.)
            } else {
                // OCW2: EOI. We don't track ISR, so absorb silently.
                (void)v;
            }
        } else {
            // Data port: either an ICW (during init sequence) or OCW1 (mask).
            switch (chip.step) {
                case IcwStep::Icw2: {
                    // ICW2: vector base. Low 3 bits are forced to zero on
                    // the real chip.
                    chip.vector_base = v & 0xf8;
                    if (kPicDebug) {
                        std::fprintf(stderr,
                                     "[pic] %s ICW2 vector_base=0x%02x\n",
                                     (&chip == &master_) ? "master" : "slave",
                                     chip.vector_base);
                    }
                    // Decide whether ICW3 is expected: in our two-chip setup
                    // we always cascade, so yes.
                    chip.step = IcwStep::Icw3;
                    break;
                }
                case IcwStep::Icw3: {
                    chip.icw3 = v;
                    chip.step = chip.expect_icw4 ? IcwStep::Icw4
                                                 : IcwStep::Idle;
                    break;
                }
                case IcwStep::Icw4: {
                    chip.icw4 = v;
                    chip.step = IcwStep::Idle;
                    break;
                }
                case IcwStep::Idle: {
                    // OCW1: interrupt mask register.
                    const std::uint8_t prev = chip.mask;
                    chip.mask = v;
                    if constexpr (kPicDebug) {
                        if (prev != v) {
                            std::fprintf(stderr,
                                         "[pic] %s OCW1 mask 0x%02x -> 0x%02x\n",
                                         (&chip == &master_) ? "master" : "slave",
                                         prev, v);
                        }
                    }
                    ReplayLocked(chip, prev);
                    break;
                }
            }
        }
        return;
    }

    // Read side.
    std::uint8_t r = 0;
    if (cmd_port) {
        // OCW3-read selects IRR or ISR. We don't track ISR; return IRR for
        // the rare cases Linux peeks (and 0 otherwise).
        r = chip.irr;
    } else {
        r = chip.mask;
    }
    acc.value = r;
}

void Pic8259::InjectLocked(Chip& chip, int local_irq) {
    if (!inject_) {
        return;
    }
    const std::uint8_t vector =
        static_cast<std::uint8_t>(chip.vector_base + (local_irq & 7));
    if constexpr (kPicDebug) {
        if (local_irq != 0) {  // skip PIT spam
            std::fprintf(stderr, "[pic] inject vector=0x%02x (%s irq %d)\n",
                         vector, (&chip == &master_) ? "master" : "slave",
                         local_irq);
        }
    }
    // Destination = vCPU 0. We're single-vCPU for now; if/when this grows
    // multi-vCPU the legacy PIC traditionally only steers IRQs to the BSP.
    inject_(vector, /*destination=*/0);
}

void Pic8259::ReplayLocked(Chip& chip, std::uint8_t prev_mask) {
    // For each bit that went 1 -> 0 (unmasked) AND has a latched IRR bit,
    // inject and clear the IRR bit.
    const std::uint8_t newly_unmasked = static_cast<std::uint8_t>(
        prev_mask & ~chip.mask);
    if (newly_unmasked == 0) {
        return;
    }
    for (int i = 0; i < 8; ++i) {
        const std::uint8_t bit = static_cast<std::uint8_t>(1u << i);
        if ((newly_unmasked & bit) && (chip.irr & bit)) {
            chip.irr &= ~bit;
            InjectLocked(chip, i);
        }
    }
}

void Pic8259::Raise(int irq) {
    if (irq < 0 || irq > 15) {
        return;
    }
    std::lock_guard<std::mutex> lk(lock_);
    Chip& chip = (irq < 8) ? master_ : slave_;
    const int local = irq & 7;
    const std::uint8_t bit = static_cast<std::uint8_t>(1u << local);

    if (chip.mask & bit) {
        // Masked: latch and let ReplayLocked re-deliver on unmask.
        chip.irr |= bit;
        if constexpr (kPicDebug) {
            if (irq != 0) {
                std::fprintf(stderr, "[pic] raise irq=%d MASKED (mask=0x%02x)\n",
                             irq, chip.mask);
            }
        }
        return;
    }

    // For IRQs on the slave chip, the master must have IRQ 2 (cascade)
    // unmasked too; if it's masked the IRQ would stay pending. We don't
    // model the slave path strictly because nothing on our bus uses it
    // yet, but be conservative and refuse delivery if cascade is masked.
    if (irq >= 8) {
        constexpr std::uint8_t kCascadeBit = 1u << 2;
        if (master_.mask & kCascadeBit) {
            chip.irr |= bit;
            return;
        }
    }

    InjectLocked(chip, local);
}

// ---- Phase 33.5 save/restore ---------------------------------------------

namespace {

void ChipToBytes(const Pic8259::ChipState& c, std::uint8_t* p) {
    p[0] = c.vector_base;
    p[1] = c.mask;
    p[2] = c.irr;
    p[3] = c.icw1;
    p[4] = c.icw3;
    p[5] = c.icw4;
    p[6] = c.step;
    p[7] = c.expect_icw4 ? 1u : 0u;
}

Pic8259::ChipState ChipFromBytes(const std::uint8_t* p) {
    Pic8259::ChipState c;
    c.vector_base = p[0];
    c.mask        = p[1];
    c.irr         = p[2];
    c.icw1        = p[3];
    c.icw3        = p[4];
    c.icw4        = p[5];
    c.step        = p[6];
    c.expect_icw4 = (p[7] != 0) ? 1u : 0u;
    return c;
}

}  // namespace

Pic8259::State Pic8259::CaptureState() const {
    std::lock_guard<std::mutex> lk(lock_);
    auto snap = [](const Chip& src) {
        ChipState d;
        d.vector_base = src.vector_base;
        d.mask        = src.mask;
        d.irr         = src.irr;
        d.icw1        = src.icw1;
        d.icw3        = src.icw3;
        d.icw4        = src.icw4;
        d.step        = static_cast<std::uint8_t>(src.step);
        d.expect_icw4 = src.expect_icw4 ? 1u : 0u;
        return d;
    };
    State s;
    s.master = snap(master_);
    s.slave  = snap(slave_);
    return s;
}

void Pic8259::ApplyState(const Pic8259::State& s) {
    std::lock_guard<std::mutex> lk(lock_);
    auto restore = [](Chip& dst, const ChipState& src) {
        dst.vector_base = src.vector_base;
        dst.mask        = src.mask;
        dst.irr         = src.irr;
        dst.icw1        = src.icw1;
        dst.icw3        = src.icw3;
        dst.icw4        = src.icw4;
        dst.step        = static_cast<IcwStep>(src.step);
        dst.expect_icw4 = (src.expect_icw4 != 0);
    };
    restore(master_, s.master);
    restore(slave_,  s.slave);
    // Deferred: re-inject deliverable IRR bits in ResumeRuntime so we
    // never call inject_ from inside Apply (which Phase 33.6 may invoke
    // before all other devices' Apply have completed).
}

void Pic8259::ResumeRuntime() {
    std::lock_guard<std::mutex> lk(lock_);
    // Master: deliverable = unmasked IRR.
    {
        const std::uint8_t deliverable =
            static_cast<std::uint8_t>(master_.irr & ~master_.mask);
        for (int i = 0; i < 8; ++i) {
            const std::uint8_t bit = static_cast<std::uint8_t>(1u << i);
            if (deliverable & bit) {
                master_.irr &= static_cast<std::uint8_t>(~bit);
                InjectLocked(master_, i);
            }
        }
    }
    // Slave: deliverable requires the slave-local bit be unmasked AND
    // the master cascade line (IRQ2) be unmasked too. Otherwise the IRQ
    // would not reach the CPU even if injected, so leave it latched.
    const std::uint8_t kCascadeBit = 0x04;
    if ((master_.mask & kCascadeBit) == 0) {
        const std::uint8_t deliverable =
            static_cast<std::uint8_t>(slave_.irr & ~slave_.mask);
        for (int i = 0; i < 8; ++i) {
            const std::uint8_t bit = static_cast<std::uint8_t>(1u << i);
            if (deliverable & bit) {
                slave_.irr &= static_cast<std::uint8_t>(~bit);
                InjectLocked(slave_, i);
            }
        }
    }
}

std::size_t Pic8259::EncodeState(const Pic8259::State& s,
                                 std::span<std::uint8_t> out) {
    if (out.size() < kEncodedSize) {
        throw std::runtime_error(
            "Pic8259::EncodeState: output span smaller than kEncodedSize");
    }
    ChipToBytes(s.master, out.data() + 0);
    ChipToBytes(s.slave,  out.data() + 8);
    return kEncodedSize;
}

Pic8259::State Pic8259::DecodeState(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kEncodedSize) {
        throw std::runtime_error(
            "Pic8259::DecodeState: payload smaller than kEncodedSize");
    }
    State s;
    s.master = ChipFromBytes(bytes.data() + 0);
    s.slave  = ChipFromBytes(bytes.data() + 8);
    return s;
}

}  // namespace tinyvmm::devices
