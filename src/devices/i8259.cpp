#include "i8259.h"

#include <cstdio>

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

}  // namespace tinyvmm::devices
