#include "pit8254.h"

#include <profileapi.h>

#include <cstdio>

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace tinyvmm::devices {

namespace {

constexpr std::uint64_t kPitHz = 1193182;  // PIT reference clock

// 16550-style "we don't care" mask helpers -- here just for clarity.
constexpr std::uint8_t kCwBcd = 0x01;
constexpr std::uint8_t kCwModeMask = 0x0E;
constexpr std::uint8_t kCwModeShift = 1;
constexpr std::uint8_t kCwAccessMask = 0x30;
constexpr std::uint8_t kCwAccessShift = 4;
constexpr std::uint8_t kCwSelMask = 0xC0;
constexpr std::uint8_t kCwSelShift = 6;

}  // namespace

Pit8254::Pit8254() {
    LARGE_INTEGER f{};
    QueryPerformanceFrequency(&f);
    qpc_freq_ = static_cast<std::uint64_t>(f.QuadPart);
    // Channel 0 / 1 gates are wired high on a PC.
    ch_[0].gate = true;
    ch_[1].gate = true;
    // Channel 2 gate follows port-0x61 bit 0; default low.
    ch_[2].gate = false;
}

Pit8254::~Pit8254() {
    if (irq_thread_started_.load()) {
        if (irq_stop_event_) {
            SetEvent(irq_stop_event_);
        }
        if (irq_thread_.joinable()) {
            irq_thread_.join();
        }
    }
    if (irq_timer_) {
        CloseHandle(irq_timer_);
        irq_timer_ = nullptr;
    }
    if (irq_reprogram_event_) {
        CloseHandle(irq_reprogram_event_);
        irq_reprogram_event_ = nullptr;
    }
    if (irq_stop_event_) {
        CloseHandle(irq_stop_event_);
        irq_stop_event_ = nullptr;
    }
}

void Pit8254::SetIrqCallback(IrqFn cb) {
    std::lock_guard<std::mutex> lk(lock_);
    irq_callback_ = std::move(cb);
}

void Pit8254::Attach(IoBus& bus) {
    bus.Register(0x40, 1, "pit-ch0",
                 [this](IoAccess& a) { HandleCounter(0, a); });
    bus.Register(0x41, 1, "pit-ch1",
                 [this](IoAccess& a) { HandleCounter(1, a); });
    bus.Register(0x42, 1, "pit-ch2",
                 [this](IoAccess& a) { HandleCounter(2, a); });
    bus.Register(0x43, 1, "pit-ctl",
                 [this](IoAccess& a) { HandleControl(a); });
    bus.Register(0x61, 1, "sys-ctrl-b",
                 [this](IoAccess& a) { HandlePort61(a); });
}

std::uint64_t Pit8254::QpcNow() const noexcept {
    LARGE_INTEGER c{};
    QueryPerformanceCounter(&c);
    return static_cast<std::uint64_t>(c.QuadPart);
}

std::uint64_t Pit8254::QpcDeltaToPitTicks(std::uint64_t delta) const noexcept {
    // ticks = delta * 1193182 / qpc_freq_. Compute with 128-bit-ish safety
    // by splitting -- for typical qpc_freq_ ~= 10 MHz and delta < 2^53 this
    // never overflows in 64 bits anyway, but be explicit.
    if (qpc_freq_ == 0) {
        return 0;
    }
    // delta * kPitHz fits in 64 bits as long as delta < 2^64 / 1193182 ~=
    // 1.5e13, which at QPC=10MHz is ~17 days. Plenty for boot calibration.
    return (delta * kPitHz) / qpc_freq_;
}

void Pit8254::ProgramChannel(int ch, std::uint8_t cw) {
    auto& c = ch_[ch];
    if ((cw & kCwBcd) != 0) {
        // BCD count mode (bit 0 set) is part of the 8254 spec but no
        // mainstream OS uses it. We don't model it; warn once and treat
        // as binary so the guest isn't silently mis-counted.
        static bool warned = false;
        if (!warned) {
            std::fprintf(stderr,
                "[pit8254] WARN: guest selected BCD count mode on ch%d "
                "(cw=0x%02x); treating as binary.\n",
                ch, cw);
            warned = true;
        }
    }
    AccessMode acc =
        static_cast<AccessMode>((cw & kCwAccessMask) >> kCwAccessShift);
    if (acc == AccessLatch) {
        // Counter-latch command: snapshot current count, leave program
        // state otherwise untouched.
        LatchChannel(ch);
        return;
    }
    c.access = acc;
    c.mode = static_cast<std::uint8_t>((cw & kCwModeMask) >> kCwModeShift);
    // Mode 4 in real hardware uses bit 3 too; we ignore it.
    c.reload_have_lsb = false;
    c.reload_lsb = 0;
    c.read_msb_next = false;
    c.latch_valid = false;
    c.running = false;  // stays stopped until reload is written
}

void Pit8254::LatchChannel(int ch) {
    auto& c = ch_[ch];
    c.latched = ReadCount(ch, QpcNow());
    c.latch_valid = true;
    c.latched_msb_next = false;
}

std::uint16_t Pit8254::ReadCount(int ch, std::uint64_t qpc_now) const {
    const auto& c = ch_[ch];
    if (!c.running) {
        return c.reload;
    }
    if (!c.gate) {
        // Mode 0 with gate low pauses counting; we don't track the pause
        // accurately for non-mode-0 cases, but the caller of this PIT only
        // strobes gate before the first read, so this is fine.
        return c.reload;
    }
    std::uint64_t elapsed = QpcDeltaToPitTicks(qpc_now - c.start_qpc);

    // Mode 0: counter decrements once and stops at 0. After it reaches 0
    // it stays 0 (real hw wraps, but we don't need that subtlety for
    // calibration).
    // Mode 2/3: rate generator / square-wave -- counter wraps at reload.
    // For TSC calibration the kernel uses mode 0, but treat 2/3 the same
    // way (modulo reload).
    std::uint32_t reload =
        c.reload == 0 ? 0x10000u : static_cast<std::uint32_t>(c.reload);

    if (c.mode == 0) {
        if (elapsed >= reload) {
            return 0;
        }
        return static_cast<std::uint16_t>(reload - elapsed);
    }
    // Default (mode 2/3 etc.): wrap.
    std::uint64_t pos = elapsed % reload;
    return static_cast<std::uint16_t>(reload - pos);
}

void Pit8254::HandleCounter(int ch, IoAccess& acc) {
    std::lock_guard<std::mutex> lk(lock_);
    auto& c = ch_[ch];

    if (acc.is_write) {
        std::uint8_t b = static_cast<std::uint8_t>(acc.value & 0xff);
        bool completed = false;
        switch (c.access) {
            case AccessLsbOnly:
                c.reload = (c.reload & 0xff00u) | b;
                c.start_qpc = QpcNow();
                c.running = true;
                completed = true;
                break;
            case AccessMsbOnly:
                c.reload = static_cast<std::uint16_t>(
                    (c.reload & 0x00ffu) | (static_cast<std::uint16_t>(b) << 8));
                c.start_qpc = QpcNow();
                c.running = true;
                completed = true;
                break;
            case AccessLsbThenMsb:
                if (!c.reload_have_lsb) {
                    c.reload_lsb = b;
                    c.reload_have_lsb = true;
                } else {
                    c.reload = static_cast<std::uint16_t>(
                        c.reload_lsb | (static_cast<std::uint16_t>(b) << 8));
                    c.reload_have_lsb = false;
                    c.start_qpc = QpcNow();
                    c.running = true;
                    completed = true;
                }
                break;
            default:
                break;
        }
        if (completed && ch == 0) {
            Ch0ProgrammedLocked();
        }
        return;
    }

    // Read: if a latch is pending, drain that; otherwise read live counter.
    std::uint16_t val;
    bool from_latch = c.latch_valid;
    if (from_latch) {
        val = c.latched;
    } else {
        val = ReadCount(ch, QpcNow());
    }

    std::uint8_t out = 0;
    switch (c.access) {
        case AccessLsbOnly:
            out = static_cast<std::uint8_t>(val & 0xff);
            break;
        case AccessMsbOnly:
            out = static_cast<std::uint8_t>((val >> 8) & 0xff);
            break;
        case AccessLsbThenMsb: {
            bool& msb_next = from_latch ? c.latched_msb_next : c.read_msb_next;
            if (!msb_next) {
                out = static_cast<std::uint8_t>(val & 0xff);
                msb_next = true;
            } else {
                out = static_cast<std::uint8_t>((val >> 8) & 0xff);
                msb_next = false;
                if (from_latch) {
                    c.latch_valid = false;
                }
            }
            break;
        }
        default:
            out = 0xff;
            break;
    }
    acc.value = out;
}

void Pit8254::HandleControl(IoAccess& acc) {
    if (!acc.is_write) {
        // Control register is write-only on real hw; reads return floating
        // bus.
        acc.value = 0xff;
        return;
    }
    std::lock_guard<std::mutex> lk(lock_);
    std::uint8_t cw = static_cast<std::uint8_t>(acc.value & 0xff);
    int sel = (cw & kCwSelMask) >> kCwSelShift;
    if (sel == 3) {
        // Read-back command: not used by Linux's PIT TSC calibrator.
        // Treat as a counter-latch on every selected channel for safety.
        if (cw & 0x02) LatchChannel(0);
        if (cw & 0x04) LatchChannel(1);
        if (cw & 0x08) LatchChannel(2);
        return;
    }
    ProgramChannel(sel, cw);
}

void Pit8254::HandlePort61(IoAccess& acc) {
    std::lock_guard<std::mutex> lk(lock_);
    if (acc.is_write) {
        std::uint8_t b = static_cast<std::uint8_t>(acc.value & 0xff);
        // Bits 0 (timer-2 gate) and 1 (speaker-data) are guest-writable.
        // Other bits are read-only status; we just remember the lower
        // four bits and synthesise the rest on read.
        port61_ = static_cast<std::uint8_t>(b & 0x0f);
        bool new_gate = (b & 0x01) != 0;
        if (new_gate != ch_[2].gate) {
            ch_[2].gate = new_gate;
            if (new_gate && ch_[2].running) {
                // Re-anchor "now" so the counter restarts cleanly when the
                // kernel toggles the gate on, matching what real hardware
                // does in mode 0 with a rising-edge gate.
                ch_[2].start_qpc = QpcNow();
            }
        }
        return;
    }
    // Read: bits 0..1 we wrote; bit 5 = ch2 OUT (level). Others 0.
    std::uint8_t v = port61_ & 0x03;
    // Channel 2 OUT line: in mode 0, OUT = 1 iff counter has expired.
    std::uint16_t cnt = ReadCount(2, QpcNow());
    if (ch_[2].mode == 0) {
        if (ch_[2].running && cnt == 0) {
            v = static_cast<std::uint8_t>(v | 0x20);
        }
    }
    acc.value = v;
}

// ---- channel 0 IRQ generation --------------------------------------------

void Pit8254::Ch0ProgrammedLocked() {
    auto& c = ch_[0];
    // Modes 0, 4 = one-shot; modes 2, 3 = periodic. Other modes are silent.
    bool valid = (c.mode == 0 || c.mode == 2 || c.mode == 3 || c.mode == 4);
    if (!valid) {
        ch0_irq_armed_ = false;
        return;
    }
    ch0_irq_mode_   = c.mode;
    ch0_irq_reload_ = c.reload;
    ch0_irq_armed_  = true;
    EnsureIrqThreadStarted();
    if (irq_reprogram_event_) {
        SetEvent(irq_reprogram_event_);
    }
}

void Pit8254::EnsureIrqThreadStarted() {
    if (irq_thread_started_.load(std::memory_order_acquire)) {
        return;
    }
    irq_stop_event_      = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    irq_reprogram_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    // Try a high-resolution auto-reset timer first; fall back gracefully.
    irq_timer_ = CreateWaitableTimerExW(
        nullptr, nullptr,
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
        TIMER_ALL_ACCESS);
    if (!irq_timer_) {
        irq_timer_ = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    }
    if (!irq_stop_event_ || !irq_reprogram_event_ || !irq_timer_) {
        std::fprintf(stderr,
                     "[pit] failed to create IRQ-thread sync objects "
                     "(stop=%p reprogram=%p timer=%p)\n",
                     static_cast<void*>(irq_stop_event_),
                     static_cast<void*>(irq_reprogram_event_),
                     static_cast<void*>(irq_timer_));
        return;
    }
    irq_thread_started_.store(true, std::memory_order_release);
    irq_thread_ = std::thread([this] { IrqThreadMain(); });
}

void Pit8254::IrqThreadMain() {
    while (true) {
        // Snapshot programming under lock.
        std::uint16_t reload;
        std::uint8_t  mode;
        bool armed;
        IrqFn cb;
        {
            std::lock_guard<std::mutex> lk(lock_);
            reload = ch0_irq_reload_;
            mode   = ch0_irq_mode_;
            armed  = ch0_irq_armed_;
            cb     = irq_callback_;
        }

        if (!armed) {
            HANDLE waits[2] = { irq_stop_event_, irq_reprogram_event_ };
            DWORD r = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (r == WAIT_OBJECT_0) return;
            continue;
        }

        std::uint32_t reload_actual =
            (reload == 0) ? 0x10000u : static_cast<std::uint32_t>(reload);
        // Period in 100ns units: reload * 10_000_000 / 1_193_182.
        std::uint64_t period_100ns =
            (static_cast<std::uint64_t>(reload_actual) * 10000000ULL) / kPitHz;
        if (period_100ns == 0) period_100ns = 1;

        LARGE_INTEGER due;
        due.QuadPart = -static_cast<std::int64_t>(period_100ns);
        LONG period_ms = 0;
        if (mode == 2 || mode == 3) {
            std::int64_t ms = static_cast<std::int64_t>((period_100ns + 9999) / 10000);
            if (ms < 1) ms = 1;
            if (ms > 1000) ms = 1000;
            period_ms = static_cast<LONG>(ms);
        }
        if (!SetWaitableTimer(irq_timer_, &due, period_ms, nullptr, nullptr, FALSE)) {
            // Should never happen; back off briefly.
            HANDLE waits[2] = { irq_stop_event_, irq_reprogram_event_ };
            WaitForMultipleObjects(2, waits, FALSE, 10);
            continue;
        }

        for (;;) {
            HANDLE waits[3] = { irq_stop_event_, irq_reprogram_event_, irq_timer_ };
            DWORD r = WaitForMultipleObjects(3, waits, FALSE, INFINITE);
            if (r == WAIT_OBJECT_0) {
                CancelWaitableTimer(irq_timer_);
                return;
            }
            if (r == WAIT_OBJECT_0 + 1) {
                CancelWaitableTimer(irq_timer_);
                break;  // reprogram; re-snapshot
            }
            if (r == WAIT_OBJECT_0 + 2) {
                if (cb) cb(0);
                if (mode == 0 || mode == 4) {
                    // One-shot: consumed. Mark disarmed and wait for reprogram.
                    {
                        std::lock_guard<std::mutex> lk(lock_);
                        ch0_irq_armed_ = false;
                    }
                    break;
                }
                // Periodic: timer auto-rearmed; loop and wait for next tick.
                continue;
            }
            // Wait failure: break out and re-snapshot.
            break;
        }
    }
}

}  // namespace tinyvmm::devices
