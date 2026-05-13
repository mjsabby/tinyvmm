#pragma once

#include "../common.h"
#include "io_bus.h"

#include <Windows.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>

namespace tinyvmm::devices {

// Minimal Intel 8254 PIT (channels 0..2) + System Control Port B at 0x61.
//
// Why this exists at all in a paravirtualised VMM: Linux's
// `quick_pit_calibrate()` (arch/x86/kernel/tsc.c) uses the PIT as the
// reference clock to determine the TSC frequency at boot. Without a working
// PIT, the kernel either deadlocks polling 0x42 (waiting for the MSB to tick
// down) or falls back to an extremely slow alternate calibration. We need
// the kernel's view of TSC speed to be accurate.
//
// Scope:
//   * Three counters (channel 0/1/2) at ports 0x40/0x41/0x42.
//   * Control word at 0x43 (write-only).
//   * Speaker / NMI status port 0x61 -- specifically the gate-2 bit (bit 0)
//     and the speaker-data bit (bit 1). Reads also return the channel-2
//     OUT level (bit 5) which `quick_pit_calibrate()` doesn't use, but
//     other Linux paths sometimes peek at it.
//
// IRQ0 generation (channel 0) IS supported -- see SetIrqCallback. Without it,
// Linux running on a CONFIG_ACPI=n kernel has no clockevent source at all
// (no MADT means no LAPIC clockevent registration) and `nanosleep` / hrtimers
// block forever. With it, the kernel's i8253 clockevent driver picks up the
// PIT and userspace makes forward progress.
//
// Out of scope:
//   * BCD counting -- never used by Linux on x86.
//   * Counter-latch and read-back commands' status latching for channels
//     other than the one being read. Linux's calibrator only reads ch2.
//
// Time source: QueryPerformanceCounter, scaled to 1.193182 MHz (the PIT's
// reference frequency). The host's TSC drives the guest's TSC (1:1, no
// scaling), so PIT-vs-TSC measurements come out consistent and the
// calibration converges quickly.
class Pit8254 {
public:
    using IrqFn = std::function<void(int isa_irq)>;

    Pit8254();
    ~Pit8254();

    Pit8254(const Pit8254&) = delete;
    Pit8254& operator=(const Pit8254&) = delete;

    // Registers ports 0x40..0x43 and 0x61 on the bus.
    void Attach(IoBus& bus);

    // Wire the channel-0 OUT line to a PIC raise. Set this once after the
    // PIC is constructed. The callback is invoked from a host worker thread
    // (not the vCPU), so the PIC's lock_ provides cross-thread serialization.
    void SetIrqCallback(IrqFn cb);

private:
    enum AccessMode : std::uint8_t {
        AccessLatch = 0,  // counter latch command
        AccessLsbOnly = 1,
        AccessMsbOnly = 2,
        AccessLsbThenMsb = 3,
    };

    // Per-channel programming state. Only fields we actually need.
    struct Channel {
        // Last control-word programming for this channel.
        AccessMode access = AccessLsbThenMsb;
        std::uint8_t mode = 0;  // mode 0..5

        // Reload value latched in by the LSB+MSB writes to the counter port.
        std::uint16_t reload = 0;
        // Pending bytes for two-byte programming sequences.
        bool reload_have_lsb = false;
        std::uint8_t reload_lsb = 0;

        // Toggle for two-byte read sequences (LSB next vs MSB next).
        bool read_msb_next = false;

        // Latched value from a counter-latch command (or read-back).
        bool latch_valid = false;
        std::uint16_t latched = 0;
        bool latched_msb_next = false;

        // Gate input. Channel 0 and 1 are wired high on a real PC. Channel 2
        // is gated by port 0x61 bit 0.
        bool gate = false;

        // QPC tick at which the counter "last (re)started". The current
        // counter value is reload - elapsed_pit_ticks (mode 0/2/3).
        std::uint64_t start_qpc = 0;
        // True once a reload has been written and counting has begun.
        bool running = false;
    };

    // PIT register dispatch.
    void HandleCounter(int ch, IoAccess& acc);
    void HandleControl(IoAccess& acc);
    void HandlePort61(IoAccess& acc);

    // Program a control word that targets one channel.
    void ProgramChannel(int ch, std::uint8_t cw);
    // Latch the current count for a counter-latch command.
    void LatchChannel(int ch);

    // Compute the current 16-bit counter for a channel, given QPC.
    std::uint16_t ReadCount(int ch, std::uint64_t qpc_now) const;

    // Take a fresh QPC reading.
    std::uint64_t QpcNow() const noexcept;
    // Convert QPC delta to PIT ticks (1.193182 MHz).
    std::uint64_t QpcDeltaToPitTicks(std::uint64_t delta) const noexcept;

    std::mutex lock_;
    Channel ch_[3];
    std::uint8_t port61_ = 0;  // raw last-written bits

    // QPC frequency in Hz, captured once at construction.
    std::uint64_t qpc_freq_ = 0;

    // --- channel 0 IRQ generation ---
    // Lazily started when the kernel first programs channel 0 in a mode that
    // produces interrupts (modes 0, 2, 3, 4).
    void EnsureIrqThreadStarted();  // caller must hold lock_
    void IrqThreadMain();
    // Called from HandleCounter under lock_ when ch0 reload completes.
    void Ch0ProgrammedLocked();

    IrqFn irq_callback_;
    std::thread irq_thread_;
    std::atomic<bool> irq_thread_started_{false};
    HANDLE irq_stop_event_ = nullptr;
    HANDLE irq_reprogram_event_ = nullptr;
    HANDLE irq_timer_ = nullptr;

    // Snapshot of ch0 IRQ-relevant programming, updated under lock_ and
    // consumed by the worker after seeing irq_reprogram_event_.
    std::uint16_t ch0_irq_reload_ = 0;
    std::uint8_t  ch0_irq_mode_ = 0xff;  // 0xff = idle
    bool ch0_irq_armed_ = false;
};

}  // namespace tinyvmm::devices
