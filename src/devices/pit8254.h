#pragma once

#include "common.h"
#include "io_bus.h"

#include <Windows.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <span>
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

    // ---- Phase 33.5 save/restore -----------------------------------------
    //
    // PIT state covers all three channel programming registers + the
    // shared port 0x61 byte + the ch0-IRQ snapshot the host worker
    // thread reads. Per-channel `start_qpc` is NOT persisted directly;
    // instead we save the elapsed PIT-tick count since start, and Apply
    // rebases start_qpc so ReadCount() returns the same phase right
    // after restore.
    //
    // Apply only restores state -- it never starts the IRQ thread. Call
    // ResumeRuntime() after Apply (and after SetIrqCallback) to spin up
    // the IRQ worker if the saved state had ch0 armed.
    struct ChannelState {
        std::uint8_t  access            = 0;
        std::uint8_t  mode              = 0;
        std::uint16_t reload            = 0;
        std::uint8_t  reload_have_lsb   = 0;   // 0/1
        std::uint8_t  reload_lsb        = 0;
        std::uint8_t  read_msb_next     = 0;   // 0/1
        std::uint8_t  latch_valid       = 0;   // 0/1
        std::uint16_t latched           = 0;
        std::uint8_t  latched_msb_next  = 0;   // 0/1
        std::uint8_t  gate              = 0;   // 0/1
        std::uint8_t  running           = 0;   // 0/1
        std::uint64_t elapsed_pit_ticks = 0;
    };
    struct State {
        std::uint8_t  port61            = 0;
        ChannelState  ch[3]             = {};
        std::uint16_t ch0_irq_reload    = 0;
        std::uint8_t  ch0_irq_mode      = 0xff;  // 0xff = idle
        std::uint8_t  ch0_irq_armed     = 0;
    };

    // Encoded payload layout (88 bytes):
    //   [0]   port61 (u8)
    //   [1..7] reserved (zero)
    //   [8..31]  channel[0]  (24 bytes)
    //   [32..55] channel[1]  (24 bytes)
    //   [56..79] channel[2]  (24 bytes)
    //   [80..81] ch0_irq_reload (u16 LE)
    //   [82]    ch0_irq_mode (u8)
    //   [83]    ch0_irq_armed (u8)
    //   [84..87] reserved (zero)
    //
    // Per-channel layout (24 bytes):
    //   [0]  access (u8)
    //   [1]  mode (u8)
    //   [2..3]  reload (u16 LE)
    //   [4]  reload_have_lsb (u8)
    //   [5]  reload_lsb (u8)
    //   [6]  read_msb_next (u8)
    //   [7]  latch_valid (u8)
    //   [8..9]  latched (u16 LE)
    //   [10] latched_msb_next (u8)
    //   [11] gate (u8)
    //   [12] running (u8)
    //   [13..15] reserved (zero)
    //   [16..23] elapsed_pit_ticks (u64 LE)
    static constexpr std::size_t kEncodedChannelSize = 24u;
    static constexpr std::size_t kEncodedSize        = 88u;

    State CaptureState() const;
    void  ApplyState(const State& s);
    void  ResumeRuntime();

    static std::size_t EncodeState(const State& s,
                                   std::span<std::uint8_t> out);
    static State       DecodeState(std::span<const std::uint8_t> bytes);

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

    mutable std::mutex lock_;
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
