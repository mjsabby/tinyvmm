#pragma once

// virtio-console device (M20). Spec §5.3.
//
// Minimum-viable, single-port, TX-only-routed-to-host-stdout virtio console.
// Why: the 8250 TX-IRQ path is broken for userspace writes to /dev/console
// (see M19c.5). Linux has built-in support for hvc-based consoles, so all
// we need is one virtio-console device on the PCI bus with two virtqueues
// and the kernel routes printk + userspace console writes through it via
// `console=hvc0`. This sidesteps the entire 8250/PIC/IRQ chain.
//
// Queues (per spec §5.3.2 for a single-port device, no F_MULTIPORT):
//   q0 = receiveq  (host -> guest input)   ;  unused in v1 of this device.
//   q1 = transmitq (guest -> host output)  ;  drained to a FILE* sink.
//
// Features:
//   Only `VIRTIO_F_VERSION_1` (and optionally `RING_EVENT_IDX`). We deliberately
//   do NOT advertise F_SIZE / F_MULTIPORT / F_EMERG_WRITE for v1 — the driver
//   handles their absence cleanly and config space stays trivial.
//
// Device-config: 12 bytes; all zero when none of the gated features are on.
// Layout (spec §5.3.4): u16 cols, u16 rows, u32 max_nr_ports, u32 emerg_wr.

#include "../whp/memory.h"
#include "virtio.h"
#include "virtqueue.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <vector>

namespace tinyvmm::virtio {

inline constexpr std::uint32_t kConsoleReceiveQueueIdx  = 0;
inline constexpr std::uint32_t kConsoleTransmitQueueIdx = 1;
inline constexpr std::uint32_t kConsoleQueueCount       = 2;
inline constexpr std::uint32_t kConsoleQueueMax         = 64;

class ConsoleDevice : public Device {
public:
    using IrqFn = std::function<void(std::uint32_t qidx)>;

    // `sink` is where guest TX bytes get written; nullptr discards. Captures
    // a copy of every byte into an internal vector for tests (RingByteSink).
    explicit ConsoleDevice(whp::GuestMemory& mem,
                           std::FILE* sink = nullptr,
                           IrqFn irq = {});

    // ---------------------- Device interface --------------------------
    std::uint32_t DeviceId() const override { return kDeviceIdConsole; }
    std::uint64_t DeviceFeatures() const override;
    bool SetDriverFeatures(std::uint64_t acked) override;

    std::uint32_t QueueCount() const override { return kConsoleQueueCount; }
    std::uint32_t QueueMax(std::uint32_t idx) const override;
    Virtqueue* GetQueue(std::uint32_t idx) override;

    void NotifyQueue(std::uint32_t idx) override;
    void DriverOk() override { driver_ok_ = true; }
    void Reset() override;

    // Device-cfg: 12 bytes of zeros (cols/rows/max_nr_ports/emerg_wr).
    std::uint32_t ReadConfig(std::uint32_t offset,
                             std::uint32_t size) override;
    void WriteConfig(std::uint32_t, std::uint32_t, std::uint32_t) override {}

    void SetIrqCallback(IrqFn fn) { irq_ = std::move(fn); }
    void SetSink(std::FILE* f) { sink_ = f; }
    void SetCapture(bool on) { capture_ = on; }

    // ---------------------- Diagnostics -------------------------------
    bool driver_ok() const noexcept { return driver_ok_; }
    std::uint64_t acked_features() const noexcept { return acked_features_; }
    std::uint64_t tx_bytes()       const noexcept { return tx_bytes_.load(); }
    std::uint64_t tx_chains()      const noexcept { return tx_chains_.load(); }

    // Captured bytes are only populated when SetCapture(true). The mutex is
    // held only inside the test accessor; production path doesn't lock.
    std::vector<char> capture_snapshot() const;

    Virtqueue& receive_queue()  noexcept { return rxq_; }
    Virtqueue& transmit_queue() noexcept { return txq_; }

private:
    void DrainTransmitQueue();

    Virtqueue rxq_;
    Virtqueue txq_;
    bool driver_ok_ = false;
    std::uint64_t acked_features_ = 0;

    std::FILE* sink_ = nullptr;
    bool capture_ = false;
    std::vector<char> captured_;

    std::atomic<std::uint64_t> tx_bytes_{0};
    std::atomic<std::uint64_t> tx_chains_{0};

    IrqFn irq_;
};

}  // namespace tinyvmm::virtio
