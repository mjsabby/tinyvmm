#pragma once

// virtio-rng device (M17). Spec §5.4.
//
// The simplest possible virtio device: a single "requestq" virtqueue.
// The driver pushes a chain whose desc[0..] are all device-writable.
// We fill those buffers with cryptographically-random bytes from the
// host CNG provider (`tinyvmm::host::RandomFill`) and post the chain
// to the used ring with `len` equal to the total bytes we wrote.
//
// There are no device-specific feature bits — we advertise just
// `VIRTIO_F_VERSION_1 | VIRTIO_F_RING_EVENT_IDX`. There is no device
// config space either.
//
// Threading: like virtio-blk, we accept an IrqFn callback that wraps
// `PciTransport::RaiseQueueInterrupt` — the actual fill runs on
// whichever thread wrote the queue-notify MMIO (cheap, no I/O).

#include "../whp/memory.h"
#include "virtio.h"
#include "virtqueue.h"

#include <atomic>
#include <cstdint>
#include <functional>

namespace tinyvmm::virtio {

inline constexpr std::uint32_t kRngRequestQueueIdx = 0;
inline constexpr std::uint32_t kRngQueueCount       = 1;
inline constexpr std::uint32_t kRngQueueMax         = 64;

class RngDevice : public Device {
public:
    using IrqFn = std::function<void(std::uint32_t qidx)>;

    explicit RngDevice(whp::GuestMemory& mem, IrqFn irq = {});

    // ---------------------- Device interface --------------------------
    std::uint32_t DeviceId() const override { return kDeviceIdRng; }
    std::uint64_t DeviceFeatures() const override;
    bool SetDriverFeatures(std::uint64_t acked) override;

    std::uint32_t QueueCount() const override { return kRngQueueCount; }
    std::uint32_t QueueMax(std::uint32_t idx) const override;
    Virtqueue* GetQueue(std::uint32_t idx) override;

    void NotifyQueue(std::uint32_t idx) override;
    void DriverOk() override { driver_ok_ = true; }
    void Reset() override;

    // No device-cfg.
    std::uint32_t ReadConfig(std::uint32_t, std::uint32_t) override { return 0; }
    void WriteConfig(std::uint32_t, std::uint32_t, std::uint32_t) override {}

    void SetIrqCallback(IrqFn fn) { irq_ = std::move(fn); }

    // ---------------------- Diagnostics -------------------------------
    bool driver_ok() const noexcept { return driver_ok_; }
    std::uint64_t acked_features() const noexcept { return acked_features_; }
    std::uint64_t ops_done()  const noexcept { return ops_done_.load(); }
    std::uint64_t bytes_out() const noexcept { return bytes_out_.load(); }

    Virtqueue& request_queue() noexcept { return queue_; }

private:
    void DrainRequestQueue();

    Virtqueue queue_;
    bool driver_ok_ = false;
    std::uint64_t acked_features_ = 0;

    std::atomic<std::uint64_t> ops_done_{0};
    std::atomic<std::uint64_t> bytes_out_{0};

    IrqFn irq_;
};

}  // namespace tinyvmm::virtio
