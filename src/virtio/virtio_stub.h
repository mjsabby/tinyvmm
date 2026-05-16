#pragma once

// Minimal in-tree virtio Device for unit-testing the MMIO transport and the
// virtqueue accessor. One read-write queue, no real semantics: each popped
// chain is immediately pushed back as a completion.
//
// Used by `tinyvmm --virtio-test` to exercise the wire format end-to-end
// without booting a kernel.

#include "whp/memory.h"
#include "virtio.h"
#include "virtqueue.h"

#include <cstdint>

namespace tinyvmm::virtio {

class StubDevice : public Device {
public:
    explicit StubDevice(whp::GuestMemory& mem)
        : queue_(mem, /*max_size=*/256) {}

    std::uint32_t DeviceId() const override { return kDeviceIdReserved + 0xFE; }
    std::uint64_t DeviceFeatures() const override {
        // Advertise EVENT_IDX + VERSION_1 to exercise the negotiation paths.
        return kFeatureVersion1 | kFeatureRingEventIdx;
    }
    bool SetDriverFeatures(std::uint64_t acked) override {
        acked_features_ = acked;
        // Any subset is acceptable for the stub.
        return true;
    }

    std::uint32_t QueueCount() const override { return 1; }
    std::uint32_t QueueMax(std::uint32_t idx) const override {
        return idx == 0 ? 256 : 0;
    }
    Virtqueue* GetQueue(std::uint32_t idx) override {
        return idx == 0 ? &queue_ : nullptr;
    }

    void NotifyQueue(std::uint32_t idx) override {
        (void)idx;
        notify_count_++;
    }
    void DriverOk() override { driver_ok_ = true; }
    void Reset() override {
        acked_features_ = 0;
        driver_ok_ = false;
        notify_count_ = 0;
    }

    std::uint64_t notify_count() const noexcept { return notify_count_; }
    bool driver_ok() const noexcept { return driver_ok_; }
    std::uint64_t acked_features() const noexcept { return acked_features_; }
    Virtqueue& queue() noexcept { return queue_; }

private:
    Virtqueue queue_;
    std::uint64_t notify_count_ = 0;
    bool driver_ok_ = false;
    std::uint64_t acked_features_ = 0;
};

}  // namespace tinyvmm::virtio
