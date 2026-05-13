#pragma once

// virtio-net device skeleton (spec §5.1).
//
// Scope for M9: configuration space + feature negotiation + queue lifecycle
// only. No actual packet movement -- TX descriptors are completed with
// length=0 and RX descriptors are queued but never filled. The XDP
// integration (M10/M11) will plug into the queues this object owns.
//
// We deliberately advertise only the minimum feature set:
//   - VIRTIO_F_VERSION_1   (mandatory for modern transport)
//   - VIRTIO_NET_F_MAC     (so Linux uses our MAC instead of generating one)
//   - VIRTIO_NET_F_STATUS  (so we can flip link state up/down)
//   - VIRTIO_F_RING_EVENT_IDX (the perf bit; the transport plumbs it)
// Notably absent: MRG_RXBUF, CTRL_VQ, MULTIQUEUE -- defer to later.

#include "../whp/memory.h"
#include "net_backend.h"
#include "virtio.h"
#include "virtqueue.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>

namespace tinyvmm::virtio {

// virtio-net feature bits (spec §5.1.3).
inline constexpr std::uint64_t kNetFeatureMac = 1ULL << 5;
inline constexpr std::uint64_t kNetFeatureStatus = 1ULL << 16;
inline constexpr std::uint64_t kNetFeatureMrgRxBuf = 1ULL << 15;
inline constexpr std::uint64_t kNetFeatureCtrlVq = 1ULL << 17;

// Config-space layout (spec §5.1.4). All little-endian.
//   offset 0..5  : mac[6]
//   offset 6..7  : status (uint16, link_up = 0x1)
//   offset 8..9  : max_virtqueue_pairs (only with MULTIQUEUE)
//   offset 10..11: mtu                  (only with MTU)
inline constexpr std::uint16_t kNetStatusLinkUp = 1;

// Queue index assignments for a 1-pair device.
inline constexpr std::uint32_t kRxQueueIdx = 0;
inline constexpr std::uint32_t kTxQueueIdx = 1;
inline constexpr std::uint32_t kNetQueueCount = 2;
inline constexpr std::uint32_t kNetQueueMax = 256;

class NetDevice : public Device {
public:
    // `mac` is the 6-byte hardware address advertised to the guest.
    NetDevice(whp::GuestMemory& mem, const std::array<std::uint8_t, 6>& mac);

    // ---------------------- Device interface --------------------------
    std::uint32_t DeviceId() const override { return kDeviceIdNet; }
    std::uint64_t DeviceFeatures() const override;
    bool SetDriverFeatures(std::uint64_t acked) override;

    std::uint32_t QueueCount() const override { return kNetQueueCount; }
    std::uint32_t QueueMax(std::uint32_t idx) const override;
    Virtqueue* GetQueue(std::uint32_t idx) override;

    void NotifyQueue(std::uint32_t idx) override;
    void DriverOk() override;
    void Reset() override;

    std::uint32_t ReadConfig(std::uint32_t offset,
                             std::uint32_t size) override;
    void WriteConfig(std::uint32_t offset, std::uint32_t size,
                     std::uint32_t value) override;

    // ---------------------- Diagnostics -------------------------------
    std::uint64_t notify_count(std::uint32_t idx) const noexcept {
        return idx < kNetQueueCount ? notify_count_[idx].load() : 0;
    }
    bool driver_ok() const noexcept { return driver_ok_; }
    std::uint64_t acked_features() const noexcept { return acked_features_; }
    const std::array<std::uint8_t, 6>& mac() const noexcept { return mac_; }
    std::uint16_t link_status() const noexcept { return link_status_; }
    void set_link_up(bool up) {
        link_status_ = up ? kNetStatusLinkUp : 0;
    }

    // For M10/M11: hot-path workers will pop from these directly.
    Virtqueue& rx_queue() noexcept { return queues_[kRxQueueIdx]; }
    Virtqueue& tx_queue() noexcept { return queues_[kTxQueueIdx]; }

    // ---------------------- Backend wiring (M15) ----------------------
    // Backend lifetime is tied to the device. SetBackend before binding
    // the device to a transport, or at least before the guest writes
    // DRIVER_OK -- the transport will Start() the backend once the BAR
    // is mapped, and Stop() it on reset/teardown.
    void SetBackend(std::unique_ptr<NetBackend> b) noexcept {
        backend_ = std::move(b);
    }
    NetBackend* backend() noexcept { return backend_.get(); }

private:
    std::array<std::uint8_t, 6> mac_;
    std::uint16_t link_status_ = kNetStatusLinkUp;

    std::array<Virtqueue, kNetQueueCount> queues_;

    std::array<std::atomic<std::uint64_t>, kNetQueueCount> notify_count_{};
    bool driver_ok_ = false;
    std::uint64_t acked_features_ = 0;

    std::unique_ptr<NetBackend> backend_;
};

}  // namespace tinyvmm::virtio
