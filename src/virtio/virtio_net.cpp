#include "virtio_net.h"

#include <cstring>

namespace tinyvmm::virtio {

NetDevice::NetDevice(whp::GuestMemory& mem,
                     const std::array<std::uint8_t, 6>& mac)
    : mac_(mac),
      queues_{Virtqueue(mem, kNetQueueMax), Virtqueue(mem, kNetQueueMax)} {}

std::uint64_t NetDevice::DeviceFeatures() const {
    return kFeatureVersion1 | kFeatureRingEventIdx | kNetFeatureMac |
           kNetFeatureStatus;
}

bool NetDevice::SetDriverFeatures(std::uint64_t acked) {
    // The driver MUST ack VERSION_1 (modern transport contract). Without
    // it we'd be in legacy mode, which we don't speak.
    if (!(acked & kFeatureVersion1)) {
        return false;
    }
    // The driver MUST NOT add bits we never advertised.
    std::uint64_t advertised = DeviceFeatures();
    if (acked & ~advertised) {
        return false;
    }
    acked_features_ = acked;
    return true;
}

std::uint32_t NetDevice::QueueMax(std::uint32_t idx) const {
    return idx < kNetQueueCount ? kNetQueueMax : 0;
}

Virtqueue* NetDevice::GetQueue(std::uint32_t idx) {
    return idx < kNetQueueCount ? &queues_[idx] : nullptr;
}

void NetDevice::NotifyQueue(std::uint32_t idx) {
    if (idx < kNetQueueCount) {
        notify_count_[idx].fetch_add(1, std::memory_order_relaxed);
    }
    if (backend_) backend_->OnQueueNotify(idx);
}

void NetDevice::DriverOk() {
    driver_ok_ = true;
}

void NetDevice::Reset() {
    driver_ok_ = false;
    acked_features_ = 0;
    for (auto& c : notify_count_) c.store(0, std::memory_order_relaxed);
}

std::uint32_t NetDevice::ReadConfig(std::uint32_t offset,
                                    std::uint32_t size) {
    // Build a max-12-byte view of the config layout, then copy out the
    // requested slice. (Config space reads are cold; correctness over
    // micro-optimization.)
    std::uint8_t buf[12] = {};
    std::memcpy(&buf[0], mac_.data(), 6);
    buf[6] = static_cast<std::uint8_t>(link_status_ & 0xFF);
    buf[7] = static_cast<std::uint8_t>((link_status_ >> 8) & 0xFF);

    if (offset >= sizeof(buf)) return 0;
    std::uint32_t take = size;
    if (offset + take > sizeof(buf)) take = sizeof(buf) - offset;
    std::uint32_t v = 0;
    std::memcpy(&v, &buf[offset], take);
    return v;
}

void NetDevice::WriteConfig(std::uint32_t offset, std::uint32_t size,
                            std::uint32_t value) {
    // Per spec §5.1.4 the only writable byte for VIRTIO_NET_F_CTRL_GUEST_*
    // is in the optional control plane, which we don't expose. Treat all
    // writes to our minimal layout as no-ops.
    (void)offset;
    (void)size;
    (void)value;
}

}  // namespace tinyvmm::virtio
