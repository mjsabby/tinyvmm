#include "virtio_rng.h"

#include "host/rng.h"

namespace tinyvmm::virtio {

RngDevice::RngDevice(whp::GuestMemory& mem, IrqFn irq)
    : queue_(mem, kRngQueueMax), irq_(std::move(irq)) {}

std::uint64_t RngDevice::DeviceFeatures() const {
    return kFeatureVersion1 | kFeatureRingEventIdx;
}

bool RngDevice::SetDriverFeatures(std::uint64_t acked) {
    if (!(acked & kFeatureVersion1)) return false;
    if (acked & ~DeviceFeatures())   return false;
    acked_features_ = acked;
    return true;
}

std::uint32_t RngDevice::QueueMax(std::uint32_t idx) const {
    return idx == kRngRequestQueueIdx ? kRngQueueMax : 0;
}

Virtqueue* RngDevice::GetQueue(std::uint32_t idx) {
    return idx == kRngRequestQueueIdx ? &queue_ : nullptr;
}

void RngDevice::NotifyQueue(std::uint32_t idx) {
    if (idx != kRngRequestQueueIdx) return;
    if (!queue_.ready()) return;
    DrainRequestQueue();
}

void RngDevice::Reset() {
    driver_ok_ = false;
    acked_features_ = 0;
    // ops/bytes are diagnostic counters; deliberately not cleared.
}

void RngDevice::DrainRequestQueue() {
    bool any = false;
    while (auto chain = queue_.Pop()) {
        std::uint32_t total = 0;
        // Per spec §5.4.6.1 every buffer in the chain is device-writable.
        // We ignore any read-only buffers a misbehaving driver might
        // tack on; for writable buffers we just fill with random bytes.
        for (const auto& b : chain->bufs) {
            if (!b.write || b.bytes.empty()) continue;
            host::RandomFill(b.bytes.data(), b.bytes.size());
            total += static_cast<std::uint32_t>(b.bytes.size());
        }
        queue_.Push(chain->head_index, total);
        bytes_out_.fetch_add(total, std::memory_order_relaxed);
        ops_done_.fetch_add(1, std::memory_order_relaxed);
        any = true;
    }
    if (any && irq_ && queue_.ShouldInterruptDriver()) {
        irq_(kRngRequestQueueIdx);
    }
}

}  // namespace tinyvmm::virtio
