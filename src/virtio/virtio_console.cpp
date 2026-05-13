#include "virtio_console.h"

#include <cstring>

namespace tinyvmm::virtio {

ConsoleDevice::ConsoleDevice(whp::GuestMemory& mem,
                             std::FILE* sink,
                             IrqFn irq)
    : rxq_(mem, kConsoleQueueMax),
      txq_(mem, kConsoleQueueMax),
      sink_(sink),
      irq_(std::move(irq)) {}

std::uint64_t ConsoleDevice::DeviceFeatures() const {
    return kFeatureVersion1 | kFeatureRingEventIdx;
}

bool ConsoleDevice::SetDriverFeatures(std::uint64_t acked) {
    if (!(acked & kFeatureVersion1)) return false;
    if (acked & ~DeviceFeatures())   return false;
    acked_features_ = acked;
    return true;
}

std::uint32_t ConsoleDevice::QueueMax(std::uint32_t idx) const {
    if (idx == kConsoleReceiveQueueIdx)  return kConsoleQueueMax;
    if (idx == kConsoleTransmitQueueIdx) return kConsoleQueueMax;
    return 0;
}

Virtqueue* ConsoleDevice::GetQueue(std::uint32_t idx) {
    if (idx == kConsoleReceiveQueueIdx)  return &rxq_;
    if (idx == kConsoleTransmitQueueIdx) return &txq_;
    return nullptr;
}

void ConsoleDevice::NotifyQueue(std::uint32_t idx) {
    if (idx == kConsoleTransmitQueueIdx) {
        if (!txq_.ready()) return;
        DrainTransmitQueue();
        return;
    }
    // rxq notifies just mean "the driver added receive buffers". We have no
    // host->guest input source in v1, so nothing to do.
}

void ConsoleDevice::Reset() {
    driver_ok_ = false;
    acked_features_ = 0;
}

std::uint32_t ConsoleDevice::ReadConfig(std::uint32_t offset,
                                        std::uint32_t size) {
    (void)offset;
    (void)size;
    // 12 bytes of zeros (cols=0, rows=0, max_nr_ports=0, emerg_wr=0).
    // We don't advertise F_SIZE / F_MULTIPORT / F_EMERG_WRITE, so the driver
    // ignores every field anyway.
    return 0;
}

std::vector<char> ConsoleDevice::capture_snapshot() const {
    return captured_;
}

void ConsoleDevice::DrainTransmitQueue() {
    bool any = false;
    while (auto chain = txq_.Pop()) {
        std::uint32_t total = 0;
        for (const auto& b : chain->bufs) {
            // Per spec §5.3.6.1 transmitq buffers are device-readable.
            // Ignore (silently) any device-writable buffer a buggy driver
            // hands us.
            if (b.write || b.len == 0) continue;
            if (sink_ != nullptr) {
                std::fwrite(b.host_addr, 1, b.len, sink_);
            }
            if (capture_) {
                const char* p = static_cast<const char*>(b.host_addr);
                captured_.insert(captured_.end(), p, p + b.len);
            }
            total += b.len;
        }
        if (sink_ != nullptr) std::fflush(sink_);
        // Spec §5.3.6.1: device writes 0 to `len` since transmitq buffers
        // are read-only from the device side.
        txq_.Push(chain->head_index, 0);
        tx_bytes_.fetch_add(total, std::memory_order_relaxed);
        tx_chains_.fetch_add(1, std::memory_order_relaxed);
        any = true;
    }
    if (any && irq_ && txq_.ShouldInterruptDriver()) {
        irq_(kConsoleTransmitQueueIdx);
    }
}

}  // namespace tinyvmm::virtio
