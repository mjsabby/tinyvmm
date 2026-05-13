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
    // rxq notify = driver added receive buffers. Drain any pending host
    // input into them.
    if (idx == kConsoleReceiveQueueIdx) {
        if (!rxq_.ready()) return;
        std::lock_guard<std::mutex> lg(rx_mu_);
        DrainReceiveQueueLocked();
    }
}

void ConsoleDevice::WriteHostInput(const char* data, std::size_t n) {
    if (n == 0) return;
    std::lock_guard<std::mutex> lg(rx_mu_);
    rx_pending_.insert(rx_pending_.end(), data, data + n);
    if (rxq_.ready()) DrainReceiveQueueLocked();
}

void ConsoleDevice::DrainReceiveQueueLocked() {
    // Caller holds rx_mu_. rxq_.ready() was checked by caller.
    bool any = false;
    while (!rx_pending_.empty()) {
        auto chain = rxq_.Pop();
        if (!chain) break;          // driver hasn't posted any RX buffers
        std::uint32_t total = 0;
        for (const auto& b : chain->bufs) {
            if (!b.write || b.len == 0) continue;
            char* dst = static_cast<char*>(b.host_addr);
            std::uint32_t cap = b.len;
            std::uint32_t i = 0;
            while (i < cap && !rx_pending_.empty()) {
                dst[i++] = rx_pending_.front();
                rx_pending_.pop_front();
            }
            total += i;
            if (rx_pending_.empty()) break;  // no more bytes to deliver
        }
        rxq_.Push(chain->head_index, total);
        any = true;
        if (total == 0) break;       // chain had no writable buffers; bail
    }
    if (any && irq_ && rxq_.ShouldInterruptDriver()) {
        irq_(kConsoleReceiveQueueIdx);
    }
}

void ConsoleDevice::Reset() {
    driver_ok_ = false;
    acked_features_ = 0;
    {
        std::lock_guard<std::mutex> lg(rx_mu_);
        rx_pending_.clear();
    }
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
            if (byte_observer_) {
                byte_observer_(static_cast<const char*>(b.host_addr), b.len);
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
