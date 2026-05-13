#include "net_loopback.h"

#include "virtio_pci.h"

#include <algorithm>
#include <cstring>

namespace tinyvmm::virtio {

namespace {

// virtio_net_hdr_v1 (spec §5.1.6.2). With VERSION_1 and without MRG_RXBUF,
// the header is still 12 bytes (num_buffers field is present but unused).
constexpr std::size_t kVirtioNetHdrSize = 12;

}  // namespace

void LoopbackNetBackend::Start(whp::Partition& /*partition*/,
                                PciTransport& transport) {
    xport_ = &transport;
}

void LoopbackNetBackend::Stop() {
    xport_ = nullptr;
    pending_.clear();
}

void LoopbackNetBackend::OnQueueNotify(std::uint32_t qidx) {
    if (!xport_) return;
    // Either direction's notify can carry work for the loopback: a TX
    // notify produces new RX traffic, and an RX notify may unblock
    // packets that were queued waiting for buffers.
    if (qidx == kTxQueueIdx) {
        DrainTx();
    }
    DeliverRx();
}

void LoopbackNetBackend::DrainTx() {
    auto& tx = net_.tx_queue();
    if (!tx.ready()) return;

    bool any = false;
    while (auto chain = tx.Pop()) {
        // Skip the leading virtio_net_hdr (always 12 bytes after we
        // negotiated VERSION_1). The rest is the Ethernet frame.
        std::vector<std::uint8_t> pkt;
        std::size_t hdr_remaining = kVirtioNetHdrSize;
        for (const auto& b : chain->bufs) {
            if (b.write) continue;
            std::size_t off = 0;
            std::size_t len = b.len;
            if (hdr_remaining > 0) {
                const std::size_t skip = std::min<std::size_t>(len, hdr_remaining);
                hdr_remaining -= skip;
                off += skip;
                len -= skip;
            }
            if (len > 0) {
                const auto* p = static_cast<const std::uint8_t*>(b.host_addr) + off;
                pkt.insert(pkt.end(), p, p + len);
            }
        }
        tx.Push(chain->head_index, 0);
        if (!pkt.empty()) {
            pending_.push_back(std::move(pkt));
            tx_packets_++;
        }
        any = true;
    }
    if (any) xport_->RaiseQueueInterrupt(kTxQueueIdx);
}

void LoopbackNetBackend::DeliverRx() {
    auto& rx = net_.rx_queue();
    if (!rx.ready()) return;

    bool any = false;
    while (!pending_.empty()) {
        auto chain = rx.Pop();
        if (!chain) break;  // No buffers; leave pending in queue.

        auto& pkt = pending_.front();
        std::size_t hdr_remaining = kVirtioNetHdrSize;
        std::size_t pkt_off = 0;
        std::uint32_t total = 0;

        for (auto& b : chain->bufs) {
            if (!b.write) continue;
            std::uint8_t* p = static_cast<std::uint8_t*>(b.host_addr);
            std::size_t avail = b.len;
            if (hdr_remaining > 0 && avail > 0) {
                const std::size_t take = std::min(avail, hdr_remaining);
                std::memset(p, 0, take);
                p += take;
                avail -= take;
                hdr_remaining -= take;
                total += static_cast<std::uint32_t>(take);
            }
            if (avail > 0 && pkt_off < pkt.size()) {
                const std::size_t take = std::min(avail, pkt.size() - pkt_off);
                std::memcpy(p, pkt.data() + pkt_off, take);
                pkt_off += take;
                total += static_cast<std::uint32_t>(take);
            }
            if (hdr_remaining == 0 && pkt_off == pkt.size()) break;
        }
        if (pkt_off < pkt.size()) {
            rx_dropped_++;
        } else {
            rx_packets_++;
        }
        rx.Push(chain->head_index, total);
        pending_.pop_front();
        any = true;
    }
    if (any) xport_->RaiseQueueInterrupt(kRxQueueIdx);
}

}  // namespace tinyvmm::virtio
