#pragma once

// LoopbackNetBackend (M15).
//
// Self-contained virtio-net backend that simply echoes TX frames back to
// the guest as RX. Useful as:
//   * A host-side regression test fixture: --virtio-net-loopback-test
//     drives the device end-to-end through PciTransport + virtqueues and
//     verifies a packet round-trips with byte-equality.
//   * A bring-up backend when there's no real NIC / XDP driver available
//     — `--pvh-run --net --net-backend loopback` lets a kernel see a
//     functional virtio-net device that processes its own transmits.
//
// All work happens synchronously on the vcpu thread that wrote the
// queue-notify MMIO (no worker threads). That's adequate for tests; it's
// not adequate for high-throughput use cases.

#include "../common.h"
#include "net_backend.h"
#include "virtio_net.h"

#include <cstdint>
#include <deque>
#include <vector>

namespace tinyvmm::virtio {

class LoopbackNetBackend : public NetBackend {
public:
    explicit LoopbackNetBackend(NetDevice& net) : net_(net) {}

    void Start(whp::Partition& partition, PciTransport& transport) override;
    void Stop() override;
    void OnQueueNotify(std::uint32_t qidx) override;

    // Diagnostics.
    std::uint64_t tx_packets() const noexcept { return tx_packets_; }
    std::uint64_t rx_packets() const noexcept { return rx_packets_; }
    std::uint64_t rx_dropped() const noexcept { return rx_dropped_; }
    std::size_t   queued()     const noexcept { return pending_.size(); }

private:
    void DrainTx();
    void DeliverRx();

    NetDevice& net_;
    PciTransport* xport_ = nullptr;

    std::deque<std::vector<std::uint8_t>> pending_;
    std::uint64_t tx_packets_ = 0;
    std::uint64_t rx_packets_ = 0;
    std::uint64_t rx_dropped_ = 0;
};

}  // namespace tinyvmm::virtio
