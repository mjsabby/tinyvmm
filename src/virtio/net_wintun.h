#pragma once

// WintunNetBackend (M16).
//
// NOTE: include `wintun_loader.h` **before** any header that pulls in
// <Windows.h> on its own, so wintun.h's `<winsock2.h>` lands first.

#include "../net/wintun_loader.h"

#include "../common.h"
#include "net_backend.h"
#include "virtio_net.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tinyvmm::virtio {

class WintunNetBackend : public NetBackend {
public:
    struct Options {
        // Adapter name (UTF-8). Created on Start, destroyed on Stop.
        std::string adapter_name = "tinyvmm";

        // Tunnel type label (cosmetic).
        std::string tunnel_type  = "tinyvmm";

        // Host-side IPv4 address assigned to the adapter ("10.0.0.1").
        // Will be set with `prefix_length` (typically /24).
        std::string host_ipv4    = "10.0.0.1";
        std::uint8_t prefix_len  = 24;

        // Synthetic MAC used by the backend for ARP responses and as
        // the source MAC on the Ethernet frames we push to the guest.
        // Default is in the locally-administered range (qemu-ish).
        std::array<std::uint8_t, 6> backend_mac{
            0x02, 0x53, 0x54, 0x00, 0x00, 0x01};

        // WinTun ring capacity (power of two between 128 KiB and 64
        // MiB). 4 MiB is plenty for dev workloads.
        std::uint32_t ring_capacity = 4 * 1024 * 1024;
    };

    WintunNetBackend(NetDevice& net, const Options& opts);
    ~WintunNetBackend() override;

    void Start(whp::Partition& partition, PciTransport& transport) override;
    void Stop() override;
    void OnQueueNotify(std::uint32_t qidx) override;

    bool ready() const noexcept { return ready_; }

    // Stable error string set when Start() fails to bring the adapter
    // up; empty when ready.
    const std::string& last_error() const noexcept { return last_error_; }

    std::uint64_t tx_packets() const noexcept { return tx_packets_.load(); }
    std::uint64_t rx_packets() const noexcept { return rx_packets_.load(); }
    std::uint64_t tx_dropped() const noexcept { return tx_dropped_.load(); }
    std::uint64_t rx_dropped() const noexcept { return rx_dropped_.load(); }
    std::uint64_t arp_replies() const noexcept { return arp_replies_.load(); }

private:
    void WorkerLoop();
    void DrainTx();
    void DeliverRx();
    void HandleArp(const std::uint8_t* eth_frame, std::size_t len);
    bool SendIpToWintun(const std::uint8_t* ip_pkt, std::size_t len);
    bool ConfigureAdapterIp();
    void CleanupAdapter();

    NetDevice& net_;
    Options opts_;
    PciTransport* xport_ = nullptr;

    const net::WintunApi* api_ = nullptr;
    WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
    WINTUN_SESSION_HANDLE session_ = nullptr;
    HANDLE wintun_read_evt_ = nullptr;
    NET_LUID adapter_luid_{};
    bool adapter_ip_set_ = false;

    HANDLE stop_evt_     = nullptr;
    HANDLE tx_doorbell_  = nullptr;
    HANDLE rx_doorbell_  = nullptr;
    std::thread worker_;
    std::atomic<bool> running_{false};

    bool ready_ = false;
    std::string last_error_;

    // Pending Ethernet frames built from WinTun reads, waiting for
    // guest rxq buffers to land.
    std::deque<std::vector<std::uint8_t>> pending_rx_;

    std::atomic<std::uint64_t> tx_packets_{0};
    std::atomic<std::uint64_t> rx_packets_{0};
    std::atomic<std::uint64_t> tx_dropped_{0};
    std::atomic<std::uint64_t> rx_dropped_{0};
    std::atomic<std::uint64_t> arp_replies_{0};

    std::uint32_t host_ip_be_ = 0;   // host adapter IP in network byte order.
};

}  // namespace tinyvmm::virtio

namespace tinyvmm {

// --wintun-probe : standalone diagnostic, lives next to the backend
// because both need the same iphlpapi/wintun include order. Loads
// wintun.dll, creates an adapter, assigns 10.0.0.1/24, runs an RX
// loop for `seconds`, then tears the adapter down. Admin required.
int RunWintunProbe(int seconds);

}  // namespace tinyvmm
