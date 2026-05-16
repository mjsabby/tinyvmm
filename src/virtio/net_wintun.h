#pragma once

// WintunNetBackend (M16) — virtio-net data plane bridged through a
// WinTun adapter (L3 TUN) to the Windows host.
//
// Control plane (adapter create/configure/destroy) is delegated to a
// `net::WintunAdapterManager` (see net/wintun_adapter_mgr.h):
//   * `BackendKind::Dll` — uses wintun.dll directly. Requires admin.
//   * `BackendKind::Svc` — uses the wintunsvc Windows service over its
//     named pipe; works for unelevated callers.
//
// Data plane uses the clean-room user-mode `wintun::session` (vendored
// at third_party/wintunumapi/cpp) so both paths share a single ring
// implementation.

#include "common.h"

// Pull wintun.h first because it pins the winsock include order; the
// rest of the headers below assume that order is already correct.
#include "net/wintun_loader.h"
#include "net/wintun_adapter_mgr.h"

#include "net_backend.h"
#include "virtio_net.h"

// wintun_session.hpp pre-defines WIN32_LEAN_AND_MEAN that we already
// define globally via target_compile_definitions; identical value but
// /W4 still emits C4005. Suppress locally so callers of this header
// don't all need /wd4005.
#pragma warning(push)
#pragma warning(disable: 4005)
#include "wintun_session.hpp"
#pragma warning(pop)

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace tinyvmm::virtio {

class WintunNetBackend : public NetBackend {
public:
    enum class BackendKind { Dll, Svc };

    struct Options {
        BackendKind kind = BackendKind::Dll;

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
    void HandleArp(std::span<const std::uint8_t> eth_frame);
    // Zero-copy IP TX: copies directly from a virtq descriptor chain
    // (skipping the leading vhdr + Eth header) into a wintun ring slot.
    bool SendIpFromChainToWintun(const PoppedChain& chain,
                                  std::size_t ip_bytes);

    NetDevice& net_;
    Options opts_;
    PciTransport* xport_ = nullptr;

    std::unique_ptr<net::WintunAdapterManager> mgr_;
    std::optional<net::WintunAdapter>          adapter_;
    std::optional<wintun::session>             session_;
    HANDLE wintun_read_evt_ = nullptr;

    HANDLE stop_evt_     = nullptr;
    HANDLE tx_doorbell_  = nullptr;
    HANDLE rx_doorbell_  = nullptr;
    std::thread worker_;
    std::atomic<bool> running_{false};

    bool ready_ = false;
    std::string last_error_;

    // Pending RX packets waiting for guest rxq buffers. Each entry
    // owns either a wintun-owned span (zero-copy IPv4) OR an inline
    // vector (synthesized ARP reply). The Ethernet header is
    // synthesized host-side so it lives separately from the payload.
    struct PendingRx {
        std::array<std::uint8_t, 14> eth_hdr{};
        std::span<const std::byte>   wintun_payload;   // wintun-owned
        std::vector<std::uint8_t>    owned_payload;    // ARP reply, etc.
    };
    static constexpr std::size_t kPendingRxCap = 64;
    std::deque<PendingRx> pending_rx_;

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

// --wintun-svc-probe : same flow but driven through the wintunsvc
// Windows service. Works for unelevated callers; requires that
// WintunSvc be installed + running.
int RunWintunSvcProbe(int seconds);

}  // namespace tinyvmm
