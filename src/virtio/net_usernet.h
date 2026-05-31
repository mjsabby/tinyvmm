#pragma once

// UsernetBackend (M19h) -- slirp-style user-mode networking for virtio-net.
//
// Terminates the guest's L2/L3 inside tinyvmm and translates each
// connection to a Windows kernel socket (Winsock TCP/UDP) or an iphlpapi
// ICMP echo. The Windows kernel owns the real wire path; no driver and
// no admin needed beyond the normal user account.
//
// TCP uses the `tcp-sans-io` Rust crate (TsiTcpEngine in net_usernet_tsi.*)
// for full RFC 6675 SACK + RACK-TLP + PRR-Reno + ECN + RFC 7323 TS/WS +
// SYN cookies + IW=10. M34.8 flipped this from a runtime switch to the
// only TCP path; the legacy hand-rolled C++ state machine was deleted.
//
// Topology presented to the guest:
//   * gateway IP    = 10.0.0.1   (we answer ARP for this and route from it)
//   * gateway MAC   = backend_mac (synthetic, locally administered range)
//   * guest IP      = 10.0.0.2   (set by initramfs)
//   * guest MAC     = NetDevice::mac() (pinned by virtio config)
//
// What we implement on the guest-facing wire:
//   * ARP request/reply for gateway IP.
//   * IPv4 + ICMP echo (responses synthesized; remote pings proxied via
//     IcmpSendEcho on iphlpapi).
//   * IPv4 + UDP datagram NAT (per-4-tuple connected Winsock socket).
//   * IPv4 + TCP terminate-and-proxy via TsiTcpEngine.
//
// What we drop:
//   * IPv6, ARP for any IP other than the gateway, all non-TCP/UDP/ICMP
//     IPv4 protocols, IPv4 fragments.

#include "common.h"
#include "net_backend.h"
#include "virtio_net.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tinyvmm::virtio {

class UsernetBackend : public NetBackend {
public:
    // Inbound port-forward rule: a host TCP listener at
    // (host_addr_be, host_port) accepts client connections and proxies
    // them through to (guest_ip_be, guest_port) inside the guest. The
    // VMM originates a SYN toward the guest from gateway_ipv4 with a
    // randomly chosen ephemeral source port for each accepted client.
    //
    // Typical use: `--portfwd 3389:3389` to RDP into the guest.
    struct PortForward {
        std::uint32_t host_addr_be = 0;   // 127.0.0.1 by default
        std::uint16_t host_port    = 0;
        std::uint32_t guest_ip_be  = 0;   // 10.0.0.2 by default
        std::uint16_t guest_port   = 0;
    };

    struct Options {
        // Gateway IPv4 in dotted-quad text. Default 10.0.0.1.
        std::string gateway_ipv4 = "10.0.0.1";

        // Synthetic MAC for the gateway. Locally administered range so it
        // doesn't collide with anything real on the wire.
        std::array<std::uint8_t, 6> backend_mac{
            0x02, 0x53, 0x54, 0x00, 0x00, 0x01};

        // Per-conn caps. UDP entries time out idle, TCP entries on close.
        std::uint32_t max_tcp_conns = 1024;
        std::uint32_t max_udp_conns = 256;
        std::uint32_t max_icmp_inflight = 16;

        // UDP NAT idle timeout (ms).
        std::uint32_t udp_idle_ms = 60'000;

        // Inbound TCP port-forwards. Empty by default.
        std::vector<PortForward> port_forwards;

        // Verbose worker stats every ~2s when set (counters + table sizes).
        bool debug = false;
    };

    UsernetBackend(NetDevice& net, const Options& opts);
    ~UsernetBackend() override;

    void Start(whp::Partition& partition, PciTransport& transport) override;
    void Stop() override;
    void OnQueueNotify(std::uint32_t qidx) override;

    bool ready() const noexcept;

    std::uint64_t tx_packets() const noexcept;
    std::uint64_t rx_packets() const noexcept;
    std::uint64_t tx_dropped() const noexcept;
    std::uint64_t rx_dropped() const noexcept;
    std::uint64_t arp_replies() const noexcept;
    std::uint64_t tcp_conns_total() const noexcept;
    std::uint64_t udp_conns_total() const noexcept;
    std::uint64_t icmp_echoes_total() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}  // namespace tinyvmm::virtio
