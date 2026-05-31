// SPDX-License-Identifier: MIT
//
// tinyvmm — TSI (tcp-sans-io) outbound TCP engine for UsernetBackend.
//
// M34.4: replace UsernetBackend's hand-rolled C++ TCP NAT for outbound
// flows (guest → host) with the `tcp-sans-io` Rust crate (linked as the
// `tcp_sans_io.lib` staticlib). This engine is selected via the runtime
// flag `--net-usernet-tcp=tsi` and is constructed lazily from
// `UsernetBackend::State::Start()` when that option is in effect; the
// legacy path stays the default until M34.8 flips the default.
//
// The engine owns a population of `TcpConnTsi` objects, each of which
// wraps:
//   - one tcp-sans-io TCB (TcpStreamHandle*) playing the "destination"
//     role (LISTEN → SYN_RCVD → ESTABLISHED → ...);
//   - one Winsock client socket bound non-blocking to the real
//     destination on the host (TCP connect());
//   - two staging buffers (host→TCB and TCB→host).
//
// Dispatch:
//   - On the guest TX path, `OnGuestTcpPacket(now_ms, ip, ip_len)` is
//     called from HandleIpFromGuest (when the engine is active);
//     the packet is shaped as the full IPv4+TCP datagram. The engine
//     does NOT receive an L4-only buffer because tcp-sans-io's
//     inject API takes a full IP+TCP datagram.
//   - Per-iteration, the worker calls `Tick(now_ms)`. Tick runs its
//     own WSAPoll on the engine's host sockets, drives state, drains
//     TX rings, and emits any pending IPv4+TCP frames to the guest
//     via the `push_ipv4_to_guest` callback.
//   - `Shutdown()` closes all sockets, drains TCBs (RST), and frees
//     all TCB storage.
//
// Inbound (port-forwarded) TCP is NOT handled by this engine; M34.x
// keeps inbound on the legacy path. The engine only ever receives
// outbound (guest-initiated) flows.
//
// Threading: the engine is single-threaded — it runs entirely on the
// UsernetBackend worker thread. Its constructor and destructor may
// be called from the main thread (during Start/Stop on the State).
// All public methods other than ctor/dtor MUST be called from the
// worker thread.
//
// Stack: tcp-sans-io's `tcp_init` transiently uses ~2 MiB of caller
// stack to set up the in-place TCB (two `Ring<1 MiB>` plus a TcbInner).
// tinyvmm's CMakeLists.txt sets `/STACK:16777216` on the .exe, and
// Windows propagates the PE stack reserve to threads created with
// `dwStackSize == 0` (the default for `std::thread` / `_beginthreadex`).
// We verified this empirically before settling on this design — no
// explicit large-stack thread helper is needed.

#pragma once

#include "net_usernet.h"

#include <winsock2.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace tinyvmm::virtio {

class TsiTcpEngine {
public:
    // Inputs the engine needs to talk to the surrounding usernet
    // backend without depending on its private State struct.
    struct EmitCtx {
        // Deliver a single fully-built IPv4+TCP datagram to the guest.
        // Callee MUST prepend a 14-byte Ethernet header (dst=guest_mac,
        // src=backend_mac, ethertype=0x0800) and enqueue on the
        // backend's pending_rx queue. Callee MUST NOT alter the IP
        // bytes (tcp-sans-io already computed the checksums).
        std::function<void(const std::uint8_t* ip_pkt,
                           std::size_t        ip_len)> push_ipv4_to_guest;

        // Monotonic millisecond clock; tcp-sans-io takes u64 now_ms.
        std::function<std::uint64_t()> now_ms;

        std::array<std::uint8_t, 6> backend_mac{};
        std::array<std::uint8_t, 6> guest_mac{};

        // Source IPv4 address (wire byte order) the engine should use when
        // originating SYNs toward the guest on an inbound port-forwarded
        // flow. Must be the same address legacy NAT uses for its gateway,
        // so MAC/ARP resolution at the guest's IP stack succeeds.
        std::uint32_t gateway_ip_be = 0;

        // Per-conn cap. Default 64 (≈ 64 * 2.2 MiB = ~140 MiB worst
        // case). Rejecting beyond this returns a RST to the guest.
        std::size_t max_conns = 64;

        // Idle timeout (ms) after which we abort a TCB whose remote
        // host stopped responding. Default 10 min (M34.6 spec).
        std::uint64_t idle_ms = 10ull * 60ull * 1000ull;

        // Connect-establishment deadline (ms). Default 10 s.
        std::uint64_t connect_ms = 10ull * 1000ull;

        // M34.6: half-close watchdog. Once the TCB enters a half-closed
        // state (FIN_WAIT_1/2, CLOSE_WAIT, CLOSING, LAST_ACK) AND no
        // activity (TX or RX) occurs for this long, abort the conn so
        // a misbehaved peer or stalled host app can't pin engine
        // resources indefinitely. Default 30s.
        std::uint64_t half_close_ms = 30ull * 1000ull;
    };

    explicit TsiTcpEngine(EmitCtx ctx);
    ~TsiTcpEngine();

    TsiTcpEngine(const TsiTcpEngine&)            = delete;
    TsiTcpEngine& operator=(const TsiTcpEngine&) = delete;

    // Process one inbound (from guest) IPv4+TCP datagram.
    void OnGuestTcpPacket(std::uint64_t      now_ms,
                          const std::uint8_t* ip_pkt,
                          std::size_t         ip_len);

    // M34.5: Adopt a freshly-accepted host socket as the host side of an
    // inbound port-forwarded TCP flow. The engine allocates an unused
    // gateway-side ephemeral port (49152..65535), builds an active-opener
    // TCB (tcp_init + tcp_connect) targeting (guest_ip, guest_port), emits
    // a SYN toward the guest via push_ipv4_to_guest, and proxies bytes in
    // both directions once the handshake completes.
    //
    // Returns true on success (engine has taken ownership of host_sock —
    // it will closesocket() it on teardown). Returns false if the engine
    // is at its per-conn cap, can't allocate an ephem port, or the TCB
    // setup fails. On false, the caller MUST close host_sock itself.
    //
    // Thread: must be called from the same thread that calls Tick (the
    // UsernetBackend worker thread). It is *not* re-entrant with
    // OnGuestTcpPacket / Tick / Shutdown.
    bool StartInboundConn(SOCKET host_sock,
                          std::uint32_t guest_ip_be,
                          std::uint16_t guest_port_be);

    // Per-iteration housekeeping. Called from the UsernetBackend
    // worker loop after `DrainGuestTx() + DrainHostSockets()`.
    // Runs the engine's own WSAPoll on host sockets, drains both
    // sides of every TCB, and emits IPv4 frames to the guest via
    // the push_ipv4_to_guest callback.
    void Tick(std::uint64_t now_ms);

    // Tear down all TCBs and close all sockets. Must be called from
    // the worker thread before WSACleanup. Safe to call repeatedly.
    void Shutdown();

    // Stats.
    std::size_t   conn_count()      const noexcept;
    std::uint64_t total_conns()     const noexcept;
    std::uint64_t rsts_sent()       const noexcept;
    // M34.6 counters.
    std::uint64_t segments_rx()     const noexcept;  // guest TCP packets accepted
    std::uint64_t segments_tx()     const noexcept;  // TCP frames emitted to guest
    std::uint64_t aborts()          const noexcept;  // tcp_abort calls
    std::uint64_t graceful_closes() const noexcept;  // non-abort path to CLOSED

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace tinyvmm::virtio
