// SPDX-License-Identifier: MIT
//
// tinyvmm — TSI (tcp-sans-io) outbound TCP engine (M34.4 implementation).
//
// See net_usernet_tsi.h for the public design rationale.
//
// Rubber-duck-blocking fixes encoded here:
//
//   #1 Triple-drain TX ring:
//      Around every (inject/tick/send/close/abort) call, we drain the
//      TCB's TX ring both BEFORE (to clear any stale queued packet that
//      might have been left from a prior call that hit cap) AND AFTER
//      (to ship the response). tcp-sans-io's TX ring has 32 slots; an
//      undrained ring silently swallows newly queued packets.
//
//   #2 Don't WSASend while Shim::Connecting:
//      tcp-sans-io's TCB completes the 3WHS immediately (SYN-ACK
//      enters the ring on inject). The guest can therefore reach
//      ESTABLISHED and start sending HTTP request bytes BEFORE the
//      Winsock connect() to the real destination completes. We accept
//      those bytes via tcp_recv into staging_to_host but defer WSASend
//      until shim_state transitions to Established.
//
//   #3 Translate guest FIN to shutdown(SD_SEND):
//      When tcp_poll() reports TCP_EV_PEER_CLOSED and we have flushed
//      staging_to_host to the host, we call shutdown(host_sock, SD_SEND)
//      so the remote server observes EOF and can finish its response.
//      Without this, servers like nginx will wait indefinitely for the
//      EOF before closing the response side.
//
//   #4 EmitIpv4 must NOT re-wrap:
//      tcp_extract_packet returns a complete IPv4+TCP datagram with
//      both checksums already computed. We must NOT re-call the
//      EmitIpv4() helper (which would add a second IP header). We
//      prepend an Ethernet header ourselves and ship via the
//      push_ipv4_to_guest callback.

#include "net_usernet_tsi.h"

#include "diag/etw.h"
#include "net/wintun_loader.h"  // net::FormatWindowsError
#include "net/tsi_handle.h"      // tinyvmm::net::TcbHandle / RawAlignedBuf

#include "tcp_sans_io.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <malloc.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace tinyvmm::virtio {

namespace {

// ---------- ConnKey ------------------------------------------------------

struct ConnKey {
    std::uint32_t guest_ip_be   = 0;
    std::uint32_t dst_ip_be     = 0;
    std::uint16_t guest_port_be = 0;
    std::uint16_t dst_port_be   = 0;
    bool operator==(const ConnKey& o) const noexcept {
        return guest_ip_be == o.guest_ip_be && dst_ip_be == o.dst_ip_be &&
               guest_port_be == o.guest_port_be && dst_port_be == o.dst_port_be;
    }
};

struct ConnKeyHash {
    std::size_t operator()(const ConnKey& k) const noexcept {
        std::uint64_t lo = (std::uint64_t)k.guest_ip_be |
                           ((std::uint64_t)k.dst_ip_be << 32);
        std::uint64_t hi = (std::uint64_t)k.guest_port_be |
                           ((std::uint64_t)k.dst_port_be << 16);
        std::uint64_t h = lo ^ (hi * 0x9E3779B97F4A7C15ull);
        h ^= h >> 33; h *= 0xff51afd7ed558ccdull; h ^= h >> 33;
        return (std::size_t)h;
    }
};

// ---------- Tunables -----------------------------------------------------

constexpr std::size_t   kStagingCap        = 256 * 1024;
constexpr std::size_t   kReadChunkCap      = 16 * 1024;
constexpr std::uint8_t  kIpProtoTcp        = 6;
constexpr std::size_t   kIp4HdrMinSize     = 20;
constexpr std::size_t   kTcpHdrMinSize     = 20;
constexpr std::uint32_t kInitialRtoMs      = 1000;
constexpr std::uint8_t  kTcpFin = 0x01;
constexpr std::uint8_t  kTcpSyn = 0x02;
constexpr std::uint8_t  kTcpRst = 0x04;
constexpr std::uint8_t  kTcpAck = 0x10;

// ---------- Byte order helpers (local) -----------------------------------

inline std::uint16_t Be16(const std::uint8_t* p) {
    return (std::uint16_t)((std::uint16_t)p[0] << 8 | (std::uint16_t)p[1]);
}
inline std::uint32_t Be32(const std::uint8_t* p) {
    return (std::uint32_t)((std::uint32_t)p[0] << 24 |
                           (std::uint32_t)p[1] << 16 |
                           (std::uint32_t)p[2] <<  8 |
                           (std::uint32_t)p[3]);
}
inline void Wr16Be(std::uint8_t* p, std::uint16_t v) {
    p[0] = (std::uint8_t)(v >> 8); p[1] = (std::uint8_t)v;
}
inline void Wr32Be(std::uint8_t* p, std::uint32_t v) {
    p[0] = (std::uint8_t)(v >> 24); p[1] = (std::uint8_t)(v >> 16);
    p[2] = (std::uint8_t)(v >>  8); p[3] = (std::uint8_t)v;
}

// One's-complement checksum.
inline std::uint16_t InetCksum(const std::uint8_t* p, std::size_t n,
                                std::uint32_t carry = 0) {
    std::uint32_t s = carry;
    while (n >= 2) { s += (std::uint32_t)p[0] << 8 | p[1]; p += 2; n -= 2; }
    if (n) s += (std::uint32_t)p[0] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (std::uint16_t)(~s & 0xFFFF);
}

inline std::uint32_t PseudoHdrSum(std::uint32_t src_be, std::uint32_t dst_be,
                                   std::uint8_t proto, std::size_t l4_len) {
    std::uint32_t s = 0;
    auto add = [&](std::uint16_t w) { s += w; };
    auto* sb = (const std::uint8_t*)&src_be;
    auto* db = (const std::uint8_t*)&dst_be;
    add((std::uint16_t)(sb[0] << 8 | sb[1]));
    add((std::uint16_t)(sb[2] << 8 | sb[3]));
    add((std::uint16_t)(db[0] << 8 | db[1]));
    add((std::uint16_t)(db[2] << 8 | db[3]));
    add((std::uint16_t)proto);
    add((std::uint16_t)l4_len);
    return s;
}

// ---------- TCB connection record ---------------------------------------

// ---------- TCB RAII -----------------------------------------------------
//
// We use the shared TcbHandle / RawAlignedBuf / AllocateTcbStorage()
// from src/net/tsi_handle.h. The same types are consumed by
// src/net/tsi_sanity.cpp.
using ::tinyvmm::net::TcbHandle;
using ::tinyvmm::net::RawAlignedBuf;

struct TcpConnTsi {
    ConnKey key{};

    // Owns both the TCB's tcp-sans-io state AND its aligned backing
    // storage; reset() calls tcp_destroy then _aligned_free.
    TcbHandle handle;

    SOCKET host_sock = INVALID_SOCKET;

    enum class Shim { Connecting, Established, Closed };
    Shim shim_state = Shim::Connecting;

    std::vector<std::uint8_t> staging_to_host;  // tcp_recv → WSASend
    std::vector<std::uint8_t> staging_to_tcb;   // WSARecv → tcp_send

    bool host_eof_seen    = false;
    bool host_send_shut   = false;
    bool tcp_close_called = false;
    bool tcp_abort_called = false;
    bool destroyed        = false;  // set just before unique_ptr drops

    // M34.5 inbound port-forward state.
    bool is_inbound             = false;
    bool inbound_handshake_done = false;  // TCB reached ESTABLISHED/CLOSE_WAIT
    // Rubber-duck rec #3: host_sock may signal EOF *before* the guest
    // completes the SYN handshake. In that window tcp_close on a SYN_SENT
    // TCB is a local no-op; we instead remember the intent and call
    // tcp_close once the TCB establishes (or abort on timeout).
    bool pending_close_after_established = false;

    std::uint64_t connect_deadline_ms = 0;
    std::uint64_t idle_deadline_ms    = 0;
    std::uint64_t last_activity_ms    = 0;
};

// ---------- Entropy ------------------------------------------------------

std::uint32_t RandomIss() {
    std::uint32_t v = 0;
    NTSTATUS s = ::BCryptGenRandom(nullptr,
                                    reinterpret_cast<PUCHAR>(&v),
                                    sizeof(v),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (s == 0) ? v : 0xCAFEBABEu;
}

}  // namespace

// ============================================================================
// TsiTcpEngine::Impl
// ============================================================================

struct TsiTcpEngine::Impl {
    EmitCtx ctx;

    // unique_ptr because TcpConnTsi holds a pointer to its TCB storage and
    // staging buffers; a flat-by-value map would invalidate the storage
    // on rehash.
    std::unordered_map<ConnKey, std::unique_ptr<TcpConnTsi>, ConnKeyHash> conns;

    // Scratch buffer for tcp_extract_packet (~1500 bytes).
    std::vector<std::uint8_t> extract_buf;

    std::atomic<std::uint64_t> total_conns_{0};
    std::atomic<std::uint64_t> rsts_sent_{0};
    // M34.6 counters. All bumped from the worker thread; atomic so
    // public getters can be read from any thread safely (currently
    // only read from the same worker thread, but cheap to future-proof).
    std::atomic<std::uint64_t> segments_rx_{0};
    std::atomic<std::uint64_t> segments_tx_{0};
    std::atomic<std::uint64_t> aborts_{0};
    std::atomic<std::uint64_t> graceful_closes_{0};

    explicit Impl(EmitCtx c) : ctx(std::move(c)) {
        extract_buf.resize(tcp_max_packet());
    }

    ~Impl() { DestroyAllInternal(); }

    // ----- Frame emission ------------------------------------------------

    // Push a fully-built IPv4+TCP datagram to the guest as one Ethernet
    // frame. Used for both extract_packet output and synthetic RSTs.
    // Rubber-duck #4: we do NOT call EmitIpv4 (that would re-wrap with
    // a second IP header). We only prepend Ethernet.
    void PushIpv4(const std::uint8_t* ip_pkt, std::size_t ip_len) {
        if (!ip_pkt || ip_len == 0) return;
        ctx.push_ipv4_to_guest(ip_pkt, ip_len);
        // M34.6: counts attempted TX (the callback itself may drop
        // when the pending_rx queue is full; this counter is "engine
        // emitted" not "guest received").
        segments_tx_.fetch_add(1, std::memory_order_relaxed);
    }

    // Emit a synthetic IPv4+TCP RST. Build IP header + TCP header inline
    // (no TCB needed). `src/dst` here is the wire-direction src/dst, i.e.
    // we're synthesizing as if the destination were sending.
    void EmitSyntheticRst(std::uint32_t src_ip_be, std::uint32_t dst_ip_be,
                          std::uint16_t src_port_be, std::uint16_t dst_port_be,
                          std::uint32_t seq, std::uint32_t ack, bool ack_valid) {
        constexpr std::size_t kLen = kIp4HdrMinSize + kTcpHdrMinSize;
        std::uint8_t pkt[kLen]{};

        // IPv4 header (no options).
        pkt[0] = 0x45;
        pkt[1] = 0x00;
        Wr16Be(pkt + 2, (std::uint16_t)kLen);
        Wr16Be(pkt + 4, 0);           // IP ID 0 -- benign for RST
        Wr16Be(pkt + 6, 0x4000);      // DF
        pkt[8]  = 64;                 // TTL
        pkt[9]  = kIpProtoTcp;
        Wr16Be(pkt + 10, 0);
        std::memcpy(pkt + 12, &src_ip_be, 4);
        std::memcpy(pkt + 16, &dst_ip_be, 4);
        Wr16Be(pkt + 10, InetCksum(pkt, kIp4HdrMinSize));

        // TCP header.
        std::uint8_t* tcp = pkt + kIp4HdrMinSize;
        std::memcpy(tcp + 0, &src_port_be, 2);
        std::memcpy(tcp + 2, &dst_port_be, 2);
        Wr32Be(tcp + 4, seq);
        Wr32Be(tcp + 8, ack);
        tcp[12] = (std::uint8_t)((kTcpHdrMinSize / 4) << 4);
        tcp[13] = (std::uint8_t)(kTcpRst | (ack_valid ? kTcpAck : 0));
        Wr16Be(tcp + 14, 0);
        Wr16Be(tcp + 16, 0);
        Wr16Be(tcp + 18, 0);
        std::uint32_t ph = PseudoHdrSum(src_ip_be, dst_ip_be,
                                         kIpProtoTcp, kTcpHdrMinSize);
        Wr16Be(tcp + 16, InetCksum(tcp, kTcpHdrMinSize, ph));

        PushIpv4(pkt, kLen);
        rsts_sent_.fetch_add(1, std::memory_order_relaxed);
    }

    // Rubber-duck #1: drain ALL packets queued in the TCB's TX ring.
    // Called immediately before AND after every tcp_inject_packet /
    // tcp_tick / tcp_send / tcp_close / tcp_abort. TX ring has 32 slots;
    // an undrained ring silently swallows further queued packets.
    void DrainTxRing(TcpConnTsi& c) {
        if (!c.handle) return;
        for (;;) {
            std::size_t written = 0;
            int32_t rc = tcp_extract_packet(c.handle.get(),
                                             extract_buf.data(),
                                             extract_buf.size(),
                                             &written);
            if (rc != 0 || written == 0) return;
            PushIpv4(extract_buf.data(), written);
        }
    }

    // M34.6 (rubber-duck rec #6): centralize abort accounting so the
    // aborts_ counter can't drift if a new abort site is added. Idempotent
    // (subsequent calls on the same conn are no-ops). Note: tcp_abort
    // queues a RST+ACK in the TX ring (no wire effect in LISTEN/SYN_SENT
    // per tcp_sans_io.h), transitions the TCB to CLOSED, and drops
    // buffered bytes. We triple-drain around it (rubber-duck #1).
    void AbortConn(TcpConnTsi& c, std::uint64_t now_ms, bool mark_closed) {
        if (c.tcp_abort_called || !c.handle) return;
        DrainTxRing(c);
        tcp_abort(c.handle.get(), now_ms);
        DrainTxRing(c);
        c.tcp_abort_called = true;
        aborts_.fetch_add(1, std::memory_order_relaxed);
        if (mark_closed) c.shim_state = TcpConnTsi::Shim::Closed;
    }

    // ----- Connection lifecycle -----------------------------------------

    // Begin a non-blocking Winsock connect() toward the real destination.
    bool BeginConnect(TcpConnTsi& c, std::uint64_t now_ms) {
        SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            std::fprintf(stderr,
                         "[usernet-tsi] socket() failed: %d\n",
                         ::WSAGetLastError());
            return false;
        }
        u_long nb = 1;
        if (::ioctlsocket(s, FIONBIO, &nb) == SOCKET_ERROR) {
            ::closesocket(s);
            return false;
        }
        BOOL nodelay = TRUE;
        ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        std::memcpy(&sa.sin_addr.s_addr, &c.key.dst_ip_be, 4);
        sa.sin_port = c.key.dst_port_be;
        int rc = ::connect(s, (sockaddr*)&sa, sizeof(sa));
        if (rc == SOCKET_ERROR) {
            int e = ::WSAGetLastError();
            if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS) {
                ::closesocket(s);
                return false;
            }
        }
        c.host_sock = s;
        c.shim_state = TcpConnTsi::Shim::Connecting;
        c.connect_deadline_ms = now_ms + ctx.connect_ms;
        c.last_activity_ms    = now_ms;
        c.idle_deadline_ms    = now_ms + ctx.idle_ms;
        return true;
    }

    // M34.5: pick an unused gateway-side ephem port (49152..65535) for
    // an inbound flow with the given (guest_ip, guest_port). Returns 0
    // if all 16384 candidates collide with existing conns (vanishingly
    // unlikely given max_conns ≤ 64 and the engine's own ephem space).
    // Returned value is in wire byte order (NBO).
    std::uint16_t AllocateInboundEphem(std::uint32_t guest_ip_be,
                                       std::uint16_t guest_port_be) {
        constexpr std::uint16_t kLow  = 49152;
        constexpr std::uint16_t kHigh = 65535;
        constexpr std::uint32_t kRange = kHigh - kLow + 1u;
        std::uint32_t start = 0;
        ::BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&start), sizeof(start),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        start %= kRange;
        for (std::uint32_t i = 0; i < kRange; ++i) {
            std::uint16_t cand_h = (std::uint16_t)(kLow + ((start + i) % kRange));
            std::uint16_t cand_be = ::htons(cand_h);
            ConnKey k{};
            k.guest_ip_be   = guest_ip_be;
            k.dst_ip_be     = ctx.gateway_ip_be;
            k.guest_port_be = guest_port_be;
            k.dst_port_be   = cand_be;
            if (conns.find(k) == conns.end()) return cand_be;
        }
        return 0;
    }

    // M34.5: adopt host_sock as the host side of an inbound flow.
    // host_sock must already be connected (accept() return) and is set
    // non-blocking + TCP_NODELAY here defensively. On success the
    // engine owns host_sock. Returns false on cap-exceeded / ephem
    // exhausted / TCB init failure.
    bool BeginInbound(SOCKET host_sock,
                       std::uint32_t guest_ip_be,
                       std::uint16_t guest_port_be,
                       std::uint64_t now_ms) {
        if (host_sock == INVALID_SOCKET) return false;
        if (conns.size() >= ctx.max_conns) return false;
        if (ctx.gateway_ip_be == 0)        return false;

        u_long nb = 1;
        if (::ioctlsocket(host_sock, FIONBIO, &nb) == SOCKET_ERROR) {
            return false;
        }
        BOOL nodelay = TRUE;
        ::setsockopt(host_sock, IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

        std::uint16_t ephem_be = AllocateInboundEphem(guest_ip_be,
                                                       guest_port_be);
        if (ephem_be == 0) return false;

        RawAlignedBuf raw = ::tinyvmm::net::AllocateTcbStorage();
        if (!raw) return false;

        // local = gateway:ephem (we play the active opener), remote =
        // guest:guest_port. ports in HOST order; IPs as 4 wire bytes.
        std::uint16_t local_port_h  = ntohs(ephem_be);
        std::uint16_t remote_port_h = ntohs(guest_port_be);
        std::uint32_t gw_ip_be = ctx.gateway_ip_be;
        int32_t rc = tcp_init(
            static_cast<TcpStreamHandle*>(raw.get()),
            reinterpret_cast<const std::uint8_t*>(&gw_ip_be),    local_port_h,
            reinterpret_cast<const std::uint8_t*>(&guest_ip_be), remote_port_h,
            RandomIss(), kInitialRtoMs);
        if (rc != 0) {
            // raw destructor frees memory; do NOT promote to TcbHandle.
            return false;
        }
        // tcp_init succeeded; promote ownership to TcbHandle (deleter
        // now combines tcp_destroy + _aligned_free).
        TcbHandle handle(static_cast<TcpStreamHandle*>(raw.release()));

        ConnKey key{};
        key.guest_ip_be   = guest_ip_be;
        key.dst_ip_be     = gw_ip_be;
        key.guest_port_be = guest_port_be;
        key.dst_port_be   = ephem_be;

        auto up = std::make_unique<TcpConnTsi>();
        up->key                  = key;
        up->handle               = std::move(handle);
        up->host_sock            = host_sock;
        up->is_inbound           = true;
        up->shim_state           = TcpConnTsi::Shim::Established;
        up->connect_deadline_ms  = now_ms + ctx.connect_ms;
        up->idle_deadline_ms     = now_ms + ctx.idle_ms;
        up->last_activity_ms     = now_ms;
        up->staging_to_host.reserve(kReadChunkCap);
        up->staging_to_tcb.reserve(kReadChunkCap);

        // Rubber-duck rec #4: insert into the conns map BEFORE draining
        // the SYN, so even if push_ipv4_to_guest ever becomes reentrant
        // (it currently isn't) a fast guest SYN-ACK can find the TCB by
        // 5-tuple instead of getting a spurious RST.
        TcpConnTsi& cref = *up;
        auto [it, ok] = conns.emplace(key, std::move(up));
        if (!ok) {
            // Should be unreachable (we just allocated a fresh ephem);
            // the moved-from `cref` will be deleted via its handle's
            // deleter when the unique_ptr falls out of scope.
            return false;
        }

        rc = tcp_connect(cref.handle.get(), now_ms);
        if (rc != 0) {
            // Active open failed (shouldn't happen on a freshly-init'd
            // TCB). Tear down via DestroyConn so the map invariant
            // stays intact, then drop the conn.
            DestroyConn(cref);
            conns.erase(it);
            return false;
        }
        DrainTxRing(cref);  // emits the SYN
        tcp_tick(cref.handle.get(), now_ms);
        DrainTxRing(cref);

        total_conns_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // ----- Pumps ---------------------------------------------------------

    // Drain TCB recv ring into staging_to_host, then if Established,
    // WSASend from staging_to_host. Rubber-duck #2: WSASend only when
    // Established. While Connecting we accept bytes but defer Send.
    void PumpTcbToHost(TcpConnTsi& c, std::uint64_t now_ms) {
        // Step 1: drain TCB → staging.
        while (c.staging_to_host.size() < kStagingCap) {
            const std::size_t room = kStagingCap - c.staging_to_host.size();
            std::size_t chunk = std::min(room, kReadChunkCap);
            std::uint8_t scratch[kReadChunkCap];
            std::size_t got = 0;
            int32_t rc = tcp_recv(c.handle.get(), scratch, chunk, &got);
            if (rc != 0 || got == 0) break;
            c.staging_to_host.insert(c.staging_to_host.end(),
                                      scratch, scratch + got);
            c.last_activity_ms = now_ms;
        }

        // Step 2: if Established, WSASend.
        if (c.shim_state != TcpConnTsi::Shim::Established) return;
        if (c.staging_to_host.empty())                     return;
        if (c.host_send_shut)                              return;

        WSABUF wb{};
        wb.buf = (CHAR*)c.staging_to_host.data();
        wb.len = (ULONG)c.staging_to_host.size();
        DWORD sent = 0;
        DWORD flags = 0;
        int rc = ::WSASend(c.host_sock, &wb, 1, &sent, flags, nullptr, nullptr);
        if (rc == SOCKET_ERROR) {
            int e = ::WSAGetLastError();
            if (e == WSAEWOULDBLOCK) return;  // try later
            // Fatal — abort the conn.
            AbortConn(c, now_ms, /*mark_closed=*/true);
            return;
        }
        if (sent > 0) {
            c.staging_to_host.erase(c.staging_to_host.begin(),
                                     c.staging_to_host.begin() + sent);
            c.last_activity_ms = now_ms;
        }
    }

    // WSARecv from host_sock, append to staging_to_tcb, then tcp_send.
    // Rubber-duck #2: gate WSARecv on Established (pre-connect WSARecv
    // returns WSAENOTCONN).
    void PumpHostToTcb(TcpConnTsi& c, std::uint64_t now_ms) {
        if (c.shim_state != TcpConnTsi::Shim::Established) return;

        // Step 1: WSARecv → staging_to_tcb.
        while (c.staging_to_tcb.size() < kStagingCap && !c.host_eof_seen) {
            const std::size_t room = kStagingCap - c.staging_to_tcb.size();
            std::size_t chunk = std::min(room, kReadChunkCap);
            std::uint8_t scratch[kReadChunkCap];
            WSABUF wb{};
            wb.buf = (CHAR*)scratch;
            wb.len = (ULONG)chunk;
            DWORD got = 0;
            DWORD flags = 0;
            int rc = ::WSARecv(c.host_sock, &wb, 1, &got, &flags,
                                nullptr, nullptr);
            if (rc == SOCKET_ERROR) {
                int e = ::WSAGetLastError();
                if (e == WSAEWOULDBLOCK) break;
                // Distinguish RST vs other -- treat WSAECONNRESET as abort.
                if (e == WSAECONNRESET || e == WSAECONNABORTED ||
                    e == WSAETIMEDOUT  || e == WSAENETRESET) {
                    AbortConn(c, now_ms, /*mark_closed=*/true);
                    return;
                }
                c.host_eof_seen = true;
                break;
            }
            if (got == 0) {
                // Graceful EOF from host.
                c.host_eof_seen = true;
                break;
            }
            c.staging_to_tcb.insert(c.staging_to_tcb.end(),
                                     scratch, scratch + got);
            c.last_activity_ms = now_ms;
        }

        // Step 2: drain staging_to_tcb → TCB via tcp_send.
        // Rubber-duck rec #2: tcp_send returns InvalidState while the TCB
        // is in SYN_SENT (inbound, awaiting guest SYN-ACK). Skip the loop
        // entirely until the TCB can actually accept bytes; staging holds
        // them, and host_sock backpressure shields the producer.
        const std::uint8_t tcb_st = tcp_state(c.handle.get());
        const bool tcb_can_send =
            (tcb_st == TCP_STATE_ESTABLISHED ||
             tcb_st == TCP_STATE_CLOSE_WAIT);
        while (tcb_can_send && !c.staging_to_tcb.empty()) {
            DrainTxRing(c);
            std::size_t sent = 0;
            int32_t rc = tcp_send(c.handle.get(),
                                   c.staging_to_tcb.data(),
                                   c.staging_to_tcb.size(),
                                   &sent);
            DrainTxRing(c);
            if (rc != 0 || sent == 0) break;
            c.staging_to_tcb.erase(c.staging_to_tcb.begin(),
                                    c.staging_to_tcb.begin() + sent);
            c.last_activity_ms = now_ms;
        }

        // Step 3: if host EOF + staging drained + no tcp_close yet,
        // close TCB so a FIN is sent toward the guest.
        // Rubber-duck rec #3: while TCB is SYN_SENT (inbound mid-handshake)
        // a tcp_close is a local no-op with no wire effect — the guest
        // would see only the original SYN and no follow-up. Defer the
        // close until the TCB establishes; if the guest never replies,
        // the handshake deadline will abort the conn anyway.
        if (c.host_eof_seen && c.staging_to_tcb.empty() &&
            !c.tcp_close_called && !c.tcp_abort_called) {
            if (tcb_can_send) {
                DrainTxRing(c);
                tcp_close(c.handle.get(), now_ms);
                DrainTxRing(c);
                c.tcp_close_called = true;
            } else {
                c.pending_close_after_established = true;
            }
        }
    }

    // Rubber-duck #3: when TCB reports PEER_CLOSED and we've flushed
    // bytes-to-host, shutdown(SD_SEND) so the remote sees EOF.
    void MaybeShutdownSend(TcpConnTsi& c) {
        if (c.host_send_shut) return;
        if (c.shim_state != TcpConnTsi::Shim::Established) return;
        if (c.host_sock == INVALID_SOCKET) return;
        if (!c.staging_to_host.empty()) return;
        std::uint32_t ev = tcp_poll(c.handle.get());
        if (!(ev & TCP_EV_PEER_CLOSED)) return;
        ::shutdown(c.host_sock, SD_SEND);
        c.host_send_shut = true;
    }

    // Handle pending connect() result by checking writability via WSAPoll.
    void HandleConnectComplete(TcpConnTsi& c, std::uint64_t now_ms) {
        if (c.shim_state != TcpConnTsi::Shim::Connecting) return;
        if (c.host_sock == INVALID_SOCKET) return;
        // Check via getsockopt SO_ERROR after WSAPoll signaled writable.
        int err = 0;
        int errlen = sizeof(err);
        ::getsockopt(c.host_sock, SOL_SOCKET, SO_ERROR,
                     reinterpret_cast<char*>(&err), &errlen);
        if (err != 0) {
            // Real connect failure (refused, unreachable, ...).
            // Abort the TCB; the guest gets a RST.
            AbortConn(c, now_ms, /*mark_closed=*/true);
            return;
        }
        c.shim_state = TcpConnTsi::Shim::Established;
        c.last_activity_ms = now_ms;
    }

    // Rubber-duck blind-spot #2: POLLHUP/POLLERR while Established.
    // Drain any pending recv, then either tcp_close (graceful EOF) or
    // tcp_abort (real error). This is invoked when WSAPoll reports
    // POLLHUP/POLLERR on host_sock.
    void HandleHostHupErr(TcpConnTsi& c, std::uint64_t now_ms) {
        if (c.shim_state == TcpConnTsi::Shim::Closed) return;
        // First, drain any data the kernel had queued before EOF/error.
        if (c.shim_state == TcpConnTsi::Shim::Established) {
            PumpHostToTcb(c, now_ms);
        }
        int err = 0;
        int errlen = sizeof(err);
        ::getsockopt(c.host_sock, SOL_SOCKET, SO_ERROR,
                     reinterpret_cast<char*>(&err), &errlen);
        const bool was_connecting =
            (c.shim_state == TcpConnTsi::Shim::Connecting);
        if (err == 0 && !was_connecting) {
            // Graceful close path: rely on PumpHostToTcb's EOF logic
            // to call tcp_close once staging drains.
            c.host_eof_seen = true;
            return;
        }
        // Error or pre-Established error: abort.
        AbortConn(c, now_ms, /*mark_closed=*/true);
    }

    // ----- Cleanup -------------------------------------------------------

    void DestroyConn(TcpConnTsi& c) {
        if (c.destroyed) return;
        if (c.host_sock != INVALID_SOCKET) {
            ::closesocket(c.host_sock);
            c.host_sock = INVALID_SOCKET;
        }
        // TcbHandle deleter calls tcp_destroy + _aligned_free in order.
        c.handle.reset();
        c.destroyed = true;
    }

    void DestroyAllInternal() {
        for (auto& [k, up] : conns) {
            if (up) DestroyConn(*up);
        }
        conns.clear();
    }

    // ----- Inject -------------------------------------------------------

    // Process one IPv4+TCP packet from the guest. The packet *is* the
    // full IP+TCP datagram (tcp_inject_packet's expected shape).
    void OnGuestPacket(std::uint64_t now_ms,
                        const std::uint8_t* ip_pkt, std::size_t ip_len) {
        if (ip_len < kIp4HdrMinSize + kTcpHdrMinSize) return;
        const std::uint8_t ihl_bytes = (std::uint8_t)((ip_pkt[0] & 0x0F) * 4);
        if (ihl_bytes < kIp4HdrMinSize || ihl_bytes >= ip_len) return;
        const std::uint16_t total_len = Be16(ip_pkt + 2);
        if (total_len < ihl_bytes || total_len > ip_len) return;

        std::uint32_t src_ip_be = 0, dst_ip_be = 0;
        std::memcpy(&src_ip_be, ip_pkt + 12, 4);
        std::memcpy(&dst_ip_be, ip_pkt + 16, 4);
        const std::uint8_t* tcp = ip_pkt + ihl_bytes;
        const std::size_t   tcp_len = (std::size_t)total_len - ihl_bytes;
        if (tcp_len < kTcpHdrMinSize) return;

        std::uint16_t src_port_be = 0, dst_port_be = 0;
        std::memcpy(&src_port_be, tcp + 0, 2);
        std::memcpy(&dst_port_be, tcp + 2, 2);
        std::uint32_t seq = Be32(tcp + 4);
        std::uint32_t ack = Be32(tcp + 8);
        const std::uint8_t data_off_bytes = (std::uint8_t)((tcp[12] >> 4) * 4);
        if (data_off_bytes < kTcpHdrMinSize || data_off_bytes > tcp_len) return;
        const std::uint8_t flags = tcp[13];
        const std::size_t  payload_len = tcp_len - data_off_bytes;
        const bool has_syn = (flags & kTcpSyn) != 0;
        const bool has_fin = (flags & kTcpFin) != 0;
        const bool has_ack = (flags & kTcpAck) != 0;
        const bool has_rst = (flags & kTcpRst) != 0;

        // M34.6: count valid TCP segments accepted by the engine
        // (header parsing succeeded). Bumped before lookup so segments
        // that result in synthetic RSTs (no-TCB, capped, late-after-
        // Closed) still count as engine input.
        segments_rx_.fetch_add(1, std::memory_order_relaxed);

        ConnKey key{};
        key.guest_ip_be   = src_ip_be;
        key.dst_ip_be     = dst_ip_be;
        key.guest_port_be = src_port_be;
        key.dst_port_be   = dst_port_be;

        // Reap any destroyed CLOSED slot for this key first so SYN can
        // reuse the 5-tuple after a previous flow tore down.
        if (auto it = conns.find(key); it != conns.end()) {
            auto& cref = *it->second;
            if (cref.shim_state == TcpConnTsi::Shim::Closed &&
                cref.destroyed == false &&
                tcp_state(cref.handle.get()) == TCP_STATE_CLOSED) {
                DestroyConn(cref);
                conns.erase(it);
            }
        }

        auto it = conns.find(key);
        if (it == conns.end()) {
            // No TCB for this 5-tuple.
            if (has_rst) {
                // Drop -- nothing to do.
                return;
            }
            if (!has_syn) {
                // Rubber-duck rec H: emit a calibrated RST.
                // Without TCB: if incoming has ACK, RST seq=ack no-ACK;
                // else RST|ACK with ack = seq + seg_len_in_seq_space.
                if (has_ack) {
                    EmitSyntheticRst(dst_ip_be, src_ip_be,
                                      dst_port_be, src_port_be,
                                      /*seq=*/ack, /*ack=*/0,
                                      /*ack_valid=*/false);
                } else {
                    std::uint32_t seg_len =
                        (std::uint32_t)payload_len +
                        (has_syn ? 1u : 0u) +
                        (has_fin ? 1u : 0u);
                    EmitSyntheticRst(dst_ip_be, src_ip_be,
                                      dst_port_be, src_port_be,
                                      /*seq=*/0, /*ack=*/seq + seg_len,
                                      /*ack_valid=*/true);
                }
                return;
            }

            // It's a SYN. Cap check.
            if (conns.size() >= ctx.max_conns) {
                EmitSyntheticRst(dst_ip_be, src_ip_be,
                                  dst_port_be, src_port_be,
                                  /*seq=*/0, /*ack=*/seq + 1,
                                  /*ack_valid=*/true);
                return;
            }

            // Allocate TCB. local = dst (we play destination role),
            // remote = guest. Ports are host-order u16; IP pointers are
            // 4 wire bytes.
            RawAlignedBuf raw = ::tinyvmm::net::AllocateTcbStorage();
            if (!raw) return;

            std::uint16_t local_port_h  = ntohs(dst_port_be);
            std::uint16_t remote_port_h = ntohs(src_port_be);
            int32_t rc = tcp_init(
                static_cast<TcpStreamHandle*>(raw.get()),
                reinterpret_cast<const std::uint8_t*>(&dst_ip_be), local_port_h,
                reinterpret_cast<const std::uint8_t*>(&src_ip_be), remote_port_h,
                RandomIss(), kInitialRtoMs);
            if (rc != 0) {
                // raw destructor frees memory; no tcp_destroy needed
                // (init failed -> nothing to destroy).
                return;
            }
            // Promote to TcbHandle (deleter = tcp_destroy + _aligned_free).
            TcbHandle handle(static_cast<TcpStreamHandle*>(raw.release()));

            rc = tcp_listen(handle.get(), now_ms);
            if (rc != 0) {
                // handle deleter handles teardown of the just-init'd TCB.
                return;
            }

            auto up = std::make_unique<TcpConnTsi>();
            up->key = key;
            up->handle = std::move(handle);
            up->last_activity_ms = now_ms;
            up->idle_deadline_ms = now_ms + ctx.idle_ms;
            up->staging_to_host.reserve(kReadChunkCap);
            up->staging_to_tcb.reserve(kReadChunkCap);

            TcpConnTsi& c = *up;

            // Begin host-side connect to the real destination.
            if (!BeginConnect(c, now_ms)) {
                // Couldn't even create the socket -- abort TCB and
                // emit a RST so the guest moves on quickly.
                DestroyConn(c);
                EmitSyntheticRst(dst_ip_be, src_ip_be,
                                  dst_port_be, src_port_be,
                                  /*seq=*/0, /*ack=*/seq + 1,
                                  /*ack_valid=*/true);
                return;
            }

            // Inject the SYN -- the TCB will queue a SYN-ACK in its TX
            // ring. Triple-drain pattern.
            DrainTxRing(c);
            tcp_inject_packet(c.handle.get(), ip_pkt, ip_len, now_ms);
            DrainTxRing(c);
            tcp_tick(c.handle.get(), now_ms);
            DrainTxRing(c);

            total_conns_.fetch_add(1, std::memory_order_relaxed);
            conns.emplace(key, std::move(up));
            return;
        }

        // Existing TCB.
        TcpConnTsi& c = *it->second;
        if (c.destroyed || c.shim_state == TcpConnTsi::Shim::Closed) {
            // Late guest packet after we already tore down. RST it.
            if (!has_rst) {
                if (has_ack) {
                    EmitSyntheticRst(dst_ip_be, src_ip_be,
                                      dst_port_be, src_port_be,
                                      /*seq=*/ack, /*ack=*/0,
                                      /*ack_valid=*/false);
                } else {
                    std::uint32_t seg_len =
                        (std::uint32_t)payload_len +
                        (has_syn ? 1u : 0u) +
                        (has_fin ? 1u : 0u);
                    EmitSyntheticRst(dst_ip_be, src_ip_be,
                                      dst_port_be, src_port_be,
                                      /*seq=*/0, /*ack=*/seq + seg_len,
                                      /*ack_valid=*/true);
                }
            }
            return;
        }

        // Rubber-duck #1: triple-drain around inject.
        DrainTxRing(c);
        tcp_inject_packet(c.handle.get(), ip_pkt, ip_len, now_ms);
        DrainTxRing(c);
        tcp_tick(c.handle.get(), now_ms);
        DrainTxRing(c);

        c.last_activity_ms = now_ms;
        c.idle_deadline_ms = now_ms + ctx.idle_ms;

        // Pump host side -- new data may now be in the TCB's recv ring
        // (drain → staging_to_host → WSASend if Established).
        PumpTcbToHost(c, now_ms);
        MaybeShutdownSend(c);
    }
};

// ============================================================================
// TsiTcpEngine public methods
// ============================================================================

TsiTcpEngine::TsiTcpEngine(EmitCtx ctx)
    : impl_(std::make_unique<Impl>(std::move(ctx))) {}

TsiTcpEngine::~TsiTcpEngine() = default;

void TsiTcpEngine::OnGuestTcpPacket(std::uint64_t now_ms,
                                     const std::uint8_t* ip_pkt,
                                     std::size_t         ip_len) {
    if (!impl_) return;
    impl_->OnGuestPacket(now_ms, ip_pkt, ip_len);
}

bool TsiTcpEngine::StartInboundConn(SOCKET host_sock,
                                     std::uint32_t guest_ip_be,
                                     std::uint16_t guest_port_be) {
    if (!impl_) return false;
    return impl_->BeginInbound(host_sock, guest_ip_be, guest_port_be,
                                impl_->ctx.now_ms());
}

void TsiTcpEngine::Tick(std::uint64_t now_ms) {
    if (!impl_) return;

    // Build a WSAPoll fd set for all live host sockets.
    std::vector<WSAPOLLFD> fds;
    std::vector<TcpConnTsi*> ptrs;
    fds.reserve(impl_->conns.size());
    ptrs.reserve(impl_->conns.size());
    for (auto& [k, up] : impl_->conns) {
        TcpConnTsi& c = *up;
        if (c.destroyed)                                continue;
        if (c.shim_state == TcpConnTsi::Shim::Closed)   continue;
        if (c.host_sock == INVALID_SOCKET)              continue;

        WSAPOLLFD f{};
        f.fd = c.host_sock;
        f.events = 0;
        if (c.shim_state == TcpConnTsi::Shim::Connecting) {
            // Pending connect signals via writable.
            f.events |= POLLWRNORM;
        } else if (c.shim_state == TcpConnTsi::Shim::Established) {
            if (!c.host_eof_seen) f.events |= POLLRDNORM;
            if (!c.staging_to_host.empty() && !c.host_send_shut)
                f.events |= POLLWRNORM;
        }
        fds.push_back(f);
        ptrs.push_back(&c);
    }

    if (!fds.empty()) {
        int pr = ::WSAPoll(fds.data(), (ULONG)fds.size(), 0);
        (void)pr;  // 0 = no events, -1 = error (we still proceed).
    }

    // React to events.
    for (std::size_t i = 0; i < fds.size(); ++i) {
        TcpConnTsi& c = *ptrs[i];
        const short rev = fds[i].revents;
        if (rev == 0) continue;
        if (c.shim_state == TcpConnTsi::Shim::Connecting) {
            if (rev & (POLLWRNORM | POLLERR | POLLHUP)) {
                impl_->HandleConnectComplete(c, now_ms);
            }
        }
        if (c.shim_state == TcpConnTsi::Shim::Established) {
            if (rev & (POLLRDNORM | POLLHUP)) {
                impl_->PumpHostToTcb(c, now_ms);
            }
            if (rev & POLLWRNORM) {
                impl_->PumpTcbToHost(c, now_ms);
            }
        }
        if (rev & (POLLERR | POLLHUP) &&
            c.shim_state != TcpConnTsi::Shim::Closed) {
            impl_->HandleHostHupErr(c, now_ms);
        }
    }

    // Tick / pump every connection.
    std::vector<ConnKey> to_remove;
    for (auto& [k, up] : impl_->conns) {
        TcpConnTsi& c = *up;
        if (c.destroyed) { to_remove.push_back(k); continue; }

        if (c.shim_state == TcpConnTsi::Shim::Connecting) {
            if (now_ms >= c.connect_deadline_ms) {
                impl_->AbortConn(c, now_ms, /*mark_closed=*/true);
            }
        }

        // M34.5: inbound TCB-handshake watchdog. Distinct from the
        // outbound shim-connect deadline above. Once the inbound TCB
        // first reaches ESTABLISHED or CLOSE_WAIT we latch
        // inbound_handshake_done so subsequent state transitions
        // (FIN_WAIT_*, CLOSING, TIME_WAIT, ...) don't trigger an
        // unwanted abort. (Rubber-duck blocking #1.)
        if (c.is_inbound && !c.inbound_handshake_done && c.handle &&
            c.shim_state != TcpConnTsi::Shim::Closed) {
            const std::uint8_t st = tcp_state(c.handle.get());
            if (st == TCP_STATE_ESTABLISHED || st == TCP_STATE_CLOSE_WAIT) {
                c.inbound_handshake_done = true;
                c.connect_deadline_ms    = 0;
                // Rubber-duck rec #3 follow-up: if the host already
                // closed during the handshake, fire the deferred
                // tcp_close now that the TCB can carry it.
                if (c.pending_close_after_established &&
                    !c.tcp_close_called && !c.tcp_abort_called) {
                    impl_->DrainTxRing(c);
                    tcp_close(c.handle.get(), now_ms);
                    impl_->DrainTxRing(c);
                    c.tcp_close_called = true;
                    c.pending_close_after_established = false;
                }
            } else if (st == TCP_STATE_CLOSED) {
                // Guest sent RST or the TCB aborted itself; reap.
                c.shim_state = TcpConnTsi::Shim::Closed;
            } else if (now_ms >= c.connect_deadline_ms) {
                impl_->AbortConn(c, now_ms, /*mark_closed=*/true);
            }
        }

        // M34.6: half-close watchdog. Once the TCB enters any half-
        // closed state, abort if no engine-side activity (TX or RX) has
        // occurred for half_close_ms. Activity-based (rubber-duck rec
        // #3) so legitimate long-running streams in CLOSE_WAIT aren't
        // truncated, and a peer that keeps ACKing our retransmits in
        // FIN_WAIT_1 also won't be aborted unfairly. Includes CLOSING
        // (rubber-duck rec #4) so both-sides-FIN-but-our-FIN-not-yet-
        // ACKed can't stall forever.
        if (c.handle && c.shim_state != TcpConnTsi::Shim::Closed &&
            !c.tcp_abort_called) {
            const std::uint8_t st = tcp_state(c.handle.get());
            const bool half_closed =
                (st == TCP_STATE_FIN_WAIT_1 || st == TCP_STATE_FIN_WAIT_2 ||
                 st == TCP_STATE_CLOSE_WAIT || st == TCP_STATE_CLOSING  ||
                 st == TCP_STATE_LAST_ACK);
            if (half_closed &&
                now_ms >= c.last_activity_ms + impl_->ctx.half_close_ms) {
                impl_->AbortConn(c, now_ms, /*mark_closed=*/true);
            }
        }

        // Idle reap (only when not actively connecting or mid-inbound-
        // handshake).
        const bool mid_inbound_handshake =
            (c.is_inbound && !c.inbound_handshake_done);
        if (c.shim_state != TcpConnTsi::Shim::Connecting &&
            !mid_inbound_handshake &&
            !c.tcp_close_called && !c.tcp_abort_called) {
            if (now_ms >= c.idle_deadline_ms) {
                impl_->AbortConn(c, now_ms, /*mark_closed=*/true);
            }
        }

        // Standard pumps for Established.
        if (c.shim_state == TcpConnTsi::Shim::Established) {
            impl_->PumpTcbToHost(c, now_ms);
            impl_->PumpHostToTcb(c, now_ms);
            impl_->MaybeShutdownSend(c);
        }

        // Standard housekeeping tick on the TCB itself (retransmits etc).
        if (c.handle) {
            impl_->DrainTxRing(c);
            tcp_tick(c.handle.get(), now_ms);
            impl_->DrainTxRing(c);
        }

        // M34.6 (rubber-duck blocking #2): reconcile shim_state with
        // the TCB. A graceful close (host-EOF → FIN → peer FIN-ACK →
        // ACK → TIME_WAIT → CLOSED) reaches TCP_STATE_CLOSED without
        // any abort path running, so without this block the conn would
        // never be reaped from the map. Bump graceful_closes only on
        // the first transition (i.e. shim wasn't already Closed AND no
        // abort fired) so the counter tracks "non-abort completions".
        if (c.handle && c.shim_state != TcpConnTsi::Shim::Closed &&
            tcp_state(c.handle.get()) == TCP_STATE_CLOSED) {
            c.shim_state = TcpConnTsi::Shim::Closed;
            if (!c.tcp_abort_called) {
                impl_->graceful_closes_.fetch_add(
                    1, std::memory_order_relaxed);
            }
        }

        // Reap CLOSED TCBs.
        if (c.shim_state == TcpConnTsi::Shim::Closed && c.handle &&
            tcp_state(c.handle.get()) == TCP_STATE_CLOSED) {
            impl_->DestroyConn(c);
            to_remove.push_back(k);
        }
    }
    for (auto& k : to_remove) impl_->conns.erase(k);
}

void TsiTcpEngine::Shutdown() {
    if (!impl_) return;
    impl_->DestroyAllInternal();
}

std::size_t TsiTcpEngine::conn_count() const noexcept {
    return impl_ ? impl_->conns.size() : 0;
}
std::uint64_t TsiTcpEngine::total_conns() const noexcept {
    return impl_ ? impl_->total_conns_.load() : 0;
}
std::uint64_t TsiTcpEngine::rsts_sent() const noexcept {
    return impl_ ? impl_->rsts_sent_.load() : 0;
}
std::uint64_t TsiTcpEngine::segments_rx() const noexcept {
    return impl_ ? impl_->segments_rx_.load() : 0;
}
std::uint64_t TsiTcpEngine::segments_tx() const noexcept {
    return impl_ ? impl_->segments_tx_.load() : 0;
}
std::uint64_t TsiTcpEngine::aborts() const noexcept {
    return impl_ ? impl_->aborts_.load() : 0;
}
std::uint64_t TsiTcpEngine::graceful_closes() const noexcept {
    return impl_ ? impl_->graceful_closes_.load() : 0;
}

}  // namespace tinyvmm::virtio
