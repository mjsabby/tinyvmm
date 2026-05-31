#include "net_usernet.h"
#include "net_usernet_tsi.h"

#include "virtio_pci.h"
#include "net_l2.h"

#include "diag/etw.h"
#include "net/wintun_loader.h"  // net::FormatWindowsError

#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <mstcpip.h>
#include <mswsock.h>  // SIO_UDP_CONNRESET

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace tinyvmm::virtio {

namespace {

// ---- Pull only TYPES + chain helpers from net_l2 ----
using ::tinyvmm::virtio::net_l2::kVirtioNetHdrSize;
using ::tinyvmm::virtio::net_l2::kEthHdrSize;
using ::tinyvmm::virtio::net_l2::kEthTypeIp4;
using ::tinyvmm::virtio::net_l2::kEthTypeArp;
using ::tinyvmm::virtio::net_l2::kArpHardwareEth;
using ::tinyvmm::virtio::net_l2::kArpOpRequest;
using ::tinyvmm::virtio::net_l2::kArpOpReply;
using ::tinyvmm::virtio::net_l2::EthHeader;
using ::tinyvmm::virtio::net_l2::ArpIpv4;
using ::tinyvmm::virtio::net_l2::Be16;
using ::tinyvmm::virtio::net_l2::Wr16Be;
using ::tinyvmm::virtio::net_l2::Be32;
using ::tinyvmm::virtio::net_l2::Wr32Be;
using ::tinyvmm::virtio::net_l2::ReadableSummary;
using ::tinyvmm::virtio::net_l2::SummarizeReadable;
using ::tinyvmm::virtio::net_l2::CopyReadable;

constexpr std::size_t   kIp4HdrMinSize    = 20;
constexpr std::size_t   kUdpHdrSize       = 8;
constexpr std::size_t   kIcmpHdrSize      = 8;
constexpr std::uint16_t kIpv4Mtu          = 1500;
constexpr std::size_t   kPendingRxCap     = 4096;
constexpr std::uint8_t  kIpProtoIcmp = 1;
constexpr std::uint8_t  kIpProtoTcp  = 6;
constexpr std::uint8_t  kIpProtoUdp  = 17;
constexpr std::uint8_t  kIcmpEchoRequest = 8;
constexpr std::uint8_t  kIcmpEchoReply   = 0;

// ---- Terse span adapters for raw-pointer call sites.
// Packet parsing operates on `const uint8_t* + offset`. These adapters
// produce fixed-extent spans so the canonical span-based net_l2 helpers
// (Be16/Wr16Be/Be32/Wr32Be) can be used at every call site without
// re-introducing raw-pointer big-endian primitives.
constexpr std::span<const std::uint8_t, 2> S2(const std::uint8_t* p) {
    return std::span<const std::uint8_t, 2>{p, 2};
}
constexpr std::span<std::uint8_t, 2> S2(std::uint8_t* p) {
    return std::span<std::uint8_t, 2>{p, 2};
}

// ---- Internet checksum (RFC 1071) ----
inline std::uint32_t InetCksumAccum(const std::uint8_t* p, std::size_t n,
                                     std::uint32_t initial = 0) {
    std::uint32_t s = initial;
    while (n >= 2) {
        s += (std::uint32_t{p[0]} << 8) | p[1];
        p += 2;
        n -= 2;
    }
    if (n) s += std::uint32_t{p[0]} << 8;
    return s;
}
inline std::uint16_t InetCksumFold(std::uint32_t s) {
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return static_cast<std::uint16_t>(~s);
}
inline std::uint16_t InetCksum(const std::uint8_t* p, std::size_t n,
                                std::uint32_t initial = 0) {
    return InetCksumFold(InetCksumAccum(p, n, initial));
}

// Sum the 12-byte IPv4 TCP/UDP pseudo-header (un-folded).
inline std::uint32_t PseudoHdrSum(std::uint32_t src_ip_be,
                                   std::uint32_t dst_ip_be,
                                   std::uint8_t  proto,
                                   std::uint16_t l4_len) {
    std::uint8_t ph[12]{};
    std::memcpy(ph + 0, &src_ip_be, 4);
    std::memcpy(ph + 4, &dst_ip_be, 4);
    ph[8]  = 0;
    ph[9]  = proto;
    Wr16Be(S2(ph + 10), l4_len);
    return InetCksumAccum(ph, sizeof(ph), 0);
}

inline bool SetNonBlocking(SOCKET s) {
    u_long nb = 1;
    return ::ioctlsocket(s, FIONBIO, &nb) == 0;
}

// ---- Connection 4-tuple (network byte order) ----
struct ConnKey {
    std::uint32_t guest_ip_be   = 0;
    std::uint32_t dst_ip_be     = 0;
    std::uint16_t guest_port_be = 0;
    std::uint16_t dst_port_be   = 0;

    bool operator==(const ConnKey& o) const noexcept {
        return guest_ip_be == o.guest_ip_be &&
               dst_ip_be   == o.dst_ip_be   &&
               guest_port_be == o.guest_port_be &&
               dst_port_be == o.dst_port_be;
    }
};
struct ConnKeyHash {
    std::size_t operator()(const ConnKey& k) const noexcept {
        std::uint64_t h = k.guest_ip_be;
        h = (h * 1099511628211ull) ^ k.dst_ip_be;
        h = (h * 1099511628211ull) ^ k.guest_port_be;
        h = (h * 1099511628211ull) ^ k.dst_port_be;
        return static_cast<std::size_t>(h ^ (h >> 32));
    }
};

// ---- UDP per-tuple session ----
struct UdpConn {
    SOCKET sock = INVALID_SOCKET;
    std::chrono::steady_clock::time_point last_use{};
    ConnKey key{};
};

// ---- TCP per-connection state was here; moved to TsiTcpEngine (M34.8). ----

// ---- ICMP echo work item ----
struct IcmpRequest {
    std::uint32_t guest_ip_be = 0;
    std::uint32_t dst_ip_be   = 0;
    std::uint16_t identifier  = 0;
    std::uint16_t sequence    = 0;
    std::vector<std::uint8_t> payload;
};

struct IcmpReply {
    std::uint32_t guest_ip_be = 0;
    std::uint32_t src_ip_be   = 0;
    std::uint16_t identifier  = 0;
    std::uint16_t sequence    = 0;
    std::vector<std::uint8_t> payload;
};

// ---- One L2 frame queued for delivery to the guest's RX virtq ----
struct PendingRx {
    std::vector<std::uint8_t> bytes;
};

}  // namespace

// ============================================================
// UsernetBackend::State
// ============================================================
struct UsernetBackend::State {
    NetDevice& net;
    UsernetBackend::Options opts;

    PciTransport* xport = nullptr;
    whp::Partition* part = nullptr;

    HANDLE stop_evt    = nullptr;
    HANDLE tx_doorbell = nullptr;
    HANDLE rx_doorbell = nullptr;

    std::thread worker;
    std::atomic<bool> running{false};

    bool ready = false;
    bool wsa_started = false;

    std::uint32_t gateway_ip_be = 0;
    std::array<std::uint8_t, 6> guest_mac{};
    bool guest_mac_learned = false;

    std::deque<PendingRx> pending_rx;

    std::unordered_map<ConnKey, UdpConn, ConnKeyHash> udp_conns;

    // Inbound port-forward listeners (1:1 with opts.port_forwards after
    // Start; entries whose bind() failed are recorded as INVALID_SOCKET so
    // indices stay aligned with port_forwards for diagnostic purposes,
    // but a separate listeners_active list holds only valid sockets).
    struct Listener {
        SOCKET sock = INVALID_SOCKET;
        UsernetBackend::PortForward rule{};
    };
    std::vector<Listener> listeners;

    // M34.8: TSI (tcp-sans-io) TCP engine. Always constructed in
    // Start(); the legacy hand-rolled C++ TCP state machine was deleted
    // in M34.8 along with the --net-usernet-tcp runtime switch.
    std::unique_ptr<TsiTcpEngine> tsi_engine;

    std::atomic<std::uint16_t> ip_id_counter{1};

    // ICMP worker pool: synchronous IcmpSendEcho2 per worker.
    std::deque<IcmpRequest> icmp_pending;
    std::mutex icmp_pending_mu;
    HANDLE icmp_wake = nullptr;          // manual-reset; reset under mutex

    std::deque<IcmpReply> icmp_replies;
    std::mutex icmp_replies_mu;
    HANDLE icmp_reply_evt = nullptr;     // auto-reset; signaled by workers

    std::vector<std::thread> icmp_workers;
    std::atomic<std::uint32_t> icmp_inflight{0};

    // Counters.
    std::atomic<std::uint64_t> tx_packets{0};
    std::atomic<std::uint64_t> rx_packets{0};
    std::atomic<std::uint64_t> tx_dropped{0};
    std::atomic<std::uint64_t> rx_dropped{0};
    std::atomic<std::uint64_t> arp_replies{0};
    std::atomic<std::uint64_t> udp_conns_total{0};
    std::atomic<std::uint64_t> icmp_echoes_total{0};

    explicit State(NetDevice& n, const UsernetBackend::Options& o)
        : net(n), opts(o) {}

    // ---- Lifecycle ----
    void Start(whp::Partition& p, PciTransport& t);
    void Stop();

    // ---- Worker ----
    void WorkerLoop();
    void DrainGuestTx();
    void DrainHostSockets();
    void ExpireIdle();
    void DeliverPendingRx();

    // ---- L2/L3 dispatch ----
    void HandleArpFromGuest(std::span<const std::uint8_t> eth_frame);
    void HandleIpFromGuest(const std::uint8_t* ip_pkt, std::size_t ip_len);

    // ---- UDP ----
    void HandleUdpFromGuest(std::uint32_t src_ip_be, std::uint32_t dst_ip_be,
                            const std::uint8_t* udp, std::size_t udp_len);
    SOCKET UdpCreate(std::uint32_t dst_ip_be, std::uint16_t dst_port_be);
    void PumpUdpSocket(UdpConn& c);
    void EmitUdpDatagramToGuest(std::uint32_t src_ip_be, std::uint16_t src_port_be,
                                std::uint32_t dst_ip_be, std::uint16_t dst_port_be,
                                const std::uint8_t* payload, std::size_t n);

    // ---- ICMP ----
    void HandleIcmpFromGuest(std::uint32_t src_ip_be, std::uint32_t dst_ip_be,
                             const std::uint8_t* icmp, std::size_t icmp_len);
    void IcmpWorkerLoop();
    void PumpIcmpReplies();
    void EmitIcmpEchoReplyToGuest(std::uint32_t src_ip_be, std::uint32_t dst_ip_be,
                                   std::uint16_t id, std::uint16_t seq,
                                   const std::uint8_t* payload, std::size_t n);

    // ---- TCP terminates inside TsiTcpEngine (M34.8); no methods here. ----

    // ---- Inbound port-forward ----
    void StartListeners();
    void StopListeners();
    void AcceptOnListener(Listener& L);
    static void AbortiveCloseSocket(SOCKET& s);

    // M34.4: monotonic clock in milliseconds. TsiTcpEngine uses this
    // for tcp_inject_packet/tcp_tick deadlines.
    std::uint64_t NowMs() const {
        using namespace std::chrono;
        return (std::uint64_t)duration_cast<milliseconds>(
            steady_clock::now().time_since_epoch()).count();
    }

    // ---- Frame synthesis ----
    void PushPendingRx(std::vector<std::uint8_t> frame);
    std::vector<std::uint8_t> BuildArpReplyFrame(const ArpIpv4& req) const;
    void EmitIpv4(std::uint32_t src_ip_be, std::uint32_t dst_ip_be,
                  std::uint8_t proto,
                  const std::uint8_t* l4, std::size_t l4_len);
};

// ============================================================
// UsernetBackend public methods
// ============================================================
UsernetBackend::UsernetBackend(NetDevice& net, const Options& opts)
    : state_(std::make_unique<State>(net, opts)) {}

UsernetBackend::~UsernetBackend() {
    Stop();
}

void UsernetBackend::Start(whp::Partition& partition,
                            PciTransport& transport) {
    state_->Start(partition, transport);
}

void UsernetBackend::Stop() {
    if (state_) state_->Stop();
}

void UsernetBackend::OnQueueNotify(std::uint32_t /*qidx*/) {
    // Doorbells suppress these in steady state. WFMO timeout (5ms)
    // sweeps anything that slips through.
}

bool UsernetBackend::ready() const noexcept {
    return state_ && state_->ready;
}

std::uint64_t UsernetBackend::tx_packets() const noexcept {
    return state_ ? state_->tx_packets.load() : 0;
}
std::uint64_t UsernetBackend::rx_packets() const noexcept {
    return state_ ? state_->rx_packets.load() : 0;
}
std::uint64_t UsernetBackend::tx_dropped() const noexcept {
    return state_ ? state_->tx_dropped.load() : 0;
}
std::uint64_t UsernetBackend::rx_dropped() const noexcept {
    return state_ ? state_->rx_dropped.load() : 0;
}
std::uint64_t UsernetBackend::arp_replies() const noexcept {
    return state_ ? state_->arp_replies.load() : 0;
}
std::uint64_t UsernetBackend::tcp_conns_total() const noexcept {
    return (state_ && state_->tsi_engine)
        ? state_->tsi_engine->total_conns() : 0;
}
std::uint64_t UsernetBackend::udp_conns_total() const noexcept {
    return state_ ? state_->udp_conns_total.load() : 0;
}
std::uint64_t UsernetBackend::icmp_echoes_total() const noexcept {
    return state_ ? state_->icmp_echoes_total.load() : 0;
}

// ============================================================
// State::Start / Stop
// ============================================================
void UsernetBackend::State::Start(whp::Partition& p, PciTransport& t) {
    part = &p;
    xport = &t;

    WSADATA wsa{};
    int wrc = ::WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wrc != 0) {
        std::fprintf(stderr, "[usernet] WSAStartup failed: %d\n", wrc);
        return;
    }
    wsa_started = true;

    IN_ADDR ga{};
    if (::InetPtonA(AF_INET, opts.gateway_ipv4.c_str(), &ga) != 1) {
        std::fprintf(stderr, "[usernet] invalid gateway_ipv4=%s\n",
                     opts.gateway_ipv4.c_str());
        ::WSACleanup();
        wsa_started = false;
        return;
    }
    gateway_ip_be = ga.s_addr;
    guest_mac = net.mac();
    // Mark the guest MAC as known up-front (we pinned it via virtio config).
    // Otherwise EmitIpv4 silently drops inbound frames issued before the
    // guest has transmitted its first ARP -- breaking inbound port forward
    // SYNs that may race the guest's first TX.
    guest_mac_learned = true;

    stop_evt        = ::CreateEventW(nullptr, /*manual*/TRUE,  FALSE, nullptr);
    icmp_wake       = ::CreateEventW(nullptr, /*manual*/TRUE,  FALSE, nullptr);
    icmp_reply_evt  = ::CreateEventW(nullptr, /*manual*/FALSE, FALSE, nullptr);
    if (!stop_evt || !icmp_wake || !icmp_reply_evt) {
        std::fprintf(stderr, "[usernet] CreateEvent failed: %s\n",
                     net::FormatWindowsError(::GetLastError()).c_str());
        if (stop_evt)       ::CloseHandle(stop_evt), stop_evt = nullptr;
        if (icmp_wake)      ::CloseHandle(icmp_wake), icmp_wake = nullptr;
        if (icmp_reply_evt) ::CloseHandle(icmp_reply_evt), icmp_reply_evt = nullptr;
        ::WSACleanup();
        wsa_started = false;
        return;
    }

    tx_doorbell = t.InstallQueueDoorbell(p, kTxQueueIdx);
    rx_doorbell = t.InstallQueueDoorbell(p, kRxQueueIdx);

    running.store(true);
    ready = true;

    StartListeners();

    worker = std::thread([this] { WorkerLoop(); });

    // Spin up a small ICMP worker pool. Each worker drains one
    // request from icmp_pending and blocks on IcmpSendEcho2.
    const std::uint32_t nworkers = std::min<std::uint32_t>(4, opts.max_icmp_inflight);
    icmp_workers.reserve(nworkers);
    for (std::uint32_t i = 0; i < nworkers; ++i) {
        icmp_workers.emplace_back([this] { IcmpWorkerLoop(); });
    }

    // M34.8: TSI (tcp-sans-io) is the only TCP engine. Construct it
    // unconditionally; the legacy runtime switch and C++ state machine
    // were deleted along with --net-usernet-tcp.
    {
        TsiTcpEngine::EmitCtx ec{};
        // Emit a fully-built IPv4+TCP datagram from the TCB to the guest.
        // Just prepend a 14-byte Ethernet header and queue on pending_rx.
        // Do NOT call EmitIpv4 (that would add a second IP header);
        // tcp-sans-io's tcp_extract_packet already produced a valid
        // IPv4+TCP datagram with both checksums computed.
        ec.push_ipv4_to_guest =
            [this](const std::uint8_t* ip, std::size_t n) {
                if (!guest_mac_learned) return;
                if (n > kIpv4Mtu)       return;
                std::vector<std::uint8_t> frame(kEthHdrSize + n);
                std::memcpy(frame.data() + 0, guest_mac.data(),         6);
                std::memcpy(frame.data() + 6, opts.backend_mac.data(),  6);
                frame[12] = 0x08;
                frame[13] = 0x00;
                std::memcpy(frame.data() + kEthHdrSize, ip, n);
                PushPendingRx(std::move(frame));
            };
        ec.now_ms        = [this]{ return NowMs(); };
        ec.backend_mac   = opts.backend_mac;
        ec.guest_mac     = guest_mac;
        ec.gateway_ip_be = gateway_ip_be;
        // 2.18 MiB per TCB -> cap aggressively for v1. opts.max_tcp_conns
        // (1024 default) is the user-visible knob; the TSI engine should
        // not aim for that scale until snapshot/resume + per-conn
        // accounting are in place.
        ec.max_conns     = std::min<std::size_t>(opts.max_tcp_conns, 64);
        // M34.6: 10-min idle (spec), 30-s half-close watchdog.
        ec.idle_ms       = 10ull * 60ull * 1000ull;
        ec.connect_ms    = 10ull * 1000ull;
        ec.half_close_ms = 30ull * 1000ull;
        tsi_engine       = std::make_unique<TsiTcpEngine>(std::move(ec));
    }

    std::printf("[usernet] up: gateway=%s mtu=%u tcp_engine=tcp-sans-io\n",
                opts.gateway_ipv4.c_str(),
                static_cast<unsigned>(kIpv4Mtu));
    TINYVMM_ETW_INFO_KW("NetBackendStart", ::tinyvmm::diag::kw::Lifecycle,
        TraceLoggingString("usernet",                 "backend"),
        TraceLoggingString(opts.gateway_ipv4.c_str(), "gateway"),
        TraceLoggingString("tcp-sans-io",             "tcp_engine"));
}

void UsernetBackend::State::Stop() {
    TINYVMM_ETW_INFO_KW("NetBackendStop", ::tinyvmm::diag::kw::Lifecycle,
        TraceLoggingString("usernet", "backend"),
        TraceLoggingUInt64(tx_packets.load(), "tx_packets"),
        TraceLoggingUInt64(rx_packets.load(), "rx_packets"),
        TraceLoggingUInt64(tx_dropped.load(), "tx_dropped"),
        TraceLoggingUInt64(rx_dropped.load(), "rx_dropped"));

    if (running.exchange(false)) {
        if (stop_evt)   ::SetEvent(stop_evt);
        if (icmp_wake)  ::SetEvent(icmp_wake);
        if (worker.joinable()) worker.join();
        for (auto& th : icmp_workers) {
            if (th.joinable()) th.join();
        }
        icmp_workers.clear();
    } else {
        if (worker.joinable()) worker.join();
    }

    for (auto& [k, c] : udp_conns) {
        if (c.sock != INVALID_SOCKET) ::closesocket(c.sock);
    }
    udp_conns.clear();
    StopListeners();
    if (tsi_engine) {
        // M34.6 (rubber-duck blocking #1): worker thread has already
        // been joined above, so reading tsi_engine internal counters
        // here is race-free. Emit a summary ETW event before tearing
        // down the engine. conn_count() reads `conns.size()` which is
        // NOT atomic, so this MUST happen after the worker.join().
        TINYVMM_ETW_INFO_KW("NetTsiSummary", ::tinyvmm::diag::kw::Lifecycle,
            TraceLoggingString("usernet",                       "backend"),
            TraceLoggingUInt64(tsi_engine->total_conns(),       "total_conns"),
            TraceLoggingUInt64(static_cast<std::uint64_t>(
                                  tsi_engine->conn_count()),    "live_at_stop"),
            TraceLoggingUInt64(tsi_engine->segments_rx(),       "segments_rx"),
            TraceLoggingUInt64(tsi_engine->segments_tx(),       "segments_tx"),
            TraceLoggingUInt64(tsi_engine->aborts(),            "aborts"),
            TraceLoggingUInt64(tsi_engine->graceful_closes(),   "graceful_closes"),
            TraceLoggingUInt64(tsi_engine->rsts_sent(),         "rsts_sent"));
        std::printf(
            "[usernet-tsi] summary: total=%llu live=%zu seg_rx=%llu seg_tx=%llu "
            "aborts=%llu graceful=%llu rsts=%llu | usernet tx_pkts=%llu "
            "rx_pkts=%llu tx_drop=%llu rx_drop=%llu\n",
            (unsigned long long)tsi_engine->total_conns(),
            tsi_engine->conn_count(),
            (unsigned long long)tsi_engine->segments_rx(),
            (unsigned long long)tsi_engine->segments_tx(),
            (unsigned long long)tsi_engine->aborts(),
            (unsigned long long)tsi_engine->graceful_closes(),
            (unsigned long long)tsi_engine->rsts_sent(),
            (unsigned long long)tx_packets.load(),
            (unsigned long long)rx_packets.load(),
            (unsigned long long)tx_dropped.load(),
            (unsigned long long)rx_dropped.load());
        tsi_engine->Shutdown();
        tsi_engine.reset();
    }
    pending_rx.clear();

    if (stop_evt)        { ::CloseHandle(stop_evt);       stop_evt = nullptr; }
    if (icmp_wake)       { ::CloseHandle(icmp_wake);      icmp_wake = nullptr; }
    if (icmp_reply_evt)  { ::CloseHandle(icmp_reply_evt); icmp_reply_evt = nullptr; }

    if (wsa_started) {
        ::WSACleanup();
        wsa_started = false;
    }
    xport = nullptr;
    part = nullptr;
    ready = false;
}

// ============================================================
// State::WorkerLoop
// ============================================================
void UsernetBackend::State::WorkerLoop() {
    HANDLE waits[4] = { stop_evt, tx_doorbell, rx_doorbell, icmp_reply_evt };
    while (running.load()) {
        DWORD wr = ::WaitForMultipleObjectsEx(4, waits, FALSE, 5, FALSE);
        if (wr == WAIT_OBJECT_0) break;

        DrainGuestTx();
        DrainHostSockets();
        tsi_engine->Tick(NowMs());
        PumpIcmpReplies();
        ExpireIdle();
        DeliverPendingRx();
    }
}

// ============================================================
// State::DrainGuestTx
// ============================================================
void UsernetBackend::State::DrainGuestTx() {
    auto& tx = net.tx_queue();
    if (!tx.ready()) return;

    bool any = false;
    while (auto chain = tx.Pop()) {
        const auto summary = SummarizeReadable(*chain, std::span<std::uint8_t>{});
        tx.Push(chain->head_index, 0);
        any = true;

        const std::size_t kMinFrame = kVirtioNetHdrSize + kEthHdrSize;
        if (summary.total < kMinFrame) {
            tx_dropped.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const std::size_t eth_total = summary.total - kVirtioNetHdrSize;
        if (eth_total > kIpv4Mtu + kEthHdrSize) {
            tx_dropped.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        std::vector<std::uint8_t> frame(eth_total);
        std::size_t got = CopyReadable(*chain, kVirtioNetHdrSize, frame);
        if (got != eth_total) {
            tx_dropped.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        EthHeader eh{};
        std::memcpy(&eh, frame.data(), sizeof(eh));
        if (!guest_mac_learned) {
            std::memcpy(guest_mac.data(), eh.src, 6);
            guest_mac_learned = true;
        }
        const std::uint16_t etype = Be16(S2(eh.ether_type_be));
        TINYVMM_ETW_VERBOSE_KW("NetTx", ::tinyvmm::diag::kw::Net,
            TraceLoggingString("usernet",                                "backend"),
            TraceLoggingUInt32(static_cast<std::uint32_t>(eth_total),     "bytes"),
            TraceLoggingUInt16(etype,                                     "ethertype"));

        if (etype == kEthTypeArp) {
            HandleArpFromGuest(frame);
        } else if (etype == kEthTypeIp4) {
            if (eth_total > kEthHdrSize) {
                HandleIpFromGuest(frame.data() + kEthHdrSize,
                                  eth_total - kEthHdrSize);
            }
        } else {
            tx_dropped.fetch_add(1, std::memory_order_relaxed);
        }
        tx_packets.fetch_add(1, std::memory_order_relaxed);
    }
    if (any && xport) xport->RaiseQueueInterrupt(kTxQueueIdx);
}

// ============================================================
// State::HandleArpFromGuest
// ============================================================
void UsernetBackend::State::HandleArpFromGuest(
        std::span<const std::uint8_t> eth_frame) {
    if (eth_frame.size() < kEthHdrSize + sizeof(ArpIpv4)) return;
    ArpIpv4 req{};
    std::memcpy(&req, eth_frame.data() + kEthHdrSize, sizeof(req));

    if (Be16(S2(req.htype_be)) != kArpHardwareEth) return;
    if (Be16(S2(req.ptype_be)) != kEthTypeIp4) return;
    if (req.hlen != 6 || req.plen != 4) return;
    if (Be16(S2(req.opcode_be)) != kArpOpRequest) return;

    std::uint32_t tpa_be = 0;
    std::memcpy(&tpa_be, req.tpa, 4);
    if (tpa_be != gateway_ip_be) return;

    if (pending_rx.size() >= kPendingRxCap) {
        rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    PushPendingRx(BuildArpReplyFrame(req));
    arp_replies.fetch_add(1, std::memory_order_relaxed);
}

std::vector<std::uint8_t>
UsernetBackend::State::BuildArpReplyFrame(const ArpIpv4& req) const {
    std::vector<std::uint8_t> frame(kEthHdrSize + sizeof(ArpIpv4));
    EthHeader eh{};
    std::memcpy(eh.dst, req.sha, 6);
    std::memcpy(eh.src, opts.backend_mac.data(), 6);
    Wr16Be(S2(eh.ether_type_be), kEthTypeArp);
    std::memcpy(frame.data(), &eh, sizeof(eh));

    ArpIpv4 rep{};
    Wr16Be(S2(rep.htype_be), kArpHardwareEth);
    Wr16Be(S2(rep.ptype_be), kEthTypeIp4);
    rep.hlen = 6;
    rep.plen = 4;
    Wr16Be(S2(rep.opcode_be), kArpOpReply);
    std::memcpy(rep.sha, opts.backend_mac.data(), 6);
    std::memcpy(rep.spa, &gateway_ip_be, 4);
    std::memcpy(rep.tha, req.sha, 6);
    std::memcpy(rep.tpa, req.spa, 4);
    std::memcpy(frame.data() + kEthHdrSize, &rep, sizeof(rep));
    return frame;
}

// ============================================================
// State::HandleIpFromGuest
// ============================================================
void UsernetBackend::State::HandleIpFromGuest(const std::uint8_t* ip,
                                                std::size_t ip_len) {
    if (ip_len < kIp4HdrMinSize) return;
    const std::uint8_t vihl = ip[0];
    if ((vihl >> 4) != 4) return;
    const std::size_t ihl_bytes = (vihl & 0x0F) * 4u;
    if (ihl_bytes < kIp4HdrMinSize || ihl_bytes > ip_len) return;

    const std::uint16_t total_len  = Be16(S2(ip + 2));
    if (total_len > ip_len || total_len < ihl_bytes) return;

    const std::uint16_t flags_frag = Be16(S2(ip + 6));
    if ((flags_frag & 0x1FFF) != 0 || (flags_frag & 0x2000)) {
        tx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    const std::uint8_t proto = ip[9];
    std::uint32_t src_ip_be = 0, dst_ip_be = 0;
    std::memcpy(&src_ip_be, ip + 12, 4);
    std::memcpy(&dst_ip_be, ip + 16, 4);

    if (InetCksum(ip, ihl_bytes) != 0) {
        tx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    const std::uint8_t* l4     = ip + ihl_bytes;
    const std::size_t   l4_len = total_len - ihl_bytes;

    switch (proto) {
    case kIpProtoUdp:
        HandleUdpFromGuest(src_ip_be, dst_ip_be, l4, l4_len);
        break;
    case kIpProtoTcp:
        tsi_engine->OnGuestTcpPacket(NowMs(), ip, total_len);
        break;
    case kIpProtoIcmp:
        HandleIcmpFromGuest(src_ip_be, dst_ip_be, l4, l4_len);
        break;
    default:
        tx_dropped.fetch_add(1, std::memory_order_relaxed);
        break;
    }
}

// ============================================================
// State::PushPendingRx / EmitIpv4 / DeliverPendingRx
// ============================================================
void UsernetBackend::State::PushPendingRx(std::vector<std::uint8_t> frame) {
    if (pending_rx.size() >= kPendingRxCap) {
        rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    PendingRx p;
    p.bytes = std::move(frame);
    pending_rx.push_back(std::move(p));
}

void UsernetBackend::State::EmitIpv4(std::uint32_t src_ip_be,
                                       std::uint32_t dst_ip_be,
                                       std::uint8_t proto,
                                       const std::uint8_t* l4,
                                       std::size_t l4_len) {
    if (!guest_mac_learned) return;
    const std::size_t total_ip = kIp4HdrMinSize + l4_len;
    if (total_ip > kIpv4Mtu) return;

    std::vector<std::uint8_t> frame(kEthHdrSize + total_ip);

    EthHeader eh{};
    std::memcpy(eh.dst, guest_mac.data(),         6);
    std::memcpy(eh.src, opts.backend_mac.data(),  6);
    Wr16Be(S2(eh.ether_type_be), kEthTypeIp4);
    std::memcpy(frame.data(), &eh, sizeof(eh));

    std::uint8_t* ip = frame.data() + kEthHdrSize;
    ip[0] = 0x45;
    ip[1] = 0x00;
    Wr16Be(S2(ip + 2), static_cast<std::uint16_t>(total_ip));
    Wr16Be(S2(ip + 4), ip_id_counter.fetch_add(1, std::memory_order_relaxed));
    Wr16Be(S2(ip + 6), 0x4000);   // DF, no frag
    ip[8] = 64;               // TTL
    ip[9] = proto;
    Wr16Be(S2(ip + 10), 0);
    std::memcpy(ip + 12, &src_ip_be, 4);
    std::memcpy(ip + 16, &dst_ip_be, 4);
    Wr16Be(S2(ip + 10), InetCksum(ip, kIp4HdrMinSize));

    std::memcpy(ip + kIp4HdrMinSize, l4, l4_len);
    PushPendingRx(std::move(frame));
}

void UsernetBackend::State::DeliverPendingRx() {
    auto& rx = net.rx_queue();
    if (!rx.ready()) return;

    bool any = false;
    while (!pending_rx.empty()) {
        auto chain = rx.Pop();
        if (!chain) break;

        auto& entry = pending_rx.front();
        std::size_t hdr_remaining = kVirtioNetHdrSize;
        std::size_t pkt_off = 0;
        std::uint32_t total = 0;

        for (auto& b : chain->bufs) {
            if (!b.write) continue;
            std::span<std::uint8_t> dst = b.bytes;
            if (hdr_remaining > 0 && !dst.empty()) {
                const std::size_t take = std::min(dst.size(), hdr_remaining);
                std::memset(dst.data(), 0, take);
                dst = dst.subspan(take);
                hdr_remaining -= take;
                total += static_cast<std::uint32_t>(take);
            }
            if (!dst.empty() && pkt_off < entry.bytes.size()) {
                const std::size_t take = std::min(
                    dst.size(), entry.bytes.size() - pkt_off);
                std::memcpy(dst.data(), entry.bytes.data() + pkt_off, take);
                pkt_off += take;
                total += static_cast<std::uint32_t>(take);
            }
            if (hdr_remaining == 0 && pkt_off == entry.bytes.size()) break;
        }
        const bool truncated = (pkt_off < entry.bytes.size())
                            || (hdr_remaining > 0);
        if (truncated) {
            rx_dropped.fetch_add(1, std::memory_order_relaxed);
        } else {
            rx_packets.fetch_add(1, std::memory_order_relaxed);
        }
        TINYVMM_ETW_VERBOSE_KW("NetRx", ::tinyvmm::diag::kw::Net,
            TraceLoggingString("usernet",                  "backend"),
            TraceLoggingUInt32(total,                       "bytes"),
            TraceLoggingUInt8(truncated ? 1u : 0u,          "truncated"));
        rx.Push(chain->head_index, total);
        pending_rx.pop_front();
        any = true;
    }
    if (any && xport) xport->RaiseQueueInterrupt(kRxQueueIdx);
}

// ============================================================
// Phase B: UDP
// ============================================================
SOCKET UsernetBackend::State::UdpCreate(std::uint32_t dst_ip_be,
                                          std::uint16_t dst_port_be) {
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    // CRITICAL: disable connection-reset semantics on UDP sockets,
    // otherwise Windows surfaces ICMP-port-unreachable from the
    // last sendto() as WSAECONNRESET on the next recv().
    BOOL behavior = FALSE;
    DWORD bytes = 0;
    if (::WSAIoctl(s, SIO_UDP_CONNRESET, &behavior, sizeof(behavior),
                    nullptr, 0, &bytes, nullptr, nullptr) == SOCKET_ERROR) {
        // Not fatal; just log.
        TINYVMM_ETW_WARN_KW("UsernetUdpConnReset", ::tinyvmm::diag::kw::Net,
            TraceLoggingInt32(::WSAGetLastError(), "err"));
    }
    if (!SetNonBlocking(s)) {
        ::closesocket(s);
        return INVALID_SOCKET;
    }
    // connect() ties the socket to the (dst_ip, dst_port) tuple; subsequent
    // send()/recv() do not need the address. Keeps the per-conn fast path tight.
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = dst_port_be;
    sa.sin_addr.s_addr = dst_ip_be;
    if (::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR) {
        const int err = ::WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != 0) {
            ::closesocket(s);
            return INVALID_SOCKET;
        }
    }
    return s;
}

void UsernetBackend::State::HandleUdpFromGuest(std::uint32_t src_ip_be,
                                                 std::uint32_t dst_ip_be,
                                                 const std::uint8_t* udp,
                                                 std::size_t udp_len) {
    if (udp_len < kUdpHdrSize) return;
    const std::uint16_t src_port_be = *reinterpret_cast<const std::uint16_t*>(udp);
    const std::uint16_t dst_port_be = *reinterpret_cast<const std::uint16_t*>(udp + 2);
    const std::uint16_t length      = Be16(S2(udp + 4));
    if (length < kUdpHdrSize || length > udp_len) return;

    const std::uint16_t cksum = Be16(S2(udp + 6));
    if (cksum != 0) {
        std::uint32_t s = PseudoHdrSum(src_ip_be, dst_ip_be, kIpProtoUdp, length);
        if (InetCksum(udp, length, s) != 0) {
            tx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }
    if (length > udp_len) return;
    const std::uint8_t* payload = udp + kUdpHdrSize;
    const std::size_t   payload_len = length - kUdpHdrSize;

    ConnKey key{src_ip_be, dst_ip_be, src_port_be, dst_port_be};
    auto it = udp_conns.find(key);
    if (it == udp_conns.end()) {
        if (udp_conns.size() >= opts.max_udp_conns) {
            tx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        SOCKET s = UdpCreate(dst_ip_be, dst_port_be);
        if (s == INVALID_SOCKET) {
            tx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        UdpConn c;
        c.sock = s;
        c.key  = key;
        c.last_use = std::chrono::steady_clock::now();
        it = udp_conns.emplace(key, std::move(c)).first;
        udp_conns_total.fetch_add(1, std::memory_order_relaxed);
    }
    it->second.last_use = std::chrono::steady_clock::now();
    // send() ? non-blocking; ENOBUFS / WSAEWOULDBLOCK both drop silently.
    int sent = ::send(it->second.sock,
                       reinterpret_cast<const char*>(payload),
                       static_cast<int>(payload_len), 0);
    if (sent == SOCKET_ERROR) {
        tx_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}

void UsernetBackend::State::PumpUdpSocket(UdpConn& c) {
    // Drain everything readable on this socket.
    std::uint8_t buf[64 * 1024];
    for (;;) {
        int n = ::recv(c.sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n == SOCKET_ERROR) {
            int e = ::WSAGetLastError();
            if (e != WSAEWOULDBLOCK) {
                // After SIO_UDP_CONNRESET=FALSE this should only happen on
                // socket teardown; let the next ExpireIdle / Stop close it.
            }
            return;
        }
        if (n <= 0) return;
        c.last_use = std::chrono::steady_clock::now();
        EmitUdpDatagramToGuest(c.key.dst_ip_be, c.key.dst_port_be,
                                c.key.guest_ip_be, c.key.guest_port_be,
                                buf, static_cast<std::size_t>(n));
    }
}

void UsernetBackend::State::EmitUdpDatagramToGuest(
        std::uint32_t src_ip_be, std::uint16_t src_port_be,
        std::uint32_t dst_ip_be, std::uint16_t dst_port_be,
        const std::uint8_t* payload, std::size_t n) {
    if (n + kUdpHdrSize + kIp4HdrMinSize > kIpv4Mtu) {
        // Drop oversized; we don't fragment.
        rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const std::uint16_t udp_len = static_cast<std::uint16_t>(kUdpHdrSize + n);
    std::vector<std::uint8_t> udp(udp_len);
    std::memcpy(udp.data() + 0, &src_port_be, 2);
    std::memcpy(udp.data() + 2, &dst_port_be, 2);
    Wr16Be(S2(udp.data() + 4), udp_len);
    Wr16Be(S2(udp.data() + 6), 0);
    std::memcpy(udp.data() + 8, payload, n);

    std::uint32_t ph = PseudoHdrSum(src_ip_be, dst_ip_be, kIpProtoUdp, udp_len);
    std::uint16_t sum = InetCksum(udp.data(), udp_len, ph);
    if (sum == 0) sum = 0xFFFF;   // RFC 768: 0 means "checksum disabled"
    Wr16Be(S2(udp.data() + 6), sum);

    EmitIpv4(src_ip_be, dst_ip_be, kIpProtoUdp, udp.data(), udp_len);
}

// ============================================================
// Phase C: ICMP
// ============================================================
void UsernetBackend::State::HandleIcmpFromGuest(std::uint32_t src_ip_be,
                                                  std::uint32_t dst_ip_be,
                                                  const std::uint8_t* icmp,
                                                  std::size_t icmp_len) {
    if (icmp_len < kIcmpHdrSize) return;
    if (InetCksum(icmp, icmp_len) != 0) {
        tx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const std::uint8_t type = icmp[0];
    if (type != kIcmpEchoRequest) {
        tx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const std::uint16_t id  = Be16(S2(icmp + 4));
    const std::uint16_t seq = Be16(S2(icmp + 6));
    const std::uint8_t* payload = icmp + kIcmpHdrSize;
    const std::size_t   payload_len = icmp_len - kIcmpHdrSize;

    // Pinging the gateway: answer locally.
    if (dst_ip_be == gateway_ip_be) {
        EmitIcmpEchoReplyToGuest(gateway_ip_be, src_ip_be, id, seq,
                                  payload, payload_len);
        icmp_echoes_total.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Cap in-flight ICMP work to opts.max_icmp_inflight.
    if (icmp_inflight.load() >= opts.max_icmp_inflight) {
        tx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    IcmpRequest req;
    req.guest_ip_be = src_ip_be;
    req.dst_ip_be   = dst_ip_be;
    req.identifier  = id;
    req.sequence    = seq;
    req.payload.assign(payload, payload + payload_len);

    {
        std::lock_guard<std::mutex> lk(icmp_pending_mu);
        icmp_pending.push_back(std::move(req));
    }
    icmp_inflight.fetch_add(1, std::memory_order_relaxed);
    ::SetEvent(icmp_wake);
}

void UsernetBackend::State::IcmpWorkerLoop() {
    HANDLE handle = ::IcmpCreateFile();
    if (handle == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "[usernet] IcmpCreateFile failed: %lu\n",
                     ::GetLastError());
        return;
    }

    constexpr DWORD kReplyBufSize = 1500;
    std::vector<std::uint8_t> reply_buf(kReplyBufSize);

    while (running.load()) {
        std::optional<IcmpRequest> req;
        {
            std::lock_guard<std::mutex> lk(icmp_pending_mu);
            if (!icmp_pending.empty()) {
                req = std::move(icmp_pending.front());
                icmp_pending.pop_front();
            } else {
                ::ResetEvent(icmp_wake);
            }
        }
        if (!req) {
            // Re-check after reset to avoid a lost-wakeup race.
            bool empty_now = false;
            {
                std::lock_guard<std::mutex> lk(icmp_pending_mu);
                empty_now = icmp_pending.empty();
            }
            if (empty_now) {
                ::WaitForSingleObject(icmp_wake, INFINITE);
            }
            continue;
        }

        IPAddr dest = static_cast<IPAddr>(req->dst_ip_be);
        DWORD got = ::IcmpSendEcho2(
            handle,
            /*event*/ nullptr,
            /*apcRoutine*/ nullptr,
            /*apcContext*/ nullptr,
            dest,
            req->payload.empty() ? nullptr : req->payload.data(),
            static_cast<WORD>(req->payload.size()),
            /*RequestOptions*/ nullptr,
            reply_buf.data(),
            static_cast<DWORD>(reply_buf.size()),
            /*Timeout*/ 4000);

        if (got > 0) {
            const ICMP_ECHO_REPLY* r =
                reinterpret_cast<const ICMP_ECHO_REPLY*>(reply_buf.data());
            if (r->Status == IP_SUCCESS) {
                IcmpReply rep;
                rep.guest_ip_be = req->guest_ip_be;
                rep.src_ip_be   = static_cast<std::uint32_t>(r->Address);
                rep.identifier  = req->identifier;
                rep.sequence    = req->sequence;
                const auto sz = static_cast<std::size_t>(r->DataSize);
                rep.payload.assign(
                    static_cast<const std::uint8_t*>(r->Data),
                    static_cast<const std::uint8_t*>(r->Data) + sz);
                {
                    std::lock_guard<std::mutex> lk(icmp_replies_mu);
                    icmp_replies.push_back(std::move(rep));
                }
                ::SetEvent(icmp_reply_evt);
            }
        }
        icmp_inflight.fetch_sub(1, std::memory_order_relaxed);
    }
    ::IcmpCloseHandle(handle);
}

void UsernetBackend::State::PumpIcmpReplies() {
    for (;;) {
        std::optional<IcmpReply> rep;
        {
            std::lock_guard<std::mutex> lk(icmp_replies_mu);
            if (icmp_replies.empty()) break;
            rep = std::move(icmp_replies.front());
            icmp_replies.pop_front();
        }
        EmitIcmpEchoReplyToGuest(rep->src_ip_be, rep->guest_ip_be,
                                  rep->identifier, rep->sequence,
                                  rep->payload.data(), rep->payload.size());
        icmp_echoes_total.fetch_add(1, std::memory_order_relaxed);
    }
}

void UsernetBackend::State::EmitIcmpEchoReplyToGuest(
        std::uint32_t src_ip_be, std::uint32_t dst_ip_be,
        std::uint16_t id, std::uint16_t seq,
        const std::uint8_t* payload, std::size_t n) {
    const std::size_t total = kIcmpHdrSize + n;
    if (total + kIp4HdrMinSize > kIpv4Mtu) {
        rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    std::vector<std::uint8_t> icmp(total);
    icmp[0] = kIcmpEchoReply;
    icmp[1] = 0;
    Wr16Be(S2(icmp.data() + 2), 0);
    Wr16Be(S2(icmp.data() + 4), id);
    Wr16Be(S2(icmp.data() + 6), seq);
    if (n) std::memcpy(icmp.data() + kIcmpHdrSize, payload, n);
    Wr16Be(S2(icmp.data() + 2), InetCksum(icmp.data(), total));
    EmitIpv4(src_ip_be, dst_ip_be, kIpProtoIcmp, icmp.data(), total);
}


// ============================================================
// State::AbortiveCloseSocket
// ============================================================
// SO_LINGER {l_onoff=1, l_linger=0} forces RST instead of FIN on
// closesocket(). Used for inbound port-forward flows so the host
// client observes a real reset when the guest tears down, instead of
// blocking in graceful-close half-open silence.
void UsernetBackend::State::AbortiveCloseSocket(SOCKET& s) {
    if (s == INVALID_SOCKET) return;
    struct linger lg{};
    lg.l_onoff  = 1;
    lg.l_linger = 0;
    ::setsockopt(s, SOL_SOCKET, SO_LINGER,
                  reinterpret_cast<const char*>(&lg), sizeof(lg));
    ::closesocket(s);
    s = INVALID_SOCKET;
}

// ============================================================
// State::StartListeners / StopListeners
// ============================================================
void UsernetBackend::State::StartListeners() {
    listeners.clear();
    listeners.reserve(opts.port_forwards.size());
    for (const auto& rule : opts.port_forwards) {
        Listener L{};
        L.rule = rule;
        SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            std::fprintf(stderr,
                "[usernet] portfwd: socket() failed for host port %u: %d\n",
                static_cast<unsigned>(rule.host_port), ::WSAGetLastError());
            listeners.push_back(L);
            continue;
        }
        // SO_EXCLUSIVEADDRUSE (Windows-specific) prevents two callers from
        // claiming the same {addr, port} silently and lets us fail loudly
        // if the host port is already in use. Do NOT use SO_REUSEADDR on
        // Windows -- its semantics are different from BSD and would mask
        // collisions.
        BOOL excl = TRUE;
        ::setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                      reinterpret_cast<const char*>(&excl), sizeof(excl));
        if (!SetNonBlocking(s)) {
            ::closesocket(s);
            std::fprintf(stderr,
                "[usernet] portfwd: ioctlsocket(FIONBIO) failed for host "
                "port %u: %d\n",
                static_cast<unsigned>(rule.host_port), ::WSAGetLastError());
            listeners.push_back(L);
            continue;
        }
        sockaddr_in sa{};
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = rule.host_addr_be;
        sa.sin_port        = ::htons(rule.host_port);
        if (::bind(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa))
            == SOCKET_ERROR) {
            int e = ::WSAGetLastError();
            ::closesocket(s);
            in_addr ha{}; ha.s_addr = rule.host_addr_be;
            char buf[INET_ADDRSTRLEN] = {};
            ::InetNtopA(AF_INET, &ha, buf, sizeof(buf));
            std::fprintf(stderr,
                "[usernet] portfwd: bind(%s:%u) failed: %d\n",
                buf, static_cast<unsigned>(rule.host_port), e);
            listeners.push_back(L);
            continue;
        }
        if (::listen(s, SOMAXCONN) == SOCKET_ERROR) {
            int e = ::WSAGetLastError();
            ::closesocket(s);
            std::fprintf(stderr,
                "[usernet] portfwd: listen() failed for host port %u: %d\n",
                static_cast<unsigned>(rule.host_port), e);
            listeners.push_back(L);
            continue;
        }
        L.sock = s;
        listeners.push_back(L);

        in_addr ha{}; ha.s_addr = rule.host_addr_be;
        in_addr ga{}; ga.s_addr = rule.guest_ip_be;
        char hbuf[INET_ADDRSTRLEN] = {};
        char gbuf[INET_ADDRSTRLEN] = {};
        ::InetNtopA(AF_INET, &ha, hbuf, sizeof(hbuf));
        ::InetNtopA(AF_INET, &ga, gbuf, sizeof(gbuf));
        std::printf("[usernet] portfwd: %s:%u -> guest %s:%u\n",
                    hbuf, static_cast<unsigned>(rule.host_port),
                    gbuf, static_cast<unsigned>(rule.guest_port));
    }
}

void UsernetBackend::State::StopListeners() {
    for (auto& L : listeners) {
        if (L.sock != INVALID_SOCKET) {
            ::closesocket(L.sock);
            L.sock = INVALID_SOCKET;
        }
    }
    listeners.clear();
}

// ============================================================
// State::AcceptOnListener
// ============================================================
void UsernetBackend::State::AcceptOnListener(Listener& L) {
    if (L.sock == INVALID_SOCKET) return;
    // Cap accepts per cycle so one busy listener can't starve the rest
    // of the worker loop (UDP, ICMP, TSI tick) on a SYN flood.
    constexpr int kAcceptBurstCap = 16;
    for (int i = 0; i < kAcceptBurstCap; ++i) {
        sockaddr_in peer{};
        int peer_len = sizeof(peer);
        SOCKET s = ::accept(L.sock, reinterpret_cast<sockaddr*>(&peer),
                             &peer_len);
        if (s == INVALID_SOCKET) {
            int e = ::WSAGetLastError();
            (void)e;  // WSAEWOULDBLOCK is normal: ring is drained.
            return;
        }
        // M34.5 + M34.8: hand the host_sock off to the TSI engine. If
        // the engine refuses (cap-exceeded, gateway_ip_be==0, etc.),
        // abortive-close so the client observes RST instead of half-
        // open silence.
        const std::uint16_t guest_port_be = ::htons(L.rule.guest_port);
        if (!tsi_engine->StartInboundConn(s, L.rule.guest_ip_be,
                                            guest_port_be)) {
            AbortiveCloseSocket(s);
        }
    }
}

// ============================================================
// State::DrainHostSockets
// ============================================================
void UsernetBackend::State::DrainHostSockets() {
    // Count active listeners up front; they always need POLLRDNORM and
    // are independent of the udp conn map. (Without this, an otherwise-
    // idle backend that only has port-forward listeners installed would
    // never poll them.)
    //
    // M34.8: TCP host sockets are owned by TsiTcpEngine, which runs its
    // own WSAPoll on them in Tick(). This routine handles only UDP and
    // listener-accept polling now.
    std::size_t active_listeners = 0;
    for (const auto& L : listeners) {
        if (L.sock != INVALID_SOCKET) ++active_listeners;
    }
    if (udp_conns.empty() && active_listeners == 0) return;

    std::vector<WSAPOLLFD> fds;
    fds.reserve(udp_conns.size() + active_listeners);

    enum class SlotKind : std::uint8_t { Udp, Listener };
    struct Slot { SlotKind kind; ConnKey key; std::size_t listener_idx; };
    std::vector<Slot> slots;
    slots.reserve(fds.capacity());

    for (auto& [k, c] : udp_conns) {
        WSAPOLLFD f{};
        f.fd = c.sock;
        f.events = POLLRDNORM;
        fds.push_back(f);
        slots.push_back({SlotKind::Udp, k, 0});
    }
    for (std::size_t i = 0; i < listeners.size(); ++i) {
        if (listeners[i].sock == INVALID_SOCKET) continue;
        WSAPOLLFD f{};
        f.fd = listeners[i].sock;
        f.events = POLLRDNORM;
        fds.push_back(f);
        slots.push_back({SlotKind::Listener, ConnKey{}, i});
    }
    if (fds.empty()) return;

    int rc = ::WSAPoll(fds.data(), static_cast<ULONG>(fds.size()), 0);
    if (rc <= 0) return;

    for (std::size_t i = 0; i < fds.size(); ++i) {
        const SHORT rev = fds[i].revents;
        if (rev == 0) continue;
        const Slot& slot = slots[i];
        if (slot.kind == SlotKind::Listener) {
            if (rev & (POLLRDNORM | POLLERR | POLLHUP)) {
                AcceptOnListener(listeners[slot.listener_idx]);
            }
            continue;
        }
        // SlotKind::Udp
        auto it = udp_conns.find(slot.key);
        if (it == udp_conns.end()) continue;
        if (rev & (POLLRDNORM | POLLERR | POLLHUP)) {
            PumpUdpSocket(it->second);
        }
    }
}

// ============================================================
// State::ExpireIdle
// ============================================================
void UsernetBackend::State::ExpireIdle() {
    // M34.8: TCP conn lifecycle is owned by TsiTcpEngine (idle reap +
    // half-close watchdog + shim reconcile). Only UDP needs sweeping
    // here.
    const auto now = std::chrono::steady_clock::now();
    const auto udp_timeout = std::chrono::milliseconds(opts.udp_idle_ms);
    for (auto it = udp_conns.begin(); it != udp_conns.end(); ) {
        if (now - it->second.last_use > udp_timeout) {
            if (it->second.sock != INVALID_SOCKET) ::closesocket(it->second.sock);
            it = udp_conns.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace tinyvmm::virtio
