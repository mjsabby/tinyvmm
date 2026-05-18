#include "net_usernet.h"

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
#include <random>
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
constexpr std::size_t   kTcpHdrMinSize    = 20;
constexpr std::size_t   kUdpHdrSize       = 8;
constexpr std::size_t   kIcmpHdrSize      = 8;
constexpr std::uint16_t kIpv4Mtu          = 1500;
constexpr std::uint16_t kAdvertisedMss    = 1460;
constexpr std::uint8_t  kAdvertisedWscale = 7;
constexpr std::size_t   kTcpRxBufCap      = 256 * 1024;
constexpr std::size_t   kTcpTxBufCap      = 256 * 1024;
constexpr std::size_t   kPendingRxCap     = 256;
constexpr std::uint8_t  kIpProtoIcmp = 1;
constexpr std::uint8_t  kIpProtoTcp  = 6;
constexpr std::uint8_t  kIpProtoUdp  = 17;
constexpr std::uint8_t  kTcpFin = 0x01;
constexpr std::uint8_t  kTcpSyn = 0x02;
constexpr std::uint8_t  kTcpRst = 0x04;
constexpr std::uint8_t  kTcpPsh = 0x08;
constexpr std::uint8_t  kTcpAck = 0x10;
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
constexpr std::span<const std::uint8_t, 4> S4(const std::uint8_t* p) {
    return std::span<const std::uint8_t, 4>{p, 4};
}
constexpr std::span<std::uint8_t, 2> S2(std::uint8_t* p) {
    return std::span<std::uint8_t, 2>{p, 2};
}
constexpr std::span<std::uint8_t, 4> S4(std::uint8_t* p) {
    return std::span<std::uint8_t, 4>{p, 4};
}

// ---- TCP sequence-number-space comparisons (RFC 1323 §4.3) ----
inline bool SeqLt(std::uint32_t a, std::uint32_t b) {
    return static_cast<std::int32_t>(a - b) < 0;
}
inline bool SeqLe(std::uint32_t a, std::uint32_t b) {
    return static_cast<std::int32_t>(a - b) <= 0;
}
inline bool SeqGt(std::uint32_t a, std::uint32_t b) {
    return static_cast<std::int32_t>(a - b) > 0;
}
[[maybe_unused]] inline bool SeqGe(std::uint32_t a, std::uint32_t b) {
    return static_cast<std::int32_t>(a - b) >= 0;
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

// ---- TCP per-connection state ----
enum class TcpState : std::uint8_t {
    Connecting,   // outbound: non-blocking connect() outstanding
    SynRcvd,      // outbound: SYN-ACK sent, awaiting guest's ACK of SYN
    GuestSynSent, // inbound: SYN emitted toward guest, awaiting SYN-ACK
    Established,
    FinWait1,     // we sent FIN; awaiting ACK of FIN (and possibly guest FIN)
    CloseWait,    // guest sent FIN; still draining rx_buf to host
    LastAck,      // we sent FIN after CloseWait; awaiting ACK of FIN
    Closed,       // marked-for-erase; ExpireIdle sweeps
};

struct TcpConn {
    ConnKey key{};
    SOCKET  host_fd = INVALID_SOCKET;
    TcpState state = TcpState::Connecting;

    // Sequence-number space.
    std::uint32_t snd_una   = 0;   // first unacked byte (= ISN until acked)
    std::uint32_t snd_nxt   = 0;   // next byte to send (ISN+1 after SYN-ACK)
    std::uint32_t snd_wnd   = 65535; // effective send window (already scaled)
    std::uint8_t  snd_wscale = 0;  // guest's window scale (0 = none)
    bool          ws_negotiated = false; // guest sent WSopt in SYN

    std::uint32_t snd_wl1 = 0;     // seq of last segment that updated snd_wnd
    std::uint32_t snd_wl2 = 0;     // ack of last segment that updated snd_wnd

    std::uint32_t rcv_nxt = 0;     // next byte we expect from guest
    std::uint16_t guest_mss = 536;

    // tx_buf[0] corresponds to seq=snd_una; inflight = snd_nxt - snd_una.
    std::deque<std::uint8_t> tx_buf;
    std::deque<std::uint8_t> rx_buf;

    bool guest_fin_seen = false;   // guest sent FIN (rcv_nxt already incremented)
    bool host_eof_seen  = false;
    bool fin_sent       = false;   // FIN occupies seq snd_nxt-1
    bool host_send_shut = false;   // we've called shutdown(SD_SEND)
    bool delayed_ack    = false;   // pending ACK we owe the guest

    // Retransmission.
    std::chrono::steady_clock::time_point last_send{};
    std::uint32_t rto_ms  = 200;
    std::uint8_t  retries = 0;

    std::chrono::steady_clock::time_point connect_deadline{};

    std::chrono::steady_clock::time_point last_use{};

    // True iff this conn was created by accepting an inbound host
    // listener (port forward). Drives abortive close on teardown so
    // host clients observe RST instead of half-open silence.
    bool is_inbound = false;
};

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
    std::unordered_map<ConnKey, TcpConn, ConnKeyHash> tcp_conns;

    // Inbound port-forward listeners (1:1 with opts.port_forwards after
    // Start; entries whose bind() failed are recorded as INVALID_SOCKET so
    // indices stay aligned with port_forwards for diagnostic purposes,
    // but a separate listeners_active list holds only valid sockets).
    struct Listener {
        SOCKET sock = INVALID_SOCKET;
        UsernetBackend::PortForward rule{};
    };
    std::vector<Listener> listeners;

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

    std::mt19937 rng;

    // Counters.
    std::atomic<std::uint64_t> tx_packets{0};
    std::atomic<std::uint64_t> rx_packets{0};
    std::atomic<std::uint64_t> tx_dropped{0};
    std::atomic<std::uint64_t> rx_dropped{0};
    std::atomic<std::uint64_t> arp_replies{0};
    std::atomic<std::uint64_t> tcp_conns_total{0};
    std::atomic<std::uint64_t> udp_conns_total{0};
    std::atomic<std::uint64_t> icmp_echoes_total{0};

    explicit State(NetDevice& n, const UsernetBackend::Options& o)
        : net(n), opts(o),
          rng(static_cast<std::uint32_t>(::GetTickCount64() ^
                                          ::GetCurrentThreadId())) {}

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

    // ---- TCP ----
    void HandleTcpFromGuest(std::uint32_t src_ip_be, std::uint32_t dst_ip_be,
                            const std::uint8_t* tcp, std::size_t tcp_len);
    void TcpStartConnect(const ConnKey& key, std::uint32_t guest_isn,
                          std::uint16_t guest_mss,
                          std::uint8_t guest_wscale, bool ws_negotiated,
                          std::uint16_t guest_wnd);
    void TcpHandleConnectResult(TcpConn& c);
    void TcpDrainHostRecvIntoTxBuf(TcpConn& c);
    void TcpDrainRxBufToHost(TcpConn& c);
    void TcpDrainSendBuffer(TcpConn& c);
    void TcpEmitSegment(TcpConn& c, std::uint8_t flags,
                        std::uint32_t seq, std::uint32_t ack,
                        const std::uint8_t* opts, std::size_t opts_len,
                        const std::uint8_t* data, std::size_t data_len);
    void TcpEmitSynAck(TcpConn& c);
    void TcpEmitAck(TcpConn& c);
    void TcpEmitFin(TcpConn& c);
    void TcpEmitRst(std::uint32_t src_ip_be, std::uint32_t dst_ip_be,
                    std::uint16_t src_port_be, std::uint16_t dst_port_be,
                    std::uint32_t seq, std::uint32_t ack, bool ack_valid);
    void TcpClose(TcpConn& c);
    void TcpPumpRetransmits();
    std::uint16_t TcpAdvertisedWindow(const TcpConn& c) const;

    // ---- Inbound port-forward ----
    void StartListeners();
    void StopListeners();
    void AcceptOnListener(Listener& L);
    void TcpAcceptInbound(SOCKET host_sock,
                          const UsernetBackend::PortForward& rule);
    void TcpEmitSyn(TcpConn& c);
    bool AllocateEphemPort(std::uint32_t guest_ip_be,
                           std::uint32_t gw_ip_be,
                           std::uint16_t guest_port_be,
                           std::uint16_t& out_ephem_port_be);
    static void AbortiveCloseSocket(SOCKET& s);

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
    return state_ ? state_->tcp_conns_total.load() : 0;
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

    std::printf("[usernet] up: gateway=%s mtu=%u tcp_mss=%u ws=%u\n",
                opts.gateway_ipv4.c_str(),
                static_cast<unsigned>(kIpv4Mtu),
                static_cast<unsigned>(kAdvertisedMss),
                static_cast<unsigned>(kAdvertisedWscale));
    TINYVMM_ETW_INFO_KW("NetBackendStart", ::tinyvmm::diag::kw::Lifecycle,
        TraceLoggingString("usernet",                "backend"),
        TraceLoggingString(opts.gateway_ipv4.c_str(), "gateway"));
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
    for (auto& [k, c] : tcp_conns) {
        if (c.host_fd != INVALID_SOCKET) {
            if (c.is_inbound) AbortiveCloseSocket(c.host_fd);
            else              ::closesocket(c.host_fd), c.host_fd = INVALID_SOCKET;
        }
    }
    tcp_conns.clear();
    StopListeners();
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
        PumpIcmpReplies();
        TcpPumpRetransmits();
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
        HandleTcpFromGuest(src_ip_be, dst_ip_be, l4, l4_len);
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
    // send() — non-blocking; ENOBUFS / WSAEWOULDBLOCK both drop silently.
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
// Phase D: TCP
// ============================================================
std::uint16_t UsernetBackend::State::TcpAdvertisedWindow(
        const TcpConn& c) const {
    const std::size_t free_space =
        (c.rx_buf.size() < kTcpRxBufCap) ? (kTcpRxBufCap - c.rx_buf.size()) : 0;
    if (!c.ws_negotiated) {
        return static_cast<std::uint16_t>(std::min<std::size_t>(free_space, 65535));
    }
    const std::size_t scaled = free_space >> kAdvertisedWscale;
    return static_cast<std::uint16_t>(std::min<std::size_t>(scaled, 65535));
}

void UsernetBackend::State::TcpEmitSegment(TcpConn& c, std::uint8_t flags,
                                            std::uint32_t seq, std::uint32_t ack,
                                            const std::uint8_t* opts_data,
                                            std::size_t opts_len,
                                            const std::uint8_t* data,
                                            std::size_t data_len) {
    if (opts_len % 4 != 0 || opts_len > 40) return;
    const std::size_t hdr_len = kTcpHdrMinSize + opts_len;
    const std::size_t total   = hdr_len + data_len;
    if (total + kIp4HdrMinSize > kIpv4Mtu) return;

    std::vector<std::uint8_t> seg(total);
    std::memcpy(seg.data() + 0, &c.key.dst_port_be,   2);  // src = host's port
    std::memcpy(seg.data() + 2, &c.key.guest_port_be, 2);  // dst = guest's port
    Wr32Be(S4(seg.data() + 4), seq);
    Wr32Be(S4(seg.data() + 8), ack);
    seg[12] = static_cast<std::uint8_t>((hdr_len / 4) << 4);
    seg[13] = flags;
    Wr16Be(S2(seg.data() + 14), TcpAdvertisedWindow(c));
    Wr16Be(S2(seg.data() + 16), 0);   // checksum placeholder
    Wr16Be(S2(seg.data() + 18), 0);   // urgent ptr
    if (opts_len) std::memcpy(seg.data() + kTcpHdrMinSize, opts_data, opts_len);
    if (data_len) std::memcpy(seg.data() + hdr_len, data, data_len);

    // src/dst IP for the L4 checksum are: src = the host we connected to
    // (dst_ip_be of the conn), dst = guest_ip_be.
    std::uint32_t ph = PseudoHdrSum(c.key.dst_ip_be, c.key.guest_ip_be,
                                     kIpProtoTcp, static_cast<std::uint16_t>(total));
    Wr16Be(S2(seg.data() + 16), InetCksum(seg.data(), total, ph));

    EmitIpv4(c.key.dst_ip_be, c.key.guest_ip_be, kIpProtoTcp,
             seg.data(), total);

    c.last_send = std::chrono::steady_clock::now();
    c.delayed_ack = false;
}

void UsernetBackend::State::TcpEmitSynAck(TcpConn& c) {
    // SYN-ACK options: MSS=1460 (always) + WS=7 (only if guest negotiated WS).
    std::uint8_t opts_buf[8];
    std::size_t opts_len = 0;
    opts_buf[0] = 2; opts_buf[1] = 4;
    Wr16Be(S2(opts_buf + 2), kAdvertisedMss);
    opts_len = 4;
    if (c.ws_negotiated) {
        opts_buf[4] = 1;             // NOP for 4-byte alignment
        opts_buf[5] = 3;             // WSopt
        opts_buf[6] = 3;
        opts_buf[7] = kAdvertisedWscale;
        opts_len = 8;
    }
    // SYN-ACK occupies one sequence number; sent at snd_una (= ISN).
    TcpEmitSegment(c, kTcpSyn | kTcpAck, c.snd_una, c.rcv_nxt,
                   opts_buf, opts_len, nullptr, 0);
    c.rto_ms = 200;
}

void UsernetBackend::State::TcpEmitAck(TcpConn& c) {
    TcpEmitSegment(c, kTcpAck, c.snd_nxt, c.rcv_nxt, nullptr, 0, nullptr, 0);
}

void UsernetBackend::State::TcpEmitFin(TcpConn& c) {
    // FIN occupies one sequence number; sent at snd_nxt, snd_nxt++.
    TcpEmitSegment(c, kTcpFin | kTcpAck, c.snd_nxt, c.rcv_nxt,
                   nullptr, 0, nullptr, 0);
    c.snd_nxt += 1;
    c.fin_sent = true;
}

void UsernetBackend::State::TcpEmitRst(std::uint32_t src_ip_be,
                                        std::uint32_t dst_ip_be,
                                        std::uint16_t src_port_be,
                                        std::uint16_t dst_port_be,
                                        std::uint32_t seq, std::uint32_t ack,
                                        bool ack_valid) {
    std::uint8_t flags = kTcpRst | (ack_valid ? kTcpAck : 0);
    std::uint8_t seg[kTcpHdrMinSize]{};
    std::memcpy(seg + 0, &src_port_be, 2);
    std::memcpy(seg + 2, &dst_port_be, 2);
    Wr32Be(S4(seg + 4), seq);
    Wr32Be(S4(seg + 8), ack);
    seg[12] = static_cast<std::uint8_t>((kTcpHdrMinSize / 4) << 4);
    seg[13] = flags;
    Wr16Be(S2(seg + 14), 0);   // window 0 in RST
    Wr16Be(S2(seg + 16), 0);
    Wr16Be(S2(seg + 18), 0);

    std::uint32_t ph = PseudoHdrSum(src_ip_be, dst_ip_be, kIpProtoTcp,
                                     kTcpHdrMinSize);
    Wr16Be(S2(seg + 16), InetCksum(seg, kTcpHdrMinSize, ph));
    EmitIpv4(src_ip_be, dst_ip_be, kIpProtoTcp, seg, kTcpHdrMinSize);
}

void UsernetBackend::State::TcpClose(TcpConn& c) {
    if (c.host_fd != INVALID_SOCKET) {
        // For inbound port-forward flows, close abortively so the host
        // client observes a reset (TCP RST) instead of a graceful FIN
        // when we tear down (guest sent RST, handshake timed out, or
        // we hit the per-conn cap).
        if (c.is_inbound) {
            AbortiveCloseSocket(c.host_fd);
        } else {
            ::closesocket(c.host_fd);
            c.host_fd = INVALID_SOCKET;
        }
    }
    c.state = TcpState::Closed;
}

void UsernetBackend::State::TcpStartConnect(const ConnKey& key,
                                              std::uint32_t guest_isn,
                                              std::uint16_t guest_mss,
                                              std::uint8_t guest_wscale,
                                              bool ws_negotiated,
                                              std::uint16_t guest_wnd) {
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        TcpEmitRst(key.dst_ip_be, key.guest_ip_be,
                   key.dst_port_be, key.guest_port_be,
                   0, guest_isn + 1, true);
        return;
    }
    BOOL nodelay = TRUE;
    ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                  reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    if (!SetNonBlocking(s)) {
        ::closesocket(s);
        TcpEmitRst(key.dst_ip_be, key.guest_ip_be,
                   key.dst_port_be, key.guest_port_be,
                   0, guest_isn + 1, true);
        return;
    }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = key.dst_port_be;
    sa.sin_addr.s_addr = key.dst_ip_be;
    int crc = ::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    int cerr = (crc == SOCKET_ERROR) ? ::WSAGetLastError() : 0;
    if (crc == SOCKET_ERROR && cerr != WSAEWOULDBLOCK) {
        ::closesocket(s);
        TcpEmitRst(key.dst_ip_be, key.guest_ip_be,
                   key.dst_port_be, key.guest_port_be,
                   0, guest_isn + 1, true);
        return;
    }

    TcpConn c{};
    c.key       = key;
    c.host_fd   = s;
    c.state     = TcpState::Connecting;
    c.snd_una   = static_cast<std::uint32_t>(rng());
    c.snd_nxt   = c.snd_una;
    c.snd_wscale = guest_wscale;
    c.ws_negotiated = ws_negotiated;
    c.guest_mss  = guest_mss ? guest_mss : 536;
    c.snd_wnd    = static_cast<std::uint32_t>(guest_wnd) <<
                   (ws_negotiated ? guest_wscale : 0);
    c.rcv_nxt    = guest_isn + 1;
    c.last_use   = std::chrono::steady_clock::now();
    c.connect_deadline = c.last_use + std::chrono::seconds(10);

    if (crc == 0) {
        // Connect already completed (rare on non-blocking).
        c.state = TcpState::SynRcvd;
        TcpEmitSynAck(c);
        c.snd_nxt = c.snd_una + 1;
    }
    tcp_conns.emplace(key, std::move(c));
    tcp_conns_total.fetch_add(1, std::memory_order_relaxed);
}

void UsernetBackend::State::TcpHandleConnectResult(TcpConn& c) {
    int err = 0;
    int len = sizeof(err);
    if (::getsockopt(c.host_fd, SOL_SOCKET, SO_ERROR,
                      reinterpret_cast<char*>(&err), &len) == SOCKET_ERROR) {
        err = ::WSAGetLastError();
    }
    if (err != 0) {
        // connect failure → RST to guest, drop conn.
        TcpEmitRst(c.key.dst_ip_be, c.key.guest_ip_be,
                   c.key.dst_port_be, c.key.guest_port_be,
                   c.snd_una, c.rcv_nxt, true);
        TcpClose(c);
        return;
    }
    c.state = TcpState::SynRcvd;
    TcpEmitSynAck(c);
    // SYN-ACK consumes one sequence number.
    c.snd_nxt = c.snd_una + 1;
}

void UsernetBackend::State::HandleTcpFromGuest(std::uint32_t src_ip_be,
                                                 std::uint32_t dst_ip_be,
                                                 const std::uint8_t* tcp,
                                                 std::size_t tcp_len) {
    if (tcp_len < kTcpHdrMinSize) return;
    const std::uint16_t src_port_be = *reinterpret_cast<const std::uint16_t*>(tcp);
    const std::uint16_t dst_port_be = *reinterpret_cast<const std::uint16_t*>(tcp + 2);
    const std::uint32_t seq = Be32(S4(tcp + 4));
    const std::uint32_t ack = Be32(S4(tcp + 8));
    const std::uint8_t  doff_b = tcp[12];
    const std::size_t   hdr_len = (doff_b >> 4) * 4u;
    if (hdr_len < kTcpHdrMinSize || hdr_len > tcp_len) return;
    const std::uint8_t flags = tcp[13];
    const std::uint16_t wnd  = Be16(S2(tcp + 14));

    std::uint32_t ph = PseudoHdrSum(src_ip_be, dst_ip_be, kIpProtoTcp,
                                     static_cast<std::uint16_t>(tcp_len));
    if (InetCksum(tcp, tcp_len, ph) != 0) {
        tx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    ConnKey key{src_ip_be, dst_ip_be, src_port_be, dst_port_be};
    auto it = tcp_conns.find(key);

    // --- New connection: SYN (no ACK) opens a TcpConn. ---
    if (it == tcp_conns.end()) {
        if ((flags & (kTcpSyn | kTcpAck | kTcpRst)) == kTcpSyn) {
            if (tcp_conns.size() >= opts.max_tcp_conns) {
                TcpEmitRst(dst_ip_be, src_ip_be, dst_port_be, src_port_be,
                           0, seq + 1, true);
                return;
            }
            // Parse options (MSS + WS only).
            std::uint16_t guest_mss = 536;
            std::uint8_t  guest_ws  = 0;
            bool          have_ws   = false;
            std::size_t o = kTcpHdrMinSize;
            while (o < hdr_len) {
                std::uint8_t kind = tcp[o];
                if (kind == 0) break;                       // EOL
                if (kind == 1) { o += 1; continue; }        // NOP
                if (o + 1 >= hdr_len) break;
                std::uint8_t olen = tcp[o + 1];
                if (olen < 2 || o + olen > hdr_len) break;
                if (kind == 2 && olen == 4) {
                    guest_mss = Be16(S2(tcp + o + 2));
                    if (guest_mss > 1460) guest_mss = 1460;
                } else if (kind == 3 && olen == 3) {
                    guest_ws  = tcp[o + 2];
                    if (guest_ws > 14) guest_ws = 14;
                    have_ws   = true;
                }
                o += olen;
            }
            TcpStartConnect(key, seq, guest_mss, guest_ws, have_ws, wnd);
            return;
        }
        // Unknown 4-tuple, not a SYN → RST per RFC.
        if (!(flags & kTcpRst)) {
            std::uint32_t rst_seq = (flags & kTcpAck) ? ack : 0;
            std::uint32_t rst_ack = (flags & kTcpAck) ? 0u :
                seq + ((flags & (kTcpSyn | kTcpFin)) ? 1u : 0u) +
                static_cast<std::uint32_t>(tcp_len - hdr_len);
            TcpEmitRst(dst_ip_be, src_ip_be, dst_port_be, src_port_be,
                       rst_seq, rst_ack, !(flags & kTcpAck));
        }
        return;
    }

    TcpConn& c = it->second;
    c.last_use = std::chrono::steady_clock::now();

    if (flags & kTcpRst) {
        // For inbound flows, TcpClose() will abortively close host_fd
        // (SO_LINGER {1,0}) so the host client observes a real reset.
        TcpClose(c);
        return;
    }

    // Inbound port-forward handshake: we sent SYN, expect SYN+ACK.
    if (c.state == TcpState::GuestSynSent) {
        // SYN-ACK check tolerates ECN flags (CWR/ECE) in flags[7..6]; we
        // only insist on SYN+ACK being set and RST being clear.
        if ((flags & (kTcpSyn | kTcpAck | kTcpRst)) != (kTcpSyn | kTcpAck)) {
            // Drop silently. rcv_nxt is undefined until we see the guest's
            // SYN, so we cannot emit a dup-ACK -- it would advertise
            // rcv_nxt=0 which the guest would treat as invalid.
            return;
        }
        if (ack != c.snd_nxt) {
            // ACK doesn't acknowledge our SYN: blow away the conn.
            TcpEmitRst(c.key.dst_ip_be, c.key.guest_ip_be,
                       c.key.dst_port_be, c.key.guest_port_be,
                       ack, 0, false);
            TcpClose(c);
            return;
        }
        // Parse guest's MSS / WS from SYN-ACK options. The guest only
        // honors WS if we offered one; we always offer WS=kAdvertisedWscale,
        // so c.ws_negotiated stays true on the inbound conn iff the
        // guest mirrored it.
        std::uint16_t guest_mss = 536;
        std::uint8_t  guest_ws  = 0;
        bool          have_ws   = false;
        std::size_t o = kTcpHdrMinSize;
        while (o < hdr_len) {
            std::uint8_t kind = tcp[o];
            if (kind == 0) break;                       // EOL
            if (kind == 1) { o += 1; continue; }        // NOP
            if (o + 1 >= hdr_len) break;
            std::uint8_t olen = tcp[o + 1];
            if (olen < 2 || o + olen > hdr_len) break;
            if (kind == 2 && olen == 4) {
                guest_mss = Be16(S2(tcp + o + 2));
                if (guest_mss > 1460) guest_mss = 1460;
            } else if (kind == 3 && olen == 3) {
                guest_ws = tcp[o + 2];
                if (guest_ws > 14) guest_ws = 14;
                have_ws  = true;
            }
            o += olen;
        }
        c.guest_mss     = guest_mss;
        c.ws_negotiated = have_ws;
        c.snd_wscale    = have_ws ? guest_ws : 0;
        c.snd_una       = ack;
        c.rcv_nxt       = seq + 1;
        c.snd_wnd       = static_cast<std::uint32_t>(wnd) <<
                          (c.ws_negotiated ? c.snd_wscale : 0);
        c.snd_wl1       = seq;
        c.snd_wl2       = ack;
        c.rto_ms        = 200;
        c.retries       = 0;
        c.state         = TcpState::Established;
        TcpEmitAck(c);
        // Hand off to the regular per-conn pumping: any bytes the host
        // client already sent will get pulled into tx_buf and shipped
        // toward the guest now that rcv_nxt/snd_wnd are defined.
        TcpDrainHostRecvIntoTxBuf(c);
        TcpDrainSendBuffer(c);
        return;
    }

    // Duplicate SYN (no ACK) while we're already mid-handshake: idempotent.
    if ((flags & kTcpSyn) && !(flags & kTcpAck)) {
        if (c.state == TcpState::SynRcvd) {
            TcpEmitSynAck(c);
        }
        return;
    }

    // ACK processing.
    if (flags & kTcpAck) {
        if (c.state == TcpState::SynRcvd) {
            // Acceptable ACK of SYN: ack == snd_nxt (which is ISN+1).
            if (ack == c.snd_nxt) {
                c.snd_una = ack;
                c.state = TcpState::Established;
                c.snd_wnd = static_cast<std::uint32_t>(wnd) <<
                            (c.ws_negotiated ? c.snd_wscale : 0);
                c.snd_wl1 = seq;
                c.snd_wl2 = ack;
                c.rto_ms = 200;
                c.retries = 0;
                // Fall through to process payload/FIN in the same segment.
            } else if (SeqLe(ack, c.snd_una) || SeqGt(ack, c.snd_nxt)) {
                // Unacceptable ACK → drop.
                return;
            } else {
                // Mid-handshake odd ACK; ignore until correct one arrives.
                return;
            }
        } else if (c.state == TcpState::Established ||
                   c.state == TcpState::FinWait1   ||
                   c.state == TcpState::CloseWait  ||
                   c.state == TcpState::LastAck) {
            if (SeqGt(ack, c.snd_nxt)) {
                // ACKing data we never sent: dup-ACK back and drop.
                TcpEmitAck(c);
                return;
            }
            if (SeqGt(ack, c.snd_una)) {
                std::uint32_t acked = ack - c.snd_una;
                // FIN consumes one byte of ack space; subtract before popping tx_buf.
                bool fin_acked = false;
                if (c.fin_sent && acked > 0) {
                    const std::uint32_t inflight = c.snd_nxt - c.snd_una;
                    // FIN is the last byte: present at snd_nxt-1, not in tx_buf.
                    if (acked == inflight) {
                        fin_acked = true;
                        acked -= 1;
                    }
                }
                if (acked > c.tx_buf.size()) acked = static_cast<std::uint32_t>(c.tx_buf.size());
                for (std::uint32_t i = 0; i < acked; ++i) c.tx_buf.pop_front();
                c.snd_una = ack;
                c.rto_ms  = 200;
                c.retries = 0;

                if (fin_acked) {
                    if (c.state == TcpState::FinWait1 && c.guest_fin_seen) {
                        TcpClose(c);
                        return;
                    } else if (c.state == TcpState::FinWait1) {
                        // Wait for guest FIN (peer-close); rely on host_eof
                        // already seen since we're past CloseWait skip.
                    } else if (c.state == TcpState::LastAck) {
                        TcpClose(c);
                        return;
                    }
                }
            }
            // SND.WND update (RFC 793 §3.7, with WL1/WL2 protection).
            if (SeqLt(c.snd_wl1, seq) ||
                (c.snd_wl1 == seq && SeqLe(c.snd_wl2, ack))) {
                c.snd_wnd = static_cast<std::uint32_t>(wnd) <<
                            (c.ws_negotiated ? c.snd_wscale : 0);
                c.snd_wl1 = seq;
                c.snd_wl2 = ack;
            }
        }
    }

    // ---- Data + FIN processing (RFC 793 §3.9, "SEGMENT ARRIVES") ----
    // Only after SynRcvd/Established and friends.
    if (c.state == TcpState::Established ||
        c.state == TcpState::FinWait1   ||
        c.state == TcpState::CloseWait  ||
        c.state == TcpState::LastAck) {

        const std::uint8_t* payload = tcp + hdr_len;
        const std::size_t   payload_len = tcp_len - hdr_len;

        if (payload_len > 0) {
            const std::uint32_t seq_end =
                seq + static_cast<std::uint32_t>(payload_len);
            // Partial-overlap trimming.
            if (SeqLt(seq_end, c.rcv_nxt) || seq_end == c.rcv_nxt) {
                // Entirely already-received.
                TcpEmitAck(c);
            } else if (SeqGt(seq, c.rcv_nxt)) {
                // Future (no OOO buffer).
                TcpEmitAck(c);
            } else {
                std::size_t trim_left = 0;
                if (SeqLt(seq, c.rcv_nxt)) {
                    trim_left = c.rcv_nxt - seq;
                }
                const std::size_t accept_len = payload_len - trim_left;
                // RX backpressure: take min(accept_len, rx_buf_free).
                const std::size_t free_space =
                    (c.rx_buf.size() < kTcpRxBufCap) ?
                        (kTcpRxBufCap - c.rx_buf.size()) : 0;
                const std::size_t take = std::min(accept_len, free_space);
                if (take > 0) {
                    c.rx_buf.insert(c.rx_buf.end(),
                                     payload + trim_left,
                                     payload + trim_left + take);
                    c.rcv_nxt += static_cast<std::uint32_t>(take);
                }
                // ACK whatever we managed to take (also handles take==0).
                TcpEmitAck(c);
                // Try to forward to host immediately.
                TcpDrainRxBufToHost(c);
            }
        }

        if (flags & kTcpFin) {
            // FIN is valid only at seq == rcv_nxt + payload_len-trim_left
            // (we already advanced rcv_nxt above on accepted data). Use the
            // simpler check: FIN-byte is the byte immediately after data.
            const std::uint32_t fin_seq = seq + static_cast<std::uint32_t>(payload_len);
            if (fin_seq == c.rcv_nxt && !c.guest_fin_seen) {
                c.guest_fin_seen = true;
                c.rcv_nxt += 1;
                if (c.state == TcpState::Established) {
                    c.state = TcpState::CloseWait;
                }
                TcpEmitAck(c);
                // Try to flush rx_buf then shutdown(SD_SEND).
                TcpDrainRxBufToHost(c);
                if (c.rx_buf.empty() && !c.host_send_shut &&
                    c.host_fd != INVALID_SOCKET) {
                    ::shutdown(c.host_fd, SD_SEND);
                    c.host_send_shut = true;
                }
            }
        }

        // Try to make forward progress on the send buffer (drives ACK-clocked sends).
        TcpDrainSendBuffer(c);
    }
}

void UsernetBackend::State::TcpDrainSendBuffer(TcpConn& c) {
    while (true) {
        const std::uint32_t inflight = c.snd_nxt - c.snd_una;
        const std::uint32_t cap = std::min<std::uint32_t>(c.snd_wnd,
                                    static_cast<std::uint32_t>(c.tx_buf.size()));
        if (inflight >= cap) break;
        std::uint32_t avail = cap - inflight;
        if (avail == 0) break;
        std::uint32_t mss = c.guest_mss ? c.guest_mss : 536;
        if (mss > kAdvertisedMss) mss = kAdvertisedMss;
        std::uint32_t take = std::min(avail, mss);
        // tx_buf[0] is at snd_una. We want bytes [inflight, inflight+take).
        if (inflight + take > c.tx_buf.size()) {
            take = static_cast<std::uint32_t>(c.tx_buf.size() - inflight);
            if (take == 0) break;
        }
        std::vector<std::uint8_t> tmp(take);
        for (std::uint32_t i = 0; i < take; ++i) {
            tmp[i] = c.tx_buf[inflight + i];
        }
        TcpEmitSegment(c, kTcpAck | kTcpPsh, c.snd_nxt, c.rcv_nxt,
                       nullptr, 0, tmp.data(), take);
        c.snd_nxt += take;
        if (c.retries == 0) c.rto_ms = 200;
    }

    // If host has signalled EOF and tx_buf is fully drained (inflight==0
    // means snd_una==snd_nxt; all data acked, nothing in flight), send FIN.
    if (c.host_eof_seen && !c.fin_sent &&
        c.tx_buf.empty() && c.snd_una == c.snd_nxt &&
        (c.state == TcpState::Established || c.state == TcpState::CloseWait)) {
        TcpEmitFin(c);
        c.state = (c.state == TcpState::CloseWait) ?
                  TcpState::LastAck : TcpState::FinWait1;
    }
}

void UsernetBackend::State::TcpDrainRxBufToHost(TcpConn& c) {
    while (!c.rx_buf.empty() && c.host_fd != INVALID_SOCKET) {
        // send() needs a contiguous buffer; pull a chunk out.
        const std::size_t chunk =
            std::min<std::size_t>(c.rx_buf.size(), 16 * 1024);
        std::vector<std::uint8_t> tmp(chunk);
        for (std::size_t i = 0; i < chunk; ++i) tmp[i] = c.rx_buf[i];
        int sent = ::send(c.host_fd,
                           reinterpret_cast<const char*>(tmp.data()),
                           static_cast<int>(chunk), 0);
        if (sent == SOCKET_ERROR) {
            int e = ::WSAGetLastError();
            if (e == WSAEWOULDBLOCK) return;
            // Treat any other error as connection reset.
            TcpEmitRst(c.key.dst_ip_be, c.key.guest_ip_be,
                       c.key.dst_port_be, c.key.guest_port_be,
                       c.snd_nxt, c.rcv_nxt, true);
            TcpClose(c);
            return;
        }
        if (sent <= 0) return;
        for (int i = 0; i < sent; ++i) c.rx_buf.pop_front();
    }
    if (c.guest_fin_seen && c.rx_buf.empty() && !c.host_send_shut &&
        c.host_fd != INVALID_SOCKET) {
        ::shutdown(c.host_fd, SD_SEND);
        c.host_send_shut = true;
    }
}

void UsernetBackend::State::TcpDrainHostRecvIntoTxBuf(TcpConn& c) {
    while (c.host_fd != INVALID_SOCKET &&
           c.tx_buf.size() < kTcpTxBufCap &&
           !c.host_eof_seen) {
        const std::size_t cap_left = kTcpTxBufCap - c.tx_buf.size();
        const std::size_t chunk = std::min<std::size_t>(cap_left, 16 * 1024);
        std::uint8_t tmp[16 * 1024];
        int n = ::recv(c.host_fd, reinterpret_cast<char*>(tmp),
                        static_cast<int>(chunk), 0);
        if (n == SOCKET_ERROR) {
            int e = ::WSAGetLastError();
            if (e == WSAEWOULDBLOCK) return;
            // ECONNRESET etc → RST to guest, drop.
            TcpEmitRst(c.key.dst_ip_be, c.key.guest_ip_be,
                       c.key.dst_port_be, c.key.guest_port_be,
                       c.snd_nxt, c.rcv_nxt, true);
            TcpClose(c);
            return;
        }
        if (n == 0) {
            c.host_eof_seen = true;
            return;
        }
        c.tx_buf.insert(c.tx_buf.end(), tmp, tmp + n);
    }
}

void UsernetBackend::State::TcpPumpRetransmits() {
    const auto now = std::chrono::steady_clock::now();
    for (auto& [k, c] : tcp_conns) {
        if (c.state == TcpState::Closed) continue;
        if (c.state == TcpState::Connecting) {
            if (now > c.connect_deadline) {
                TcpEmitRst(c.key.dst_ip_be, c.key.guest_ip_be,
                           c.key.dst_port_be, c.key.guest_port_be,
                           c.snd_una, c.rcv_nxt, true);
                TcpClose(c);
            }
            continue;
        }
        if (c.state == TcpState::SynRcvd) {
            auto since = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - c.last_send).count();
            if (since >= static_cast<long long>(c.rto_ms)) {
                if (c.retries >= 5) {
                    TcpEmitRst(c.key.dst_ip_be, c.key.guest_ip_be,
                               c.key.dst_port_be, c.key.guest_port_be,
                               c.snd_una, c.rcv_nxt, true);
                    TcpClose(c);
                    continue;
                }
                c.retries += 1;
                c.rto_ms = std::min<std::uint32_t>(c.rto_ms * 2, 3200);
                TcpEmitSynAck(c);
            }
            continue;
        }
        if (c.state == TcpState::GuestSynSent) {
            auto since = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - c.last_send).count();
            if (since >= static_cast<long long>(c.rto_ms)) {
                if (c.retries >= 5) {
                    // Handshake failed: abortive close on host_fd so the
                    // host client sees RST, not graceful EOF.
                    TcpClose(c);
                    continue;
                }
                c.retries += 1;
                c.rto_ms = std::min<std::uint32_t>(c.rto_ms * 2, 3200);
                TcpEmitSyn(c);
            }
            continue;
        }
        // Established / FinWait1 / CloseWait / LastAck: data or FIN in flight.
        const bool inflight = (c.snd_nxt != c.snd_una);
        if (!inflight) continue;
        auto since = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - c.last_send).count();
        if (since < static_cast<long long>(c.rto_ms)) continue;
        if (c.retries >= 5) {
            TcpEmitRst(c.key.dst_ip_be, c.key.guest_ip_be,
                       c.key.dst_port_be, c.key.guest_port_be,
                       c.snd_nxt, c.rcv_nxt, true);
            TcpClose(c);
            continue;
        }
        c.retries += 1;
        c.rto_ms = std::min<std::uint32_t>(c.rto_ms * 2, 3200);

        // Retransmit oldest unacked: either tx_buf prefix or FIN.
        const std::uint32_t want = c.snd_nxt - c.snd_una;
        std::uint32_t data_to_resend = static_cast<std::uint32_t>(c.tx_buf.size());
        if (data_to_resend > want) data_to_resend = want;
        std::uint32_t mss = c.guest_mss ? c.guest_mss : 536;
        if (mss > kAdvertisedMss) mss = kAdvertisedMss;
        std::uint32_t take = std::min(data_to_resend, mss);
        if (take > 0) {
            std::vector<std::uint8_t> tmp(take);
            for (std::uint32_t i = 0; i < take; ++i) tmp[i] = c.tx_buf[i];
            TcpEmitSegment(c, kTcpAck | kTcpPsh, c.snd_una, c.rcv_nxt,
                           nullptr, 0, tmp.data(), take);
        } else if (c.fin_sent) {
            TcpEmitSegment(c, kTcpFin | kTcpAck, c.snd_nxt - 1, c.rcv_nxt,
                           nullptr, 0, nullptr, 0);
        }
    }
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
// State::AllocateEphemPort
// ============================================================
// Pick a free ephemeral port (in network byte order) for use as the
// guest-side source port of an inbound forwarded connection. Range is
// IANA-recommended 49152-65535. Avoids any port already in use by an
// existing tcp_conn with the same {guest_ip, gw_ip, guest_port} 3-tuple.
// Returns false if all 16384 candidates are taken.
bool UsernetBackend::State::AllocateEphemPort(
    std::uint32_t guest_ip_be,
    std::uint32_t gw_ip_be,
    std::uint16_t guest_port_be,
    std::uint16_t& out_ephem_port_be) {
    constexpr std::uint16_t kLow  = 49152;
    constexpr std::uint16_t kHigh = 65535;
    constexpr std::uint32_t kRange = kHigh - kLow + 1u;

    std::uint32_t start = static_cast<std::uint32_t>(rng()) % kRange;
    for (std::uint32_t i = 0; i < kRange; ++i) {
        std::uint16_t cand_host = static_cast<std::uint16_t>(
            kLow + ((start + i) % kRange));
        std::uint16_t cand_be = ::htons(cand_host);
        ConnKey k{guest_ip_be, gw_ip_be, cand_be, guest_port_be};
        if (tcp_conns.find(k) == tcp_conns.end()) {
            out_ephem_port_be = cand_be;
            return true;
        }
    }
    return false;
}

// ============================================================
// State::TcpEmitSyn  (inbound port-forward only)
// ============================================================
// Originates a SYN from the gateway toward the guest. MSS+WS options
// match what we expect the guest to mirror back in its SYN-ACK.
void UsernetBackend::State::TcpEmitSyn(TcpConn& c) {
    std::uint8_t opts_buf[8];
    opts_buf[0] = 2; opts_buf[1] = 4;
    Wr16Be(S2(opts_buf + 2), kAdvertisedMss);
    opts_buf[4] = 1;                  // NOP for 4-byte alignment
    opts_buf[5] = 3;                  // WSopt
    opts_buf[6] = 3;
    opts_buf[7] = kAdvertisedWscale;
    // SYN occupies one sequence number; sent at snd_una (= ISN).
    TcpEmitSegment(c, kTcpSyn, c.snd_una, 0,
                   opts_buf, sizeof(opts_buf), nullptr, 0);
    c.rto_ms = 200;
}

// ============================================================
// State::AcceptOnListener
// ============================================================
void UsernetBackend::State::AcceptOnListener(Listener& L) {
    if (L.sock == INVALID_SOCKET) return;
    // Cap accepts per cycle so one busy listener can't starve the rest
    // of the worker loop (UDP, ICMP, retransmits) on a SYN flood.
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
        TcpAcceptInbound(s, L.rule);
    }
}

// ============================================================
// State::TcpAcceptInbound
// ============================================================
// Newly-accepted host_sock corresponds to a freshly opened client
// connection that we are going to proxy through to the guest. We
// originate a SYN to the guest from (gateway_ip, ephem_port) ->
// (rule.guest_ip, rule.guest_port).
void UsernetBackend::State::TcpAcceptInbound(
    SOCKET host_sock, const UsernetBackend::PortForward& rule) {
    BOOL nodelay = TRUE;
    ::setsockopt(host_sock, IPPROTO_TCP, TCP_NODELAY,
                  reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    if (!SetNonBlocking(host_sock)) {
        AbortiveCloseSocket(host_sock);
        return;
    }
    if (tcp_conns.size() >= opts.max_tcp_conns) {
        AbortiveCloseSocket(host_sock);
        return;
    }

    const std::uint32_t gw_ip_be    = gateway_ip_be;
    const std::uint32_t gst_ip_be   = rule.guest_ip_be;
    const std::uint16_t gst_port_be = ::htons(rule.guest_port);
    std::uint16_t ephem_be = 0;
    if (!AllocateEphemPort(gst_ip_be, gw_ip_be, gst_port_be, ephem_be)) {
        AbortiveCloseSocket(host_sock);
        return;
    }

    // ConnKey convention: src=guest, dst=peer. For an inbound conn,
    // the "peer" from the guest's perspective is the gateway at
    // (gw_ip_be, ephem_be) and the "guest endpoint" is
    // (gst_ip_be, gst_port_be).
    ConnKey key{gst_ip_be, gw_ip_be, gst_port_be, ephem_be};

    TcpConn c{};
    c.key            = key;
    c.host_fd        = host_sock;
    c.state          = TcpState::GuestSynSent;
    c.snd_una        = static_cast<std::uint32_t>(rng());
    c.snd_nxt        = c.snd_una + 1;       // SYN consumes one seq
    c.snd_wscale     = 0;
    c.ws_negotiated  = false;               // settled when SYN-ACK arrives
    c.guest_mss      = 536;
    c.snd_wnd        = 65535;               // tentative
    c.rcv_nxt        = 0;                   // undefined until SYN-ACK
    c.last_use       = std::chrono::steady_clock::now();
    c.is_inbound     = true;

    auto [it, ok] = tcp_conns.emplace(key, std::move(c));
    if (!ok) {
        AbortiveCloseSocket(host_sock);
        return;
    }
    TcpEmitSyn(it->second);
    tcp_conns_total.fetch_add(1, std::memory_order_relaxed);
}

// ============================================================
// State::DrainHostSockets
// ============================================================
void UsernetBackend::State::DrainHostSockets() {
    // Count active listeners up front; they always need POLLRDNORM and
    // are independent of the udp/tcp conn maps. (Without this, an
    // otherwise-idle backend that only has port-forward listeners
    // installed would never poll them.)
    std::size_t active_listeners = 0;
    for (const auto& L : listeners) {
        if (L.sock != INVALID_SOCKET) ++active_listeners;
    }
    if (udp_conns.empty() && tcp_conns.empty() && active_listeners == 0) return;

    // Build the poll set. For TCP, request POLLOUT only when we need it:
    //   - Connecting (waiting for connect to complete)
    //   - rx_buf has data to push to host
    // Always request POLLRDNORM when the conn could receive (i.e. not
    // closed and tx_buf isn't at cap).
    //
    // GuestSynSent conns are deliberately excluded from per-conn polling:
    // their host socket can be readable (the client's data already sits
    // in the kernel buffer), but we mustn't drain it until the guest
    // completes the handshake -- otherwise we'd emit data toward the
    // guest with rcv_nxt=0, breaking the 3WHS.
    std::vector<WSAPOLLFD> fds;
    fds.reserve(udp_conns.size() + tcp_conns.size() + active_listeners);

    enum class SlotKind : std::uint8_t { Udp, Tcp, Listener };
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
    for (auto& [k, c] : tcp_conns) {
        if (c.state == TcpState::Closed || c.host_fd == INVALID_SOCKET) continue;
        if (c.state == TcpState::GuestSynSent) continue;
        WSAPOLLFD f{};
        f.fd = c.host_fd;
        f.events = 0;
        if (c.state == TcpState::Connecting) {
            f.events |= POLLWRNORM;
        } else {
            if (c.tx_buf.size() < kTcpTxBufCap && !c.host_eof_seen) {
                f.events |= POLLRDNORM;
            }
            if (!c.rx_buf.empty() && !c.host_send_shut) {
                f.events |= POLLWRNORM;
            }
        }
        if (f.events == 0) continue;
        fds.push_back(f);
        slots.push_back({SlotKind::Tcp, k, 0});
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
        if (slot.kind == SlotKind::Udp) {
            auto it = udp_conns.find(slot.key);
            if (it == udp_conns.end()) continue;
            if (rev & (POLLRDNORM | POLLERR | POLLHUP)) {
                PumpUdpSocket(it->second);
            }
        } else {
            auto it = tcp_conns.find(slot.key);
            if (it == tcp_conns.end()) continue;
            TcpConn& c = it->second;
            if (c.state == TcpState::Connecting) {
                if (rev & (POLLWRNORM | POLLERR | POLLHUP)) {
                    TcpHandleConnectResult(c);
                }
                continue;
            }
            if (rev & (POLLERR | POLLHUP)) {
                // Surfaces as connection-reset or graceful peer close;
                // recv() will distinguish.
            }
            if (rev & POLLWRNORM) {
                TcpDrainRxBufToHost(c);
            }
            if (rev & POLLRDNORM) {
                TcpDrainHostRecvIntoTxBuf(c);
            }
            TcpDrainSendBuffer(c);
        }
    }
}

// ============================================================
// State::ExpireIdle
// ============================================================
void UsernetBackend::State::ExpireIdle() {
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
    // Sweep marked-closed TCP conns.
    for (auto it = tcp_conns.begin(); it != tcp_conns.end(); ) {
        if (it->second.state == TcpState::Closed) {
            it = tcp_conns.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace tinyvmm::virtio
