#include "net_wintun.h"

#include "virtio_pci.h"

#include "net/wintun_device_path.h"

#include "diag/etw.h"

#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <system_error>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

// Returns true and prints a diagnostic hint when `e` came from
// REGISTER_RINGS being rejected with ERROR_ACCESS_DENIED, which is a
// fundamental wintun.sys limitation that no user-mode workaround can
// bypass. The wintun kernel driver attaches a device-object SD of
// `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NWNRNX;;;HI)` (SYSTEM+BA only,
// plus a High mandatory integrity label that blocks medium-IL processes
// regardless of the device interface DACL).
namespace {
bool ExplainWintunSessionAccessDenied(const std::system_error& e,
                                      const char* prefix) {
    if (e.code().value() != static_cast<int>(ERROR_ACCESS_DENIED)) {
        return false;
    }
    const char* what = e.what();
    if (!what || std::strstr(what, "TUN_IOCTL_REGISTER_RINGS") == nullptr) {
        return false;
    }
    std::fprintf(stderr,
        "%s wintun.sys gates REGISTER_RINGS to SYSTEM + BUILTIN\\Administrators\n"
        "%s only (mandatory IL = High). A standard-user token cannot run a\n"
        "%s wintun session on an adapter created by anyone, including the\n"
        "%s wintunsvc service. The control plane (adapter create / IP / delete)\n"
        "%s works without admin via wintunsvc, but the data plane is blocked\n"
        "%s inside the driver and there is no user-mode workaround.\n"
        "%s -> re-run from an elevated token, or extend wintunsvc so that the\n"
        "%s    service owns the device handle and shares the ring memory +\n"
        "%s    tail-moved events with the client via DuplicateHandle.\n",
        prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix);
    return true;
}
}  // namespace

namespace tinyvmm::virtio {

namespace {

constexpr std::size_t kVirtioNetHdrSize = 12;
constexpr std::size_t kEthHdrSize       = 14;
constexpr std::uint16_t kEthTypeIp4     = 0x0800;
constexpr std::uint16_t kEthTypeArp     = 0x0806;

// Wire-layout POD for the Ethernet II header. `ether_type` is stored
// big-endian on the wire; callers use Be16/Wr16Be on its bytes.
#pragma pack(push, 1)
struct EthHeader {
    std::uint8_t dst[6];
    std::uint8_t src[6];
    std::uint8_t ether_type_be[2];
};
static_assert(sizeof(EthHeader) == 14);

// Wire-layout POD for an IPv4-over-Ethernet ARP packet (RFC 826 §2.2
// with the ARPHRD_ETHER / ETH_P_IP specialization). All multi-byte
// integer fields are big-endian on the wire.
struct ArpIpv4 {
    std::uint8_t htype_be[2];   // 1 = Ethernet
    std::uint8_t ptype_be[2];   // 0x0800 = IPv4
    std::uint8_t hlen;          // 6
    std::uint8_t plen;          // 4
    std::uint8_t opcode_be[2];  // 1 = request, 2 = reply
    std::uint8_t sha[6];        // sender MAC
    std::uint8_t spa[4];        // sender IPv4
    std::uint8_t tha[6];        // target MAC
    std::uint8_t tpa[4];        // target IPv4
};
static_assert(sizeof(ArpIpv4) == 28);
#pragma pack(pop)

constexpr std::uint16_t Be16(std::span<const std::uint8_t, 2> p) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
constexpr void Wr16Be(std::span<std::uint8_t, 2> p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xFF);
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    const int s_size = util::checked_int_cast<int>(s.size());
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), s_size, nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), s_size, w.data(), n);
    return w;
}

bool ParseIpv4(const std::string& s, std::uint32_t* out_be) {
    IN_ADDR a{};
    if (::InetPtonA(AF_INET, s.c_str(), &a) != 1) return false;
    *out_be = a.s_addr;  // already network byte order
    return true;
}

// Walk the readable buffers of a chain, summing total bytes and copying
// up to `peek.size()` bytes of the prefix into `peek`. Used to inspect
// the first vhdr+Eth header without materializing the whole frame.
struct ReadableSummary { std::size_t total; std::size_t peeked; };
ReadableSummary SummarizeReadable(const PoppedChain& chain,
                                   std::span<std::uint8_t> peek) {
    ReadableSummary s{};
    for (const auto& b : chain.bufs) {
        if (b.write) continue;
        const auto sz = b.bytes.size();
        if (s.peeked < peek.size()) {
            const std::size_t take = std::min(peek.size() - s.peeked, sz);
            std::memcpy(peek.data() + s.peeked, b.bytes.data(), take);
            s.peeked += take;
        }
        s.total += sz;
    }
    return s;
}

// Copy the readable buffers of a chain (concatenated) starting at
// logical offset `skip` into `dst`. Returns bytes copied (clamped to
// dst.size()).
std::size_t CopyReadable(const PoppedChain& chain,
                          std::size_t skip,
                          std::span<std::uint8_t> dst) {
    std::size_t logical = 0;
    std::size_t written = 0;
    for (const auto& b : chain.bufs) {
        if (b.write) continue;
        const auto sz = b.bytes.size();
        if (logical + sz <= skip) {
            logical += sz;
            continue;
        }
        const std::size_t src_off = (skip > logical) ? (skip - logical) : 0;
        const std::size_t avail   = sz - src_off;
        const std::size_t take    = std::min(avail, dst.size() - written);
        std::memcpy(dst.data() + written, b.bytes.data() + src_off, take);
        written += take;
        logical += sz;
        if (written == dst.size()) break;
    }
    return written;
}

}  // namespace

WintunNetBackend::WintunNetBackend(NetDevice& net, const Options& opts)
    : net_(net), opts_(opts) {}

WintunNetBackend::~WintunNetBackend() {
    Stop();
}

void WintunNetBackend::Start(whp::Partition& partition,
                              PciTransport& transport) {
    xport_ = &transport;

    if (!ParseIpv4(opts_.host_ipv4, &host_ip_be_)) {
        last_error_ = "Invalid host_ipv4: " + opts_.host_ipv4;
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        return;
    }

    try {
        mgr_ = (opts_.kind == BackendKind::Svc)
                   ? net::MakeWintunSvcManager()
                   : net::MakeWintunDllManager();
    } catch (const std::exception& e) {
        last_error_ = std::string("WinTun adapter manager init failed: ") + e.what();
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        return;
    }

    std::wstring wname  = Utf8ToWide(opts_.adapter_name);
    std::wstring wtype  = Utf8ToWide(opts_.tunnel_type);

    try {
        adapter_.emplace(mgr_->Create(wname, wtype));
    } catch (const std::exception& e) {
        last_error_ = std::string("WinTun adapter Create failed: ") + e.what();
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        adapter_.reset();
        mgr_.reset();
        return;
    }

    try {
        mgr_->ConfigureIpv4(*adapter_, host_ip_be_, opts_.prefix_len, 1500);
    } catch (const std::exception& e) {
        last_error_ = std::string("WinTun adapter ConfigureIpv4 failed: ") + e.what();
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        try { mgr_->Destroy(*adapter_); } catch (...) {}
        adapter_.reset();
        mgr_.reset();
        return;
    }

    try {
        session_.emplace(mgr_->OpenSession(*adapter_, opts_.ring_capacity));
    } catch (const std::system_error& e) {
        last_error_ = std::string("wintun::session::open failed: ") + e.what();
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        ExplainWintunSessionAccessDenied(e, "[wintun-net]");
        try { mgr_->Destroy(*adapter_); } catch (...) {}
        adapter_.reset();
        mgr_.reset();
        return;
    } catch (const std::exception& e) {
        // mgr_->OpenSession on the SVC path raises HrError on transport /
        // service failures; treat those the same as a session::open
        // failure so we don't leak the adapter.
        last_error_ = std::string("wintun OpenSession failed: ") + e.what();
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        try { mgr_->Destroy(*adapter_); } catch (...) {}
        adapter_.reset();
        mgr_.reset();
        return;
    }
    wintun_read_evt_ = session_->read_wait_event();

    tx_doorbell_ = transport.InstallQueueDoorbell(partition, kTxQueueIdx);
    rx_doorbell_ = transport.InstallQueueDoorbell(partition, kRxQueueIdx);
    stop_evt_ = ::CreateEventW(nullptr, /*manual*/TRUE,
                               /*initial*/FALSE, nullptr);
    if (!stop_evt_) {
        last_error_ = "CreateEvent(stop) failed: " +
                      net::FormatWindowsError(::GetLastError());
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        session_.reset();
        try { mgr_->Destroy(*adapter_); } catch (...) {}
        adapter_.reset();
        mgr_.reset();
        return;
    }

    ready_ = true;
    running_.store(true);
    worker_ = std::thread([this] { WorkerLoop(); });

    std::printf("[wintun-net] up: backend=%s adapter=\"%s\" host=%s/%u "
                "backend_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                mgr_->backend_label(),
                opts_.adapter_name.c_str(),
                opts_.host_ipv4.c_str(),
                static_cast<unsigned>(opts_.prefix_len),
                opts_.backend_mac[0], opts_.backend_mac[1],
                opts_.backend_mac[2], opts_.backend_mac[3],
                opts_.backend_mac[4], opts_.backend_mac[5]);
    TINYVMM_ETW_INFO_KW("NetBackendStart", ::tinyvmm::diag::kw::Lifecycle,
        TraceLoggingString(mgr_->backend_label(),  "backend"),
        TraceLoggingString(opts_.adapter_name.c_str(), "adapter"),
        TraceLoggingString(opts_.host_ipv4.c_str(),    "host_ipv4"),
        TraceLoggingUInt8(opts_.prefix_len,           "prefix_len"));
}

void WintunNetBackend::Stop() {
    TINYVMM_ETW_INFO_KW("NetBackendStop", ::tinyvmm::diag::kw::Lifecycle,
        TraceLoggingString("wintun", "backend"),
        TraceLoggingUInt64(tx_packets_.load(std::memory_order_relaxed), "tx_packets"),
        TraceLoggingUInt64(rx_packets_.load(std::memory_order_relaxed), "rx_packets"),
        TraceLoggingUInt64(tx_dropped_.load(std::memory_order_relaxed), "tx_dropped"),
        TraceLoggingUInt64(rx_dropped_.load(std::memory_order_relaxed), "rx_dropped"));
    if (running_.exchange(false)) {
        if (stop_evt_) ::SetEvent(stop_evt_);
        if (worker_.joinable()) worker_.join();
    } else if (worker_.joinable()) {
        worker_.join();
    }
    if (stop_evt_) { ::CloseHandle(stop_evt_); stop_evt_ = nullptr; }

    // Release any wintun-owned pending RX spans before tearing down the
    // session; once the session is reset the ring memory is unmapped and
    // releasing afterwards is meaningless.
    while (!pending_rx_.empty()) {
        auto& p = pending_rx_.front();
        if (session_ && !p.wintun_payload.empty()) {
            session_->release_receive_packet(p.wintun_payload);
        }
        pending_rx_.pop_front();
    }

    // Session close *before* adapter destroy: if we're using wintunsvc,
    // destroying the adapter via the service will tear down the rings
    // from the service-side handle as a side effect, and our session
    // would observe ERROR_HANDLE_EOF. Closing locally first is cleaner.
    session_.reset();
    wintun_read_evt_ = nullptr;

    if (mgr_ && adapter_) {
        try {
            mgr_->Destroy(*adapter_);
        } catch (const std::exception& e) {
            std::fprintf(stderr,
                         "[wintun-net] Destroy adapter warning: %s\n", e.what());
        }
    }
    adapter_.reset();
    mgr_.reset();

    xport_ = nullptr;
    ready_ = false;
}

void WintunNetBackend::OnQueueNotify(std::uint32_t /*qidx*/) {
    // Doorbells suppress these in steady state. If one does slip
    // through (initial setup races), the worker will pick it up.
}

void WintunNetBackend::WorkerLoop() {
    constexpr DWORD kWaitCount = 4;
    HANDLE waits[kWaitCount] = {
        stop_evt_, tx_doorbell_, rx_doorbell_, wintun_read_evt_};

    while (running_.load()) {
        DWORD wr = ::WaitForMultipleObjectsEx(kWaitCount, waits,
                                              FALSE, 5, FALSE);
        if (wr == WAIT_OBJECT_0) break;

        DrainTx();
        DeliverRx();
    }
}

void WintunNetBackend::DrainTx() {
    auto& tx = net_.tx_queue();
    if (!tx.ready()) return;

    bool any = false;
    // Peek buffer holds the vhdr + Eth header so we can route on
    // ethertype without materializing the whole frame.
    constexpr std::size_t kHeadSize = kVirtioNetHdrSize + kEthHdrSize;
    std::array<std::uint8_t, kHeadSize> head{};

    while (auto chain = tx.Pop()) {
        const auto summary = SummarizeReadable(*chain, head);
        tx.Push(chain->head_index, 0);
        any = true;

        if (summary.total < kHeadSize) {
            TINYVMM_ETW_VERBOSE_KW("NetTxDrop", ::tinyvmm::diag::kw::Net,
                TraceLoggingString("wintun",                                "backend"),
                TraceLoggingString("short",                                 "reason"),
                TraceLoggingUInt32(static_cast<std::uint32_t>(summary.total), "bytes"));
            tx_dropped_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const std::size_t ip_bytes = summary.total - kHeadSize;
        if (ip_bytes > wintun::max_ip_packet_size) {
            TINYVMM_ETW_VERBOSE_KW("NetTxDrop", ::tinyvmm::diag::kw::Net,
                TraceLoggingString("wintun",                                "backend"),
                TraceLoggingString("oversized",                             "reason"),
                TraceLoggingUInt32(static_cast<std::uint32_t>(summary.total), "bytes"));
            tx_dropped_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        EthHeader eh{};
        std::memcpy(&eh, head.data() + kVirtioNetHdrSize, sizeof(eh));
        const std::uint16_t etype = Be16(std::span{eh.ether_type_be});
        TINYVMM_ETW_VERBOSE_KW("NetTx", ::tinyvmm::diag::kw::Net,
            TraceLoggingString("wintun",                                  "backend"),
            TraceLoggingUInt32(static_cast<std::uint32_t>(summary.total), "bytes"),
            TraceLoggingUInt16(etype,                                     "ethertype"));

        if (etype == kEthTypeArp) {
            // ARP is rare and tiny; materialize Eth + ARP for HandleArp.
            const std::size_t eth_total = summary.total - kVirtioNetHdrSize;
            std::vector<std::uint8_t> frame(eth_total);
            CopyReadable(*chain, kVirtioNetHdrSize, frame);
            HandleArp(frame);
        } else if (etype == kEthTypeIp4) {
            if (ip_bytes == 0) {
                tx_dropped_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            if (SendIpFromChainToWintun(*chain, ip_bytes)) {
                tx_packets_.fetch_add(1, std::memory_order_relaxed);
            } else {
                tx_dropped_.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            // IPv6 / 802.1Q / LLDP / etc. -> drop.
            tx_dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    if (any && xport_) xport_->RaiseQueueInterrupt(kTxQueueIdx);
}

void WintunNetBackend::HandleArp(std::span<const std::uint8_t> eth_frame) {
    if (eth_frame.size() < kEthHdrSize + sizeof(ArpIpv4)) return;

    ArpIpv4 req{};
    std::memcpy(&req, eth_frame.data() + kEthHdrSize, sizeof(req));

    const std::uint16_t htype  = Be16(std::span{req.htype_be});
    const std::uint16_t ptype  = Be16(std::span{req.ptype_be});
    const std::uint16_t opcode = Be16(std::span{req.opcode_be});
    if (htype != 1 || ptype != kEthTypeIp4 || req.hlen != 6 || req.plen != 4) {
        return;
    }
    if (opcode != 1) return;  // only respond to requests

    std::uint32_t tpa_be = 0;
    std::memcpy(&tpa_be, req.tpa, 4);
    if (tpa_be != host_ip_be_) return;       // not our gateway IP

    if (pending_rx_.size() >= kPendingRxCap) {
        rx_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    PendingRx entry{};
    EthHeader eh{};
    std::memcpy(eh.dst, req.sha, 6);                          // -> guest
    std::memcpy(eh.src, opts_.backend_mac.data(), 6);         // <- backend
    Wr16Be(std::span{eh.ether_type_be}, kEthTypeArp);
    std::memcpy(entry.eth_hdr.data(), &eh, sizeof(eh));

    ArpIpv4 rep{};
    Wr16Be(std::span{rep.htype_be},  1);
    Wr16Be(std::span{rep.ptype_be},  kEthTypeIp4);
    rep.hlen = 6;
    rep.plen = 4;
    Wr16Be(std::span{rep.opcode_be}, 2);                      // reply
    std::memcpy(rep.sha, opts_.backend_mac.data(), 6);        // sha = us
    std::memcpy(rep.spa, &host_ip_be_, 4);                    // spa = host IP
    std::memcpy(rep.tha, req.sha, 6);                         // tha = guest MAC
    std::memcpy(rep.tpa, req.spa, 4);                         // tpa = guest IP
    entry.owned_payload.resize(sizeof(rep));
    std::memcpy(entry.owned_payload.data(), &rep, sizeof(rep));

    pending_rx_.push_back(std::move(entry));
    arp_replies_.fetch_add(1, std::memory_order_relaxed);
}

bool WintunNetBackend::SendIpFromChainToWintun(const PoppedChain& chain,
                                                std::size_t ip_bytes) {
    if (!session_) return false;
    if (ip_bytes == 0 || ip_bytes > wintun::max_ip_packet_size) return false;
    wintun::status st = wintun::status::ok;
    auto buf = session_->allocate_send_packet(
        static_cast<std::uint32_t>(ip_bytes), st);
    if (st != wintun::status::ok || buf.empty()) {
        if (st == wintun::status::eof) {
            std::fprintf(stderr,
                         "[wintun-net] session EOF on send; stopping worker\n");
            running_.store(false);
        }
        return false;
    }
    // Zero-copy: scatter-gather from guest descriptors directly into the
    // wintun ring slot, skipping the leading vhdr (12B) + Eth header (14B).
    std::span<std::uint8_t> dst{
        reinterpret_cast<std::uint8_t*>(buf.data()), buf.size()};
    const std::size_t got = CopyReadable(
        chain, kVirtioNetHdrSize + kEthHdrSize, dst);
    if (got != ip_bytes) {
        // SummarizeReadable already validated sizes; this is defense in
        // depth against a logic bug rather than a guest-driven path. We
        // still must commit the slot to keep the ring producer head
        // monotone, but signal the truncation upstream.
        session_->send_packet(buf);
        return false;
    }
    session_->send_packet(buf);
    return true;
}

void WintunNetBackend::DeliverRx() {
    if (!session_) return;

    // Drain WinTun's RX ring into pending_rx_ until we hit the queue
    // cap. Slots stay reserved in wintun until we deliver to the guest
    // and call release_receive_packet (zero-copy RX path).
    for (;;) {
        if (pending_rx_.size() >= kPendingRxCap) break;
        wintun::status st = wintun::status::ok;
        auto pkt = session_->receive_packet(st);
        if (st == wintun::status::empty) break;
        if (st == wintun::status::eof) {
            std::fprintf(stderr,
                         "[wintun-net] session EOF on recv; stopping worker\n");
            running_.store(false);
            break;
        }
        if (st == wintun::status::invalid_data) {
            // Clean-room session does NOT advance head on invalid_data;
            // continuing would spin forever. Tear down.
            std::fprintf(stderr,
                         "[wintun-net] session reported invalid_data; "
                         "ring is corrupt -- stopping worker\n");
            running_.store(false);
            break;
        }
        if (st != wintun::status::ok || pkt.empty()) break;

        // WinTun gives us an L3 packet. We need an L2 frame, so
        // prepend an Ethernet header. Detect IPv4 vs IPv6 by version
        // nibble; IPv6 we currently drop.
        const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(pkt.data());
        const std::size_t   sz = pkt.size();
        const std::uint8_t version = (sz > 0) ? (p[0] >> 4) : 0;
        if (version != 4) {
            rx_dropped_.fetch_add(1, std::memory_order_relaxed);
            session_->release_receive_packet(pkt);
            continue;
        }
        PendingRx entry{};
        EthHeader eh{};
        std::memcpy(eh.dst, net_.mac().data(), 6);         // dst = guest
        std::memcpy(eh.src, opts_.backend_mac.data(), 6);  // src = backend
        Wr16Be(std::span{eh.ether_type_be}, kEthTypeIp4);
        std::memcpy(entry.eth_hdr.data(), &eh, sizeof(eh));
        // Retain the wintun ring slot; we release after guest delivery.
        entry.wintun_payload = pkt;
        pending_rx_.push_back(std::move(entry));
    }

    // Try to land pending packets into guest rxq buffers.
    auto& rx = net_.rx_queue();
    if (!rx.ready()) return;

    bool any = false;
    while (!pending_rx_.empty()) {
        auto chain = rx.Pop();
        if (!chain) break;  // No buffers; leave packets pending.

        auto& entry = pending_rx_.front();
        // Pick the payload source for this entry. Exactly one is non-empty.
        const std::uint8_t* payload_ptr = nullptr;
        std::size_t         payload_sz  = 0;
        if (!entry.wintun_payload.empty()) {
            payload_ptr = reinterpret_cast<const std::uint8_t*>(
                entry.wintun_payload.data());
            payload_sz  = entry.wintun_payload.size();
        } else {
            payload_ptr = entry.owned_payload.data();
            payload_sz  = entry.owned_payload.size();
        }

        // Scatter: vhdr (12B zeros) | eth_hdr (14B) | payload, directly
        // into the guest's writable descriptors.
        std::size_t hdr_remaining = kVirtioNetHdrSize;
        std::size_t eth_off       = 0;
        std::size_t pkt_off       = 0;
        std::uint32_t total       = 0;

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
            if (!dst.empty() && eth_off < entry.eth_hdr.size()) {
                const std::size_t take = std::min(
                    dst.size(), entry.eth_hdr.size() - eth_off);
                std::memcpy(dst.data(), entry.eth_hdr.data() + eth_off, take);
                dst = dst.subspan(take);
                eth_off += take;
                total += static_cast<std::uint32_t>(take);
            }
            if (!dst.empty() && pkt_off < payload_sz) {
                const std::size_t take = std::min(dst.size(), payload_sz - pkt_off);
                std::memcpy(dst.data(), payload_ptr + pkt_off, take);
                pkt_off += take;
                total += static_cast<std::uint32_t>(take);
            }
            if (hdr_remaining == 0
                && eth_off == entry.eth_hdr.size()
                && pkt_off == payload_sz) {
                break;
            }
        }
        const bool truncated = (pkt_off < payload_sz)
                            || (eth_off < entry.eth_hdr.size())
                            || (hdr_remaining > 0);
        if (truncated) {
            rx_dropped_.fetch_add(1, std::memory_order_relaxed);
        } else {
            rx_packets_.fetch_add(1, std::memory_order_relaxed);
        }
        TINYVMM_ETW_VERBOSE_KW("NetRx", ::tinyvmm::diag::kw::Net,
            TraceLoggingString("wintun",                  "backend"),
            TraceLoggingUInt32(total,                      "bytes"),
            TraceLoggingUInt8(truncated ? 1u : 0u,         "truncated"));
        rx.Push(chain->head_index, total);

        // Release the wintun ring slot now that the payload has been
        // copied into the guest. We must release whether or not we
        // truncated, so wintun's consumer head keeps advancing.
        if (session_ && !entry.wintun_payload.empty()) {
            session_->release_receive_packet(entry.wintun_payload);
        }
        pending_rx_.pop_front();
        any = true;
    }
    if (any && xport_) xport_->RaiseQueueInterrupt(kRxQueueIdx);
}

}  // namespace tinyvmm::virtio

namespace tinyvmm {

int RunWintunProbe(int seconds) {
    using namespace tinyvmm::net;

    // Always try to load the DLL first — useful diagnostic even when
    // we lack the privilege to actually create an adapter.
    std::string err;
    const auto& api = LoadWintunApi(&err);
    if (!api.Available()) {
        std::fprintf(stderr, "[wintun-probe] FAIL: %s\n", err.c_str());
        return 1;
    }
    DWORD ver = api.GetRunningDriverVersion();
    std::printf("[wintun-probe] wintun.dll loaded; running driver version 0x%08lx%s\n",
                ver, ver == 0 ? " (driver not yet loaded into kernel)" : "");

    if (!IsProcessElevated()) {
        std::fprintf(stderr,
            "[wintun-probe] cannot create adapter without elevation; "
            "DLL load OK, run from an elevated shell to exercise the driver.\n");
        return 1;
    }

    const wchar_t* name = L"tinyvmm-probe";
    WINTUN_ADAPTER_HANDLE adapter =
        api.CreateAdapter(name, L"tinyvmm", nullptr);
    if (!adapter) {
        std::fprintf(stderr, "[wintun-probe] WintunCreateAdapter failed: %s\n",
                     FormatWindowsError(::GetLastError()).c_str());
        return 1;
    }
    std::printf("[wintun-probe] adapter \"tinyvmm-probe\" created\n");

    NET_LUID luid{};
    api.GetAdapterLuid(adapter, &luid);

    MIB_UNICASTIPADDRESS_ROW row{};
    ::InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    row.Address.si_family = AF_INET;
    row.Address.Ipv4.sin_family = AF_INET;
    ::InetPtonA(AF_INET, "10.0.0.1", &row.Address.Ipv4.sin_addr);
    row.OnLinkPrefixLength = 24;
    row.DadState = IpDadStatePreferred;
    DWORD rc = ::CreateUnicastIpAddressEntry(&row);
    if (rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS) {
        std::fprintf(stderr,
            "[wintun-probe] CreateUnicastIpAddressEntry failed: %s\n",
            FormatWindowsError(rc).c_str());
        api.CloseAdapter(adapter);
        return 1;
    }
    std::printf("[wintun-probe] adapter IP set to 10.0.0.1/24\n");

    // Drive the clean-room session for the actual RX loop, so the
    // probe also exercises the same code the runtime backend uses.
    std::wstring device_path;
    try {
        device_path = FindWintunDevicePathByLuid(luid);
    } catch (const std::exception& e) {
        std::fprintf(stderr,
                     "[wintun-probe] FindWintunDevicePathByLuid failed: %s\n",
                     e.what());
        ::DeleteUnicastIpAddressEntry(&row);
        api.CloseAdapter(adapter);
        return 1;
    }

    std::optional<wintun::session> sess;
    try {
        sess.emplace(wintun::session::open(device_path, 4 * 1024 * 1024));
    } catch (const std::exception& e) {
        std::fprintf(stderr,
                     "[wintun-probe] wintun::session::open failed: %s\n",
                     e.what());
        ::DeleteUnicastIpAddressEntry(&row);
        api.CloseAdapter(adapter);
        return 1;
    }
    HANDLE evt = sess->read_wait_event();

    std::printf("[wintun-probe] listening for %d seconds... "
                "try `ping 10.0.0.1` from another shell\n", seconds);
    const ULONGLONG start = ::GetTickCount64();
    const ULONGLONG deadline = start + static_cast<ULONGLONG>(seconds) * 1000ull;
    int total = 0;
    for (;;) {
        const ULONGLONG now = ::GetTickCount64();
        if (now >= deadline) break;
        const ULONGLONG remaining = deadline - now;
        const DWORD wait_ms =
            (remaining > 500ull) ? DWORD{500} : static_cast<DWORD>(remaining);
        DWORD wr = ::WaitForSingleObject(evt, wait_ms);
        if (wr != WAIT_OBJECT_0 && wr != WAIT_TIMEOUT) break;
        for (;;) {
            wintun::status st = wintun::status::ok;
            auto pkt = sess->receive_packet(st);
            if (st == wintun::status::empty) break;
            if (st == wintun::status::eof ||
                st == wintun::status::invalid_data) {
                std::fprintf(stderr,
                             "[wintun-probe] session terminated (st=%u)\n",
                             static_cast<unsigned>(st));
                break;
            }
            if (st != wintun::status::ok || pkt.empty()) break;
            ++total;
            const std::uint8_t* p =
                reinterpret_cast<const std::uint8_t*>(pkt.data());
            const std::size_t   sz = pkt.size();
            if (sz >= 20 && (p[0] >> 4) == 4) {
                std::printf("[wintun-probe] rx %zu bytes: IPv4 "
                            "%u.%u.%u.%u -> %u.%u.%u.%u proto=%u\n",
                            sz, p[12], p[13], p[14], p[15],
                            p[16], p[17], p[18], p[19], p[9]);
            } else if (sz >= 40 && (p[0] >> 4) == 6) {
                std::printf("[wintun-probe] rx %zu bytes: IPv6 next-hdr=%u\n",
                            sz, p[6]);
            } else {
                std::printf("[wintun-probe] rx %zu bytes (non-IP)\n", sz);
            }
            sess->release_receive_packet(pkt);
        }
    }
    std::printf("[wintun-probe] %d packets received\n", total);

    sess.reset();
    ::DeleteUnicastIpAddressEntry(&row);
    api.CloseAdapter(adapter);
    std::printf("[wintun-probe] adapter removed; PASS\n");
    return 0;
}

int RunWintunSvcProbe(int seconds) {
    using namespace tinyvmm::net;

    std::printf("[wintun-svc-probe] connecting to \\\\.\\pipe\\wintunsvc ...\n");
    std::unique_ptr<WintunAdapterManager> mgr;
    try {
        mgr = MakeWintunSvcManager();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[wintun-svc-probe] FAIL: %s\n", e.what());
        return 1;
    }

    WintunAdapter adapter{};
    try {
        adapter = mgr->Create(L"tinyvmm-probe", L"tinyvmm");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[wintun-svc-probe] Create failed: %s\n",
                     e.what());
        return 1;
    }
    std::printf("[wintun-svc-probe] adapter created via service; "
                "luid=0x%016llx\n",
                static_cast<unsigned long long>(adapter.luid.Value));
    std::wprintf(L"[wintun-svc-probe] device path: %ls\n",
                 adapter.device_path.c_str());

    std::uint32_t ip_be = 0;
    ::InetPtonA(AF_INET, "10.0.0.1", &ip_be);

    try {
        mgr->ConfigureIpv4(adapter, ip_be, 24, 1500);
    } catch (const std::exception& e) {
        std::fprintf(stderr,
                     "[wintun-svc-probe] ConfigureIpv4 failed: %s\n", e.what());
        try { mgr->Destroy(adapter); } catch (...) {}
        return 1;
    }
    std::printf("[wintun-svc-probe] adapter IP set to 10.0.0.1/24\n");

    std::optional<wintun::session> sess2;
    try {
        sess2.emplace(mgr->OpenSession(adapter, 4 * 1024 * 1024));
    } catch (const std::system_error& e) {
        std::fprintf(stderr,
                     "[wintun-svc-probe] OpenSession failed: %s\n",
                     e.what());
        ExplainWintunSessionAccessDenied(e, "[wintun-svc-probe]");
        try { mgr->Destroy(adapter); } catch (...) {}
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr,
                     "[wintun-svc-probe] OpenSession failed: %s\n",
                     e.what());
        try { mgr->Destroy(adapter); } catch (...) {}
        return 1;
    }
    HANDLE evt2 = sess2->read_wait_event();

    std::printf("[wintun-svc-probe] listening for %d seconds... "
                "try `ping 10.0.0.1` from another shell\n", seconds);
    const ULONGLONG start2 = ::GetTickCount64();
    const ULONGLONG deadline2 =
        start2 + static_cast<ULONGLONG>(seconds) * 1000ull;
    int total2 = 0;
    for (;;) {
        const ULONGLONG now = ::GetTickCount64();
        if (now >= deadline2) break;
        const ULONGLONG remaining = deadline2 - now;
        const DWORD wait_ms =
            (remaining > 500ull) ? DWORD{500} : static_cast<DWORD>(remaining);
        DWORD wr = ::WaitForSingleObject(evt2, wait_ms);
        if (wr != WAIT_OBJECT_0 && wr != WAIT_TIMEOUT) break;
        for (;;) {
            wintun::status st = wintun::status::ok;
            auto pkt = sess2->receive_packet(st);
            if (st == wintun::status::empty) break;
            if (st == wintun::status::eof ||
                st == wintun::status::invalid_data) {
                std::fprintf(stderr,
                    "[wintun-svc-probe] session terminated (st=%u)\n",
                    static_cast<unsigned>(st));
                break;
            }
            if (st != wintun::status::ok || pkt.empty()) break;
            ++total2;
            const std::uint8_t* p =
                reinterpret_cast<const std::uint8_t*>(pkt.data());
            const std::size_t sz = pkt.size();
            if (sz >= 20 && (p[0] >> 4) == 4) {
                std::printf("[wintun-svc-probe] rx %zu bytes: IPv4 "
                            "%u.%u.%u.%u -> %u.%u.%u.%u proto=%u\n",
                            sz, p[12], p[13], p[14], p[15],
                            p[16], p[17], p[18], p[19], p[9]);
            } else if (sz >= 40 && (p[0] >> 4) == 6) {
                std::printf("[wintun-svc-probe] rx %zu bytes: IPv6 next-hdr=%u\n",
                            sz, p[6]);
            } else {
                std::printf("[wintun-svc-probe] rx %zu bytes (non-IP)\n", sz);
            }
            sess2->release_receive_packet(pkt);
        }
    }
    std::printf("[wintun-svc-probe] %d packets received\n", total2);

    sess2.reset();
    try { mgr->Destroy(adapter); } catch (...) {}
    std::printf("[wintun-svc-probe] adapter removed; PASS\n");
    return 0;
}

}  // namespace tinyvmm
