#include "net_wintun.h"

#include "virtio_pci.h"

#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace tinyvmm::virtio {

namespace {

constexpr std::size_t kVirtioNetHdrSize = 12;
constexpr std::size_t kEthHdrSize       = 14;
constexpr std::uint16_t kEthTypeIp4     = 0x0800;
constexpr std::uint16_t kEthTypeIp6     = 0x86DD;
constexpr std::uint16_t kEthTypeArp     = 0x0806;

std::uint16_t Be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}
void Wr16Be(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xFF);
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                  static_cast<int>(s.size()),
                                  nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                          w.data(), n);
    return w;
}

bool ParseIpv4(const std::string& s, std::uint32_t* out_be) {
    IN_ADDR a{};
    if (::InetPtonA(AF_INET, s.c_str(), &a) != 1) return false;
    *out_be = a.s_addr;  // already network byte order
    return true;
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

    if (!net::IsProcessElevated()) {
        last_error_ =
            "WinTun backend requires admin/elevated privileges to create "
            "a TUN adapter. Re-run from an elevated PowerShell.";
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        return;
    }

    std::string load_err;
    const auto& api = net::LoadWintunApi(&load_err);
    if (!api.Available()) {
        last_error_ = "WinTun DLL not loadable: " + load_err;
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        return;
    }
    api_ = &api;

    if (!ParseIpv4(opts_.host_ipv4, &host_ip_be_)) {
        last_error_ = "Invalid host_ipv4: " + opts_.host_ipv4;
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        return;
    }

    std::wstring wname  = Utf8ToWide(opts_.adapter_name);
    std::wstring wtype  = Utf8ToWide(opts_.tunnel_type);
    adapter_ = api_->CreateAdapter(wname.c_str(), wtype.c_str(), nullptr);
    if (!adapter_) {
        last_error_ = "WintunCreateAdapter failed: " +
                      net::FormatWindowsError(::GetLastError());
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        return;
    }
    api_->GetAdapterLuid(adapter_, &adapter_luid_);

    if (!ConfigureAdapterIp()) {
        CleanupAdapter();
        return;
    }
    adapter_ip_set_ = true;

    session_ = api_->StartSession(adapter_, opts_.ring_capacity);
    if (!session_) {
        last_error_ = "WintunStartSession failed: " +
                      net::FormatWindowsError(::GetLastError());
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        CleanupAdapter();
        return;
    }
    wintun_read_evt_ = api_->GetReadWaitEvent(session_);

    tx_doorbell_ = transport.InstallQueueDoorbell(partition, kTxQueueIdx);
    rx_doorbell_ = transport.InstallQueueDoorbell(partition, kRxQueueIdx);
    stop_evt_ = ::CreateEventW(nullptr, /*manual*/TRUE,
                               /*initial*/FALSE, nullptr);
    if (!stop_evt_) {
        last_error_ = "CreateEvent(stop) failed: " +
                      net::FormatWindowsError(::GetLastError());
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        api_->EndSession(session_);
        session_ = nullptr;
        CleanupAdapter();
        return;
    }

    ready_ = true;
    running_.store(true);
    worker_ = std::thread([this] { WorkerLoop(); });

    std::printf("[wintun-net] up: adapter=\"%s\" host=%s/%u backend_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                opts_.adapter_name.c_str(),
                opts_.host_ipv4.c_str(),
                static_cast<unsigned>(opts_.prefix_len),
                opts_.backend_mac[0], opts_.backend_mac[1],
                opts_.backend_mac[2], opts_.backend_mac[3],
                opts_.backend_mac[4], opts_.backend_mac[5]);
}

void WintunNetBackend::Stop() {
    if (running_.exchange(false)) {
        if (stop_evt_) ::SetEvent(stop_evt_);
        if (worker_.joinable()) worker_.join();
    } else if (worker_.joinable()) {
        worker_.join();
    }
    if (stop_evt_) { ::CloseHandle(stop_evt_); stop_evt_ = nullptr; }

    if (api_ && session_) {
        api_->EndSession(session_);
        session_ = nullptr;
        wintun_read_evt_ = nullptr;
    }
    CleanupAdapter();
    xport_ = nullptr;
    ready_ = false;
    pending_rx_.clear();
}

void WintunNetBackend::OnQueueNotify(std::uint32_t /*qidx*/) {
    // Doorbells suppress these in steady state. If one does slip
    // through (initial setup races), the worker will pick it up.
}

void WintunNetBackend::CleanupAdapter() {
    if (!api_) return;

    if (adapter_ && adapter_ip_set_) {
        MIB_UNICASTIPADDRESS_ROW row{};
        ::InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = adapter_luid_;
        row.Address.si_family = AF_INET;
        row.Address.Ipv4.sin_family = AF_INET;
        row.Address.Ipv4.sin_addr.s_addr = host_ip_be_;
        ::DeleteUnicastIpAddressEntry(&row);
        adapter_ip_set_ = false;
    }
    if (adapter_) {
        api_->CloseAdapter(adapter_);
        adapter_ = nullptr;
    }
}

bool WintunNetBackend::ConfigureAdapterIp() {
    MIB_UNICASTIPADDRESS_ROW row{};
    ::InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = adapter_luid_;
    row.Address.si_family = AF_INET;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.s_addr = host_ip_be_;
    row.OnLinkPrefixLength = opts_.prefix_len;
    row.DadState = IpDadStatePreferred;

    DWORD rc = ::CreateUnicastIpAddressEntry(&row);
    if (rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS) {
        last_error_ = "CreateUnicastIpAddressEntry failed: " +
                      net::FormatWindowsError(rc);
        std::fprintf(stderr, "[wintun-net] %s\n", last_error_.c_str());
        return false;
    }

    MIB_IPINTERFACE_ROW ifrow{};
    ::InitializeIpInterfaceEntry(&ifrow);
    ifrow.Family = AF_INET;
    ifrow.InterfaceLuid = adapter_luid_;
    if (::GetIpInterfaceEntry(&ifrow) == NO_ERROR) {
        ifrow.NlMtu = 1500;
        ifrow.SitePrefixLength = 0;
        ifrow.UseAutomaticMetric = FALSE;
        ifrow.Metric = 1;
        DWORD rc2 = ::SetIpInterfaceEntry(&ifrow);
        if (rc2 != NO_ERROR) {
            std::fprintf(stderr,
                         "[wintun-net] SetIpInterfaceEntry warning: %s\n",
                         net::FormatWindowsError(rc2).c_str());
        }
    }
    return true;
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
    std::vector<std::uint8_t> frame;
    frame.reserve(1600);

    while (auto chain = tx.Pop()) {
        // Coalesce readable buffers, skipping the leading 12-byte
        // virtio_net_hdr. What remains is one Ethernet frame.
        frame.clear();
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
                frame.insert(frame.end(), p, p + len);
            }
        }
        tx.Push(chain->head_index, 0);
        any = true;

        if (frame.size() < kEthHdrSize) {
            tx_dropped_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const std::uint16_t etype = Be16(frame.data() + 12);
        if (etype == kEthTypeArp) {
            HandleArp(frame.data(), frame.size());
            // ARP is "tx" from guest POV but we never send it to
            // WinTun. Don't count as tx_dropped either.
        } else if (etype == kEthTypeIp4) {
            const std::uint8_t* ip = frame.data() + kEthHdrSize;
            std::size_t ip_len = frame.size() - kEthHdrSize;
            if (SendIpToWintun(ip, ip_len)) {
                tx_packets_.fetch_add(1, std::memory_order_relaxed);
            } else {
                tx_dropped_.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            // IPv6 or anything exotic -> drop silently.
            tx_dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    if (any && xport_) xport_->RaiseQueueInterrupt(kTxQueueIdx);
}

void WintunNetBackend::HandleArp(const std::uint8_t* eth, std::size_t len) {
    if (len < kEthHdrSize + 28) return;
    const std::uint8_t* arp = eth + kEthHdrSize;
    const std::uint16_t htype  = Be16(arp + 0);
    const std::uint16_t ptype  = Be16(arp + 2);
    const std::uint8_t  hlen   = arp[4];
    const std::uint8_t  plen   = arp[5];
    const std::uint16_t opcode = Be16(arp + 6);
    if (htype != 1 || ptype != kEthTypeIp4 || hlen != 6 || plen != 4) return;
    if (opcode != 1) return;  // only respond to requests

    const std::uint8_t* sha = arp + 8;       // sender MAC (guest)
    const std::uint8_t* spa = arp + 14;      // sender IP  (guest)
    const std::uint8_t* tpa = arp + 24;      // target IP  (asked for)

    std::uint32_t tpa_be = 0;
    std::memcpy(&tpa_be, tpa, 4);
    if (tpa_be != host_ip_be_) return;       // not our gateway IP

    // Build reply directly into a new pending_rx_ entry.
    std::vector<std::uint8_t> reply(kEthHdrSize + 28);
    auto* p = reply.data();

    // Ethernet header: dst=guest MAC, src=backend MAC, type=ARP.
    std::memcpy(p + 0, sha, 6);
    std::memcpy(p + 6, opts_.backend_mac.data(), 6);
    Wr16Be(p + 12, kEthTypeArp);

    // ARP body.
    Wr16Be(p + 14, 1);                 // htype
    Wr16Be(p + 16, kEthTypeIp4);       // ptype
    p[18] = 6;                          // hlen
    p[19] = 4;                          // plen
    Wr16Be(p + 20, 2);                  // opcode = reply
    std::memcpy(p + 22, opts_.backend_mac.data(), 6);  // sha = us
    std::memcpy(p + 28, &host_ip_be_, 4);              // spa = host IP
    std::memcpy(p + 32, sha, 6);                       // tha = guest MAC
    std::memcpy(p + 38, spa, 4);                       // tpa = guest IP

    pending_rx_.push_back(std::move(reply));
    arp_replies_.fetch_add(1, std::memory_order_relaxed);
}

bool WintunNetBackend::SendIpToWintun(const std::uint8_t* ip_pkt,
                                       std::size_t len) {
    if (!api_ || !session_) return false;
    if (len == 0 || len > WINTUN_MAX_IP_PACKET_SIZE) return false;
    BYTE* dst = api_->AllocateSendPacket(session_,
                                          static_cast<DWORD>(len));
    if (!dst) return false;
    std::memcpy(dst, ip_pkt, len);
    api_->SendPacket(session_, dst);
    return true;
}

void WintunNetBackend::DeliverRx() {
    if (!api_ || !session_) return;

    // Drain WinTun's RX ring into pending_rx_.
    for (;;) {
        DWORD pkt_size = 0;
        BYTE* p = api_->ReceivePacket(session_, &pkt_size);
        if (!p) {
            DWORD e = ::GetLastError();
            if (e == ERROR_NO_MORE_ITEMS) break;
            if (e == ERROR_HANDLE_EOF) { running_.store(false); break; }
            if (e == ERROR_INVALID_DATA) continue;
            break;
        }
        // WinTun gives us an L3 packet. We need an L2 frame, so
        // prepend an Ethernet header. Detect IPv4 vs IPv6 by version
        // nibble; IPv6 we currently drop.
        const std::uint8_t version = (pkt_size > 0) ? (p[0] >> 4) : 0;
        if (version == 4) {
            std::vector<std::uint8_t> frame(kEthHdrSize + pkt_size);
            std::memcpy(frame.data() + 0, net_.mac().data(), 6);          // dst = guest
            std::memcpy(frame.data() + 6, opts_.backend_mac.data(), 6);   // src = backend
            Wr16Be(frame.data() + 12, kEthTypeIp4);
            std::memcpy(frame.data() + kEthHdrSize, p, pkt_size);
            pending_rx_.push_back(std::move(frame));
        } else {
            rx_dropped_.fetch_add(1, std::memory_order_relaxed);
        }
        api_->ReleaseReceivePacket(session_, p);
    }

    // Try to land pending packets into guest rxq buffers.
    auto& rx = net_.rx_queue();
    if (!rx.ready()) return;

    bool any = false;
    while (!pending_rx_.empty()) {
        auto chain = rx.Pop();
        if (!chain) break;  // No buffers; leave packets pending.

        auto& pkt = pending_rx_.front();
        std::size_t hdr_remaining = kVirtioNetHdrSize;
        std::size_t pkt_off = 0;
        std::uint32_t total = 0;

        for (auto& b : chain->bufs) {
            if (!b.write) continue;
            std::uint8_t* dp = static_cast<std::uint8_t*>(b.host_addr);
            std::size_t avail = b.len;
            if (hdr_remaining > 0 && avail > 0) {
                const std::size_t take = std::min(avail, hdr_remaining);
                std::memset(dp, 0, take);
                dp += take;
                avail -= take;
                hdr_remaining -= take;
                total += static_cast<std::uint32_t>(take);
            }
            if (avail > 0 && pkt_off < pkt.size()) {
                const std::size_t take = std::min(avail, pkt.size() - pkt_off);
                std::memcpy(dp, pkt.data() + pkt_off, take);
                pkt_off += take;
                total += static_cast<std::uint32_t>(take);
            }
            if (hdr_remaining == 0 && pkt_off == pkt.size()) break;
        }
        if (pkt_off < pkt.size()) {
            rx_dropped_.fetch_add(1, std::memory_order_relaxed);
        } else {
            rx_packets_.fetch_add(1, std::memory_order_relaxed);
        }
        rx.Push(chain->head_index, total);
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

    WINTUN_SESSION_HANDLE session =
        api.StartSession(adapter, 4 * 1024 * 1024);
    if (!session) {
        std::fprintf(stderr, "[wintun-probe] WintunStartSession failed: %s\n",
                     FormatWindowsError(::GetLastError()).c_str());
        ::DeleteUnicastIpAddressEntry(&row);
        api.CloseAdapter(adapter);
        return 1;
    }
    HANDLE evt = api.GetReadWaitEvent(session);

    std::printf("[wintun-probe] listening for %d seconds... "
                "try `ping 10.0.0.1` from another shell\n", seconds);
    DWORD start = ::GetTickCount();
    int total = 0;
    while (::GetTickCount() - start < static_cast<DWORD>(seconds) * 1000u) {
        DWORD elapsed = ::GetTickCount() - start;
        DWORD remaining = static_cast<DWORD>(seconds) * 1000u - elapsed;
        DWORD wr = ::WaitForSingleObject(evt, (std::min)(remaining, DWORD{500}));
        if (wr != WAIT_OBJECT_0 && wr != WAIT_TIMEOUT) break;
        for (;;) {
            DWORD sz = 0;
            BYTE* p = api.ReceivePacket(session, &sz);
            if (!p) {
                if (::GetLastError() == ERROR_NO_MORE_ITEMS) break;
                break;
            }
            ++total;
            if (sz >= 20 && (p[0] >> 4) == 4) {
                std::printf("[wintun-probe] rx %lu bytes: IPv4 "
                            "%u.%u.%u.%u -> %u.%u.%u.%u proto=%u\n",
                            sz, p[12], p[13], p[14], p[15],
                            p[16], p[17], p[18], p[19], p[9]);
            } else if (sz >= 40 && (p[0] >> 4) == 6) {
                std::printf("[wintun-probe] rx %lu bytes: IPv6 next-hdr=%u\n",
                            sz, p[6]);
            } else {
                std::printf("[wintun-probe] rx %lu bytes (non-IP)\n", sz);
            }
            api.ReleaseReceivePacket(session, p);
        }
    }
    std::printf("[wintun-probe] %d packets received\n", total);

    api.EndSession(session);
    ::DeleteUnicastIpAddressEntry(&row);
    api.CloseAdapter(adapter);
    std::printf("[wintun-probe] adapter removed; PASS\n");
    return 0;
}

}  // namespace tinyvmm
