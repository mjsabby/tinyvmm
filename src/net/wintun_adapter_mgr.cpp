#include "wintun_adapter_mgr.h"
#include "wintun_device_path.h"
#include "wintun_loader.h"
#include "wintun_svc_client.h"

#include <ws2tcpip.h>

#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace tinyvmm::net {

namespace {

// Apply IPv4 address + on-link prefix + MTU via IPHelper. Used by both
// the DLL path (we're admin and IPHelper accepts CreateUnicastIpAddress)
// and the diagnostic probe. The Svc path bypasses this in favor of the
// service's configure_adapter command.
void ApplyIpHelperIpv4(const NET_LUID& luid,
                       std::uint32_t ip_be,
                       std::uint8_t prefix_len,
                       std::uint32_t mtu) {
    MIB_UNICASTIPADDRESS_ROW row{};
    ::InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid                 = luid;
    row.Address.si_family             = AF_INET;
    row.Address.Ipv4.sin_family       = AF_INET;
    row.Address.Ipv4.sin_addr.s_addr  = ip_be;
    row.OnLinkPrefixLength            = prefix_len;
    row.DadState                      = IpDadStatePreferred;

    DWORD rc = ::CreateUnicastIpAddressEntry(&row);
    if (rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS) {
        throw HrError(HRESULT_FROM_WIN32(rc),
                      "CreateUnicastIpAddressEntry failed");
    }

    MIB_IPINTERFACE_ROW ifrow{};
    ::InitializeIpInterfaceEntry(&ifrow);
    ifrow.Family        = AF_INET;
    ifrow.InterfaceLuid = luid;
    if (::GetIpInterfaceEntry(&ifrow) == NO_ERROR) {
        ifrow.NlMtu              = mtu ? mtu : 1500;
        ifrow.SitePrefixLength   = 0;
        ifrow.UseAutomaticMetric = FALSE;
        ifrow.Metric             = 1;
        DWORD rc2 = ::SetIpInterfaceEntry(&ifrow);
        if (rc2 != NO_ERROR) {
            std::fprintf(stderr,
                         "[wintun-mgr] SetIpInterfaceEntry warning: %s\n",
                         FormatWindowsError(rc2).c_str());
        }
    }
}

void RemoveIpHelperIpv4(const NET_LUID& luid, std::uint32_t ip_be) {
    MIB_UNICASTIPADDRESS_ROW row{};
    ::InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid                = luid;
    row.Address.si_family            = AF_INET;
    row.Address.Ipv4.sin_family      = AF_INET;
    row.Address.Ipv4.sin_addr.s_addr = ip_be;
    (void) ::DeleteUnicastIpAddressEntry(&row);
}

class WintunDllAdapterManager final : public WintunAdapterManager {
public:
    explicit WintunDllAdapterManager(const WintunApi* api) : api_(api) {}

    ~WintunDllAdapterManager() override {
        for (auto& [name, st] : adapters_) {
            if (st.ip_assigned) {
                RemoveIpHelperIpv4(st.luid, st.ip_be);
            }
            if (st.handle) {
                api_->CloseAdapter(st.handle);
            }
        }
    }

    WintunAdapter Create(const std::wstring& name,
                         const std::wstring& tunnel_type) override {
        WINTUN_ADAPTER_HANDLE h =
            api_->CreateAdapter(name.c_str(), tunnel_type.c_str(), nullptr);
        if (!h) {
            throw HrError(HRESULT_FROM_WIN32(::GetLastError()),
                          "WintunCreateAdapter failed");
        }
        NET_LUID luid{};
        api_->GetAdapterLuid(h, &luid);

        std::wstring path;
        try {
            path = FindWintunDevicePathByLuid(luid);
        } catch (...) {
            api_->CloseAdapter(h);
            throw;
        }

        Entry st{};
        st.handle = h;
        st.luid   = luid;
        adapters_[name] = st;

        WintunAdapter out{};
        out.name        = name;
        out.luid        = luid;
        out.device_path = path;
        return out;
    }

    void ConfigureIpv4(const WintunAdapter& a, std::uint32_t ip_be,
                       std::uint8_t prefix_len, std::uint32_t mtu) override {
        ApplyIpHelperIpv4(a.luid, ip_be, prefix_len, mtu);
        auto it = adapters_.find(a.name);
        if (it != adapters_.end()) {
            it->second.ip_be       = ip_be;
            it->second.ip_assigned = true;
        }
    }

    void Destroy(WintunAdapter& a) override {
        auto it = adapters_.find(a.name);
        if (it == adapters_.end()) return;
        if (it->second.ip_assigned) {
            RemoveIpHelperIpv4(it->second.luid, it->second.ip_be);
        }
        if (it->second.handle) {
            api_->CloseAdapter(it->second.handle);
        }
        adapters_.erase(it);
        a.device_path.clear();
        a.luid = NET_LUID{};
    }

    ::wintun::session OpenSession(const WintunAdapter& a,
                                  std::uint32_t capacity) override {
        if (capacity == 0) capacity = 4u * 1024u * 1024u;
        return ::wintun::session::open(a.device_path, capacity);
    }

    const char* backend_label() const noexcept override { return "wintun-dll"; }

private:
    struct Entry {
        WINTUN_ADAPTER_HANDLE handle = nullptr;
        NET_LUID              luid{};
        std::uint32_t         ip_be       = 0;
        bool                  ip_assigned = false;
    };
    const WintunApi* api_ = nullptr;
    std::unordered_map<std::wstring, Entry> adapters_;
};

class WintunSvcAdapterManager final : public WintunAdapterManager {
public:
    WintunSvcAdapterManager() = default;

    ~WintunSvcAdapterManager() override {
        // Best-effort tear-down. Note: if the service still holds the
        // adapter at this point, it'll be deleted by our delete_adapter
        // calls already issued by Destroy(). The adapters_ map is used
        // to chase any stragglers from a missed Destroy().
        for (auto& name : tracked_) {
            try {
                if (!client_) Reconnect();
                if (!client_) continue;
                // If a session is still open on this adapter (caller
                // bypassed Destroy()), free it first so the service
                // doesn't return AdapterBusy.
                if (session_open_.erase(name) > 0) {
                    try { client_->CloseSession(); } catch (...) {}
                }
                client_->DeleteAdapter(name);
            } catch (...) {
                // Swallow — we're tearing down.
            }
        }
    }

    WintunAdapter Create(const std::wstring& name,
                         const std::wstring& tunnel_type) override {
        EnsureClient();
        WintunSvcAdapterInfo info = client_->EnsureAdapter(name, tunnel_type);

        std::wstring path = FindWintunDevicePathByLuid(info.luid);

        tracked_.insert(name);

        WintunAdapter out{};
        out.name        = name;
        out.luid        = info.luid;
        out.device_path = path;
        return out;
    }

    void ConfigureIpv4(const WintunAdapter& a, std::uint32_t ip_be,
                       std::uint8_t prefix_len, std::uint32_t mtu) override {
        // Render "10.0.0.1/24" form.
        in_addr addr{};
        addr.s_addr = ip_be;
        char ip_str[INET_ADDRSTRLEN] = {};
        if (!::InetNtopA(AF_INET, &addr, ip_str, sizeof(ip_str))) {
            throw HrError(HRESULT_FROM_WIN32(::WSAGetLastError()),
                          "InetNtopA failed");
        }
        char cidr_buf[32];
        std::snprintf(cidr_buf, sizeof(cidr_buf), "%s/%u",
                      ip_str, static_cast<unsigned>(prefix_len));

        EnsureClient();
        client_->ConfigureAdapterIpv4(a.name, cidr_buf, mtu ? mtu : 1500);
    }

    void Destroy(WintunAdapter& a) override {
        try {
            EnsureClient();
            // If the user opened a session on this adapter via this
            // manager, the service still has the active-session claim
            // (the data-plane wintun::session has been dropped client-
            // side, but the service-side ConnectionSession won't close
            // until we tell it to). Without this, delete_adapter would
            // return AdapterBusy.
            if (session_open_.erase(a.name) > 0) {
                try {
                    client_->CloseSession();
                } catch (const HrError& e) {
                    std::fprintf(stderr,
                                 "[wintun-svc] close_session warning: %s\n",
                                 e.what());
                }
            }
            client_->DeleteAdapter(a.name);
        } catch (const HrError& e) {
            std::fprintf(stderr, "[wintun-svc] delete_adapter warning: %s\n",
                         e.what());
        }
        tracked_.erase(a.name);
        a.device_path.clear();
        a.luid = NET_LUID{};
    }

    ::wintun::session OpenSession(const WintunAdapter& a,
                                  std::uint32_t capacity) override {
        EnsureClient();
        WintunSvcSessionHandles h = client_->OpenSession(a.name, capacity);

        ::wintun::adopt_params ap{};
        ap.section          = h.section;
        ap.send_tail_moved  = h.send_tail_moved;
        ap.recv_tail_moved  = h.recv_tail_moved;
        ap.capacity         = h.capacity;
        ap.ring_size        = h.ring_size;
        ap.send_ring_offset = h.send_ring_offset;
        ap.recv_ring_offset = h.recv_ring_offset;
        ap.total_size       = h.total_size;

        // adopt() takes ownership of the three HANDLEs on success.
        // On throw, we own them — close to avoid leaking.
        try {
            ::wintun::session s = ::wintun::session::adopt(ap);
            session_open_.insert(a.name);
            return s;
        } catch (...) {
            if (h.section)         ::CloseHandle(h.section);
            if (h.send_tail_moved) ::CloseHandle(h.send_tail_moved);
            if (h.recv_tail_moved) ::CloseHandle(h.recv_tail_moved);
            // The service-side rings are still allocated. Best effort
            // tell it to release them so the next OpenSession on this
            // adapter doesn't see AdapterBusy.
            try { client_->CloseSession(); } catch (...) {}
            throw;
        }
    }

    const char* backend_label() const noexcept override { return "wintun-svc"; }

private:
    void EnsureClient() {
        if (!client_) Reconnect();
    }

    void Reconnect() {
        auto c = std::make_unique<WintunSvcClient>();
        c->Connect();
        c->Ping();
        client_ = std::move(c);
    }

    std::unique_ptr<WintunSvcClient> client_;
    std::unordered_set<std::wstring> tracked_;
    std::unordered_set<std::wstring> session_open_;
};

}  // namespace

std::unique_ptr<WintunAdapterManager> MakeWintunDllManager() {
    std::string load_err;
    const WintunApi& api = LoadWintunApi(&load_err);
    if (!api.Available()) {
        throw HrError(E_FAIL,
                      ("WinTun DLL not loadable: " + load_err).c_str());
    }
    if (!IsProcessElevated()) {
        throw HrError(HRESULT_FROM_WIN32(ERROR_ELEVATION_REQUIRED),
                      "WinTun DLL adapter manager requires elevation. "
                      "Re-run from an elevated shell, or pass "
                      "`--net-backend wintun-svc` to use the wintunsvc "
                      "Windows service (no admin required).");
    }
    return std::make_unique<WintunDllAdapterManager>(&api);
}

std::unique_ptr<WintunAdapterManager> MakeWintunSvcManager() {
    return std::make_unique<WintunSvcAdapterManager>();
}

}  // namespace tinyvmm::net
