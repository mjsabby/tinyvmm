#include "xdp_probe.h"

#ifdef TINYVMM_NO_XDP
// ----- Stub-build path -----
// The XDP-for-Windows headers (`afxdp.h`, `xdpapi.h`) use C-style
// aggregate initialization that's compatible with MSVC's `cl.exe` but
// rejected by modern clang-cl (`XSK_BIND_IN Bind = {0};` is an
// int->enum hard error in clang's C++20 mode regardless of -W flags).
// When the build pins clang-cl (e.g. for UBSan) we compile this stub
// instead so `--xdp-probe` stays linkable and reports the backend as
// unavailable.

#include <cstdio>

namespace tinyvmm::host {

int RunXdpProbe(int /*ifindex*/) {
    std::printf("[xdp-probe] XDP support disabled in this build "
                "(TINYVMM_NO_XDP). Rebuild without UBSan to enable.\n");
    return 1;
}

}  // namespace tinyvmm::host

#else  // !TINYVMM_NO_XDP

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>

#define XDP_INCLUDE_WINCOMMON
#include <xdp/apiversion.h>
#define XDP_API_VERSION XDP_API_VERSION_3
#include <xdp/wincommon.h>
#include <xdpapi.h>
#include <afxdp.h>

#include <cstdio>
#include <cstring>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")

namespace tinyvmm::host {

namespace {

struct NicInfo {
    ULONG ifindex;
    char  description[256];
    char  friendly[128];
    bool  is_up;
    bool  is_loopback;
};

std::vector<NicInfo> ListNics() {
    std::vector<NicInfo> out;
    ULONG buf_size = 16 * 1024;
    std::vector<unsigned char> buf(buf_size);
    DWORD rc = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
        nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
        &buf_size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(buf_size);
        rc = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
            &buf_size);
    }
    if (rc != NO_ERROR) {
        std::fprintf(stderr,
            "[xdp-probe] GetAdaptersAddresses failed: %lu\n", rc);
        return out;
    }
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
         a; a = a->Next) {
        NicInfo n{};
        n.ifindex     = a->IfIndex;
        n.is_up       = (a->OperStatus == IfOperStatusUp);
        n.is_loopback = (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
        if (a->Description) {
            int len = WideCharToMultiByte(CP_UTF8, 0, a->Description, -1,
                n.description, sizeof(n.description) - 1, nullptr, nullptr);
            if (len <= 0) std::snprintf(n.description, sizeof(n.description), "?");
        }
        if (a->FriendlyName) {
            int len = WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
                n.friendly, sizeof(n.friendly) - 1, nullptr, nullptr);
            if (len <= 0) std::snprintf(n.friendly, sizeof(n.friendly), "?");
        }
        out.push_back(n);
    }
    return out;
}

// Try to bind an XSK with the given flags. Returns S_OK on success and
// leaves Sock open; caller closes. On failure logs the error and closes
// Sock if it was created.
HRESULT TryBind(ULONG ifindex, ULONG queue, XSK_BIND_FLAGS flags,
                const char* label) {
    HANDLE sock = nullptr;
    HRESULT hr = XskCreate(&sock);
    if (FAILED(hr)) {
        const char* hint = "";
        if (hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)) {
            hint = "  (XDP device unreachable -- run as Administrator, "
                   "or grant access via 'xdpcfg.exe SetDeviceSddl ...')";
        } else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
            hint = "  (access denied -- run as Administrator)";
        }
        std::printf("    %-10s XskCreate failed hr=0x%08lx%s\n",
                    label, hr, hint);
        return hr;
    }
    hr = XskBind(sock, ifindex, queue, flags);
    if (FAILED(hr)) {
        const char* hint = "";
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)) {
            hint = "  (this attach mode not supported on this NIC)";
        } else if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND)) {
            hint = "  (IfIndex / queue not present)";
        }
        std::printf("    %-10s XskBind hr=0x%08lx%s\n",
                    label, hr, hint);
        CloseHandle(sock);
        return hr;
    }
    std::printf("    %-10s XskBind OK (supported on if=%lu queue=%lu)\n",
                label, ifindex, queue);
    CloseHandle(sock);
    return S_OK;
}

void ProbeIfIndex(ULONG ifindex) {
    std::printf("[xdp-probe] testing ifindex=%lu queue=0...\n", ifindex);
    // Native binds usually go through Generic if the NIC has no native XDP
    // driver. We test each flag independently to distinguish.
    TryBind(ifindex, 0,
            static_cast<XSK_BIND_FLAGS>(XSK_BIND_FLAG_RX | XSK_BIND_FLAG_NATIVE),
            "native");
    TryBind(ifindex, 0,
            static_cast<XSK_BIND_FLAGS>(XSK_BIND_FLAG_RX | XSK_BIND_FLAG_GENERIC),
            "generic");
    TryBind(ifindex, 0,
            static_cast<XSK_BIND_FLAGS>(XSK_BIND_FLAG_RX),
            "auto");
}

}  // namespace

int RunXdpProbe(int ifindex) {
    auto nics = ListNics();
    if (nics.empty()) {
        std::fprintf(stderr,
            "[xdp-probe] no NICs found (or enumeration failed)\n");
        return 1;
    }
    std::printf("[xdp-probe] host NICs:\n");
    std::printf("  %-7s %-6s %-9s %s\n", "IfIndex", "State", "Type", "Description");
    for (const auto& n : nics) {
        std::printf("  %-7lu %-6s %-9s %s  [%s]\n",
            n.ifindex,
            n.is_up ? "UP" : "DOWN",
            n.is_loopback ? "loopback" : "ndis",
            n.description,
            n.friendly);
    }
    if (ifindex <= 0) {
        std::printf("\n[xdp-probe] no --xdp-if specified; rerun with "
                    "--xdp-probe <IfIndex> to test attachment.\n");
        std::printf("[xdp-probe] hint: pick a non-loopback NIC with State=UP "
                    "above.\n");
        return 0;
    }
    ProbeIfIndex(static_cast<ULONG>(ifindex));
    return 0;
}

}  // namespace tinyvmm::host

#endif  // !TINYVMM_NO_XDP
