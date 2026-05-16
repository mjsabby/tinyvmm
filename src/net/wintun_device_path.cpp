#include "wintun_device_path.h"

// Define INITGUID so the GUID_* symbols below get linker-emitted as
// definitions in this translation unit (rather than just declarations).
// Required for GUID_DEVCLASS_NET, GUID_DEVINTERFACE_NET, and
// DEVPKEY_Device_InstanceId.
#define INITGUID

#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <ndisguid.h>

#include <objbase.h>

#include <thread>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace tinyvmm::net {

namespace {

// Convert NET_LUID -> NetCfgInstanceId GUID -> braces-style string for
// case-insensitive comparison against registry values.
bool LuidToNetCfgGuidString(const NET_LUID& luid, std::wstring& out) {
    GUID guid{};
    DWORD rc = ::ConvertInterfaceLuidToGuid(&luid, &guid);
    if (rc != NO_ERROR) {
        ::SetLastError(rc);
        return false;
    }
    wchar_t buf[64] = {};
    int n = ::StringFromGUID2(guid, buf, static_cast<int>(std::size(buf)));
    if (n == 0) return false;
    out.assign(buf);
    return true;
}

// Read REG_SZ value from a registry key. Returns empty string on failure.
std::wstring RegReadString(HKEY key, const wchar_t* name) {
    DWORD type = 0;
    DWORD size = 0;
    if (::RegQueryValueExW(key, name, nullptr, &type, nullptr, &size)
            != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) ||
        size == 0) {
        return {};
    }
    std::wstring out(size / sizeof(wchar_t), L'\0');
    DWORD got = size;
    if (::RegQueryValueExW(key, name, nullptr, &type,
                           reinterpret_cast<BYTE*>(out.data()), &got)
            != ERROR_SUCCESS) {
        return {};
    }
    // Trim any trailing NUL(s).
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

// Find DevInstanceID (e.g., "ROOT\\NET\\0000") for the adapter whose
// driver-registry NetCfgInstanceId matches `our_guid_str`.
bool FindDevInstanceIdByNetCfgGuid(const std::wstring& our_guid_str,
                                    std::wstring& out_instance_id) {
    HDEVINFO devs = ::SetupDiGetClassDevsExW(
        &GUID_DEVCLASS_NET, nullptr, nullptr,
        DIGCF_PRESENT, nullptr, nullptr, nullptr);
    if (devs == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool found = false;
    SP_DEVINFO_DATA data{};
    data.cbSize = sizeof(data);
    for (DWORD i = 0; ::SetupDiEnumDeviceInfo(devs, i, &data); ++i) {
        HKEY key = ::SetupDiOpenDevRegKey(devs, &data, DICS_FLAG_GLOBAL, 0,
                                          DIREG_DRV, KEY_QUERY_VALUE);
        if (key == INVALID_HANDLE_VALUE) continue;

        std::wstring v = RegReadString(key, L"NetCfgInstanceId");
        ::RegCloseKey(key);
        if (v.empty()) continue;
        if (::_wcsicmp(v.c_str(), our_guid_str.c_str()) != 0) continue;

        // Match. Pull the DevInstanceID.
        wchar_t id_buf[MAX_DEVICE_ID_LEN] = {};
        if (::SetupDiGetDeviceInstanceIdW(devs, &data, id_buf,
                                          static_cast<DWORD>(std::size(id_buf)),
                                          nullptr)) {
            out_instance_id.assign(id_buf);
            found = true;
        }
        break;
    }
    ::SetupDiDestroyDeviceInfoList(devs);
    return found;
}

bool QueryDeviceInterfacePath(const std::wstring& dev_instance_id,
                              std::wstring& out_path) {
    ULONG len = 0;
    CONFIGRET cr = ::CM_Get_Device_Interface_List_SizeW(
        &len,
        const_cast<GUID*>(&GUID_DEVINTERFACE_NET),
        const_cast<DEVINSTID_W>(dev_instance_id.c_str()),
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS || len < 2) return false;

    std::vector<wchar_t> buf(len);
    cr = ::CM_Get_Device_Interface_ListW(
        const_cast<GUID*>(&GUID_DEVINTERFACE_NET),
        const_cast<DEVINSTID_W>(dev_instance_id.c_str()),
        buf.data(), len,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS || buf[0] == L'\0') return false;

    // Multi-string; we want the first entry.
    out_path.assign(buf.data());
    return !out_path.empty();
}

}  // namespace

std::wstring FindWintunDevicePathByLuid(
    const NET_LUID& luid,
    std::chrono::milliseconds total_wait) {
    std::wstring our_guid;
    if (!LuidToNetCfgGuidString(luid, our_guid)) {
        throw HrError(HRESULT_FROM_WIN32(::GetLastError()),
                      "ConvertInterfaceLuidToGuid (or StringFromGUID2) failed");
    }

    const auto start = std::chrono::steady_clock::now();
    std::chrono::milliseconds backoff{25};
    std::wstring instance_id;
    std::wstring path;
    DWORD last_err = 0;

    for (;;) {
        instance_id.clear();
        path.clear();
        if (FindDevInstanceIdByNetCfgGuid(our_guid, instance_id)) {
            if (QueryDeviceInterfacePath(instance_id, path)) {
                // Sanity-check: the path must be openable. We don't keep
                // the handle (the caller's wintun::session::open will reopen
                // with the correct sharing flags), but a probe avoids
                // returning a not-yet-ready path that would fail loudly
                // a few microseconds later.
                HANDLE h = ::CreateFileW(
                    path.c_str(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, 0, nullptr);
                if (h != INVALID_HANDLE_VALUE) {
                    ::CloseHandle(h);
                    return path;
                }
                last_err = ::GetLastError();
            } else {
                last_err = ::GetLastError();
            }
        } else {
            last_err = ::GetLastError();
        }

        const auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed >= total_wait) break;
        std::this_thread::sleep_for(backoff);
        backoff = std::min(backoff * 2, std::chrono::milliseconds{200});
    }

    std::string msg = "FindWintunDevicePathByLuid: no matching device "
                      "interface present after retries";
    throw HrError(last_err ? HRESULT_FROM_WIN32(last_err) : E_FAIL, msg.c_str());
}

}  // namespace tinyvmm::net
