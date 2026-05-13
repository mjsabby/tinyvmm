#include "wintun_loader.h"

#include <windows.h>
#include <shlwapi.h>

#include <cstdio>
#include <cstring>
#include <mutex>

namespace tinyvmm::net {

namespace {

WintunApi g_api{};
std::once_flag g_load_once;
std::string g_load_error;

template <typename Fn>
bool Resolve(HMODULE mod, const char* name, Fn*& out) {
    out = reinterpret_cast<Fn*>(::GetProcAddress(mod, name));
    return out != nullptr;
}

void DoLoad() {
    HMODULE mod = nullptr;

    wchar_t envbuf[MAX_PATH] = {};
    DWORD envlen = ::GetEnvironmentVariableW(L"WINTUN_DLL", envbuf, MAX_PATH);
    if (envlen > 0 && envlen < MAX_PATH) {
        mod = ::LoadLibraryExW(envbuf, nullptr,
                               LOAD_WITH_ALTERED_SEARCH_PATH);
    }
    if (!mod) {
        const wchar_t* repo_path =
            L"C:\\tinyvmm\\third_party\\wintun\\wintun.dll";
        if (::PathFileExistsW(repo_path)) {
            mod = ::LoadLibraryExW(repo_path, nullptr,
                                   LOAD_WITH_ALTERED_SEARCH_PATH);
        }
    }
    if (!mod) {
        mod = ::LoadLibraryExW(L"wintun.dll", nullptr,
                               LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    }
    if (!mod) {
        g_load_error = "LoadLibrary(wintun.dll) failed: " +
                       FormatWindowsError(::GetLastError());
        return;
    }

    bool ok = true;
    ok &= Resolve(mod, "WintunCreateAdapter",            g_api.CreateAdapter);
    ok &= Resolve(mod, "WintunOpenAdapter",              g_api.OpenAdapter);
    ok &= Resolve(mod, "WintunCloseAdapter",             g_api.CloseAdapter);
    ok &= Resolve(mod, "WintunDeleteDriver",             g_api.DeleteDriver);
    ok &= Resolve(mod, "WintunGetAdapterLUID",           g_api.GetAdapterLuid);
    ok &= Resolve(mod, "WintunGetRunningDriverVersion",  g_api.GetRunningDriverVersion);
    ok &= Resolve(mod, "WintunSetLogger",                g_api.SetLogger);
    ok &= Resolve(mod, "WintunStartSession",             g_api.StartSession);
    ok &= Resolve(mod, "WintunEndSession",               g_api.EndSession);
    ok &= Resolve(mod, "WintunGetReadWaitEvent",         g_api.GetReadWaitEvent);
    ok &= Resolve(mod, "WintunReceivePacket",            g_api.ReceivePacket);
    ok &= Resolve(mod, "WintunReleaseReceivePacket",     g_api.ReleaseReceivePacket);
    ok &= Resolve(mod, "WintunAllocateSendPacket",       g_api.AllocateSendPacket);
    ok &= Resolve(mod, "WintunSendPacket",               g_api.SendPacket);

    if (!ok) {
        g_load_error = "wintun.dll missing one or more expected exports";
        g_api = WintunApi{};
        ::FreeLibrary(mod);
    }
}

}  // namespace

const WintunApi& LoadWintunApi(std::string* out_error) {
    std::call_once(g_load_once, DoLoad);
    if (out_error) *out_error = g_load_error;
    return g_api;
}

std::string FormatWindowsError(unsigned long err) {
    if (err == 0) return {};
    LPSTR buf = nullptr;
    DWORD n = ::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    std::string out;
    if (n && buf) {
        out.assign(buf, n);
        while (!out.empty() && (out.back() == '\r' || out.back() == '\n' ||
                                out.back() == '.' || out.back() == ' ')) {
            out.pop_back();
        }
    }
    char codestr[32];
    std::snprintf(codestr, sizeof(codestr), " (0x%08lx)", err);
    out += codestr;
    if (buf) ::LocalFree(buf);
    return out;
}

bool IsProcessElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD got = 0;
    bool result = false;
    if (::GetTokenInformation(token, TokenElevation, &elevation,
                              sizeof(elevation), &got)) {
        result = elevation.TokenIsElevated != 0;
    }
    ::CloseHandle(token);
    return result;
}

}  // namespace tinyvmm::net
