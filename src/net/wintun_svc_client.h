#pragma once

// Minimal client for the WintunSvc named-pipe protocol
// (`\\.\pipe\wintunsvc`). Newline-delimited JSON, request/response.
//
// We only implement the subset tinyvmm needs:
//   * Ping
//   * EnsureAdapter(name, tunnel_type) -> AdapterInfo
//   * ConfigureAdapter(name, ipv4_cidr, mtu)
//   * DeleteAdapter(name)
//
// Transport:
//   * `CreateFileW` opens the pipe with overlapped I/O.
//   * Each request is a single ASCII JSON line followed by `\n`, capped
//     at 4 KiB on the wire.
//   * Each response is read with deadline-bounded overlapped ReadFile +
//     CancelIoEx, then parsed by a strict (length-bounded, escape-aware)
//     parser tailored to the wire shape -- no general JSON library.
//
// Threading: NOT thread-safe. Owned by the construction/teardown thread
// of `WintunNetBackend`; the worker thread never touches it.

#include "common.h"

#include <Windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tinyvmm::net {

struct WintunSvcAdapterInfo {
    std::wstring name;
    NET_LUID luid{};
    std::wstring guid;   // "{...}" form, NetCfgInstanceId
};

// Result of OpenSession: handles duplicated into THIS process by the
// service, plus the ring-layout dimensions the client needs to map the
// section and set up `wintun::session::adopt`. All HANDLEs are owned by
// the caller after a successful OpenSession; close them via
// `wintun::session::adopt` (which takes ownership on success) or via
// `CloseHandle` directly if `adopt` is never reached.
struct WintunSvcSessionHandles {
    HANDLE        section          = nullptr;
    HANDLE        send_tail_moved  = nullptr;
    HANDLE        recv_tail_moved  = nullptr;
    std::uint32_t capacity         = 0;
    std::uint32_t ring_size        = 0;
    std::uint32_t send_ring_offset = 0;
    std::uint32_t recv_ring_offset = 0;
    std::uint64_t total_size       = 0;
};

class WintunSvcClient {
public:
    explicit WintunSvcClient(std::chrono::milliseconds io_timeout =
                                 std::chrono::milliseconds{5000});
    ~WintunSvcClient();

    WintunSvcClient(const WintunSvcClient&)            = delete;
    WintunSvcClient& operator=(const WintunSvcClient&) = delete;

    // Opens \\.\pipe\wintunsvc and switches it to byte/message mode.
    // Throws HrError on failure (service not running, access denied,
    // etc.). The message includes a hint when likely service-not-running.
    void Connect();

    // Health check. Throws on any transport/protocol failure.
    void Ping();

    // Create-or-noop. Returns the adapter info on success.
    WintunSvcAdapterInfo EnsureAdapter(const std::wstring& name,
                                       const std::wstring& tunnel_type);

    // Apply IPv4 address + MTU. `cidr` is "10.0.0.1/24" form. `routes` is
    // always sent as an empty array (required by the server schema).
    void ConfigureAdapterIpv4(const std::wstring& name,
                              const std::string& cidr,
                              std::uint32_t mtu);

    // Remove the adapter from the service. Idempotent on the server.
    void DeleteAdapter(const std::wstring& name);

    // Ask the service to perform `TUN_IOCTL_REGISTER_RINGS` on our behalf
    // and duplicate the resulting handles into this process.
    //
    // The service-side device handle + service-side section view stay
    // alive for the lifetime of THIS pipe connection: closing the pipe
    // (via this client's destructor) signals the service to release the
    // resources. Callers must therefore keep the `WintunSvcClient` alive
    // for the lifetime of the returned `wintun::session`.
    //
    // `capacity` is in bytes. Must be a power of two in [128 KiB, 64 MiB].
    // Pass 0 to accept the service's default (4 MiB).
    //
    // Throws HrError on transport / server failure.
    WintunSvcSessionHandles OpenSession(const std::wstring& name,
                                        std::uint32_t capacity);

    // Optional explicit teardown of the session opened on this connection
    // without disconnecting the pipe. Idempotent on the server.
    void CloseSession();

private:
    void SendRequest(const std::string& json_line);
    std::string ReadOneLine();
    static std::wstring Utf8ToWide(const std::string& s);
    static std::string  WideToUtf8(const std::wstring& w);
    static std::string JsonEscape(const std::wstring& s);

    HANDLE pipe_  = INVALID_HANDLE_VALUE;
    HANDLE evt_   = nullptr;  // overlapped event
    std::chrono::milliseconds timeout_;
    std::vector<char> rd_carry_;  // bytes read past one `\n` boundary
};

}  // namespace tinyvmm::net
