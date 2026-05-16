#pragma once

// WinTun adapter lifecycle (create / configure-IP / destroy), exposed as
// an abstract interface so the same `WintunNetBackend` data plane can be
// driven by two different *control* planes:
//
//   * `WintunDllAdapterManager` — loads `wintun.dll` and creates the
//     adapter directly. **Requires the calling process to be elevated**
//     (the driver only allows admins to create/delete adapters).
//
//   * `WintunSvcAdapterManager` — talks to the `wintunsvc` Windows
//     service over its named pipe. The service runs as LocalSystem and
//     performs the create/delete on the caller's behalf, so the calling
//     process can be **unelevated**.
//
// Both managers populate the same `WintunAdapter` record (name + LUID +
// device interface path). After Create() returns, the backend uses the
// clean-room `wintun::session` (third_party/wintunumapi/cpp) to drive
// the data ring over the device path. The session works for both
// elevated and unelevated callers — the privilege gate is *only* on
// adapter create/delete, not on the IOCTL_REGISTER_RINGS pathway.
//
// Threading: managers are NOT thread-safe. The backend touches them
// only on the host thread that constructs/tears down the device.

#include "common.h"

// Forward-include via the vendored clean-room session. We need the full
// type because `OpenSession` returns `wintun::session` by value.
#pragma warning(push)
#pragma warning(disable: 4005)  // STATUS_* macro redefs vs winnt.h
#include "wintun_session.hpp"
#pragma warning(pop)

#include <Windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <cstdint>
#include <memory>
#include <string>

namespace tinyvmm::net {

struct WintunAdapter {
    std::wstring name;
    NET_LUID     luid{};
    std::wstring device_path;  // \\?\...
};

class WintunAdapterManager {
public:
    virtual ~WintunAdapterManager() = default;

    WintunAdapterManager(const WintunAdapterManager&)            = delete;
    WintunAdapterManager& operator=(const WintunAdapterManager&) = delete;

    // Create-or-reuse an adapter named `name`. Returns a record whose
    // `device_path` is openable for IOCTL_REGISTER_RINGS. Throws
    // HrError on failure.
    virtual WintunAdapter Create(const std::wstring& name,
                                  const std::wstring& tunnel_type) = 0;

    // Assign IPv4 address + on-link prefix + MTU to the adapter. `ip_be`
    // is in network byte order. Idempotent.
    virtual void ConfigureIpv4(const WintunAdapter& a,
                                std::uint32_t ip_be,
                                std::uint8_t prefix_len,
                                std::uint32_t mtu) = 0;

    // Tear down an adapter previously returned by Create(). After this
    // returns, `a` is invalidated.
    virtual void Destroy(WintunAdapter& a) = 0;

    // Open a `wintun::session` on the adapter's rings using whichever
    // path is appropriate for this manager:
    //   * DLL manager  — calls `wintun::session::open(device_path, ...)`
    //                    directly (requires the kernel-imposed High-IL
    //                    gate to be satisfied by the calling process,
    //                    typically by running elevated).
    //   * Svc manager  — asks `wintunsvc` to perform the privileged
    //                    `TUN_IOCTL_REGISTER_RINGS` and `DuplicateHandle`
    //                    the section + tail-moved events into this
    //                    process, then `wintun::session::adopt`s them.
    //
    // `capacity` is in bytes; must be a power of two in [128 KiB, 64 MiB].
    // Passing 0 picks each backend's default (4 MiB).
    //
    // The returned session may depend on internal manager state (e.g. the
    // SVC manager's pipe connection backs the section lifetime): the
    // caller MUST keep the manager alive for the lifetime of the session.
    virtual ::wintun::session OpenSession(const WintunAdapter& a,
                                          std::uint32_t capacity) = 0;

    // Short label for diagnostics ("wintun-dll", "wintun-svc").
    virtual const char* backend_label() const noexcept = 0;

protected:
    WintunAdapterManager() = default;
};

// Construct a manager that uses wintun.dll directly. Requires elevation.
// Throws HrError if wintun.dll is not loadable.
std::unique_ptr<WintunAdapterManager> MakeWintunDllManager();

// Construct a manager that talks to `wintunsvc` over its named pipe.
// Does NOT require elevation. Throws HrError if the service is not
// reachable.
std::unique_ptr<WintunAdapterManager> MakeWintunSvcManager();

}  // namespace tinyvmm::net
