#pragma once

// Runtime loader for wintun.dll.
//
// NOTE on include order: wintun.h itself pulls <winsock2.h>, <windows.h>,
// <ipexport.h>, <ifdef.h>, <ws2ipdef.h> in the correct order. Any TU that
// uses WinTun MUST include this header before any other header that
// pulls <Windows.h> on its own (including the project's `common.h`),
// otherwise winsock.h v1 sneaks in first and you get a cascade of
// redefinition errors.

#include "../../third_party/wintun/wintun.h"

#include <string>

namespace tinyvmm::net {

struct WintunApi {
    WINTUN_CREATE_ADAPTER_FUNC*             CreateAdapter             = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC*               OpenAdapter               = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC*              CloseAdapter              = nullptr;
    WINTUN_DELETE_DRIVER_FUNC*              DeleteDriver              = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC*           GetAdapterLuid            = nullptr;
    WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* GetRunningDriverVersion   = nullptr;
    WINTUN_SET_LOGGER_FUNC*                 SetLogger                 = nullptr;
    WINTUN_START_SESSION_FUNC*              StartSession              = nullptr;
    WINTUN_END_SESSION_FUNC*                EndSession                = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC*        GetReadWaitEvent          = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC*             ReceivePacket             = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC*     ReleaseReceivePacket      = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC*       AllocateSendPacket        = nullptr;
    WINTUN_SEND_PACKET_FUNC*                SendPacket                = nullptr;

    bool Available() const noexcept { return CreateAdapter != nullptr; }
};

// Loads wintun.dll (idempotent) and returns the resolved API table.
//
// Search order:
//   1. WINTUN_DLL env var (full path)
//   2. C:\tinyvmm\third_party\wintun\wintun.dll
//   3. process directory
//   4. LoadLibrary's default search path
//
// On failure, returns an API table with all members null and the
// error message in `out_error` (if non-null).
const WintunApi& LoadWintunApi(std::string* out_error = nullptr);

// Returns the system error string for `last_error_code` ("" on success).
std::string FormatWindowsError(unsigned long last_error_code);

// Returns true if the calling process token is elevated (admin / SYSTEM).
// WinTun adapter creation requires this.
bool IsProcessElevated();

}  // namespace tinyvmm::net
