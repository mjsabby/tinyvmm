#pragma once

// Discover the `\\?\<...>` wintun device interface path for an adapter
// identified by NET_LUID. Used by both the privileged (wintun.dll) and
// unprivileged (wintunsvc) backends so they can share a single session
// implementation (`wintun::session` from third_party/wintunumapi).
//
// Algorithm (mirrors wintun's own AdapterGetDeviceObjectFileName):
//   1. ConvertInterfaceLuidToGuid(luid)         -> NetCfgInstanceId GUID
//   2. SetupDiGetClassDevsExW(GUID_DEVCLASS_NET, DIGCF_PRESENT)
//      For each device, read `NetCfgInstanceId` from its driver registry
//      key and compare to ours; on match grab DEVPKEY_Device_InstanceId.
//   3. CM_Get_Device_Interface_List_SizeW + CM_Get_Device_Interface_ListW
//      with the matched DevInstanceID + GUID_DEVINTERFACE_NET. Returns
//      the wintun device path.
//
// All steps are read-only and work for non-elevated callers (verified on
// Windows 10/11 default install; failures fall through to a clear error).
//
// Because PnP/device-interface registration may lag adapter creation by
// up to a few hundred milliseconds, the public entry point retries with
// short backoff up to `total_wait_ms`.

#include "common.h"

#include <Windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <chrono>
#include <string>

namespace tinyvmm::net {

// Returns the wintun device interface path for `luid`.
// Throws HrError on any failure (no interface present, registry access
// denied, etc.). Retries internally until `total_wait` elapses.
//
// Typical paths look like:
//   \\?\ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}
std::wstring FindWintunDevicePathByLuid(
    const NET_LUID& luid,
    std::chrono::milliseconds total_wait = std::chrono::milliseconds{2000});

}  // namespace tinyvmm::net
