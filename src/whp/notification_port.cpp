#include "notification_port.h"

#include <utility>

namespace tinyvmm::whp {

NotificationPort::NotificationPort(WHV_PARTITION_HANDLE part_handle,
                                   WHV_NOTIFICATION_PORT_HANDLE port,
                                   HANDLE event,
                                   std::uint64_t gpa,
                                   std::uint64_t value,
                                   std::uint32_t length)
    : part_handle_(part_handle),
      port_(port),
      event_(event),
      gpa_(gpa),
      value_(value),
      length_(length) {
    match_.GuestAddress = gpa;
    match_.Value = value;
    match_.Length = length;
    match_.MatchOnValue = 1;
    match_.MatchOnLength = 1;
}

NotificationPort::~NotificationPort() {
    // We registered via the legacy WHvRegisterPartitionDoorbellEvent path
    // (see CreateMmioDoorbell rationale below), so port_ is unused and
    // the per-doorbell teardown goes through WHvUnregisterPartitionDoorbellEvent.
    if (port_ != nullptr) {
        WHvDeleteNotificationPort(part_handle_, port_);
        port_ = nullptr;
    } else if (registered_) {
        // Best-effort: deprecation pragma may emit a warning at compile time
        // but the function is still exported by WinHvPlatform.dll.
#pragma warning(push)
#pragma warning(disable : 4996)
        WHvUnregisterPartitionDoorbellEvent(part_handle_, &match_);
#pragma warning(pop)
        registered_ = false;
    }
    if (event_ != nullptr) {
        CloseHandle(event_);
        event_ = nullptr;
    }
}

bool NotificationPort::Wait(DWORD ms) {
    DWORD r = WaitForSingleObject(event_, ms);
    if (r == WAIT_OBJECT_0) {
        ResetEvent(event_);
        return true;
    }
    return false;
}

void NotificationPort::Reset() {
    ResetEvent(event_);
}

std::unique_ptr<NotificationPort> NotificationPort::CreateMmioDoorbell(
    Partition& partition, std::uint64_t gpa, std::uint64_t value,
    std::uint32_t length) {
    if (length != 1 && length != 2 && length != 4 && length != 8) {
        Fatal("CreateMmioDoorbell: length must be 1/2/4/8");
    }

    HANDLE evt = CreateEventW(nullptr, /*manual reset=*/TRUE,
                              /*initially signaled=*/FALSE, nullptr);
    if (evt == nullptr) {
        ThrowIfFailed(HRESULT_FROM_WIN32(GetLastError()),
                      "CreateEventW for notification port");
    }

    // ---- Legacy MMIO doorbell registration ----
    // We deliberately use WHvRegisterPartitionDoorbellEvent here, even
    // though the Windows SDK marks it deprecated. The "newer"
    // WHvCreateNotificationPort(WHvNotificationPortTypeDoorbell, ...) API
    // is for VTL/synic-style cross-partition signaling and does NOT
    // intercept guest MMIO writes -- empirically, registering one and
    // then having the guest write to the matching GPA still surfaces
    // the access as an MMIO exit to user mode.
    //
    // Microsoft's own user-mode VMM (openvmm, vm/whp/src/lib.rs) uses
    // WHvRegisterPartitionDoorbellEvent for the MMIO-doorbell path,
    // confirming this is the intended API for our use case.
    WHV_DOORBELL_MATCH_DATA match = {};
    match.GuestAddress = gpa;
    match.Value = value;
    match.Length = length;
    match.MatchOnValue = 1;
    match.MatchOnLength = 1;

#pragma warning(push)
#pragma warning(disable : 4996)
    HRESULT hr = WHvRegisterPartitionDoorbellEvent(partition.handle(), &match,
                                                   evt);
#pragma warning(pop)
    if (FAILED(hr)) {
        CloseHandle(evt);
        ThrowIfFailed(hr, "WHvRegisterPartitionDoorbellEvent");
    }

    auto np = std::unique_ptr<NotificationPort>(new NotificationPort(
        partition.handle(), /*port=*/nullptr, evt, gpa, value, length));
    np->registered_ = true;
    return np;
}

}  // namespace tinyvmm::whp
