#pragma once

// RAII wrapper around a WHP notification port (`WHvCreateNotificationPort`).
//
// The interesting variant for tinyvmm is the *MMIO doorbell*: register a
// (GPA, value, length) tuple, and any guest write that matches will signal
// a Win32 event handle **instead of** taking a VM exit to user mode. This
// is the building block for "0 user-mode exits per packet" on the TX path.
//
// Lifetime: the port belongs to a partition, the event handle belongs to
// us. Destruction tears both down.

#include "../common.h"
#include "partition.h"

#include <Windows.h>
#include <WinHvPlatform.h>
#include <WinHvPlatformDefs.h>

#include <cstdint>
#include <memory>

namespace tinyvmm::whp {

class NotificationPort {
public:
    // Create a doorbell on `(gpa, value)` of `length` bytes. The returned
    // object owns both the WHP port handle and a manual-reset Win32 event.
    // The caller may WaitForSingleObject on `event()`; the event is reset
    // automatically by Wait(), or manually with ResetEvent().
    //
    // `length` must be 1, 2, 4, or 8. `value` is the exact value the guest
    // is expected to write; mismatched values fall through to a normal
    // MMIO exit.
    static std::unique_ptr<NotificationPort> CreateMmioDoorbell(
        Partition& partition, std::uint64_t gpa, std::uint64_t value,
        std::uint32_t length);

    NotificationPort(const NotificationPort&) = delete;
    NotificationPort& operator=(const NotificationPort&) = delete;

    ~NotificationPort();

    // Underlying Win32 event. Manual-reset; call ResetEvent or Wait() to
    // clear. Hot-path workers WaitForSingleObject on this.
    HANDLE event() const noexcept { return event_; }

    // Convenience: WaitForSingleObject + ResetEvent. Returns true if the
    // event was signaled within `ms`. Auto-reset semantics for the caller
    // even though the underlying event is manual-reset.
    bool Wait(DWORD ms);

    // Reset without waiting (useful before kicking off a fresh observation
    // window).
    void Reset();

    // Diagnostic accessors.
    std::uint64_t gpa() const noexcept { return gpa_; }
    std::uint64_t value() const noexcept { return value_; }
    std::uint32_t length() const noexcept { return length_; }

private:
    NotificationPort(WHV_PARTITION_HANDLE part_handle,
                     WHV_NOTIFICATION_PORT_HANDLE port,
                     HANDLE event,
                     std::uint64_t gpa,
                     std::uint64_t value,
                     std::uint32_t length);

    WHV_PARTITION_HANDLE part_handle_;
    WHV_NOTIFICATION_PORT_HANDLE port_;
    HANDLE event_;
    std::uint64_t gpa_;
    std::uint64_t value_;
    std::uint32_t length_;
    WHV_DOORBELL_MATCH_DATA match_{};
    bool registered_ = false;
};

}  // namespace tinyvmm::whp
