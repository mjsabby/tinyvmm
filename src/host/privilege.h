#pragma once

#include <Windows.h>

#include <cstddef>

namespace tinyvmm::host {

// Try to enable SeLockMemoryPrivilege on the current process token. Returns
// true if the privilege is now enabled, false if it could not be (typically
// because it was never granted to the user account).
//
// To grant the privilege:
//   secpol.msc -> Local Policies -> User Rights Assignment ->
//   "Lock pages in memory" -> add the user, then sign out and back in.
//
// The privilege grant by policy is necessary but not sufficient; the process
// must also explicitly enable it in its access token, which is what this
// function does.
bool EnableLockMemoryPrivilege() noexcept;

// Returns the host's minimum large-page size in bytes (typically 2 MiB on
// x86_64). Cached on first call.
std::size_t LargePageSize() noexcept;

}  // namespace tinyvmm::host
