#include "privilege.h"

namespace tinyvmm::host {

bool EnableLockMemoryPrivilege() noexcept {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    LUID luid = {};
    if (!::LookupPrivilegeValueW(nullptr, SE_LOCK_MEMORY_NAME, &luid)) {
        ::CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = ::AdjustTokenPrivileges(token, FALSE, &tp,
                                      sizeof(TOKEN_PRIVILEGES), nullptr,
                                      nullptr);
    DWORD err = ::GetLastError();
    ::CloseHandle(token);

    // AdjustTokenPrivileges returns success even when the privilege wasn't
    // assigned; the only way to detect "not held" is via GetLastError.
    return ok && err != ERROR_NOT_ALL_ASSIGNED;
}

std::size_t LargePageSize() noexcept {
    static const std::size_t cached = ::GetLargePageMinimum();
    return cached;
}

}  // namespace tinyvmm::host
