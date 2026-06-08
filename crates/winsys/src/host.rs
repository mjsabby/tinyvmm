//! Host-OS helpers: the SeLockMemoryPrivilege enable + large-page query that
//! back the guest-RAM allocation policy.

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Memory::GetLargePageMinimum;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use std::sync::OnceLock;

use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

pub mod block_file;
pub mod mapped_file;

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Fill `buf` with cryptographically-strong random bytes from Windows CNG
/// (`BCryptGenRandom` with the system-preferred RNG, so no algorithm handle to
/// manage). Returns false on the (practically impossible) CNG failure, in which
/// case the caller must not treat the buffer as random. Mirrors host/rng.cpp.
pub fn random_fill(buf: &mut [u8]) -> bool {
    // BCryptGenRandom takes a ULONG length; cap each call and loop.
    let mut off = 0usize;
    while off < buf.len() {
        let chunk = core::cmp::min(buf.len() - off, 0x4000_0000usize);
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr().add(off),
                chunk as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            // STATUS_SUCCESS == 0.
            return false;
        }
        off += chunk;
    }
    true
}

/// Try to enable SeLockMemoryPrivilege on the current process token. Returns
/// true if the privilege is now enabled. Mirrors host/privilege.cpp.
pub fn enable_lock_memory_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let name = wide("SeLockMemoryPrivilege");
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let ok = AdjustTokenPrivileges(
            token,
            0,
            &tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        let err = windows_sys::Win32::Foundation::GetLastError();
        CloseHandle(token);

        ok != 0 && err != ERROR_NOT_ALL_ASSIGNED
    }
}

/// Host's minimum large-page size in bytes (typically 2 MiB on x86_64).
pub fn large_page_size() -> usize {
    static CACHED: OnceLock<usize> = OnceLock::new();
    *CACHED.get_or_init(|| unsafe { GetLargePageMinimum() })
}
