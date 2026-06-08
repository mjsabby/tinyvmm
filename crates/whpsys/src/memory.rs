//! One contiguous slab of guest physical memory backed by a host VirtualAlloc
//! region and mapped into the partition at a fixed GPA.

use crate::error::{check_hr, Error, Result};
use crate::host;
use core::ffi::c_void;
use std::sync::atomic::{AtomicU16, Ordering};
use windows_sys::Win32::System::Hypervisor::{
    WHvMapGpaRange, WHvMapGpaRangeFlagExecute, WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite,
    WHvUnmapGpaRange, WHV_PARTITION_HANDLE,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_LARGE_PAGES, MEM_RELEASE, MEM_RESERVE,
    PAGE_READWRITE,
};
use winsys::SharedPtr;

const PAGE: usize = 4096;

fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

pub struct GuestMemory {
    part: WHV_PARTITION_HANDLE,
    base: SharedPtr<u8>,
    gpa: u64,
    size: usize,
    large_pages: bool,
}

// `GuestMemory` now AUTO-derives Send + Sync: every field is Send+Sync
// (`part` is an `isize`; `base` is a `SharedPtr<u8>` whose cross-thread access
// is governed by WHP + our own host-write serialization, asserted once inside
// `SharedPtr`). No blanket `unsafe impl` needed here.

impl GuestMemory {
    pub fn new(
        part: WHV_PARTITION_HANDLE,
        gpa: u64,
        size_bytes: usize,
        executable: bool,
        large_if_available: bool,
    ) -> Result<Self> {
        if size_bytes == 0 || (gpa as usize & (PAGE - 1)) != 0 {
            return Err(Error::msg(
                "GuestMemory: gpa must be 4 KiB aligned and size non-zero",
            ));
        }
        let lp = host::large_page_size();
        let want_large = large_if_available && lp != 0 && (gpa as usize).is_multiple_of(lp);
        let alloc_size = if want_large {
            align_up(size_bytes, lp)
        } else {
            align_up(size_bytes, PAGE)
        };

        let mut base: *mut u8 = std::ptr::null_mut();
        let mut large = false;
        if want_large {
            let p = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    alloc_size,
                    MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
                    PAGE_READWRITE,
                )
            };
            if !p.is_null() {
                base = p as *mut u8;
                large = true;
            } else {
                eprintln!(
                    "[mem] WARN: large-page alloc failed (SeLockMemoryPrivilege not held?); \
                     falling back to 4 KiB pages"
                );
            }
        }
        if base.is_null() {
            let p = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    alloc_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if p.is_null() {
                return Err(Error::msg("VirtualAlloc(guest RAM) failed"));
            }
            base = p as *mut u8;
        }

        let mut flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;
        if executable {
            flags |= WHvMapGpaRangeFlagExecute;
        }
        let hr =
            unsafe { WHvMapGpaRange(part, base as *const c_void, gpa, alloc_size as u64, flags) };
        if let Err(e) = check_hr(hr, "WHvMapGpaRange") {
            unsafe {
                VirtualFree(base as *mut c_void, 0, MEM_RELEASE);
            }
            return Err(e);
        }

        Ok(GuestMemory {
            part,
            base: SharedPtr::new(base),
            gpa,
            size: alloc_size,
            large_pages: large,
        })
    }

    /// Allocate a host-backed slab that is **not** mapped into any partition
    /// (`part == 0`, `gpa == 0`). For host-side selftests / fuzzers (e.g. the
    /// virtqueue fuzzer) that exercise the bounds-checked guest-memory accessors
    /// without a live WHP partition. `Drop` frees the `VirtualAlloc` but skips
    /// `WHvUnmapGpaRange` since there is no GPA mapping to undo.
    pub fn new_host_only(size_bytes: usize) -> Result<Self> {
        if size_bytes == 0 {
            return Err(Error::msg(
                "GuestMemory::new_host_only: size must be non-zero",
            ));
        }
        let alloc_size = align_up(size_bytes, PAGE);
        let p = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                alloc_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if p.is_null() {
            return Err(Error::msg("VirtualAlloc(host-only guest RAM) failed"));
        }
        Ok(GuestMemory {
            part: 0,
            base: SharedPtr::new(p as *mut u8),
            gpa: 0,
            size: alloc_size,
            large_pages: false,
        })
    }

    pub fn host_base(&self) -> *mut u8 {
        self.base.get()
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn large_pages(&self) -> bool {
        self.large_pages
    }

    pub fn host_ptr(&self, guest_phys: u64) -> Option<*mut u8> {
        if guest_phys < self.gpa {
            return None;
        }
        let off = (guest_phys - self.gpa) as usize;
        if off >= self.size {
            return None;
        }
        Some(unsafe { self.base.get().add(off) })
    }

    /// Bounds-checked host pointer for a `[gpa, gpa+len)` guest range. Uses a
    /// subtraction-form check so a near-`u64::MAX` gpa can't wrap the bound.
    pub fn host_range(&self, gpa: u64, len: u64) -> Option<*mut u8> {
        if gpa < self.gpa {
            return None;
        }
        let off = gpa - self.gpa;
        let size = self.size as u64;
        if off >= size || len > size - off {
            return None;
        }
        Some(unsafe { self.base.get().add(off as usize) })
    }

    pub fn gpa(&self) -> u64 {
        self.gpa
    }

    pub fn write_at(&self, guest_phys: u64, src: &[u8]) -> Result<()> {
        if guest_phys < self.gpa {
            return Err(Error::msg("GuestMemory::write_at out of range"));
        }
        let off = (guest_phys - self.gpa) as usize;
        if off > self.size || src.len() > self.size - off {
            return Err(Error::msg("GuestMemory::write_at out of range"));
        }
        if src.is_empty() {
            return Ok(());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.base.get().add(off), src.len());
        }
        Ok(())
    }

    /// A mutable byte view of `len` bytes starting at `guest_phys`. Used to
    /// stage boot artifacts (ACPI) and Hyper-V pages where the writer is the
    /// sole accessor at that moment.
    #[allow(clippy::mut_from_ref)]
    pub fn slice_mut(&self, guest_phys: u64, len: usize) -> Option<&mut [u8]> {
        let p = self.host_ptr(guest_phys)?;
        let off = (guest_phys - self.gpa) as usize;
        if len > self.size - off {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts_mut(p, len) })
    }

    // ---- Typed, bounds-checked accessors -------------------------------------
    //
    // These concentrate ALL of the guest-RAM raw-pointer access into this one
    // audited place: every method bounds-checks the `[gpa, gpa+N)` range via
    // `host_range` and then performs a single small `copy_nonoverlapping` to/from
    // a stack buffer. Callers (the virtqueue, devices) use them with NO `unsafe`.

    /// Copy `dst.len()` bytes from guest RAM at `gpa` into `dst`. Returns false
    /// (leaving `dst` untouched) if the range is out of bounds.
    #[must_use]
    pub fn read_into(&self, gpa: u64, dst: &mut [u8]) -> bool {
        let Some(p) = self.host_range(gpa, dst.len() as u64) else {
            return false;
        };
        if !dst.is_empty() {
            unsafe { std::ptr::copy_nonoverlapping(p, dst.as_mut_ptr(), dst.len()) };
        }
        true
    }

    /// Read a fixed `N`-byte array from guest RAM at `gpa`.
    pub fn read_array<const N: usize>(&self, gpa: u64) -> Option<[u8; N]> {
        let mut b = [0u8; N];
        self.read_into(gpa, &mut b).then_some(b)
    }

    /// Copy `src` into guest RAM at `gpa`. Returns false if out of bounds.
    #[must_use]
    pub fn write_bytes(&self, gpa: u64, src: &[u8]) -> bool {
        let Some(p) = self.host_range(gpa, src.len() as u64) else {
            return false;
        };
        if !src.is_empty() {
            unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), p, src.len()) };
        }
        true
    }

    pub fn read_u16(&self, gpa: u64) -> Option<u16> {
        self.read_array::<2>(gpa).map(u16::from_le_bytes)
    }
    pub fn read_u32(&self, gpa: u64) -> Option<u32> {
        self.read_array::<4>(gpa).map(u32::from_le_bytes)
    }
    pub fn read_u64(&self, gpa: u64) -> Option<u64> {
        self.read_array::<8>(gpa).map(u64::from_le_bytes)
    }
    #[must_use]
    pub fn write_u16(&self, gpa: u64, v: u16) -> bool {
        self.write_bytes(gpa, &v.to_le_bytes())
    }
    #[must_use]
    pub fn write_u32(&self, gpa: u64, v: u32) -> bool {
        self.write_bytes(gpa, &v.to_le_bytes())
    }

    /// Atomic acquire-load of a `u16` at `gpa` (the virtio ring uses these for
    /// the avail/used index + event-suppression fields shared with the guest).
    pub fn load_acquire_u16(&self, gpa: u64) -> Option<u16> {
        let p = self.host_range(gpa, 2)? as *const u16;
        // SAFETY: host_range validated [gpa, gpa+2) is inside the mapping; the
        // virtio ring fields are naturally 2-byte aligned.
        Some(unsafe { AtomicU16::from_ptr(p as *mut u16).load(Ordering::Acquire) })
    }

    /// Atomic release-store of a `u16` at `gpa`. Returns false if out of bounds.
    #[must_use]
    pub fn store_release_u16(&self, gpa: u64, v: u16) -> bool {
        let Some(p) = self.host_range(gpa, 2) else {
            return false;
        };
        // SAFETY: as above.
        unsafe { AtomicU16::from_ptr(p as *mut u16).store(v, Ordering::Release) };
        true
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe {
                // part == 0 => host-only slab (new_host_only): no GPA mapping to undo.
                if self.part != 0 {
                    WHvUnmapGpaRange(self.part, self.gpa, self.size as u64);
                }
                VirtualFree(self.base.get() as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}
