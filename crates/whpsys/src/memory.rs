//! One contiguous slab of guest physical memory backed by a host VirtualAlloc
//! region and mapped into the partition at a fixed GPA.

use crate::error::{Error, Result, check_hr};
use crate::host;
use core::ffi::c_void;
use std::sync::atomic::{AtomicU16, Ordering};
use windows_sys::Win32::System::Hypervisor::{
    WHV_PARTITION_HANDLE, WHvMapGpaRange, WHvMapGpaRangeFlagExecute, WHvMapGpaRangeFlagRead,
    WHvMapGpaRangeFlagWrite, WHvUnmapGpaRange,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_LARGE_PAGES, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc,
    VirtualFree,
};
use winsys::SharedPtr;

const PAGE: usize = 4096;

fn align_up(v: usize, a: usize) -> usize {
    // Saturating so a near-usize::MAX size can't wrap to a tiny allocation (the
    // allocation then simply fails instead of silently under-provisioning).
    v.saturating_add(a - 1) & !(a - 1)
}

/// Describes guest RAM that straddles the 32-bit PCI MMIO hole: `[gpa, gpa +
/// low_size)` maps the first `low_size` host bytes, and `[high_gpa, high_gpa +
/// (size - low_size))` maps the remainder, leaving `[gpa + low_size, high_gpa)`
/// free for device BARs. The host backing store stays a single contiguous
/// allocation; only the GPA mapping has a hole.
struct Split {
    low_size: usize,
    high_gpa: u64,
}

pub struct GuestMemory {
    part: WHV_PARTITION_HANDLE,
    base: SharedPtr<u8>,
    gpa: u64,
    size: usize,
    large_pages: bool,
    split: Option<Split>,
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

        let (base, large) = Self::alloc_host(alloc_size, want_large)?;

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
            split: None,
        })
    }

    /// Allocate guest RAM that straddles the 32-bit PCI MMIO hole. The first
    /// `low_limit` bytes map at GPA 0; any remainder maps at `high_gpa`
    /// (typically 4 GiB), leaving `[low_limit, high_gpa)` free for device BARs.
    /// When `total_bytes <= low_limit` this is exactly
    /// `new(part, 0, total_bytes, ..)` (no hole). `low_limit` and `high_gpa`
    /// must be 4 KiB aligned (and, for large pages to stick, `low_limit` should
    /// be large-page aligned).
    pub fn new_split(
        part: WHV_PARTITION_HANDLE,
        total_bytes: usize,
        low_limit: usize,
        high_gpa: u64,
        executable: bool,
        large_if_available: bool,
    ) -> Result<Self> {
        if total_bytes == 0 {
            return Err(Error::msg("GuestMemory::new_split: size must be non-zero"));
        }
        // The common case: everything fits below the hole, so map one range.
        if total_bytes <= low_limit {
            return Self::new(part, 0, total_bytes, executable, large_if_available);
        }
        if (low_limit & (PAGE - 1)) != 0 || (high_gpa as usize & (PAGE - 1)) != 0 {
            return Err(Error::msg(
                "GuestMemory::new_split: low_limit and high_gpa must be 4 KiB aligned",
            ));
        }

        let lp = host::large_page_size();
        // GPA 0 is large-page aligned; require `low_limit` to be as well so both
        // mapped sub-ranges keep large-page granularity.
        let want_large = large_if_available && lp != 0 && low_limit.is_multiple_of(lp);
        let granule = if want_large { lp } else { PAGE };
        let alloc_size = align_up(total_bytes, granule);

        let (base, large) = Self::alloc_host(alloc_size, want_large)?;

        let high_size = alloc_size - low_limit;
        let mut flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;
        if executable {
            flags |= WHvMapGpaRangeFlagExecute;
        }

        // Low region: host[0, low_limit) -> GPA [0, low_limit).
        let hr = unsafe { WHvMapGpaRange(part, base as *const c_void, 0, low_limit as u64, flags) };
        if let Err(e) = check_hr(hr, "WHvMapGpaRange(low)") {
            unsafe {
                VirtualFree(base as *mut c_void, 0, MEM_RELEASE);
            }
            return Err(e);
        }
        // High region: host[low_limit, alloc_size) -> GPA [high_gpa, ..).
        let hr = unsafe {
            WHvMapGpaRange(
                part,
                base.add(low_limit) as *const c_void,
                high_gpa,
                high_size as u64,
                flags,
            )
        };
        if let Err(e) = check_hr(hr, "WHvMapGpaRange(high)") {
            unsafe {
                WHvUnmapGpaRange(part, 0, low_limit as u64);
                VirtualFree(base as *mut c_void, 0, MEM_RELEASE);
            }
            return Err(e);
        }

        Ok(GuestMemory {
            part,
            base: SharedPtr::new(base),
            gpa: 0,
            size: alloc_size,
            large_pages: large,
            split: Some(Split {
                low_size: low_limit,
                high_gpa,
            }),
        })
    }

    /// Host-side allocation shared by `new` / `new_split`. Tries large pages
    /// first when requested, falling back to 4 KiB pages. Returns the base
    /// pointer and whether large pages were actually used.
    fn alloc_host(alloc_size: usize, want_large: bool) -> Result<(*mut u8, bool)> {
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
        Ok((base, large))
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
            split: None,
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

    /// Translate a guest-physical `[gpa, gpa + len)` range to an offset into the
    /// host backing store, requiring the whole range to fall inside a single
    /// mapped region (it must not straddle the MMIO hole). Returns `None` if any
    /// byte is unmapped. This is the one place that knows about the low/high
    /// split, so every typed accessor below inherits the hole-awareness.
    fn region_off(&self, gpa: u64, len: u64) -> Option<usize> {
        // Low region: [self.gpa, self.gpa + low_size).
        let low_size = match &self.split {
            Some(s) => s.low_size as u64,
            None => self.size as u64,
        };
        if gpa >= self.gpa {
            let off = gpa - self.gpa;
            if off < low_size {
                return (len <= low_size - off).then_some(off as usize);
            }
        }
        // High region (split only): [high_gpa, high_gpa + (size - low_size)).
        if let Some(s) = &self.split
            && gpa >= s.high_gpa
        {
            let off = gpa - s.high_gpa;
            let high_size = (self.size - s.low_size) as u64;
            if off < high_size && len <= high_size - off {
                return Some(s.low_size + off as usize);
            }
        }
        None
    }

    pub fn host_ptr(&self, guest_phys: u64) -> Option<*mut u8> {
        let off = self.region_off(guest_phys, 1)?;
        Some(unsafe { self.base.get().add(off) })
    }

    /// Bounds-checked host pointer for a `[gpa, gpa+len)` guest range. Rejects
    /// any range that is unmapped or that would straddle the MMIO hole.
    pub fn host_range(&self, gpa: u64, len: u64) -> Option<*mut u8> {
        let off = self.region_off(gpa, len)?;
        Some(unsafe { self.base.get().add(off) })
    }

    pub fn gpa(&self) -> u64 {
        self.gpa
    }

    pub fn write_at(&self, guest_phys: u64, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }
        let off = self
            .region_off(guest_phys, src.len() as u64)
            .ok_or_else(|| Error::msg("GuestMemory::write_at out of range"))?;
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.base.get().add(off), src.len());
        }
        Ok(())
    }

    /// Restore a previously-saved RAM image into the host backing store. The
    /// bytes must be laid out exactly as produced by reading
    /// `host_base()..host_base()+size()` (the low region followed by the high
    /// region), so this restores across the MMIO hole without re-deriving GPAs.
    /// Copies `min(bytes.len(), size())` bytes.
    pub fn load_image(&self, bytes: &[u8]) {
        let n = bytes.len().min(self.size);
        if n > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.base.get(), n);
            }
        }
    }

    // `slice_mut(&self) -> &mut [u8]` was removed: returning an aliasable `&mut`
    // over memory the guest CPU concurrently mutates is unsound (Rust's `&mut`
    // exclusivity is a lie there). All former call sites now go through the
    // raw-pointer copy accessors below (`write_bytes` / `read_array`), which
    // never materialize a Rust reference to guest RAM.

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
                    match &self.split {
                        Some(s) => {
                            WHvUnmapGpaRange(self.part, self.gpa, s.low_size as u64);
                            WHvUnmapGpaRange(
                                self.part,
                                s.high_gpa,
                                (self.size - s.low_size) as u64,
                            );
                        }
                        None => {
                            WHvUnmapGpaRange(self.part, self.gpa, self.size as u64);
                        }
                    }
                }
                VirtualFree(self.base.get() as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a GuestMemory with a null backing pointer purely to exercise the
    // `region_off` translation logic (it never dereferences `base`, and Drop is
    // a no-op for a null base).
    fn fake(size: usize, split: Option<Split>) -> GuestMemory {
        GuestMemory {
            part: 0,
            base: SharedPtr::new(std::ptr::null_mut()),
            gpa: 0,
            size,
            large_pages: false,
            split,
        }
    }

    #[test]
    fn region_off_split_maps_low_then_high_across_the_hole() {
        let low = 0xE000_0000usize; // 3584 MiB MMIO hole base
        let high_gpa = 0x1_0000_0000u64; // 4 GiB
        let size = 0x1_0000_0000usize; // 4096 MiB total (512 MiB high)
        let gm = fake(
            size,
            Some(Split {
                low_size: low,
                high_gpa,
            }),
        );

        // Low region.
        assert_eq!(gm.region_off(0, 0x1000), Some(0));
        assert_eq!(
            gm.region_off(low as u64 - 0x1000, 0x1000),
            Some(low - 0x1000)
        );
        // A range that would straddle the hole is rejected.
        assert_eq!(gm.region_off(low as u64 - 0x800, 0x1000), None);
        // The hole itself is unmapped.
        assert_eq!(gm.region_off(low as u64, 1), None);
        assert_eq!(gm.region_off(high_gpa - 1, 1), None);
        // High region maps to the host bytes immediately after the low region.
        assert_eq!(gm.region_off(high_gpa, 0x1000), Some(low));
        let high_size = size - low;
        assert_eq!(
            gm.region_off(high_gpa + high_size as u64 - 1, 1),
            Some(size - 1)
        );
        // One past the top of high RAM is unmapped.
        assert_eq!(gm.region_off(high_gpa + high_size as u64, 1), None);
    }

    #[test]
    fn region_off_without_split_is_a_single_contiguous_region() {
        let gm = fake(0x1000_0000, None);
        assert_eq!(gm.region_off(0, 0x1000), Some(0));
        assert_eq!(gm.region_off(0x0FFF_F000, 0x1000), Some(0x0FFF_F000));
        // End-of-range and overruns are rejected.
        assert_eq!(gm.region_off(0x1000_0000, 1), None);
        assert_eq!(gm.region_off(0x0FFF_F800, 0x1000), None);
    }

    // Proves the save/restore round-trip for split RAM: a snapshot stores the
    // contiguous host image (`host_base()..+size()`, i.e. low region then high
    // region) and restore replays it via `load_image`. This reconstructs the
    // exact same GPA→byte mapping across the MMIO hole — without needing a live
    // WHP partition (part == 0 skips the GPA maps; Drop just frees the buffer).
    #[test]
    fn split_ram_save_image_restores_to_the_same_gpas() {
        // Small page-multiple sizes so the test allocates KiB, not GiB: pretend
        // the hole is at 8 KiB and high RAM starts at 16 KiB.
        let low_limit = 0x2000usize; // 8 KiB low region
        let high_gpa = 0x4000u64; // high region starts at GPA 16 KiB
        let total = 0x3000usize; // 12 KiB total => 4 KiB high region
        let high_size = total - low_limit;

        let (base, _) = GuestMemory::alloc_host(total, false).unwrap();
        let gm = GuestMemory {
            part: 0,
            base: SharedPtr::new(base),
            gpa: 0,
            size: total,
            large_pages: false,
            split: Some(Split {
                low_size: low_limit,
                high_gpa,
            }),
        };

        // The "saved RAM image": the contiguous low||high host bytes.
        let image: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        gm.load_image(&image);

        // Low GPAs read back the front of the image.
        assert_eq!(gm.read_array::<1>(0), Some([image[0]]));
        assert_eq!(
            gm.read_array::<1>(low_limit as u64 - 1),
            Some([image[low_limit - 1]])
        );
        // The hole is unmapped on both edges.
        assert_eq!(gm.read_array::<1>(low_limit as u64), None);
        assert_eq!(gm.read_array::<1>(high_gpa - 1), None);
        // High GPAs read back the tail of the image (bytes after the low region).
        assert_eq!(gm.read_array::<1>(high_gpa), Some([image[low_limit]]));
        assert_eq!(
            gm.read_array::<1>(high_gpa + high_size as u64 - 1),
            Some([image[total - 1]])
        );
        assert_eq!(gm.read_array::<1>(high_gpa + high_size as u64), None);

        // A write to a high GPA lands in the right host byte, so a re-save would
        // round-trip it back to the same place.
        assert!(gm.write_u16(high_gpa, 0xBEEF));
        assert_eq!(gm.read_u16(high_gpa), Some(0xBEEF));
    }
}
