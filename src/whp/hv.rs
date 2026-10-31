//! Minimal Hyper-V enlightenment surface: the Reference TSC page + the handful
//! of MSRs Linux writes once it detects Hyper-V via CPUID. Port of
//! src/whp/hv_enlightenment.cpp.
//!
//! Both partition reference clocks derive from the guest TSC: the page as
//! `(tsc * scale) >> 64` with a zero offset, and `TIME_REF_COUNT` by reading
//! the calling vCPU's TSC and scaling it the same way. They agree to the tick
//! and share the guest TSC's epoch (about zero when the partition is created,
//! as the TLFS specifies), and a snapshot restore, which puts every vCPU's TSC
//! back, resumes both where they stopped.

#![allow(unused_unsafe)]

use crate::whp::GuestMemory;
use core::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock};
use windows_sys::Win32::System::Hypervisor::{
    WHvCapabilityCodeInterruptClockFrequency, WHvGetCapability,
};

pub const MSR_GUEST_OS_ID: u32 = 0x4000_0000;
pub const MSR_HYPERCALL: u32 = 0x4000_0001;
pub const MSR_VP_INDEX: u32 = 0x4000_0002;
pub const MSR_TIME_REF_COUNT: u32 = 0x4000_0020;
pub const MSR_REFERENCE_TSC: u32 = 0x4000_0021;
pub const MSR_TSC_FREQUENCY: u32 = 0x4000_0022;
pub const MSR_APIC_FREQUENCY: u32 = 0x4000_0023;
pub const MSR_VP_ASSIST_PAGE: u32 = 0x4000_0073;
pub const MSR_TSC_INVARIANT_CTL: u32 = 0x4000_0118;

const PAGE_SHIFT: u64 = 12;
const PAGE_SIZE: usize = 4096;

// `mov eax, 2 (HV_STATUS_INVALID_HYPERCALL_CODE); ret`
const HYPERCALL_STUB: [u8; 6] = [0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MsrHandled {
    Yes,
    NoInjectGp,
}

pub fn compute_tsc_scale(tsc_hz: u64) -> u64 {
    if tsc_hz == 0 {
        return 0;
    }
    ((10_000_000u128 << 64) / tsc_hz as u128) as u64
}

/// Rate WHP's LAPIC timer counts at (its "interrupt clock"), which is what the
/// guest must be told in `HV_X64_MSR_APIC_FREQUENCY`. It is *not* the TSC
/// frequency (200 MHz vs ~3 GHz on current hosts): a guest told the TSC rate
/// programs every LAPIC timer ~16x too long. Falls back to 200 MHz, the value
/// current Hyper-V builds report, if the capability can't be read.
pub fn interrupt_clock_hz() -> u64 {
    static HZ: OnceLock<u64> = OnceLock::new();
    *HZ.get_or_init(|| {
        let mut hz: u64 = 0;
        let mut written: u32 = 0;
        // SAFETY: WHvGetCapability writes at most 8 bytes into `hz`.
        let hr = unsafe {
            WHvGetCapability(
                WHvCapabilityCodeInterruptClockFrequency,
                &mut hz as *mut u64 as *mut c_void,
                std::mem::size_of::<u64>() as u32,
                &mut written,
            )
        };
        if hr >= 0 && hz != 0 {
            hz
        } else {
            eprintln!(
                "[hv] WARN: WHvGetCapability(InterruptClockFrequency) failed \
                 (HRESULT 0x{:08x}); assuming a 200 MHz LAPIC timer",
                hr as u32
            );
            200_000_000
        }
    })
}

struct MsrCache {
    guest_os_id: u64,
    hypercall_msr: u64,
    reference_tsc_msr: u64,
    tsc_invariant_ctl: u64,
    vp_assist_page: u64,
}

pub struct HvEnlightenment {
    ram: Arc<GuestMemory>,
    tsc_hz: u64,
    tsc_scale: u64,
    apic_hz: u64,
    cache: Mutex<MsrCache>,
}

impl HvEnlightenment {
    /// `apic_hz` is the LAPIC timer rate the guest calibrates against; pass
    /// [`interrupt_clock_hz`].
    pub fn new(ram: Arc<GuestMemory>, tsc_hz: u64, apic_hz: u64) -> Self {
        HvEnlightenment {
            ram,
            tsc_hz,
            tsc_scale: compute_tsc_scale(tsc_hz),
            apic_hz,
            cache: Mutex::new(MsrCache {
                guest_os_id: 0,
                hypercall_msr: 0,
                reference_tsc_msr: 0,
                tsc_invariant_ctl: 0,
                vp_assist_page: 0,
            }),
        }
    }

    pub fn tsc_hz(&self) -> u64 {
        self.tsc_hz
    }
    pub fn apic_hz(&self) -> u64 {
        self.apic_hz
    }
    pub fn tsc_scale(&self) -> u64 {
        self.tsc_scale
    }

    /// Partition reference time, in 100 ns units, at guest TSC `guest_tsc`:
    /// exactly what the guest computes from the reference TSC page.
    pub fn reference_time(&self, guest_tsc: u64) -> u64 {
        ((guest_tsc as u128 * self.tsc_scale as u128) >> 64) as u64
    }

    fn write_reference_tsc_page(&self, guest_pfn: u64) -> bool {
        // Build the page in a host buffer and write it via the bounds-checked
        // copy accessor — no `&mut [u8]` aliasing guest-shared memory (the old
        // `slice_mut` path was unsound: aliasable `&mut` over RAM the guest CPU
        // can concurrently touch).
        let gpa = guest_pfn << PAGE_SHIFT;
        let mut page = [0u8; PAGE_SIZE];
        page[8..16].copy_from_slice(&self.tsc_scale.to_le_bytes());
        if !self.ram.write_bytes(gpa, &page) {
            return false;
        }
        // Publish a stable non-zero sequence after the body is visible.
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        self.ram.write_bytes(gpa, &1u32.to_le_bytes())
    }

    fn write_hypercall_page(&self, guest_pfn: u64) -> bool {
        let gpa = guest_pfn << PAGE_SHIFT;
        let mut page = [0u8; PAGE_SIZE];
        page[..HYPERCALL_STUB.len()].copy_from_slice(&HYPERCALL_STUB);
        self.ram.write_bytes(gpa, &page)
    }

    pub fn handle_wrmsr(&self, _vp_index: u32, msr: u32, value: u64) -> MsrHandled {
        let mut c = self.cache.lock().unwrap();
        match msr {
            MSR_GUEST_OS_ID => {
                c.guest_os_id = value;
                MsrHandled::Yes
            }
            MSR_HYPERCALL => {
                c.hypercall_msr = value;
                if value & 1 != 0 {
                    let pfn = value >> PAGE_SHIFT;
                    if !self.write_hypercall_page(pfn) {
                        eprintln!("[hv] WRMSR HYPERCALL: bad PFN=0x{pfn:x}; page left untouched");
                    }
                }
                MsrHandled::Yes
            }
            MSR_REFERENCE_TSC => {
                c.reference_tsc_msr = value;
                if value & 1 != 0 {
                    let pfn = value >> PAGE_SHIFT;
                    if !self.write_reference_tsc_page(pfn) {
                        eprintln!(
                            "[hv] WRMSR REFERENCE_TSC: bad PFN=0x{pfn:x}; guest will fall back \
                             to RDMSR TIME_REF_COUNT"
                        );
                    }
                }
                MsrHandled::Yes
            }
            MSR_TSC_INVARIANT_CTL => {
                c.tsc_invariant_ctl = value;
                MsrHandled::Yes
            }
            MSR_VP_ASSIST_PAGE => {
                // We don't implement the assist-page enlightenments (EOI assist,
                // nested VMCS); the page is guest RAM that stays zeroed, which
                // Linux reads as "no assist". Accepting the write avoids the
                // benign-but-noisy `#GP` Linux logs from `hv_cpu_init`.
                c.vp_assist_page = value;
                MsrHandled::Yes
            }
            _ => MsrHandled::NoInjectGp,
        }
    }

    /// `guest_tsc` reads the calling vCPU's TSC; only `TIME_REF_COUNT` needs
    /// it, and a failed read answers with #GP.
    pub fn handle_rdmsr(
        &self,
        vp_index: u32,
        msr: u32,
        guest_tsc: impl FnOnce() -> Option<u64>,
        out: &mut u64,
    ) -> MsrHandled {
        let c = self.cache.lock().unwrap();
        match msr {
            MSR_GUEST_OS_ID => {
                *out = c.guest_os_id;
                MsrHandled::Yes
            }
            MSR_HYPERCALL => {
                *out = c.hypercall_msr;
                MsrHandled::Yes
            }
            MSR_VP_INDEX => {
                *out = vp_index as u64;
                MsrHandled::Yes
            }
            MSR_TIME_REF_COUNT => {
                drop(c);
                match guest_tsc() {
                    Some(tsc) => {
                        *out = self.reference_time(tsc);
                        MsrHandled::Yes
                    }
                    None => {
                        *out = 0;
                        MsrHandled::NoInjectGp
                    }
                }
            }
            MSR_REFERENCE_TSC => {
                *out = c.reference_tsc_msr;
                MsrHandled::Yes
            }
            // The frequency MSRs are what let Linux's `ms_hyperv_init_platform`
            // bypass PIT/HPET calibration (it sets `x86_platform.calibrate_tsc
            // = hv_get_tsc_khz` and takes the LAPIC timer period from the APIC
            // frequency). Without them the guest falls back to PIT calibration →
            // fails (no IRQ0/HPET) → `calibrate_delay()` spins forever.
            MSR_TSC_FREQUENCY => {
                *out = self.tsc_hz;
                MsrHandled::Yes
            }
            // WHP's LAPIC timer counts at the interrupt clock, not the TSC.
            MSR_APIC_FREQUENCY => {
                *out = self.apic_hz;
                MsrHandled::Yes
            }
            MSR_VP_ASSIST_PAGE => {
                *out = c.vp_assist_page;
                MsrHandled::Yes
            }
            MSR_TSC_INVARIANT_CTL => {
                *out = c.tsc_invariant_ctl;
                MsrHandled::Yes
            }
            _ => {
                *out = 0;
                MsrHandled::NoInjectGp
            }
        }
    }

    /// Snapshot the Hyper-V MSR cache (5 u64 = 40 bytes). The hypercall +
    /// reference-TSC guest pages are part of RAM (restored separately).
    pub fn snapshot_capture(&self) -> Vec<u8> {
        let c = self.cache.lock().unwrap();
        let mut b = Vec::with_capacity(40);
        b.extend_from_slice(&c.guest_os_id.to_le_bytes());
        b.extend_from_slice(&c.hypercall_msr.to_le_bytes());
        b.extend_from_slice(&c.reference_tsc_msr.to_le_bytes());
        b.extend_from_slice(&c.tsc_invariant_ctl.to_le_bytes());
        b.extend_from_slice(&c.vp_assist_page.to_le_bytes());
        b
    }

    /// Restore the MSR cache, then re-publish the hypercall + reference-TSC
    /// pages with THIS host's tsc_scale (must run AFTER RAM restore so the fresh
    /// pages win over the snapshot's, in case the restore host has a different
    /// TSC frequency).
    pub fn snapshot_apply(&self, bytes: &[u8]) {
        if bytes.len() < 32 {
            return;
        }
        let guest_os_id = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let hypercall_msr = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let reference_tsc_msr = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let tsc_invariant_ctl = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        // vp_assist_page added later; tolerate older 32-byte snapshots.
        let vp_assist_page = bytes
            .get(32..40)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
            .unwrap_or(0);
        {
            let mut c = self.cache.lock().unwrap();
            c.guest_os_id = guest_os_id;
            c.hypercall_msr = hypercall_msr;
            c.reference_tsc_msr = reference_tsc_msr;
            c.tsc_invariant_ctl = tsc_invariant_ctl;
            c.vp_assist_page = vp_assist_page;
        }
        if hypercall_msr & 1 != 0 {
            self.write_hypercall_page(hypercall_msr >> PAGE_SHIFT);
        }
        if reference_tsc_msr & 1 != 0 {
            self.write_reference_tsc_page(reference_tsc_msr >> PAGE_SHIFT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TIME_REF_COUNT` and the reference TSC page are one clock: for any guest
    /// TSC the MSR returns what the guest computes from the page. The MSR used
    /// to scale the host's TSC instead, about the host's uptime ahead.
    #[test]
    fn time_ref_count_matches_the_reference_tsc_page() {
        let ram = Arc::new(GuestMemory::new_host_only(0x4000).unwrap());
        let tsc_hz = 3_187_200_000;
        let hv = HvEnlightenment::new(ram.clone(), tsc_hz, 200_000_000);
        assert!(hv.handle_wrmsr(0, MSR_REFERENCE_TSC, 0x2000 | 1) == MsrHandled::Yes);
        let page = ram.read_array::<24>(0x2000).unwrap();
        assert_eq!(u32::from_le_bytes(page[0..4].try_into().unwrap()), 1);
        let scale = u64::from_le_bytes(page[8..16].try_into().unwrap());
        let offset = i64::from_le_bytes(page[16..24].try_into().unwrap());
        for tsc in [0, 1, tsc_hz, 4_000_000_000_000, u64::MAX / 3] {
            let mut msr = 0;
            let r = hv.handle_rdmsr(1, MSR_TIME_REF_COUNT, || Some(tsc), &mut msr);
            assert!(r == MsrHandled::Yes);
            let page_time = ((tsc as u128 * scale as u128) >> 64) as i64 + offset;
            assert_eq!(msr, page_time as u64, "guest tsc {tsc}");
        }
        // One second of guest TSC is 10^7 ticks of 100 ns.
        let mut one_second = 0;
        let _ = hv.handle_rdmsr(0, MSR_TIME_REF_COUNT, || Some(tsc_hz), &mut one_second);
        assert!(
            (9_999_999..=10_000_000).contains(&one_second),
            "{one_second}"
        );
        let r = hv.handle_rdmsr(0, MSR_TIME_REF_COUNT, || None, &mut one_second);
        assert!(r == MsrHandled::NoInjectGp, "an unreadable TSC answers #GP");
    }
}
