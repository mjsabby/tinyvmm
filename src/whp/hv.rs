//! Minimal Hyper-V enlightenment surface: the Reference TSC page + the handful
//! of MSRs Linux writes once it detects Hyper-V via CPUID. Port of
//! src/whp/hv_enlightenment.cpp.

#![allow(unused_unsafe)]

use crate::whp::GuestMemory;
use core::arch::x86_64::_rdtsc;
use std::sync::{Arc, Mutex};

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
    cache: Mutex<MsrCache>,
}

impl HvEnlightenment {
    pub fn new(ram: Arc<GuestMemory>, tsc_hz: u64) -> Self {
        HvEnlightenment {
            ram,
            tsc_hz,
            tsc_scale: compute_tsc_scale(tsc_hz),
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
    pub fn tsc_scale(&self) -> u64 {
        self.tsc_scale
    }

    fn read_100ns(&self) -> u64 {
        let tsc = unsafe { _rdtsc() };
        ((tsc as u128).wrapping_mul(self.tsc_scale as u128) >> 64) as u64
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

    pub fn handle_rdmsr(&self, vp_index: u32, msr: u32, out: &mut u64) -> MsrHandled {
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
                *out = self.read_100ns();
                MsrHandled::Yes
            }
            MSR_REFERENCE_TSC => {
                *out = c.reference_tsc_msr;
                MsrHandled::Yes
            }
            // The frequency MSRs are what let Linux's `ms_hyperv_init_platform`
            // bypass PIT/HPET TSC calibration (it sets `x86_platform.calibrate_tsc
            // = hv_get_tsc_khz`). Without them the guest falls back to PIT
            // calibration → fails (no IRQ0/HPET) → `calibrate_delay()` spins
            // forever. The software LAPIC's timer counts in host-TSC ticks, so
            // its bus frequency *is* the TSC frequency.
            MSR_TSC_FREQUENCY | MSR_APIC_FREQUENCY => {
                *out = self.tsc_hz;
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
