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

    fn page_for(&self, guest_pfn: u64) -> Option<&mut [u8]> {
        let gpa = guest_pfn << PAGE_SHIFT;
        gpa.checked_add(PAGE_SIZE as u64)?;
        if gpa as usize >= self.ram.size() || gpa as usize + PAGE_SIZE > self.ram.size() {
            return None;
        }
        self.ram.slice_mut(gpa, PAGE_SIZE)
    }

    fn write_reference_tsc_page(&self, guest_pfn: u64) -> bool {
        let scale = self.tsc_scale;
        let Some(page) = self.page_for(guest_pfn) else {
            return false;
        };
        page.fill(0);
        // Header: tsc_sequence(u32)=0, reserved1(u32)=0, tsc_scale(u64), tsc_offset(i64)=0
        page[8..16].copy_from_slice(&scale.to_le_bytes());
        // offset stays 0. Publish a stable non-zero sequence.
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        true
    }

    fn write_hypercall_page(&self, guest_pfn: u64) -> bool {
        let Some(page) = self.page_for(guest_pfn) else {
            return false;
        };
        page.fill(0);
        page[..HYPERCALL_STUB.len()].copy_from_slice(&HYPERCALL_STUB);
        true
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

    /// Snapshot the Hyper-V MSR cache (4 u64 = 32 bytes). The hypercall +
    /// reference-TSC guest pages are part of RAM (restored separately).
    pub fn snapshot_capture(&self) -> Vec<u8> {
        let c = self.cache.lock().unwrap();
        let mut b = Vec::with_capacity(32);
        b.extend_from_slice(&c.guest_os_id.to_le_bytes());
        b.extend_from_slice(&c.hypercall_msr.to_le_bytes());
        b.extend_from_slice(&c.reference_tsc_msr.to_le_bytes());
        b.extend_from_slice(&c.tsc_invariant_ctl.to_le_bytes());
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
        {
            let mut c = self.cache.lock().unwrap();
            c.guest_os_id = guest_os_id;
            c.hypercall_msr = hypercall_msr;
            c.reference_tsc_msr = reference_tsc_msr;
            c.tsc_invariant_ctl = tsc_invariant_ctl;
        }
        if hypercall_msr & 1 != 0 {
            self.write_hypercall_page(hypercall_msr >> PAGE_SHIFT);
        }
        if reference_tsc_msr & 1 != 0 {
            self.write_reference_tsc_page(reference_tsc_msr >> PAGE_SHIFT);
        }
    }
}
