//! CPU-affinity policy applied to the BSP and every AP thread just before its
//! run loop starts. Port of src/whp/cpu_affinity.cpp.
//!
//! On hybrid Intel hosts (Alder/Raptor Lake), vCPU threads bouncing across the
//! P-core / E-core boundary trip Linux's `clocksource_watchdog` into marking
//! TSC unstable (silently demoting `clock_gettime` to a slower clocksource for
//! the rest of boot). Pinning all vCPU threads to either the P-core set OR the
//! E-core set keeps RDTSC consistent across vCPUs without giving up cross-core
//! scheduling within that set. Uses CPU Sets (`SetThreadSelectedCpuSets`,
//! W10 1709+), which cooperate with the scheduler rather than hard-binding.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::SystemInformation::{
    CpuSetInformation, GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, SetThreadSelectedCpuSets,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AffinityMode {
    /// No pinning (default).
    All,
    /// All P-core logical processors (including SMT siblings).
    PCore,
    /// P-cores, one logical processor per physical core (no SMT).
    PCorePhysical,
    /// All E-core logical processors (E-cores have no SMT).
    ECore,
}

#[derive(Clone, Copy)]
struct CpuSetEntry {
    id: u32,
    group: u16,
    logical_processor_index: u8,
    core_index: u8,
    efficiency_class: u8,
}

struct CpuSetDb {
    entries: Vec<CpuSetEntry>,
    hybrid: bool,
}

fn db() -> &'static CpuSetDb {
    static DB: OnceLock<CpuSetDb> = OnceLock::new();
    DB.get_or_init(|| {
        let mut db = CpuSetDb {
            entries: Vec::new(),
            hybrid: false,
        };
        let mut needed: u32 = 0;
        unsafe {
            GetSystemCpuSetInformation(core::ptr::null_mut(), 0, &mut needed, GetCurrentProcess(), 0)
        };
        if needed == 0 {
            return db;
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            GetSystemCpuSetInformation(
                buf.as_mut_ptr() as *mut SYSTEM_CPU_SET_INFORMATION,
                needed,
                &mut needed,
                GetCurrentProcess(),
                0,
            )
        };
        if ok == 0 {
            return db;
        }

        let stride = core::mem::size_of::<SYSTEM_CPU_SET_INFORMATION>();
        let total = needed as usize;
        let mut off = 0usize;
        let mut first = true;
        let mut first_eff = 0u8;
        while off + stride <= total {
            let p = unsafe { &*(buf.as_ptr().add(off) as *const SYSTEM_CPU_SET_INFORMATION) };
            let size = p.Size as usize;
            if size == 0 {
                break;
            }
            if p.Type == CpuSetInformation {
                let cs = unsafe { p.Anonymous.CpuSet };
                let e = CpuSetEntry {
                    id: cs.Id,
                    group: cs.Group,
                    logical_processor_index: cs.LogicalProcessorIndex,
                    core_index: cs.CoreIndex,
                    efficiency_class: cs.EfficiencyClass,
                };
                if first {
                    first_eff = e.efficiency_class;
                    first = false;
                } else if e.efficiency_class != first_eff {
                    db.hybrid = true;
                }
                db.entries.push(e);
            }
            off += size;
        }
        db
    })
}

/// Topology summary derived from `GetSystemCpuSetInformation` (cached).
pub struct HostTopology {
    pub total_logical: u32,
    pub p_logical: u32,
    pub p_physical: u32,
    pub e_logical: u32,
    pub hybrid: bool,
}

pub fn topology() -> &'static HostTopology {
    static TOP: OnceLock<HostTopology> = OnceLock::new();
    TOP.get_or_init(|| {
        let db = db();
        let mut top = HostTopology {
            total_logical: db.entries.len() as u32,
            p_logical: 0,
            p_physical: 0,
            e_logical: 0,
            hybrid: db.hybrid,
        };
        let mut p_cores: BTreeSet<(u16, u8)> = BTreeSet::new();
        for e in &db.entries {
            let is_e = db.hybrid && e.efficiency_class == 0;
            if is_e {
                top.e_logical += 1;
            } else {
                top.p_logical += 1;
                p_cores.insert((e.group, e.core_index));
            }
        }
        top.p_physical = p_cores.len() as u32;
        top
    })
}

/// Resolve the CPU-set IDs for `mode`. Empty = "no pinning" (also returned for
/// `ECore` on a non-hybrid host, where there are no E-cores to pin to).
pub fn resolve_cpu_set_ids(mode: AffinityMode) -> Vec<u32> {
    if mode == AffinityMode::All {
        return Vec::new();
    }
    let db = db();
    if db.entries.is_empty() {
        return Vec::new();
    }
    // On non-hybrid hosts, every core counts as a P-core.
    let is_p = |e: &CpuSetEntry| !db.hybrid || e.efficiency_class >= 1;

    let mut out: Vec<u32> = Vec::new();
    match mode {
        AffinityMode::PCore => {
            for e in &db.entries {
                if is_p(e) {
                    out.push(e.id);
                }
            }
        }
        AffinityMode::ECore => {
            if !db.hybrid {
                return Vec::new();
            }
            for e in &db.entries {
                if e.efficiency_class == 0 {
                    out.push(e.id);
                }
            }
        }
        AffinityMode::PCorePhysical => {
            // Keep one entry (smallest LogicalProcessorIndex) per physical
            // P-core, dropping SMT siblings.
            let mut by_core: BTreeMap<(u16, u8), CpuSetEntry> = BTreeMap::new();
            for e in &db.entries {
                if !is_p(e) {
                    continue;
                }
                let key = (e.group, e.core_index);
                match by_core.get(&key) {
                    Some(cur) if cur.logical_processor_index <= e.logical_processor_index => {}
                    _ => {
                        by_core.insert(key, *e);
                    }
                }
            }
            for (_, e) in by_core {
                out.push(e.id);
            }
        }
        AffinityMode::All => {}
    }
    out.sort_unstable();
    out
}

/// Pin the calling thread to `cpu_set_ids` via `SetThreadSelectedCpuSets`.
/// Returns true on success or on empty input.
pub fn pin_current_thread(cpu_set_ids: &[u32]) -> bool {
    if cpu_set_ids.is_empty() {
        return true;
    }
    let ok = unsafe {
        SetThreadSelectedCpuSets(
            GetCurrentThread(),
            cpu_set_ids.as_ptr(),
            cpu_set_ids.len() as u32,
        )
    };
    if ok == 0 {
        eprintln!(
            "[cpu-affinity] SetThreadSelectedCpuSets failed: error={}",
            unsafe { GetLastError() }
        );
        return false;
    }
    true
}

/// Parse `--cpu-affinity` (case-insensitive): "all", "p", "e", "p-physical".
pub fn parse_affinity_mode(s: &str) -> Option<AffinityMode> {
    match s.to_ascii_lowercase().as_str() {
        "all" => Some(AffinityMode::All),
        "p" | "p-core" | "pcore" => Some(AffinityMode::PCore),
        "e" | "e-core" | "ecore" => Some(AffinityMode::ECore),
        "p-physical" | "p-phys" | "pphysical" => Some(AffinityMode::PCorePhysical),
        _ => None,
    }
}

/// Stable text name (matches `--cpu-affinity` tokens) for logging.
pub fn affinity_mode_name(m: AffinityMode) -> &'static str {
    match m {
        AffinityMode::All => "all",
        AffinityMode::PCore => "p",
        AffinityMode::PCorePhysical => "p-physical",
        AffinityMode::ECore => "e",
    }
}
