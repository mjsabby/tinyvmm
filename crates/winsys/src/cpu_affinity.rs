//! CPU placement: which cores tinyvmm runs on. Port of
//! src/whp/cpu_affinity.cpp.
//!
//! On hybrid hosts (Intel Alder/Raptor Lake and later), `--cpu-affinity`
//! (default `p`) confines the whole process to one core class with
//! `SetProcessDefaultCpuSets`: the vCPUs and every VMM thread (doorbell pumps,
//! NAT and 9p workers, threads created later) run only on P-cores, or only on
//! E-cores. vCPU threads also pin themselves to the mode's own set
//! (`SetThreadSelectedCpuSets`), which for `p-physical` keeps one logical
//! processor per P-core.
//!
//! Keeping vCPUs in one class also keeps RDTSC consistent: threads bouncing
//! across the P/E boundary trip Linux's `clocksource_watchdog` into marking
//! the TSC unstable. CPU Sets (W10 1709+) cooperate with the scheduler rather
//! than hard-binding. Kernel work done for the process (interrupts and DPCs,
//! file system worker threads) is not confined.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::SystemInformation::{
    CpuSetInformation, GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, SetProcessDefaultCpuSets, SetThreadSelectedCpuSets,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AffinityMode {
    /// No restriction.
    All,
    /// P-cores, all their logical processors (default). Every core on a
    /// non-hybrid host.
    PCore,
    /// P-cores; vCPU threads use one logical processor per physical core (no
    /// SMT sharing), the rest of the process every P-core logical processor.
    PCorePhysical,
    /// E-cores.
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
            GetSystemCpuSetInformation(
                core::ptr::null_mut(),
                0,
                &mut needed,
                GetCurrentProcess(),
                0,
            )
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
        while off + stride <= total {
            let p = unsafe { &*(buf.as_ptr().add(off) as *const SYSTEM_CPU_SET_INFORMATION) };
            let size = p.Size as usize;
            if size == 0 {
                break;
            }
            if p.Type == CpuSetInformation {
                let cs = unsafe { p.Anonymous.CpuSet };
                db.entries.push(CpuSetEntry {
                    id: cs.Id,
                    group: cs.Group,
                    logical_processor_index: cs.LogicalProcessorIndex,
                    core_index: cs.CoreIndex,
                    efficiency_class: cs.EfficiencyClass,
                });
            }
            off += size;
        }
        db.hybrid = is_hybrid(&db.entries);
        db
    })
}

fn is_hybrid(entries: &[CpuSetEntry]) -> bool {
    entries
        .iter()
        .any(|e| e.efficiency_class != entries[0].efficiency_class)
}

/// P-cores are the highest `EfficiencyClass` present; every lower class
/// counts as E-cores.
fn p_class(entries: &[CpuSetEntry]) -> u8 {
    entries
        .iter()
        .map(|e| e.efficiency_class)
        .max()
        .unwrap_or(0)
}

/// The CPU sets `mode` confines a thread to: the mode's core class for the
/// whole process (`vcpu` false), the mode's own set for a vCPU thread. Empty
/// means unrestricted: mode `all`, or a class that covers every processor
/// (P-cores on a non-hybrid host) or none (E-cores on one).
fn select(entries: &[CpuSetEntry], mode: AffinityMode, vcpu: bool) -> Vec<u32> {
    let hybrid = is_hybrid(entries);
    let p = p_class(entries);
    let mut out: Vec<u32> = match mode {
        AffinityMode::All => return Vec::new(),
        AffinityMode::ECore if !hybrid => return Vec::new(),
        AffinityMode::ECore => entries
            .iter()
            .filter(|e| e.efficiency_class < p)
            .map(|e| e.id)
            .collect(),
        AffinityMode::PCorePhysical if vcpu => {
            // One entry (the lowest LogicalProcessorIndex) per physical
            // P-core, dropping SMT siblings.
            let mut by_core: BTreeMap<(u16, u8), CpuSetEntry> = BTreeMap::new();
            for e in entries.iter().filter(|e| e.efficiency_class == p) {
                match by_core.get(&(e.group, e.core_index)) {
                    Some(cur) if cur.logical_processor_index <= e.logical_processor_index => {}
                    _ => {
                        by_core.insert((e.group, e.core_index), *e);
                    }
                }
            }
            by_core.values().map(|e| e.id).collect()
        }
        AffinityMode::PCore | AffinityMode::PCorePhysical if !hybrid => return Vec::new(),
        AffinityMode::PCore | AffinityMode::PCorePhysical => entries
            .iter()
            .filter(|e| e.efficiency_class == p)
            .map(|e| e.id)
            .collect(),
    };
    out.sort_unstable();
    out
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
        let p = p_class(&db.entries);
        let mut top = HostTopology {
            total_logical: db.entries.len() as u32,
            p_logical: 0,
            p_physical: 0,
            e_logical: 0,
            hybrid: db.hybrid,
        };
        let mut p_cores: BTreeSet<(u16, u8)> = BTreeSet::new();
        for e in &db.entries {
            if e.efficiency_class < p {
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

/// The CPU-set IDs a vCPU thread pins itself to under `mode`. Empty = no
/// pinning.
pub fn resolve_cpu_set_ids(mode: AffinityMode) -> Vec<u32> {
    select(&db().entries, mode, true)
}

/// The CPU-set IDs the whole process is confined to under `mode` (its core
/// class). Empty = unrestricted.
pub fn process_cpu_set_ids(mode: AffinityMode) -> Vec<u32> {
    select(&db().entries, mode, false)
}

/// Confine every thread of this process that has no CPU sets of its own,
/// including threads created later, to `cpu_set_ids`
/// (`SetProcessDefaultCpuSets`). Returns true on success or on empty input.
pub fn restrict_process(cpu_set_ids: &[u32]) -> bool {
    if cpu_set_ids.is_empty() {
        return true;
    }
    let ok = unsafe {
        SetProcessDefaultCpuSets(
            GetCurrentProcess(),
            cpu_set_ids.as_ptr(),
            cpu_set_ids.len() as u32,
        )
    };
    if ok == 0 {
        eprintln!(
            "[cpu-affinity] SetProcessDefaultCpuSets failed: error={}",
            unsafe { GetLastError() }
        );
        return false;
    }
    true
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `cores` physical cores of `smt` logical processors each, numbered from
    /// `first_lp`; the CPU-set id is 100 + the logical processor index.
    fn cores(first_lp: u8, cores: u8, smt: u8, class: u8) -> Vec<CpuSetEntry> {
        (0..cores * smt)
            .map(|i| CpuSetEntry {
                id: 100 + u32::from(first_lp + i),
                group: 0,
                logical_processor_index: first_lp + i,
                core_index: first_lp + i / smt * smt,
                efficiency_class: class,
            })
            .collect()
    }

    /// On a hybrid host the process gets its core class, and vCPUs the mode's
    /// own set; on a non-hybrid host only `p-physical` pins anything (its
    /// vCPUs, one per core).
    #[test]
    fn modes_confine_the_process_to_a_core_class() {
        // Two P-cores with SMT (LPs 0-3), four E-cores (LPs 4-7).
        let mut hybrid = cores(0, 2, 2, 1);
        hybrid.extend(cores(4, 4, 1, 0));
        let p = vec![100, 101, 102, 103];
        let e = vec![104, 105, 106, 107];
        for (mode, process, vcpu) in [
            (AffinityMode::All, vec![], vec![]),
            (AffinityMode::PCore, p.clone(), p.clone()),
            (AffinityMode::PCorePhysical, p.clone(), vec![100, 102]),
            (AffinityMode::ECore, e.clone(), e.clone()),
        ] {
            assert_eq!(select(&hybrid, mode, false), process, "{mode:?} process");
            assert_eq!(select(&hybrid, mode, true), vcpu, "{mode:?} vCPU");
        }

        let uniform = cores(0, 4, 2, 0);
        for mode in [AffinityMode::All, AffinityMode::PCore, AffinityMode::ECore] {
            assert_eq!(select(&uniform, mode, false), Vec::<u32>::new(), "{mode:?}");
            assert_eq!(select(&uniform, mode, true), Vec::<u32>::new(), "{mode:?}");
        }
        assert_eq!(
            select(&uniform, AffinityMode::PCorePhysical, false),
            Vec::<u32>::new()
        );
        assert_eq!(
            select(&uniform, AffinityMode::PCorePhysical, true),
            vec![100, 102, 104, 106]
        );
    }
}
