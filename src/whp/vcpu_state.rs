//! Per-vCPU state capture/apply for save/restore. Port of src/whp/vcpu_state.cpp.
//!
//! Capture order: arch -> timing -> intr_ctl (per-reg, ok bits) -> sup_msr
//! (per-reg, ok bits) -> XSAVE blob -> APIC blob (may be empty) -> SynIC.
//! Apply order  : arch -> sup_msr (before XSAVE: XRSTORS validates IA32_XSS/CET)
//! -> XSAVE -> APIC (if non-empty) -> intr_ctl (individually) -> SynIC. Timing
//! (Tsc/TscAux) is applied LAST (separate call) to minimize cross-vCPU skew.
//!
//! SynIC is the Hyper-V enlightenment state the hypervisor keeps per vCPU
//! (`hv.rs`): the VP assist page (lazy EOI), the SynIC control, page and
//! interrupt-source registers, the synthetic timers, and the message and
//! event-flag pages, which overlay guest RAM rather than live in it.

#![allow(dead_code)]

use crate::error::{Error, Result};
use crate::whp::vcpu::Vcpu;
use windows_sys::Win32::System::Hypervisor::{
    WHV_REGISTER_NAME, WHvRegisterInternalActivityState, WHvRegisterInterruptState,
    WHvRegisterPendingInterruption, WHvRegisterScontrol, WHvRegisterSiefp, WHvRegisterSimp,
    WHvRegisterSint0, WHvRegisterSint1, WHvRegisterSint2, WHvRegisterSint3, WHvRegisterSint4,
    WHvRegisterSint5, WHvRegisterSint6, WHvRegisterSint7, WHvRegisterSint8, WHvRegisterSint9,
    WHvRegisterSint10, WHvRegisterSint11, WHvRegisterSint12, WHvRegisterSint13, WHvRegisterSint14,
    WHvRegisterSint15, WHvRegisterVpAssistPage, WHvVirtualProcessorStateTypeSynicEventFlagPage,
    WHvVirtualProcessorStateTypeSynicMessagePage, WHvVirtualProcessorStateTypeSynicTimerState,
    WHvX64RegisterApicBase, WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3,
    WHvX64RegisterCr4, WHvX64RegisterCr8, WHvX64RegisterCs, WHvX64RegisterCstar,
    WHvX64RegisterDeliverabilityNotifications, WHvX64RegisterDr0, WHvX64RegisterDr1,
    WHvX64RegisterDr2, WHvX64RegisterDr3, WHvX64RegisterDr6, WHvX64RegisterDr7, WHvX64RegisterDs,
    WHvX64RegisterEfer, WHvX64RegisterEs, WHvX64RegisterFs, WHvX64RegisterGdtr, WHvX64RegisterGs,
    WHvX64RegisterIdtr, WHvX64RegisterInterruptSspTableAddr, WHvX64RegisterKernelGsBase,
    WHvX64RegisterLdtr, WHvX64RegisterLstar, WHvX64RegisterPat, WHvX64RegisterPl0Ssp,
    WHvX64RegisterPl1Ssp, WHvX64RegisterPl2Ssp, WHvX64RegisterPl3Ssp, WHvX64RegisterR8,
    WHvX64RegisterR9, WHvX64RegisterR10, WHvX64RegisterR11, WHvX64RegisterR12, WHvX64RegisterR13,
    WHvX64RegisterR14, WHvX64RegisterR15, WHvX64RegisterRax, WHvX64RegisterRbp, WHvX64RegisterRbx,
    WHvX64RegisterRcx, WHvX64RegisterRdi, WHvX64RegisterRdx, WHvX64RegisterRflags,
    WHvX64RegisterRip, WHvX64RegisterRsi, WHvX64RegisterRsp, WHvX64RegisterSCet,
    WHvX64RegisterSfmask, WHvX64RegisterSs, WHvX64RegisterSsp, WHvX64RegisterStar,
    WHvX64RegisterSysenterCs, WHvX64RegisterSysenterEip, WHvX64RegisterSysenterEsp,
    WHvX64RegisterTr, WHvX64RegisterTsc, WHvX64RegisterTscAux, WHvX64RegisterUCet,
    WHvX64RegisterXCr0, WHvX64RegisterXss,
};

pub const ARCH_REGS: &[WHV_REGISTER_NAME] = &[
    WHvX64RegisterRax,
    WHvX64RegisterRcx,
    WHvX64RegisterRdx,
    WHvX64RegisterRbx,
    WHvX64RegisterRsp,
    WHvX64RegisterRbp,
    WHvX64RegisterRsi,
    WHvX64RegisterRdi,
    WHvX64RegisterR8,
    WHvX64RegisterR9,
    WHvX64RegisterR10,
    WHvX64RegisterR11,
    WHvX64RegisterR12,
    WHvX64RegisterR13,
    WHvX64RegisterR14,
    WHvX64RegisterR15,
    WHvX64RegisterRip,
    WHvX64RegisterRflags,
    WHvX64RegisterEs,
    WHvX64RegisterCs,
    WHvX64RegisterSs,
    WHvX64RegisterDs,
    WHvX64RegisterFs,
    WHvX64RegisterGs,
    WHvX64RegisterLdtr,
    WHvX64RegisterTr,
    WHvX64RegisterIdtr,
    WHvX64RegisterGdtr,
    WHvX64RegisterCr0,
    WHvX64RegisterCr2,
    WHvX64RegisterCr3,
    WHvX64RegisterCr4,
    WHvX64RegisterCr8,
    WHvX64RegisterXCr0,
    WHvX64RegisterDr0,
    WHvX64RegisterDr1,
    WHvX64RegisterDr2,
    WHvX64RegisterDr3,
    WHvX64RegisterDr6,
    WHvX64RegisterDr7,
    WHvX64RegisterEfer,
    WHvX64RegisterKernelGsBase,
    WHvX64RegisterApicBase,
    WHvX64RegisterPat,
    WHvX64RegisterSysenterCs,
    WHvX64RegisterSysenterEsp,
    WHvX64RegisterSysenterEip,
    WHvX64RegisterStar,
    WHvX64RegisterLstar,
    WHvX64RegisterCstar,
    WHvX64RegisterSfmask,
];

pub const TIMING_REGS: &[WHV_REGISTER_NAME] = &[WHvX64RegisterTsc, WHvX64RegisterTscAux];

pub const INTR_CTL_REGS: &[WHV_REGISTER_NAME] = &[
    WHvRegisterPendingInterruption,
    WHvRegisterInterruptState,
    WHvX64RegisterDeliverabilityNotifications,
    WHvRegisterInternalActivityState,
];

pub const SUP_MSR_REGS: &[WHV_REGISTER_NAME] = &[
    WHvX64RegisterXss,
    WHvX64RegisterUCet,
    WHvX64RegisterSCet,
    WHvX64RegisterSsp,
    WHvX64RegisterPl0Ssp,
    WHvX64RegisterPl1Ssp,
    WHvX64RegisterPl2Ssp,
    WHvX64RegisterPl3Ssp,
    WHvX64RegisterInterruptSspTableAddr,
];

/// The SynIC registers the hypervisor keeps per vCPU (OpenVMM's
/// `SyntheticMsrs`): the VP assist page, SynIC control, the event-flag and
/// message page MSRs, then the 16 interrupt sources.
pub const SYNIC_REGS: &[WHV_REGISTER_NAME] = &[
    WHvRegisterVpAssistPage,
    WHvRegisterScontrol,
    WHvRegisterSiefp,
    WHvRegisterSimp,
    WHvRegisterSint0,
    WHvRegisterSint1,
    WHvRegisterSint2,
    WHvRegisterSint3,
    WHvRegisterSint4,
    WHvRegisterSint5,
    WHvRegisterSint6,
    WHvRegisterSint7,
    WHvRegisterSint8,
    WHvRegisterSint9,
    WHvRegisterSint10,
    WHvRegisterSint11,
    WHvRegisterSint12,
    WHvRegisterSint13,
    WHvRegisterSint14,
    WHvRegisterSint15,
];
const SYNIC_SIEFP: usize = 2;
const SYNIC_SIMP: usize = 3;
/// `HV_SYNTHETIC_TIMERS_STATE`: four timers of config, count, adjustment and
/// an undelivered expiration (40 bytes each), then 40 reserved bytes.
const SYNIC_TIMERS_BYTES: usize = 200;
const SYNIC_PAGE_BYTES: usize = 4096;

#[derive(Default)]
pub struct CapturedVcpuState {
    pub arch: Vec<[u8; 16]>,
    pub timing: Vec<[u8; 16]>,
    pub intr_ctl: Vec<[u8; 16]>,
    pub intr_ctl_ok: Vec<bool>,
    pub sup_msr: Vec<[u8; 16]>,
    pub sup_msr_ok: Vec<bool>,
    pub xsave: Vec<u8>,
    pub apic: Vec<u8>,
    pub synic: Vec<[u8; 16]>,
    pub synic_timers: Vec<u8>,
    /// Empty while the guest has the page off.
    pub synic_message_page: Vec<u8>,
    /// Empty while the guest has the page off.
    pub synic_event_flags_page: Vec<u8>,
}

/// Read one of the vCPU's SynIC state blobs, `capacity` bytes at most.
fn synic_state(
    vp: &Vcpu,
    ty: windows_sys::Win32::System::Hypervisor::WHV_VIRTUAL_PROCESSOR_STATE_TYPE,
    capacity: usize,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; capacity];
    let n = vp.get_state(ty, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn capture(vp: &Vcpu) -> Result<CapturedVcpuState> {
    let mut out = CapturedVcpuState {
        arch: vp.get_registers_bytes(ARCH_REGS)?,
        timing: vp.get_registers_bytes(TIMING_REGS)?,
        ..Default::default()
    };

    for &name in INTR_CTL_REGS {
        match vp.get_register_bytes(name) {
            Ok(b) => {
                out.intr_ctl.push(b);
                out.intr_ctl_ok.push(true);
            }
            Err(_) => {
                out.intr_ctl.push([0u8; 16]);
                out.intr_ctl_ok.push(false);
            }
        }
    }
    for &name in SUP_MSR_REGS {
        match vp.get_register_bytes(name) {
            Ok(b) => {
                out.sup_msr.push(b);
                out.sup_msr_ok.push(true);
            }
            Err(_) => {
                out.sup_msr.push([0u8; 16]);
                out.sup_msr_ok.push(false);
            }
        }
    }

    out.xsave = vp.get_xsave()?;
    out.apic = vp.get_interrupt_controller();

    out.synic = vp.get_registers_bytes(SYNIC_REGS)?;
    out.synic_timers = synic_state(
        vp,
        WHvVirtualProcessorStateTypeSynicTimerState,
        SYNIC_TIMERS_BYTES,
    )?;
    // Bit 0 of SIMP / SIEFP enables the page. Linux turns them on only with
    // VMBus (direct-mode timers interrupt without a message), so they are
    // usually off and have nothing to save.
    if out.synic[SYNIC_SIMP][0] & 1 != 0 {
        out.synic_message_page = synic_state(
            vp,
            WHvVirtualProcessorStateTypeSynicMessagePage,
            SYNIC_PAGE_BYTES,
        )?;
    }
    if out.synic[SYNIC_SIEFP][0] & 1 != 0 {
        out.synic_event_flags_page = synic_state(
            vp,
            WHvVirtualProcessorStateTypeSynicEventFlagPage,
            SYNIC_PAGE_BYTES,
        )?;
    }
    Ok(out)
}

pub fn apply_non_timing(vp: &Vcpu, st: &CapturedVcpuState) -> Result<()> {
    if st.arch.len() != ARCH_REGS.len() {
        return Err(Error::msg("vcpu-state: arch reg count mismatch"));
    }
    // 1. Arch first (establishes XCR0/CR4/EFER/segments/ApicBase).
    vp.set_registers_bytes(ARCH_REGS, &st.arch)?;

    // 1.5 Supervisor MSRs BEFORE XSAVE (XRSTORS validates IA32_XSS/CET). Per-reg
    // with WARN-on-failure (unsupported names on older WHP builds are tolerated).
    for (i, &name) in SUP_MSR_REGS.iter().enumerate() {
        if i < st.sup_msr_ok.len()
            && st.sup_msr_ok[i]
            && let Err(e) = vp.set_register_bytes(name, &st.sup_msr[i])
        {
            eprintln!("[vcpu-state] WARN: set sup_msr[{i}] (0x{name:08x}) failed: {e}");
        }
    }

    // 2. XSAVE blob.
    vp.set_xsave(&st.xsave)?;

    // 3. APIC blob (if present).
    if !st.apic.is_empty() {
        vp.set_interrupt_controller(&st.apic)?;
    }

    // 4. Interrupt-control synthetic registers, individually (WARN on failure).
    for (i, &name) in INTR_CTL_REGS.iter().enumerate() {
        if i < st.intr_ctl_ok.len()
            && st.intr_ctl_ok[i]
            && let Err(e) = vp.set_register_bytes(name, &st.intr_ctl[i])
        {
            eprintln!("[vcpu-state] WARN: set intr_ctl[{i}] (0x{name:08x}) failed: {e}");
        }
    }

    // 5. SynIC, in OpenVMM's order: the registers (which place the pages),
    // the page contents, then the timers last: setting them can make the
    // hypervisor deliver an undelivered expiration into the message page,
    // which must hold its contents by then.
    if st.synic.len() != SYNIC_REGS.len() {
        return Err(Error::msg("vcpu-state: SynIC reg count mismatch"));
    }
    vp.set_registers_bytes(SYNIC_REGS, &st.synic)?;
    if !st.synic_message_page.is_empty() {
        vp.set_state(
            WHvVirtualProcessorStateTypeSynicMessagePage,
            &st.synic_message_page,
        )?;
    }
    if !st.synic_event_flags_page.is_empty() {
        vp.set_state(
            WHvVirtualProcessorStateTypeSynicEventFlagPage,
            &st.synic_event_flags_page,
        )?;
    }
    vp.set_state(
        WHvVirtualProcessorStateTypeSynicTimerState,
        &st.synic_timers,
    )?;
    Ok(())
}

pub fn apply_timing(vp: &Vcpu, st: &CapturedVcpuState) -> Result<()> {
    if st.timing.len() != TIMING_REGS.len() {
        return Err(Error::msg("vcpu-state: timing reg count mismatch"));
    }
    vp.set_registers_bytes(TIMING_REGS, &st.timing)
}

// ============================================================
// Wire encode / decode (name-tagged so reorder-safe at read time)
// ============================================================
fn put_u32(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_le_bytes());
}

/// [u32 vp_idx][u32 count][ u32 name | 16 bytes value ]*
pub fn encode_regs(vp_idx: u32, names: &[WHV_REGISTER_NAME], vals: &[[u8; 16]]) -> Vec<u8> {
    let mut o = Vec::with_capacity(8 + names.len() * 20);
    put_u32(&mut o, vp_idx);
    put_u32(&mut o, names.len() as u32);
    for (i, &name) in names.iter().enumerate() {
        put_u32(&mut o, name as u32);
        o.extend_from_slice(&vals[i]);
    }
    o
}

/// [u32 vp_idx][u32 count][ u32 name | u8 ok | u8 pad[3] | 16 bytes value ]*
pub fn encode_okregs(
    vp_idx: u32,
    names: &[WHV_REGISTER_NAME],
    vals: &[[u8; 16]],
    ok: &[bool],
) -> Vec<u8> {
    let mut o = Vec::with_capacity(8 + names.len() * 24);
    put_u32(&mut o, vp_idx);
    put_u32(&mut o, names.len() as u32);
    for (i, &name) in names.iter().enumerate() {
        put_u32(&mut o, name as u32);
        o.push(ok[i] as u8);
        o.extend_from_slice(&[0u8, 0, 0]);
        o.extend_from_slice(&vals[i]);
    }
    o
}

/// [u32 vp_idx][u32 len][bytes]
pub fn encode_blob(vp_idx: u32, blob: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(8 + blob.len());
    put_u32(&mut o, vp_idx);
    put_u32(&mut o, blob.len() as u32);
    o.extend_from_slice(blob);
    o
}

fn rd_u32(b: &[u8], off: usize) -> Result<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| Error::msg("vcpu-state: truncated section"))
}

/// Decode a reg block into values ordered per `canonical` (default [0;16] for
/// any name absent from the payload). Returns (vp_idx, values).
pub fn decode_regs(
    payload: &[u8],
    canonical: &[WHV_REGISTER_NAME],
) -> Result<(u32, Vec<[u8; 16]>)> {
    let vp_idx = rd_u32(payload, 0)?;
    let count = rd_u32(payload, 4)? as usize;
    let mut map: std::collections::HashMap<u32, [u8; 16]> = std::collections::HashMap::new();
    let mut off = 8;
    for _ in 0..count {
        let name = rd_u32(payload, off)?;
        let val: [u8; 16] = payload
            .get(off + 4..off + 20)
            .ok_or_else(|| Error::msg("vcpu-state: truncated reg"))?
            .try_into()
            .unwrap();
        map.insert(name, val);
        off += 20;
    }
    let out = canonical
        .iter()
        .map(|n| map.get(&(*n as u32)).copied().unwrap_or([0u8; 16]))
        .collect();
    Ok((vp_idx, out))
}

/// Decode an ok-reg block. Returns (vp_idx, values, ok) ordered per `canonical`.
pub fn decode_okregs(
    payload: &[u8],
    canonical: &[WHV_REGISTER_NAME],
) -> Result<(u32, Vec<[u8; 16]>, Vec<bool>)> {
    let vp_idx = rd_u32(payload, 0)?;
    let count = rd_u32(payload, 4)? as usize;
    let mut map: std::collections::HashMap<u32, ([u8; 16], bool)> =
        std::collections::HashMap::new();
    let mut off = 8;
    for _ in 0..count {
        let name = rd_u32(payload, off)?;
        let ok = *payload
            .get(off + 4)
            .ok_or_else(|| Error::msg("vcpu-state: truncated okreg"))?
            != 0;
        let val: [u8; 16] = payload
            .get(off + 8..off + 24)
            .ok_or_else(|| Error::msg("vcpu-state: truncated okreg val"))?
            .try_into()
            .unwrap();
        map.insert(name, (val, ok));
        off += 24;
    }
    let mut vals = Vec::with_capacity(canonical.len());
    let mut oks = Vec::with_capacity(canonical.len());
    for n in canonical {
        match map.get(&(*n as u32)) {
            Some((v, ok)) => {
                vals.push(*v);
                oks.push(*ok);
            }
            None => {
                vals.push([0u8; 16]);
                oks.push(false);
            }
        }
    }
    Ok((vp_idx, vals, oks))
}

/// Decode a blob block. Returns (vp_idx, bytes).
pub fn decode_blob(payload: &[u8]) -> Result<(u32, Vec<u8>)> {
    let vp_idx = rd_u32(payload, 0)?;
    let len = rd_u32(payload, 4)? as usize;
    let bytes = payload
        .get(8..8 + len)
        .ok_or_else(|| Error::msg("vcpu-state: truncated blob"))?
        .to_vec();
    Ok((vp_idx, bytes))
}
