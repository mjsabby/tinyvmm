//! tinyvmm (Rust) — a tiny user-mode VMM on the Windows Hypervisor Platform.
//! Phase 1: boot an unmodified PVH Linux kernel to a serial console.

// windows-sys exposes WHv* enum values as non-UPPER_CASE consts; we match on
// them in patterns throughout the run loop.
#![allow(non_upper_case_globals)]
// Several WHP/device helper APIs and fields are deliberately ahead of their
// first caller in this phase-1 core (they're exercised by the deferred PCI/
// virtio/snapshot phases). Keep them without dead-code noise.
#![allow(dead_code)]

mod boot;
mod devices;
mod diag;
mod display;
mod error;
mod host;
mod net;
mod pci;
mod virtio;
mod whp;

use crate::devices::io_bus::IoBus;
use crate::devices::legacy::LegacyIsaStubs;
use crate::devices::mmio_bus::MmioBus;
use crate::devices::pic::Pic8259;
use crate::devices::pit::Pit8254;
use crate::devices::serial::Serial8250;
use crate::display::Display;
use crate::error::{check_hr, Error, Result};
use crate::host::block_file::BlockFile;
use crate::net::nat::{NatBackend, NatOptions, PortForward};
use crate::pci::{PciBus, PciFunction};
use crate::virtio::blk::BlockDevice;
use crate::virtio::console::ConsoleDevice;
use crate::virtio::device::VirtioDevice;
use crate::virtio::gpu::GpuDevice;
use crate::virtio::input::{InputDevice, InputEvent};
use crate::virtio::net::{LoopbackBackend, NetDevice};
use crate::virtio::p9::P9Device;
use crate::virtio::rng::RngDevice;
use crate::virtio::transport::{self, PciTransport};
use crate::whp::cpu_affinity::{self, AffinityMode};
use crate::whp::cpuid::{build_static_cpuid_result_list, cached_tsc_hz, set_hide_tsc_deadline};
use crate::whp::hv::HvEnlightenment;
use crate::whp::run_loop::{RunLoop, StopReason};
use crate::whp::{GuestMemory, Partition, Vcpu};

use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{GetFileType, ReadFile, FILE_TYPE_CHAR};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleInputW, SetConsoleMode,
    CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT,
    ENABLE_MOUSE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT, ENABLE_QUICK_EDIT_MODE,
    ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT,
    FROM_LEFT_1ST_BUTTON_PRESSED, FROM_LEFT_2ND_BUTTON_PRESSED, INPUT_RECORD, KEY_EVENT,
    MOUSE_EVENT, MOUSE_EVENT_RECORD, MOUSE_HWHEELED, MOUSE_WHEELED, RIGHTMOST_BUTTON_PRESSED,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Hypervisor::{
    WHvGetCapability, WHvRequestInterrupt, WHvCapabilityCodeHypervisorPresent,
    WHvX64LocalApicEmulationModeX2Apic, WHV_INTERRUPT_CONTROL, WHV_PARTITION_HANDLE,
};

const MAX_VCPUS: u32 = boot::acpi::MAX_VCPUS;

#[derive(Clone, Copy, PartialEq)]
enum NetBackendKind {
    Loopback,
    Nat,
    Wintun,
}

impl NetBackendKind {
    fn as_str(self) -> &'static str {
        match self {
            NetBackendKind::Loopback => "loopback",
            NetBackendKind::Nat => "nat",
            NetBackendKind::Wintun => "wintun",
        }
    }
    fn from_str(s: &str) -> Option<NetBackendKind> {
        match s {
            "loopback" => Some(NetBackendKind::Loopback),
            "nat" => Some(NetBackendKind::Nat),
            "wintun" => Some(NetBackendKind::Wintun),
            _ => None,
        }
    }
}

/// One virtio-net NIC. `--net` (repeatable) appends a NIC; `--net-backend`,
/// `--portfwd`, `--wintun-name`, `--wintun-host` modify the most recent NIC.
#[derive(Clone)]
struct NicSpec {
    backend: NetBackendKind,
    port_forwards: Vec<PortForward>,
    wintun_name: Option<String>,
    wintun_host: Option<[u8; 4]>,
}

impl NicSpec {
    fn new() -> Self {
        NicSpec {
            backend: NetBackendKind::Nat,
            port_forwards: Vec::new(),
            wintun_name: None,
            wintun_host: None,
        }
    }
}

#[derive(Clone)]
struct DriveSpec {
    path: String,
    readonly: bool,
}

#[derive(Clone)]
struct P9ShareSpec {
    tag: String,
    host_root: std::path::PathBuf,
    readonly: bool,
}

fn print_usage() {
    eprintln!(
        "tinyvmm (rust) — phase 1 (PVH boot core)\n\
         \n\
         Usage:\n\
         \x20 tinyvmm --smoke\n\
         \x20 tinyvmm --blk-selftest        host-side virtio-blk DISCARD/WRITE_ZEROES test\n\
         \x20 tinyvmm --pci-selftest        host-side PCI host-bridge + BAR + sizing test\n\
         \x20 tinyvmm --pvh-info <vmlinux>\n\
         \x20 tinyvmm --pvh-run [--initrd <cpio>] [--ram-mb N] [--vcpus N] [--rng] [--input]\n\
         \x20              [--net [--net-backend loopback|nat] [--portfwd H:G]...]...  (repeat --net per NIC)\n\
         \x20              [--drive <path>[,readonly]]... [--cpu-affinity all|p|e|p-physical]\n\
         \x20              [--virtio-9p-share <tag>=<host_path>[,ro]]...\n\
         \x20              [--gpu [WxH]]  (virtio-gpu 2D scanout to a window; default 1280x800)\n\
         \x20              [--save <path> [--unsafe-save-mutable-drive]]\n\
         \x20              [--watchdog-secs N] [--debug-boot] <vmlinux> [-- <cmdline>]\n\
         \x20 tinyvmm --restore <path> [--drive <path>[,ro|rw]]... [--cpu-affinity all|p|e|p-physical]\n\
         \x20              [--watchdog-secs N] [--unsafe-restore-mutable-drive]\n"
    );
}

fn check_whp_available() -> Result<()> {
    let mut present: u32 = 0;
    let mut written: u32 = 0;
    let hr = unsafe {
        WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            &mut present as *mut u32 as *mut c_void,
            4,
            &mut written,
        )
    };
    check_hr(hr, "WHvGetCapability(HypervisorPresent)")?;
    if present == 0 {
        return Err(Error::msg(
            "Windows Hypervisor Platform reports no hypervisor present \
             (enable the 'Windows Hypervisor Platform' Windows feature)",
        ));
    }
    Ok(())
}

fn run_smoke() -> Result<i32> {
    check_whp_available()?;
    println!("[smoke] WHP available");
    // Minimal partition: just a processor count + setup. No extended exits, no
    // CPUID list, no LAPIC emulation — the smoke only needs the raw run path,
    // and x2APIC emulation changes HLT semantics. Mirrors the C++ `RunSmoke`.
    let mut part = Partition::new(1)?;
    part.setup()?;
    let ram = GuestMemory::new(part.handle(), 0, 16 * 1024 * 1024, true, true)?;
    println!(
        "[smoke] mapped {} MiB guest RAM ({})",
        ram.size() / (1024 * 1024),
        if ram.large_pages() {
            "MEM_LARGE_PAGES"
        } else {
            "4 KiB pages"
        }
    );
    println!("[smoke] partition + vCPU created OK (tsc_hz={})", cached_tsc_hz());

    // Drop a HLT (0xF4) at GPA 0x1000 and point CS:IP at it in real mode, then
    // run until the next exit. We expect WHvRunVpExitReasonX64Halt — this proves
    // the whole WHP run path (map RAM, set regs, enter guest, decode exit) works,
    // not just that the handles were created. Mirrors the C++ `RunSmoke`.
    use crate::whp::regs::{reg64, seg};
    use crate::whp::vcpu::{exit_reason_name, ExitReason};
    use windows_sys::Win32::System::Hypervisor::{
        WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs, WHvX64RegisterFs, WHvX64RegisterGs,
        WHvX64RegisterRflags, WHvX64RegisterRip, WHvX64RegisterSs,
    };

    const CODE_GPA: u64 = 0x1000;
    ram.write_at(CODE_GPA, &[0xF4])?;

    let vcpu = Vcpu::new(part.handle(), 0)?;
    // Real-mode segment attributes (high byte of the access rights): code =
    // Type(0xB)|S|P = 0x9B, data = Type(0x3)|S|P = 0x93. CS.Base = CODE_GPA so
    // CS:IP = cs:0 resolves to linear CODE_GPA. RFLAGS bit 1 is reserved-1, IF=0.
    const CODE_ATTR: u16 = 0x9B;
    const DATA_ATTR: u16 = 0x93;
    let code = seg(CODE_GPA, 0xFFFF, (CODE_GPA >> 4) as u16, CODE_ATTR);
    let data = seg(0, 0xFFFF, 0, DATA_ATTR);
    let names = [
        WHvX64RegisterCs,
        WHvX64RegisterDs,
        WHvX64RegisterEs,
        WHvX64RegisterSs,
        WHvX64RegisterFs,
        WHvX64RegisterGs,
        WHvX64RegisterRflags,
        WHvX64RegisterRip,
    ];
    let values = [code, data, data, data, data, data, reg64(0x2), reg64(0)];
    vcpu.set_registers(&names, &values)?;

    println!("[smoke] running vCPU until next exit...");
    let exit = vcpu.run_exit()?;
    println!(
        "[smoke] exit reason = {} RIP={:#x}",
        exit_reason_name(exit.raw_reason()),
        exit.rip()
    );
    if exit.reason() != ExitReason::Halt {
        eprintln!(
            "[smoke] FAIL: expected Halt, got {}",
            exit_reason_name(exit.raw_reason())
        );
        return Ok(2);
    }
    println!("[smoke] PASS");
    Ok(0)
}

/// Host-side self-test of the virtio-blk DISCARD / WRITE_ZEROES path. Drives
/// real requests straight through a `BlockDevice` + async `BlockFile` against a
/// temp file (no guest kernel needed — these ops complete synchronously inside
/// `notify_queue`). Verifies the targeted ranges are zeroed on the host file,
/// untouched ranges are preserved, and the op counters advance. Mirrors the
/// C++ `--virtio-blk-discard-test`.
fn run_blk_selftest() -> Result<i32> {
    use crate::virtio::blk::BlockDevice;

    const NEXT: u16 = 1;
    const WRITE: u16 = 2;
    const T_DISCARD: u32 = 11;
    const T_WRITE_ZEROES: u32 = 13;

    check_whp_available()?;
    let mut part = Partition::new(1)?;
    part.enable_extended_exits(true, true, false)?;
    set_hide_tsc_deadline(true);
    let list = build_static_cpuid_result_list(true);
    part.set_cpuid_result_list(&list)?;
    part.set_local_apic_emulation(WHvX64LocalApicEmulationModeX2Apic)?;
    part.setup()?;
    let ram = Arc::new(GuestMemory::new(part.handle(), 0, 4 * 1024 * 1024, false, false)?);

    // A 64 KiB temp file prefilled with 0xFF.
    let path = std::env::temp_dir().join("tinyvmm_blk_selftest.img");
    let path_str = path.to_string_lossy().to_string();
    std::fs::write(&path, vec![0xFFu8; 64 * 1024])
        .map_err(|e| Error::msg(format!("selftest: write temp file: {e}")))?;

    let backend = Arc::new(BlockFile::new(&path_str, false));
    if !backend.open() {
        let _ = std::fs::remove_file(&path);
        return Err(Error::msg(format!(
            "selftest: BlockFile open failed err={}",
            backend.open_err()
        )));
    }
    backend.start();
    let dev = BlockDevice::new(ram.clone(), backend.clone(), 64);

    // Virtqueue layout in guest RAM (GPA base 0).
    let desc_gpa: u64 = 0x1_0000;
    let avail_gpa: u64 = 0x1_1000;
    let used_gpa: u64 = 0x1_2000;
    const QSIZE: u16 = 8;

    let put = |gpa: u64, bytes: &[u8]| ram.write_at(gpa, bytes).expect("selftest write_at");
    let write_desc = |i: u64, addr: u64, len: u32, flags: u16, next: u16| {
        let base = desc_gpa + i * 16;
        put(base, &addr.to_le_bytes());
        put(base + 8, &len.to_le_bytes());
        put(base + 12, &flags.to_le_bytes());
        put(base + 14, &next.to_le_bytes());
    };

    dev.enable_queue(0, desc_gpa, avail_gpa, used_gpa, QSIZE, false);

    // Issue one range request (header + 16-byte range descriptor + status) using
    // descriptors [d, d+1, d+2] and buffers at `buf_gpa`. Returns the status byte.
    let issue = |avail_slot: u16, d: u64, buf_gpa: u64, rtype: u32, sector: u64, num_sectors: u32| -> u8 {
        let hdr = buf_gpa;
        let range = buf_gpa + 0x100;
        let stat = buf_gpa + 0x200;
        // virtio_blk_req header: le32 type, le32 reserved, le64 sector.
        put(hdr, &rtype.to_le_bytes());
        put(hdr + 4, &0u32.to_le_bytes());
        put(hdr + 8, &0u64.to_le_bytes());
        // virtio_blk_discard_write_zeroes: le64 sector, le32 num_sectors, le32 flags.
        put(range, &sector.to_le_bytes());
        put(range + 8, &num_sectors.to_le_bytes());
        put(range + 12, &0u32.to_le_bytes());
        put(stat, &[0xAAu8]); // sentinel; device overwrites with status
        write_desc(d, hdr, 16, NEXT, (d + 1) as u16);
        write_desc(d + 1, range, 16, NEXT, (d + 2) as u16);
        write_desc(d + 2, stat, 1, WRITE, 0);
        // avail ring: ring[slot] = head desc index; publish idx = slot+1.
        put(avail_gpa + 4 + 2 * avail_slot as u64, &(d as u16).to_le_bytes());
        put(avail_gpa + 2, &(avail_slot + 1).to_le_bytes());
        dev.notify_queue(0);
        ram.slice_mut(stat, 1).expect("selftest status")[0]
    };

    // WRITE_ZEROES on sectors [0, 16) -> bytes [0, 8192); DISCARD on sectors
    // [64, 80) -> bytes [32768, 40960).
    let st_wz = issue(0, 0, 0x2_0000, T_WRITE_ZEROES, 0, 16);
    let st_dc = issue(1, 3, 0x3_0000, T_DISCARD, 64, 16);

    let ops_wz = dev.ops_write_zeroes();
    let ops_dc = dev.ops_discard();
    let ops_err = dev.ops_err();

    // Release the device + backend so the file handle is closed before we read.
    drop(dev);
    drop(backend);
    let data = std::fs::read(&path).map_err(|e| Error::msg(format!("selftest: read back: {e}")))?;
    let _ = std::fs::remove_file(&path);

    let zeroed = |r: std::ops::Range<usize>| data[r.clone()].iter().all(|&b| b == 0);
    let intact = |r: std::ops::Range<usize>| data[r.clone()].iter().all(|&b| b == 0xFF);

    let mut ok = true;
    let mut fail = |cond: bool, msg: &str| {
        if !cond {
            ok = false;
            eprintln!("[blk-selftest] FAIL: {msg}");
        }
    };
    fail(st_wz == 0, "WRITE_ZEROES status != OK");
    fail(st_dc == 0, "DISCARD status != OK");
    fail(ops_wz == 1, "ops_write_zeroes != 1");
    fail(ops_dc == 1, "ops_discard != 1");
    fail(ops_err == 0, "ops_err != 0");
    fail(zeroed(0..8192), "WRITE_ZEROES region not zeroed");
    fail(intact(8192..32768), "gap before DISCARD was modified");
    fail(zeroed(32768..40960), "DISCARD region not zeroed");
    fail(intact(40960..65536), "tail after DISCARD was modified");

    if ok {
        println!(
            "[blk-selftest] PASS: WRITE_ZEROES + DISCARD zero the host file, \
             ranges isolated (wz={ops_wz} discard={ops_dc} err={ops_err})"
        );
        Ok(0)
    } else {
        Ok(1)
    }
}

/// A minimal host-side `PciFunction` for `--pci-selftest`: one 16 KiB 64-bit
/// MMIO BAR over a real `PciConfigSpace`, no guest. Lets the selftest exercise
/// the PCI host bridge (0xCF8/0xCFC routing + BAR pre-assignment + sizing)
/// without standing up a partition. Mirrors the spirit of C++ `--pci-test`.
struct SelftestPciDevice {
    cfg: std::sync::Mutex<crate::pci::config::PciConfigSpace>,
}

impl SelftestPciDevice {
    fn new() -> Arc<Self> {
        use crate::pci::config::PciConfigSpace;
        let mut c = PciConfigSpace::new();
        c.set_ids(0x1AF4, 0x1052, 0x1AF4, 0x0001);
        c.set_class(0xFF, 0x00, 0x00, 0x01);
        c.declare_mmio64_bar(0, 0x4000, false); // 16 KiB MMIO64
        Arc::new(SelftestPciDevice {
            cfg: std::sync::Mutex::new(c),
        })
    }
}

impl PciFunction for SelftestPciDevice {
    fn name(&self) -> &str {
        "pci-selftest-dummy"
    }
    fn config_read(&self, offset: u32, size: u32) -> u32 {
        self.cfg.lock().unwrap().read(offset, size)
    }
    fn config_write(&self, offset: u32, size: u32, value: u32) {
        let _ = self.cfg.lock().unwrap().write(offset, size, value);
    }
    fn bar_layout(&self) -> [(crate::pci::config::BarKind, u32); 6] {
        self.cfg.lock().unwrap().bar_layout()
    }
    fn assign_bar_base(&self, idx: usize, gpa: u64) {
        self.cfg.lock().unwrap().set_bar_base(idx, gpa);
    }
}

/// Drive one Type-0 config read through the 0xCF8/0xCFC port pair.
fn pci_cfg_read(io: &IoBus, dev: u8, off: u32, size: u16) -> u32 {
    use crate::devices::io_bus::IoAccess;
    use crate::pci::CONFIG_ADDRESS_ENABLE;
    let addr = CONFIG_ADDRESS_ENABLE | ((dev as u32) << 11) | (off & 0xFC);
    let mut a = IoAccess { port: 0xCF8, access_size: 4, is_write: true, value: addr };
    io.dispatch(&mut a);
    let mut d = IoAccess {
        port: 0xCFC + (off & 0x3) as u16,
        access_size: size,
        is_write: false,
        value: 0,
    };
    io.dispatch(&mut d);
    d.value
}

/// Drive one Type-0 config write through the 0xCF8/0xCFC port pair.
fn pci_cfg_write(io: &IoBus, dev: u8, off: u32, size: u16, value: u32) {
    use crate::devices::io_bus::IoAccess;
    use crate::pci::CONFIG_ADDRESS_ENABLE;
    let addr = CONFIG_ADDRESS_ENABLE | ((dev as u32) << 11) | (off & 0xFC);
    let mut a = IoAccess { port: 0xCF8, access_size: 4, is_write: true, value: addr };
    io.dispatch(&mut a);
    let mut d = IoAccess {
        port: 0xCFC + (off & 0x3) as u16,
        access_size: size,
        is_write: true,
        value,
    };
    io.dispatch(&mut d);
}

/// Host-side PCI host-bridge selftest (no guest): builds a PciBus + one dummy
/// device, then drives 0xCF8/0xCFC config cycles to verify ID reads, BAR
/// pre-assignment into the MMIO window, the BAR sizing dance, and master-abort
/// reads for absent functions. Mirrors C++ `--pci-test`.
fn run_pci_selftest() -> Result<i32> {
    let bus = PciBus::new();
    let dev = SelftestPciDevice::new();
    let bdf = bus.add_device(dev);
    let mut io = IoBus::new();
    bus.attach_io_bus(&mut io);
    let d = bdf.device;

    let mut fails = 0u32;
    let mut check = |cond: bool, msg: &str| {
        println!("[pci-selftest] {} {msg}", if cond { " ok:" } else { "FAIL:" });
        if !cond {
            fails += 1;
        }
    };

    // 1. Vendor / device ID readable through CF8/CFC.
    check(pci_cfg_read(&io, d, 0x00, 2) == 0x1AF4, "vendor id 0x1AF4");
    check(pci_cfg_read(&io, d, 0x02, 2) == 0x1052, "device id 0x1052");

    // 2. BAR0 pre-assigned into [0xE000_0000, 0xFEC0_0000) and flagged 64-bit.
    let bar0_raw = pci_cfg_read(&io, d, 0x10, 4);
    let bar0 = (bar0_raw & 0xFFFF_FFF0) as u64;
    check(
        (0xE000_0000..0xFEC0_0000).contains(&bar0),
        "BAR0 pre-assigned in MMIO window",
    );
    check(bar0_raw & 0x6 == 0x4, "BAR0 advertises 64-bit memory");
    check(
        pci_cfg_read(&io, d, 0x14, 4) == 0,
        "BAR0 high dword reads 0 (base < 4 GiB)",
    );

    // 3. BAR sizing dance through CF8/CFC: write all-ones, read size mask.
    let saved = pci_cfg_read(&io, d, 0x10, 4);
    pci_cfg_write(&io, d, 0x10, 4, 0xFFFF_FFFF);
    let sized = pci_cfg_read(&io, d, 0x10, 4) & 0xFFFF_FFF0;
    check((!sized).wrapping_add(1) == 0x4000, "BAR0 sizes to 16 KiB");
    pci_cfg_write(&io, d, 0x10, 4, saved); // restore the programmed base

    // 4. An absent function reads all-ones (master abort).
    check(
        pci_cfg_read(&io, 31, 0x00, 4) == 0xFFFF_FFFF,
        "absent device reads all-ones",
    );

    if fails == 0 {
        println!("[pci-selftest] PASS");
        Ok(0)
    } else {
        println!("[pci-selftest] FAIL ({fails} check(s) failed)");
        Ok(2)
    }
}

fn run_pvh_info(args: &[String]) -> Result<i32> {
    let path = args
        .get(2)
        .ok_or_else(|| Error::msg("--pvh-info: expected path to vmlinux"))?;
    let bytes = std::fs::read(path).map_err(|e| Error::msg(format!("read {path}: {e}")))?;
    println!("[pvh] path={path}");
    boot::loader::print_pvh_info(&bytes)?;
    Ok(0)
}

struct PvhArgs {
    vmlinux: String,
    cmdline: String,
    initrd: Option<String>,
    ram_mb: u32,
    vcpus: u32,
    watchdog_secs: u32,
    nics: Vec<NicSpec>,
    with_rng: bool,
    with_gpu: bool,
    gpu_width: u32,
    gpu_height: u32,
    drives: Vec<DriveSpec>,
    affinity_mode: AffinityMode,
    p9_shares: Vec<P9ShareSpec>,
    save_path: Option<String>,
    unsafe_save_mutable_drive: bool,
    with_input: bool,
}

/// Parse a `--portfwd HOSTPORT:GUESTPORT` rule. The host side binds 127.0.0.1
/// and the guest side targets the standard guest IP 10.0.0.2.
fn parse_portfwd(s: &str) -> Result<PortForward> {
    let parts: Vec<&str> = s.split(':').collect();
    let [hp, gp] = parts.as_slice() else {
        return Err(Error::msg("--portfwd wants HOSTPORT:GUESTPORT"));
    };
    let host_port: u16 = hp
        .parse()
        .map_err(|_| Error::msg("--portfwd: bad host port"))?;
    let guest_port: u16 = gp
        .parse()
        .map_err(|_| Error::msg("--portfwd: bad guest port"))?;
    Ok(PortForward {
        host_addr: [127, 0, 0, 1],
        host_port,
        guest_ip: [10, 0, 0, 2],
        guest_port,
    })
}

/// Parse a `WIDTHxHEIGHT` display size (e.g. "1280x800"). Returns `None` if the
/// string isn't two positive integers joined by 'x'/'X'.
fn parse_wxh(s: &str) -> Option<(u32, u32)> {
    let (w, h) = s.split_once(['x', 'X'])?;
    let w: u32 = w.parse().ok()?;
    let h: u32 = h.parse().ok()?;
    if w == 0 || h == 0 {
        return None;
    }
    Some((w, h))
}

fn parse_pvh_args(args: &[String]) -> Result<PvhArgs> {
    let mut initrd = None;
    let mut ram_mb = 256u32;
    let mut vcpus = 1u32;
    let mut watchdog_secs = 0u32;
    let mut debug_boot = false;
    let mut nics: Vec<NicSpec> = Vec::new();
    let mut with_rng = false;
    let mut with_gpu = false;
    let mut gpu_width = 1280u32;
    let mut gpu_height = 800u32;
    let mut drives: Vec<DriveSpec> = Vec::new();
    let mut affinity_mode = AffinityMode::All;
    let mut p9_shares: Vec<P9ShareSpec> = Vec::new();
    let mut save_path: Option<String> = None;
    let mut unsafe_save_mutable_drive = false;
    let mut with_input = false;

    let mut i = 2;
    while i < args.len() && args[i].starts_with("--") && args[i] != "--" {
        match args[i].as_str() {
            "--initrd" => {
                i += 1;
                initrd = Some(
                    args.get(i)
                        .ok_or_else(|| Error::msg("--initrd wants a path"))?
                        .clone(),
                );
            }
            "--ram-mb" => {
                i += 1;
                let v: u32 = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| {
                        Error::msg("--ram-mb wants a positive integer in MiB (128..3584)")
                    })?;
                // Hard range: the PCI MMIO window opens at 0xE000_0000 = 3584 MiB,
                // so a larger contiguous region would collide with device BARs.
                // Reject (don't clamp) so a typo surfaces instead of silently
                // running a differently-sized VM. Mirrors the C++ --ram-mb.
                if !(128..=3584).contains(&v) {
                    return Err(Error::msg(format!(
                        "--ram-mb: {v} out of range [128..3584] MiB (>3584 needs a low/high \
                         RAM split around the PCI MMIO hole; not supported)"
                    )));
                }
                ram_mb = v;
            }
            "--vcpus" => {
                i += 1;
                vcpus = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::msg("--vcpus wants an integer"))?;
            }
            "--watchdog-secs" => {
                i += 1;
                watchdog_secs = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::msg("--watchdog-secs wants an integer"))?;
            }
            "--debug-boot" => debug_boot = true,
            "--net" => nics.push(NicSpec::new()),
            "--net-backend" => {
                i += 1;
                let k = args
                    .get(i)
                    .ok_or_else(|| Error::msg("--net-backend wants loopback|nat|wintun"))?;
                let backend = NetBackendKind::from_str(k).ok_or_else(|| {
                    Error::msg(format!("--net-backend: unknown '{k}' (want loopback|nat|wintun)"))
                })?;
                // Modify the most recent NIC; create one if --net-backend is
                // used without a preceding --net (back-compat single-NIC form).
                if nics.is_empty() {
                    nics.push(NicSpec::new());
                }
                nics.last_mut().unwrap().backend = backend;
            }
            "--wintun-name" => {
                i += 1;
                let s = args
                    .get(i)
                    .ok_or_else(|| Error::msg("--wintun-name wants an adapter name"))?
                    .clone();
                if nics.is_empty() {
                    nics.push(NicSpec::new());
                }
                nics.last_mut().unwrap().wintun_name = Some(s);
            }
            "--wintun-host" => {
                i += 1;
                let s = args
                    .get(i)
                    .ok_or_else(|| Error::msg("--wintun-host wants an IPv4 (e.g. 10.0.0.1)"))?;
                let ip = parse_ipv4(s)
                    .ok_or_else(|| Error::msg(format!("--wintun-host: bad IPv4 '{s}'")))?;
                if nics.is_empty() {
                    nics.push(NicSpec::new());
                }
                nics.last_mut().unwrap().wintun_host = Some(ip);
            }
            "--portfwd" => {
                i += 1;
                let s = args
                    .get(i)
                    .ok_or_else(|| Error::msg("--portfwd wants HOSTPORT:GUESTPORT"))?;
                let pf = parse_portfwd(s)?;
                if nics.is_empty() {
                    nics.push(NicSpec::new());
                }
                nics.last_mut().unwrap().port_forwards.push(pf);
            }
            "--rng" => with_rng = true,
            "--gpu" => {
                with_gpu = true;
                // Optional immediate WxH size (e.g. `--gpu 1024x768`). If the
                // next token isn't a size it's left for the kernel-path arg.
                if let Some((w, h)) = args.get(i + 1).and_then(|s| parse_wxh(s)) {
                    gpu_width = w;
                    gpu_height = h;
                    i += 1;
                }
            }
            "--input" => with_input = true,
            "--cpu-affinity" => {
                i += 1;
                let m = args
                    .get(i)
                    .ok_or_else(|| Error::msg("--cpu-affinity wants all|p|e|p-physical"))?;
                affinity_mode = cpu_affinity::parse_affinity_mode(m).ok_or_else(|| {
                    Error::msg(format!(
                        "--cpu-affinity: unknown mode '{m}' (want all|p|e|p-physical)"
                    ))
                })?;
            }
            "--drive" => {
                i += 1;
                let spec = args
                    .get(i)
                    .ok_or_else(|| Error::msg("--drive wants <path>[,readonly]"))?;
                let mut parts = spec.splitn(2, ',');
                let path = parts.next().unwrap_or("").to_string();
                let mut readonly = false;
                if let Some(opts) = parts.next() {
                    for kv in opts.split(',') {
                        match kv {
                            "readonly" | "ro" => readonly = true,
                            other => {
                                return Err(Error::msg(format!(
                                    "--drive: unknown option '{other}' (want readonly)"
                                )))
                            }
                        }
                    }
                }
                if path.is_empty() {
                    return Err(Error::msg("--drive: empty path"));
                }
                if drives.len() >= 8 {
                    return Err(Error::msg("--drive: max 8 drives supported"));
                }
                drives.push(DriveSpec { path, readonly });
            }
            "--virtio-9p-share" => {
                i += 1;
                let spec = args
                    .get(i)
                    .ok_or_else(|| Error::msg("--virtio-9p-share wants <tag>=<host_path>[,ro]"))?;
                let eq = spec.find('=').ok_or_else(|| {
                    Error::msg("--virtio-9p-share: missing '=' (want <tag>=<host_path>[,ro])")
                })?;
                let tag = spec[..eq].to_string();
                if tag.is_empty() || tag.len() > 256 {
                    return Err(Error::msg("--virtio-9p-share: tag must be 1..256 bytes"));
                }
                let mut parts = spec[eq + 1..].splitn(2, ',');
                let path = parts.next().unwrap_or("");
                let mut readonly = false;
                if let Some(opts) = parts.next() {
                    for kv in opts.split(',') {
                        match kv {
                            "readonly" | "ro" => readonly = true,
                            other => {
                                return Err(Error::msg(format!(
                                    "--virtio-9p-share: unknown option '{other}' (want ro)"
                                )))
                            }
                        }
                    }
                }
                if path.is_empty() {
                    return Err(Error::msg("--virtio-9p-share: empty host path"));
                }
                let host = std::fs::canonicalize(path).map_err(|e| {
                    Error::msg(format!(
                        "--virtio-9p-share: cannot resolve host path '{path}': {e}"
                    ))
                })?;
                if !host.is_dir() {
                    return Err(Error::msg(format!(
                        "--virtio-9p-share: host path is not a directory: {}",
                        host.display()
                    )));
                }
                if p9_shares.iter().any(|s| s.tag == tag) {
                    return Err(Error::msg(format!("--virtio-9p-share: duplicate tag '{tag}'")));
                }
                if p9_shares.len() >= 8 {
                    return Err(Error::msg("--virtio-9p-share: max 8 shares supported"));
                }
                p9_shares.push(P9ShareSpec {
                    tag,
                    host_root: host,
                    readonly,
                });
            }
            "--save" => {
                i += 1;
                save_path = Some(
                    args.get(i)
                        .ok_or_else(|| Error::msg("--save wants a path"))?
                        .clone(),
                );
            }
            "--unsafe-save-mutable-drive" => unsafe_save_mutable_drive = true,
            other => return Err(Error::msg(format!("--pvh-run: unknown flag {other}"))),
        }
        i += 1;
    }

    let vmlinux = args
        .get(i)
        .ok_or_else(|| Error::msg("--pvh-run: expected path to vmlinux"))?
        .clone();
    i += 1;

    // Everything after a bare "--" is the kernel cmdline.
    let mut cmdline = String::new();
    if i < args.len() && args[i] == "--" {
        i += 1;
        cmdline = args[i..].join(" ");
    }
    if cmdline.is_empty() {
        // Phase 2 default: route the kernel console to the virtio-console
        // (hvc0) so the initramfs /init drops to an interactive shell. With
        // --debug-boot, also stream early boot to ttyS0 (the 8250) before
        // hvc0 comes up. pci=conf1 forces our 0xCF8/0xCFC mechanism. Without a
        // GPU we also disable the kernel framebuffer/KMS (`nofb nomodeset`);
        // with --gpu we drop those so the virtio-gpu DRM driver can mode-set.
        let fb = if with_gpu { "" } else { " nofb nomodeset" };
        cmdline = if debug_boot {
            format!("earlyprintk=ttyS0,115200 console=hvc0 pci=conf1,nocrs,lastbus=0{fb}")
        } else {
            format!("console=hvc0 pci=conf1,nocrs,lastbus=0{fb}")
        };
    }

    Ok(PvhArgs {
        vmlinux,
        cmdline,
        initrd,
        ram_mb,
        vcpus: vcpus.clamp(1, MAX_VCPUS),
        watchdog_secs,
        nics,
        with_rng,
        with_gpu,
        gpu_width,
        gpu_height,
        drives,
        affinity_mode,
        p9_shares,
        save_path,
        unsafe_save_mutable_drive,
        with_input,
    })
}

/// Heavy post-mortem diagnostics (per-vCPU exit breakdown + a guest-RAM dump)
/// are gated behind the `TINYVMM_DIAG` env var so normal runs stay quiet.
/// Enabled when set to a non-empty value whose first char isn't '0'. Mirrors the
/// C++ `TINYVMM_DIAG=1` gate.
fn diag_enabled() -> bool {
    std::env::var("TINYVMM_DIAG")
        .map(|v| !v.is_empty() && !v.starts_with('0'))
        .unwrap_or(false)
}

/// Dump the first `min(64 MiB, ram)` of guest RAM to `path` for post-mortem
/// inspection (grep printk strings, parse the dmesg ringbuffer, ...). Best
/// effort: a failure is warned about, not fatal.
fn dump_guest_ram(ram: &GuestMemory, path: &str) {
    const DUMP_BYTES: usize = 64 * 1024 * 1024;
    let n = DUMP_BYTES.min(ram.size());
    // SAFETY: host_base()..+size() is the live guest RAM slab; we read n <= size.
    let slice = unsafe { std::slice::from_raw_parts(ram.host_base(), n) };
    match std::fs::write(path, slice) {
        Ok(()) => eprintln!(
            "[pvh-run] dumped {} MiB of guest RAM to {path}",
            n / (1024 * 1024)
        ),
        Err(e) => eprintln!("[pvh-run] WARN: guest RAM dump to {path} failed: {e}"),
    }
}

fn run_pvh_run(args: &[String]) -> Result<i32> {
    let cfg = parse_pvh_args(args)?;

    // Snapshot save preconditions (mirror the C++, relaxed for net): a snapshot
    // must capture a self-contained machine. virtio-net AND virtio-9p are both
    // snapshottable: the net device model is captured and a FRESH backend is
    // wired in on restore (live external flows reset, but new flows + the device
    // work); the 9p device captures its fid table (paths + open modes) and
    // reopens the host handles on restore. Drives must be read-only unless the
    // operator opts in (the disk is not part of the snapshot).
    if cfg.save_path.is_some() && !cfg.unsafe_save_mutable_drive {
        for d in &cfg.drives {
            if !d.readonly {
                return Err(Error::msg(format!(
                    "--save refuses the mutable drive '{}' (pass --unsafe-save-mutable-drive \
                     to override, or mark the drive ,readonly)",
                    d.path
                )));
            }
        }
    }

    let mut btimer = diag::boot_timer::BootTimer::new();
    btimer.mark("pvh-run start");

    check_whp_available()?;
    println!("[pvh-run] WHP available");
    btimer.mark("WHP probe done");

    diag::etw::Event::new("VmStart", diag::etw::INFO, diag::etw::kw::LIFECYCLE)
        .str("kernel", &cfg.vmlinux)
        .u64("ram_mb", cfg.ram_mb as u64)
        .u32("vcpus", cfg.vcpus)
        .u32("nics", cfg.nics.len() as u32)
        .u32("rng", cfg.with_rng as u32)
        .u32("drives", cfg.drives.len() as u32)
        .u32("gpu", cfg.with_gpu as u32)
        .write();

    if host::enable_lock_memory_privilege() {
        println!("[host] SeLockMemoryPrivilege: enabled");
    }

    let ram_bytes = (cfg.ram_mb as usize) << 20;

    // --- Partition ---
    let mut part = Partition::new(cfg.vcpus)?;
    part.enable_extended_exits(true, true, false)?;
    set_hide_tsc_deadline(true);
    let static_cpuid = build_static_cpuid_result_list(true);
    part.set_cpuid_result_list(&static_cpuid)?;
    part.set_local_apic_emulation(WHvX64LocalApicEmulationModeX2Apic)?;
    part.setup()?;
    let part_handle = part.handle();

    // --- Guest RAM ---
    let ram = Arc::new(GuestMemory::new(part_handle, 0, ram_bytes, true, true)?);
    println!(
        "[pvh-run] guest RAM: {} MiB at GPA 0 ({})",
        ram.size() / (1024 * 1024),
        if ram.large_pages() {
            "MEM_LARGE_PAGES"
        } else {
            "4 KiB pages"
        }
    );

    // --- Hyper-V enlightenment (Reference TSC page + MSRs) ---
    let hv = Arc::new(HvEnlightenment::new(ram.clone(), cached_tsc_hz()));
    println!(
        "[pvh-run] Hyper-V enlightenment ready (tsc_hz={}, scale=0x{:016x})",
        hv.tsc_hz(),
        hv.tsc_scale()
    );
    btimer.mark("guest RAM mapped");

    // --- Load kernel + initramfs (memory-mapped; pages go straight to a
    // memcpy into guest RAM, no read-into-Vec copy). The mappings are dropped
    // right after load_pvh has copied the bytes. ---
    let load = {
        let vmlinux = host::mapped_file::MappedFile::open(&cfg.vmlinux)?;
        let initramfs = match &cfg.initrd {
            Some(p) => Some(host::mapped_file::MappedFile::open(p)?),
            None => None,
        };
        boot::loader::load_pvh(
            &ram,
            vmlinux.bytes(),
            &cfg.cmdline,
            ram.size() as u64,
            initramfs.as_ref().map(|m| m.bytes()),
            cfg.vcpus,
        )?
    };
    println!(
        "[pvh-run] loaded {} bytes; entry=0x{:08x} start_info_gpa=0x{:x}",
        load.bytes_loaded, load.entry_point, load.start_info_gpa
    );
    if load.initramfs_size > 0 {
        println!(
            "[pvh-run] initramfs: {} bytes at GPA 0x{:x}",
            load.initramfs_size, load.initramfs_gpa
        );
    }
    println!("[pvh-run] cmdline: \"{}\"", cfg.cmdline);
    btimer.mark("vmlinux+initramfs loaded");

    // --- vCPUs ---
    let mut vcpus: Vec<Arc<Vcpu>> = Vec::with_capacity(cfg.vcpus as usize);
    for i in 0..cfg.vcpus {
        vcpus.push(Arc::new(Vcpu::new(part_handle, i)?));
    }
    boot::loader::setup_pvh_entry(&vcpus[0], &load)?;

    // --- Device model ---
    let mut io_bus = IoBus::new();
    let mmio_bus = Arc::new(MmioBus::new());

    let com1 = Serial8250::new(0x3F8);
    com1.attach(&mut io_bus);

    let pit = Pit8254::new();
    pit.attach(&mut io_bus);

    let legacy = LegacyIsaStubs::new();
    legacy.attach(&mut io_bus);

    // Legacy PIC: the only ISA-IRQ -> guest-IDT path in virtual-wire mode.
    let pic = Pic8259::new(Box::new(move |vector: u8, dest: u32| -> bool {
        let ctrl = WHV_INTERRUPT_CONTROL {
            _bitfield: 0, // Type=Fixed, DestMode=Physical, Trigger=Edge
            Destination: dest,
            Vector: vector as u32,
        };
        let hr = unsafe {
            WHvRequestInterrupt(
                part_handle,
                &ctrl,
                std::mem::size_of::<WHV_INTERRUPT_CONTROL>() as u32,
            )
        };
        hr >= 0
    }));
    pic.attach(&mut io_bus);
    {
        let pic = pic.clone();
        com1.set_irq_callback(Box::new(move |irq| pic.raise(irq)));
    }

    // --- PCI bus + virtio-console (interactive hvc0) ---
    let console = ConsoleDevice::new(ram.clone());
    let console_dev: Arc<dyn VirtioDevice> = console.clone();
    let copts = transport::Options {
        vendor_id: 0x1AF4, // Red Hat
        sub_vendor_id: 0x1AF4,
        sub_id: virtio::device::DEVICE_ID_CONSOLE as u16,
        num_msix_vectors: 3, // rx + tx + config-change
        pci_class: 0x07,     // simple communication controller
        pci_subclass: 0x80,  // other
        doorbells: true,     // suppress per-kick VM exits on the console too
    };
    let vcon = PciTransport::new(
        "virtio-pci-console",
        console_dev,
        copts,
        mmio_bus.clone(),
        part_handle,
    );
    {
        // Console -> transport IRQ. Weak to avoid an Arc cycle
        // (transport owns the device; the device's IRQ points back).
        let wt = Arc::downgrade(&vcon);
        console.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
    }
    let pci_bus = PciBus::new();
    let cfunc: Arc<dyn PciFunction> = vcon.clone();
    let bdf = pci_bus.add_device(cfunc);
    println!(
        "[pvh-run] virtio-console on PCI 00:{:02x}.0 (hvc0)",
        bdf.device
    );

    // Snapshot bookkeeping: every virtio PciTransport in PCI-add order. The
    // index into this vec is the device_index stamped into each PciDevice
    // snapshot section, so save/restore must add devices in the same order.
    let mut transports: Vec<Arc<PciTransport>> = vec![vcon.clone()];

    // Kept across the run so save-time quiesce can still each net backend
    // before capturing (a consistent snapshot needs the RX/TX data plane idle).
    let mut net_devices: Vec<Arc<NetDevice>> = Vec::with_capacity(cfg.nics.len());

    // --- virtio-net NICs (repeatable --net), each with its own backend ---
    for (ni, nic) in cfg.nics.iter().enumerate() {
        let mac = nic_mac(ni);
        let net = NetDevice::new(ram.clone(), mac);
        net_devices.push(net.clone());
        let net_dev: Arc<dyn VirtioDevice> = net.clone();
        let nopts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_NET as u16,
            num_msix_vectors: 3, // rx + tx + config-change
            pci_class: 0x02,     // network controller
            pci_subclass: 0x00,
            doorbells: true,     // hot path: suppress the per-kick VM exit
        };
        let nt = PciTransport::new(
            &format!("virtio-pci-net[{ni}]"),
            net_dev,
            nopts,
            mmio_bus.clone(),
            part_handle,
        );
        let wt = Arc::downgrade(&nt);
        net.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        let nfunc: Arc<dyn PciFunction> = nt.clone();
        let nbdf = pci_bus.add_device(nfunc);
        transports.push(nt.clone());
        let backend_name = wire_net_backend(&net, nic)?;
        println!(
            "[pvh-run] virtio-net[{}] on PCI 00:{:02x}.0 ({}, mac {})",
            ni,
            nbdf.device,
            backend_name,
            fmt_mac(&mac)
        );
    }

    // --- virtio-rng (optional, --rng) ---
    if cfg.with_rng {
        let rng = RngDevice::new(ram.clone());
        let rng_dev: Arc<dyn VirtioDevice> = rng.clone();
        let ropts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_RNG as u16,
            num_msix_vectors: 2, // requestq + config-change
            pci_class: 0x10,     // encryption/decryption controller (other)
            pci_subclass: 0x80,
            doorbells: false,    // low-rate; fill is cheap, serviced inline on the vCPU
        };
        let rt = PciTransport::new("virtio-pci-rng", rng_dev, ropts, mmio_bus.clone(), part_handle);
        let wt = Arc::downgrade(&rt);
        rng.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        let rfunc: Arc<dyn PciFunction> = rt.clone();
        let rbdf = pci_bus.add_device(rfunc);
        transports.push(rt.clone());
        println!("[pvh-run] virtio-rng on PCI 00:{:02x}.0 (/dev/hwrng)", rbdf.device);
    }

    // --- virtio-blk (optional, repeatable via --drive) ---
    // Each --drive becomes one virtio-blk PCI device backed by an async
    // host::BlockFile (FILE_FLAG_OVERLAPPED + per-disk IOCP worker thread).
    // Drive N typically appears in the guest as /dev/vd<a+N>. Both the backend
    // and device are kept alive (in these Vecs) past the run loop because the
    // transport references the device and the completion callback runs on the
    // backend's IOCP worker; we stop() each backend in teardown below.
    let mut blk_backends: Vec<Arc<BlockFile>> = Vec::with_capacity(cfg.drives.len());
    let mut blk_devices: Vec<Arc<BlockDevice>> = Vec::with_capacity(cfg.drives.len());
    for (i, d) in cfg.drives.iter().enumerate() {
        let backend = Arc::new(BlockFile::new(&d.path, d.readonly));
        if !backend.open() {
            return Err(Error::msg(format!(
                "--drive: failed to open '{}' (readonly={}): err={}",
                d.path, d.readonly as u32, backend.open_err()
            )));
        }
        let blk = BlockDevice::new(ram.clone(), backend.clone(), 256);
        let blk_dev: Arc<dyn VirtioDevice> = blk.clone();
        let bopts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_BLOCK as u16,
            num_msix_vectors: 2, // requestq + config-change
            pci_class: 0x01,     // mass storage
            pci_subclass: 0x00,  // SCSI controller (canonical for virtio-blk)
            doorbells: true,     // hot I/O path: suppress the per-kick VM exit (the async submit runs on the pump thread)
        };
        let bt = PciTransport::new(
            &format!("virtio-pci-blk[{i}]"),
            blk_dev,
            bopts,
            mmio_bus.clone(),
            part_handle,
        );
        let wt = Arc::downgrade(&bt);
        blk.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        // Wire IRQ before starting the IOCP worker so an early completion
        // can't fire into a null sink.
        backend.start();
        let bfunc: Arc<dyn PciFunction> = bt.clone();
        let bbdf = pci_bus.add_device(bfunc);
        transports.push(bt.clone());
        let cap_sect = backend.size() / 512;
        println!(
            "[pvh-run] virtio-blk[{}] on PCI 00:{:02x}.0 path={}{} capacity={} sectors ({:.1} MiB)",
            i,
            bbdf.device,
            d.path,
            if d.readonly { " (ro)" } else { "" },
            cap_sect,
            backend.size() as f64 / (1024.0 * 1024.0)
        );
        blk_backends.push(backend);
        blk_devices.push(blk);
    }

    // --- virtio-input keyboard + absolute tablet (optional, --input) ---
    // Added after blk and before 9p so the device order matches run_restore.
    // Host source: the GPU window when --gpu is set (wired below), else the
    // interactive console.
    let input_devices = if cfg.with_input {
        let devs = add_input_devices(&ram, &mmio_bus, part_handle, &pci_bus, &mut transports);
        println!(
            "[pvh-run] virtio-input keyboard + tablet on PCI (host source: {})",
            if cfg.with_gpu { "gpu window" } else { "console" }
        );
        Some(devs)
    } else {
        None
    };

    // --- virtio-9p (optional, repeatable via --virtio-9p-share) ---
    // Each share becomes one virtio-9p PCI device exposing one host directory.
    // The guest mounts via:
    //   mount -t 9p -o trans=virtio,version=9p2000.L <tag> /mnt/...
    let mut p9_devices: Vec<Arc<P9Device>> = Vec::with_capacity(cfg.p9_shares.len());
    for (i, s) in cfg.p9_shares.iter().enumerate() {
        let p9 = P9Device::new(ram.clone(), s.tag.clone(), s.host_root.clone(), s.readonly);
        let p9_dev: Arc<dyn VirtioDevice> = p9.clone();
        let popts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_P9 as u16,
            num_msix_vectors: 2, // requestq + config-change
            pci_class: 0xFF,     // unassigned / other
            pci_subclass: 0x00,
            doorbells: true, // run notify (host file I/O) on the pump thread, off the vCPU, and suppress the exit
        };
        let pt = PciTransport::new(
            &format!("virtio-pci-9p[{i}]"),
            p9_dev,
            popts,
            mmio_bus.clone(),
            part_handle,
        );
        let wt = Arc::downgrade(&pt);
        p9.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        let pfunc: Arc<dyn PciFunction> = pt.clone();
        let pbdf = pci_bus.add_device(pfunc);
        transports.push(pt.clone());
        p9_devices.push(p9.clone());
        println!(
            "[pvh-run] virtio-9p[{}] on PCI 00:{:02x}.0 tag={} host={}{}",
            i,
            pbdf.device,
            s.tag,
            s.host_root.display(),
            if s.readonly { " (ro)" } else { "" }
        );
    }

    // --- virtio-gpu (optional, --gpu): basic 2D scanout to a Win32 window ---
    // Added last so its snapshot device-index doesn't perturb the others (and
    // --save + --gpu is refused above anyway). The Display owns a Win32 window
    // on its own message-pump thread; RESOURCE_FLUSH presents the bound scanout
    // resource to it via a CPU blit.
    let mut display: Option<Arc<Display>> = None;
    let mut gpu_keepalive: Option<Arc<GpuDevice>> = None;
    if cfg.with_gpu {
        let gpu = GpuDevice::new(ram.clone(), cfg.gpu_width, cfg.gpu_height);
        let gpu_dev: Arc<dyn VirtioDevice> = gpu.clone();

        // Spawn the display window. If it can't be created we still expose the
        // device (so the guest's GPU probe succeeds); present then no-ops.
        match Display::new(
            &format!("tinyvmm - virtio-gpu {}x{}", cfg.gpu_width, cfg.gpu_height),
            cfg.gpu_width,
            cfg.gpu_height,
        ) {
            Some(d) => {
                let dd = d.clone();
                gpu.set_present_callback(Box::new(move |bgra, w, h| dd.present(bgra, w, h)));
                display = Some(d);
            }
            None => {
                eprintln!("[pvh-run] WARN: virtio-gpu window creation failed; running headless");
            }
        }

        let gopts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_GPU as u16,
            num_msix_vectors: 3, // controlq + cursorq + config-change
            pci_class: 0x03,     // display controller
            pci_subclass: 0x80,  // other
            doorbells: false,    // low-rate; serviced inline on the vCPU thread
        };
        let gt = PciTransport::new("virtio-pci-gpu", gpu_dev, gopts, mmio_bus.clone(), part_handle);
        let wt = Arc::downgrade(&gt);
        gpu.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        let gfunc: Arc<dyn PciFunction> = gt.clone();
        let gbdf = pci_bus.add_device(gfunc);
        transports.push(gt.clone());
        gpu_keepalive = Some(gpu.clone());
        println!(
            "[pvh-run] virtio-gpu on PCI 00:{:02x}.0 ({}x{}{})",
            gbdf.device,
            cfg.gpu_width,
            cfg.gpu_height,
            if display.is_some() { "" } else { ", headless" }
        );
    }

    pci_bus.attach_io_bus(&mut io_bus);

    let io_bus = Arc::new(io_bus);

    // --- Run loops (one per vCPU) ---
    let mut loops: Vec<RunLoop> = Vec::with_capacity(cfg.vcpus as usize);
    for vp in &vcpus {
        let mut rl = RunLoop::new(vp.clone(), io_bus.clone(), mmio_bus.clone(), cfg.vcpus)?;
        rl.set_hv(hv.clone());
        loops.push(rl);
    }

    // Control handles for stopping every loop from the watchdog / after BSP exit.
    let stoppers: Arc<Vec<(Arc<AtomicBool>, Arc<Vcpu>)>> =
        Arc::new(loops.iter().map(|l| (l.stop_flag(), l.vcpu())).collect());
    let stop_all = {
        let stoppers = stoppers.clone();
        move || {
            for (flag, vp) in stoppers.iter() {
                flag.store(true, Ordering::Release);
                let _ = vp.cancel();
            }
        }
    };

    // Watchdog (optional): stop everything after N seconds.
    let watchdog_done = Arc::new(AtomicBool::new(false));
    let watchdog = if cfg.watchdog_secs > 0 {
        let stop_all = stop_all.clone();
        let done = watchdog_done.clone();
        let secs = cfg.watchdog_secs;
        let counters: Vec<_> = loops.iter().map(|l| l.counters()).collect();
        Some(std::thread::spawn(move || {
            for s in 1..=secs {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if done.load(Ordering::Acquire) {
                    return;
                }
                let io: u64 = counters.iter().map(|c| c.io.load(Ordering::Relaxed)).sum();
                let cpuid: u64 = counters.iter().map(|c| c.cpuid.load(Ordering::Relaxed)).sum();
                let msr: u64 = counters.iter().map(|c| c.msr.load(Ordering::Relaxed)).sum();
                eprintln!("[pvh-run] @{s:2}s  io={io} cpuid={cpuid} msr={msr}");
            }
            eprintln!("[pvh-run] watchdog: {secs}s elapsed, requesting stop");
            stop_all();
        }))
    } else {
        None
    };

    // Interactive console: raw stdin -> virtio-console RX. Ctrl+A X quits.
    // When both --gpu and --input are active, the GPU window is the host input
    // source (1:1 pixel coords for the tablet); the console reader then just
    // forwards hvc0 bytes. Otherwise --input falls back to the console source.
    let window_owns_input = display.is_some() && input_devices.is_some();
    if window_owns_input {
        wire_window_input(
            display.as_ref().unwrap(),
            input_devices.as_ref().unwrap(),
            cfg.gpu_width,
            cfg.gpu_height,
        );
    }
    let console_input = if window_owns_input { None } else { input_devices };
    let console_restore =
        setup_interactive_console(console.clone(), console_input, stop_all.clone());

    // Shutdown sentinel watcher: the guest prints this marker on hvc0 to
    // request a clean stop. Harnesses rely on it because an ACPI-less
    // `poweroff` falls back to STI;HLT and never produces a halt VM-exit,
    // which would otherwise leave us spinning idle. We scan the console TX
    // byte stream (guest -> host) for the sentinel and stop every vCPU.
    {
        const SENTINEL: &[u8] = b"=== tinyvmm shutdown requested ===";
        let stop_all = stop_all.clone();
        let mut acc: Vec<u8> = Vec::new();
        let mut fired = false;
        console.set_byte_observer(Box::new(move |bytes: &[u8]| {
            if fired {
                return;
            }
            acc.extend_from_slice(bytes);
            if acc
                .windows(SENTINEL.len())
                .any(|w| w == SENTINEL)
            {
                fired = true;
                stop_all();
            }
            // Bound memory; keep only enough tail for a straddling match.
            if acc.len() > SENTINEL.len() {
                let drop = acc.len() - SENTINEL.len();
                acc.drain(0..drop);
            }
        }));
    }

    println!("[pvh-run] running ({} vCPU(s))", cfg.vcpus);

    // CPU-affinity policy: resolve the CPU-set IDs once, then each vCPU thread
    // pins itself just before entering its run loop. Empty = no pinning.
    let cpu_set_ids = Arc::new(cpu_affinity::resolve_cpu_set_ids(cfg.affinity_mode));
    if cfg.affinity_mode != AffinityMode::All {
        let top = cpu_affinity::topology();
        println!(
            "[cpu-affinity] mode={} -> {} CPU-set(s) (host: {} logical, {} P-logical, \
             {} P-physical, {} E-logical, hybrid={})",
            cpu_affinity::affinity_mode_name(cfg.affinity_mode),
            cpu_set_ids.len(),
            top.total_logical,
            top.p_logical,
            top.p_physical,
            top.e_logical,
            top.hybrid
        );
        if cpu_set_ids.is_empty() {
            eprintln!(
                "[cpu-affinity] WARN: mode '{}' resolved to no CPU sets on this host; \
                 running unpinned",
                cpu_affinity::affinity_mode_name(cfg.affinity_mode)
            );
        }
    }
    btimer.mark("entering guest");

    // Arm the snapshot trigger so the guest's CPUID(0x4000DE57) is caught by the
    // run loop and surfaces as StopReason::SnapshotRequested instead of running
    // forever. Only when --save was requested.
    if cfg.save_path.is_some() {
        crate::whp::snapshot::arm();
        println!("[snapshot] armed: waiting for the guest snapshot trigger (CPUID 0x4000DE57)");
    }

    // BSP runs on the main thread; APs each get their own thread. Every vCPU
    // thread pins itself to the resolved CPU set before its run loop.
    //
    // Capture every vCPU's counters BEFORE consuming `loops`, so the shutdown
    // summary can aggregate across ALL vCPUs (not just the BSP) and TINYVMM_DIAG
    // can print a per-vCPU breakdown. Index 0 is the BSP.
    let vcpu_counters: Vec<Arc<crate::whp::run_loop::Counters>> =
        loops.iter().map(|l| l.counters()).collect();

    let bsp = loops.remove(0);
    let mut ap_handles = Vec::new();
    for (i, l) in loops.into_iter().enumerate() {
        let ids = cpu_set_ids.clone();
        let h = std::thread::Builder::new()
            .name(format!("vcpu-{}", i + 1))
            .spawn(move || {
                cpu_affinity::pin_current_thread(&ids);
                l.run()
            })
            .map_err(|e| Error::msg(format!("spawn AP thread: {e}")))?;
        ap_handles.push(h);
    }

    cpu_affinity::pin_current_thread(&cpu_set_ids);
    let reason = bsp.run();
    btimer.mark("guest exited");

    // Tear down: stop APs, signal watchdog, join. Capture each AP's stop reason
    // and surface any abnormal one — otherwise an AP that died on an exception /
    // unhandled exit is invisible (only the BSP's reason is the process result).
    stop_all();
    watchdog_done.store(true, Ordering::Release);
    let mut ap_reasons: Vec<StopReason> = Vec::with_capacity(ap_handles.len());
    for h in ap_handles {
        match h.join() {
            Ok(r) => ap_reasons.push(r),
            Err(_) => eprintln!("[pvh-run] WARN: an AP vCPU thread panicked"),
        }
    }
    for (i, r) in ap_reasons.iter().enumerate() {
        if !matches!(
            r,
            StopReason::GuestHalted | StopReason::Cancelled | StopReason::SnapshotRequested
        ) {
            eprintln!("[pvh-run] vCPU {} (AP) stopped abnormally: {:?}", i + 1, r);
        }
    }
    if let Some(w) = watchdog {
        let _ = w.join();
    }
    console_restore.restore();

    // Close the virtio-gpu window and join its message-pump thread.
    if let Some(d) = &display {
        d.shutdown();
    }
    if let Some(g) = &gpu_keepalive {
        println!(
            "[pvh-run] virtio-gpu stats: ctrl_cmds={} frames_presented={}",
            g.ctrl_cmds(),
            g.frames()
        );
    }

    // Quiesce every virtio-blk IOCP worker before its BlockDevice owner is
    // dropped, so no completion lands on freed memory. Then print the per-disk
    // shutdown summary (max_inflight > 1 proves the concurrent-writer phase
    // reached real queue depth from the backend's view).
    for b in &blk_backends {
        b.stop();
    }

    // Snapshot save: if armed and the guest issued the trigger, capture the now
    // quiesced machine (APs stopped + joined, blk IOCP workers drained) and
    // write the file, then exit. If the guest stopped for any other reason, the
    // snapshot is not written.
    if let Some(ref save_path) = cfg.save_path {
        if matches!(reason, StopReason::SnapshotRequested) {
            // Quiesce every net data plane and 9p worker pool before capturing,
            // so no inbound frame or 9p reply mutates an RX/used ring or guest
            // RAM after the device + RAM sections are taken.
            for nd in &net_devices {
                nd.quiesce_backend();
            }
            for p9 in &p9_devices {
                p9.quiesce();
            }
            write_snapshot(
                save_path, &cfg, part_handle, &vcpus, &ram, &hv, &pic, &pit, &com1, &legacy,
                &pci_bus, &transports, &blk_backends, &net_devices,
            )?;
            return Ok(0);
        }
        eprintln!(
            "[snapshot] guest exited (reason={reason:?}) WITHOUT issuing the snapshot trigger; \
             no snapshot written"
        );
        return Ok(1);
    }

    for (i, (b, d)) in blk_backends.iter().zip(blk_devices.iter()).enumerate() {
        println!(
            "[pvh-run] virtio-blk[{}] stats: submitted={} completed={} errors={} \
             max_inflight={} (virtio in={} out={} flush={} discard={} wz={} err={})",
            i,
            b.submitted(),
            b.completed(),
            b.errors(),
            b.max_inflight(),
            d.ops_in(),
            d.ops_out(),
            d.ops_flush(),
            d.ops_discard(),
            d.ops_write_zeroes(),
            d.ops_err()
        );
    }

    btimer.mark("teardown done");

    // Aggregate exit counters across ALL vCPUs (the previous summary only
    // reported the BSP's, undercounting on SMP guests).
    let io: u64 = vcpu_counters.iter().map(|c| c.io.load(Ordering::Relaxed)).sum();
    let mmio: u64 = vcpu_counters.iter().map(|c| c.mmio.load(Ordering::Relaxed)).sum();
    let cpuid: u64 = vcpu_counters.iter().map(|c| c.cpuid.load(Ordering::Relaxed)).sum();
    let msr: u64 = vcpu_counters.iter().map(|c| c.msr.load(Ordering::Relaxed)).sum();
    let halt: u64 = vcpu_counters.iter().map(|c| c.halt.load(Ordering::Relaxed)).sum();
    let other: u64 = vcpu_counters.iter().map(|c| c.other.load(Ordering::Relaxed)).sum();

    diag::etw::Event::new("VmStop", diag::etw::INFO, diag::etw::kw::LIFECYCLE)
        .str("reason", &format!("{reason:?}"))
        .u64("io", io)
        .u64("cpuid", cpuid)
        .u64("msr", msr)
        .u64("uart_tx", com1.tx_bytes())
        .f64("total_ms", btimer.elapsed_ms())
        .write();

    println!(
        "[pvh-run] stopped: reason={reason:?} uart_tx={} \
         exits[io={io} mmio={mmio} cpuid={cpuid} msr={msr} halt={halt} other={other}]",
        com1.tx_bytes(),
    );

    // TINYVMM_DIAG: per-vCPU exit breakdown + a guest-RAM dump for post-mortem.
    if diag_enabled() {
        for (i, cc) in vcpu_counters.iter().enumerate() {
            eprintln!(
                "[pvh-run] vCPU {i} exits: io={} mmio={} cpuid={} msr={} halt={} other={}",
                cc.io.load(Ordering::Relaxed),
                cc.mmio.load(Ordering::Relaxed),
                cc.cpuid.load(Ordering::Relaxed),
                cc.msr.load(Ordering::Relaxed),
                cc.halt.load(Ordering::Relaxed),
                cc.other.load(Ordering::Relaxed),
            );
        }
        dump_guest_ram(&ram, "tinyvmm-guest-ram.bin");
    }

    Ok(match reason {
        StopReason::GuestHalted | StopReason::Cancelled => 0,
        _ => 1,
    })
}

/// Serialize a port-forward rule as "hA.hB.hC.hD:hport:gA.gB.gC.gD:gport" for
/// the snapshot header, so restore can rebuild the NAT backend's forwards.
fn encode_portfwd(pf: &PortForward) -> String {
    format!(
        "{}.{}.{}.{}:{}:{}.{}.{}.{}:{}",
        pf.host_addr[0], pf.host_addr[1], pf.host_addr[2], pf.host_addr[3], pf.host_port,
        pf.guest_ip[0], pf.guest_ip[1], pf.guest_ip[2], pf.guest_ip[3], pf.guest_port
    )
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let o: Vec<&str> = s.split('.').collect();
    if o.len() != 4 {
        return None;
    }
    let mut a = [0u8; 4];
    for i in 0..4 {
        a[i] = o[i].parse().ok()?;
    }
    Some(a)
}

fn decode_portfwd(s: &str) -> Option<PortForward> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 4 {
        return None;
    }
    Some(PortForward {
        host_addr: parse_ipv4(parts[0])?,
        host_port: parts[1].parse().ok()?,
        guest_ip: parse_ipv4(parts[2])?,
        guest_port: parts[3].parse().ok()?,
    })
}

/// Deterministic per-NIC MAC: locally-administered qemu-ish OUI, last byte = NIC
/// index, so save and restore derive the same address for each NIC position.
fn nic_mac(index: usize) -> [u8; 6] {
    [0x52, 0x54, 0x00, 0x12, 0x34, 0x56u8.wrapping_add(index as u8)]
}

fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Create + wire the host backend for one NIC; returns a short label. Shared by
/// run_pvh_run (at device creation) and run_restore (after the device snapshot
/// is applied), so a restored NIC keeps its configured backend kind. Fallible:
/// the WinTun backend can fail to bring up its adapter (e.g. not elevated).
fn wire_net_backend(net: &Arc<NetDevice>, nic: &NicSpec) -> Result<String> {
    let label = match nic.backend {
        NetBackendKind::Loopback => {
            net.set_backend(LoopbackBackend::new(net));
            "loopback".to_string()
        }
        NetBackendKind::Nat => {
            let opts = NatOptions {
                port_forwards: nic.port_forwards.clone(),
                ..NatOptions::default()
            };
            net.set_backend(NatBackend::new(net, opts));
            "nat gw=10.0.0.1".to_string()
        }
        NetBackendKind::Wintun => {
            let host = nic.wintun_host.unwrap_or([10, 0, 0, 1]);
            let name = nic
                .wintun_name
                .clone()
                .unwrap_or_else(|| "tinyvmm".to_string());
            let opts = crate::net::wintun::WintunOptions {
                adapter_name: name.clone(),
                host_ipv4: host,
                ..crate::net::wintun::WintunOptions::default()
            };
            let backend = crate::net::wintun::WintunBackend::new(net, &opts)
                .map_err(|e| Error::msg(format!("wintun NIC '{name}': {e}")))?;
            net.set_backend(backend);
            format!(
                "wintun adapter='{name}' host={}.{}.{}.{}",
                host[0], host[1], host[2], host[3]
            )
        }
    };
    if diag::etw::enabled(diag::etw::INFO, diag::etw::kw::LIFECYCLE) {
        let m = net.mac();
        let mac = m.iter().fold(0u64, |a, &b| (a << 8) | b as u64);
        diag::etw::Event::new("NetBackendStart", diag::etw::INFO, diag::etw::kw::LIFECYCLE)
            .str("backend", &label)
            .hex64("mac", mac)
            .write();
    }
    Ok(label)
}

/// Reconstruct one NIC's spec + MAC from the snapshot header under `prefix`
/// (e.g. "nic0" or the legacy "net"). Defaults: Nat backend, index-derived MAC.
fn parse_restore_nic(
    jr: &crate::whp::snapshot_file::JsonReader,
    prefix: &str,
    index: usize,
) -> (NicSpec, [u8; 6]) {
    let backend = jr
        .get_str(&format!("{prefix}_backend"))
        .ok()
        .and_then(|s| NetBackendKind::from_str(&s))
        .unwrap_or(NetBackendKind::Nat);
    let mut port_forwards = Vec::new();
    let pf_count = jr.get_u64(&format!("{prefix}_portfwd_count")).unwrap_or(0) as usize;
    for j in 0..pf_count {
        if let Ok(s) = jr.get_str(&format!("{prefix}_portfwd{j}")) {
            if let Some(pf) = decode_portfwd(&s) {
                port_forwards.push(pf);
            }
        }
    }
    let mac = match jr.get_u64(&format!("{prefix}_mac")) {
        Ok(m) => [
            (m >> 40) as u8,
            (m >> 32) as u8,
            (m >> 24) as u8,
            (m >> 16) as u8,
            (m >> 8) as u8,
            m as u8,
        ],
        Err(_) => nic_mac(index),
    };
    let wintun_name = jr.get_str(&format!("{prefix}_wintun_name")).ok();
    let wintun_host = jr
        .get_str(&format!("{prefix}_wintun_host"))
        .ok()
        .and_then(|s| parse_ipv4(&s));
    (
        NicSpec {
            backend,
            port_forwards,
            wintun_name,
            wintun_host,
        },
        mac,
    )
}

/// Capture the quiesced machine to a snapshot file. The vCPUs must be stopped
/// and the device IOCP workers drained before calling. Section order mirrors the
/// C++: per-vCPU -> HV -> legacy -> per-PCI-device -> RAM (last, largest).
#[allow(clippy::too_many_arguments)]
fn write_snapshot(
    path: &str,
    cfg: &PvhArgs,
    _part_handle: windows_sys::Win32::System::Hypervisor::WHV_PARTITION_HANDLE,
    vcpus: &[Arc<Vcpu>],
    ram: &Arc<GuestMemory>,
    hv: &Arc<HvEnlightenment>,
    pic: &Arc<Pic8259>,
    pit: &Arc<Pit8254>,
    com1: &Arc<Serial8250>,
    legacy: &Arc<LegacyIsaStubs>,
    pci_bus: &Arc<PciBus>,
    transports: &[Arc<PciTransport>],
    blk_backends: &[Arc<BlockFile>],
    net_devices: &[Arc<crate::virtio::net::NetDevice>],
) -> Result<()> {
    use crate::whp::snapshot_file::{JsonWriter, SectionType, SnapshotWriter};
    use crate::whp::vcpu_state as vs;

    // Capture per-vCPU state first (the vCPUs are stopped, so registers are
    // stable).
    let mut caps = Vec::with_capacity(vcpus.len());
    for vp in vcpus {
        caps.push(vs::capture(vp)?);
    }

    // Header JSON: enough to reconstruct the device tree + RAM on restore.
    let mut jw = JsonWriter::new();
    jw.str("phase", "rust-1")
        .u64("vcpu_count", vcpus.len() as u64)
        .u64("ram_size_bytes", ram.size() as u64)
        .bool("large_pages", ram.large_pages())
        .u64("tsc_hz_at_save", cached_tsc_hz())
        .bool("hide_tsc_deadline", true)
        .bool("with_rng", cfg.with_rng)
        .bool("with_gpu", cfg.with_gpu)
        .u64("gpu_width", cfg.gpu_width as u64)
        .u64("gpu_height", cfg.gpu_height as u64)
        .bool("with_input", cfg.with_input)
        .u64("nic_count", cfg.nics.len() as u64)
        .u64("drive_count", cfg.drives.len() as u64)
        .u64("p9_count", cfg.p9_shares.len() as u64);
    // Per-NIC config so restore rebuilds each NIC + its (fresh) backend, even
    // when NICs use different backends. MAC comes from the live device so it
    // matches what the guest cached.
    for (i, nic) in cfg.nics.iter().enumerate() {
        let mac = net_devices
            .get(i)
            .map(|n| n.mac())
            .unwrap_or_else(|| nic_mac(i));
        let mac_u64 = mac.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
        jw.u64(&format!("nic{i}_mac"), mac_u64)
            .str(&format!("nic{i}_backend"), nic.backend.as_str())
            .u64(&format!("nic{i}_portfwd_count"), nic.port_forwards.len() as u64);
        for (j, pf) in nic.port_forwards.iter().enumerate() {
            jw.str(&format!("nic{i}_portfwd{j}"), &encode_portfwd(pf));
        }
        if nic.backend == NetBackendKind::Wintun {
            let name = nic.wintun_name.clone().unwrap_or_else(|| "tinyvmm".to_string());
            let host = nic.wintun_host.unwrap_or([10, 0, 0, 1]);
            jw.str(&format!("nic{i}_wintun_name"), &name).str(
                &format!("nic{i}_wintun_host"),
                &format!("{}.{}.{}.{}", host[0], host[1], host[2], host[3]),
            );
        }
    }
    for (i, d) in cfg.drives.iter().enumerate() {
        jw.str(&format!("drive{i}_path"), &d.path)
            .u64(&format!("drive{i}_size"), blk_backends[i].size())
            .bool(&format!("drive{i}_readonly"), d.readonly);
    }
    // Per-9p-share config so restore rebuilds each virtio-9p device with the same
    // tag/root/RO. The device's own fid table is captured in its PciDevice section.
    for (i, s) in cfg.p9_shares.iter().enumerate() {
        jw.str(&format!("p9{i}_tag"), &s.tag)
            .str(&format!("p9{i}_root"), &s.host_root.to_string_lossy())
            .bool(&format!("p9{i}_readonly"), s.readonly);
    }

    let mut w = SnapshotWriter::create(path)?;
    w.write_header(&jw.finish())?;

    // Per-vCPU sections.
    for (i, c) in caps.iter().enumerate() {
        let i = i as u32;
        w.write_section(SectionType::VcpuRegs, &vs::encode_regs(i, vs::ARCH_REGS, &c.arch))?;
        w.write_section(SectionType::VcpuXsave, &vs::encode_blob(i, &c.xsave))?;
        w.write_section(SectionType::VcpuApic, &vs::encode_blob(i, &c.apic))?;
        w.write_section(
            SectionType::VcpuIntrCtl,
            &vs::encode_okregs(i, vs::INTR_CTL_REGS, &c.intr_ctl, &c.intr_ctl_ok),
        )?;
        w.write_section(
            SectionType::VcpuSupMsr,
            &vs::encode_okregs(i, vs::SUP_MSR_REGS, &c.sup_msr, &c.sup_msr_ok),
        )?;
        w.write_section(SectionType::VcpuTiming, &vs::encode_regs(i, vs::TIMING_REGS, &c.timing))?;
    }

    // HV enlightenment MSRs.
    w.write_section(SectionType::HvEnlightenment, &hv.snapshot_capture())?;

    // Legacy singletons.
    w.write_section(SectionType::LegacyPic8259, &pic.snapshot_capture())?;
    w.write_section(SectionType::LegacyPit8254, &pit.snapshot_capture())?;
    w.write_section(SectionType::LegacySerial8250, &com1.snapshot_capture())?;
    w.write_section(SectionType::LegacyIsaStubs, &legacy.snapshot_capture())?;
    w.write_section(SectionType::LegacyPciBus, &pci_bus.snapshot_capture())?;

    // Per-PCI-device sections: [u16 device_index][DeviceSnapshot]. One blob per
    // virtio function carries config + MSI-X + common-cfg + queues + state.
    for (idx, t) in transports.iter().enumerate() {
        let snap = t.snapshot_capture();
        let mut payload = (idx as u16).to_le_bytes().to_vec();
        payload.extend_from_slice(&snap.encode());
        w.write_section(SectionType::PciDevice, &payload)?;
    }

    // RAM last (largest section; a writer crash then leaves the metadata intact,
    // and the CRC trailer catches truncation).
    let ram_slice = unsafe { std::slice::from_raw_parts(ram.host_base(), ram.size()) };
    w.write_section(SectionType::RamRaw, ram_slice)?;

    let n = w.finalize()?;
    println!("[snapshot] wrote {n} bytes to {path}");
    Ok(())
}

/// Restore a machine from a snapshot file and resume it. The device tree + RAM
/// size come entirely from the snapshot header; `--restore` also accepts optional
/// `--drive` (positional path/RO overrides), `--cpu-affinity`, `--watchdog-secs`,
/// and `--unsafe-restore-mutable-drive`.
/// Parse a restore-time `--drive` override: `<path>[,readonly|ro|rw]`. Returns
/// the path and an OPTIONAL readonly flag — `None` means "inherit the saved
/// drive's readonly state". (The boot-time `--drive` parse instead defaults RO
/// to false; here we must distinguish "unspecified" from "rw".)
fn parse_drive_override(spec: &str) -> Result<(String, Option<bool>)> {
    let mut parts = spec.splitn(2, ',');
    let path = parts.next().unwrap_or("").to_string();
    if path.is_empty() {
        return Err(Error::msg("--drive: empty path"));
    }
    let mut ro: Option<bool> = None;
    if let Some(opts) = parts.next() {
        for kv in opts.split(',') {
            match kv {
                "readonly" | "ro" => ro = Some(true),
                "rw" | "readwrite" => ro = Some(false),
                other => {
                    return Err(Error::msg(format!(
                        "--drive: unknown option '{other}' (want readonly|ro|rw)"
                    )))
                }
            }
        }
    }
    Ok((path, ro))
}

fn run_restore(args: &[String]) -> Result<i32> {
    let path = args
        .get(2)
        .ok_or_else(|| Error::msg("--restore wants a snapshot path"))?
        .clone();

    // Restore-time overrides (parity with the C++ --restore flags). Drives are
    // overridden positionally (the i-th --drive overrides saved drive i).
    let mut drive_overrides: Vec<(String, Option<bool>)> = Vec::new();
    let mut affinity_mode = AffinityMode::All;
    let mut watchdog_secs = 0u32;
    let mut unsafe_restore_mutable_drive = false;
    {
        let mut i = 3;
        while i < args.len() {
            match args[i].as_str() {
                "--drive" => {
                    i += 1;
                    let spec = args
                        .get(i)
                        .ok_or_else(|| Error::msg("--restore --drive wants <path>[,readonly|ro]"))?;
                    drive_overrides.push(parse_drive_override(spec)?);
                }
                "--cpu-affinity" => {
                    i += 1;
                    let m = args
                        .get(i)
                        .ok_or_else(|| Error::msg("--cpu-affinity wants all|p|e|p-physical"))?;
                    affinity_mode = cpu_affinity::parse_affinity_mode(m).ok_or_else(|| {
                        Error::msg(format!(
                            "--cpu-affinity: unknown mode '{m}' (want all|p|e|p-physical)"
                        ))
                    })?;
                }
                "--watchdog-secs" => {
                    i += 1;
                    watchdog_secs = args
                        .get(i)
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| Error::msg("--watchdog-secs wants an integer"))?;
                }
                "--unsafe-restore-mutable-drive" => unsafe_restore_mutable_drive = true,
                other => {
                    return Err(Error::msg(format!(
                        "--restore: unknown flag '{other}' (want --drive, --cpu-affinity, \
                         --watchdog-secs, --unsafe-restore-mutable-drive)"
                    )));
                }
            }
            i += 1;
        }
    }

    use crate::whp::snapshot_file::{JsonReader, SectionType, SnapshotReader};
    use crate::whp::vcpu_state as vs;

    check_whp_available()?;
    println!("[restore] WHP available");

    let mut reader = SnapshotReader::open(&path)?;
    reader.verify_trailer()?;
    let header = reader.read_header()?;
    let jr = JsonReader::parse(&header)?;

    let vcpu_count = jr.get_u64("vcpu_count")? as u32;
    let ram_size = jr.get_u64("ram_size_bytes")? as usize;
    let large_pages = jr.get_bool("large_pages").unwrap_or(true);
    let tsc_hz_at_save = jr.get_u64("tsc_hz_at_save").unwrap_or(0);
    let with_rng = jr.get_bool("with_rng").unwrap_or(false);
    let with_gpu = jr.get_bool("with_gpu").unwrap_or(false);
    let gpu_width = jr.get_u64("gpu_width").unwrap_or(1280) as u32;
    let gpu_height = jr.get_u64("gpu_height").unwrap_or(800) as u32;
    let with_input = jr.get_bool("with_input").unwrap_or(false);
    let drive_count = jr.get_u64("drive_count").unwrap_or(0) as usize;
    let p9_count = jr.get_u64("p9_count").unwrap_or(0) as usize;
    // Reconstruct the per-NIC specs (backend + port-forwards) and MACs from the
    // header. Back-compat: an older single-NIC snapshot used with_net + net_*.
    let mut restore_nics: Vec<(NicSpec, [u8; 6])> = Vec::new();
    let nic_count = jr.get_u64("nic_count").ok();
    match nic_count {
        Some(n) => {
            for i in 0..n as usize {
                restore_nics.push(parse_restore_nic(&jr, &format!("nic{i}"), i));
            }
        }
        None => {
            if jr.get_bool("with_net").unwrap_or(false) {
                restore_nics.push(parse_restore_nic(&jr, "net", 0));
            }
        }
    }
    println!(
        "[restore] header: vcpus={vcpu_count} ram={} MiB large_pages={large_pages} rng={with_rng} \
         gpu={with_gpu} nics={} drives={drive_count}",
        ram_size / (1024 * 1024),
        restore_nics.len()
    );

    if host::enable_lock_memory_privilege() {
        println!("[host] SeLockMemoryPrivilege: enabled");
    }

    // --- Partition (same setup as a fresh boot, minus the kernel load) ---
    let mut part = Partition::new(vcpu_count)?;
    part.enable_extended_exits(true, true, false)?;
    set_hide_tsc_deadline(true);
    let static_cpuid = build_static_cpuid_result_list(true);
    part.set_cpuid_result_list(&static_cpuid)?;
    part.set_local_apic_emulation(WHvX64LocalApicEmulationModeX2Apic)?;
    part.setup()?;
    let part_handle = part.handle();

    let ram = Arc::new(GuestMemory::new(part_handle, 0, ram_size, true, large_pages)?);
    let hv = Arc::new(HvEnlightenment::new(ram.clone(), cached_tsc_hz()));

    let mut vcpus: Vec<Arc<Vcpu>> = Vec::with_capacity(vcpu_count as usize);
    for i in 0..vcpu_count {
        vcpus.push(Arc::new(Vcpu::new(part_handle, i)?));
    }

    // --- Device model: mirror run_pvh_run's creation ORDER exactly so the
    // per-device snapshot indices line up: console(0), nets, [rng], [blk...],
    // [9p...]. ---
    let mut io_bus = IoBus::new();
    let mmio_bus = Arc::new(MmioBus::new());

    let com1 = Serial8250::new(0x3F8);
    com1.attach(&mut io_bus);
    let pit = Pit8254::new();
    pit.attach(&mut io_bus);
    let legacy = LegacyIsaStubs::new();
    legacy.attach(&mut io_bus);
    let pic = Pic8259::new(Box::new(move |vector: u8, dest: u32| -> bool {
        let ctrl = WHV_INTERRUPT_CONTROL {
            _bitfield: 0,
            Destination: dest,
            Vector: vector as u32,
        };
        let hr = unsafe {
            WHvRequestInterrupt(
                part_handle,
                &ctrl,
                std::mem::size_of::<WHV_INTERRUPT_CONTROL>() as u32,
            )
        };
        hr >= 0
    }));
    pic.attach(&mut io_bus);
    {
        let pic = pic.clone();
        com1.set_irq_callback(Box::new(move |irq| pic.raise(irq)));
    }

    let console = ConsoleDevice::new(ram.clone());
    let console_dev: Arc<dyn VirtioDevice> = console.clone();
    let copts = transport::Options {
        vendor_id: 0x1AF4,
        sub_vendor_id: 0x1AF4,
        sub_id: virtio::device::DEVICE_ID_CONSOLE as u16,
        num_msix_vectors: 3,
        pci_class: 0x07,
        pci_subclass: 0x80,
        doorbells: true,
    };
    let vcon = PciTransport::new("virtio-pci-console", console_dev, copts, mmio_bus.clone(), part_handle);
    {
        let wt = Arc::downgrade(&vcon);
        console.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
    }
    let pci_bus = PciBus::new();
    let cfunc: Arc<dyn PciFunction> = vcon.clone();
    pci_bus.add_device(cfunc);
    let mut transports: Vec<Arc<PciTransport>> = vec![vcon.clone()];

    // virtio-net NICs (if present in the snapshot): rebuild each device model
    // now so PciDevice indices line up with the save run (console=0, net0=1,
    // ...). The FRESH host backend is wired in later, AFTER the device snapshot
    // is applied (queues programmed + driver_ok), so live pre-snapshot flows
    // reset but the device model + new flows work.
    let mut net_devices: Vec<Arc<NetDevice>> = Vec::with_capacity(restore_nics.len());
    for (ni, (_nic, mac)) in restore_nics.iter().enumerate() {
        let net = NetDevice::new(ram.clone(), *mac);
        net_devices.push(net.clone());
        let net_dev: Arc<dyn VirtioDevice> = net.clone();
        let nopts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_NET as u16,
            num_msix_vectors: 3,
            pci_class: 0x02,
            pci_subclass: 0x00,
            doorbells: true,
        };
        let nt = PciTransport::new(
            &format!("virtio-pci-net[{ni}]"),
            net_dev,
            nopts,
            mmio_bus.clone(),
            part_handle,
        );
        let wt = Arc::downgrade(&nt);
        net.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        pci_bus.add_device(nt.clone() as Arc<dyn PciFunction>);
        transports.push(nt.clone());
    }

    if with_rng {
        let rng = RngDevice::new(ram.clone());
        let rng_dev: Arc<dyn VirtioDevice> = rng.clone();
        let ropts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_RNG as u16,
            num_msix_vectors: 2,
            pci_class: 0x10,
            pci_subclass: 0x80,
            doorbells: false,
        };
        let rt = PciTransport::new("virtio-pci-rng", rng_dev, ropts, mmio_bus.clone(), part_handle);
        let wt = Arc::downgrade(&rt);
        rng.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        pci_bus.add_device(rt.clone() as Arc<dyn PciFunction>);
        transports.push(rt.clone());
    }

    let mut blk_backends: Vec<Arc<BlockFile>> = Vec::with_capacity(drive_count);
    for i in 0..drive_count {
        let saved_path = jr.get_str(&format!("drive{i}_path"))?;
        let saved_ro = jr.get_bool(&format!("drive{i}_readonly")).unwrap_or(true);
        let saved_size = jr.get_u64(&format!("drive{i}_size")).unwrap_or(0);
        // Apply a positional --drive override (relocate the disk / change RO).
        let (dpath, dro) = match drive_overrides.get(i) {
            Some((p, ro)) => (p.clone(), ro.unwrap_or(saved_ro)),
            None => (saved_path.clone(), saved_ro),
        };
        // The virtio-blk RO feature bit the guest negotiated is part of the
        // restored device model; flipping it on restore desyncs the guest.
        if dro != saved_ro && !unsafe_restore_mutable_drive {
            return Err(Error::msg(format!(
                "--restore: drive {i} readonly mismatch (saved={saved_ro}, requested={dro}); \
                 pass --unsafe-restore-mutable-drive to force"
            )));
        }
        let backend = Arc::new(BlockFile::new(&dpath, dro));
        if !backend.open() {
            return Err(Error::msg(format!(
                "--restore: failed to reopen drive '{}' (readonly={}): err={}",
                dpath, dro as u32, backend.open_err()
            )));
        }
        // The disk is NOT captured in the snapshot, so a size change means the
        // on-disk state no longer matches the restored RAM. Reject unless forced.
        let actual = backend.size();
        if saved_size != 0 && actual != saved_size {
            if unsafe_restore_mutable_drive {
                eprintln!(
                    "[restore] WARN: drive {i} '{dpath}' size {actual} != saved {saved_size} \
                     bytes (forced by --unsafe-restore-mutable-drive)"
                );
            } else {
                return Err(Error::msg(format!(
                    "--restore: drive {i} '{dpath}' size {actual} != saved {saved_size} bytes \
                     (a resized/changed disk diverges from restored RAM); pass \
                     --unsafe-restore-mutable-drive to force"
                )));
            }
        }
        let blk = BlockDevice::new(ram.clone(), backend.clone(), 256);
        let blk_dev: Arc<dyn VirtioDevice> = blk.clone();
        let bopts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_BLOCK as u16,
            num_msix_vectors: 2,
            pci_class: 0x01,
            pci_subclass: 0x00,
            doorbells: true,
        };
        let bt = PciTransport::new(
            &format!("virtio-pci-blk[{i}]"),
            blk_dev,
            bopts,
            mmio_bus.clone(),
            part_handle,
        );
        let wt = Arc::downgrade(&bt);
        blk.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        backend.start();
        pci_bus.add_device(bt.clone() as Arc<dyn PciFunction>);
        transports.push(bt.clone());
        blk_backends.push(backend);
    }

    // virtio-input (if present in the snapshot): recreate in the same order as
    // run_pvh_run (after blk, before 9p) so PciDevice indices align. The host
    // input source is wired further below (the GPU window if --gpu, else console).
    let input_devices = if with_input {
        Some(add_input_devices(&ram, &mmio_bus, part_handle, &pci_bus, &mut transports))
    } else {
        None
    };

    // virtio-9p devices (reconstructed from the header; each device's fid table
    // is restored from its PciDevice section's device-state, which reopens the
    // host handles). Same creation ORDER as run_pvh_run so PCI/device indices
    // line up: console, nets, rng, blk, input, 9p.
    for i in 0..p9_count {
        let tag = jr.get_str(&format!("p9{i}_tag"))?;
        let root = jr.get_str(&format!("p9{i}_root"))?;
        let ro = jr.get_bool(&format!("p9{i}_readonly")).unwrap_or(false);
        let p9 = P9Device::new(ram.clone(), tag.clone(), std::path::PathBuf::from(&root), ro);
        let p9_dev: Arc<dyn VirtioDevice> = p9.clone();
        let popts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_P9 as u16,
            num_msix_vectors: 2,
            pci_class: 0xFF,
            pci_subclass: 0x00,
            doorbells: true,
        };
        let pt = PciTransport::new(
            &format!("virtio-pci-9p[{i}]"),
            p9_dev,
            popts,
            mmio_bus.clone(),
            part_handle,
        );
        let wt = Arc::downgrade(&pt);
        p9.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        pci_bus.add_device(pt.clone() as Arc<dyn PciFunction>);
        transports.push(pt.clone());
        println!(
            "[restore] virtio-9p[{i}] tag={tag} host={root}{}",
            if ro { " (ro)" } else { "" }
        );
    }

    // virtio-gpu (if present in the snapshot): rebuilt LAST so its PciDevice
    // index matches the save run. The Display + present callback are wired now,
    // BEFORE the device snapshot is applied, so apply_device_state can re-present
    // the restored scanout image into the freshly-created window.
    let mut display: Option<Arc<Display>> = None;
    let mut gpu_keepalive: Option<Arc<GpuDevice>> = None;
    if with_gpu {
        let gpu = GpuDevice::new(ram.clone(), gpu_width, gpu_height);
        let gpu_dev: Arc<dyn VirtioDevice> = gpu.clone();
        match Display::new(
            &format!("tinyvmm - virtio-gpu {gpu_width}x{gpu_height}"),
            gpu_width,
            gpu_height,
        ) {
            Some(d) => {
                let dd = d.clone();
                gpu.set_present_callback(Box::new(move |bgra, w, h| dd.present(bgra, w, h)));
                display = Some(d);
            }
            None => {
                eprintln!("[restore] WARN: virtio-gpu window creation failed; running headless");
            }
        }
        let gopts = transport::Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: virtio::device::DEVICE_ID_GPU as u16,
            num_msix_vectors: 3,
            pci_class: 0x03,
            pci_subclass: 0x80,
            doorbells: false,
        };
        let gt = PciTransport::new("virtio-pci-gpu", gpu_dev, gopts, mmio_bus.clone(), part_handle);
        let wt = Arc::downgrade(&gt);
        gpu.set_irq_callback(Box::new(move |q| {
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));
        pci_bus.add_device(gt.clone() as Arc<dyn PciFunction>);
        transports.push(gt.clone());
        gpu_keepalive = Some(gpu.clone());
    }

    pci_bus.attach_io_bus(&mut io_bus);
    let io_bus = Arc::new(io_bus);

    // --- Read all sections. RAM is copied straight into guest memory as it is
    // encountered (it is last + largest); the smaller sections are stashed and
    // applied afterwards in dependency order. ---
    let mut sec_hv: Option<Vec<u8>> = None;
    let mut sec_pic: Option<Vec<u8>> = None;
    let mut sec_pit: Option<Vec<u8>> = None;
    let mut sec_serial: Option<Vec<u8>> = None;
    let mut sec_isa: Option<Vec<u8>> = None;
    let mut sec_bus: Option<Vec<u8>> = None;
    let mut sec_devices: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut caps: Vec<vs::CapturedVcpuState> =
        (0..vcpu_count).map(|_| vs::CapturedVcpuState::default()).collect();
    // Section-cardinality counters: a well-formed snapshot has exactly one RAM
    // section and one VcpuRegs section per vCPU. A wrong count means a truncated
    // or foreign file, which we reject below rather than resuming half a machine.
    let mut n_ram = 0u32;
    let mut n_vcpu_regs = 0u32;

    while let Some(s) = reader.next_section()? {
        match s.ty {
            SectionType::RamRaw => {
                n_ram += 1;
                ram.write_at(0, s.payload)?;
            }
            SectionType::HvEnlightenment => sec_hv = Some(s.payload.to_vec()),
            SectionType::LegacyPic8259 => sec_pic = Some(s.payload.to_vec()),
            SectionType::LegacyPit8254 => sec_pit = Some(s.payload.to_vec()),
            SectionType::LegacySerial8250 => sec_serial = Some(s.payload.to_vec()),
            SectionType::LegacyIsaStubs => sec_isa = Some(s.payload.to_vec()),
            SectionType::LegacyPciBus => sec_bus = Some(s.payload.to_vec()),
            SectionType::PciDevice => {
                if s.payload.len() < 2 {
                    return Err(Error::msg("snapshot: short PciDevice section"));
                }
                let idx = u16::from_le_bytes([s.payload[0], s.payload[1]]);
                sec_devices.push((idx, s.payload[2..].to_vec()));
            }
            SectionType::VcpuRegs => {
                n_vcpu_regs += 1;
                let (i, v) = vs::decode_regs(s.payload, vs::ARCH_REGS)?;
                if (i as usize) < caps.len() {
                    caps[i as usize].arch = v;
                }
            }
            SectionType::VcpuTiming => {
                let (i, v) = vs::decode_regs(s.payload, vs::TIMING_REGS)?;
                if (i as usize) < caps.len() {
                    caps[i as usize].timing = v;
                }
            }
            SectionType::VcpuXsave => {
                let (i, b) = vs::decode_blob(s.payload)?;
                if (i as usize) < caps.len() {
                    caps[i as usize].xsave = b;
                }
            }
            SectionType::VcpuApic => {
                let (i, b) = vs::decode_blob(s.payload)?;
                if (i as usize) < caps.len() {
                    caps[i as usize].apic = b;
                }
            }
            SectionType::VcpuIntrCtl => {
                let (i, v, ok) = vs::decode_okregs(s.payload, vs::INTR_CTL_REGS)?;
                if (i as usize) < caps.len() {
                    caps[i as usize].intr_ctl = v;
                    caps[i as usize].intr_ctl_ok = ok;
                }
            }
            SectionType::VcpuSupMsr => {
                let (i, v, ok) = vs::decode_okregs(s.payload, vs::SUP_MSR_REGS)?;
                if (i as usize) < caps.len() {
                    caps[i as usize].sup_msr = v;
                    caps[i as usize].sup_msr_ok = ok;
                }
            }
            _ => {}
        }
    }

    // Validate section cardinality before touching device state: a Rust-written
    // snapshot always carries exactly one RAM section, one VcpuRegs per vCPU, all
    // six HV/legacy singletons, and one PciDevice section per device. A mismatch
    // means a truncated, corrupt, or foreign (e.g. C++-written) file.
    if n_ram != 1 {
        return Err(Error::msg(format!(
            "snapshot: expected exactly 1 RAM section, found {n_ram}"
        )));
    }
    if n_vcpu_regs != vcpu_count {
        return Err(Error::msg(format!(
            "snapshot: expected {vcpu_count} VcpuRegs section(s), found {n_vcpu_regs}"
        )));
    }
    if sec_hv.is_none()
        || sec_pic.is_none()
        || sec_pit.is_none()
        || sec_serial.is_none()
        || sec_isa.is_none()
        || sec_bus.is_none()
    {
        return Err(Error::msg(
            "snapshot: missing one or more HV/legacy singleton sections",
        ));
    }
    if sec_devices.len() != transports.len() {
        return Err(Error::msg(format!(
            "snapshot: expected {} PciDevice section(s), found {}",
            transports.len(),
            sec_devices.len()
        )));
    }

    // Apply legacy singletons.
    if let Some(b) = sec_pic {
        pic.snapshot_apply(&b);
    }
    if let Some(b) = sec_pit {
        pit.snapshot_apply(&b);
    }
    if let Some(b) = sec_serial {
        com1.snapshot_apply(&b);
    }
    if let Some(b) = sec_isa {
        legacy.snapshot_apply(&b);
    }
    if let Some(b) = sec_bus {
        pci_bus.snapshot_apply(&b);
    }

    // Apply per-PCI-device state (config -> common -> MSI-X -> queues -> device).
    for (idx, bytes) in &sec_devices {
        let t = transports.get(*idx as usize).ok_or_else(|| {
            Error::msg(format!("snapshot: PciDevice index {idx} out of range"))
        })?;
        let snap = crate::virtio::transport::DeviceSnapshot::decode(bytes)
            .ok_or_else(|| Error::msg("snapshot: malformed PciDevice payload"))?;
        t.snapshot_apply(&snap);
    }

    // virtio-net: wire in a FRESH per-NIC backend now that each device model
    // (queues + driver_ok) is restored. Pre-snapshot external flows are gone
    // (a NAT socket table starts empty); new flows + the device work normally.
    for (nd, (nic, mac)) in net_devices.iter().zip(restore_nics.iter()) {
        let label = wire_net_backend(nd, nic)?;
        println!(
            "[restore] virtio-net mac {} backend: {} (fresh; prior flows reset)",
            fmt_mac(mac),
            label
        );
    }

    // HV after RAM, so the freshly published hypercall + reference-TSC pages
    // (carrying THIS host's tsc_scale) win over the snapshot's bytes.
    if let Some(b) = sec_hv {
        hv.snapshot_apply(&b);
    }

    // vCPU non-timing state (arch -> sup_msr -> XSAVE -> APIC -> intr_ctl).
    for (i, vp) in vcpus.iter().enumerate() {
        vs::apply_non_timing(vp, &caps[i])?;
    }

    let tsc_now = cached_tsc_hz();
    if tsc_hz_at_save != 0 && tsc_now != 0 {
        let drift = (tsc_now as i64 - tsc_hz_at_save as i64).unsigned_abs();
        // 100 ppm = tsc_hz / 10_000. The reference-TSC page scales by tsc_hz, so
        // a host whose TSC frequency differs from the save host by more than this
        // will skew the guest clock until it re-syncs.
        if drift > tsc_hz_at_save / 10_000 {
            let ppm = drift.saturating_mul(1_000_000) / tsc_hz_at_save;
            eprintln!(
                "[restore] WARN: TSC frequency drift {tsc_hz_at_save} -> {tsc_now} Hz \
                 (~{ppm} ppm > 100 ppm); guest timekeeping may skew until it re-syncs"
            );
        }
    }

    // --- Run loops ---
    let mut loops: Vec<RunLoop> = Vec::with_capacity(vcpu_count as usize);
    for vp in &vcpus {
        let mut rl = RunLoop::new(vp.clone(), io_bus.clone(), mmio_bus.clone(), vcpu_count)?;
        rl.set_hv(hv.clone());
        loops.push(rl);
    }

    let stoppers: Arc<Vec<(Arc<AtomicBool>, Arc<Vcpu>)>> =
        Arc::new(loops.iter().map(|l| (l.stop_flag(), l.vcpu())).collect());
    let stop_all = {
        let stoppers = stoppers.clone();
        move || {
            for (flag, vp) in stoppers.iter() {
                flag.store(true, Ordering::Release);
                let _ = vp.cancel();
            }
        }
    };

    let window_owns_input = display.is_some() && input_devices.is_some();
    if window_owns_input {
        wire_window_input(
            display.as_ref().unwrap(),
            input_devices.as_ref().unwrap(),
            gpu_width,
            gpu_height,
        );
    }
    let console_input = if window_owns_input { None } else { input_devices };
    let console_restore =
        setup_interactive_console(console.clone(), console_input, stop_all.clone());
    {
        const SENTINEL: &[u8] = b"=== tinyvmm shutdown requested ===";
        let stop_all = stop_all.clone();
        let mut acc: Vec<u8> = Vec::new();
        let mut fired = false;
        console.set_byte_observer(Box::new(move |bytes: &[u8]| {
            if fired {
                return;
            }
            acc.extend_from_slice(bytes);
            if acc.windows(SENTINEL.len()).any(|w| w == SENTINEL) {
                fired = true;
                stop_all();
            }
            if acc.len() > SENTINEL.len() {
                let drop = acc.len() - SENTINEL.len();
                acc.drain(0..drop);
            }
        }));
    }

    // Apply timing (TSC/TscAux) back-to-back across all vCPUs immediately before
    // running, to minimize cross-vCPU TSC skew on resume.
    for (i, vp) in vcpus.iter().enumerate() {
        vs::apply_timing(vp, &caps[i])?;
    }

    // Watchdog (optional): stop everything after N seconds, printing per-second
    // exit counters. Mirrors the --pvh-run watchdog. Must be set up while `loops`
    // is still intact (it reads each loop's counters).
    let watchdog_done = Arc::new(AtomicBool::new(false));
    let watchdog = if watchdog_secs > 0 {
        let stop_all = stop_all.clone();
        let done = watchdog_done.clone();
        let secs = watchdog_secs;
        let counters: Vec<_> = loops.iter().map(|l| l.counters()).collect();
        Some(std::thread::spawn(move || {
            for s in 1..=secs {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if done.load(Ordering::Acquire) {
                    return;
                }
                let io: u64 = counters.iter().map(|c| c.io.load(Ordering::Relaxed)).sum();
                let cpuid: u64 = counters.iter().map(|c| c.cpuid.load(Ordering::Relaxed)).sum();
                let msr: u64 = counters.iter().map(|c| c.msr.load(Ordering::Relaxed)).sum();
                eprintln!("[restore] @{s:2}s  io={io} cpuid={cpuid} msr={msr}");
            }
            eprintln!("[restore] watchdog: {secs}s elapsed, requesting stop");
            stop_all();
        }))
    } else {
        None
    };

    // CPU-affinity: resolve the CPU-set IDs once; each vCPU thread pins itself
    // just before entering its run loop. Empty = no pinning.
    let cpu_set_ids = Arc::new(cpu_affinity::resolve_cpu_set_ids(affinity_mode));
    if affinity_mode != AffinityMode::All {
        let top = cpu_affinity::topology();
        println!(
            "[cpu-affinity] mode={} -> {} CPU-set(s) (host: {} logical, {} P-logical, \
             {} P-physical, {} E-logical, hybrid={})",
            cpu_affinity::affinity_mode_name(affinity_mode),
            cpu_set_ids.len(),
            top.total_logical,
            top.p_logical,
            top.p_physical,
            top.e_logical,
            top.hybrid
        );
        if cpu_set_ids.is_empty() {
            eprintln!(
                "[cpu-affinity] WARN: mode '{}' resolved to no CPU sets on this host; \
                 running unpinned",
                cpu_affinity::affinity_mode_name(affinity_mode)
            );
        }
    }

    println!("[restore] resuming {vcpu_count} vCPU(s)");

    let bsp = loops.remove(0);
    let mut ap_handles = Vec::new();
    for (i, l) in loops.into_iter().enumerate() {
        let ids = cpu_set_ids.clone();
        let h = std::thread::Builder::new()
            .name(format!("vcpu-{}", i + 1))
            .spawn(move || {
                cpu_affinity::pin_current_thread(&ids);
                l.run()
            })
            .map_err(|e| Error::msg(format!("spawn AP thread: {e}")))?;
        ap_handles.push(h);
    }
    cpu_affinity::pin_current_thread(&cpu_set_ids);
    let reason = bsp.run();

    stop_all();
    watchdog_done.store(true, Ordering::Release);
    // Surface any AP that stopped abnormally (exception / unhandled exit).
    let mut ap_reasons: Vec<StopReason> = Vec::with_capacity(ap_handles.len());
    for h in ap_handles {
        match h.join() {
            Ok(r) => ap_reasons.push(r),
            Err(_) => eprintln!("[restore] WARN: an AP vCPU thread panicked"),
        }
    }
    for (i, r) in ap_reasons.iter().enumerate() {
        if !matches!(r, StopReason::GuestHalted | StopReason::Cancelled) {
            eprintln!("[restore] vCPU {} (AP) stopped abnormally: {:?}", i + 1, r);
        }
    }
    if let Some(w) = watchdog {
        let _ = w.join();
    }
    console_restore.restore();
    for b in &blk_backends {
        b.stop();
    }
    if let Some(d) = &display {
        d.shutdown();
    }
    if let Some(g) = &gpu_keepalive {
        println!(
            "[restore] virtio-gpu stats: ctrl_cmds={} frames_presented={}",
            g.ctrl_cmds(),
            g.frames()
        );
    }

    println!("[restore] stopped: reason={:?} uart_tx={}", reason, com1.tx_bytes());
    Ok(match reason {
        StopReason::GuestHalted | StopReason::Cancelled => 0,
        _ => 1,
    })
}

struct ConsoleModeRestore {
    valid: bool,
    hin: HANDLE,
    in_mode: u32,
    hout: HANDLE,
    out_mode: u32,
}

impl ConsoleModeRestore {
    fn restore(&self) {
        if self.valid {
            unsafe {
                SetConsoleMode(self.hin, self.in_mode);
                SetConsoleMode(self.hout, self.out_mode);
            }
        }
    }
}

/// The pair of virtio-input devices (keyboard + absolute tablet) created by
/// `--input`. Kept so the host input source (the console reader) can inject
/// events; the devices themselves are also held alive by the transport list.
struct InputDevices {
    keyboard: Arc<InputDevice>,
    tablet: Arc<InputDevice>,
}

/// Build one virtio-input PCI function: wire the device's queue-interrupt back
/// to the transport and register it on the bus. Returns the transport so the
/// caller can record it for snapshotting.
fn attach_input_transport(
    name: &str,
    dev: Arc<InputDevice>,
    pci_subclass: u8,
    mmio_bus: &Arc<MmioBus>,
    part_handle: WHV_PARTITION_HANDLE,
    pci_bus: &Arc<PciBus>,
) -> Arc<PciTransport> {
    let vdev: Arc<dyn VirtioDevice> = dev.clone();
    let opts = transport::Options {
        vendor_id: 0x1AF4,
        sub_vendor_id: 0x1AF4,
        sub_id: virtio::device::DEVICE_ID_INPUT as u16,
        num_msix_vectors: 3, // eventq + statusq + config-change
        pci_class: 0x09,     // input device controller
        pci_subclass,
        // Low rate, host-driven: the guest only kicks to replenish eventq
        // buffers (a no-op for us) or post statusq LED updates. Service inline.
        doorbells: false,
    };
    let t = PciTransport::new(name, vdev, opts, mmio_bus.clone(), part_handle);
    let wt = Arc::downgrade(&t);
    dev.set_irq_callback(Box::new(move |q| {
        if let Some(tt) = wt.upgrade() {
            tt.raise_queue_interrupt(q);
        }
    }));
    pci_bus.add_device(t.clone() as Arc<dyn PciFunction>);
    t
}

/// Create the keyboard + tablet virtio-input devices, register them on the PCI
/// bus, and append their transports (in keyboard-then-tablet order, which both
/// the run and restore paths must match for snapshot device indices to line up).
fn add_input_devices(
    ram: &Arc<GuestMemory>,
    mmio_bus: &Arc<MmioBus>,
    part_handle: WHV_PARTITION_HANDLE,
    pci_bus: &Arc<PciBus>,
    transports: &mut Vec<Arc<PciTransport>>,
) -> InputDevices {
    let keyboard = InputDevice::new_keyboard(ram.clone());
    let kt = attach_input_transport(
        "virtio-pci-input-keyboard",
        keyboard.clone(),
        0x00, // keyboard
        mmio_bus,
        part_handle,
        pci_bus,
    );
    transports.push(kt);

    let tablet = InputDevice::new_tablet(ram.clone());
    let tt = attach_input_transport(
        "virtio-pci-input-tablet",
        tablet.clone(),
        0x02, // mouse / pointing device
        mmio_bus,
        part_handle,
        pci_bus,
    );
    transports.push(tt);

    InputDevices { keyboard, tablet }
}

/// Route the GPU window's input events into the virtio-input devices: keyboard
/// keys to the keyboard, pointer motion/buttons/wheel to the absolute tablet.
/// The window client area equals the scanout, so pointer pixels map straight
/// onto the tablet's absolute axes (0..=ABS_AXIS_MAX). Used when both `--gpu`
/// and `--input` are present — the window then replaces the console as the host
/// input source (the console reader falls back to plain hvc0 byte forwarding).
/// The sink runs on the window's message-pump thread and reuses its event
/// buffers, so a steady input stream allocates nothing after warmup.
fn wire_window_input(display: &Arc<Display>, devs: &InputDevices, width: u32, height: u32) {
    use crate::display::{MouseButton, WindowEvent};
    use crate::virtio::input::{
        ABS_X, ABS_Y, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, REL_HWHEEL, REL_WHEEL,
    };

    let keyboard = devs.keyboard.clone();
    let tablet = devs.tablet.clone();
    let mut pressed = [false; 256];
    let mut cw = width.max(1);
    let mut ch = height.max(1);
    let mut kbd: Vec<InputEvent> = Vec::new();
    let mut tab: Vec<InputEvent> = Vec::new();

    display.set_input_sink(Box::new(move |ev| match ev {
        WindowEvent::Key { vkey, pressed: down, repeat, .. } => {
            let Some(code) = vk_to_linux_keycode(vkey) else {
                return;
            };
            let kc = code as usize;
            kbd.clear();
            if down {
                // evdev value 2 == autorepeat.
                let val = if repeat || pressed[kc] { 2 } else { 1 };
                pressed[kc] = true;
                kbd.push(InputEvent::key_value(code, val));
            } else if pressed[kc] {
                pressed[kc] = false;
                kbd.push(InputEvent::key(code, false));
            }
            if !kbd.is_empty() {
                keyboard.submit_frame(&kbd);
            }
        }
        WindowEvent::PointerMotion { x, y } => {
            tab.clear();
            push_abs(&mut tab, x, y, cw, ch, ABS_X, ABS_Y);
            tablet.submit_frame(&tab);
        }
        WindowEvent::Button { button, pressed: down, x, y } => {
            let code = match button {
                MouseButton::Left => BTN_LEFT,
                MouseButton::Right => BTN_RIGHT,
                MouseButton::Middle => BTN_MIDDLE,
                MouseButton::X1 | MouseButton::X2 => return, // tablet has no side btns
            };
            tab.clear();
            push_abs(&mut tab, x, y, cw, ch, ABS_X, ABS_Y);
            tab.push(InputEvent::key(code, down));
            tablet.submit_frame(&tab);
        }
        WindowEvent::Wheel { dx, dy } => {
            tab.clear();
            if dy != 0 {
                tab.push(InputEvent::rel(REL_WHEEL, wheel_notches(dy)));
            }
            if dx != 0 {
                tab.push(InputEvent::rel(REL_HWHEEL, wheel_notches(dx)));
            }
            if !tab.is_empty() {
                tablet.submit_frame(&tab);
            }
        }
        WindowEvent::Resized { width, height } if width > 0 && height > 0 => {
            cw = width;
            ch = height;
        }
        WindowEvent::Focus { gained: false } => {
            // Release any held keys so focus loss can't leave a key stuck down.
            kbd.clear();
            for (kc, down) in pressed.iter_mut().enumerate() {
                if *down {
                    *down = false;
                    kbd.push(InputEvent::key(kc as u16, false));
                }
            }
            if !kbd.is_empty() {
                keyboard.submit_frame(&kbd);
            }
        }
        _ => {}
    }));
}

/// Push ABS_X/ABS_Y for a client pixel, scaled to the tablet's absolute range.
fn push_abs(tab: &mut Vec<InputEvent>, x: i32, y: i32, cw: u32, ch: u32, abs_x: u16, abs_y: u16) {
    let cx = x.clamp(0, cw as i32 - 1) as i64;
    let cy = y.clamp(0, ch as i32 - 1) as i64;
    let max = crate::virtio::input::ABS_AXIS_MAX as i64;
    let ax = if cw > 1 { (cx * max / (cw as i64 - 1)) as u32 } else { 0 };
    let ay = if ch > 1 { (cy * max / (ch as i64 - 1)) as u32 } else { 0 };
    tab.push(InputEvent::abs(abs_x, ax));
    tab.push(InputEvent::abs(abs_y, ay));
}

/// WHEEL_DELTA (120) units -> evdev notch count (at least ±1 for any motion).
fn wheel_notches(delta: i32) -> i32 {
    let c = delta / 120;
    if c != 0 {
        c
    } else {
        delta.signum()
    }
}

/// Put the console into raw VT mode and spawn a detached reader thread that
/// forwards keystrokes into the guest's virtio-console RX. Ctrl+A X quits.
/// When stdin is redirected (not a console), input forwarding is skipped.
///
/// When `input` is supplied and stdin is a real console, the reader switches to
/// `ReadConsoleInputW` with mouse input enabled: keystrokes still drive hvc0
/// (translated to VT sequences) *and* the virtio-input keyboard, while mouse
/// motion/buttons/wheel drive the virtio-input absolute tablet.
fn setup_interactive_console(
    console: Arc<ConsoleDevice>,
    input: Option<InputDevices>,
    stop_all: impl Fn() + Send + 'static,
) -> ConsoleModeRestore {
    unsafe {
        let hin = GetStdHandle(STD_INPUT_HANDLE);
        let hout = GetStdHandle(STD_OUTPUT_HANDLE);
        let is_console = GetFileType(hin) == FILE_TYPE_CHAR;
        let want_mouse = is_console && input.is_some();
        let mut in_mode: u32 = 0;
        let mut out_mode: u32 = 0;
        if is_console {
            GetConsoleMode(hin, &mut in_mode);
            GetConsoleMode(hout, &mut out_mode);
            let raw_in = if want_mouse {
                // ReadConsoleInputW path: enable window + mouse records and set
                // EXTENDED_FLAGS to clear QuickEdit (which would otherwise eat
                // mouse events for text selection). We translate keys to VT
                // ourselves, so VT *input* mode is left off.
                (in_mode
                    & !(ENABLE_LINE_INPUT
                        | ENABLE_ECHO_INPUT
                        | ENABLE_PROCESSED_INPUT
                        | ENABLE_QUICK_EDIT_MODE))
                    | ENABLE_EXTENDED_FLAGS
                    | ENABLE_WINDOW_INPUT
                    | ENABLE_MOUSE_INPUT
            } else {
                (in_mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT
            };
            SetConsoleMode(hin, raw_in);
            SetConsoleMode(
                hout,
                out_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            );
            if want_mouse {
                eprintln!(
                    "[pvh-run] interactive console + virtio-input -- mouse & keyboard forwarded; \
                     Ctrl+A then X to quit"
                );
            } else {
                eprintln!("[pvh-run] interactive console -- press Ctrl+A then X to quit");
            }
        }

        // HANDLE isn't Send; smuggle it across the thread boundary as usize.
        let hin_addr = hin as usize;
        let hout_addr = hout as usize;
        match input {
            Some(devs) if want_mouse => {
                spawn_input_reader(hin_addr, hout_addr, console, devs, stop_all);
            }
            // No input devices, or stdin is redirected (no console records):
            // forward raw bytes from a real console (VT mode) or a pipe/file.
            _ => spawn_byte_reader(hin_addr, console, stop_all),
        }

        ConsoleModeRestore {
            valid: is_console,
            hin,
            in_mode,
            hout,
            out_mode,
        }
    }
}

/// Byte-stream reader: forwards stdin bytes to hvc0. Used when there are no
/// virtio-input devices, or when stdin is a redirected pipe/file (so
/// `echo cmd | tinyvmm ...` drives the shell). Ctrl+A X quits.
fn spawn_byte_reader(
    hin_addr: usize,
    console: Arc<ConsoleDevice>,
    stop_all: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || {
        let hin = hin_addr as HANDLE;
        let mut escape = false;
        let mut buf = [0u8; 256];
        loop {
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    hin,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                return;
            }
            let mut out = Vec::with_capacity(read as usize);
            for &b in &buf[..read as usize] {
                if escape {
                    escape = false;
                    if b == b'x' || b == b'X' {
                        eprintln!("\r\n[pvh-run] Ctrl+A X -- quitting");
                        stop_all();
                        return;
                    }
                    if b == 0x01 {
                        out.push(0x01);
                    }
                    continue;
                }
                if b == 0x01 {
                    escape = true;
                    continue;
                }
                out.push(b);
            }
            if !out.is_empty() {
                console.write_host_input(&out);
            }
        }
    });
}

/// Console-record reader (mouse + keyboard). Drives hvc0 (VT-translated keys),
/// the virtio-input keyboard (key down/up), and the virtio-input tablet
/// (absolute motion, buttons, wheel). Ctrl+A X quits.
fn spawn_input_reader(
    hin_addr: usize,
    hout_addr: usize,
    console: Arc<ConsoleDevice>,
    devs: InputDevices,
    stop_all: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || {
        let hin = hin_addr as HANDLE;
        let hout = hout_addr as HANDLE;
        let keyboard = devs.keyboard;
        let tablet = devs.tablet;
        let mut escape = false; // Ctrl+A escape state for the hvc0 quit shortcut
        let mut pressed = [false; 256]; // per-keycode state for the kbd device
        let mut prev_buttons: u32 = 0; // last LEFT|RIGHT|MIDDLE button mask
        let mut recs: [INPUT_RECORD; 64] = unsafe { std::mem::zeroed() };
        // Reused across iterations so a steady stream of input allocates
        // nothing after warmup (mirrors the device-side ChainScratch reuse).
        let mut hvc0: Vec<u8> = Vec::new();
        let mut kbd: Vec<InputEvent> = Vec::new();
        let mut tab: Vec<InputEvent> = Vec::new();
        loop {
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadConsoleInputW(hin, recs.as_mut_ptr(), recs.len() as u32, &mut read)
            };
            if ok == 0 || read == 0 {
                return;
            }
            hvc0.clear();
            kbd.clear();
            tab.clear();
            let mut quit = false;
            for r in &recs[..read as usize] {
                match r.EventType as u32 {
                    KEY_EVENT => {
                        let k = unsafe { r.Event.KeyEvent };
                        let down = k.bKeyDown != 0;
                        let wc = unsafe { k.uChar.UnicodeChar };
                        let reps = k.wRepeatCount.max(1);
                        // virtio-input keyboard: emit for both press and release.
                        if let Some(code) = vk_to_linux_keycode(k.wVirtualKeyCode) {
                            let kc = code as usize;
                            if down {
                                for _ in 0..reps {
                                    let val = if pressed[kc] { 2 } else { 1 };
                                    pressed[kc] = true;
                                    kbd.push(InputEvent::key_value(code, val));
                                }
                            } else if pressed[kc] {
                                pressed[kc] = false;
                                kbd.push(InputEvent::key(code, false));
                            }
                        }
                        // hvc0 text console: key-down only, VT-translated.
                        if down && append_hvc0_bytes(&mut hvc0, &mut escape, wc, k.wVirtualKeyCode, reps)
                        {
                            quit = true;
                            break;
                        }
                    }
                    MOUSE_EVENT => {
                        let m = unsafe { r.Event.MouseEvent };
                        append_mouse_events(&mut tab, &mut prev_buttons, hout, &m);
                    }
                    _ => {}
                }
            }
            if !hvc0.is_empty() {
                console.write_host_input(&hvc0);
            }
            if !kbd.is_empty() {
                keyboard.submit_frame(&kbd);
            }
            if !tab.is_empty() {
                tablet.submit_frame(&tab);
            }
            if quit {
                eprintln!("\r\n[pvh-run] Ctrl+A X -- quitting");
                stop_all();
                return;
            }
        }
    });
}

/// Append `bytes` to `out` `reps` times (key-repeat expansion for hvc0).
fn push_repeated(out: &mut Vec<u8>, bytes: &[u8], reps: u16) {
    for _ in 0..reps {
        out.extend_from_slice(bytes);
    }
}

/// Translate one key-down record into hvc0 bytes (VT sequences for navigation
/// keys, UTF-8 for printable characters), honoring the Ctrl+A escape. Returns
/// true if the user asked to quit (Ctrl+A then X).
fn append_hvc0_bytes(out: &mut Vec<u8>, escape: &mut bool, wc: u16, vk: u16, reps: u16) -> bool {
    if *escape {
        *escape = false;
        if wc == u16::from(b'x') || wc == u16::from(b'X') {
            return true;
        }
        if wc == 0x01 {
            out.push(0x01); // literal Ctrl+A
        }
        return false;
    }
    if wc == 0x01 {
        *escape = true; // arm escape, swallow
        return false;
    }
    // Navigation / function keys arrive with UnicodeChar == 0; emit xterm/VT.
    if wc == 0 {
        if let Some(seq) = vk_to_vt_sequence(vk) {
            push_repeated(out, seq, reps);
        }
        return false;
    }
    if wc == u16::from(b'\r') {
        push_repeated(out, b"\n", reps);
    } else if wc < 0x80 {
        push_repeated(out, &[wc as u8], reps);
    } else if let Some(c) = char::from_u32(wc as u32) {
        let mut tmp = [0u8; 4];
        push_repeated(out, c.encode_utf8(&mut tmp).as_bytes(), reps);
    }
    false
}

/// Convert a Windows mouse record into tablet events: absolute position
/// (scaled to the eventq axis range), button transitions, and wheel scroll.
fn append_mouse_events(
    tab: &mut Vec<InputEvent>,
    prev_buttons: &mut u32,
    hout: HANDLE,
    m: &MOUSE_EVENT_RECORD,
) {
    use crate::virtio::input::{ABS_AXIS_MAX, ABS_X, ABS_Y, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT,
        REL_HWHEEL, REL_WHEEL};

    // Absolute position: scale visible-window cell coords into 0..=ABS_AXIS_MAX.
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
    if unsafe { GetConsoleScreenBufferInfo(hout, &mut info) } != 0 {
        let w = &info.srWindow;
        let cols = (w.Right - w.Left + 1).max(1) as i32;
        let rows = (w.Bottom - w.Top + 1).max(1) as i32;
        let rx = (m.dwMousePosition.X as i32 - w.Left as i32).clamp(0, cols - 1);
        let ry = (m.dwMousePosition.Y as i32 - w.Top as i32).clamp(0, rows - 1);
        let ax = if cols > 1 { rx * ABS_AXIS_MAX as i32 / (cols - 1) } else { 0 };
        let ay = if rows > 1 { ry * ABS_AXIS_MAX as i32 / (rows - 1) } else { 0 };
        tab.push(InputEvent::abs(ABS_X, ax as u32));
        tab.push(InputEvent::abs(ABS_Y, ay as u32));
    }

    // Button transitions (low word holds the pressed-button mask).
    let cur = m.dwButtonState
        & (FROM_LEFT_1ST_BUTTON_PRESSED | RIGHTMOST_BUTTON_PRESSED | FROM_LEFT_2ND_BUTTON_PRESSED);
    for (mask, code) in [
        (FROM_LEFT_1ST_BUTTON_PRESSED, BTN_LEFT),
        (RIGHTMOST_BUTTON_PRESSED, BTN_RIGHT),
        (FROM_LEFT_2ND_BUTTON_PRESSED, BTN_MIDDLE),
    ] {
        let was = *prev_buttons & mask != 0;
        let is = cur & mask != 0;
        if was != is {
            tab.push(InputEvent::key(code, is));
        }
    }
    *prev_buttons = cur;

    // Wheel: the high word of dwButtonState is a signed delta (WHEEL_DELTA=120).
    if m.dwEventFlags & MOUSE_WHEELED != 0 {
        let delta = (m.dwButtonState >> 16) as i16 as i32;
        if delta != 0 {
            let clicks = delta / 120;
            tab.push(InputEvent::rel(REL_WHEEL, if clicks != 0 { clicks } else { delta.signum() }));
        }
    }
    if m.dwEventFlags & MOUSE_HWHEELED != 0 {
        let delta = (m.dwButtonState >> 16) as i16 as i32;
        if delta != 0 {
            let clicks = delta / 120;
            tab.push(InputEvent::rel(REL_HWHEEL, if clicks != 0 { clicks } else { delta.signum() }));
        }
    }
}

/// xterm/VT escape for a navigation or function key (matches the C++ reference).
fn vk_to_vt_sequence(vk: u16) -> Option<&'static [u8]> {
    let seq: &'static [u8] = match vk {
        0x26 => b"\x1b[A",   // VK_UP
        0x28 => b"\x1b[B",   // VK_DOWN
        0x27 => b"\x1b[C",   // VK_RIGHT
        0x25 => b"\x1b[D",   // VK_LEFT
        0x24 => b"\x1b[H",   // VK_HOME
        0x23 => b"\x1b[F",   // VK_END
        0x2D => b"\x1b[2~",  // VK_INSERT
        0x2E => b"\x1b[3~",  // VK_DELETE
        0x21 => b"\x1b[5~",  // VK_PRIOR (PgUp)
        0x22 => b"\x1b[6~",  // VK_NEXT (PgDn)
        0x70 => b"\x1bOP",   // VK_F1
        0x71 => b"\x1bOQ",   // VK_F2
        0x72 => b"\x1bOR",   // VK_F3
        0x73 => b"\x1bOS",   // VK_F4
        0x74 => b"\x1b[15~", // VK_F5
        0x75 => b"\x1b[17~", // VK_F6
        0x76 => b"\x1b[18~", // VK_F7
        0x77 => b"\x1b[19~", // VK_F8
        0x78 => b"\x1b[20~", // VK_F9
        0x79 => b"\x1b[21~", // VK_F10
        0x7A => b"\x1b[23~", // VK_F11
        0x7B => b"\x1b[24~", // VK_F12
        _ => return None,
    };
    Some(seq)
}

/// Map a Windows virtual-key code to a Linux evdev keycode (KEY_*). Returns
/// None for keys the keyboard device does not advertise.
fn vk_to_linux_keycode(vk: u16) -> Option<u16> {
    // QWERTY letter row order for VK_A..VK_Z (0x41..0x5A).
    const LETTERS: [u16; 26] = [
        30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17,
        45, 21, 44,
    ];
    // VK_0..VK_9 (0x30..0x39) -> KEY_0..KEY_9.
    const DIGITS: [u16; 10] = [11, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    // VK_NUMPAD0..9 (0x60..0x69) -> KEY_KP0..KEY_KP9.
    const NUMPAD: [u16; 10] = [82, 79, 80, 81, 75, 76, 77, 71, 72, 73];

    Some(match vk {
        0x41..=0x5A => LETTERS[(vk - 0x41) as usize],
        0x30..=0x39 => DIGITS[(vk - 0x30) as usize],
        0x60..=0x69 => NUMPAD[(vk - 0x60) as usize],
        0x70..=0x79 => 59 + (vk - 0x70),      // VK_F1..F10 -> KEY_F1..F10
        0x7A => 87,                            // VK_F11
        0x7B => 88,                            // VK_F12
        0x0D => 28,                            // VK_RETURN -> KEY_ENTER
        0x1B => 1,                             // VK_ESCAPE -> KEY_ESC
        0x08 => 14,                            // VK_BACK -> KEY_BACKSPACE
        0x09 => 15,                            // VK_TAB
        0x20 => 57,                            // VK_SPACE
        0x10 | 0xA0 => 42,                     // VK_SHIFT / VK_LSHIFT -> KEY_LEFTSHIFT
        0xA1 => 54,                            // VK_RSHIFT
        0x11 | 0xA2 => 29,                     // VK_CONTROL / VK_LCONTROL -> KEY_LEFTCTRL
        0xA3 => 97,                            // VK_RCONTROL
        0x12 | 0xA4 => 56,                     // VK_MENU / VK_LMENU -> KEY_LEFTALT
        0xA5 => 100,                           // VK_RMENU -> KEY_RIGHTALT
        0x5B => 125,                           // VK_LWIN -> KEY_LEFTMETA
        0x5C => 126,                           // VK_RWIN -> KEY_RIGHTMETA
        0x14 => 58,                            // VK_CAPITAL -> KEY_CAPSLOCK
        0x90 => 69,                            // VK_NUMLOCK
        0x91 => 70,                            // VK_SCROLL -> KEY_SCROLLLOCK
        0x26 => 103,                           // VK_UP
        0x28 => 108,                           // VK_DOWN
        0x25 => 105,                           // VK_LEFT
        0x27 => 106,                           // VK_RIGHT
        0x24 => 102,                           // VK_HOME
        0x23 => 107,                           // VK_END
        0x21 => 104,                           // VK_PRIOR -> KEY_PAGEUP
        0x22 => 109,                           // VK_NEXT -> KEY_PAGEDOWN
        0x2D => 110,                           // VK_INSERT
        0x2E => 111,                           // VK_DELETE
        0x6A => 55,                            // VK_MULTIPLY -> KEY_KPASTERISK
        0x6B => 78,                            // VK_ADD -> KEY_KPPLUS
        0x6D => 74,                            // VK_SUBTRACT -> KEY_KPMINUS
        0x6E => 83,                            // VK_DECIMAL -> KEY_KPDOT
        0x6F => 98,                            // VK_DIVIDE -> KEY_KPSLASH
        0xBA => 39,                            // VK_OEM_1 ;:
        0xBB => 13,                            // VK_OEM_PLUS =+
        0xBC => 51,                            // VK_OEM_COMMA ,<
        0xBD => 12,                            // VK_OEM_MINUS -_
        0xBE => 52,                            // VK_OEM_PERIOD .>
        0xBF => 53,                            // VK_OEM_2 /?
        0xC0 => 41,                            // VK_OEM_3 `~
        0xDB => 26,                            // VK_OEM_4 [{
        0xDC => 43,                            // VK_OEM_5 \|
        0xDD => 27,                            // VK_OEM_6 ]}
        0xDE => 40,                            // VK_OEM_7 '"
        _ => return None,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    diag::etw::register();

    let result = match args[1].as_str() {
        "--smoke" => run_smoke(),
        "--blk-selftest" => run_blk_selftest(),
        "--pci-selftest" => run_pci_selftest(),
        "--pvh-info" => run_pvh_info(&args),
        "--pvh-run" => run_pvh_run(&args),
        "--restore" => run_restore(&args),
        other => {
            eprintln!("unknown command: {other}");
            print_usage();
            Ok(1)
        }
    };

    diag::etw::unregister();

    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("tinyvmm error: {e}");
            std::process::exit(1);
        }
    }
}
