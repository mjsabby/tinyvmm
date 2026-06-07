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
use crate::error::{check_hr, Error, Result};
use crate::host::block_file::BlockFile;
use crate::net::nat::{NatBackend, NatOptions, PortForward};
use crate::pci::{PciBus, PciFunction};
use crate::virtio::blk::BlockDevice;
use crate::virtio::console::ConsoleDevice;
use crate::virtio::device::VirtioDevice;
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
    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Hypervisor::{
    WHvGetCapability, WHvRequestInterrupt, WHvCapabilityCodeHypervisorPresent,
    WHvX64LocalApicEmulationModeX2Apic, WHV_INTERRUPT_CONTROL,
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
         \x20 tinyvmm --pvh-info <vmlinux>\n\
         \x20 tinyvmm --pvh-run [--initrd <cpio>] [--ram-mb N] [--vcpus N] [--rng]\n\
         \x20              [--net [--net-backend loopback|nat] [--portfwd H:G]...]...  (repeat --net per NIC)\n\
         \x20              [--drive <path>[,readonly]]... [--cpu-affinity all|p|e|p-physical]\n\
         \x20              [--virtio-9p-share <tag>=<host_path>[,ro]]...\n\
         \x20              [--save <path> [--unsafe-save-mutable-drive]]\n\
         \x20              [--watchdog-secs N] [--debug-boot] <vmlinux> [-- <cmdline>]\n\
         \x20 tinyvmm --restore <path>\n"
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
    let mut part = Partition::new(1)?;
    part.enable_extended_exits(true, true, false)?;
    set_hide_tsc_deadline(true);
    let list = build_static_cpuid_result_list(true);
    part.set_cpuid_result_list(&list)?;
    part.set_local_apic_emulation(WHvX64LocalApicEmulationModeX2Apic)?;
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
    let _vcpu = Vcpu::new(part.handle(), 0)?;
    println!("[smoke] partition + vCPU created OK (tsc_hz={})", cached_tsc_hz());
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
    drives: Vec<DriveSpec>,
    affinity_mode: AffinityMode,
    p9_shares: Vec<P9ShareSpec>,
    save_path: Option<String>,
    unsafe_save_mutable_drive: bool,
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

fn parse_pvh_args(args: &[String]) -> Result<PvhArgs> {
    let mut initrd = None;
    let mut ram_mb = 256u32;
    let mut vcpus = 1u32;
    let mut watchdog_secs = 0u32;
    let mut debug_boot = false;
    let mut nics: Vec<NicSpec> = Vec::new();
    let mut with_rng = false;
    let mut drives: Vec<DriveSpec> = Vec::new();
    let mut affinity_mode = AffinityMode::All;
    let mut p9_shares: Vec<P9ShareSpec> = Vec::new();
    let mut save_path: Option<String> = None;
    let mut unsafe_save_mutable_drive = false;

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
                ram_mb = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::msg("--ram-mb wants an integer"))?;
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
        // hvc0 comes up. pci=conf1 forces our 0xCF8/0xCFC mechanism.
        cmdline = if debug_boot {
            "earlyprintk=ttyS0,115200 console=hvc0 pci=conf1,nocrs,lastbus=0 nofb nomodeset"
                .to_string()
        } else {
            "console=hvc0 pci=conf1,nocrs,lastbus=0 nofb nomodeset".to_string()
        };
    }

    Ok(PvhArgs {
        vmlinux,
        cmdline,
        initrd,
        ram_mb: ram_mb.clamp(128, 3584),
        vcpus: vcpus.clamp(1, MAX_VCPUS),
        watchdog_secs,
        nics,
        with_rng,
        drives,
        affinity_mode,
        p9_shares,
        save_path,
        unsafe_save_mutable_drive,
    })
}

fn run_pvh_run(args: &[String]) -> Result<i32> {
    let cfg = parse_pvh_args(args)?;

    // Snapshot save preconditions (mirror the C++, relaxed for net): a snapshot
    // must capture a self-contained machine. virtio-net IS snapshottable -- the
    // device model is captured and a FRESH backend is wired in on restore (live
    // external flows reset, but new flows + the device work). virtio-9p is still
    // refused: its open fids -> host file handles are live state we don't yet
    // re-open on restore. Drives must be read-only unless the operator opts in.
    if cfg.save_path.is_some() {
        if !cfg.p9_shares.is_empty() {
            return Err(Error::msg(
                "--save is incompatible with --virtio-9p-share (open fids -> host handles are \
                 live state not yet restorable)",
            ));
        }
        if !cfg.unsafe_save_mutable_drive {
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

    // --- virtio-9p (optional, repeatable via --virtio-9p-share) ---
    // Each share becomes one virtio-9p PCI device exposing one host directory.
    // The guest mounts via:
    //   mount -t 9p -o trans=virtio,version=9p2000.L <tag> /mnt/...
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
        println!(
            "[pvh-run] virtio-9p[{}] on PCI 00:{:02x}.0 tag={} host={}{}",
            i,
            pbdf.device,
            s.tag,
            s.host_root.display(),
            if s.readonly { " (ro)" } else { "" }
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
    let console_restore = setup_interactive_console(console.clone(), stop_all.clone());

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

    // Tear down: stop APs, signal watchdog, join.
    stop_all();
    watchdog_done.store(true, Ordering::Release);
    for h in ap_handles {
        let _ = h.join();
    }
    if let Some(w) = watchdog {
        let _ = w.join();
    }
    console_restore.restore();

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
            // Still every net data plane before capturing so no inbound frame
            // mutates an RX queue / guest RAM mid-snapshot.
            for nd in &net_devices {
                nd.quiesce_backend();
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

    let c = bsp.counters();
    btimer.mark("teardown done");
    diag::etw::Event::new("VmStop", diag::etw::INFO, diag::etw::kw::LIFECYCLE)
        .str("reason", &format!("{reason:?}"))
        .u64("io", c.io.load(Ordering::Relaxed))
        .u64("cpuid", c.cpuid.load(Ordering::Relaxed))
        .u64("msr", c.msr.load(Ordering::Relaxed))
        .u64("uart_tx", com1.tx_bytes())
        .f64("total_ms", btimer.elapsed_ms())
        .write();

    println!(
        "[pvh-run] stopped: reason={:?} uart_tx={} exits[io={} mmio={} cpuid={} msr={} halt={} other={}]",
        reason,
        com1.tx_bytes(),
        c.io.load(Ordering::Relaxed),
        c.mmio.load(Ordering::Relaxed),
        c.cpuid.load(Ordering::Relaxed),
        c.msr.load(Ordering::Relaxed),
        c.halt.load(Ordering::Relaxed),
        c.other.load(Ordering::Relaxed),
    );

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
    Ok(match nic.backend {
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
    })
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
        .u64("nic_count", cfg.nics.len() as u64)
        .u64("drive_count", cfg.drives.len() as u64);
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
/// size come entirely from the snapshot header; `--restore` takes no other args.
fn run_restore(args: &[String]) -> Result<i32> {
    let path = args
        .get(2)
        .ok_or_else(|| Error::msg("--restore wants a snapshot path"))?
        .clone();

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
    let drive_count = jr.get_u64("drive_count").unwrap_or(0) as usize;
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
         nics={} drives={drive_count}",
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
    // per-device snapshot indices line up: console(0), [rng], [blk...]. NET and
    // 9p are never present (the save path refuses them). ---
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
        let dpath = jr.get_str(&format!("drive{i}_path"))?;
        let dro = jr.get_bool(&format!("drive{i}_readonly")).unwrap_or(true);
        let backend = Arc::new(BlockFile::new(&dpath, dro));
        if !backend.open() {
            return Err(Error::msg(format!(
                "--restore: failed to reopen drive '{}' (readonly={}): err={}",
                dpath, dro as u32, backend.open_err()
            )));
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

    while let Some(s) = reader.next_section()? {
        match s.ty {
            SectionType::RamRaw => {
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
        if drift > tsc_hz_at_save / 100 {
            eprintln!(
                "[restore] WARN: TSC frequency drift {tsc_hz_at_save} -> {tsc_now} Hz (>1%); \
                 guest timekeeping may skew until it re-syncs"
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

    let console_restore = setup_interactive_console(console.clone(), stop_all.clone());
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

    println!("[restore] resuming {vcpu_count} vCPU(s)");

    let bsp = loops.remove(0);
    let mut ap_handles = Vec::new();
    for (i, l) in loops.into_iter().enumerate() {
        let h = std::thread::Builder::new()
            .name(format!("vcpu-{}", i + 1))
            .spawn(move || l.run())
            .map_err(|e| Error::msg(format!("spawn AP thread: {e}")))?;
        ap_handles.push(h);
    }
    let reason = bsp.run();

    stop_all();
    for h in ap_handles {
        let _ = h.join();
    }
    console_restore.restore();
    for b in &blk_backends {
        b.stop();
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

/// Put the console into raw VT mode and spawn a detached reader thread that
/// forwards keystrokes into the guest's virtio-console RX. Ctrl+A X quits.
/// When stdin is redirected (not a console), input forwarding is skipped.
fn setup_interactive_console(
    console: Arc<ConsoleDevice>,
    stop_all: impl Fn() + Send + 'static,
) -> ConsoleModeRestore {
    unsafe {
        let hin = GetStdHandle(STD_INPUT_HANDLE);
        let hout = GetStdHandle(STD_OUTPUT_HANDLE);
        let is_console = GetFileType(hin) == FILE_TYPE_CHAR;
        let mut in_mode: u32 = 0;
        let mut out_mode: u32 = 0;
        if is_console {
            GetConsoleMode(hin, &mut in_mode);
            GetConsoleMode(hout, &mut out_mode);
            let raw_in = (in_mode
                & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT;
            SetConsoleMode(hin, raw_in);
            SetConsoleMode(
                hout,
                out_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            );
            eprintln!("[pvh-run] interactive console -- press Ctrl+A then X to quit");
        }

        // HANDLE isn't Send; smuggle it across the thread boundary as usize.
        // We forward bytes from both a real console (raw VT mode, above) and a
        // redirected pipe/file (so `echo cmd | tinyvmm ...` drives the shell).
        let hin_addr = hin as usize;
        std::thread::spawn(move || {
            let hin = hin_addr as HANDLE;
            let mut escape = false;
            let mut buf = [0u8; 256];
            loop {
                let mut read: u32 = 0;
                let ok = ReadFile(
                    hin,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                );
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

        ConsoleModeRestore {
            valid: is_console,
            hin,
            in_mode,
            hout,
            out_mode,
        }
    }
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
