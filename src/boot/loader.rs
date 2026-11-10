//! PVH ELF loader: parses the kernel ELF, copies PT_LOAD segments into guest
//! RAM, stages hvm_start_info + e820 memmap + cmdline + GDT + ACPI in low
//! memory, and programs the BSP for 32-bit PVH entry. Port of boot/pvh_loader.cpp.

use crate::error::{Error, Result};
use crate::whp::regs::{reg64, seg, table};
use crate::whp::{GuestMemory, Vcpu};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use windows_sys::Win32::System::Hypervisor::{
    WHvX64RegisterCr0, WHvX64RegisterCr4, WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs,
    WHvX64RegisterFs, WHvX64RegisterGdtr, WHvX64RegisterGs, WHvX64RegisterRax, WHvX64RegisterRbx,
    WHvX64RegisterRflags, WHvX64RegisterRip, WHvX64RegisterSs,
};

use crate::boot::acpi;
use crate::mem_layout::{HIGH_RAM_BASE, MMIO_WINDOW_BASE};

// Low-memory staging layout (mirrors pvh_loader.cpp). The e820 map reserves
// everything below `BOOT_ARTIFACT_END`; the bzImage loader stages its zero page
// there too.
pub(super) const GDT_GPA: u64 = 0x1000;
const START_INFO_GPA: u64 = 0x2000;
const MEMMAP_GPA: u64 = 0x2100;
const MODLIST_GPA: u64 = 0x2400;
pub(super) const CMDLINE_GPA: u64 = 0x2800;
pub(super) const CMDLINE_MAX: usize = 0x800;
const ACPI_GPA: u64 = 0x3000;
const BOOT_ARTIFACT_END: u64 = 0x10000;

// PVH protocol constants.
const HVM_START_MAGIC: u32 = 0x336e_c578;
const HVM_START_VERSION: u32 = 1;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;
const ELF_NOTE_PHYS32_ENTRY: u32 = 18;

// ELF constants.
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const SHT_NOTE: u32 = 7;
const EM_X86_64: u16 = 0x3e;
/// More program headers than a kernel has (a handful).
const MAX_PROGRAM_HEADERS: usize = 1024;

// 32-bit flat-PM GDT (null / code / data).
const GDT_CODE32: u64 = 0x00CF_9A00_0000_FFFF;
const GDT_DATA32: u64 = 0x00CF_9200_0000_FFFF;
const GDT_CODE_SEL: u16 = 0x08;
const GDT_DATA_SEL: u16 = 0x10;

pub struct PvhLoadResult {
    pub entry_point: u32,
    pub start_info_gpa: u64,
    pub gdt_gpa: u64,
    pub bytes_loaded: u64,
    pub initramfs_gpa: u64,
    pub initramfs_size: u64,
}

struct LoadSegment {
    paddr: u64,
    filesz: u64,
    file_offset: u64,
}

fn rd_u16(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| Error::msg("ELF: truncated u16 read"))
}
fn rd_u32(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| Error::msg("ELF: truncated u32 read"))
}
fn rd_u64(b: &[u8], o: usize) -> Result<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| Error::msg("ELF: truncated u64 read"))
}

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// Copy a boot image into guest RAM on several threads. The copy is dominated
/// by first-touch faults on the mapped source pages rather than by memcpy, and
/// Windows resolves faults on distinct pages concurrently.
pub(super) fn copy_to_guest(ram: &GuestMemory, gpa: u64, src: &[u8]) -> Result<()> {
    const CHUNK: usize = 4 << 20;
    const MAX_THREADS: usize = 8;
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(MAX_THREADS)
        .min(src.len().div_ceil(CHUNK));
    if threads <= 1 {
        return ram.write_at(gpa, src);
    }
    if ram.host_range(gpa, src.len() as u64).is_none() {
        return Err(Error::msg("GuestMemory::write_at out of range"));
    }
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let offset = next.fetch_add(CHUNK, Ordering::Relaxed);
                    if offset >= src.len() {
                        break;
                    }
                    let end = (offset + CHUNK).min(src.len());
                    if !ram.write_bytes(gpa + offset as u64, &src[offset..end]) {
                        failed.store(true, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    if failed.load(Ordering::Relaxed) {
        return Err(Error::msg("GuestMemory::write_at out of range"));
    }
    Ok(())
}

/// Scan a PT_NOTE/SHT_NOTE blob for the Xen PHYS32_ENTRY note.
fn find_pvh_note(blob: &[u8]) -> Option<u32> {
    let mut off = 0usize;
    while off + 12 <= blob.len() {
        let namesz = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
        let descsz = u32::from_le_bytes(blob[off + 4..off + 8].try_into().unwrap()) as usize;
        let ntype = u32::from_le_bytes(blob[off + 8..off + 12].try_into().unwrap());
        off += 12;
        let name_pad = (namesz + 3) & !3;
        let desc_pad = (descsz + 3) & !3;
        if off + name_pad + desc_pad > blob.len() {
            break;
        }
        let name = &blob[off..off + namesz.min(name_pad)];
        let desc = &blob[off + name_pad..off + name_pad + descsz];
        if ntype == ELF_NOTE_PHYS32_ENTRY
            && namesz == 4
            && name.starts_with(b"Xen")
            && (descsz == 4 || descsz == 8)
        {
            let mut entry: u64 = 0;
            for (i, b) in desc.iter().enumerate().take(8) {
                entry |= (*b as u64) << (i * 8);
            }
            return Some(entry as u32);
        }
        off += name_pad + desc_pad;
    }
    None
}

/// Scan a note blob with `find_pvh_note`, counting its length against what
/// is `left` of the file to scan: headers that name the same bytes over and
/// over can then cost no more than the file is long.
fn scan_notes(blob: &[u8], left: &mut usize) -> Result<Option<u32>> {
    *left = left
        .checked_sub(blob.len())
        .ok_or_else(|| Error::msg("ELF notes overlap in the file"))?;
    Ok(find_pvh_note(blob))
}

struct PvhInfo {
    phys32_entry: Option<u32>,
    segments: Vec<LoadSegment>,
    kernel_phys_max: u64,
}

fn inspect(bytes: &[u8]) -> Result<PvhInfo> {
    if bytes.len() < 64 {
        return Err(Error::msg("file smaller than ELF header"));
    }
    if bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(Error::msg("not an ELF file"));
    }
    if bytes[4] != 2 {
        return Err(Error::msg("ELF is not 64-bit"));
    }
    if bytes[5] != 1 {
        return Err(Error::msg("ELF is not little-endian"));
    }
    if rd_u16(bytes, 18)? != EM_X86_64 {
        return Err(Error::msg("ELF e_machine != EM_X86_64"));
    }

    let e_phoff = rd_u64(bytes, 32)? as usize;
    let e_phentsize = rd_u16(bytes, 54)? as usize;
    let e_phnum = rd_u16(bytes, 56)? as usize;
    if e_phoff == 0 || e_phnum == 0 || e_phentsize != 56 {
        return Err(Error::msg("ELF has no program headers"));
    }
    if e_phnum > MAX_PROGRAM_HEADERS {
        return Err(Error::msg("ELF has too many program headers"));
    }

    let mut info = PvhInfo {
        phys32_entry: None,
        segments: Vec::new(),
        kernel_phys_max: 0,
    };
    // What the PT_LOADs take from the file, and what is scanned for notes,
    // come to no more than the file holds unless headers share bytes: a
    // crafted image's way of having a small file copied and scanned once per
    // header.
    let mut load_left = bytes.len();
    let mut notes_left = bytes.len();

    for i in 0..e_phnum {
        let ph = e_phoff + i * 56;
        let p_type = rd_u32(bytes, ph)?;
        let p_offset = rd_u64(bytes, ph + 8)?;
        let p_paddr = rd_u64(bytes, ph + 24)?;
        let p_filesz = rd_u64(bytes, ph + 32)?;
        let p_memsz = rd_u64(bytes, ph + 40)?;

        if p_type == PT_NOTE {
            let start = p_offset as usize;
            let end = start.saturating_add(p_filesz as usize);
            // The first entry found is the one used: nothing after it is
            // scanned.
            if info.phys32_entry.is_none() && end <= bytes.len() {
                info.phys32_entry = scan_notes(&bytes[start..end], &mut notes_left)?;
            }
        } else if p_type == PT_LOAD {
            if p_filesz == 0 && p_memsz == 0 {
                continue;
            }
            let end = (p_offset as usize).saturating_add(p_filesz as usize);
            if end > bytes.len() {
                return Err(Error::msg("PT_LOAD extends past end of file"));
            }
            if p_memsz < p_filesz {
                return Err(Error::msg("PT_LOAD p_memsz < p_filesz"));
            }
            load_left = load_left
                .checked_sub(p_filesz as usize)
                .ok_or_else(|| Error::msg("PT_LOAD segments overlap in the file"))?;
            info.segments.push(LoadSegment {
                paddr: p_paddr,
                filesz: p_filesz,
                file_offset: p_offset,
            });
            info.kernel_phys_max = info.kernel_phys_max.max(p_paddr + p_memsz);
        }
    }

    // Fallback: scan SHT_NOTE sections for kernels that keep the note only as a
    // section (no PT_NOTE program header).
    if info.phys32_entry.is_none() {
        let e_shoff = rd_u64(bytes, 40)? as usize;
        let e_shentsize = rd_u16(bytes, 58)? as usize;
        let e_shnum = rd_u16(bytes, 60)? as usize;
        if e_shoff != 0 && e_shnum != 0 && e_shentsize == 64 {
            // Sections name the bytes the segments did, a second time.
            let mut notes_left = bytes.len();
            for i in 0..e_shnum {
                let sh = e_shoff + i * 64;
                if rd_u32(bytes, sh + 4)? != SHT_NOTE {
                    continue;
                }
                let sh_offset = rd_u64(bytes, sh + 24)? as usize;
                let sh_size = rd_u64(bytes, sh + 32)? as usize;
                let end = sh_offset.saturating_add(sh_size);
                if end <= bytes.len()
                    && let Some(e) = scan_notes(&bytes[sh_offset..end], &mut notes_left)?
                {
                    info.phys32_entry = Some(e);
                    break;
                }
            }
        }
    }

    Ok(info)
}

/// Inspect a PVH ELF and report the entry point / load span (for `--pvh-info`).
pub fn print_pvh_info(bytes: &[u8]) -> Result<()> {
    let info = inspect(bytes)?;
    match info.phys32_entry {
        Some(e) => println!("[pvh] PVH PHYS32_ENTRY=0x{e:08x}"),
        None => println!("[pvh] PVH PHYS32_ENTRY: NOT FOUND -- not PVH-capable"),
    }
    println!("[pvh] PT_LOAD segments: {}", info.segments.len());
    for (i, s) in info.segments.iter().enumerate() {
        println!(
            "[pvh]   [{i}] paddr=0x{:08x} filesz=0x{:08x} off=0x{:08x}",
            s.paddr, s.filesz, s.file_offset
        );
    }
    if !info.segments.is_empty() {
        println!("[pvh] kernel_phys_max=0x{:x}", info.kernel_phys_max);
    }
    Ok(())
}

pub fn load_pvh(
    ram: &GuestMemory,
    vmlinux: &[u8],
    cmdline: &str,
    ram_bytes: u64,
    initramfs: Option<&[u8]>,
    vcpu_count: u32,
    vmbus: bool,
) -> Result<PvhLoadResult> {
    let info = inspect(vmlinux)?;
    let Some(entry) = info.phys32_entry else {
        return Err(Error::msg(
            "PVH note (Xen, type 18) not present in ELF -- rebuild kernel with CONFIG_PVH=y",
        ));
    };
    if info.kernel_phys_max > ram_bytes {
        return Err(Error::msg(
            "kernel PT_LOAD extends past configured guest RAM size",
        ));
    }

    // Copy each PT_LOAD into RAM. BSS tail (memsz - filesz) is already zero
    // because VirtualAlloc(MEM_COMMIT) hands back zeroed pages.
    let mut bytes_loaded = 0u64;
    for s in &info.segments {
        if s.filesz > 0 {
            let start = s.file_offset as usize;
            let end = start + s.filesz as usize;
            copy_to_guest(ram, s.paddr, &vmlinux[start..end])?;
            bytes_loaded += s.filesz;
        }
    }

    // Optional initramfs, placed 2 MiB-aligned after the kernel image.
    let mut initramfs_gpa = 0u64;
    let mut initramfs_size = 0u64;
    if let Some(img) = initramfs {
        if img.is_empty() {
            return Err(Error::msg("initramfs file is empty"));
        }
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut gpa = align_up(info.kernel_phys_max, TWO_MIB);
        if gpa < 0x10_0000 {
            gpa = 0x10_0000;
        }
        if gpa > ram_bytes || img.len() as u64 > ram_bytes - gpa {
            return Err(Error::msg(
                "initramfs would extend past configured guest RAM",
            ));
        }
        copy_to_guest(ram, gpa, img)?;
        initramfs_gpa = gpa;
        initramfs_size = img.len() as u64;

        // modlist[0] -> initramfs.
        let mut modlist = [0u8; 32];
        modlist[0..8].copy_from_slice(&gpa.to_le_bytes());
        modlist[8..16].copy_from_slice(&(img.len() as u64).to_le_bytes());
        ram.write_at(MODLIST_GPA, &modlist)?;
    }

    // GDT.
    let mut gdt = [0u8; 24];
    gdt[8..16].copy_from_slice(&GDT_CODE32.to_le_bytes());
    gdt[16..24].copy_from_slice(&GDT_DATA32.to_le_bytes());
    ram.write_at(GDT_GPA, &gdt)?;

    write_cmdline(ram, cmdline)?;
    let rsdp_gpa = write_acpi(ram, vcpu_count, vmbus)?;

    // e820 memmap: hvm_memmap_table_entry is the e820 entry plus 4 reserved bytes.
    let mm = e820_map(ram_bytes);
    let mut mm_bytes = Vec::with_capacity(mm.len() * 24);
    for &(addr, size, ty) in &mm {
        mm_bytes.extend_from_slice(&addr.to_le_bytes());
        mm_bytes.extend_from_slice(&size.to_le_bytes());
        mm_bytes.extend_from_slice(&ty.to_le_bytes());
        mm_bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    ram.write_at(MEMMAP_GPA, &mm_bytes)?;

    // hvm_start_info.
    let mut si = [0u8; 56];
    si[0..4].copy_from_slice(&HVM_START_MAGIC.to_le_bytes());
    si[4..8].copy_from_slice(&HVM_START_VERSION.to_le_bytes());
    // flags @8 = 0
    let nr_modules: u32 = if initramfs.is_some() { 1 } else { 0 };
    si[12..16].copy_from_slice(&nr_modules.to_le_bytes());
    si[16..24].copy_from_slice(&MODLIST_GPA.to_le_bytes());
    si[24..32].copy_from_slice(&CMDLINE_GPA.to_le_bytes());
    si[32..40].copy_from_slice(&rsdp_gpa.to_le_bytes());
    si[40..48].copy_from_slice(&MEMMAP_GPA.to_le_bytes());
    si[48..52].copy_from_slice(&(mm.len() as u32).to_le_bytes());
    ram.write_at(START_INFO_GPA, &si)?;

    Ok(PvhLoadResult {
        entry_point: entry,
        start_info_gpa: START_INFO_GPA,
        gdt_gpa: GDT_GPA,
        bytes_loaded,
        initramfs_gpa,
        initramfs_size,
    })
}

/// Write the NUL-terminated kernel command line at `CMDLINE_GPA`.
pub(super) fn write_cmdline(ram: &GuestMemory, cmdline: &str) -> Result<()> {
    let cmd = cmdline.as_bytes();
    if cmd.len() + 1 > CMDLINE_MAX {
        return Err(Error::msg("cmdline too long"));
    }
    let mut cbuf = vec![0u8; cmd.len() + 1];
    cbuf[..cmd.len()].copy_from_slice(cmd);
    ram.write_at(CMDLINE_GPA, &cbuf)
}

/// Write the ACPI tables and return the RSDP's guest-physical address.
pub(super) fn write_acpi(ram: &GuestMemory, vcpu_count: u32, vmbus: bool) -> Result<u64> {
    ram.write_at(ACPI_GPA, &acpi::build(ACPI_GPA, vcpu_count, vmbus))?;
    Ok(ACPI_GPA)
}

/// The guest's e820 memory map as `(address, size, type)`.
pub(super) fn e820_map(ram_bytes: u64) -> Vec<(u64, u64, u32)> {
    const ISA_HOLE_START: u64 = 0xa0000;
    const ISA_HOLE_END: u64 = 0x100000;
    let mut mm = vec![
        (0, BOOT_ARTIFACT_END, E820_RESERVED),
        (
            BOOT_ARTIFACT_END,
            ISA_HOLE_START - BOOT_ARTIFACT_END,
            E820_RAM,
        ),
        (ISA_HOLE_START, ISA_HOLE_END - ISA_HOLE_START, E820_RESERVED),
    ];
    // Low RAM stops at the PCI MMIO window; RAM beyond it is relocated above
    // 4 GiB (see `mem_layout`), leaving the window free for device BARs.
    let low_top = ram_bytes.min(MMIO_WINDOW_BASE);
    if low_top > ISA_HOLE_END {
        mm.push((ISA_HOLE_END, low_top - ISA_HOLE_END, E820_RAM));
    }
    if ram_bytes > MMIO_WINDOW_BASE {
        mm.push((HIGH_RAM_BASE, ram_bytes - MMIO_WINDOW_BASE, E820_RAM));
    }
    mm
}

/// Program the BSP for 32-bit PVH entry: flat-32 segments, GDTR, CR0.PE=1,
/// EBX = start_info_gpa, RIP = entry_point.
pub fn setup_pvh_entry(vp: &Vcpu, res: &PvhLoadResult) -> Result<()> {
    // 32-bit PM attributes: Type | S | P | DB | G.
    let code_attr: u16 = 0xB | (1 << 4) | (1 << 7) | (1 << 14) | (1 << 15);
    let data_attr: u16 = 0x3 | (1 << 4) | (1 << 7) | (1 << 14) | (1 << 15);

    let code = seg(0, 0xFFFF_FFFF, GDT_CODE_SEL, code_attr);
    let data = seg(0, 0xFFFF_FFFF, GDT_DATA_SEL, data_attr);

    const CR0_PE: u64 = 1 << 0;
    const CR0_ET: u64 = 1 << 4;

    let names = [
        WHvX64RegisterCs,
        WHvX64RegisterDs,
        WHvX64RegisterEs,
        WHvX64RegisterSs,
        WHvX64RegisterFs,
        WHvX64RegisterGs,
        WHvX64RegisterGdtr,
        WHvX64RegisterCr0,
        WHvX64RegisterCr4,
        WHvX64RegisterRflags,
        WHvX64RegisterRip,
        WHvX64RegisterRbx,
        WHvX64RegisterRax,
    ];
    let values = [
        code,
        data,
        data,
        data,
        data,
        data,
        table(res.gdt_gpa, 23),
        reg64(CR0_PE | CR0_ET),
        reg64(0),
        reg64(0x2),
        reg64(res.entry_point as u64),
        reg64(res.start_info_gpa),
        reg64(0),
    ];
    vp.set_registers(&names, &values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;

    const ENTRY: u32 = 0x0100_0000;
    const PADDR: u64 = 0x10_0000;

    /// The Xen PHYS32_ENTRY note naming `ENTRY`.
    fn pvh_note() -> Vec<u8> {
        let words = [4, 4, ELF_NOTE_PHYS32_ENTRY].map(u32::to_le_bytes);
        [&words.concat()[..], b"Xen\0", &ENTRY.to_le_bytes()].concat()
    }

    /// An ELF file: its header, a program header for each of `segments` (its
    /// type and the bytes of `body` it names, loaded at `PADDR`), `body`,
    /// then a section header for each of `sections` likewise.
    fn elf(
        segments: &[(u32, Range<usize>)],
        sections: &[(u32, Range<usize>)],
        body: &[u8],
    ) -> Vec<u8> {
        fn put(file: &mut [u8], at: usize, bytes: &[u8]) {
            file[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let body_at = 64 + 56 * segments.len();
        let mut file = vec![0u8; body_at];
        put(&mut file, 0, &[0x7f, b'E', b'L', b'F', 2, 1]);
        put(&mut file, 18, &EM_X86_64.to_le_bytes());
        put(&mut file, 32, &64u64.to_le_bytes());
        put(&mut file, 54, &56u16.to_le_bytes());
        put(&mut file, 56, &(segments.len() as u16).to_le_bytes());
        for (i, (kind, bytes)) in segments.iter().enumerate() {
            let ph = 64 + 56 * i;
            put(&mut file, ph, &kind.to_le_bytes());
            put(
                &mut file,
                ph + 8,
                &((body_at + bytes.start) as u64).to_le_bytes(),
            );
            put(&mut file, ph + 24, &PADDR.to_le_bytes());
            put(&mut file, ph + 32, &(bytes.len() as u64).to_le_bytes());
            put(&mut file, ph + 40, &(bytes.len() as u64).to_le_bytes());
        }
        file.extend_from_slice(body);
        if !sections.is_empty() {
            let e_shoff = file.len() as u64;
            put(&mut file, 40, &e_shoff.to_le_bytes());
            put(&mut file, 58, &64u16.to_le_bytes());
            put(&mut file, 60, &(sections.len() as u16).to_le_bytes());
        }
        for (kind, bytes) in sections {
            let mut sh = [0u8; 64];
            put(&mut sh, 4, &kind.to_le_bytes());
            put(&mut sh, 24, &((body_at + bytes.start) as u64).to_le_bytes());
            put(&mut sh, 32, &(bytes.len() as u64).to_le_bytes());
            file.extend_from_slice(&sh);
        }
        file
    }

    #[test]
    fn finds_the_entry_in_a_note_segment_or_section() {
        let body = [&[0xAA; 32][..], &pvh_note()].concat();
        let note = 32..body.len();
        let segments = [(PT_LOAD, 0..32), (PT_NOTE, note.clone())];
        let info = inspect(&elf(&segments, &[], &body)).unwrap();
        assert_eq!(info.phys32_entry, Some(ENTRY));
        assert_eq!(info.segments.len(), 1);
        assert_eq!(info.kernel_phys_max, PADDR + 32);
        // A kernel that keeps the note only as a section.
        let info = inspect(&elf(&segments[..1], &[(SHT_NOTE, note)], &body)).unwrap();
        assert_eq!(info.phys32_entry, Some(ENTRY));
        let info = inspect(&elf(&segments[..1], &[], &body)).unwrap();
        assert_eq!(info.phys32_entry, None);
    }

    #[test]
    fn headers_naming_the_same_bytes_over_and_over_are_refused() {
        let error = |file: &[u8]| inspect(file).err().unwrap().to_string();
        let body = [&[0u8; 4096][..], &pvh_note()].concat();
        let (all, note) = (0..body.len(), 4096..body.len());
        // Segments that share no bytes load. One naming the file's bytes
        // again had them copied again: 65535 times, with as many headers.
        let apart = [
            (PT_LOAD, 0..2048),
            (PT_LOAD, 2048..4096),
            (PT_NOTE, note.clone()),
        ];
        let info = inspect(&elf(&apart, &[], &body)).unwrap();
        assert_eq!((info.segments.len(), info.phys32_entry), (2, Some(ENTRY)));
        let again = vec![(PT_LOAD, all.clone()); 3];
        assert_eq!(
            error(&elf(&again, &[], &body)),
            "PT_LOAD segments overlap in the file"
        );
        // Once the entry is found, no other note is scanned: these hundred
        // each name the whole file.
        let mut found = vec![(PT_NOTE, note)];
        found.extend(vec![(PT_NOTE, all.clone()); 100]);
        let info = inspect(&elf(&found, &[], &body)).unwrap();
        assert_eq!(info.phys32_entry, Some(ENTRY));
        // Until it is found, no byte is scanned twice, in segments or in
        // sections.
        let lost = vec![(PT_NOTE, all.clone()); 100];
        assert_eq!(
            error(&elf(&lost, &[], &body)),
            "ELF notes overlap in the file"
        );
        let lost = vec![(SHT_NOTE, all); 100];
        assert_eq!(
            error(&elf(&apart[..2], &lost, &body)),
            "ELF notes overlap in the file"
        );
        // And a kernel has no thousand program headers.
        let headers = |count: usize| elf(&vec![(0, 0..0); count], &[], &body);
        assert!(inspect(&headers(MAX_PROGRAM_HEADERS)).is_ok());
        assert_eq!(
            error(&headers(MAX_PROGRAM_HEADERS + 1)),
            "ELF has too many program headers"
        );
    }
}
