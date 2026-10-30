//! Linux/x86 boot protocol loader for compressed kernels: the `bzImage`
//! (`vmlinuz`) that distributions ship (Documentation/arch/x86/boot.rst).
//! Copies the protected-mode kernel into guest RAM, stages the zero page
//! (`struct boot_params`) with the setup header, e820 map, command line,
//! initramfs and ACPI RSDP, and enters the kernel's 32-bit entry point. The
//! kernel's own decompressor takes over from there, so this works whatever the
//! compression and without `CONFIG_PVH`.

use crate::boot::loader::{self, CMDLINE_GPA, CMDLINE_MAX, GDT_GPA};
use crate::error::{Error, Result};
use crate::mem_layout::MMIO_WINDOW_BASE;
use crate::whp::regs::{reg64, seg, table};
use crate::whp::{GuestMemory, Vcpu};
use windows_sys::Win32::System::Hypervisor::{
    WHvX64RegisterCr0, WHvX64RegisterCr4, WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs,
    WHvX64RegisterFs, WHvX64RegisterGdtr, WHvX64RegisterGs, WHvX64RegisterRax, WHvX64RegisterRbp,
    WHvX64RegisterRbx, WHvX64RegisterRdi, WHvX64RegisterRflags, WHvX64RegisterRip,
    WHvX64RegisterRsi, WHvX64RegisterSs,
};

/// The zero page sits in the low memory that the e820 map reserves, next to
/// the GDT, command line and ACPI tables.
const BOOT_PARAMS_GPA: u64 = 0x4000;
const ZERO_PAGE_SIZE: usize = 4096;

// Setup header fields; offsets are the same in the image and the zero page.
const SETUP_SECTS: usize = 0x1F1;
const BOOT_FLAG: usize = 0x1FE;
const JUMP_OFFSET: usize = 0x201;
const HEADER_MAGIC: usize = 0x202;
const VERSION: usize = 0x206;
const TYPE_OF_LOADER: usize = 0x210;
const LOADFLAGS: usize = 0x211;
const CODE32_START: usize = 0x214;
const RAMDISK_IMAGE: usize = 0x218;
const RAMDISK_SIZE: usize = 0x21C;
const CMD_LINE_PTR: usize = 0x228;
const INITRD_ADDR_MAX: usize = 0x22C;
const RELOCATABLE_KERNEL: usize = 0x234;
const CMDLINE_SIZE: usize = 0x238;
const PAYLOAD_OFFSET: usize = 0x248;
const PREF_ADDRESS: usize = 0x258;
const INIT_SIZE: usize = 0x260;
/// `edd_mbr_sig_buffer` follows the setup header in the zero page.
const HEADER_END_MAX: usize = 0x290;

// Zero-page fields outside the setup header.
const ACPI_RSDP_ADDR: usize = 0x070;
const EXT_RAMDISK_IMAGE: usize = 0x0C0;
const EXT_RAMDISK_SIZE: usize = 0x0C4;
const EXT_CMD_LINE_PTR: usize = 0x0C8;
const E820_ENTRIES: usize = 0x1E8;
const E820_TABLE: usize = 0x2D0;
const E820_MAX_ENTRIES: usize = 128;
const E820_ENTRY_SIZE: usize = 20;

const LOADED_HIGH: u8 = 1 << 0;
const LOADER_UNDEFINED: u8 = 0xFF;
/// Protocol 2.10 (Linux 2.6.31) added `pref_address` and `init_size`.
const MIN_VERSION: u16 = 0x020A;
/// Where a non-relocatable kernel's protected-mode code must be loaded.
const LEGACY_LOAD_ADDR: u64 = 0x10_0000;
const PAGE: u64 = 4096;

// The 32-bit boot protocol wants flat 4 GiB segments at __BOOT_CS (0x10) and
// __BOOT_DS (0x18).
const GDT_CODE32: u64 = 0x00CF_9A00_0000_FFFF;
const GDT_DATA32: u64 = 0x00CF_9200_0000_FFFF;
const BOOT_CS: u16 = 0x10;
const BOOT_DS: u16 = 0x18;

pub struct BzImageLoad {
    pub entry_point: u32,
    pub boot_params_gpa: u64,
    pub version: u16,
    pub bytes_loaded: u64,
    pub initramfs_gpa: u64,
    pub initramfs_size: u64,
}

/// Whether `image` is a bzImage (the 0xAA55 boot flag and the "HdrS" magic).
pub fn is_bzimage(image: &[u8]) -> bool {
    image.get(BOOT_FLAG..BOOT_FLAG + 2) == Some(&[0x55, 0xAA][..])
        && image.get(HEADER_MAGIC..HEADER_MAGIC + 4) == Some(&b"HdrS"[..])
}

struct Header {
    /// Bytes of real-mode setup code before the protected-mode kernel.
    setup_size: usize,
    /// End of the setup header (exclusive), as declared by its jump.
    header_end: usize,
    version: u16,
    relocatable: bool,
    initrd_addr_max: u32,
    cmdline_size: u32,
    pref_address: u64,
    init_size: u32,
    payload_offset: u32,
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from(u32_at(b, off)) | (u64::from(u32_at(b, off + 4)) << 32)
}
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn parse_header(image: &[u8]) -> Result<Header> {
    if !is_bzimage(image) {
        return Err(Error::msg("not a bzImage (no HdrS setup header)"));
    }
    // A zero means the historical default of 4 setup sectors.
    let setup_sects = match image[SETUP_SECTS] {
        0 => 4,
        n => n as usize,
    };
    let setup_size = (setup_sects + 1) * 512;
    if image.len() <= setup_size {
        return Err(Error::msg("bzImage: no protected-mode kernel after setup"));
    }
    let version = u16_at(image, VERSION);
    if version < MIN_VERSION {
        return Err(Error::msg(format!(
            "bzImage: boot protocol {}.{:02} is too old (need 2.10+)",
            version >> 8,
            version & 0xFF
        )));
    }
    if image[LOADFLAGS] & LOADED_HIGH == 0 {
        return Err(Error::msg(
            "bzImage: kernel isn't loaded high (zImage unsupported)",
        ));
    }
    let header_end = (HEADER_MAGIC + image[JUMP_OFFSET] as usize).min(HEADER_END_MAX);
    Ok(Header {
        setup_size,
        header_end,
        version,
        relocatable: image[RELOCATABLE_KERNEL] != 0,
        initrd_addr_max: u32_at(image, INITRD_ADDR_MAX),
        cmdline_size: u32_at(image, CMDLINE_SIZE),
        pref_address: u64_at(image, PREF_ADDRESS),
        init_size: u32_at(image, INIT_SIZE),
        payload_offset: u32_at(image, PAYLOAD_OFFSET),
    })
}

/// Load a bzImage, its initramfs and the boot data into guest RAM.
pub fn load(
    ram: &GuestMemory,
    image: &[u8],
    cmdline: &str,
    ram_bytes: u64,
    initramfs: Option<&[u8]>,
    vcpu_count: u32,
) -> Result<BzImageLoad> {
    let hdr = parse_header(image)?;
    let kernel = &image[hdr.setup_size..];
    let load_addr = if hdr.relocatable {
        hdr.pref_address
    } else {
        LEGACY_LOAD_ADDR
    };
    // The decompressor works within [load_addr, load_addr + init_size), and the
    // 32-bit entry identity-maps only the low 4 GiB, so all boot data stays in
    // the RAM below the PCI MMIO window.
    let low_top = ram_bytes.min(MMIO_WINDOW_BASE);
    let kernel_end = load_addr + u64::from(hdr.init_size).max(kernel.len() as u64);
    if load_addr < LEGACY_LOAD_ADDR || kernel_end > low_top {
        return Err(Error::msg(format!(
            "bzImage: the kernel needs RAM at 0x{load_addr:x}..0x{kernel_end:x}; raise --ram-mb"
        )));
    }
    if cmdline.len() > hdr.cmdline_size as usize || cmdline.len() + 1 > CMDLINE_MAX {
        return Err(Error::msg(format!(
            "cmdline too long ({} bytes; this kernel takes {})",
            cmdline.len(),
            (hdr.cmdline_size as usize).min(CMDLINE_MAX - 1)
        )));
    }
    loader::copy_to_guest(ram, load_addr, kernel)?;

    // Place the initramfs as high as the kernel allows, like GRUB does, clear
    // of the area the decompressor works in.
    let (initramfs_gpa, initramfs_size) = match initramfs {
        None => (0, 0),
        Some([]) => return Err(Error::msg("initramfs file is empty")),
        Some(img) => {
            let size = img.len() as u64;
            let limit = low_top.min(u64::from(hdr.initrd_addr_max) + 1);
            let gpa = limit.checked_sub(size).map(|top| top & !(PAGE - 1));
            match gpa {
                Some(gpa) if gpa >= kernel_end => {
                    loader::copy_to_guest(ram, gpa, img)?;
                    (gpa, size)
                }
                _ => {
                    return Err(Error::msg(format!(
                        "bzImage: no room for a {} MiB initramfs below 0x{limit:x}; raise --ram-mb",
                        size >> 20
                    )));
                }
            }
        }
    };

    let mut gdt = [0u8; 32];
    gdt[BOOT_CS as usize..BOOT_CS as usize + 8].copy_from_slice(&GDT_CODE32.to_le_bytes());
    gdt[BOOT_DS as usize..BOOT_DS as usize + 8].copy_from_slice(&GDT_DATA32.to_le_bytes());
    ram.write_at(GDT_GPA, &gdt)?;
    loader::write_cmdline(ram, cmdline)?;
    let rsdp = loader::write_acpi(ram, vcpu_count)?;

    let mut zp = vec![0u8; ZERO_PAGE_SIZE];
    zp[SETUP_SECTS..hdr.header_end].copy_from_slice(&image[SETUP_SECTS..hdr.header_end]);
    zp[TYPE_OF_LOADER] = LOADER_UNDEFINED;
    put_u32(&mut zp, CODE32_START, load_addr as u32);
    put_u32(&mut zp, RAMDISK_IMAGE, initramfs_gpa as u32);
    put_u32(&mut zp, RAMDISK_SIZE, initramfs_size as u32);
    put_u32(&mut zp, EXT_RAMDISK_IMAGE, (initramfs_gpa >> 32) as u32);
    put_u32(&mut zp, EXT_RAMDISK_SIZE, (initramfs_size >> 32) as u32);
    put_u32(&mut zp, CMD_LINE_PTR, CMDLINE_GPA as u32);
    put_u32(&mut zp, EXT_CMD_LINE_PTR, (CMDLINE_GPA >> 32) as u32);
    put_u64(&mut zp, ACPI_RSDP_ADDR, rsdp);
    let map = loader::e820_map(ram_bytes);
    if map.len() > E820_MAX_ENTRIES {
        return Err(Error::msg("bzImage: e820 map too large"));
    }
    zp[E820_ENTRIES] = map.len() as u8;
    for (i, &(addr, size, ty)) in map.iter().enumerate() {
        let e = E820_TABLE + i * E820_ENTRY_SIZE;
        put_u64(&mut zp, e, addr);
        put_u64(&mut zp, e + 8, size);
        put_u32(&mut zp, e + 16, ty);
    }
    ram.write_at(BOOT_PARAMS_GPA, &zp)?;

    Ok(BzImageLoad {
        entry_point: load_addr as u32,
        boot_params_gpa: BOOT_PARAMS_GPA,
        version: hdr.version,
        bytes_loaded: kernel.len() as u64,
        initramfs_gpa,
        initramfs_size,
    })
}

/// Program the BSP for the 32-bit boot protocol entry: flat segments at
/// __BOOT_CS/__BOOT_DS, CR0.PE=1, paging and interrupts off, ESI = the zero
/// page, and EBX/EBP/EDI zero.
pub fn setup_entry(vp: &Vcpu, load: &BzImageLoad) -> Result<()> {
    // 32-bit PM attributes: Type | S | P | DB | G.
    let code_attr: u16 = 0xB | (1 << 4) | (1 << 7) | (1 << 14) | (1 << 15);
    let data_attr: u16 = 0x3 | (1 << 4) | (1 << 7) | (1 << 14) | (1 << 15);
    let code = seg(0, 0xFFFF_FFFF, BOOT_CS, code_attr);
    let data = seg(0, 0xFFFF_FFFF, BOOT_DS, data_attr);

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
        WHvX64RegisterRsi,
        WHvX64RegisterRbx,
        WHvX64RegisterRbp,
        WHvX64RegisterRdi,
        WHvX64RegisterRax,
    ];
    let values = [
        code,
        data,
        data,
        data,
        data,
        data,
        table(GDT_GPA, 31),
        reg64(CR0_PE | CR0_ET),
        reg64(0),
        reg64(0x2),
        reg64(u64::from(load.entry_point)),
        reg64(load.boot_params_gpa),
        reg64(0),
        reg64(0),
        reg64(0),
        reg64(0),
    ];
    vp.set_registers(&names, &values)
}

/// Describe a bzImage's boot header (for `--pvh-info`).
pub fn print_info(image: &[u8]) -> Result<()> {
    let hdr = parse_header(image)?;
    let payload = hdr.setup_size + hdr.payload_offset as usize;
    let compression = match image.get(payload..payload + 4) {
        Some([0x1F, 0x8B, ..]) => "gzip",
        Some([0x28, 0xB5, 0x2F, 0xFD]) => "zstd",
        Some([0xFD, b'7', b'z', b'X']) => "xz",
        Some([0x02, 0x21, 0x4C, 0x18]) => "lz4",
        Some([b'B', b'Z', b'h', _]) => "bzip2",
        Some([0x89, b'L', b'Z', b'O']) => "lzo",
        Some([0x5D, 0x00, ..]) => "lzma",
        _ => "unknown",
    };
    println!(
        "[bzimage] boot protocol {}.{:02}, {}, payload {compression}",
        hdr.version >> 8,
        hdr.version & 0xFF,
        if hdr.relocatable {
            "relocatable"
        } else {
            "not relocatable"
        }
    );
    println!(
        "[bzimage] pref_address=0x{:x} init_size=0x{:x} cmdline_size={} initrd_addr_max=0x{:x}",
        hdr.pref_address, hdr.init_size, hdr.cmdline_size, hdr.initrd_addr_max
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    /// A minimal relocatable bzImage: 4 setup sectors with a 2.15 header, then
    /// `kernel` as the protected-mode code.
    fn bzimage(kernel: &[u8], init_size: u32) -> Vec<u8> {
        let mut img = vec![0u8; 5 * 512];
        img[SETUP_SECTS] = 4;
        img[BOOT_FLAG..BOOT_FLAG + 2].copy_from_slice(&[0x55, 0xAA]);
        img[0x200] = 0xEB;
        img[JUMP_OFFSET] = 0x6A; // header ends at 0x26C
        img[HEADER_MAGIC..HEADER_MAGIC + 4].copy_from_slice(b"HdrS");
        img[VERSION..VERSION + 2].copy_from_slice(&0x020Fu16.to_le_bytes());
        img[LOADFLAGS] = LOADED_HIGH;
        put_u32(&mut img, CODE32_START, 0x10_0000);
        put_u32(&mut img, INITRD_ADDR_MAX, 0x7FFF_FFFF);
        img[RELOCATABLE_KERNEL] = 1;
        put_u32(&mut img, CMDLINE_SIZE, 2047);
        put_u64(&mut img, PREF_ADDRESS, 0x100_0000);
        put_u32(&mut img, INIT_SIZE, init_size);
        img.extend_from_slice(kernel);
        img
    }

    fn read(ram: &GuestMemory, gpa: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        assert!(ram.read_into(gpa, &mut buf));
        buf
    }

    #[test]
    fn stages_kernel_initramfs_and_zero_page() {
        let ram_bytes = 64 * MIB;
        let ram = GuestMemory::new_host_only(ram_bytes as usize).unwrap();
        let image = bzimage(b"KERNEL", 4 * MIB as u32);
        let initrd = vec![0x5Au8; 3 * 4096 + 100];
        let load = load(&ram, &image, "console=hvc0", ram_bytes, Some(&initrd), 2).unwrap();

        assert_eq!(load.entry_point, 0x100_0000);
        assert_eq!(read(&ram, 0x100_0000, 6), b"KERNEL");
        // The initramfs ends at the top of RAM, page aligned.
        assert_eq!(
            load.initramfs_gpa,
            (ram_bytes - initrd.len() as u64) & !(PAGE - 1)
        );
        assert_eq!(read(&ram, load.initramfs_gpa, initrd.len()), initrd);

        let zp = read(&ram, BOOT_PARAMS_GPA, ZERO_PAGE_SIZE);
        assert_eq!(&zp[HEADER_MAGIC..HEADER_MAGIC + 4], b"HdrS");
        assert_eq!(zp[TYPE_OF_LOADER], LOADER_UNDEFINED);
        assert_eq!(u32_at(&zp, CODE32_START), 0x100_0000);
        assert_eq!(u64::from(u32_at(&zp, RAMDISK_IMAGE)), load.initramfs_gpa);
        assert_eq!(u32_at(&zp, RAMDISK_SIZE) as usize, initrd.len());
        assert_eq!(u64::from(u32_at(&zp, CMD_LINE_PTR)), CMDLINE_GPA);
        assert_eq!(read(&ram, CMDLINE_GPA, 13), b"console=hvc0\0");
        assert_eq!(u64_at(&zp, ACPI_RSDP_ADDR), 0x3000);
        assert_eq!(&read(&ram, 0x3000, 8), b"RSD PTR ");
        let map = loader::e820_map(ram_bytes);
        assert_eq!(zp[E820_ENTRIES] as usize, map.len());
        let last = E820_TABLE + (map.len() - 1) * E820_ENTRY_SIZE;
        assert_eq!(u64_at(&zp, last), 0x10_0000);
        assert_eq!(u64_at(&zp, last + 8), ram_bytes - 0x10_0000);
        assert_eq!(u32_at(&zp, last + 16), 1); // E820_RAM
    }

    #[test]
    fn refuses_layouts_that_do_not_fit() {
        let ram_bytes = 32 * MIB;
        let ram = GuestMemory::new_host_only(ram_bytes as usize).unwrap();
        // The decompressor's area (16 + 24 MiB) runs past RAM.
        let image = bzimage(b"K", 24 * MIB as u32);
        assert!(load(&ram, &image, "", ram_bytes, None, 1).is_err());
        // The kernel fits, but the initramfs would overlap its area.
        let image = bzimage(b"K", 8 * MIB as u32);
        let initrd = vec![1u8; 9 * MIB as usize];
        assert!(load(&ram, &image, "", ram_bytes, Some(&initrd), 1).is_err());
        assert!(load(&ram, &image, &"x".repeat(2048), ram_bytes, None, 1).is_err());
        assert!(load(&ram, &image, "", ram_bytes, None, 1).is_ok());
    }

    #[test]
    fn non_relocatable_kernels_load_at_1_mib() {
        let ram = GuestMemory::new_host_only(32 << 20).unwrap();
        let mut image = bzimage(b"OLD", 4 << 20);
        image[RELOCATABLE_KERNEL] = 0;
        let load = load(&ram, &image, "", 32 << 20, None, 1).unwrap();
        assert_eq!(load.entry_point, 0x10_0000);
        assert_eq!(read(&ram, 0x10_0000, 3), b"OLD");
    }

    #[test]
    fn rejects_non_bzimages() {
        let ram = GuestMemory::new_host_only(32 << 20).unwrap();
        assert!(!is_bzimage(b"\x7fELF"));
        let mut image = bzimage(b"K", 1 << 20);
        image[VERSION..VERSION + 2].copy_from_slice(&0x0209u16.to_le_bytes());
        assert!(load(&ram, &image, "", 32 << 20, None, 1).is_err());
    }
}
