//! Minimal ACPI tables built on the host for the guest: RSDP, XSDT, FADT,
//! FACS, MADT and DSDT. The MADT lets Linux skip "virtual wire mode" and
//! register the LAPIC clock-event device (without which hrtimers never fire).
//! The FADT and DSDT give it power management through `devices::power`: S5
//! soft-off, and a reset register for reboots.
//!
//! The FADT describes fixed ACPI hardware with no events: no buttons, no GPEs,
//! no PM timer, so nothing ever raises the SCI. It is not hardware-reduced,
//! because that mode makes Linux drop the 8259 PIC, the only path for ISA
//! interrupts here (the MADT lists no IOAPIC). With ACPI enabled, Linux finds
//! PCI through the DSDT's host bridge (`\_SB.PCI0`) instead of probing for it,
//! and VMBus (`crate::vmbus`), when on, through `\_SB.VMBS`.

use crate::devices::power::{
    PM1_CNT_LEN, PM1_EVT_LEN, PM1A_CNT_PORT, PM1A_EVT_PORT, RESET_PORT, RESET_VALUE, SLP_TYP_S5,
};
use crate::mem_layout::{MMIO_WINDOW_BASE, MMIO_WINDOW_END};

pub const MAX_VCPUS: u32 = 32;
pub const FOOTPRINT: usize = 4096;

const RSDP_OFFSET: usize = 0x000;
const XSDT_OFFSET: usize = 0x040;
const FACS_OFFSET: usize = 0x080;
const FADT_OFFSET: usize = 0x0C0;
const MADT_OFFSET: usize = 0x200;
const DSDT_OFFSET: usize = 0x440;

const HEADER_LEN: usize = 36;
const XSDT_LEN: usize = HEADER_LEN + 2 * 8;
const FACS_LEN: usize = 64;
const FADT_LEN: usize = 276;
const MADT_ENTRIES_OFFSET: usize = 44;
const MADT_ENTRY_LEN: usize = 16;

const _: () = assert!(XSDT_OFFSET + XSDT_LEN <= FACS_OFFSET);
// The FACS must be 64-byte aligned; the tables' base is page aligned.
const _: () = assert!(FACS_OFFSET.is_multiple_of(64) && FACS_OFFSET + FACS_LEN <= FADT_OFFSET);
const _: () = assert!(FADT_OFFSET + FADT_LEN <= MADT_OFFSET);
const _: () =
    assert!(MADT_OFFSET + MADT_ENTRIES_OFFSET + MAX_VCPUS as usize * MADT_ENTRY_LEN <= DSDT_OFFSET);

/// Never raised, but ACPICA installs a handler on it, so it has to be an
/// interrupt nothing else uses.
const SCI_IRQ: u16 = 9;
/// The CMOS register holding the century (`devices::legacy`).
const CMOS_CENTURY: u8 = 0x32;
/// IAPC_BOOT_ARCH: there are ISA devices (serial, PIT, RTC), but no 8042.
const BOOT_ARCH_LEGACY_DEVICES: u16 = 1 << 0;
/// FADT flags: WBINVD works and C1 is supported; no fixed-feature power or
/// sleep button and no RTC wake status (PWR_BUTTON, SLP_BUTTON and FIX_RTC set
/// mean absent); RESET_REG is supported.
const FADT_FLAGS: u32 = 1 | (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 10);
/// P_LVL2_LAT above 100 and P_LVL3_LAT above 1000 say C2 and C3 are absent.
const NO_C2_LATENCY: u16 = 101;
const NO_C3_LATENCY: u16 = 1001;
const GAS_SYSTEM_IO: u8 = 1;
const GAS_ACCESS_BYTE: u8 = 1;

fn checksum(bytes: &[u8]) -> u8 {
    let mut s: u8 = 0;
    for &b in bytes {
        s = s.wrapping_add(b);
    }
    0u8.wrapping_sub(s)
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// A Generic Address Structure for an I/O port register.
fn put_io_gas(buf: &mut [u8], off: usize, port: u16, bit_width: u8, access_size: u8) {
    buf[off] = GAS_SYSTEM_IO;
    buf[off + 1] = bit_width;
    buf[off + 2] = 0; // bit offset
    buf[off + 3] = access_size;
    put_u64(buf, off + 4, u64::from(port));
}

/// Standard 36-byte ACPI description-table header.
fn fill_header(
    buf: &mut [u8],
    off: usize,
    sig: &[u8; 4],
    length: u32,
    revision: u8,
    oem_table_id: &[u8; 8],
) {
    buf[off..off + 4].copy_from_slice(sig);
    put_u32(buf, off + 4, length);
    buf[off + 8] = revision;
    buf[off + 9] = 0; // checksum, filled later
    buf[off + 10..off + 16].copy_from_slice(b"TINYVM");
    buf[off + 16..off + 24].copy_from_slice(oem_table_id);
    put_u32(buf, off + 24, 1); // oem_revision
    buf[off + 28..off + 32].copy_from_slice(b"TVMM");
    put_u32(buf, off + 32, 1); // asl_compiler_revision
}

fn seal(buf: &mut [u8], off: usize, len: usize) {
    buf[off + 9] = checksum(&buf[off..off + len]);
}

/// Build the tables into a `FOOTPRINT`-byte buffer where the guest physical
/// address of byte 0 equals `gpa_base`. The RSDP is at offset 0. `vmbus` adds
/// the VMBus device.
pub fn build(gpa_base: u64, vcpu_count: u32, vmbus: bool) -> Vec<u8> {
    assert!(gpa_base.is_multiple_of(64) && gpa_base + FOOTPRINT as u64 <= 1 << 32);
    let vcpu_count = vcpu_count.clamp(1, MAX_VCPUS);
    let gpa = |off: usize| gpa_base + off as u64;
    let mut buf = vec![0u8; FOOTPRINT];

    // ---- MADT ----
    let madt_len = MADT_ENTRIES_OFFSET + vcpu_count as usize * MADT_ENTRY_LEN;
    fill_header(
        &mut buf,
        MADT_OFFSET,
        b"APIC",
        madt_len as u32,
        5,
        b"MADT    ",
    );
    put_u32(&mut buf, MADT_OFFSET + 36, 0xFEE0_0000); // local_apic_address
    put_u32(&mut buf, MADT_OFFSET + 40, 1); // flags: PCAT_COMPAT
    for i in 0..vcpu_count {
        let e = MADT_OFFSET + MADT_ENTRIES_OFFSET + (i as usize) * MADT_ENTRY_LEN;
        buf[e] = 9; // type: Local x2APIC
        buf[e + 1] = MADT_ENTRY_LEN as u8;
        // reserved u16 @ +2 stays 0
        put_u32(&mut buf, e + 4, i); // local_apic_id
        put_u32(&mut buf, e + 8, 1); // flags: enabled
        put_u32(&mut buf, e + 12, i); // acpi_processor_uid
    }
    seal(&mut buf, MADT_OFFSET, madt_len);

    // ---- DSDT ----
    let aml = dsdt_aml(vmbus);
    let dsdt_len = HEADER_LEN + aml.len();
    assert!(DSDT_OFFSET + dsdt_len <= FOOTPRINT);
    fill_header(
        &mut buf,
        DSDT_OFFSET,
        b"DSDT",
        dsdt_len as u32,
        2,
        b"DSDT    ",
    );
    buf[DSDT_OFFSET + HEADER_LEN..DSDT_OFFSET + dsdt_len].copy_from_slice(&aml);
    seal(&mut buf, DSDT_OFFSET, dsdt_len);

    // ---- FACS (no checksum) ----
    buf[FACS_OFFSET..FACS_OFFSET + 4].copy_from_slice(b"FACS");
    put_u32(&mut buf, FACS_OFFSET + 4, FACS_LEN as u32);
    buf[FACS_OFFSET + 32] = 2; // version

    // ---- FADT (revision 6) ----
    let f = FADT_OFFSET;
    fill_header(&mut buf, f, b"FACP", FADT_LEN as u32, 6, b"FADT    ");
    // FIRMWARE_CTRL only: X_FIRMWARE_CTRL is for a FACS above 4 GiB, and
    // OSPM would ignore this field were both set.
    put_u32(&mut buf, f + 36, gpa(FACS_OFFSET) as u32);
    put_u32(&mut buf, f + 40, gpa(DSDT_OFFSET) as u32);
    put_u16(&mut buf, f + 46, SCI_IRQ);
    // SMI_CMD (48) stays 0: no SMM, so the machine is always in ACPI mode.
    put_u32(&mut buf, f + 56, u32::from(PM1A_EVT_PORT));
    put_u32(&mut buf, f + 64, u32::from(PM1A_CNT_PORT));
    buf[f + 88] = PM1_EVT_LEN;
    buf[f + 89] = PM1_CNT_LEN;
    put_u16(&mut buf, f + 96, NO_C2_LATENCY);
    put_u16(&mut buf, f + 98, NO_C3_LATENCY);
    buf[f + 108] = CMOS_CENTURY;
    put_u16(&mut buf, f + 109, BOOT_ARCH_LEGACY_DEVICES);
    put_u32(&mut buf, f + 112, FADT_FLAGS);
    put_io_gas(&mut buf, f + 116, RESET_PORT, 8, GAS_ACCESS_BYTE);
    buf[f + 128] = RESET_VALUE;
    put_u64(&mut buf, f + 140, gpa(DSDT_OFFSET)); // X_DSDT
    put_io_gas(&mut buf, f + 148, PM1A_EVT_PORT, PM1_EVT_LEN * 8, 0);
    put_io_gas(&mut buf, f + 172, PM1A_CNT_PORT, PM1_CNT_LEN * 8, 0);
    seal(&mut buf, f, FADT_LEN);

    // ---- XSDT ----
    fill_header(
        &mut buf,
        XSDT_OFFSET,
        b"XSDT",
        XSDT_LEN as u32,
        1,
        b"XSDT    ",
    );
    put_u64(&mut buf, XSDT_OFFSET + 36, gpa(FADT_OFFSET));
    put_u64(&mut buf, XSDT_OFFSET + 44, gpa(MADT_OFFSET));
    seal(&mut buf, XSDT_OFFSET, XSDT_LEN);

    // ---- RSDP (ACPI 2.0+) ----
    buf[RSDP_OFFSET..RSDP_OFFSET + 8].copy_from_slice(b"RSD PTR ");
    buf[RSDP_OFFSET + 9..RSDP_OFFSET + 15].copy_from_slice(b"TINYVM"); // oem_id
    buf[RSDP_OFFSET + 15] = 2; // revision (ACPI 2.0+)
    put_u32(&mut buf, RSDP_OFFSET + 16, 0); // rsdt_address
    put_u32(&mut buf, RSDP_OFFSET + 20, 36); // length
    put_u64(&mut buf, RSDP_OFFSET + 24, gpa(XSDT_OFFSET));
    // ACPI 1.0 checksum: first 20 bytes sum to zero.
    buf[RSDP_OFFSET + 8] = checksum(&buf[RSDP_OFFSET..RSDP_OFFSET + 20]);
    // ACPI 2.0+ extended checksum: full 36-byte struct sums to zero.
    buf[RSDP_OFFSET + 32] = checksum(&buf[RSDP_OFFSET..RSDP_OFFSET + 36]);

    buf
}

/// The DSDT's definition block:
///
/// ```text
/// Name (_S5, Package () { 5, 5, 0, 0 })
/// Scope (\_SB) {
///     Device (PCI0) {
///         Name (_HID, EisaId ("PNP0A03"))
///         Name (_UID, 0)
///         Name (_CRS, ResourceTemplate () { bus 0, ports 0xCF8-0xCFF,
///             I/O windows around them, the 32-bit BAR window })
///     }
///     Device (VMBS) {                 // with `vmbus`
///         Name (_HID, "VMBus")
///         Name (_UID, 0)
///         Name (_CRS, ResourceTemplate () {})
///     }
/// }
/// ```
///
/// No `_PRT`: every PCI function here interrupts through MSI-X, with no
/// interrupt pin. VMBus needs no resources: Linux's driver walks `_CRS` but
/// takes its interrupt from the SynIC, and offers no device MMIO.
fn dsdt_aml(vmbus: bool) -> Vec<u8> {
    let s5 = u64::from(SLP_TYP_S5);
    let pci0 = [
        b"PCI0".to_vec(),
        aml::name(b"_HID", &aml::integer(PNP0A03)),
        aml::name(b"_UID", &aml::integer(0)),
        aml::name(b"_CRS", &aml::buffer(&pci_root_resources())),
    ]
    .concat();
    let mut sb = [b"\\_SB_".to_vec(), aml::device(&pci0)].concat();
    if vmbus {
        let vmbs = [
            b"VMBS".to_vec(),
            aml::name(b"_HID", &aml::string(b"VMBus")),
            aml::name(b"_UID", &aml::integer(0)),
            aml::name(b"_CRS", &aml::buffer(&aml::END_TAG)),
        ]
        .concat();
        sb.extend(aml::device(&vmbs));
    }
    [
        aml::name(b"_S5_", &aml::package(&[s5, s5, 0, 0])),
        aml::scope(&sb),
    ]
    .concat()
}

/// `EisaId ("PNP0A03")`, a PCI host bridge.
const PNP0A03: u64 = 0x030A_D041;

/// The host bridge's resources: what it decodes (bus 0, the config ports) and
/// the windows it forwards to the bus. `pci=nocrs`, a default argument, makes
/// Linux ignore the windows; without it they have to cover every BAR.
fn pci_root_resources() -> Vec<u8> {
    let window_end = u32::try_from(MMIO_WINDOW_END - 1).unwrap();
    [
        aml::word_address(aml::RESOURCE_BUS, 0, 0, 0),
        aml::io(0x0CF8, 8),
        aml::word_address(aml::RESOURCE_IO, aml::IO_ENTIRE_RANGE, 0x0000, 0x0CF7),
        aml::word_address(aml::RESOURCE_IO, aml::IO_ENTIRE_RANGE, 0x0D00, 0xFFFF),
        aml::dword_memory(MMIO_WINDOW_BASE as u32, window_end),
        aml::END_TAG.to_vec(),
    ]
    .concat()
}

/// Just enough AML (ACPI 6.5 chapter 20) and resource-descriptor encoding
/// (chapter 6.4) for the DSDT.
mod aml {
    const NAME_OP: u8 = 0x08;
    const STRING_PREFIX: u8 = 0x0D;
    const SCOPE_OP: u8 = 0x10;
    const BUFFER_OP: u8 = 0x11;
    const PACKAGE_OP: u8 = 0x12;
    const DEVICE_OP: [u8; 2] = [0x5B, 0x82];

    pub const RESOURCE_IO: u8 = 1;
    pub const RESOURCE_BUS: u8 = 2;
    /// I/O range flag: the window passes both ISA and non-ISA addresses.
    pub const IO_ENTIRE_RANGE: u8 = 3;
    /// End tag, with a zero checksum ("treat as summing to zero").
    pub const END_TAG: [u8; 2] = [0x79, 0x00];

    /// PkgLength: the length of what follows plus that of the encoding itself,
    /// in 1 to 4 bytes.
    pub fn pkg_length(body_len: usize) -> Vec<u8> {
        if body_len < 63 {
            return vec![(body_len + 1) as u8];
        }
        let (n, total) = (2..=4)
            .map(|n| (n, body_len + n))
            .find(|&(n, total)| total < 1 << (4 + 8 * (n - 1)))
            .expect("AML object too large");
        let mut out = vec![(((n - 1) << 6) | (total & 0xF)) as u8];
        out.extend((0..n - 1).map(|i| (total >> (4 + 8 * i)) as u8));
        out
    }

    fn with_pkg_length(op: &[u8], body: &[u8]) -> Vec<u8> {
        [op, &pkg_length(body.len()), body].concat()
    }

    pub fn integer(v: u64) -> Vec<u8> {
        match v {
            0 | 1 => vec![v as u8], // ZeroOp, OneOp
            2..=0xFF => vec![0x0A, v as u8],
            0x100..=0xFFFF => [&[0x0B][..], &(v as u16).to_le_bytes()].concat(),
            0x1_0000..=0xFFFF_FFFF => [&[0x0C][..], &(v as u32).to_le_bytes()].concat(),
            _ => [&[0x0E][..], &v.to_le_bytes()].concat(),
        }
    }

    pub fn name(seg: &[u8; 4], value: &[u8]) -> Vec<u8> {
        [&[NAME_OP][..], seg, value].concat()
    }

    /// A string constant: `StringPrefix`, the ASCII bytes, a NUL.
    pub fn string(s: &[u8]) -> Vec<u8> {
        [&[STRING_PREFIX][..], s, &[0]].concat()
    }

    pub fn package(elements: &[u64]) -> Vec<u8> {
        let mut body = vec![elements.len() as u8];
        for &e in elements {
            body.extend(integer(e));
        }
        with_pkg_length(&[PACKAGE_OP], &body)
    }

    pub fn buffer(bytes: &[u8]) -> Vec<u8> {
        with_pkg_length(
            &[BUFFER_OP],
            &[integer(bytes.len() as u64), bytes.to_vec()].concat(),
        )
    }

    /// `Scope`; `body` starts with the name string.
    pub fn scope(body: &[u8]) -> Vec<u8> {
        with_pkg_length(&[SCOPE_OP], body)
    }

    /// `Device`; `body` starts with the name string.
    pub fn device(body: &[u8]) -> Vec<u8> {
        with_pkg_length(&DEVICE_OP, body)
    }

    /// A fixed, positively decoded range a bridge forwards (Word Address
    /// Space Descriptor).
    pub fn word_address(resource: u8, type_flags: u8, min: u16, max: u16) -> Vec<u8> {
        let mut d = vec![0x88, 13, 0, resource, 0x0C, type_flags];
        for v in [0, min, max, 0, max - min + 1] {
            d.extend(v.to_le_bytes());
        }
        d
    }

    /// A read-write memory range a bridge forwards (DWord Address Space
    /// Descriptor).
    pub fn dword_memory(min: u32, max: u32) -> Vec<u8> {
        let mut d = vec![0x87, 23, 0, 0, 0x0C, 0x01];
        for v in [0, min, max, 0, max - min + 1] {
            d.extend(v.to_le_bytes());
        }
        d
    }

    /// I/O ports a device decodes with 16-bit addresses (I/O Port Descriptor).
    pub fn io(base: u16, len: u8) -> Vec<u8> {
        let [lo, hi] = base.to_le_bytes();
        vec![0x47, 0x01, lo, hi, lo, hi, 0x01, len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x3000;

    fn u32_at(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    fn u64_at(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    /// The table at `gpa`: checks its checksum and returns its bytes.
    fn table(buf: &[u8], gpa: u64, sig: &[u8; 4]) -> Vec<u8> {
        let off = (gpa - BASE) as usize;
        assert_eq!(&buf[off..off + 4], sig);
        let len = u32_at(buf, off + 4) as usize;
        let t = buf[off..off + len].to_vec();
        assert_eq!(checksum(&t), 0, "{} checksum", String::from_utf8_lossy(sig));
        t
    }

    #[test]
    fn tables_link_from_the_rsdp_to_the_power_registers() {
        let buf = build(BASE, 4, false);
        assert_eq!(buf.len(), FOOTPRINT);
        assert_eq!(&buf[..8], b"RSD PTR ");
        assert_eq!(checksum(&buf[..20]), 0);
        assert_eq!(checksum(&buf[..36]), 0);

        let xsdt = table(&buf, u64_at(&buf, 24), b"XSDT");
        let fadt = table(&buf, u64_at(&xsdt, 36), b"FACP");
        let madt = table(&buf, u64_at(&xsdt, 44), b"APIC");
        assert_eq!(xsdt.len(), 52);
        assert_eq!(madt.len(), 44 + 4 * 16);

        let facs = u64::from(u32_at(&fadt, 36));
        assert_eq!(facs % 64, 0);
        assert_eq!(&buf[(facs - BASE) as usize..][..4], b"FACS");
        let dsdt = u64_at(&fadt, 140);
        assert_eq!(u64::from(u32_at(&fadt, 40)), dsdt);
        let dsdt = table(&buf, dsdt, b"DSDT");
        assert_eq!(dsdt[8], 2, "DSDT revision 2: 64-bit integers");

        // PM1a_EVT/CNT and RESET_REG point at devices::power, in the legacy
        // fields and the GAS ones alike.
        assert_eq!(u32_at(&fadt, 56), u32::from(PM1A_EVT_PORT));
        assert_eq!(u32_at(&fadt, 64), u32::from(PM1A_CNT_PORT));
        assert_eq!((fadt[88], fadt[89]), (4, 2));
        assert_eq!(&fadt[148..152], &[GAS_SYSTEM_IO, 32, 0, 0]);
        assert_eq!(u64_at(&fadt, 152), u64::from(PM1A_EVT_PORT));
        assert_eq!(&fadt[172..176], &[GAS_SYSTEM_IO, 16, 0, 0]);
        assert_eq!(u64_at(&fadt, 176), u64::from(PM1A_CNT_PORT));
        assert_eq!(&fadt[116..120], &[GAS_SYSTEM_IO, 8, 0, GAS_ACCESS_BYTE]);
        assert_eq!(u64_at(&fadt, 120), u64::from(RESET_PORT));
        assert_eq!(fadt[128], RESET_VALUE);
        assert_eq!(u32_at(&fadt, 112) & (1 << 20), 0, "not hardware-reduced");
        assert_eq!(u32_at(&fadt, 76), 0, "no PM timer");
    }

    #[test]
    fn pkg_length_counts_itself_and_grows_at_the_boundaries() {
        assert_eq!(aml::pkg_length(0), [0x01]);
        assert_eq!(aml::pkg_length(62), [0x3F]);
        // 63 + 1 no longer fits six bits; 63 + 2 = 0x41 takes two bytes.
        assert_eq!(aml::pkg_length(63), [0x41, 0x04]);
        assert_eq!(aml::pkg_length(0xFFD), [0x4F, 0xFF]);
        assert_eq!(aml::pkg_length(0xFFE), [0x81, 0x00, 0x01]);
        assert_eq!(aml::pkg_length(0xFFFFC), [0x8F, 0xFF, 0xFF]);
        assert_eq!(aml::pkg_length(0xFFFFD), [0xC1, 0x00, 0x00, 0x01]);
    }

    /// Reads a PkgLength at `aml[at..]`: (value, bytes it took).
    fn read_pkg_length(aml: &[u8], at: usize) -> (usize, usize) {
        let n = 1 + usize::from(aml[at] >> 6);
        if n == 1 {
            return (usize::from(aml[at] & 0x3F), 1);
        }
        let v = (1..n).fold(usize::from(aml[at] & 0xF), |v, i| {
            v | (usize::from(aml[at + i]) << (4 + 8 * (i - 1)))
        });
        (v, n)
    }

    #[test]
    fn dsdt_declares_s5_and_the_pci_host_bridge() {
        let aml = dsdt_aml(false);
        // The same bytes iasl emits for these declarations.
        let s5 = [
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x08, 0x04, 0x0A, 0x05, 0x0A, 0x05, 0, 0,
        ];
        assert_eq!(aml[..14], s5);
        let hid = [0x08, b'_', b'H', b'I', b'D', 0x0C, 0x41, 0xD0, 0x0A, 0x03];
        assert!(aml.windows(hid.len()).any(|w| w == hid));

        // Scope (\_SB) runs to the end of the block, and Device (PCI0) to the
        // end of the scope.
        let scope = 14;
        assert_eq!(aml[scope], 0x10);
        let (len, n) = read_pkg_length(&aml, scope + 1);
        assert_eq!(scope + 1 + len, aml.len());
        assert_eq!(&aml[scope + 1 + n..][..5], b"\\_SB_");
        let device = scope + 1 + n + 5;
        assert_eq!(aml[device..device + 2], [0x5B, 0x82]);
        let (len, n) = read_pkg_length(&aml, device + 2);
        assert_eq!(device + 2 + len, aml.len());
        assert_eq!(&aml[device + 2 + n..][..4], b"PCI0");

        // _CRS is the last object: a buffer whose descriptors end in the end
        // tag, and whose window covers the BARs.
        let crs = aml.windows(5).position(|w| w == b"\x08_CRS").unwrap() + 5;
        assert_eq!(aml[crs], 0x11);
        let (len, n) = read_pkg_length(&aml, crs + 1);
        assert_eq!(crs + 1 + len, aml.len());
        let (size_at, size) = (crs + 1 + n, usize::from(aml[crs + 2 + n]));
        assert_eq!(aml[size_at], 0x0A);
        let resources = &aml[size_at + 2..];
        assert_eq!(resources.len(), size);
        let mut at = 0;
        let mut window = None;
        while resources[at] != 0x79 {
            let (tag, len) = if resources[at] & 0x80 != 0 {
                let len = usize::from(u16::from_le_bytes([resources[at + 1], resources[at + 2]]));
                (resources[at], 3 + len)
            } else {
                (resources[at] >> 3, 1 + usize::from(resources[at] & 7))
            };
            if tag == 0x87 {
                window = Some((u32_at(resources, at + 10), u32_at(resources, at + 14)));
            }
            at += len;
        }
        assert_eq!(at + 2, resources.len());
        assert_eq!(window, Some((0xE000_0000, 0xFEBF_FFFF)));
    }

    #[test]
    fn dsdt_declares_vmbus_after_pci0_when_asked() {
        let without = dsdt_aml(false);
        let aml = dsdt_aml(true);
        assert!(!without.windows(4).any(|w| w == b"VMBS"));
        // The same bytes iasl emits for Device (VMBS) { Name (_HID, "VMBus")
        // Name (_UID, 0) Name (_CRS, ResourceTemplate () {}) }.
        let vmbs = [
            &[0x5B, 0x82, 0x22][..],
            b"VMBS",
            &[0x08],
            b"_HID",
            &[0x0D],
            b"VMBus\0",
            &[0x08],
            b"_UID",
            &[0x00, 0x08],
            b"_CRS",
            &[0x11, 0x05, 0x0A, 0x02, 0x79, 0x00],
        ]
        .concat();
        assert!(aml.ends_with(&vmbs), "the last thing in \\_SB");
        // \_SB grew by the device; its PkgLength covers it.
        let (len, n) = read_pkg_length(&aml, 15);
        assert_eq!(15 + len, aml.len());
        assert_eq!(&aml[15 + n..][..5], b"\\_SB_");
        assert_eq!(
            &aml[..aml.len() - vmbs.len()][14 + 1 + n..],
            &without[14 + 1 + n..]
        );
        assert!(build(BASE, 2, true).windows(4).any(|w| w == b"VMBS"));
    }
}
