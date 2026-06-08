//! Minimal ACPI tables (RSDP + XSDT + MADT) built on the host for the PVH
//! guest. Giving Linux a MADT lets it skip "virtual wire mode" and register
//! the LAPIC clock-event device (without which hrtimers never fire). Port of
//! boot/acpi_tables.cpp.

pub const MAX_VCPUS: u32 = 32;
pub const FOOTPRINT: usize = 1024;

const RSDP_OFFSET: usize = 0x00;
const XSDT_OFFSET: usize = 0x40;
const MADT_OFFSET: usize = 0x80;

fn checksum(bytes: &[u8]) -> u8 {
    let mut s: u8 = 0;
    for &b in bytes {
        s = s.wrapping_add(b);
    }
    0u8.wrapping_sub(s)
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
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

/// Build RSDP / XSDT / MADT into a `FOOTPRINT`-byte buffer where the guest
/// physical address of byte 0 equals `gpa_base`. Returns the buffer and the
/// offset of the RSDP (always 0).
pub fn build(gpa_base: u64, vcpu_count: u32) -> Vec<u8> {
    let vcpu_count = vcpu_count.clamp(1, MAX_VCPUS);
    let mut buf = vec![0u8; FOOTPRINT];

    // ---- MADT ----
    let madt_len = 44 + vcpu_count * 16;
    fill_header(&mut buf, MADT_OFFSET, b"APIC", madt_len, 5, b"MADT    ");
    put_u32(&mut buf, MADT_OFFSET + 36, 0xFEE0_0000); // local_apic_address
    put_u32(&mut buf, MADT_OFFSET + 40, 1); // flags: PCAT_COMPAT
    for i in 0..vcpu_count {
        let e = MADT_OFFSET + 44 + (i as usize) * 16;
        buf[e] = 9; // type: Local x2APIC
        buf[e + 1] = 16; // length
        // reserved u16 @ +2 stays 0
        put_u32(&mut buf, e + 4, i); // local_apic_id
        put_u32(&mut buf, e + 8, 1); // flags: enabled
        put_u32(&mut buf, e + 12, i); // acpi_processor_uid
    }
    let madt_sum = checksum(&buf[MADT_OFFSET..MADT_OFFSET + madt_len as usize]);
    buf[MADT_OFFSET + 9] = madt_sum;

    // ---- XSDT (one entry -> MADT) ----
    fill_header(&mut buf, XSDT_OFFSET, b"XSDT", 44, 1, b"XSDT    ");
    put_u64(&mut buf, XSDT_OFFSET + 36, gpa_base + MADT_OFFSET as u64);
    let xsdt_sum = checksum(&buf[XSDT_OFFSET..XSDT_OFFSET + 44]);
    buf[XSDT_OFFSET + 9] = xsdt_sum;

    // ---- RSDP (ACPI 2.0+) ----
    buf[RSDP_OFFSET..RSDP_OFFSET + 8].copy_from_slice(b"RSD PTR ");
    buf[RSDP_OFFSET + 9..RSDP_OFFSET + 15].copy_from_slice(b"TINYVM"); // oem_id
    buf[RSDP_OFFSET + 15] = 2; // revision (ACPI 2.0+)
    put_u32(&mut buf, RSDP_OFFSET + 16, 0); // rsdt_address
    put_u32(&mut buf, RSDP_OFFSET + 20, 36); // length
    put_u64(&mut buf, RSDP_OFFSET + 24, gpa_base + XSDT_OFFSET as u64);
    // ACPI 1.0 checksum: first 20 bytes sum to zero.
    buf[RSDP_OFFSET + 8] = checksum(&buf[RSDP_OFFSET..RSDP_OFFSET + 20]);
    // ACPI 2.0+ extended checksum: full 36-byte struct sums to zero.
    buf[RSDP_OFFSET + 32] = checksum(&buf[RSDP_OFFSET..RSDP_OFFSET + 36]);

    buf
}
