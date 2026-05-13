#include "acpi_tables.h"

#include <cstring>

namespace tinyvmm::boot::acpi {

namespace {

#pragma pack(push, 1)

struct Rsdp {
    char          signature[8];   // "RSD PTR "
    std::uint8_t  checksum;       // sum of first 20 bytes == 0
    char          oem_id[6];
    std::uint8_t  revision;       // 2 = ACPI 2.0+
    std::uint32_t rsdt_address;   // 0; we use XSDT
    std::uint32_t length;         // sizeof(Rsdp)
    std::uint64_t xsdt_address;
    std::uint8_t  extended_checksum;  // sum of full struct == 0
    std::uint8_t  reserved[3];
};
static_assert(sizeof(Rsdp) == 36, "RSDP must be 36 bytes");

struct AcpiTableHeader {
    char          signature[4];
    std::uint32_t length;
    std::uint8_t  revision;
    std::uint8_t  checksum;
    char          oem_id[6];
    char          oem_table_id[8];
    std::uint32_t oem_revision;
    char          asl_compiler_id[4];
    std::uint32_t asl_compiler_revision;
};
static_assert(sizeof(AcpiTableHeader) == 36, "ACPI header must be 36 bytes");

struct Xsdt {
    AcpiTableHeader header;
    std::uint64_t   entry[1];   // points at MADT
};
static_assert(sizeof(Xsdt) == 44, "XSDT (1 entry) must be 44 bytes");

struct MadtFixed {
    AcpiTableHeader header;
    std::uint32_t   local_apic_address;  // 0xFEE00000
    std::uint32_t   flags;               // bit 0 = PCAT_COMPAT
};
static_assert(sizeof(MadtFixed) == 44, "MADT fixed part must be 44 bytes");

struct MadtLocalApic {
    std::uint8_t  type;       // 0
    std::uint8_t  length;     // 8
    std::uint8_t  acpi_processor_uid;
    std::uint8_t  apic_id;
    std::uint32_t flags;      // 1 = enabled
};
static_assert(sizeof(MadtLocalApic) == 8, "MADT LAPIC entry must be 8 bytes");

struct MadtLocalX2Apic {
    std::uint8_t  type;       // 9
    std::uint8_t  length;     // 16
    std::uint16_t reserved;
    std::uint32_t local_apic_id;
    std::uint32_t flags;      // 1 = enabled
    std::uint32_t acpi_processor_uid;
};
static_assert(sizeof(MadtLocalX2Apic) == 16,
              "MADT x2APIC entry must be 16 bytes");

#pragma pack(pop)

// Two's-complement checksum so the byte sum is zero.
std::uint8_t Checksum(const std::uint8_t* p, std::size_t len) {
    std::uint8_t s = 0;
    for (std::size_t i = 0; i < len; ++i) s = static_cast<std::uint8_t>(s + p[i]);
    return static_cast<std::uint8_t>(0u - s);
}

void FillHeader(AcpiTableHeader& h, const char (&sig)[5],
                std::uint32_t len, std::uint8_t rev,
                const char (&oem_table_id)[9]) {
    std::memcpy(h.signature, sig, 4);
    h.length = len;
    h.revision = rev;
    h.checksum = 0;
    std::memcpy(h.oem_id, "TINYVM", 6);
    std::memcpy(h.oem_table_id, oem_table_id, 8);
    h.oem_revision = 1;
    std::memcpy(h.asl_compiler_id, "TVMM", 4);
    h.asl_compiler_revision = 1;
}

constexpr std::uint64_t kRsdpOffset = 0x00;
constexpr std::uint64_t kXsdtOffset = 0x40;
constexpr std::uint64_t kMadtOffset = 0x80;

}  // namespace

std::uint64_t Build(std::uint8_t* host_base, std::uint64_t gpa_base) {
    // Zero the whole footprint so any padding between structures reads back
    // as zero (Linux skips zero entries cleanly).
    std::memset(host_base, 0, kFootprint);

    // ---- MADT ----
    auto* madt = reinterpret_cast<MadtFixed*>(host_base + kMadtOffset);
    auto* lapic = reinterpret_cast<MadtLocalApic*>(
        host_base + kMadtOffset + sizeof(MadtFixed));
    auto* x2apic = reinterpret_cast<MadtLocalX2Apic*>(
        host_base + kMadtOffset + sizeof(MadtFixed) + sizeof(MadtLocalApic));

    std::uint32_t madt_len = static_cast<std::uint32_t>(
        sizeof(MadtFixed) + sizeof(MadtLocalApic) + sizeof(MadtLocalX2Apic));
    FillHeader(madt->header, "APIC", madt_len, /*rev=*/5, "MADT    ");
    madt->local_apic_address = 0xFEE00000u;
    madt->flags = 1;  // PCAT_COMPAT: we still have an 8259 around (i8259.cpp)

    lapic->type = 0;
    lapic->length = sizeof(MadtLocalApic);
    lapic->acpi_processor_uid = 0;
    lapic->apic_id = 0;
    lapic->flags = 1;  // enabled

    x2apic->type = 9;
    x2apic->length = sizeof(MadtLocalX2Apic);
    x2apic->reserved = 0;
    x2apic->local_apic_id = 0;
    x2apic->flags = 1;  // enabled
    x2apic->acpi_processor_uid = 0;

    madt->header.checksum = Checksum(reinterpret_cast<std::uint8_t*>(madt),
                                     madt_len);

    // ---- XSDT (one entry -> MADT) ----
    auto* xsdt = reinterpret_cast<Xsdt*>(host_base + kXsdtOffset);
    FillHeader(xsdt->header, "XSDT", sizeof(Xsdt), /*rev=*/1, "XSDT    ");
    xsdt->entry[0] = gpa_base + kMadtOffset;
    xsdt->header.checksum = Checksum(reinterpret_cast<std::uint8_t*>(xsdt),
                                     sizeof(Xsdt));

    // ---- RSDP (ACPI 2.0+) ----
    auto* rsdp = reinterpret_cast<Rsdp*>(host_base + kRsdpOffset);
    std::memcpy(rsdp->signature, "RSD PTR ", 8);
    std::memcpy(rsdp->oem_id, "TINYVM", 6);
    rsdp->revision = 2;
    rsdp->rsdt_address = 0;
    rsdp->length = sizeof(Rsdp);
    rsdp->xsdt_address = gpa_base + kXsdtOffset;
    // ACPI 1.0 checksum: first 20 bytes sum to zero.
    rsdp->checksum = 0;
    rsdp->checksum = Checksum(reinterpret_cast<std::uint8_t*>(rsdp), 20);
    // ACPI 2.0+ extended checksum: full struct sums to zero.
    rsdp->extended_checksum = 0;
    rsdp->extended_checksum = Checksum(reinterpret_cast<std::uint8_t*>(rsdp),
                                       sizeof(Rsdp));

    return gpa_base + kRsdpOffset;
}

}  // namespace tinyvmm::boot::acpi
