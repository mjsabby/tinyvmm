#pragma once

// Minimal ACPI tables built on the host for the PVH guest.
//
// Layout (returned by Build()):
//
//   gpa_base + 0x00    RSDP  (36 bytes, ACPI 2.0+)
//   gpa_base + 0x40    XSDT  (header + one 64-bit entry -> MADT)
//   gpa_base + 0x80    MADT  (header + Local APIC fields + LAPIC entry +
//                              x2APIC entry)
//
// Total footprint < 256 B. We do *not* provide FADT / DSDT / SSDT / HPET /
// MCFG — the Linux PVH boot path doesn't require any of those, and Linux on
// x86_64 will boot happily with just RSDP -> XSDT -> MADT for a 1-CPU box.
//
// The point of providing this at all is to give Linux a MADT so it skips
// "virtual wire mode" and properly registers the LAPIC clock event device.
// Without that, hrtimers never fire (nanosleep / sleep hang forever).

#include <cstddef>
#include <cstdint>

namespace tinyvmm::boot::acpi {

// Build RSDP / XSDT / MADT into the host pointer at host_base, with the
// guest physical address of host_base equal to gpa_base. The output area
// must be at least 256 bytes.
//
// Returns the guest physical address of the RSDP (for hvm_start_info
// .rsdp_paddr).
std::uint64_t Build(std::uint8_t* host_base, std::uint64_t gpa_base);

// Total bytes Build() will write. Useful for e820 reservation.
constexpr std::size_t kFootprint = 256;

}  // namespace tinyvmm::boot::acpi
