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

// Maximum supported vCPU count surfaced through MADT. Sized so the per-CPU
// x2APIC entries fit comfortably inside `kFootprint` (see below). Also serves
// as the upper bound for the `--vcpus` CLI flag.
constexpr std::uint32_t kMaxVcpus = 32;

// Build RSDP / XSDT / MADT into the host pointer at host_base, with the
// guest physical address of host_base equal to gpa_base. The output area
// must be at least `kFootprint` bytes.
//
// `vcpu_count` controls how many MADT processor entries are emitted (one
// Type 9 x2APIC entry per logical CPU, apic_id == processor_uid == index).
// Must be in [1, kMaxVcpus]. The BSP is always index 0; APs are 1..N-1.
//
// Returns the guest physical address of the RSDP (for hvm_start_info
// .rsdp_paddr).
std::uint64_t Build(std::uint8_t* host_base, std::uint64_t gpa_base,
                    std::uint32_t vcpu_count = 1);

// Total bytes Build() will write. Useful for e820 reservation.
//   RSDP (offset 0x000): 36 bytes
//   XSDT (offset 0x040): 44 bytes
//   MADT (offset 0x080): 44 (fixed) + kMaxVcpus*16 (one x2APIC entry each)
//                       = 44 + 512 = 556 bytes for kMaxVcpus=32.
// We round up to 1 KiB so future expansion (FADT/HPET/MCFG) has headroom
// without disturbing the e820 reservation.
constexpr std::size_t kFootprint = 1024;

}  // namespace tinyvmm::boot::acpi
