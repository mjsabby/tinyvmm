#pragma once

#include "common.h"
#include "whp/memory.h"
#include "whp/vcpu.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tinyvmm::boot {

// One PT_LOAD segment from the kernel ELF, recorded for later loading and for
// diagnostics. Sizes are post-clamp (clamped to file size for filesz; memsz
// is the BSS-extended size).
struct LoadSegment {
    std::uint64_t paddr;
    std::uint64_t filesz;
    std::uint64_t memsz;
    std::uint64_t file_offset;
    std::uint32_t flags;  // ELF p_flags (PF_R/W/X)
};

struct PvhInfo {
    std::filesystem::path path;
    std::uint64_t e_entry = 0;          // ELF entry (informational; PVH uses note)
    std::optional<std::uint32_t> phys32_entry;  // From Xen ELF note 18
    std::vector<LoadSegment> segments;

    std::uint64_t kernel_phys_min = ~0ull;
    std::uint64_t kernel_phys_max = 0;

    // True if we found everything required to actually boot via PVH.
    bool BootCapable() const noexcept {
        return phys32_entry.has_value() && !segments.empty();
    }
};

struct PvhLoadConfig {
    std::string cmdline;       // appended NUL-terminated to guest mem
    std::uint64_t ram_bytes;   // total guest RAM size (from GuestMemory)
    std::optional<std::filesystem::path> initramfs;  // optional initrd path
    std::uint32_t vcpu_count = 1;  // # of vCPUs, propagated into MADT
};

struct PvhLoadResult {
    std::uint32_t entry_point;     // 32-bit physical entry
    std::uint64_t start_info_gpa;  // EBX value at entry
    std::uint64_t gdt_gpa;         // where SetupPvhEntry should program GDTR
    std::uint64_t bytes_loaded;
    std::uint64_t initramfs_gpa = 0;
    std::uint64_t initramfs_size = 0;
};

// ---- Read-only inspection ----

// Parse the ELF and report what we found. Throws on malformed ELF; returns
// `phys32_entry == nullopt` if the binary is fine but lacks the PVH note.
PvhInfo InspectPvh(const std::filesystem::path& vmlinux);

// Pretty-print to a FILE* (typically stdout). Useful for `--pvh-info`.
void PrintPvhInfo(const PvhInfo& info, std::FILE* out);

// ---- Load + setup ----

// Parse the ELF, copy PT_LOAD segments into `ram` at their physical addresses,
// stage hvm_start_info + memmap + cmdline in low memory, build a 32-bit PM
// GDT in low memory. Throws on any failure (bad ELF, segment outside RAM,
// missing PVH note).
PvhLoadResult LoadPvh(whp::GuestMemory& ram,
                      const std::filesystem::path& vmlinux,
                      const PvhLoadConfig& cfg);

// Configure `vp` for 32-bit PVH entry: GDTR -> our GDT, CR0.PE=1, CS/DS/ES/SS
// flat-32, EBX = start_info_gpa, RIP = entry_point. Caller is responsible for
// having a `RunLoop` ready before this returns (we don't actually call Run
// here).
void SetupPvhEntry(whp::Vcpu& vp, const PvhLoadResult& res);

}  // namespace tinyvmm::boot
