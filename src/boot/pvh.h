#pragma once

// PVH boot protocol structures. Reproduced from xen/include/public/arch-x86/
// hvm/start_info.h and elfnote.h. We don't link against Xen; these are fixed
// ABI pieces that Linux (CONFIG_PVH=y) uses to come up.

#include <cstdint>

namespace tinyvmm::boot::pvh {

// XEN_ELFNOTE_PHYS32_ENTRY: name="Xen" (4 bytes incl. NUL), descsz=4,
// desc = uint32 entry-point physical address. Always 32-bit PM, no paging.
constexpr std::uint32_t kElfNotePhys32Entry = 18;
constexpr char kXenNoteName[4] = {'X', 'e', 'n', 0};

// hvm_start_info.magic. The Xen spec defines this as the literal value
// 0x336ec578 (not "xEn3" as one might guess from the byte pattern). See
// xen/include/public/arch-x86/hvm/start_info.h. Linux's PVH entry path
// `cmp [hvm_start_info_ptr], $0x336ec578` will BUG() on any other value.
constexpr std::uint32_t kHvmStartMagic = 0x336ec578u;
constexpr std::uint32_t kHvmStartVersion = 1;

// hvm_memmap_table_entry.type
constexpr std::uint32_t kE820Ram = 1;
constexpr std::uint32_t kE820Reserved = 2;
constexpr std::uint32_t kE820Acpi = 3;
constexpr std::uint32_t kE820Nvs = 4;

#pragma pack(push, 1)

struct HvmStartInfo {
    std::uint32_t magic;            // "xEn3"
    std::uint32_t version;          // 0 or 1
    std::uint32_t flags;
    std::uint32_t nr_modules;
    std::uint64_t modlist_paddr;
    std::uint64_t cmdline_paddr;
    std::uint64_t rsdp_paddr;
    std::uint64_t memmap_paddr;
    std::uint32_t memmap_entries;
    std::uint32_t reserved;
};
static_assert(sizeof(HvmStartInfo) == 56);

struct HvmMemmapTableEntry {
    std::uint64_t addr;
    std::uint64_t size;
    std::uint32_t type;
    std::uint32_t reserved;
};
static_assert(sizeof(HvmMemmapTableEntry) == 24);

struct HvmModlistEntry {
    std::uint64_t paddr;
    std::uint64_t size;
    std::uint64_t cmdline_paddr;
    std::uint64_t reserved;
};
static_assert(sizeof(HvmModlistEntry) == 32);

#pragma pack(pop)

}  // namespace tinyvmm::boot::pvh
