#include "pvh_loader.h"

#include "acpi_tables.h"
#include "elf.h"
#include "pvh.h"

#include <Windows.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace tinyvmm::boot {

namespace {

// Where we stash boot info in low guest memory. These are below the 1 MiB BIOS
// area but above page 0; well clear of any vmlinux PT_LOAD which lives at
// >=16 MiB.
//
//   0x0000 .. 0x0FFF   page zero (kept reserved)
//   0x1000             GDT (16 bytes -> null + 32-bit code + 32-bit data)
//   0x2000             hvm_start_info
//   0x2100             hvm_memmap_table[]   (room for 16 entries, 24 B each)
//   0x2400             hvm_modlist[]        (unused for now)
//   0x2800             cmdline string       (up to ~2 KiB)
//   0x3000             ACPI RSDP / XSDT / MADT (256 B reserved)
//
// All within the first 16 KiB of guest RAM so PVH's restriction "structures
// must be below 4 GiB" is trivially satisfied.
constexpr std::uint64_t kGdtGpa        = 0x1000;
constexpr std::uint64_t kStartInfoGpa  = 0x2000;
constexpr std::uint64_t kMemmapGpa     = 0x2100;
constexpr std::uint64_t kModlistGpa    = 0x2400;
constexpr std::uint64_t kCmdlineGpa    = 0x2800;
constexpr std::size_t   kCmdlineMax    = 0x800;
constexpr std::uint64_t kAcpiGpa       = 0x3000;

// Map an entire file into a vector. Sufficient for vmlinux-sized binaries
// (~tens of MB).
std::vector<std::uint8_t> ReadAllBytes(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        char buf[256];
        std::snprintf(buf, sizeof(buf), "failed to open %s",
                      p.string().c_str());
        throw HrError(E_FAIL, buf);
    }
    f.seekg(0, std::ios::end);
    auto sz = f.tellg();
    if (sz < 0) {
        throw HrError(E_FAIL, "failed to size input file");
    }
    f.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(sz));
    if (sz > 0) {
        f.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(sz));
        if (f.gcount() != static_cast<std::streamsize>(sz)) {
            throw HrError(E_FAIL, "short read on input file");
        }
    }
    return bytes;
}

void ValidateEhdr(const elf::Ehdr64& eh) {
    if (eh.e_ident[0] != elf::kElfMag0 || eh.e_ident[1] != elf::kElfMag1 ||
        eh.e_ident[2] != elf::kElfMag2 || eh.e_ident[3] != elf::kElfMag3) {
        throw HrError(E_FAIL, "not an ELF file");
    }
    if (eh.e_ident[4] != elf::kElfClass64) {
        throw HrError(E_FAIL, "ELF is not 64-bit");
    }
    if (eh.e_ident[5] != elf::kElfData2Lsb) {
        throw HrError(E_FAIL, "ELF is not little-endian");
    }
    if (eh.e_machine != elf::kEmX8664) {
        throw HrError(E_FAIL, "ELF e_machine != EM_X86_64");
    }
    if (eh.e_phoff == 0 || eh.e_phnum == 0 ||
        eh.e_phentsize != sizeof(elf::Phdr64)) {
        throw HrError(E_FAIL, "ELF has no program headers");
    }
}

// Scan a PT_NOTE segment looking for the Xen PVH PHYS32_ENTRY note. Returns
// the entry value if present.
std::optional<std::uint32_t> FindPvhNoteIn(const std::uint8_t* base,
                                           std::size_t size) {
    std::size_t off = 0;
    while (off + sizeof(elf::Nhdr) <= size) {
        elf::Nhdr nh{};
        std::memcpy(&nh, base + off, sizeof(nh));
        off += sizeof(nh);

        // Notes are 4-byte-aligned in the file image.
        const std::size_t name_pad =
            (nh.n_namesz + 3) & ~static_cast<std::size_t>(3);
        const std::size_t desc_pad =
            (nh.n_descsz + 3) & ~static_cast<std::size_t>(3);
        if (off + name_pad + desc_pad > size) {
            break;  // truncated; bail rather than over-read.
        }

        const std::uint8_t* name = base + off;
        const std::uint8_t* desc = base + off + name_pad;

        if (nh.n_type == pvh::kElfNotePhys32Entry && nh.n_namesz == 4 &&
            std::memcmp(name, pvh::kXenNoteName, 4) == 0 &&
            (nh.n_descsz == 4 || nh.n_descsz == 8)) {
            // Linux's arch/x86/platform/pvh/head_64.S emits this with
            // `_ASM_PTR` which is `.quad` on x86_64 -> an 8-byte desc whose
            // low 32 bits are the actual entry. The Xen spec strictly says 4
            // bytes; accept both.
            std::uint64_t entry64 = 0;
            std::memcpy(&entry64, desc, nh.n_descsz);
            return static_cast<std::uint32_t>(entry64);
        }

        off += name_pad + desc_pad;
    }
    return std::nullopt;
}

PvhInfo InspectPvhFromBytes(std::vector<std::uint8_t>&& bytes,
                            const std::filesystem::path& path) {
    if (bytes.size() < sizeof(elf::Ehdr64)) {
        throw HrError(E_FAIL, "file smaller than ELF header");
    }
    elf::Ehdr64 eh{};
    std::memcpy(&eh, bytes.data(), sizeof(eh));
    ValidateEhdr(eh);

    PvhInfo info;
    info.path = path;
    info.e_entry = eh.e_entry;

    if (eh.e_phoff + static_cast<std::uint64_t>(eh.e_phnum) * sizeof(elf::Phdr64) >
        bytes.size()) {
        throw HrError(E_FAIL, "program headers extend past end of file");
    }

    for (std::uint16_t i = 0; i < eh.e_phnum; ++i) {
        elf::Phdr64 ph{};
        std::memcpy(&ph,
                    bytes.data() + eh.e_phoff +
                        static_cast<std::uint64_t>(i) * sizeof(elf::Phdr64),
                    sizeof(ph));

        if (ph.p_type == elf::kPtNote) {
            if (ph.p_offset + ph.p_filesz > bytes.size()) {
                continue;
            }
            auto e = FindPvhNoteIn(
                bytes.data() + ph.p_offset, ph.p_filesz);
            if (e && !info.phys32_entry) {
                info.phys32_entry = e;
            }
        } else if (ph.p_type == elf::kPtLoad) {
            if (ph.p_filesz == 0 && ph.p_memsz == 0) {
                continue;
            }
            if (ph.p_offset + ph.p_filesz > bytes.size()) {
                throw HrError(E_FAIL, "PT_LOAD extends past end of file");
            }
            LoadSegment seg{
                .paddr = ph.p_paddr,
                .filesz = ph.p_filesz,
                .memsz = ph.p_memsz,
                .file_offset = ph.p_offset,
                .flags = ph.p_flags,
            };
            info.segments.push_back(seg);
            info.kernel_phys_min =
                std::min(info.kernel_phys_min, ph.p_paddr);
            info.kernel_phys_max = std::max(
                info.kernel_phys_max, ph.p_paddr + ph.p_memsz);
        }
    }

    // Some kernels (notably Linux when CONFIG_PVH is enabled but the linker
    // script doesn't emit a PT_NOTE program header) keep the Xen ELF note
    // only as an SHT_NOTE *section*. Walk the section headers as a fallback
    // so we catch those.
    if (!info.phys32_entry && eh.e_shoff != 0 && eh.e_shnum != 0 &&
        eh.e_shentsize == sizeof(elf::Shdr64)) {
        const std::uint64_t sh_total =
            static_cast<std::uint64_t>(eh.e_shnum) * sizeof(elf::Shdr64);
        if (eh.e_shoff + sh_total <= bytes.size()) {
            for (std::uint16_t i = 0; i < eh.e_shnum; ++i) {
                elf::Shdr64 sh{};
                std::memcpy(&sh,
                            bytes.data() + eh.e_shoff +
                                static_cast<std::uint64_t>(i) *
                                    sizeof(elf::Shdr64),
                            sizeof(sh));
                if (sh.sh_type != elf::kShtNote) continue;
                if (sh.sh_offset + sh.sh_size > bytes.size()) continue;
                auto e = FindPvhNoteIn(bytes.data() + sh.sh_offset,
                                       sh.sh_size);
                if (e) {
                    info.phys32_entry = e;
                    break;
                }
            }
        }
    }
    return info;
}

}  // namespace

PvhInfo InspectPvh(const std::filesystem::path& vmlinux) {
    auto bytes = ReadAllBytes(vmlinux);
    return InspectPvhFromBytes(std::move(bytes), vmlinux);
}

void PrintPvhInfo(const PvhInfo& info, std::FILE* out) {
    std::fprintf(out, "[pvh] path=%s\n", info.path.string().c_str());
    std::fprintf(out, "[pvh] e_entry=0x%llx (informational)\n",
                 static_cast<unsigned long long>(info.e_entry));
    if (info.phys32_entry) {
        std::fprintf(out, "[pvh] PVH PHYS32_ENTRY=0x%08x\n",
                     *info.phys32_entry);
    } else {
        std::fprintf(out, "[pvh] PVH PHYS32_ENTRY: NOT FOUND -- not PVH-capable\n");
    }
    std::fprintf(out, "[pvh] PT_LOAD segments: %zu\n", info.segments.size());
    for (std::size_t i = 0; i < info.segments.size(); ++i) {
        const auto& s = info.segments[i];
        char perm[4] = "---";
        if (s.flags & elf::kPfR) perm[0] = 'r';
        if (s.flags & elf::kPfW) perm[1] = 'w';
        if (s.flags & elf::kPfX) perm[2] = 'x';
        std::fprintf(out,
                     "[pvh]   [%zu] paddr=0x%08llx filesz=0x%08llx "
                     "memsz=0x%08llx off=0x%08llx %s\n",
                     i, static_cast<unsigned long long>(s.paddr),
                     static_cast<unsigned long long>(s.filesz),
                     static_cast<unsigned long long>(s.memsz),
                     static_cast<unsigned long long>(s.file_offset), perm);
    }
    if (!info.segments.empty()) {
        std::fprintf(out, "[pvh] kernel paddr range: 0x%llx .. 0x%llx (%.2f MiB)\n",
                     static_cast<unsigned long long>(info.kernel_phys_min),
                     static_cast<unsigned long long>(info.kernel_phys_max),
                     (info.kernel_phys_max - info.kernel_phys_min) / 1048576.0);
    }
}

namespace {

// 32-bit flat-PM GDT. Three 8-byte descriptors:
//   [0] null
//   [1] code: base=0 limit=4G G=1 DB=1 P=1 S=1 Type=0xB (exec/read, accessed)
//   [2] data: base=0 limit=4G G=1 DB=1 P=1 S=1 Type=0x3 (rw, accessed)
//
// 0x00CF9A000000FFFF and 0x00CF92000000FFFF are the canonical encodings.
constexpr std::uint64_t kGdtNull = 0;
constexpr std::uint64_t kGdtCode32 = 0x00CF9A000000FFFFull;
constexpr std::uint64_t kGdtData32 = 0x00CF92000000FFFFull;

constexpr std::uint16_t kGdtCodeSelector = 0x08;  // index 1
constexpr std::uint16_t kGdtDataSelector = 0x10;  // index 2

}  // namespace

PvhLoadResult LoadPvh(whp::GuestMemory& ram,
                      const std::filesystem::path& vmlinux,
                      const PvhLoadConfig& cfg) {
    auto bytes = ReadAllBytes(vmlinux);
    PvhInfo info = InspectPvhFromBytes(std::vector<std::uint8_t>(bytes),
                                       vmlinux);
    if (!info.phys32_entry) {
        throw HrError(
            E_FAIL,
            "PVH note (Xen, type 18) not present in ELF -- rebuild kernel "
            "with CONFIG_PVH=y or use a PVH-capable image");
    }
    if (info.kernel_phys_max > cfg.ram_bytes) {
        throw HrError(
            E_FAIL,
            "kernel PT_LOAD extends past configured guest RAM size");
    }

    // Copy each PT_LOAD into RAM at its p_paddr. Zero-fill the BSS tail
    // (memsz - filesz). WriteAt range-checks against ram bounds.
    PvhLoadResult res{};
    for (const auto& s : info.segments) {
        if (s.filesz > 0) {
            ram.WriteAt(s.paddr, bytes.data() + s.file_offset, s.filesz);
        }
        if (s.memsz > s.filesz) {
            std::vector<std::uint8_t> zeros(s.memsz - s.filesz, 0);
            ram.WriteAt(s.paddr + s.filesz, zeros.data(), zeros.size());
        }
        res.bytes_loaded += s.filesz;
    }

    // ---- Optional initramfs ----
    // Place it right after the kernel image, aligned up to 2 MiB so the
    // kernel won't allocate over its own .bss padding. Linux's PVH path
    // reserves the modlist regions itself based on hvm_modlist entries.
    std::vector<std::uint8_t> initramfs_bytes;
    std::uint64_t initramfs_gpa = 0;
    if (cfg.initramfs) {
        initramfs_bytes = ReadAllBytes(*cfg.initramfs);
        if (initramfs_bytes.empty()) {
            throw HrError(E_FAIL, "initramfs file is empty");
        }
        constexpr std::uint64_t k2MiB = 2ull * 1024ull * 1024ull;
        initramfs_gpa = (info.kernel_phys_max + k2MiB - 1) & ~(k2MiB - 1);
        if (initramfs_gpa < 0x100000ull) initramfs_gpa = 0x100000ull;
        if (initramfs_gpa + initramfs_bytes.size() > cfg.ram_bytes) {
            throw HrError(E_FAIL,
                "initramfs would extend past configured guest RAM");
        }
        ram.WriteAt(initramfs_gpa, initramfs_bytes.data(),
                    initramfs_bytes.size());
        res.initramfs_gpa  = initramfs_gpa;
        res.initramfs_size = initramfs_bytes.size();

        // Stage the single modlist entry that points at the initramfs.
        pvh::HvmModlistEntry mod{};
        mod.paddr         = initramfs_gpa;
        mod.size          = initramfs_bytes.size();
        mod.cmdline_paddr = 0;
        mod.reserved      = 0;
        ram.WriteAt(kModlistGpa, &mod, sizeof(mod));
    }

    // ---- Stage boot-info structures in low memory ----

    // GDT
    {
        std::uint64_t gdt[3] = {kGdtNull, kGdtCode32, kGdtData32};
        ram.WriteAt(kGdtGpa, gdt, sizeof(gdt));
    }

    // cmdline
    {
        std::string cmdline = cfg.cmdline;
        if (cmdline.size() + 1 > kCmdlineMax) {
            throw HrError(E_FAIL, "cmdline too long");
        }
        std::vector<std::uint8_t> buf(cmdline.size() + 1, 0);
        std::memcpy(buf.data(), cmdline.data(), cmdline.size());
        ram.WriteAt(kCmdlineGpa, buf.data(), buf.size());
    }

    // ACPI tables (RSDP + XSDT + MADT). The MADT gives Linux a Local APIC
    // entry, which lets it skip "virtual wire mode" and properly register
    // the LAPIC clock event device for hrtimers (without this, every call
    // to nanosleep/sleep hangs forever).
    std::uint64_t rsdp_gpa = 0;
    {
        auto* host = static_cast<std::uint8_t*>(ram.HostPointer(kAcpiGpa));
        if (host == nullptr) {
            throw HrError(E_FAIL, "ACPI staging area not in guest RAM");
        }
        rsdp_gpa = acpi::Build(host, kAcpiGpa);
    }

    // E820 layout. We must expose enough sub-1MB conventional RAM that the
    // kernel's `reserve_real_mode()` (for AP/wakeup trampolines) and other
    // sub-1MB allocations succeed. Our boot artifacts (GDT, hvm_start_info,
    // memmap, modlist, cmdline) all live below 0x10000, so:
    //
    //   [0          .. 0x10000)   reserved -- our boot artifacts
    //   [0x10000    .. 0xa0000)   RAM      -- 576 KiB conventional, enough
    //                                         for the trampoline and a bit
    //                                         more.
    //   [0xa0000    .. 0x100000)  reserved -- legacy ISA / VGA / EBDA hole
    //   [0x100000   .. ram_bytes) RAM      -- main system RAM
    {
        constexpr std::uint64_t kBootArtifactEnd = 0x10000;   // 64 KiB
        constexpr std::uint64_t kIsaHoleStart   = 0xa0000;   // 640 KiB
        constexpr std::uint64_t kIsaHoleEnd     = 0x100000;  // 1 MiB
        std::vector<pvh::HvmMemmapTableEntry> mm;
        mm.push_back({.addr = 0,
                      .size = kBootArtifactEnd,
                      .type = pvh::kE820Reserved,
                      .reserved = 0});
        mm.push_back({.addr = kBootArtifactEnd,
                      .size = kIsaHoleStart - kBootArtifactEnd,
                      .type = pvh::kE820Ram,
                      .reserved = 0});
        mm.push_back({.addr = kIsaHoleStart,
                      .size = kIsaHoleEnd - kIsaHoleStart,
                      .type = pvh::kE820Reserved,
                      .reserved = 0});
        if (cfg.ram_bytes > kIsaHoleEnd) {
            mm.push_back({.addr = kIsaHoleEnd,
                          .size = cfg.ram_bytes - kIsaHoleEnd,
                          .type = pvh::kE820Ram,
                          .reserved = 0});
        }
        ram.WriteAt(kMemmapGpa, mm.data(),
                    mm.size() * sizeof(pvh::HvmMemmapTableEntry));

        // hvm_start_info
        pvh::HvmStartInfo si{};
        si.magic = pvh::kHvmStartMagic;
        si.version = pvh::kHvmStartVersion;
        si.flags = 0;
        si.nr_modules = cfg.initramfs ? 1u : 0u;
        si.modlist_paddr = kModlistGpa;
        si.cmdline_paddr = kCmdlineGpa;
        si.rsdp_paddr = rsdp_gpa;
        si.memmap_paddr = kMemmapGpa;
        si.memmap_entries = static_cast<std::uint32_t>(mm.size());
        si.reserved = 0;
        ram.WriteAt(kStartInfoGpa, &si, sizeof(si));
    }

    res.entry_point = *info.phys32_entry;
    res.start_info_gpa = kStartInfoGpa;
    res.gdt_gpa = kGdtGpa;
    return res;
}

void SetupPvhEntry(whp::Vcpu& vp, const PvhLoadResult& res) {
    // 32-bit PM segment attributes. Same encoding we use elsewhere.
    constexpr std::uint16_t kCodeAttr32 =
        /*Type*/ 0xB | /*S*/ (1 << 4) | /*P*/ (1 << 7) |
        /*DB*/ (1 << 14) | /*G*/ (1 << 15);
    constexpr std::uint16_t kDataAttr32 =
        /*Type*/ 0x3 | /*S*/ (1 << 4) | /*P*/ (1 << 7) |
        /*DB*/ (1 << 14) | /*G*/ (1 << 15);

    auto code_seg = WHV_X64_SEGMENT_REGISTER{};
    code_seg.Base = 0;
    code_seg.Limit = 0xFFFFFFFFu;
    code_seg.Selector = kGdtCodeSelector;
    code_seg.Attributes = kCodeAttr32;

    auto data_seg = WHV_X64_SEGMENT_REGISTER{};
    data_seg.Base = 0;
    data_seg.Limit = 0xFFFFFFFFu;
    data_seg.Selector = kGdtDataSelector;
    data_seg.Attributes = kDataAttr32;

    auto gdtr = WHV_X64_TABLE_REGISTER{};
    gdtr.Base = res.gdt_gpa;
    gdtr.Limit = 23;  // 3 entries * 8 bytes - 1

    // CR0: PE only. NW=0 CD=0 PG=0 (no paging in 32-bit PM as PVH spec
    // requires). ET=1 for sanity. Bit 4 (ET) is reserved-reads-as-1 on modern
    // CPUs; leave it.
    constexpr std::uint64_t kCr0Pe = 1ull << 0;
    constexpr std::uint64_t kCr0Et = 1ull << 4;

    const std::array<WHV_REGISTER_NAME, 13> names = {
        WHvX64RegisterCs,    WHvX64RegisterDs,    WHvX64RegisterEs,
        WHvX64RegisterSs,    WHvX64RegisterFs,    WHvX64RegisterGs,
        WHvX64RegisterGdtr,  WHvX64RegisterCr0,   WHvX64RegisterCr4,
        WHvX64RegisterRflags, WHvX64RegisterRip,  WHvX64RegisterRbx,
        WHvX64RegisterRax,
    };
    std::array<WHV_REGISTER_VALUE, 13> values{};
    values[0].Segment = code_seg;
    values[1].Segment = data_seg;
    values[2].Segment = data_seg;
    values[3].Segment = data_seg;
    values[4].Segment = data_seg;
    values[5].Segment = data_seg;
    values[6].Table = gdtr;
    values[7].Reg64 = kCr0Pe | kCr0Et;
    values[8].Reg64 = 0;
    values[9].Reg64 = 0x2;  // bit 1 reserved-must-be-1, IF=0
    values[10].Reg64 = res.entry_point;
    values[11].Reg64 = res.start_info_gpa;
    values[12].Reg64 = 0;

    vp.SetRegisters(names, values);
}

}  // namespace tinyvmm::boot
