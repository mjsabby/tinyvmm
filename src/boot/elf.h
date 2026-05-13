#pragma once

// Just enough ELF64 to parse a Linux vmlinux. We bring our own definitions so
// we don't depend on a third-party libelf -- it's all small fixed-layout
// structs and a half-dozen named constants.

#include <cstdint>

namespace tinyvmm::boot::elf {

constexpr std::uint8_t kElfMag0 = 0x7f;
constexpr std::uint8_t kElfMag1 = 'E';
constexpr std::uint8_t kElfMag2 = 'L';
constexpr std::uint8_t kElfMag3 = 'F';

constexpr std::uint8_t kElfClass64 = 2;
constexpr std::uint8_t kElfData2Lsb = 1;
constexpr std::uint8_t kEvCurrent = 1;

constexpr std::uint16_t kEtExec = 2;
constexpr std::uint16_t kEmX8664 = 0x3e;

// p_type values we care about
constexpr std::uint32_t kPtLoad = 1;
constexpr std::uint32_t kPtNote = 4;

// sh_type values we care about
constexpr std::uint32_t kShtNote = 7;

// p_flags
constexpr std::uint32_t kPfX = 1;
constexpr std::uint32_t kPfW = 2;
constexpr std::uint32_t kPfR = 4;

#pragma pack(push, 1)

struct Ehdr64 {
    std::uint8_t  e_ident[16];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint64_t e_entry;
    std::uint64_t e_phoff;
    std::uint64_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
};
static_assert(sizeof(Ehdr64) == 64);

struct Phdr64 {
    std::uint32_t p_type;
    std::uint32_t p_flags;
    std::uint64_t p_offset;
    std::uint64_t p_vaddr;
    std::uint64_t p_paddr;
    std::uint64_t p_filesz;
    std::uint64_t p_memsz;
    std::uint64_t p_align;
};
static_assert(sizeof(Phdr64) == 56);

struct Shdr64 {
    std::uint32_t sh_name;
    std::uint32_t sh_type;
    std::uint64_t sh_flags;
    std::uint64_t sh_addr;
    std::uint64_t sh_offset;
    std::uint64_t sh_size;
    std::uint32_t sh_link;
    std::uint32_t sh_info;
    std::uint64_t sh_addralign;
    std::uint64_t sh_entsize;
};
static_assert(sizeof(Shdr64) == 64);

struct Nhdr {
    std::uint32_t n_namesz;
    std::uint32_t n_descsz;
    std::uint32_t n_type;
};
static_assert(sizeof(Nhdr) == 12);

#pragma pack(pop)

}  // namespace tinyvmm::boot::elf
