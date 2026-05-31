#pragma once

// M33.3 save/restore file format primitives.
//
// File layout:
//   [FileHeader] 24 bytes:
//     char[8]  magic = "TVMMSAVE"
//     u32      version  (kVersion)
//     u32      reserved = 0
//     u64      header_json_size
//   [Header JSON]  UTF-8 bytes (flat object: ASCII keys, int/bool/string values)
//   [Sections]    repeated TLV blocks:
//     u32      type    (SectionType)
//     u32      reserved = 0
//     u64      length
//     bytes    payload (`length` bytes)
//   [Trailer]
//     u32      crc32   IEEE-802.3 polynomial 0xEDB88320, reflected,
//                      init 0xFFFFFFFF, xorout 0xFFFFFFFF.
//                      Computed over every byte preceding the trailer
//                      (file header + JSON + every section's header + payload).
//
// All multi-byte integers are LITTLE-ENDIAN on disk. The format is
// x86_64-only (tinyvmm is Windows-only and the WHP register values are
// already a host-endian 16-byte union, so byteswapping them on a
// hypothetical big-endian host would not produce a meaningful file
// anyway). LE-explicit helpers exist so the on-disk encoding is
// well-defined and not "whatever the compiler does".
//
// Reader rules (must be enforced):
//   * file_size >= 24+0+4 (header + 0 sections + trailer)
//   * magic and version exact match
//   * header_json_size <= file_size - 24 - 4 (trailer)
//   * a section header is read only if remaining bytes >= 16 + 4 (header
//     + trailer); the last 4 bytes are always trailer-CRC
//   * section.length <= remaining bytes - 4 (trailer)
//   * NextSection() returns nullopt when exactly 4 bytes remain
//   * VerifyTrailer() compares the saved CRC32 against the running CRC32
//     over the first (file_size - 4) bytes.

#include <Windows.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace tinyvmm::whp::snapshot {

inline constexpr char kMagic[8] = {'T','V','M','M','S','A','V','E'};
inline constexpr std::uint32_t kVersion = 1u;

// Wire-format identifiers for section payloads. Phase 33.3 defines the
// first seven; Phase 33.4 added PCI/MSI-X/virtqueue/per-device device
// state. Do not renumber existing values: they are now part of the
// on-disk ABI.
//
// Phase 33.4 sections all start with a 4-byte BDF prefix (u8 bus, u8 dev,
// u8 fn, u8 reserved=0); VIRTQUEUE adds a (u16 qidx, u16 pad) after BDF
// so the same payload type carries multiple queues per device.
enum class SectionType : std::uint32_t {
    RamRaw                 = 0x0001,
    VcpuRegs               = 0x0010,
    VcpuXsave              = 0x0011,
    VcpuApic               = 0x0012,
    VcpuIntrCtl            = 0x0013,
    VcpuTiming             = 0x0014,
    // M33.7: per-vCPU supervisor MSRs (IA32_XSS + CET MSRs). Same
    // wire encoding as VcpuIntrCtl: u32 vp_idx | u32 reg_count |
    // [u32 name | u8 ok | u8 pad[3] | 16 bytes value]*. Required to
    // round-trip XSAVE areas that include CET supervisor state
    // (XSTATE_BV bits 11/12, XCOMP_BV bit 63 compact format) on
    // Linux 6.6+ kernels with CONFIG_X86_KERNEL_IBT/CET_SS.
    VcpuSupMsr             = 0x0015,
    HvEnlightenment        = 0x0020,
    // Phase 33.4
    PciDevice              = 0x0030,
    VirtioPciTransport     = 0x0031,
    MsixState              = 0x0032,
    Virtqueue              = 0x0040,
    VirtioRngState         = 0x0050,
    VirtioConsoleState     = 0x0051,
    VirtioBlkState         = 0x0052,
    // Phase 33.5 (legacy singletons; no BDF prefix; payload is encoded
    // State bytes directly).
    LegacySerial8250       = 0x0060,
    LegacyPic8259          = 0x0061,
    LegacyPit8254          = 0x0062,
    LegacyPciBus           = 0x0063,
    LegacyIsaStubs         = 0x0064,
};

const char* SectionTypeName(SectionType t) noexcept;

// CRC-32 (IEEE 802.3, polynomial 0xEDB88320, reflected, init 0xFFFFFFFF,
// xorout 0xFFFFFFFF). `crc` starts at 0xFFFFFFFFu and is xor-finalized at
// the end. The 256-entry lookup table is built on first use (function-local
// static, thread-safe).
std::uint32_t Crc32Update(std::uint32_t crc,
                          const void* data,
                          std::size_t length) noexcept;
inline std::uint32_t Crc32Finalize(std::uint32_t crc) noexcept {
    return crc ^ 0xFFFFFFFFu;
}

// Little-endian primitives. The "encode" helpers write into a caller-owned
// 4-/8-byte buffer; the "decode" helpers read from a 4-/8-byte buffer.
// These are explicit so the file format is well-defined regardless of
// compiler endianness assumptions.
void    WriteLe32(void* dst, std::uint32_t v) noexcept;
void    WriteLe64(void* dst, std::uint64_t v) noexcept;
std::uint32_t ReadLe32(const void* src) noexcept;
std::uint64_t ReadLe64(const void* src) noexcept;

// -------------- Minimal JSON helpers (flat object only) ----------------
//
// Phase 33.3 only needs to round-trip a handful of integer + bool + string
// values in the header. We deliberately do NOT pull in a JSON library; the
// writer emits a canonical compact object and the reader splits on
// top-level commas/colons. The writer escapes only the characters that
// must be escaped in a JSON string: `\`, `"`, and control characters
// 0x00..0x1F (rendered as \uXXXX). The reader unescapes the inverse set.

class JsonObjectWriter {
public:
    void Add(const char* key, std::uint64_t value);
    void Add(const char* key, std::int64_t value);
    void Add(const char* key, bool value);
    void Add(const char* key, std::string_view value);
    std::string str() const;
private:
    std::vector<std::string> entries_;
};

class JsonObjectReader {
public:
    explicit JsonObjectReader(std::string_view json);

    bool Has(const char* key) const noexcept;
    std::uint64_t GetUint(const char* key) const;
    std::int64_t  GetInt(const char* key) const;
    bool          GetBool(const char* key) const;
    std::string   GetString(const char* key) const;

private:
    std::unordered_map<std::string, std::string> kv_;
};

// ---------------------------- Writer / Reader ---------------------------

class SnapshotWriter {
public:
    // Opens `path` for write, truncating any existing file. Pure Win32:
    // CreateFileA(GENERIC_WRITE, no sharing, CREATE_ALWAYS,
    // FILE_ATTRIBUTE_NORMAL). Throws HrError on failure.
    explicit SnapshotWriter(const std::string& path);

    // Best-effort close. If !finalized_, the partial file is deleted and a
    // diagnostic is logged to stderr. Never throws (destructor-safe).
    ~SnapshotWriter();

    SnapshotWriter(const SnapshotWriter&) = delete;
    SnapshotWriter& operator=(const SnapshotWriter&) = delete;

    // Writes [FileHeader] + JSON. Must be called exactly once, before any
    // WriteSection. JSON is written as-is (caller is responsible for any
    // escaping; use JsonObjectWriter to produce it). CRC32 starts here.
    void WriteHeader(std::string_view json);

    // Writes a single TLV section. May be called any number of times after
    // WriteHeader and before Finalize. RAM payloads are chunked through
    // 1 MiB writes internally to keep CRT and Win32 paths well-behaved.
    void WriteSection(SectionType type,
                      const void* data,
                      std::size_t length);

    // Writes the trailer CRC32, fflushes via FlushFileBuffers, and closes
    // the handle. Must be called exactly once. After this, the destructor
    // does nothing.
    void Finalize();

    // Total bytes written to disk, including header + sections + trailer.
    std::uint64_t bytes_written() const noexcept { return bytes_; }

    // Path the file was opened at. Useful in error messages.
    const std::string& path() const noexcept { return path_; }

private:
    void WriteRaw_(const void* data, std::size_t length);

    std::string path_;
    HANDLE      handle_ = INVALID_HANDLE_VALUE;
    std::uint32_t crc_  = 0xFFFFFFFFu;
    std::uint64_t bytes_ = 0;
    bool finalized_      = false;
    bool header_written_ = false;
};

class SnapshotReader {
public:
    // Opens and slurps `path` into memory. The whole file is read up-front
    // (Phase 33.3 file size is bounded by RAM size, hundreds of MiB at
    // most). Throws HrError if the file is missing or the file size is
    // smaller than the minimum (24+0+4 = 28 bytes).
    explicit SnapshotReader(const std::string& path);

    SnapshotReader(const SnapshotReader&) = delete;
    SnapshotReader& operator=(const SnapshotReader&) = delete;

    // Validates magic + version, then returns the header JSON. Must be
    // called exactly once before NextSection.
    std::string ReadHeader();

    // Section view returned by NextSection. The `payload` span points into
    // the SnapshotReader's internal buffer; valid for the SnapshotReader's
    // lifetime. Phase 33.3 design has the reader collect sections into an
    // in-memory model before applying; callers are expected to copy out
    // sections of interest if they need a longer lifetime.
    struct Section {
        SectionType type;
        std::span<const std::uint8_t> payload;
    };

    // Returns the next section, or nullopt if exactly 4 bytes (the trailer)
    // remain. Throws if a section header would read past file_size-4, if
    // section.length would overflow the remaining bytes, or if the reserved
    // field is non-zero.
    std::optional<Section> NextSection();

    // Verifies the trailer CRC32 against the running CRC32 over the
    // preceding bytes. Throws on mismatch. Must be called exactly once
    // after NextSection has returned nullopt (or at any point after; the
    // CRC is computed over the file prefix regardless of read position).
    void VerifyTrailer();

    // Total file size in bytes (including trailer).
    std::uint64_t file_size() const noexcept { return buf_.size(); }
    const std::string& path() const noexcept { return path_; }

private:
    std::string path_;
    std::vector<std::uint8_t> buf_;
    std::size_t pos_ = 0;
    bool header_read_ = false;
};

}  // namespace tinyvmm::whp::snapshot
