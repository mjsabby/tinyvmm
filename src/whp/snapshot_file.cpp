#include "snapshot_file.h"

#include "common.h"

#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace tinyvmm::whp::snapshot {

const char* SectionTypeName(SectionType t) noexcept {
    switch (t) {
        case SectionType::RamRaw:             return "RAM_RAW";
        case SectionType::VcpuRegs:           return "VCPU_REGS";
        case SectionType::VcpuXsave:          return "VCPU_XSAVE";
        case SectionType::VcpuApic:           return "VCPU_APIC";
        case SectionType::VcpuIntrCtl:        return "VCPU_INTR_CTL";
        case SectionType::VcpuTiming:         return "VCPU_TIMING";
        case SectionType::VcpuSupMsr:         return "VCPU_SUP_MSR";
        case SectionType::HvEnlightenment:    return "HV_ENLIGHTENMENT";
        case SectionType::PciDevice:          return "PCI_DEVICE";
        case SectionType::VirtioPciTransport: return "VIRTIO_PCI_TRANSPORT";
        case SectionType::MsixState:          return "MSIX_STATE";
        case SectionType::Virtqueue:          return "VIRTQUEUE";
        case SectionType::VirtioRngState:     return "VIRTIO_RNG_STATE";
        case SectionType::VirtioConsoleState: return "VIRTIO_CONSOLE_STATE";
        case SectionType::VirtioBlkState:     return "VIRTIO_BLK_STATE";
        case SectionType::LegacySerial8250:   return "LEGACY_SERIAL_8250";
        case SectionType::LegacyPic8259:      return "LEGACY_PIC_8259";
        case SectionType::LegacyPit8254:      return "LEGACY_PIT_8254";
        case SectionType::LegacyPciBus:       return "LEGACY_PCI_BUS";
        case SectionType::LegacyIsaStubs:     return "LEGACY_ISA_STUBS";
        default:                              return "<unknown>";
    }
}

// ---------------- CRC-32 IEEE 802.3 (poly 0xEDB88320, reflected) ---------

namespace {

const std::array<std::uint32_t, 256>& Crc32Table() noexcept {
    static const std::array<std::uint32_t, 256> table = []() {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }();
    return table;
}

}  // namespace

std::uint32_t Crc32Update(std::uint32_t crc,
                          const void* data,
                          std::size_t length) noexcept {
    const auto& tbl = Crc32Table();
    const auto* p = static_cast<const std::uint8_t*>(data);
    std::uint32_t c = crc;
    for (std::size_t i = 0; i < length; ++i) {
        c = tbl[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    }
    return c;
}

// ---------------- Little-endian primitives ------------------------------

void WriteLe32(void* dst, std::uint32_t v) noexcept {
    auto* p = static_cast<std::uint8_t*>(dst);
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

void WriteLe64(void* dst, std::uint64_t v) noexcept {
    auto* p = static_cast<std::uint8_t*>(dst);
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>(v >> (i * 8));
    }
}

std::uint32_t ReadLe32(const void* src) noexcept {
    const auto* p = static_cast<const std::uint8_t*>(src);
    return  static_cast<std::uint32_t>(p[0])
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16)
         | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t ReadLe64(const void* src) noexcept {
    const auto* p = static_cast<const std::uint8_t*>(src);
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(p[i]) << (i * 8);
    }
    return v;
}

// ---------------- JsonObjectWriter --------------------------------------

namespace {

void EscapeJsonString(const std::string_view in, std::string& out) {
    out.push_back('"');
    for (char ch : in) {
        const auto uc = static_cast<unsigned char>(ch);
        switch (ch) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (uc < 0x20u) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    out += buf;
                } else {
                    out.push_back(ch);
                }
        }
    }
    out.push_back('"');
}

std::string UnescapeJsonString(std::string_view in) {
    // in is the bytes BETWEEN the surrounding quotes (already stripped).
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        const char ch = in[i];
        if (ch != '\\') { out.push_back(ch); continue; }
        if (i + 1 >= in.size()) {
            throw std::runtime_error("json: dangling backslash in string");
        }
        const char esc = in[++i];
        switch (esc) {
            case '"':  out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/':  out.push_back('/'); break;
            case 'b':  out.push_back('\b'); break;
            case 'f':  out.push_back('\f'); break;
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;
            case 'u': {
                if (i + 4 >= in.size()) {
                    throw std::runtime_error("json: truncated \\uXXXX");
                }
                unsigned code = 0;
                for (int k = 0; k < 4; ++k) {
                    const char hc = in[++i];
                    unsigned d = 0;
                    if (hc >= '0' && hc <= '9') d = unsigned(hc - '0');
                    else if (hc >= 'a' && hc <= 'f') d = 10u + unsigned(hc - 'a');
                    else if (hc >= 'A' && hc <= 'F') d = 10u + unsigned(hc - 'A');
                    else throw std::runtime_error("json: bad hex in \\uXXXX");
                    code = (code << 4) | d;
                }
                // We only round-trip control chars (<0x80) via \uXXXX; any
                // higher codepoint here is unexpected for tinyvmm's
                // limited schema. Encode as a UTF-8 byte stream anyway.
                if (code < 0x80u) {
                    out.push_back(static_cast<char>(code));
                } else if (code < 0x800u) {
                    out.push_back(static_cast<char>(0xC0u | (code >> 6)));
                    out.push_back(static_cast<char>(0x80u | (code & 0x3Fu)));
                } else {
                    out.push_back(static_cast<char>(0xE0u | (code >> 12)));
                    out.push_back(static_cast<char>(0x80u | ((code >> 6) & 0x3Fu)));
                    out.push_back(static_cast<char>(0x80u | (code & 0x3Fu)));
                }
                break;
            }
            default:
                throw std::runtime_error("json: unknown escape sequence");
        }
    }
    return out;
}

}  // namespace

void JsonObjectWriter::Add(const char* key, std::uint64_t value) {
    std::string entry;
    EscapeJsonString(key, entry);
    char buf[32];
    std::snprintf(buf, sizeof(buf), ":%llu",
                  static_cast<unsigned long long>(value));
    entry += buf;
    entries_.push_back(std::move(entry));
}

void JsonObjectWriter::Add(const char* key, std::int64_t value) {
    std::string entry;
    EscapeJsonString(key, entry);
    char buf[32];
    std::snprintf(buf, sizeof(buf), ":%lld",
                  static_cast<long long>(value));
    entry += buf;
    entries_.push_back(std::move(entry));
}

void JsonObjectWriter::Add(const char* key, bool value) {
    std::string entry;
    EscapeJsonString(key, entry);
    entry += value ? ":true" : ":false";
    entries_.push_back(std::move(entry));
}

void JsonObjectWriter::Add(const char* key, std::string_view value) {
    std::string entry;
    EscapeJsonString(key, entry);
    entry.push_back(':');
    EscapeJsonString(value, entry);
    entries_.push_back(std::move(entry));
}

std::string JsonObjectWriter::str() const {
    std::string out;
    out.push_back('{');
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += entries_[i];
    }
    out.push_back('}');
    return out;
}

// ---------------- JsonObjectReader --------------------------------------

namespace {

void SkipJsonWhitespace(std::string_view s, std::size_t& i) {
    while (i < s.size() &&
           (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) {
        ++i;
    }
}

std::string_view ScanJsonStringRaw(std::string_view s, std::size_t& i) {
    // Returns the bytes BETWEEN the surrounding quotes, advancing `i` past
    // the closing quote. Handles \" and \\ pass-through.
    if (i >= s.size() || s[i] != '"') {
        throw std::runtime_error("json: expected '\"' at object key");
    }
    ++i;
    const std::size_t start = i;
    while (i < s.size()) {
        if (s[i] == '\\') {
            if (i + 1 >= s.size()) {
                throw std::runtime_error("json: dangling backslash");
            }
            i += 2;
            continue;
        }
        if (s[i] == '"') {
            std::string_view inner = s.substr(start, i - start);
            ++i;
            return inner;
        }
        ++i;
    }
    throw std::runtime_error("json: unterminated string");
}

std::string_view ScanJsonValueRaw(std::string_view s, std::size_t& i) {
    // Returns the value's raw token (string with quotes, number, true/false,
    // null). Does NOT support nested objects/arrays (Phase 33.3 doesn't
    // need them).
    SkipJsonWhitespace(s, i);
    if (i >= s.size()) {
        throw std::runtime_error("json: missing value");
    }
    const std::size_t start = i;
    if (s[i] == '"') {
        ++i;
        while (i < s.size()) {
            if (s[i] == '\\') {
                if (i + 1 >= s.size()) {
                    throw std::runtime_error("json: dangling backslash");
                }
                i += 2;
            } else if (s[i] == '"') {
                ++i;
                return s.substr(start, i - start);
            } else {
                ++i;
            }
        }
        throw std::runtime_error("json: unterminated string value");
    }
    // Number / true / false / null: consume characters until comma / } /
    // whitespace.
    while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ' ' &&
           s[i] != '\t' && s[i] != '\n' && s[i] != '\r') {
        ++i;
    }
    return s.substr(start, i - start);
}

}  // namespace

JsonObjectReader::JsonObjectReader(std::string_view json) {
    std::size_t i = 0;
    SkipJsonWhitespace(json, i);
    if (i >= json.size() || json[i] != '{') {
        throw std::runtime_error("json: expected '{' at object start");
    }
    ++i;
    SkipJsonWhitespace(json, i);
    if (i < json.size() && json[i] == '}') { return; }  // empty object
    while (true) {
        SkipJsonWhitespace(json, i);
        const std::string key = UnescapeJsonString(ScanJsonStringRaw(json, i));
        SkipJsonWhitespace(json, i);
        if (i >= json.size() || json[i] != ':') {
            throw std::runtime_error("json: expected ':' after key");
        }
        ++i;
        const std::string_view raw = ScanJsonValueRaw(json, i);
        kv_.emplace(key, std::string(raw));
        SkipJsonWhitespace(json, i);
        if (i < json.size() && json[i] == ',') { ++i; continue; }
        if (i < json.size() && json[i] == '}') { ++i; break; }
        throw std::runtime_error("json: expected ',' or '}' after value");
    }
}

bool JsonObjectReader::Has(const char* key) const noexcept {
    return kv_.find(key) != kv_.end();
}

std::uint64_t JsonObjectReader::GetUint(const char* key) const {
    auto it = kv_.find(key);
    if (it == kv_.end()) {
        throw std::runtime_error(std::string("json: missing key '") + key + "'");
    }
    char* endp = nullptr;
    const auto v = std::strtoull(it->second.c_str(), &endp, 10);
    if (!endp || *endp != '\0') {
        throw std::runtime_error(std::string("json: not a uint at key '") + key + "'");
    }
    return v;
}

std::int64_t JsonObjectReader::GetInt(const char* key) const {
    auto it = kv_.find(key);
    if (it == kv_.end()) {
        throw std::runtime_error(std::string("json: missing key '") + key + "'");
    }
    char* endp = nullptr;
    const auto v = std::strtoll(it->second.c_str(), &endp, 10);
    if (!endp || *endp != '\0') {
        throw std::runtime_error(std::string("json: not an int at key '") + key + "'");
    }
    return v;
}

bool JsonObjectReader::GetBool(const char* key) const {
    auto it = kv_.find(key);
    if (it == kv_.end()) {
        throw std::runtime_error(std::string("json: missing key '") + key + "'");
    }
    if (it->second == "true") return true;
    if (it->second == "false") return false;
    throw std::runtime_error(std::string("json: not a bool at key '") + key + "'");
}

std::string JsonObjectReader::GetString(const char* key) const {
    auto it = kv_.find(key);
    if (it == kv_.end()) {
        throw std::runtime_error(std::string("json: missing key '") + key + "'");
    }
    const std::string& raw = it->second;
    if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"') {
        throw std::runtime_error(std::string("json: not a string at key '") + key + "'");
    }
    return UnescapeJsonString(std::string_view(raw).substr(1, raw.size() - 2));
}

// ---------------- SnapshotWriter ----------------------------------------

SnapshotWriter::SnapshotWriter(const std::string& path) : path_(path) {
    handle_ = CreateFileA(
        path.c_str(),
        GENERIC_WRITE,
        0,                       // no sharing
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        throw HrError(HRESULT_FROM_WIN32(err),
                      ("SnapshotWriter open '" + path + "'").c_str());
    }
}

SnapshotWriter::~SnapshotWriter() {
    if (handle_ != INVALID_HANDLE_VALUE) {
        if (!finalized_) {
            std::fprintf(stderr,
                "[snapshot-writer] WARN: destructor called before Finalize();"
                " deleting partial file '%s'\n", path_.c_str());
        }
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
        if (!finalized_) {
            DeleteFileA(path_.c_str());
        }
    }
}

void SnapshotWriter::WriteRaw_(const void* data, std::size_t length) {
    const auto* p = static_cast<const std::uint8_t*>(data);
    std::size_t remaining = length;
    while (remaining > 0) {
        // Chunk to 1 MiB. Easier to diagnose partial-write errors and keeps
        // the CRC/Write loop well-behaved for very large RAM sections.
        const DWORD want =
            (remaining > (1u << 20)) ? (1u << 20)
                                     : static_cast<DWORD>(remaining);
        DWORD got = 0;
        if (!WriteFile(handle_, p, want, &got, nullptr)) {
            const DWORD err = GetLastError();
            throw HrError(HRESULT_FROM_WIN32(err),
                ("SnapshotWriter WriteFile '" + path_ + "'").c_str());
        }
        if (got != want) {
            throw std::runtime_error("SnapshotWriter: short write");
        }
        crc_ = Crc32Update(crc_, p, want);
        p += want;
        bytes_ += want;
        remaining -= want;
    }
}

void SnapshotWriter::WriteHeader(std::string_view json) {
    if (header_written_) {
        throw std::runtime_error("SnapshotWriter::WriteHeader called twice");
    }
    if (finalized_) {
        throw std::runtime_error("SnapshotWriter::WriteHeader after Finalize");
    }
    // FileHeader (24 bytes)
    std::uint8_t hdr[24] = {};
    std::memcpy(hdr, kMagic, 8);
    WriteLe32(hdr + 8,  kVersion);
    WriteLe32(hdr + 12, 0u);  // reserved
    WriteLe64(hdr + 16, static_cast<std::uint64_t>(json.size()));
    WriteRaw_(hdr, sizeof(hdr));
    WriteRaw_(json.data(), json.size());
    header_written_ = true;
}

void SnapshotWriter::WriteSection(SectionType type,
                                  const void* data,
                                  std::size_t length) {
    if (!header_written_) {
        throw std::runtime_error("SnapshotWriter::WriteSection before WriteHeader");
    }
    if (finalized_) {
        throw std::runtime_error("SnapshotWriter::WriteSection after Finalize");
    }
    std::uint8_t sec[16] = {};
    WriteLe32(sec + 0, static_cast<std::uint32_t>(type));
    WriteLe32(sec + 4, 0u);  // reserved
    WriteLe64(sec + 8, static_cast<std::uint64_t>(length));
    WriteRaw_(sec, sizeof(sec));
    if (length > 0) {
        WriteRaw_(data, length);
    }
}

void SnapshotWriter::Finalize() {
    if (finalized_) {
        throw std::runtime_error("SnapshotWriter::Finalize called twice");
    }
    if (!header_written_) {
        throw std::runtime_error("SnapshotWriter::Finalize before WriteHeader");
    }
    // Trailer: CRC32 finalized over everything written so far.
    const std::uint32_t final_crc = Crc32Finalize(crc_);
    std::uint8_t tail[4] = {};
    WriteLe32(tail, final_crc);
    // Bypass the running CRC update (we're writing the CRC itself).
    DWORD got = 0;
    if (!WriteFile(handle_, tail, 4, &got, nullptr) || got != 4) {
        const DWORD err = GetLastError();
        throw HrError(HRESULT_FROM_WIN32(err),
            ("SnapshotWriter trailer WriteFile '" + path_ + "'").c_str());
    }
    bytes_ += 4;
    if (!FlushFileBuffers(handle_)) {
        const DWORD err = GetLastError();
        throw HrError(HRESULT_FROM_WIN32(err),
            ("SnapshotWriter FlushFileBuffers '" + path_ + "'").c_str());
    }
    if (!CloseHandle(handle_)) {
        const DWORD err = GetLastError();
        handle_ = INVALID_HANDLE_VALUE;
        throw HrError(HRESULT_FROM_WIN32(err),
            ("SnapshotWriter CloseHandle '" + path_ + "'").c_str());
    }
    handle_ = INVALID_HANDLE_VALUE;
    finalized_ = true;
}

// ---------------- SnapshotReader ----------------------------------------

SnapshotReader::SnapshotReader(const std::string& path) : path_(path) {
    HANDLE h = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        throw HrError(HRESULT_FROM_WIN32(err),
            ("SnapshotReader open '" + path + "'").c_str());
    }
    LARGE_INTEGER li = {};
    if (!GetFileSizeEx(h, &li)) {
        const DWORD err = GetLastError();
        CloseHandle(h);
        throw HrError(HRESULT_FROM_WIN32(err),
            ("SnapshotReader GetFileSizeEx '" + path + "'").c_str());
    }
    if (li.QuadPart < 24 + 4) {
        CloseHandle(h);
        throw std::runtime_error(
            "SnapshotReader: file too small to contain header + trailer");
    }
    buf_.resize(static_cast<std::size_t>(li.QuadPart));
    DWORD got = 0;
    // Single ReadFile call is fine for hundreds-of-MiB files on x64
    // Windows; the kernel ReadFile path handles the size internally.
    if (!ReadFile(h, buf_.data(),
                  static_cast<DWORD>(buf_.size()), &got, nullptr) ||
        got != buf_.size()) {
        const DWORD err = GetLastError();
        CloseHandle(h);
        throw HrError(HRESULT_FROM_WIN32(err),
            ("SnapshotReader ReadFile '" + path + "'").c_str());
    }
    CloseHandle(h);
}

std::string SnapshotReader::ReadHeader() {
    if (header_read_) {
        throw std::runtime_error("SnapshotReader::ReadHeader called twice");
    }
    if (buf_.size() < 24u + 4u) {
        throw std::runtime_error("SnapshotReader: file too small for header");
    }
    if (std::memcmp(buf_.data(), kMagic, 8) != 0) {
        throw std::runtime_error("SnapshotReader: bad magic (not a TVMMSAVE file)");
    }
    const std::uint32_t ver = ReadLe32(buf_.data() + 8);
    if (ver != kVersion) {
        char msg[96];
        std::snprintf(msg, sizeof(msg),
            "SnapshotReader: unsupported version %u (expected %u)",
            ver, kVersion);
        throw std::runtime_error(msg);
    }
    const std::uint32_t reserved = ReadLe32(buf_.data() + 12);
    if (reserved != 0) {
        throw std::runtime_error("SnapshotReader: nonzero reserved in header");
    }
    const std::uint64_t json_size = ReadLe64(buf_.data() + 16);
    // Header + JSON + at least the 4-byte trailer.
    if (json_size > buf_.size() - 24u - 4u) {
        throw std::runtime_error("SnapshotReader: header JSON size overflows file");
    }
    std::string json(reinterpret_cast<const char*>(buf_.data() + 24),
                     static_cast<std::size_t>(json_size));
    pos_ = 24u + static_cast<std::size_t>(json_size);
    header_read_ = true;
    return json;
}

std::optional<SnapshotReader::Section> SnapshotReader::NextSection() {
    if (!header_read_) {
        throw std::runtime_error("SnapshotReader::NextSection before ReadHeader");
    }
    const std::size_t file_size = buf_.size();
    if (pos_ + 4u > file_size) {
        throw std::runtime_error("SnapshotReader: read past file end (no trailer)");
    }
    if (pos_ + 4u == file_size) {
        return std::nullopt;  // exactly the trailer left
    }
    if (pos_ + 16u + 4u > file_size) {
        throw std::runtime_error(
            "SnapshotReader: section header would overlap trailer");
    }
    const std::uint32_t type     = ReadLe32(buf_.data() + pos_ + 0);
    const std::uint32_t reserved = ReadLe32(buf_.data() + pos_ + 4);
    const std::uint64_t length   = ReadLe64(buf_.data() + pos_ + 8);
    if (reserved != 0) {
        throw std::runtime_error(
            "SnapshotReader: nonzero reserved in section header");
    }
    const std::size_t after_hdr = pos_ + 16u;
    if (length > file_size - 4u - after_hdr) {
        throw std::runtime_error(
            "SnapshotReader: section length overflows remaining bytes");
    }
    Section s;
    s.type = static_cast<SectionType>(type);
    s.payload = std::span<const std::uint8_t>(
        buf_.data() + after_hdr, static_cast<std::size_t>(length));
    pos_ = after_hdr + static_cast<std::size_t>(length);
    return s;
}

void SnapshotReader::VerifyTrailer() {
    if (buf_.size() < 4u) {
        throw std::runtime_error("SnapshotReader: file too small for trailer");
    }
    const std::size_t covered = buf_.size() - 4u;
    std::uint32_t computed = 0xFFFFFFFFu;
    computed = Crc32Update(computed, buf_.data(), covered);
    computed = Crc32Finalize(computed);
    const std::uint32_t stored = ReadLe32(buf_.data() + covered);
    if (computed != stored) {
        char msg[96];
        std::snprintf(msg, sizeof(msg),
            "SnapshotReader: CRC32 mismatch (stored=0x%08X computed=0x%08X)",
            stored, computed);
        throw std::runtime_error(msg);
    }
}

}  // namespace tinyvmm::whp::snapshot
