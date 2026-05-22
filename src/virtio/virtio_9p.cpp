#include "virtio_9p.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <system_error>
#include <tuple>
#include <utility>

namespace tinyvmm::virtio {

namespace {

constexpr std::uint32_t kV9fsMagic              = 0x01021997;
constexpr std::uint8_t  kDtDir                  = 4;
constexpr std::uint8_t  kDtReg                  = 8;
constexpr std::uint32_t kSIfDir                 = 0040000;
constexpr std::uint32_t kSIfReg                 = 0100000;
constexpr std::uint64_t kFileTimeBiasTo1970     = 116444736000000000ULL;
constexpr std::size_t   kReplyHeaderSize        = 7;
constexpr std::size_t   kRreadHeaderSize        = 11;  // 7 hdr + 4 count
constexpr std::uint16_t kMaxWalkNames           = 16;

std::wstring NormalizeForContainment(const std::filesystem::path& p) {
    std::error_code ec;
    auto canon = std::filesystem::weakly_canonical(p, ec);
    if (ec) canon = p;
    auto w = canon.lexically_normal().wstring();
    for (auto& c : w) {
        if (c == L'/') c = L'\\';
        c = static_cast<wchar_t>(std::towlower(c));
    }
    while (w.size() > 3 && w.back() == L'\\') w.pop_back();
    return w;
}

}  // namespace

// ============================================================
// FidEntry move / dtor
// ============================================================

P9Device::FidEntry::FidEntry(FidEntry&& o) noexcept
    : host_path(std::move(o.host_path)),
      is_dir(o.is_dir),
      qid_path(o.qid_path),
      handle(o.handle),
      opened(o.opened),
      open_flags(o.open_flags),
      dir_cache(std::move(o.dir_cache)),
      dir_cache_built(o.dir_cache_built) {
    o.handle = nullptr;
    o.opened = false;
    o.dir_cache_built = false;
}

P9Device::FidEntry& P9Device::FidEntry::operator=(FidEntry&& o) noexcept {
    if (this != &o) {
        CloseHandle();
        host_path = std::move(o.host_path);
        is_dir = o.is_dir;
        qid_path = o.qid_path;
        handle = o.handle;
        opened = o.opened;
        open_flags = o.open_flags;
        dir_cache = std::move(o.dir_cache);
        dir_cache_built = o.dir_cache_built;
        o.handle = nullptr;
        o.opened = false;
        o.dir_cache_built = false;
    }
    return *this;
}

P9Device::FidEntry::~FidEntry() {
    CloseHandle();
}

void P9Device::FidEntry::CloseHandle() noexcept {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(reinterpret_cast<HANDLE>(handle));
    }
    handle = nullptr;
    opened = false;
    dir_cache.clear();
    dir_cache_built = false;
}

// ============================================================
// Encoders / decoders
// ============================================================

void P9Device::Encode1(std::vector<std::uint8_t>& out, std::uint8_t v) {
    out.push_back(v);
}

void P9Device::Encode2(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v));
    out.push_back(static_cast<std::uint8_t>(v >> 8));
}

void P9Device::Encode4(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

void P9Device::Encode8(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

void P9Device::EncodeString(std::vector<std::uint8_t>& out, const std::string& s) {
    std::size_t n = s.size();
    if (n > 0xFFFF) n = 0xFFFF;
    Encode2(out, static_cast<std::uint16_t>(n));
    out.insert(out.end(),
               reinterpret_cast<const std::uint8_t*>(s.data()),
               reinterpret_cast<const std::uint8_t*>(s.data()) + n);
}

void P9Device::EncodeQid(std::vector<std::uint8_t>& out,
                          std::uint8_t type, std::uint32_t version,
                          std::uint64_t path) {
    Encode1(out, type);
    Encode4(out, version);
    Encode8(out, path);
}

void P9Device::AppendQid(std::vector<std::uint8_t>& out,
                          std::uint8_t type, std::uint32_t version,
                          std::uint64_t path) {
    EncodeQid(out, type, version, path);
}

void P9Device::FinalizeMessage(std::vector<std::uint8_t>& out) {
    std::uint32_t sz = static_cast<std::uint32_t>(out.size());
    out[0] = static_cast<std::uint8_t>(sz);
    out[1] = static_cast<std::uint8_t>(sz >> 8);
    out[2] = static_cast<std::uint8_t>(sz >> 16);
    out[3] = static_cast<std::uint8_t>(sz >> 24);
}

bool P9Device::Decode1(const std::vector<std::uint8_t>& in,
                        std::size_t& off, std::uint8_t& v) {
    if (off + 1 > in.size()) return false;
    v = in[off]; off += 1; return true;
}

bool P9Device::Decode2(const std::vector<std::uint8_t>& in,
                        std::size_t& off, std::uint16_t& v) {
    if (off + 2 > in.size()) return false;
    v = static_cast<std::uint16_t>(in[off]) |
        (static_cast<std::uint16_t>(in[off + 1]) << 8);
    off += 2; return true;
}

bool P9Device::Decode4(const std::vector<std::uint8_t>& in,
                        std::size_t& off, std::uint32_t& v) {
    if (off + 4 > in.size()) return false;
    v = 0;
    for (int i = 0; i < 4; ++i)
        v |= static_cast<std::uint32_t>(in[off + i]) << (i * 8);
    off += 4; return true;
}

bool P9Device::Decode8(const std::vector<std::uint8_t>& in,
                        std::size_t& off, std::uint64_t& v) {
    if (off + 8 > in.size()) return false;
    v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(in[off + i]) << (i * 8);
    off += 8; return true;
}

bool P9Device::DecodeString(const std::vector<std::uint8_t>& in,
                              std::size_t& off, std::string& s) {
    std::uint16_t n;
    if (!Decode2(in, off, n)) return false;
    if (off + n > in.size()) return false;
    s.assign(reinterpret_cast<const char*>(in.data() + off), n);
    off += n;
    return true;
}

// ============================================================
// Win32 helpers
// ============================================================

std::wstring P9Device::Utf8ToWide(const std::string& s, bool& ok) {
    ok = true;
    if (s.empty()) return {};
    if (s.find('\0') != std::string::npos) { ok = false; return {}; }
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                s.data(), static_cast<int>(s.size()),
                                nullptr, 0);
    if (n <= 0) { ok = false; return {}; }
    std::wstring w; w.resize(static_cast<std::size_t>(n));
    int r = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                s.data(), static_cast<int>(s.size()),
                                w.data(), n);
    if (r != n) { ok = false; return {}; }
    return w;
}

std::string P9Device::WideToUtf8(const wchar_t* s, std::size_t n) {
    if (n == 0 || s == nullptr) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, s, static_cast<int>(n),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out; out.resize(static_cast<std::size_t>(needed));
    int r = WideCharToMultiByte(CP_UTF8, 0, s, static_cast<int>(n),
                                out.data(), needed, nullptr, nullptr);
    if (r != needed) return {};
    return out;
}

std::uint32_t P9Device::Win32ErrnoToP9(unsigned long e) {
    switch (e) {
        case ERROR_SUCCESS:              return 0;
        case ERROR_FILE_NOT_FOUND:       return kP9Enoent;
        case ERROR_PATH_NOT_FOUND:       return kP9Enoent;
        case ERROR_INVALID_DRIVE:        return kP9Enoent;
        case ERROR_NO_MORE_FILES:        return kP9Enoent;
        case ERROR_ACCESS_DENIED:        return kP9Eacces;
        case ERROR_SHARING_VIOLATION:    return kP9Eacces;
        case ERROR_LOCK_VIOLATION:       return kP9Eacces;
        case ERROR_FILE_EXISTS:          return kP9Eexist;
        case ERROR_ALREADY_EXISTS:       return kP9Eexist;
        case ERROR_INVALID_NAME:         return kP9Einval;
        case ERROR_INVALID_PARAMETER:    return kP9Einval;
        case ERROR_BAD_PATHNAME:         return kP9Einval;
        case ERROR_NEGATIVE_SEEK:        return kP9Einval;
        case ERROR_INVALID_BLOCK_LENGTH: return kP9Einval;
        case ERROR_FILENAME_EXCED_RANGE: return kP9Enametoolong;
        case ERROR_DIR_NOT_EMPTY:        return kP9Enotempty;
        case ERROR_DISK_FULL:            return kP9Enospc;
        case ERROR_HANDLE_DISK_FULL:     return kP9Enospc;
        case ERROR_INVALID_HANDLE:       return kP9Ebadf;
        case ERROR_TOO_MANY_OPEN_FILES:  return kP9Emfile;
        case ERROR_WRITE_PROTECT:        return kP9Erofs;
        case ERROR_NOT_SUPPORTED:        return kP9Enosys;
        case ERROR_DIRECTORY:            return kP9Enotdir;
        case ERROR_NOT_READY:            return kP9Eio;
        case ERROR_OPERATION_ABORTED:    return kP9Eio;
        case ERROR_BROKEN_PIPE:          return kP9Eio;
        default:                         return kP9Eio;
    }
}

void P9Device::FileTimeToUnix(const FILETIME& ft,
                                std::uint64_t& sec, std::uint64_t& nsec) {
    ULARGE_INTEGER u;
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart < kFileTimeBiasTo1970) { sec = 0; nsec = 0; return; }
    std::uint64_t since1970 = u.QuadPart - kFileTimeBiasTo1970;
    sec  = since1970 / 10000000ULL;
    nsec = (since1970 % 10000000ULL) * 100ULL;
}

void P9Device::UnixToFileTime(std::uint64_t sec, std::uint64_t nsec,
                                FILETIME& ft) {
    std::uint64_t hundred_ns =
        sec * 10000000ULL + (nsec / 100ULL) + kFileTimeBiasTo1970;
    ft.dwLowDateTime  = static_cast<DWORD>(hundred_ns & 0xFFFFFFFFu);
    ft.dwHighDateTime = static_cast<DWORD>(hundred_ns >> 32);
}

std::wstring P9Device::ToWin32LongPath(const std::filesystem::path& p) {
    auto w = p.wstring();
    for (auto& c : w) if (c == L'/') c = L'\\';
    if (w.size() >= 4 && w[0] == L'\\' && w[1] == L'\\' &&
        (w[2] == L'?' || w[2] == L'.') && w[3] == L'\\') {
        return w;
    }
    if (w.size() >= 2 && w[0] == L'\\' && w[1] == L'\\') {
        return L"\\\\?\\UNC\\" + w.substr(2);
    }
    if (w.size() >= 3 && std::iswalpha(w[0]) && w[1] == L':' && w[2] == L'\\') {
        return L"\\\\?\\" + w;
    }
    return w;
}

bool P9Device::IsSafeNameComponent(const std::string& comp) {
    if (comp.empty()) return false;
    if (comp == "." || comp == "..") return false;
    if (comp.size() > 255) return false;
    for (char c : comp) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20) return false;
        switch (c) {
            case '/': case '\\': case ':': case '*': case '?':
            case '"': case '<': case '>': case '|':
                return false;
            default: break;
        }
    }
    if (comp.back() == '.' || comp.back() == ' ') return false;

    auto dot_pos = comp.find('.');
    std::string stem = dot_pos == std::string::npos
                           ? comp
                           : comp.substr(0, dot_pos);
    std::string upper = stem;
    for (auto& c : upper)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    static const char* const kReserved[] = {
        "CON",  "PRN",  "AUX",  "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5",
        "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
        "LPT6", "LPT7", "LPT8", "LPT9",
    };
    for (auto* r : kReserved) {
        if (upper == r) return false;
    }
    return true;
}

std::filesystem::path P9Device::JoinChild(const std::filesystem::path& base,
                                            const std::string& child) {
    bool ok = true;
    std::wstring wchild = Utf8ToWide(child, ok);
    if (!ok) return {};
    return base / std::filesystem::path(wchild);
}

bool P9Device::PathContained(const std::filesystem::path& p) const {
    auto pn = NormalizeForContainment(p);
    if (pn.size() < share_root_norm_.size()) return false;
    if (pn.compare(0, share_root_norm_.size(), share_root_norm_) != 0) return false;
    if (pn.size() == share_root_norm_.size()) return true;
    return pn[share_root_norm_.size()] == L'\\';
}

void* P9Device::OpenForAttrs(const std::filesystem::path& p,
                              unsigned long& gle) {
    auto w = ToWin32LongPath(p);
    HANDLE h = CreateFileW(w.c_str(),
                            FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS,
                            nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        gle = GetLastError();
        return nullptr;
    }
    gle = 0;
    return h;
}

bool P9Device::ReadAttrsByHandle(void* h,
                                   std::uint8_t&  qid_type,
                                   std::uint32_t& qid_version,
                                   std::uint64_t& qid_path,
                                   std::uint32_t& mode,
                                   std::uint64_t& nlink,
                                   std::uint64_t& size,
                                   std::uint64_t& blocks,
                                   std::uint64_t& atime_s, std::uint64_t& atime_n,
                                   std::uint64_t& mtime_s, std::uint64_t& mtime_n,
                                   std::uint64_t& ctime_s, std::uint64_t& ctime_n,
                                   std::uint32_t& errno_out) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(reinterpret_cast<HANDLE>(h), &info)) {
        errno_out = Win32ErrnoToP9(GetLastError());
        return false;
    }
    bool is_dir = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    qid_type    = is_dir ? kP9QTDir : kP9QTFile;
    qid_version = 0;
    qid_path    = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) |
                  info.nFileIndexLow;
    if (qid_path == 0) qid_path = next_qid_path_++;
    if (is_dir) {
        mode = kSIfDir | 0755u;
    } else {
        bool ro = (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0;
        mode = kSIfReg | (ro ? 0444u : 0644u);
    }
    nlink = info.nNumberOfLinks ? info.nNumberOfLinks : 1;
    size  = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) |
            info.nFileSizeLow;
    blocks = (size + 511) / 512;
    FileTimeToUnix(info.ftLastAccessTime, atime_s, atime_n);
    FileTimeToUnix(info.ftLastWriteTime,  mtime_s, mtime_n);
    FileTimeToUnix(info.ftCreationTime,   ctime_s, ctime_n);
    errno_out = 0;
    return true;
}

bool P9Device::StatPathForFid(const std::filesystem::path& p,
                                std::uint8_t&  qid_type,
                                std::uint64_t& qid_path,
                                bool&          is_dir,
                                std::uint32_t& errno_out) {
    unsigned long gle = 0;
    void* h = OpenForAttrs(p, gle);
    if (!h) {
        errno_out = Win32ErrnoToP9(gle);
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(reinterpret_cast<HANDLE>(h), &info)) {
        errno_out = Win32ErrnoToP9(GetLastError());
        ::CloseHandle(reinterpret_cast<HANDLE>(h));
        return false;
    }
    is_dir   = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    qid_type = is_dir ? kP9QTDir : kP9QTFile;
    qid_path = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) |
               info.nFileIndexLow;
    if (qid_path == 0) qid_path = next_qid_path_++;
    ::CloseHandle(reinterpret_cast<HANDLE>(h));
    errno_out = 0;
    return true;
}

// ============================================================
// Device skeleton
// ============================================================

P9Device::P9Device(whp::GuestMemory& mem, P9Share share, IrqFn irq)
    : queue_(mem, kP9QueueMax),
      share_(std::move(share)),
      irq_(std::move(irq)) {
    share_root_norm_ = NormalizeForContainment(share_.host_root);
    config_bytes_    = BuildConfigBytes(share_.tag);
}

P9Device::~P9Device() {
    std::lock_guard<std::mutex> lk(fids_mu_);
    fids_.clear();
}

std::uint64_t P9Device::DeviceFeatures() const {
    return kFeatureVersion1 | kFeatureRingEventIdx |
           kFeatureRingIndirectDesc | kP9FeatureMountTag;
}

bool P9Device::SetDriverFeatures(std::uint64_t acked) {
    if (!(acked & kFeatureVersion1)) return false;
    if (acked & ~DeviceFeatures())   return false;
    acked_features_ = acked;
    return true;
}

std::uint32_t P9Device::QueueMax(std::uint32_t idx) const {
    return idx == kP9RequestQueueIdx ? kP9QueueMax : 0;
}

Virtqueue* P9Device::GetQueue(std::uint32_t idx) {
    return idx == kP9RequestQueueIdx ? &queue_ : nullptr;
}

void P9Device::NotifyQueue(std::uint32_t idx) {
    if (idx != kP9RequestQueueIdx) return;
    if (!queue_.ready()) return;
    std::lock_guard<std::mutex> lk(notify_mu_);
    DrainRequestQueue();
}

void P9Device::Reset() {
    driver_ok_        = false;
    acked_features_   = 0;
    negotiated_msize_ = 0;
    std::lock_guard<std::mutex> lk(fids_mu_);
    fids_.clear();
}

std::uint32_t P9Device::ReadConfig(std::uint32_t offset, std::uint32_t size) {
    std::uint32_t v = 0;
    for (std::uint32_t i = 0; i < size; ++i) {
        std::uint32_t o = offset + i;
        if (o < config_bytes_.size()) {
            v |= static_cast<std::uint32_t>(config_bytes_[o]) << (i * 8);
        }
    }
    return v;
}

std::uint64_t P9Device::fids_size() noexcept {
    std::lock_guard<std::mutex> lk(fids_mu_);
    return fids_.size();
}

std::vector<std::uint8_t> P9Device::BuildConfigBytes(const std::string& tag) {
    std::vector<std::uint8_t> b;
    std::size_t n = tag.size();
    if (n > 0xFFFF) n = 0xFFFF;
    b.push_back(static_cast<std::uint8_t>(n));
    b.push_back(static_cast<std::uint8_t>(n >> 8));
    for (std::size_t i = 0; i < n; ++i) {
        b.push_back(static_cast<std::uint8_t>(tag[i]));
    }
    return b;
}

// ============================================================
// Chain I/O
// ============================================================

std::vector<std::uint8_t> P9Device::ReadChain(const std::vector<ChainBuf>& bufs) {
    std::vector<std::uint8_t> out;
    std::size_t total = 0;
    for (const auto& b : bufs) if (!b.write) total += b.bytes.size();
    out.reserve(total);
    for (const auto& b : bufs) {
        if (b.write) continue;
        out.insert(out.end(), b.bytes.data(),
                    b.bytes.data() + b.bytes.size());
    }
    return out;
}

std::uint32_t P9Device::WriteChain(std::vector<ChainBuf>& bufs,
                                     const std::vector<std::uint8_t>& reply) {
    std::size_t off = 0;
    for (auto& b : bufs) {
        if (!b.write) continue;
        if (off >= reply.size()) break;
        std::size_t n = std::min(b.bytes.size(), reply.size() - off);
        if (n > 0) std::memcpy(b.bytes.data(), reply.data() + off, n);
        off += n;
    }
    return static_cast<std::uint32_t>(off);
}

std::uint32_t P9Device::WritableCapacity(const std::vector<ChainBuf>& bufs) {
    std::size_t total = 0;
    for (const auto& b : bufs) if (b.write) total += b.bytes.size();
    return total > 0xFFFFFFFFu ? 0xFFFFFFFFu
                               : static_cast<std::uint32_t>(total);
}

void P9Device::BuildRlerror(std::vector<std::uint8_t>& reply,
                              std::uint16_t tag, std::uint32_t ecode) {
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RLerror);
    Encode2(reply, tag);
    Encode4(reply, ecode);
    FinalizeMessage(reply);
}

void P9Device::BuildHeaderOnly(std::vector<std::uint8_t>& reply,
                                 std::uint8_t reply_type, std::uint16_t tag) {
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, reply_type);
    Encode2(reply, tag);
    FinalizeMessage(reply);
}

// ============================================================
// Drain + dispatch
// ============================================================

void P9Device::DrainRequestQueue() {
    bool any = false;
    while (auto chain = queue_.Pop()) {
        std::vector<std::uint8_t> t_msg = ReadChain(chain->bufs);
        std::uint32_t cap = WritableCapacity(chain->bufs);
        std::vector<std::uint8_t> reply;
        DispatchMessage(t_msg, reply, cap);
        std::uint32_t written = WriteChain(chain->bufs, reply);
        queue_.Push(chain->head_index, written);
        any = true;
    }
    if (any && irq_ && queue_.ShouldInterruptDriver()) {
        irq_(kP9RequestQueueIdx);
    }
}

void P9Device::DispatchMessage(const std::vector<std::uint8_t>& t_msg,
                                 std::vector<std::uint8_t>&       reply,
                                 std::uint32_t                    writable_cap) {
    requests_.fetch_add(1, std::memory_order_relaxed);
    if (t_msg.size() < kReplyHeaderSize) {
        BuildRlerror(reply, 0, kP9Eproto);
        rlerrors_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    std::uint8_t  type = t_msg[4];
    std::uint16_t tag  = static_cast<std::uint16_t>(t_msg[5]) |
                         (static_cast<std::uint16_t>(t_msg[6]) << 8);
    std::vector<std::uint8_t> body(t_msg.begin() + kReplyHeaderSize,
                                    t_msg.end());

    std::uint32_t effective_cap = writable_cap;
    if (negotiated_msize_ != 0 && negotiated_msize_ < effective_cap) {
        effective_cap = negotiated_msize_;
    }

    switch (type) {
        case kP9TVersion:  HandleTversion (tag, body, reply, effective_cap); break;
        case kP9TAttach:   HandleTattach  (tag, body, reply, effective_cap); break;
        case kP9TWalk:     HandleTwalk    (tag, body, reply, effective_cap); break;
        case kP9TLopen:    HandleTlopen   (tag, body, reply, effective_cap); break;
        case kP9TLcreate:  HandleTlcreate (tag, body, reply, effective_cap); break;
        case kP9TRead:     HandleTread    (tag, body, reply, effective_cap); break;
        case kP9TWrite:    HandleTwrite   (tag, body, reply, effective_cap); break;
        case kP9TReaddir:  HandleTreaddir (tag, body, reply, effective_cap); break;
        case kP9TGetattr:  HandleTgetattr (tag, body, reply, effective_cap); break;
        case kP9TSetattr:  HandleTsetattr (tag, body, reply, effective_cap); break;
        case kP9TClunk:    HandleTclunk   (tag, body, reply, effective_cap); break;
        case kP9TRemove:   HandleTremove  (tag, body, reply, effective_cap); break;
        case kP9TFsync:    HandleTfsync   (tag, body, reply, effective_cap); break;
        case kP9TFlush:    HandleTflush   (tag, body, reply, effective_cap); break;
        case kP9TMkdir:    HandleTmkdir   (tag, body, reply, effective_cap); break;
        case kP9TRename:   HandleTrename  (tag, body, reply, effective_cap); break;
        case kP9TRenameat: HandleTrenameat(tag, body, reply, effective_cap); break;
        case kP9TUnlinkat: HandleTunlinkat(tag, body, reply, effective_cap); break;
        case kP9TStatfs:   HandleTstatfs  (tag, body, reply, effective_cap); break;
        default:
            BuildRlerror(reply, tag, kP9Enosys);
            break;
    }
    if (reply.size() >= 5 && reply[4] == kP9RLerror) {
        rlerrors_.fetch_add(1, std::memory_order_relaxed);
    }
}

std::vector<std::uint8_t> P9Device::InjectMessage(
    const std::vector<std::uint8_t>& full_t_msg) {
    std::vector<std::uint8_t> reply;
    DispatchMessage(full_t_msg, reply,
                    negotiated_msize_ ? negotiated_msize_ : kP9MsizeMax);
    return reply;
}

// ============================================================
// T-message handlers
// ============================================================

void P9Device::HandleTversion(std::uint16_t tag,
                                const std::vector<std::uint8_t>& body,
                                std::vector<std::uint8_t>& reply,
                                std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t msize_req;
    std::string   version;
    if (!Decode4(body, off, msize_req) ||
        !DecodeString(body, off, version)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        fids_.clear();
    }
    std::uint32_t agreed = msize_req;
    if (agreed > kP9MsizeMax) agreed = kP9MsizeMax;
    if (agreed < kP9MsizeMin) agreed = kP9MsizeMin;
    negotiated_msize_ = agreed;

    std::string resp_version =
        (version == "9P2000.L") ? std::string("9P2000.L") : std::string("unknown");

    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RVersion);
    Encode2(reply, tag);
    Encode4(reply, agreed);
    EncodeString(reply, resp_version);
    FinalizeMessage(reply);
}

void P9Device::HandleTattach(std::uint16_t tag,
                                const std::vector<std::uint8_t>& body,
                                std::vector<std::uint8_t>& reply,
                                std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid, afid;
    std::string   uname, aname;
    std::uint32_t n_uname;
    if (!Decode4(body, off, fid)   || !Decode4(body, off, afid)   ||
        !DecodeString(body, off, uname) ||
        !DecodeString(body, off, aname) ||
        !Decode4(body, off, n_uname)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    (void)uname; (void)n_uname;
    if (afid != kP9NoFid) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    if (!aname.empty() && aname != "/" && aname != share_.tag) {
        BuildRlerror(reply, tag, kP9Enoent);
        return;
    }
    std::uint8_t qt = 0;
    std::uint64_t qp = 0;
    bool is_dir = false;
    std::uint32_t err = 0;
    if (!StatPathForFid(share_.host_root, qt, qp, is_dir, err)) {
        BuildRlerror(reply, tag, err);
        return;
    }
    if (!is_dir) {
        BuildRlerror(reply, tag, kP9Enotdir);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        FidEntry e;
        e.host_path = share_.host_root;
        e.is_dir    = true;
        e.qid_path  = qp;
        fids_[fid]  = std::move(e);
    }
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RAttach);
    Encode2(reply, tag);
    EncodeQid(reply, qt, 0, qp);
    FinalizeMessage(reply);
}

void P9Device::HandleTwalk(std::uint16_t tag,
                            const std::vector<std::uint8_t>& body,
                            std::vector<std::uint8_t>& reply,
                            std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid, newfid;
    std::uint16_t nwname;
    if (!Decode4(body, off, fid) || !Decode4(body, off, newfid) ||
        !Decode2(body, off, nwname)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    if (nwname > kMaxWalkNames) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    std::vector<std::string> wnames;
    wnames.reserve(nwname);
    for (std::uint16_t i = 0; i < nwname; ++i) {
        std::string s;
        if (!DecodeString(body, off, s)) {
            BuildRlerror(reply, tag, kP9Eproto);
            return;
        }
        wnames.push_back(std::move(s));
    }

    std::filesystem::path src_path;
    bool src_is_dir = false;
    std::uint64_t src_qid_path = 0;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) {
            BuildRlerror(reply, tag, kP9Ebadf);
            return;
        }
        if (it->second.opened) {
            BuildRlerror(reply, tag, kP9Einval);
            return;
        }
        src_path     = it->second.host_path;
        src_is_dir   = it->second.is_dir;
        src_qid_path = it->second.qid_path;
        if (newfid != fid) {
            if (fids_.find(newfid) != fids_.end()) {
                BuildRlerror(reply, tag, kP9Einval);
                return;
            }
        }
    }

    if (nwname == 0) {
        FidEntry e;
        e.host_path = src_path;
        e.is_dir    = src_is_dir;
        e.qid_path  = src_qid_path;
        {
            std::lock_guard<std::mutex> lk(fids_mu_);
            fids_[newfid] = std::move(e);
        }
        reply.clear();
        Encode4(reply, 0);
        Encode1(reply, kP9RWalk);
        Encode2(reply, tag);
        Encode2(reply, 0);
        FinalizeMessage(reply);
        return;
    }

    if (!src_is_dir) {
        BuildRlerror(reply, tag, kP9Enotdir);
        return;
    }

    std::filesystem::path cur = src_path;
    std::vector<std::pair<std::uint8_t, std::uint64_t>> qids;
    qids.reserve(nwname);

    for (std::uint16_t i = 0; i < nwname; ++i) {
        const auto& name = wnames[i];
        std::filesystem::path next;
        if (name == ".") {
            next = cur;
        } else if (name == "..") {
            if (NormalizeForContainment(cur) == share_root_norm_) {
                next = cur;
            } else {
                next = cur.parent_path();
                if (!PathContained(next)) {
                    next = share_.host_root;
                }
            }
        } else {
            if (!IsSafeNameComponent(name)) {
                if (i == 0) {
                    BuildRlerror(reply, tag, kP9Enoent);
                    return;
                }
                break;
            }
            next = JoinChild(cur, name);
            if (!PathContained(next)) {
                if (i == 0) {
                    BuildRlerror(reply, tag, kP9Enoent);
                    return;
                }
                break;
            }
        }
        std::uint8_t qt = 0;
        std::uint64_t qp = 0;
        bool isd = false;
        std::uint32_t err = 0;
        if (!StatPathForFid(next, qt, qp, isd, err)) {
            if (i == 0) {
                BuildRlerror(reply, tag, err);
                return;
            }
            break;
        }
        if (!isd && i + 1 < nwname) {
            if (i == 0) {
                BuildRlerror(reply, tag, kP9Enotdir);
                return;
            }
            break;
        }
        qids.emplace_back(qt, qp);
        cur = next;
    }

    if (qids.size() == nwname) {
        auto [qt, qp] = qids.back();
        FidEntry e;
        e.host_path = cur;
        e.is_dir    = (qt & kP9QTDir) != 0;
        e.qid_path  = qp;
        {
            std::lock_guard<std::mutex> lk(fids_mu_);
            fids_[newfid] = std::move(e);
        }
    }

    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RWalk);
    Encode2(reply, tag);
    Encode2(reply, static_cast<std::uint16_t>(qids.size()));
    for (auto& qe : qids) {
        EncodeQid(reply, qe.first, 0, qe.second);
    }
    FinalizeMessage(reply);
}

void P9Device::HandleTlopen(std::uint16_t tag,
                             const std::vector<std::uint8_t>& body,
                             std::vector<std::uint8_t>& reply,
                             std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid, flags;
    if (!Decode4(body, off, fid) || !Decode4(body, off, flags)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    std::filesystem::path host_path;
    bool is_dir = false;
    std::uint64_t qid_path = 0;
    bool already_open = false;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        host_path    = it->second.host_path;
        is_dir       = it->second.is_dir;
        qid_path     = it->second.qid_path;
        already_open = it->second.opened;
    }
    if (already_open) { BuildRlerror(reply, tag, kP9Einval); return; }

    std::uint32_t acc        = flags & kP9OAccmode;
    bool want_write          = (acc != kP9ORdonly);
    bool want_trunc          = (flags & kP9OTrunc) != 0;
    bool want_append         = (flags & kP9OAppend) != 0;
    bool want_dir            = (flags & kP9ODirectory) != 0;

    if (want_dir && !is_dir) { BuildRlerror(reply, tag, kP9Enotdir); return; }
    if (share_.readonly && (want_write || want_trunc)) {
        BuildRlerror(reply, tag, kP9Erofs);
        return;
    }

    DWORD access = 0;
    if (is_dir) {
        access = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES;
    } else {
        switch (acc) {
            case kP9ORdonly:
                access = GENERIC_READ;
                break;
            case kP9OWronly:
                access = want_append
                            ? (FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                               FILE_READ_ATTRIBUTES)
                            : GENERIC_WRITE;
                break;
            case kP9ORdwr:
                access = GENERIC_READ |
                          (want_append
                              ? (FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES)
                              : GENERIC_WRITE);
                break;
            default:
                BuildRlerror(reply, tag, kP9Einval);
                return;
        }
    }
    DWORD disposition = OPEN_EXISTING;
    if (want_trunc && !is_dir) disposition = TRUNCATE_EXISTING;
    DWORD flags_attr =
        is_dir ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;

    auto wp = ToWin32LongPath(host_path);
    HANDLE h = CreateFileW(wp.c_str(), access,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, disposition, flags_attr, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        BuildRlerror(reply, tag, Win32ErrnoToP9(GetLastError()));
        return;
    }

    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) {
            ::CloseHandle(h);
            BuildRlerror(reply, tag, kP9Ebadf);
            return;
        }
        if (it->second.opened) {
            ::CloseHandle(h);
            BuildRlerror(reply, tag, kP9Einval);
            return;
        }
        it->second.handle     = h;
        it->second.opened     = true;
        it->second.open_flags = flags;
    }

    std::uint8_t qt = is_dir ? kP9QTDir : kP9QTFile;
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RLopen);
    Encode2(reply, tag);
    EncodeQid(reply, qt, 0, qid_path);
    Encode4(reply, 0);  // iounit
    FinalizeMessage(reply);
}

void P9Device::HandleTlcreate(std::uint16_t tag,
                                const std::vector<std::uint8_t>& body,
                                std::vector<std::uint8_t>& reply,
                                std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid;
    std::string   name;
    std::uint32_t flags, mode, gid;
    if (!Decode4(body, off, fid) ||
        !DecodeString(body, off, name) ||
        !Decode4(body, off, flags) ||
        !Decode4(body, off, mode) ||
        !Decode4(body, off, gid)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    (void)mode; (void)gid;
    if (share_.readonly) { BuildRlerror(reply, tag, kP9Erofs); return; }
    if (!IsSafeNameComponent(name)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    std::filesystem::path parent_path;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        if (!it->second.is_dir) { BuildRlerror(reply, tag, kP9Enotdir); return; }
        if (it->second.opened) { BuildRlerror(reply, tag, kP9Einval); return; }
        parent_path = it->second.host_path;
    }
    auto new_path = JoinChild(parent_path, name);
    if (!PathContained(new_path)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }

    std::uint32_t acc        = flags & kP9OAccmode;
    bool want_append         = (flags & kP9OAppend) != 0;
    DWORD access             = GENERIC_WRITE | FILE_READ_ATTRIBUTES;
    if (acc == kP9ORdwr || acc == kP9ORdonly) access |= GENERIC_READ;
    if (want_append) {
        access = (access & ~GENERIC_WRITE) | FILE_APPEND_DATA |
                  FILE_WRITE_ATTRIBUTES;
    }

    DWORD disposition;
    bool excl  = (flags & kP9OExcl)  != 0;
    bool trunc = (flags & kP9OTrunc) != 0;
    if (excl)        disposition = CREATE_NEW;
    else if (trunc)  disposition = CREATE_ALWAYS;
    else             disposition = OPEN_ALWAYS;

    auto wp = ToWin32LongPath(new_path);
    HANDLE h = CreateFileW(wp.c_str(), access,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, disposition,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        BuildRlerror(reply, tag, Win32ErrnoToP9(GetLastError()));
        return;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(h, &info)) {
        auto err = Win32ErrnoToP9(GetLastError());
        ::CloseHandle(h);
        BuildRlerror(reply, tag, err);
        return;
    }
    std::uint64_t qp =
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) |
        info.nFileIndexLow;
    if (qp == 0) qp = next_qid_path_++;

    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) {
            ::CloseHandle(h);
            BuildRlerror(reply, tag, kP9Ebadf);
            return;
        }
        it->second.host_path  = new_path;
        it->second.is_dir     = false;
        it->second.qid_path   = qp;
        it->second.handle     = h;
        it->second.opened     = true;
        it->second.open_flags = flags;
    }
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RLcreate);
    Encode2(reply, tag);
    EncodeQid(reply, kP9QTFile, 0, qp);
    Encode4(reply, 0);  // iounit
    FinalizeMessage(reply);
}

void P9Device::HandleTread(std::uint16_t tag,
                            const std::vector<std::uint8_t>& body,
                            std::vector<std::uint8_t>& reply,
                            std::uint32_t cap) {
    std::size_t off = 0;
    std::uint32_t fid;
    std::uint64_t offset;
    std::uint32_t count;
    if (!Decode4(body, off, fid) ||
        !Decode8(body, off, offset) ||
        !Decode4(body, off, count)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    HANDLE h = nullptr;
    bool opened = false;
    bool is_dir = false;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        h      = reinterpret_cast<HANDLE>(it->second.handle);
        opened = it->second.opened;
        is_dir = it->second.is_dir;
    }
    if (!opened || h == nullptr || h == INVALID_HANDLE_VALUE) {
        BuildRlerror(reply, tag, kP9Ebadf);
        return;
    }
    if (is_dir) {
        BuildRlerror(reply, tag, kP9Eisdir);
        return;
    }
    std::uint32_t max_payload = cap > kRreadHeaderSize
                                   ? (cap - kRreadHeaderSize)
                                   : 0;
    if (count > max_payload) count = max_payload;

    std::vector<std::uint8_t> data(count);
    DWORD got = 0;
    if (count > 0) {
        OVERLAPPED ov = {};
        ov.Offset     = static_cast<DWORD>(offset & 0xFFFFFFFFu);
        ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
        BOOL ok = ReadFile(h, data.data(), count, &got, &ov);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF) {
                got = 0;
            } else {
                BuildRlerror(reply, tag, Win32ErrnoToP9(err));
                return;
            }
        }
    }
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RRead);
    Encode2(reply, tag);
    Encode4(reply, got);
    reply.insert(reply.end(), data.begin(), data.begin() + got);
    FinalizeMessage(reply);
}

void P9Device::HandleTwrite(std::uint16_t tag,
                              const std::vector<std::uint8_t>& body,
                              std::vector<std::uint8_t>& reply,
                              std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid;
    std::uint64_t offset;
    std::uint32_t count;
    if (!Decode4(body, off, fid) ||
        !Decode8(body, off, offset) ||
        !Decode4(body, off, count)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    if (off + count > body.size()) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    if (share_.readonly) {
        BuildRlerror(reply, tag, kP9Erofs);
        return;
    }
    HANDLE h = nullptr;
    bool opened = false;
    bool is_dir = false;
    std::uint32_t open_flags = 0;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        h         = reinterpret_cast<HANDLE>(it->second.handle);
        opened    = it->second.opened;
        is_dir    = it->second.is_dir;
        open_flags = it->second.open_flags;
    }
    if (!opened || h == nullptr || h == INVALID_HANDLE_VALUE) {
        BuildRlerror(reply, tag, kP9Ebadf);
        return;
    }
    if (is_dir) {
        BuildRlerror(reply, tag, kP9Eisdir);
        return;
    }
    DWORD wrote = 0;
    if (count > 0) {
        OVERLAPPED ov = {};
        if (open_flags & kP9OAppend) {
            // FILE_APPEND_DATA semantics: offset ignored, write at EOF.
            ov.Offset     = 0xFFFFFFFFu;
            ov.OffsetHigh = 0xFFFFFFFFu;
        } else {
            ov.Offset     = static_cast<DWORD>(offset & 0xFFFFFFFFu);
            ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
        }
        BOOL ok = WriteFile(h, body.data() + off, count, &wrote, &ov);
        if (!ok) {
            BuildRlerror(reply, tag, Win32ErrnoToP9(GetLastError()));
            return;
        }
    }
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RWrite);
    Encode2(reply, tag);
    Encode4(reply, wrote);
    FinalizeMessage(reply);
}

void P9Device::HandleTreaddir(std::uint16_t tag,
                                const std::vector<std::uint8_t>& body,
                                std::vector<std::uint8_t>& reply,
                                std::uint32_t cap) {
    std::size_t off = 0;
    std::uint32_t fid;
    std::uint64_t req_offset;
    std::uint32_t count;
    if (!Decode4(body, off, fid) ||
        !Decode8(body, off, req_offset) ||
        !Decode4(body, off, count)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    std::filesystem::path dir_path;
    bool is_dir = false;
    bool opened = false;
    HANDLE h    = nullptr;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        dir_path = it->second.host_path;
        is_dir   = it->second.is_dir;
        opened   = it->second.opened;
        h        = reinterpret_cast<HANDLE>(it->second.handle);
    }
    if (!is_dir) { BuildRlerror(reply, tag, kP9Enotdir); return; }
    if (!opened || h == nullptr || h == INVALID_HANDLE_VALUE) {
        BuildRlerror(reply, tag, kP9Ebadf);
        return;
    }

    std::uint32_t max_payload =
        cap > kRreadHeaderSize ? (cap - kRreadHeaderSize) : 0;
    if (count > max_payload) count = max_payload;

    // (Re)build dir_cache on offset==0.
    if (req_offset == 0) {
        std::vector<FidEntry::DirEntryCached> cache;
        auto search_path = ToWin32LongPath(dir_path) + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE fh = FindFirstFileW(search_path.c_str(), &fd);
        if (fh == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND &&
                err != ERROR_NO_MORE_FILES) {
                BuildRlerror(reply, tag, Win32ErrnoToP9(err));
                return;
            }
        } else {
            do {
                std::wstring wname(fd.cFileName);
                std::string name = WideToUtf8(wname.c_str(), wname.size());
                if (name.empty()) continue;

                FidEntry::DirEntryCached ent;
                ent.name = name;
                bool dir_entry =
                    (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                ent.qid_type    = dir_entry ? kP9QTDir : kP9QTFile;
                ent.qid_version = 0;
                ent.d_type      = dir_entry ? kDtDir : kDtReg;

                std::filesystem::path child_path;
                if (name == ".") {
                    child_path = dir_path;
                } else if (name == "..") {
                    child_path = dir_path.parent_path();
                    if (!PathContained(child_path)) child_path = dir_path;
                } else {
                    child_path = JoinChild(dir_path, name);
                }
                std::uint8_t qt = 0;
                std::uint64_t qp = 0;
                bool isd = false;
                std::uint32_t serr = 0;
                if (StatPathForFid(child_path, qt, qp, isd, serr)) {
                    ent.qid_type = qt;
                    ent.qid_path = qp;
                    ent.d_type   = isd ? kDtDir : kDtReg;
                } else {
                    ent.qid_path = next_qid_path_++;
                }
                cache.push_back(std::move(ent));
            } while (FindNextFileW(fh, &fd));
            FindClose(fh);
        }
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it != fids_.end()) {
            it->second.dir_cache       = std::move(cache);
            it->second.dir_cache_built = true;
        }
    }

    std::vector<FidEntry::DirEntryCached> snapshot;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        snapshot = it->second.dir_cache;
    }

    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RReaddir);
    Encode2(reply, tag);
    std::size_t count_off = reply.size();
    Encode4(reply, 0);
    std::size_t start_payload = reply.size();

    std::size_t start_index =
        req_offset >= snapshot.size() ? snapshot.size()
                                       : static_cast<std::size_t>(req_offset);
    for (std::size_t i = start_index; i < snapshot.size(); ++i) {
        const auto& e = snapshot[i];
        std::size_t need = 13 + 8 + 1 + 2 + e.name.size();
        if ((reply.size() - start_payload) + need > max_payload) break;
        EncodeQid(reply, e.qid_type, e.qid_version, e.qid_path);
        Encode8(reply, static_cast<std::uint64_t>(i + 1));
        Encode1(reply, e.d_type);
        EncodeString(reply, e.name);
    }
    std::uint32_t payload_len =
        static_cast<std::uint32_t>(reply.size() - start_payload);
    reply[count_off + 0] = static_cast<std::uint8_t>(payload_len);
    reply[count_off + 1] = static_cast<std::uint8_t>(payload_len >> 8);
    reply[count_off + 2] = static_cast<std::uint8_t>(payload_len >> 16);
    reply[count_off + 3] = static_cast<std::uint8_t>(payload_len >> 24);
    FinalizeMessage(reply);
}

void P9Device::HandleTgetattr(std::uint16_t tag,
                                const std::vector<std::uint8_t>& body,
                                std::vector<std::uint8_t>& reply,
                                std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid;
    std::uint64_t request_mask;
    if (!Decode4(body, off, fid) || !Decode8(body, off, request_mask)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    std::filesystem::path path;
    bool was_open = false;
    HANDLE existing = nullptr;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        path     = it->second.host_path;
        was_open = it->second.opened;
        existing = reinterpret_cast<HANDLE>(it->second.handle);
    }
    HANDLE h = (was_open && existing != nullptr &&
                existing != INVALID_HANDLE_VALUE)
                   ? existing
                   : INVALID_HANDLE_VALUE;
    HANDLE opened_here = INVALID_HANDLE_VALUE;
    if (h == INVALID_HANDLE_VALUE) {
        unsigned long gle = 0;
        h = reinterpret_cast<HANDLE>(OpenForAttrs(path, gle));
        if (h == nullptr) {
            BuildRlerror(reply, tag, Win32ErrnoToP9(gle));
            return;
        }
        opened_here = h;
    }

    std::uint8_t qt = 0; std::uint32_t qv = 0; std::uint64_t qp = 0;
    std::uint32_t mode = 0;
    std::uint64_t nlink = 0, size = 0, blocks = 0;
    std::uint64_t atime_s = 0, atime_n = 0;
    std::uint64_t mtime_s = 0, mtime_n = 0;
    std::uint64_t ctime_s = 0, ctime_n = 0;
    std::uint32_t err = 0;
    bool ok = ReadAttrsByHandle(h, qt, qv, qp, mode, nlink, size, blocks,
                                  atime_s, atime_n,
                                  mtime_s, mtime_n,
                                  ctime_s, ctime_n, err);
    if (opened_here != INVALID_HANDLE_VALUE) ::CloseHandle(opened_here);
    if (!ok) {
        BuildRlerror(reply, tag, err);
        return;
    }
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RGetattr);
    Encode2(reply, tag);
    Encode8(reply, kP9StatsBasic & request_mask);
    EncodeQid(reply, qt, qv, qp);
    Encode4(reply, mode);
    Encode4(reply, 0);          // uid
    Encode4(reply, 0);          // gid
    Encode8(reply, nlink);
    Encode8(reply, 0);          // rdev
    Encode8(reply, size);
    Encode8(reply, 4096);       // blksize
    Encode8(reply, blocks);
    Encode8(reply, atime_s); Encode8(reply, atime_n);
    Encode8(reply, mtime_s); Encode8(reply, mtime_n);
    Encode8(reply, ctime_s); Encode8(reply, ctime_n);
    Encode8(reply, 0); Encode8(reply, 0);   // btime
    Encode8(reply, 0);          // gen
    Encode8(reply, 0);          // data_version
    FinalizeMessage(reply);
}

void P9Device::HandleTsetattr(std::uint16_t tag,
                                const std::vector<std::uint8_t>& body,
                                std::vector<std::uint8_t>& reply,
                                std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid, valid, mode, uid, gid;
    std::uint64_t sz, atime_s, atime_n, mtime_s, mtime_n;
    if (!Decode4(body, off, fid)       || !Decode4(body, off, valid) ||
        !Decode4(body, off, mode)      || !Decode4(body, off, uid)   ||
        !Decode4(body, off, gid)       || !Decode8(body, off, sz)    ||
        !Decode8(body, off, atime_s)   || !Decode8(body, off, atime_n) ||
        !Decode8(body, off, mtime_s)   || !Decode8(body, off, mtime_n)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    (void)mode; (void)uid; (void)gid;
    if (share_.readonly) { BuildRlerror(reply, tag, kP9Erofs); return; }

    std::filesystem::path path;
    HANDLE existing = nullptr;
    bool was_open = false;
    bool is_dir = false;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        path     = it->second.host_path;
        was_open = it->second.opened;
        existing = reinterpret_cast<HANDLE>(it->second.handle);
        is_dir   = it->second.is_dir;
    }

    HANDLE h = existing;
    HANDLE opened_here = INVALID_HANDLE_VALUE;
    bool need_size = (valid & kP9SetattrSize) != 0;
    bool need_handle = need_size || !was_open ||
                        h == nullptr || h == INVALID_HANDLE_VALUE;
    if (need_handle) {
        DWORD access = FILE_WRITE_ATTRIBUTES;
        if (need_size) access |= GENERIC_WRITE;
        DWORD attr =
            is_dir ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
        auto wp = ToWin32LongPath(path);
        HANDLE nh = CreateFileW(wp.c_str(), access,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, attr, nullptr);
        if (nh == INVALID_HANDLE_VALUE) {
            BuildRlerror(reply, tag, Win32ErrnoToP9(GetLastError()));
            return;
        }
        h = nh;
        opened_here = nh;
    }

    if (valid & kP9SetattrSize) {
        LARGE_INTEGER li; li.QuadPart = static_cast<LONGLONG>(sz);
        if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN) ||
            !SetEndOfFile(h)) {
            auto err = Win32ErrnoToP9(GetLastError());
            if (opened_here != INVALID_HANDLE_VALUE) ::CloseHandle(opened_here);
            BuildRlerror(reply, tag, err);
            return;
        }
    }
    if (valid & (kP9SetattrAtime | kP9SetattrMtime)) {
        FILETIME a_ft = {}, m_ft = {};
        FILETIME* pa = nullptr;
        FILETIME* pm = nullptr;
        if (valid & kP9SetattrAtime) {
            if (valid & kP9SetattrAtimeSet)
                UnixToFileTime(atime_s, atime_n, a_ft);
            else
                GetSystemTimeAsFileTime(&a_ft);
            pa = &a_ft;
        }
        if (valid & kP9SetattrMtime) {
            if (valid & kP9SetattrMtimeSet)
                UnixToFileTime(mtime_s, mtime_n, m_ft);
            else
                GetSystemTimeAsFileTime(&m_ft);
            pm = &m_ft;
        }
        if (!SetFileTime(h, nullptr, pa, pm)) {
            auto err = Win32ErrnoToP9(GetLastError());
            if (opened_here != INVALID_HANDLE_VALUE) ::CloseHandle(opened_here);
            BuildRlerror(reply, tag, err);
            return;
        }
    }
    if (opened_here != INVALID_HANDLE_VALUE) ::CloseHandle(opened_here);
    BuildHeaderOnly(reply, kP9RSetattr, tag);
}

void P9Device::HandleTclunk(std::uint16_t tag,
                              const std::vector<std::uint8_t>& body,
                              std::vector<std::uint8_t>& reply,
                              std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid;
    if (!Decode4(body, off, fid)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) {
            BuildRlerror(reply, tag, kP9Ebadf);
            return;
        }
        fids_.erase(it);
    }
    BuildHeaderOnly(reply, kP9RClunk, tag);
}

void P9Device::HandleTremove(std::uint16_t tag,
                               const std::vector<std::uint8_t>& body,
                               std::vector<std::uint8_t>& reply,
                               std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid;
    if (!Decode4(body, off, fid)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    std::filesystem::path path;
    bool is_dir = false;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) {
            BuildRlerror(reply, tag, kP9Ebadf);
            return;
        }
        path   = it->second.host_path;
        is_dir = it->second.is_dir;
        it->second.CloseHandle();
        fids_.erase(it);
        found = true;
    }
    (void)found;
    if (share_.readonly) {
        BuildRlerror(reply, tag, kP9Erofs);
        return;
    }
    if (NormalizeForContainment(path) == share_root_norm_) {
        BuildRlerror(reply, tag, kP9Eacces);
        return;
    }
    auto wp = ToWin32LongPath(path);
    BOOL ok = is_dir ? RemoveDirectoryW(wp.c_str())
                      : DeleteFileW(wp.c_str());
    if (!ok) {
        BuildRlerror(reply, tag, Win32ErrnoToP9(GetLastError()));
        return;
    }
    BuildHeaderOnly(reply, kP9RRemove, tag);
}

void P9Device::HandleTfsync(std::uint16_t tag,
                              const std::vector<std::uint8_t>& body,
                              std::vector<std::uint8_t>& reply,
                              std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid;
    std::uint32_t datasync;
    if (!Decode4(body, off, fid) || !Decode4(body, off, datasync)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    (void)datasync;
    HANDLE h = nullptr;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        h = reinterpret_cast<HANDLE>(it->second.handle);
    }
    if (h != nullptr && h != INVALID_HANDLE_VALUE) {
        if (!FlushFileBuffers(h)) {
            DWORD err = GetLastError();
            if (err != ERROR_ACCESS_DENIED && err != ERROR_INVALID_HANDLE) {
                BuildRlerror(reply, tag, Win32ErrnoToP9(err));
                return;
            }
        }
    }
    BuildHeaderOnly(reply, kP9RFsync, tag);
}

void P9Device::HandleTflush(std::uint16_t tag,
                              const std::vector<std::uint8_t>& body,
                              std::vector<std::uint8_t>& reply,
                              std::uint32_t cap) {
    (void)cap; (void)body;
    BuildHeaderOnly(reply, kP9RFlush, tag);
}

void P9Device::HandleTmkdir(std::uint16_t tag,
                              const std::vector<std::uint8_t>& body,
                              std::vector<std::uint8_t>& reply,
                              std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t dfid;
    std::string   name;
    std::uint32_t mode, gid;
    if (!Decode4(body, off, dfid) ||
        !DecodeString(body, off, name) ||
        !Decode4(body, off, mode) ||
        !Decode4(body, off, gid)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    (void)mode; (void)gid;
    if (share_.readonly) { BuildRlerror(reply, tag, kP9Erofs); return; }
    if (!IsSafeNameComponent(name)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    std::filesystem::path parent;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(dfid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        if (!it->second.is_dir) { BuildRlerror(reply, tag, kP9Enotdir); return; }
        parent = it->second.host_path;
    }
    auto new_path = JoinChild(parent, name);
    if (!PathContained(new_path)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    auto wp = ToWin32LongPath(new_path);
    if (!CreateDirectoryW(wp.c_str(), nullptr)) {
        BuildRlerror(reply, tag, Win32ErrnoToP9(GetLastError()));
        return;
    }
    std::uint8_t qt = 0;
    std::uint64_t qp = 0;
    bool isd = false;
    std::uint32_t err = 0;
    if (!StatPathForFid(new_path, qt, qp, isd, err)) {
        BuildRlerror(reply, tag, err);
        return;
    }
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RMkdir);
    Encode2(reply, tag);
    EncodeQid(reply, qt, 0, qp);
    FinalizeMessage(reply);
}

void P9Device::HandleTrename(std::uint16_t tag,
                               const std::vector<std::uint8_t>& body,
                               std::vector<std::uint8_t>& reply,
                               std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid, dfid;
    std::string   name;
    if (!Decode4(body, off, fid)  || !Decode4(body, off, dfid) ||
        !DecodeString(body, off, name)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    if (share_.readonly) { BuildRlerror(reply, tag, kP9Erofs); return; }
    if (!IsSafeNameComponent(name)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    std::filesystem::path old_path;
    std::filesystem::path new_parent;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto itf = fids_.find(fid);
        auto itd = fids_.find(dfid);
        if (itf == fids_.end() || itd == fids_.end()) {
            BuildRlerror(reply, tag, kP9Ebadf);
            return;
        }
        if (!itd->second.is_dir) {
            BuildRlerror(reply, tag, kP9Enotdir);
            return;
        }
        old_path   = itf->second.host_path;
        new_parent = itd->second.host_path;
        // Drop any open handle on the source so MoveFileExW can proceed.
        itf->second.CloseHandle();
    }
    auto new_path = JoinChild(new_parent, name);
    if (!PathContained(new_path)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    auto wold = ToWin32LongPath(old_path);
    auto wnew = ToWin32LongPath(new_path);
    if (!MoveFileExW(wold.c_str(), wnew.c_str(),
                      MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
        BuildRlerror(reply, tag, Win32ErrnoToP9(GetLastError()));
        return;
    }
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto itf = fids_.find(fid);
        if (itf != fids_.end()) {
            itf->second.host_path = new_path;
        }
    }
    BuildHeaderOnly(reply, kP9RRename, tag);
}

void P9Device::HandleTrenameat(std::uint16_t tag,
                                 const std::vector<std::uint8_t>& body,
                                 std::vector<std::uint8_t>& reply,
                                 std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t old_dirfid, new_dirfid;
    std::string   old_name, new_name;
    if (!Decode4(body, off, old_dirfid) ||
        !DecodeString(body, off, old_name) ||
        !Decode4(body, off, new_dirfid) ||
        !DecodeString(body, off, new_name)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    if (share_.readonly) { BuildRlerror(reply, tag, kP9Erofs); return; }
    if (!IsSafeNameComponent(old_name) || !IsSafeNameComponent(new_name)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    std::filesystem::path old_dir, new_dir;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto ito = fids_.find(old_dirfid);
        auto itn = fids_.find(new_dirfid);
        if (ito == fids_.end() || itn == fids_.end()) {
            BuildRlerror(reply, tag, kP9Ebadf);
            return;
        }
        if (!ito->second.is_dir || !itn->second.is_dir) {
            BuildRlerror(reply, tag, kP9Enotdir);
            return;
        }
        old_dir = ito->second.host_path;
        new_dir = itn->second.host_path;
    }
    auto old_path = JoinChild(old_dir, old_name);
    auto new_path = JoinChild(new_dir, new_name);
    if (!PathContained(old_path) || !PathContained(new_path)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    auto wold = ToWin32LongPath(old_path);
    auto wnew = ToWin32LongPath(new_path);
    if (!MoveFileExW(wold.c_str(), wnew.c_str(),
                      MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
        BuildRlerror(reply, tag, Win32ErrnoToP9(GetLastError()));
        return;
    }
    BuildHeaderOnly(reply, kP9RRenameat, tag);
}

void P9Device::HandleTunlinkat(std::uint16_t tag,
                                 const std::vector<std::uint8_t>& body,
                                 std::vector<std::uint8_t>& reply,
                                 std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t dirfid;
    std::string   name;
    std::uint32_t flags;
    if (!Decode4(body, off, dirfid) ||
        !DecodeString(body, off, name) ||
        !Decode4(body, off, flags)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    if (share_.readonly) { BuildRlerror(reply, tag, kP9Erofs); return; }
    if (!IsSafeNameComponent(name)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    std::filesystem::path parent;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(dirfid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        if (!it->second.is_dir) { BuildRlerror(reply, tag, kP9Enotdir); return; }
        parent = it->second.host_path;
    }
    auto target = JoinChild(parent, name);
    if (!PathContained(target)) {
        BuildRlerror(reply, tag, kP9Einval);
        return;
    }
    auto wp = ToWin32LongPath(target);
    BOOL ok = (flags & kP9AtRemoveDir) ? RemoveDirectoryW(wp.c_str())
                                          : DeleteFileW(wp.c_str());
    if (!ok) {
        DWORD err = GetLastError();
        // Linux's unlinkat without AT_REMOVEDIR on a directory should
        // return EISDIR; DeleteFileW returns ERROR_ACCESS_DENIED in that
        // case. Translate explicitly.
        if (!(flags & kP9AtRemoveDir) && err == ERROR_ACCESS_DENIED) {
            DWORD attrs = GetFileAttributesW(wp.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES &&
                (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                BuildRlerror(reply, tag, kP9Eisdir);
                return;
            }
        }
        BuildRlerror(reply, tag, Win32ErrnoToP9(err));
        return;
    }
    BuildHeaderOnly(reply, kP9RUnlinkat, tag);
}

void P9Device::HandleTstatfs(std::uint16_t tag,
                               const std::vector<std::uint8_t>& body,
                               std::vector<std::uint8_t>& reply,
                               std::uint32_t cap) {
    (void)cap;
    std::size_t off = 0;
    std::uint32_t fid;
    if (!Decode4(body, off, fid)) {
        BuildRlerror(reply, tag, kP9Eproto);
        return;
    }
    std::filesystem::path path;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) { BuildRlerror(reply, tag, kP9Ebadf); return; }
        path = it->second.host_path;
    }
    auto wp = ToWin32LongPath(path);
    // Ensure trailing backslash on the volume root for GetDiskFreeSpaceExW.
    ULARGE_INTEGER avail_to_caller = {};
    ULARGE_INTEGER total           = {};
    ULARGE_INTEGER free_bytes      = {};
    BOOL ok = GetDiskFreeSpaceExW(wp.c_str(), &avail_to_caller,
                                    &total, &free_bytes);
    std::uint64_t blocks_total = 1ULL << 20;
    std::uint64_t blocks_free  = 1ULL << 20;
    std::uint64_t blocks_avail = 1ULL << 20;
    constexpr std::uint64_t kBlockSize = 4096;
    if (ok) {
        blocks_total = total.QuadPart            / kBlockSize;
        blocks_free  = free_bytes.QuadPart       / kBlockSize;
        blocks_avail = avail_to_caller.QuadPart  / kBlockSize;
    }
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RStatfs);
    Encode2(reply, tag);
    Encode4(reply, kV9fsMagic);
    Encode4(reply, static_cast<std::uint32_t>(kBlockSize));
    Encode8(reply, blocks_total);
    Encode8(reply, blocks_free);
    Encode8(reply, blocks_avail);
    Encode8(reply, 0);          // files
    Encode8(reply, 0);          // ffree
    Encode8(reply, 0);          // fsid
    Encode4(reply, 255);        // namelen
    FinalizeMessage(reply);
}

}  // namespace tinyvmm::virtio
