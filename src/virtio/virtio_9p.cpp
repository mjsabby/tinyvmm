#include "virtio_9p.h"

#include <algorithm>
#include <cstring>

namespace tinyvmm::virtio {

namespace {

// 9P message header sizes. The 4B size + 1B type + 2B tag header is
// the same for every T- and R- message (spec §"protocol").
constexpr std::size_t kP9HdrBytes = 4 + 1 + 2;
// Maximum config space we expose -- u16 tag_len + up to 256B tag.
constexpr std::size_t kP9MaxTagLen = 256;

}  // namespace

// ---------------------------------------------------------------------------
// Construction / configuration
// ---------------------------------------------------------------------------

P9Device::P9Device(whp::GuestMemory& mem, P9Share share, IrqFn irq)
    : queue_(mem, kP9QueueMax),
      share_(std::move(share)),
      config_bytes_(BuildConfigBytes(share_.tag)),
      irq_(std::move(irq)) {}

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
    return idx == kP9RequestQueueIdx ? queue_.max_size() : 0;
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
    driver_ok_       = false;
    acked_features_  = 0;
    negotiated_msize_ = 0;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        fids_.clear();
        next_qid_path_ = 1;
    }
    // requests_/rlerrors_ are diagnostic counters; not cleared.
}

std::uint32_t P9Device::ReadConfig(std::uint32_t offset, std::uint32_t size) {
    if (size == 0 || size > 4) return 0;
    std::uint32_t v = 0;
    for (std::uint32_t i = 0; i < size; ++i) {
        const std::size_t pos = offset + i;
        const std::uint8_t b = pos < config_bytes_.size()
                                ? config_bytes_[pos]
                                : std::uint8_t{0};
        v |= static_cast<std::uint32_t>(b) << (8u * i);
    }
    return v;
}

// ---------------------------------------------------------------------------
// Wire en/decoders
// ---------------------------------------------------------------------------

void P9Device::Encode1(std::vector<std::uint8_t>& out, std::uint8_t v) {
    out.push_back(v);
}
void P9Device::Encode2(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
}
void P9Device::Encode4(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}
void P9Device::Encode8(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}
void P9Device::EncodeString(std::vector<std::uint8_t>& out,
                             const std::string& s) {
    // Spec: u16 length followed by raw bytes (no NUL terminator).
    // Cap at u16 to prevent overflow. Linux never sends more.
    const std::size_t n = std::min<std::size_t>(s.size(), 0xFFFF);
    Encode2(out, static_cast<std::uint16_t>(n));
    out.insert(out.end(), s.begin(), s.begin() + n);
}
void P9Device::EncodeQid(std::vector<std::uint8_t>& out,
                          std::uint8_t type, std::uint32_t version,
                          std::uint64_t path) {
    Encode1(out, type);
    Encode4(out, version);
    Encode8(out, path);
}
void P9Device::FinalizeMessage(std::vector<std::uint8_t>& out) {
    // Patch the 4-byte size header at offset 0.
    const std::uint32_t sz = static_cast<std::uint32_t>(out.size());
    out[0] = static_cast<std::uint8_t>( sz        & 0xFFu);
    out[1] = static_cast<std::uint8_t>((sz >>  8) & 0xFFu);
    out[2] = static_cast<std::uint8_t>((sz >> 16) & 0xFFu);
    out[3] = static_cast<std::uint8_t>((sz >> 24) & 0xFFu);
}

bool P9Device::Decode1(const std::vector<std::uint8_t>& in,
                        std::size_t& off, std::uint8_t& v) {
    if (off + 1 > in.size()) return false;
    v = in[off]; off += 1; return true;
}
bool P9Device::Decode2(const std::vector<std::uint8_t>& in,
                        std::size_t& off, std::uint16_t& v) {
    if (off + 2 > in.size()) return false;
    v = static_cast<std::uint16_t>(in[off] |
                                    (static_cast<std::uint16_t>(in[off + 1]) << 8));
    off += 2; return true;
}
bool P9Device::Decode4(const std::vector<std::uint8_t>& in,
                        std::size_t& off, std::uint32_t& v) {
    if (off + 4 > in.size()) return false;
    v = static_cast<std::uint32_t>(in[off]) |
        (static_cast<std::uint32_t>(in[off + 1]) << 8) |
        (static_cast<std::uint32_t>(in[off + 2]) << 16) |
        (static_cast<std::uint32_t>(in[off + 3]) << 24);
    off += 4; return true;
}
bool P9Device::DecodeString(const std::vector<std::uint8_t>& in,
                             std::size_t& off, std::string& s) {
    std::uint16_t len = 0;
    if (!Decode2(in, off, len)) return false;
    if (off + len > in.size())  return false;
    s.assign(reinterpret_cast<const char*>(in.data() + off), len);
    off += len; return true;
}

// ---------------------------------------------------------------------------
// Static config bytes (u16 tag_len + tag)
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> P9Device::BuildConfigBytes(const std::string& tag) {
    const std::size_t n = std::min(tag.size(), kP9MaxTagLen);
    std::vector<std::uint8_t> v;
    v.reserve(2 + n);
    v.push_back(static_cast<std::uint8_t>(n & 0xFFu));
    v.push_back(static_cast<std::uint8_t>((n >> 8) & 0xFFu));
    v.insert(v.end(), tag.begin(), tag.begin() + n);
    return v;
}

// ---------------------------------------------------------------------------
// Chain marshalling helpers
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> P9Device::ReadChain(
        const std::vector<ChainBuf>& bufs) {
    // Concatenate all device-readable buffers in order. The 1 MiB
    // msize cap bounds the total length, so growing into a vector
    // is safe.
    std::size_t total = 0;
    for (const auto& b : bufs) {
        if (!b.write) total += b.bytes.size();
    }
    std::vector<std::uint8_t> out;
    out.reserve(total);
    for (const auto& b : bufs) {
        if (!b.write) {
            out.insert(out.end(), b.bytes.begin(), b.bytes.end());
        }
    }
    return out;
}

std::uint32_t P9Device::WriteChain(std::vector<ChainBuf>& bufs,
                                    const std::vector<std::uint8_t>& reply) {
    std::size_t off = 0;
    for (auto& b : bufs) {
        if (!b.write || b.bytes.empty()) continue;
        if (off >= reply.size()) break;
        const std::size_t to_copy =
            std::min(b.bytes.size(), reply.size() - off);
        std::memcpy(b.bytes.data(), reply.data() + off, to_copy);
        off += to_copy;
    }
    return static_cast<std::uint32_t>(off);
}

void P9Device::BuildRlerror(std::vector<std::uint8_t>& reply,
                             std::uint16_t tag, std::uint32_t ecode) {
    reply.clear();
    Encode4(reply, 0);              // placeholder size
    Encode1(reply, kP9RLerror);
    Encode2(reply, tag);
    Encode4(reply, ecode);
    FinalizeMessage(reply);
}

// ---------------------------------------------------------------------------
// Protocol handlers
// ---------------------------------------------------------------------------

void P9Device::HandleTversion(std::uint16_t tag,
                               const std::vector<std::uint8_t>& body,
                               std::vector<std::uint8_t>& reply) {
    std::size_t off = 0;
    std::uint32_t driver_msize = 0;
    std::string version;
    if (!Decode4(body, off, driver_msize) ||
        !DecodeString(body, off, version)) {
        BuildRlerror(reply, tag, /*EINVAL*/22);
        rlerrors_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // Negotiate msize.
    if (driver_msize < kP9MsizeMin) driver_msize = kP9MsizeMin;
    if (driver_msize > kP9MsizeMax) driver_msize = kP9MsizeMax;
    negotiated_msize_ = driver_msize;

    // We only speak 9P2000.L. Linux always asks for ".L"; any other
    // request gets "unknown" per spec, which causes the client to
    // give up the connection cleanly.
    std::string reply_version =
        (version.rfind("9P2000.L", 0) == 0) ? "9P2000.L" : "unknown";

    // Tversion implicitly resets all FIDs (spec §"version"). The
    // mount tag is fresh after this; clear any previous attaches.
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        fids_.clear();
        next_qid_path_ = 1;
    }

    reply.clear();
    Encode4(reply, 0);                  // placeholder size
    Encode1(reply, kP9RVersion);
    Encode2(reply, tag);
    Encode4(reply, negotiated_msize_);
    EncodeString(reply, reply_version);
    FinalizeMessage(reply);
}

void P9Device::HandleTattach(std::uint16_t tag,
                              const std::vector<std::uint8_t>& body,
                              std::vector<std::uint8_t>& reply) {
    std::size_t off = 0;
    std::uint32_t fid = 0, afid = 0, n_uname = 0;
    std::string uname, aname;
    if (!Decode4(body, off, fid)        ||
        !Decode4(body, off, afid)       ||
        !DecodeString(body, off, uname) ||
        !DecodeString(body, off, aname) ||
        !Decode4(body, off, n_uname)) {
        BuildRlerror(reply, tag, /*EINVAL*/22);
        rlerrors_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // We don't support 9P auth. The driver should pass NOFID for
    // afid; anything else is a usage error.
    if (afid != kP9NoFid) {
        BuildRlerror(reply, tag, /*EPERM*/1);
        rlerrors_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // aname selects which subtree to expose. We only serve a single
    // share per device, so empty or matching-the-mount-tag aname is
    // accepted; any other value is ENOENT. The kernel typically
    // passes the mount tag as aname when the trans_fd path is used,
    // but with virtio-9p it usually passes "" -- accept both.
    if (!aname.empty() && aname != share_.tag) {
        BuildRlerror(reply, tag, /*ENOENT*/2);
        rlerrors_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    FidEntry root{};
    root.host_path = share_.host_root;
    root.is_dir    = true;

    std::uint64_t qid_path;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        if (fids_.count(fid) != 0) {
            BuildRlerror(reply, tag, /*EBADF*/9);
            rlerrors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        qid_path        = next_qid_path_++;
        root.qid_path   = qid_path;
        fids_.emplace(fid, std::move(root));
    }

    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RAttach);
    Encode2(reply, tag);
    EncodeQid(reply, kP9QTDir, /*version=*/0, qid_path);
    FinalizeMessage(reply);
}

// Tgetattr request body:    u32 fid, u64 request_mask
// Tgetattr reply payload:
//   u64 valid
//   qid[13]
//   u32 mode, u32 uid, u32 gid
//   u64 nlink, u64 rdev, u64 size, u64 blksize, u64 blocks
//   u64 atime_sec, u64 atime_nsec
//   u64 mtime_sec, u64 mtime_nsec
//   u64 ctime_sec, u64 ctime_nsec
//   u64 btime_sec, u64 btime_nsec
//   u64 gen, u64 data_version
//
// Phase 1: return synthetic dir attrs for any tracked FidEntry. The
// FidEntry only ever points at share_.host_root in Phase 1, so we
// only need to fake one path. Phase 3 will replace this with
// GetFileInformationByHandle + the FILE_BASIC_INFO timestamps.
void P9Device::HandleTgetattr(std::uint16_t tag,
                               const std::vector<std::uint8_t>& body,
                               std::vector<std::uint8_t>& reply) {
    std::size_t off = 0;
    std::uint32_t fid = 0;
    // request_mask is u64; we accept anything and report all-valid.
    std::uint32_t mask_lo = 0, mask_hi = 0;
    if (!Decode4(body, off, fid)     ||
        !Decode4(body, off, mask_lo) ||
        !Decode4(body, off, mask_hi)) {
        BuildRlerror(reply, tag, /*EINVAL*/22);
        rlerrors_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    std::uint64_t qid_path = 0;
    bool is_dir = false;
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        auto it = fids_.find(fid);
        if (it == fids_.end()) {
            BuildRlerror(reply, tag, /*EBADF*/9);
            rlerrors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        qid_path = it->second.qid_path;
        is_dir   = it->second.is_dir;
    }

    // P9_STATS_BASIC = 0x000007FFULL covers everything the kernel
    // needs at mount time (mode/uid/gid/nlink/rdev/size/blocks/atime
    // /mtime/ctime). Report all-basic-valid; the kernel happily
    // accepts that.
    constexpr std::uint64_t kStatsBasic = 0x000007FFULL;

    // POSIX-style mode: directory bit + 0755.
    constexpr std::uint32_t kModeDirRwxRxRx =
        0040000u /*S_IFDIR*/ | 0755u;
    constexpr std::uint32_t kModeFileRwR_R_ =
        0100000u /*S_IFREG*/ | 0644u;

    const std::uint8_t  qtype = is_dir ? kP9QTDir : kP9QTFile;
    const std::uint32_t mode  = is_dir ? kModeDirRwxRxRx : kModeFileRwR_R_;
    const std::uint64_t nlink = is_dir ? 2u : 1u;

    reply.clear();
    Encode4(reply, 0);                  // placeholder size
    Encode1(reply, kP9RGetattr);
    Encode2(reply, tag);
    Encode8(reply, kStatsBasic);
    EncodeQid(reply, qtype, /*version=*/0, qid_path);
    Encode4(reply, mode);
    Encode4(reply, /*uid=*/0);
    Encode4(reply, /*gid=*/0);
    Encode8(reply, nlink);
    Encode8(reply, /*rdev=*/0);
    Encode8(reply, /*size=*/0);
    Encode8(reply, /*blksize=*/4096);
    Encode8(reply, /*blocks=*/0);
    Encode8(reply, /*atime_sec=*/0);  Encode8(reply, /*atime_nsec=*/0);
    Encode8(reply, /*mtime_sec=*/0);  Encode8(reply, /*mtime_nsec=*/0);
    Encode8(reply, /*ctime_sec=*/0);  Encode8(reply, /*ctime_nsec=*/0);
    Encode8(reply, /*btime_sec=*/0);  Encode8(reply, /*btime_nsec=*/0);
    Encode8(reply, /*gen=*/0);
    Encode8(reply, /*data_version=*/0);
    FinalizeMessage(reply);
}

// Tclunk request body:    u32 fid
// Rclunk reply payload:   <empty>  (just the 7B header)
//
// "Forget" the named fid. The kernel issues Tclunk on every fid drop
// (including the root fid at umount). Phase 1 fids only carry the
// synthetic qid_path, so Forget == map.erase.
void P9Device::HandleTclunk(std::uint16_t tag,
                             const std::vector<std::uint8_t>& body,
                             std::vector<std::uint8_t>& reply) {
    std::size_t off = 0;
    std::uint32_t fid = 0;
    if (!Decode4(body, off, fid)) {
        BuildRlerror(reply, tag, /*EINVAL*/22);
        rlerrors_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(fids_mu_);
        // Per spec, Tclunk releases the fid even on backend error.
        // Erase unconditionally; if the fid wasn't tracked, that's
        // a no-op (no Rlerror -- the kernel is allowed to clunk
        // unknown fids during cleanup).
        fids_.erase(fid);
    }
    reply.clear();
    Encode4(reply, 0);
    Encode1(reply, kP9RClunk);
    Encode2(reply, tag);
    FinalizeMessage(reply);
}

// ---------------------------------------------------------------------------
// Main drain loop
// ---------------------------------------------------------------------------

void P9Device::DrainRequestQueue() {
    bool any = false;
    std::vector<std::uint8_t> reply;
    reply.reserve(256);

    while (auto chain_opt = queue_.Pop()) {
        any = true;
        auto& chain = *chain_opt;
        const std::vector<std::uint8_t> t_msg = ReadChain(chain.bufs);

        std::uint32_t used_len = 0;
        if (t_msg.size() < kP9HdrBytes) {
            // Misbehaving driver -- push with len=0 and move on.
            queue_.Push(chain.head_index, 0);
            rlerrors_.fetch_add(1, std::memory_order_relaxed);
            requests_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        // Parse header: u32 size, u8 type, u16 tag.
        std::uint32_t msg_size  = static_cast<std::uint32_t>(t_msg[0]) |
                                  (static_cast<std::uint32_t>(t_msg[1]) <<  8) |
                                  (static_cast<std::uint32_t>(t_msg[2]) << 16) |
                                  (static_cast<std::uint32_t>(t_msg[3]) << 24);
        const std::uint8_t  type = t_msg[4];
        const std::uint16_t tag  = static_cast<std::uint16_t>(
            t_msg[5] | (static_cast<std::uint16_t>(t_msg[6]) << 8));

        // Reject impossibly-sized messages early. The msg_size field
        // must include the header and not exceed the negotiated
        // msize (or kP9MsizeMax pre-version).
        const std::uint32_t cap = negotiated_msize_ ? negotiated_msize_
                                                     : kP9MsizeMax;
        if (msg_size < kP9HdrBytes || msg_size > cap ||
            msg_size > t_msg.size()) {
            BuildRlerror(reply, tag, /*EPROTO*/71);
            rlerrors_.fetch_add(1, std::memory_order_relaxed);
            used_len = WriteChain(chain.bufs, reply);
            queue_.Push(chain.head_index, used_len);
            requests_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        // Slice out the body for the handler.
        std::vector<std::uint8_t> body(t_msg.begin() + kP9HdrBytes,
                                        t_msg.begin() + msg_size);

        switch (type) {
            case kP9TVersion:
                HandleTversion(tag, body, reply);
                break;
            case kP9TAttach:
                HandleTattach(tag, body, reply);
                break;
            case kP9TGetattr:
                HandleTgetattr(tag, body, reply);
                break;
            case kP9TClunk:
                HandleTclunk(tag, body, reply);
                break;
            default:
                // Phase 1: everything else is ENOSYS. Phase 2+ will
                // implement the rest, and Phase 6 will keep this
                // default for genuinely-unsupported ops (xattr*, lock*).
                BuildRlerror(reply, tag, kP9ErrNosys);
                rlerrors_.fetch_add(1, std::memory_order_relaxed);
                break;
        }

        used_len = WriteChain(chain.bufs, reply);
        queue_.Push(chain.head_index, used_len);
        requests_.fetch_add(1, std::memory_order_relaxed);
    }

    if (any && irq_ && queue_.ShouldInterruptDriver()) {
        irq_(kP9RequestQueueIdx);
    }
}

}  // namespace tinyvmm::virtio
