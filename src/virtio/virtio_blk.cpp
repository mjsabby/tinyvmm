#include "virtio_blk.h"

#include "diag/etw.h"
#include "whp/snapshot_file.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace tinyvmm::virtio {

namespace {

// virtio_blk config-space layout (spec §5.2.4).
constexpr std::uint32_t kCfgCapacity              = 0;    // le64 sectors
constexpr std::uint32_t kCfgSizeMax               = 8;    // le32
constexpr std::uint32_t kCfgSegMax                = 12;   // le32
constexpr std::uint32_t kCfgBlkSize               = 20;   // le32 (after geometry[4])
// DISCARD / WRITE_ZEROES sub-config (M34.x add-on; spec §5.2.4 cont'd).
constexpr std::uint32_t kCfgMaxDiscardSectors     = 32;   // le32
constexpr std::uint32_t kCfgMaxDiscardSeg         = 36;   // le32
constexpr std::uint32_t kCfgDiscardSectorAlign    = 40;   // le32
constexpr std::uint32_t kCfgMaxWriteZeroesSectors = 44;   // le32
constexpr std::uint32_t kCfgMaxWriteZeroesSeg     = 48;   // le32
constexpr std::uint32_t kCfgWriteZeroesMayUnmap   = 52;   // u8

// Per-request max range count (we always advertise 1 == single range).
constexpr std::uint32_t kBlkMaxDiscardSeg     = 1;
constexpr std::uint32_t kBlkMaxWriteZeroesSeg = 1;
// Per-range max sectors: 2 GiB at 512 B/sector = 4 Mi sectors. The
// guest sends single-range requests so this caps the largest range.
constexpr std::uint32_t kBlkMaxDiscardSectors     = 4 * 1024 * 1024;
constexpr std::uint32_t kBlkMaxWriteZeroesSectors = 4 * 1024 * 1024;

void PutLe(std::uint8_t* dst, std::uint64_t v, std::uint32_t bytes) {
    for (std::uint32_t i = 0; i < bytes; ++i) {
        dst[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

}  // namespace

BlockDevice::BlockDevice(whp::GuestMemory& mem, host::BlockFile& backend,
                          IrqFn irq, std::uint32_t queue_max)
    : backend_(backend), irq_(std::move(irq)),
      queue_(mem, queue_max) {
    backend_.SetCompletionCallback(
        [this](host::BlockFile::Request* r) { OnComplete(r); });

    const std::uint64_t capacity_sectors = backend_.size() / kBlkSectorSize;
    PutLe(blk_cfg_ + kCfgCapacity, capacity_sectors, 8);
    // SIZE_MAX: max bytes per data segment. Pick something generous (64 KiB).
    PutLe(blk_cfg_ + kCfgSizeMax,  64u * 1024u, 4);
    // SEG_MAX: max data segs per request. Reserve 2 entries for header +
    // status, so the driver can chain queue_max - 2 data segs.
    PutLe(blk_cfg_ + kCfgSegMax,
           queue_max >= 2 ? (queue_max - 2) : 0, 4);
    PutLe(blk_cfg_ + kCfgBlkSize,  kBlkSectorSize, 4);
    // DISCARD / WRITE_ZEROES config. Always populated; the guest only
    // reads these fields if it accepts the matching feature bit
    // (DeviceFeatures gates that based on backend.readonly()).
    PutLe(blk_cfg_ + kCfgMaxDiscardSectors,     kBlkMaxDiscardSectors,     4);
    PutLe(blk_cfg_ + kCfgMaxDiscardSeg,         kBlkMaxDiscardSeg,         4);
    PutLe(blk_cfg_ + kCfgDiscardSectorAlign,    1,                         4);
    PutLe(blk_cfg_ + kCfgMaxWriteZeroesSectors, kBlkMaxWriteZeroesSectors, 4);
    PutLe(blk_cfg_ + kCfgMaxWriteZeroesSeg,     kBlkMaxWriteZeroesSeg,     4);
    // write_zeroes_may_unmap=1: we DO unmap (FSCTL_SET_ZERO_DATA on
    // a sparse NTFS file deallocates clusters).
    PutLe(blk_cfg_ + kCfgWriteZeroesMayUnmap,   1,                         1);
}

BlockDevice::~BlockDevice() = default;

std::uint64_t BlockDevice::DeviceFeatures() const {
    std::uint64_t f = kFeatureVersion1 | kFeatureRingEventIdx |
                       kBlkFeatureBlkSize | kBlkFeatureFlush |
                       kBlkFeatureSegMax  | kBlkFeatureSizeMax;
    if (backend_.readonly()) {
        f |= kBlkFeatureRo;
    } else {
        // DISCARD + WRITE_ZEROES are only valid on writable backends.
        f |= kBlkFeatureDiscard | kBlkFeatureWriteZeroes;
    }
    return f;
}

bool BlockDevice::SetDriverFeatures(std::uint64_t acked) {
    // Anything the driver acks must be a subset of what we offer.
    if (acked & ~DeviceFeatures()) return false;
    driver_features_ = acked;
    return true;
}

std::uint32_t BlockDevice::QueueMax(std::uint32_t idx) const {
    return idx == 0 ? queue_.max_size() : 0;
}

Virtqueue* BlockDevice::GetQueue(std::uint32_t idx) {
    return idx == 0 ? &queue_ : nullptr;
}

void BlockDevice::NotifyQueue(std::uint32_t idx) {
    if (idx != 0) return;
    while (true) {
        std::optional<PoppedChain> popped;
        {
            std::lock_guard<std::mutex> lk(queue_mu_);
            popped = queue_.Pop();
        }
        if (!popped) break;

        if (popped->bufs.size() < 2) {
            ops_err_.fetch_add(1);
            continue;
        }
        ChainBuf& hdr  = popped->bufs.front();
        ChainBuf& stat = popped->bufs.back();
        const bool hdr_ok = !hdr.write && hdr.bytes.size() >= 16;
        const bool sta_ok = stat.write && !stat.bytes.empty();
        if (!hdr_ok || !sta_ok) {
            if (sta_ok) {
                stat.bytes[0] = kBlkStatusUnsupp;
            }
            {
                std::lock_guard<std::mutex> lk(queue_mu_);
                queue_.Push(popped->head_index, /*used_len=*/1);
            }
            ops_err_.fetch_add(1);
            RaiseIrqIfNeeded();
            continue;
        }

        std::uint32_t type = 0;
        std::uint64_t sector = 0;
        std::memcpy(&type,   hdr.bytes.data() + 0, 4);
        std::memcpy(&sector, hdr.bytes.data() + 8, 8);

        auto req = std::make_unique<Req>();
        req->dev = this;
        req->head_idx = popped->head_index;
        req->type = type;
        req->status_byte = stat.bytes.data();
        for (std::size_t i = 1; i + 1 < popped->bufs.size(); ++i) {
            req->data_segs.push_back(popped->bufs[i]);
        }
        // Reject ridiculous sector values before multiplying. With
        // kBlkSectorSize == 512 the threshold is UINT64_MAX/512, so
        // we will never let `sector * 512` wrap into a valid-looking
        // small offset.
        bool sector_ok = sector <= UINT64_MAX / kBlkSectorSize;
        req->cur_file_offset = sector_ok ? (sector * kBlkSectorSize) : 0;
        if (!sector_ok && type != kBlkTypeFlush) {
            *req->status_byte = kBlkStatusIoErr;
            {
                std::lock_guard<std::mutex> lk(queue_mu_);
                queue_.Push(req->head_idx, /*used_len=*/1);
            }
            ops_err_.fetch_add(1);
            RaiseIrqIfNeeded();
            continue;
        }

        // FLUSH: no data segments expected; if any are present, we ignore
        // them (some legacy drivers append a zero-length seg).
        if (type == kBlkTypeFlush) {
            ops_flush_.fetch_add(1);
            req->op = host::BlockFile::Request::OpFlush;
            Req* raw = req.get();
            {
                std::lock_guard<std::mutex> lk(pending_mu_);
                pending_.push_back(std::move(req));
            }
            if (!backend_.Submit(raw)) {
                raw->failed = true;
                FinishRequest(raw);
            }
            continue;
        }

        // DISCARD / WRITE_ZEROES: one or more 16-byte BlkDiscardWriteZeroes
        // structs follow the header, then the trailing status byte.
        //
        // For both ops we delegate to BlockFile::ZeroRange() which uses
        // FSCTL_SET_ZERO_DATA on the host file. On NTFS sparse files
        // this both zeroes the logical bytes AND deallocates the
        // backing clusters, which is exactly what DISCARD wants and
        // also satisfies WRITE_ZEROES with may_unmap=1.
        //
        // Synchronous: we don't route through IOCP since these ops are
        // rare and the FSCTL itself is sync.
        if (type == kBlkTypeDiscard || type == kBlkTypeWriteZeroes) {
            const bool is_wz = (type == kBlkTypeWriteZeroes);
            // Concatenate all data segs into one byte buffer; each
            // range is 16 bytes. A driver MAY split a single range
            // across two descriptor segments, but Linux's virtio-blk
            // emits one descriptor per range.
            std::size_t total = 0;
            for (auto& s : req->data_segs) total += s.bytes.size();
            if (total == 0 || (total % sizeof(BlkDiscardWriteZeroes)) != 0) {
                *req->status_byte = kBlkStatusUnsupp;
                {
                    std::lock_guard<std::mutex> lk(queue_mu_);
                    queue_.Push(req->head_idx, /*used_len=*/1);
                }
                ops_err_.fetch_add(1);
                RaiseIrqIfNeeded();
                continue;
            }
            // Data segs must be device-readable (host reads the ranges).
            bool segs_ok = true;
            for (auto& s : req->data_segs) {
                if (s.write) { segs_ok = false; break; }
            }
            if (!segs_ok) {
                *req->status_byte = kBlkStatusUnsupp;
                {
                    std::lock_guard<std::mutex> lk(queue_mu_);
                    queue_.Push(req->head_idx, /*used_len=*/1);
                }
                ops_err_.fetch_add(1);
                RaiseIrqIfNeeded();
                continue;
            }
            if (backend_.readonly()) {
                *req->status_byte = kBlkStatusIoErr;
                {
                    std::lock_guard<std::mutex> lk(queue_mu_);
                    queue_.Push(req->head_idx, /*used_len=*/1);
                }
                ops_err_.fetch_add(1);
                RaiseIrqIfNeeded();
                continue;
            }
            const std::size_t nranges = total / sizeof(BlkDiscardWriteZeroes);
            const std::uint32_t cap_seg = is_wz ? kBlkMaxWriteZeroesSeg
                                                : kBlkMaxDiscardSeg;
            if (nranges > cap_seg) {
                *req->status_byte = kBlkStatusUnsupp;
                {
                    std::lock_guard<std::mutex> lk(queue_mu_);
                    queue_.Push(req->head_idx, /*used_len=*/1);
                }
                ops_err_.fetch_add(1);
                RaiseIrqIfNeeded();
                continue;
            }

            // Assemble the range bytes (worst case 1 range = 16 bytes).
            std::uint8_t range_buf[16 * 8] = {};  // up to 8 ranges
            std::size_t off = 0;
            for (auto& s : req->data_segs) {
                if (off + s.bytes.size() > sizeof(range_buf)) break;
                std::memcpy(range_buf + off, s.bytes.data(), s.bytes.size());
                off += s.bytes.size();
            }
            const std::uint32_t cap_sectors = is_wz
                ? kBlkMaxWriteZeroesSectors : kBlkMaxDiscardSectors;
            const std::uint64_t backend_size = backend_.size();
            bool all_ok = true;
            for (std::size_t k = 0; k < nranges; ++k) {
                BlkDiscardWriteZeroes rd{};
                std::memcpy(&rd, range_buf + k * 16, 16);
                if (rd.num_sectors == 0) continue;
                if (rd.num_sectors > cap_sectors) { all_ok = false; break; }
                // Compute byte offset/length; subtraction-form bounds check.
                if (rd.sector > UINT64_MAX / kBlkSectorSize) {
                    all_ok = false; break;
                }
                const std::uint64_t byte_off = rd.sector * kBlkSectorSize;
                const std::uint64_t byte_len =
                    static_cast<std::uint64_t>(rd.num_sectors) * kBlkSectorSize;
                if (byte_off > backend_size ||
                    byte_len > backend_size - byte_off) {
                    all_ok = false; break;
                }
                // For DISCARD, flags should be 0. For WRITE_ZEROES, the
                // unmap bit is advisory; we always unmap via SET_ZERO_DATA
                // on sparse files, so the bit is effectively ignored.
                if (!is_wz && (rd.flags != 0)) { all_ok = false; break; }
                if (!backend_.ZeroRange(byte_off, byte_len)) {
                    all_ok = false; break;
                }
            }
            *req->status_byte = all_ok ? kBlkStatusOk : kBlkStatusIoErr;
            {
                std::lock_guard<std::mutex> lk(queue_mu_);
                queue_.Push(req->head_idx, /*used_len=*/1);
            }
            if (all_ok) {
                if (is_wz) ops_write_zeroes_.fetch_add(1);
                else       ops_discard_.fetch_add(1);
            } else {
                ops_err_.fetch_add(1);
            }
            RaiseIrqIfNeeded();
            continue;
        }

        if (type != kBlkTypeIn && type != kBlkTypeOut) {
            *req->status_byte = kBlkStatusUnsupp;
            {
                std::lock_guard<std::mutex> lk(queue_mu_);
                queue_.Push(req->head_idx, /*used_len=*/1);
            }
            ops_err_.fetch_add(1);
            RaiseIrqIfNeeded();
            continue;
        }

        // For OpIn (read), data segs must be device-writable; for OpOut
        // (write), they must be device-readable.
        const bool want_write = (type == kBlkTypeIn);
        bool dir_ok = true;
        for (auto& s : req->data_segs) {
            if (s.write != want_write) { dir_ok = false; break; }
        }
        if (!dir_ok) {
            *req->status_byte = kBlkStatusUnsupp;
            {
                std::lock_guard<std::mutex> lk(queue_mu_);
                queue_.Push(req->head_idx, /*used_len=*/1);
            }
            ops_err_.fetch_add(1);
            RaiseIrqIfNeeded();
            continue;
        }

        // Refuse writes when read-only.
        if (type == kBlkTypeOut && backend_.readonly()) {
            *req->status_byte = kBlkStatusIoErr;
            {
                std::lock_guard<std::mutex> lk(queue_mu_);
                queue_.Push(req->head_idx, /*used_len=*/1);
            }
            ops_err_.fetch_add(1);
            RaiseIrqIfNeeded();
            continue;
        }

        // Empty data: ack immediately.
        if (req->data_segs.empty()) {
            *req->status_byte = kBlkStatusOk;
            {
                std::lock_guard<std::mutex> lk(queue_mu_);
                queue_.Push(req->head_idx, /*used_len=*/1);
            }
            RaiseIrqIfNeeded();
            continue;
        }

        if (type == kBlkTypeIn) ops_in_.fetch_add(1);
        else                    ops_out_.fetch_add(1);

        Req* raw = req.get();
        {
            std::lock_guard<std::mutex> lk(pending_mu_);
            pending_.push_back(std::move(req));
        }
        TINYVMM_ETW_VERBOSE_KW("BlkSubmit", ::tinyvmm::diag::kw::Block,
            TraceLoggingUInt32(raw->type,                              "type"),
            TraceLoggingUInt64(raw->cur_file_offset / kBlkSectorSize, "sector"),
            TraceLoggingUInt32(static_cast<std::uint32_t>(raw->data_segs.size()), "segs"),
            TraceLoggingUInt16(raw->head_idx,                          "head"));
        SubmitNext(raw);
    }
}

void BlockDevice::SubmitNext(Req* r) {
    if (r->cur_seg >= r->data_segs.size()) {
        FinishRequest(r);
        return;
    }
    auto& seg = r->data_segs[r->cur_seg];
    // Bounds-check the segment against the backing file BEFORE handing
    // it to ReadFile/WriteFile. We use subtraction so that an attacker
    // who controls `seg.bytes.size()` (32-bit) and `cur_file_offset`
    // (built from a 64-bit sector) cannot wrap past the upper-bound
    // check.
    const std::uint64_t backend_size = backend_.size();
    const std::uint64_t seg_len = seg.bytes.size();
    if (r->cur_file_offset > backend_size ||
        seg_len > backend_size - r->cur_file_offset) {
        r->failed = true;
        FinishRequest(r);
        return;
    }
    r->buf = seg.bytes.data();
    r->bytes = static_cast<std::uint32_t>(seg_len);
    r->file_offset = r->cur_file_offset;
    r->op = (r->type == kBlkTypeIn) ? host::BlockFile::Request::OpRead
                                     : host::BlockFile::Request::OpWrite;
    if (!backend_.Submit(r)) {
        r->failed = true;
        FinishRequest(r);
    }
}

void BlockDevice::OnComplete(host::BlockFile::Request* req) {
    Req* r = static_cast<Req*>(req);
    if (!r->ok) {
        r->failed = true;
        FinishRequest(r);
        return;
    }
    if (r->op == host::BlockFile::Request::OpFlush) {
        FinishRequest(r);
        return;
    }
    // Saturating add: `total_done` is u32 because the virtio used_len
    // is a u32; for a request with > 4 GiB of total reads we cap the
    // reported byte count at UINT32_MAX. The actual transfer happened
    // exactly as the guest asked.
    if (r->bytes > UINT32_MAX - r->total_done) {
        r->total_done = UINT32_MAX;
    } else {
        r->total_done += r->bytes;
    }
    r->cur_file_offset += r->bytes;
    r->cur_seg++;
    SubmitNext(r);
}

void BlockDevice::FinishRequest(Req* r) {
    *r->status_byte = r->failed ? kBlkStatusIoErr : kBlkStatusOk;
    // used_len includes both the data the device wrote (only for reads) and
    // the trailing 1-byte status. Per spec §5.2.6.2 used_len is the total
    // bytes "written into the buffer" by the device.
    const std::uint32_t used_len =
        r->failed ? 1u
                  : ((r->type == kBlkTypeIn ? r->total_done : 0u) + 1u);
    {
        std::lock_guard<std::mutex> lk(queue_mu_);
        queue_.Push(r->head_idx, used_len);
    }
    ops_done_.fetch_add(1);
    TINYVMM_ETW_VERBOSE_KW("BlkComplete", ::tinyvmm::diag::kw::Block,
        TraceLoggingUInt32(r->type,                                "type"),
        TraceLoggingUInt32(used_len,                               "used_len"),
        TraceLoggingUInt8(r->failed ? 1 : 0,                       "failed"),
        TraceLoggingUInt16(r->head_idx,                            "head"));

    std::unique_ptr<Req> owned;
    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        for (auto it = pending_.begin(); it != pending_.end(); ++it) {
            if (it->get() == r) {
                owned = std::move(*it);
                pending_.erase(it);
                break;
            }
        }
    }

    RaiseIrqIfNeeded();
}

void BlockDevice::RaiseIrqIfNeeded() {
    bool fire = false;
    {
        std::lock_guard<std::mutex> lk(queue_mu_);
        fire = queue_.ShouldInterruptDriver();
    }
    if (fire && irq_) irq_(0);
}

void BlockDevice::DriverOk() {}

void BlockDevice::Reset() {
    // Best-effort. Caller is expected to have stopped the backend (and thus
    // quiesced the IOCP worker) before exercising reset.
    std::lock_guard<std::mutex> p(pending_mu_);
    pending_.clear();
    driver_features_ = 0;
}

std::uint32_t BlockDevice::ReadConfig(std::uint32_t off, std::uint32_t size) {
    if (size == 0 || off >= sizeof(blk_cfg_) ||
        size > sizeof(blk_cfg_) - off) return 0;
    std::uint32_t v = 0;
    std::memcpy(&v, blk_cfg_ + off, std::min<std::size_t>(size, 4));
    return v;
}

void BlockDevice::WriteConfig(std::uint32_t /*off*/, std::uint32_t /*size*/,
                               std::uint32_t /*value*/) {
    // virtio-blk config is read-only.
}

// ----------------------- M33.4 save/restore ---------------------------

std::size_t BlockDevice::EncodeState(const State& s,
                                     std::vector<std::uint8_t>& out) {
    using namespace tinyvmm::whp::snapshot;
    const std::size_t start = out.size();
    out.resize(start + kEncodedSize, 0);
    std::uint8_t* p = out.data() + start;
    WriteLe64(p + 0, s.driver_features);
    std::memcpy(p + 8, s.blk_cfg, 64);
    return kEncodedSize;
}

BlockDevice::State BlockDevice::DecodeState(
    std::span<const std::uint8_t> bytes) {
    using namespace tinyvmm::whp::snapshot;
    if (bytes.size() < kEncodedSize) {
        throw std::runtime_error(
            "BlockDevice::DecodeState: payload too small");
    }
    const std::uint8_t* p = bytes.data();
    State s;
    s.driver_features = ReadLe64(p + 0);
    std::memcpy(s.blk_cfg, p + 8, 64);
    return s;
}

}  // namespace tinyvmm::virtio
