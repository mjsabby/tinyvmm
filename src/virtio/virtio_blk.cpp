#include "virtio_blk.h"

#include <algorithm>
#include <cstring>

namespace tinyvmm::virtio {

namespace {

// virtio_blk config-space layout (spec §5.2.4).
constexpr std::uint32_t kCfgCapacity     = 0;    // le64 sectors
constexpr std::uint32_t kCfgSizeMax      = 8;    // le32
constexpr std::uint32_t kCfgSegMax       = 12;   // le32
constexpr std::uint32_t kCfgBlkSize      = 20;   // le32 (after geometry[4])

void PutLe(std::uint8_t* dst, std::uint64_t v, std::uint32_t bytes) {
    for (std::uint32_t i = 0; i < bytes; ++i) {
        dst[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

}  // namespace

BlockDevice::BlockDevice(whp::GuestMemory& mem, host::BlockFile& backend,
                          IrqFn irq, std::uint32_t queue_max)
    : mem_(mem), backend_(backend), irq_(std::move(irq)),
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
}

BlockDevice::~BlockDevice() = default;

std::uint64_t BlockDevice::DeviceFeatures() const {
    std::uint64_t f = kFeatureVersion1 | kFeatureRingEventIdx |
                       kBlkFeatureBlkSize | kBlkFeatureFlush |
                       kBlkFeatureSegMax  | kBlkFeatureSizeMax;
    if (backend_.readonly()) f |= kBlkFeatureRo;
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
        const bool hdr_ok = !hdr.write && hdr.len >= 16;
        const bool sta_ok = stat.write && stat.len >= 1;
        if (!hdr_ok || !sta_ok) {
            if (sta_ok) {
                *static_cast<std::uint8_t*>(stat.host_addr) = kBlkStatusUnsupp;
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
        const auto* hp = static_cast<const std::uint8_t*>(hdr.host_addr);
        std::memcpy(&type,   hp + 0, 4);
        std::memcpy(&sector, hp + 8, 8);

        auto req = std::make_unique<Req>();
        req->dev = this;
        req->head_idx = popped->head_index;
        req->type = type;
        req->status_byte = static_cast<std::uint8_t*>(stat.host_addr);
        for (std::size_t i = 1; i + 1 < popped->bufs.size(); ++i) {
            req->data_segs.push_back(popped->bufs[i]);
        }
        req->cur_file_offset = sector * kBlkSectorSize;

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
        SubmitNext(raw);
    }
}

void BlockDevice::SubmitNext(Req* r) {
    if (r->cur_seg >= r->data_segs.size()) {
        FinishRequest(r);
        return;
    }
    auto& seg = r->data_segs[r->cur_seg];
    r->buf = seg.host_addr;
    r->bytes = seg.len;
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
    r->total_done    += r->bytes;
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
    if (size == 0 || off + size > sizeof(blk_cfg_)) return 0;
    std::uint32_t v = 0;
    std::memcpy(&v, blk_cfg_ + off, std::min<std::size_t>(size, 4));
    return v;
}

void BlockDevice::WriteConfig(std::uint32_t /*off*/, std::uint32_t /*size*/,
                               std::uint32_t /*value*/) {
    // virtio-blk config is read-only.
}

}  // namespace tinyvmm::virtio
