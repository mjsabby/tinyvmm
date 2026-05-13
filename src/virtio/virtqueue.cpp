#include "virtqueue.h"

#include <atomic>
#include <cstring>

namespace tinyvmm::virtio {

namespace {

#pragma pack(push, 1)
struct VringDesc {
    std::uint64_t addr;
    std::uint32_t len;
    std::uint16_t flags;
    std::uint16_t next;
};
struct VringUsedElem {
    std::uint32_t id;
    std::uint32_t len;
};
#pragma pack(pop)

static_assert(sizeof(VringDesc) == 16, "VringDesc must be 16 bytes");
static_assert(sizeof(VringUsedElem) == 8, "VringUsedElem must be 8 bytes");

inline std::uint16_t AcquireLoad16(const std::uint16_t* p) {
    return std::atomic_ref<const std::uint16_t>(*p).load(
        std::memory_order_acquire);
}
inline void ReleaseStore16(std::uint16_t* p, std::uint16_t v) {
    std::atomic_ref<std::uint16_t>(*p).store(v, std::memory_order_release);
}

}  // namespace

void Virtqueue::Reset() {
    size_ = 0;
    ready_ = false;
    desc_gpa_ = 0;
    avail_gpa_ = 0;
    used_gpa_ = 0;
    last_avail_ = 0;
    last_used_idx_ = 0;
    last_used_signaled_ = 0;
}

void* Virtqueue::HostFromGpa(std::uint64_t gpa, std::uint32_t bytes) const {
    if (gpa < mem_.gpa()) return nullptr;
    std::uint64_t off = gpa - mem_.gpa();
    if (off + bytes > mem_.size()) return nullptr;
    return static_cast<std::uint8_t*>(mem_.host_base()) + off;
}

std::uint16_t Virtqueue::LoadAvailIdx() const {
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpa(avail_gpa_ + 2, sizeof(std::uint16_t)));
    if (!p) return last_avail_;
    return AcquireLoad16(p);
}
std::uint16_t Virtqueue::LoadAvailFlags() const {
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpa(avail_gpa_, sizeof(std::uint16_t)));
    if (!p) return 0;
    return AcquireLoad16(p);
}
std::uint16_t Virtqueue::LoadAvailRing(std::uint16_t slot) const {
    std::uint64_t off = 4 + sizeof(std::uint16_t) * slot;
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpa(avail_gpa_ + off, sizeof(std::uint16_t)));
    if (!p) return 0;
    return *p;
}
std::uint16_t Virtqueue::LoadUsedEvent() const {
    std::uint64_t off = 4 + sizeof(std::uint16_t) * size_;
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpa(avail_gpa_ + off, sizeof(std::uint16_t)));
    if (!p) return 0;
    return AcquireLoad16(p);
}

void Virtqueue::StoreUsedIdx(std::uint16_t idx) {
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpa(used_gpa_ + 2, sizeof(std::uint16_t)));
    if (!p) return;
    ReleaseStore16(p, idx);
}
void Virtqueue::StoreUsedRing(std::uint16_t slot, std::uint32_t id,
                              std::uint32_t len) {
    std::uint64_t off = 4 + sizeof(VringUsedElem) * slot;
    auto* p = static_cast<VringUsedElem*>(
        HostFromGpa(used_gpa_ + off, sizeof(VringUsedElem)));
    if (!p) return;
    p->id = id;
    p->len = len;
}

void Virtqueue::StoreAvailEvent(std::uint16_t event_idx) {
    // `avail_event` lives at the tail of the used ring, after the
    // `flags(2) + idx(2) + ring[size]*8 = 4 + 8*size` prefix.
    std::uint64_t off = 4 + sizeof(VringUsedElem) * size_;
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpa(used_gpa_ + off, sizeof(std::uint16_t)));
    if (!p) return;
    ReleaseStore16(p, event_idx);
}

std::optional<PoppedChain> Virtqueue::Pop() {
    if (!ready_ || size_ == 0) return std::nullopt;

    std::uint16_t avail_idx = LoadAvailIdx();
    if (avail_idx == last_avail_) return std::nullopt;

    std::uint16_t slot = static_cast<std::uint16_t>(last_avail_ % size_);
    std::uint16_t head = LoadAvailRing(slot);
    if (head >= size_) {
        last_avail_++;
        return std::nullopt;
    }

    auto* desc_table = static_cast<VringDesc*>(
        HostFromGpa(desc_gpa_, sizeof(VringDesc) * size_));
    if (!desc_table) {
        last_avail_++;
        return std::nullopt;
    }

    PoppedChain out;
    out.head_index = head;
    out.bufs.reserve(4);

    std::uint16_t cur = head;
    for (std::uint32_t hop = 0; hop < size_; ++hop) {
        const VringDesc& d = desc_table[cur];

        if (d.flags & kVringDescFIndirect) {
            std::uint32_t inner_count = d.len / sizeof(VringDesc);
            auto* inner = static_cast<VringDesc*>(HostFromGpa(d.addr, d.len));
            if (!inner) break;
            std::uint32_t i = 0;
            for (std::uint32_t step = 0; step < inner_count && step < size_;
                 ++step) {
                const VringDesc& id = inner[i];
                void* host = HostFromGpa(id.addr, id.len);
                if (host) {
                    out.bufs.push_back(
                        ChainBuf{host, id.len,
                                 (id.flags & kVringDescFWrite) != 0});
                }
                if (!(id.flags & kVringDescFNext)) break;
                if (id.next >= inner_count) break;
                i = id.next;
            }
        } else {
            void* host = HostFromGpa(d.addr, d.len);
            if (host) {
                out.bufs.push_back(
                    ChainBuf{host, d.len,
                             (d.flags & kVringDescFWrite) != 0});
            }
        }

        if (!(d.flags & kVringDescFNext)) break;
        if (d.next >= size_) break;
        cur = d.next;
    }

    last_avail_++;
    // Tell the driver to kick us on the next chain it adds. With
    // VIRTIO_F_RING_EVENT_IDX negotiated, the driver suppresses kicks
    // until avail.idx crosses `avail_event`; without keeping this
    // updated the driver would only ever kick us once.
    if (event_idx_) {
        StoreAvailEvent(last_avail_);
    }
    return out;
}

void Virtqueue::Push(std::uint16_t head_index, std::uint32_t used_len) {
    if (!ready_ || size_ == 0) return;

    std::uint16_t slot = static_cast<std::uint16_t>(last_used_idx_ % size_);
    StoreUsedRing(slot, head_index, used_len);

    last_used_idx_++;
    StoreUsedIdx(last_used_idx_);
}

bool Virtqueue::VringNeedEvent(std::uint16_t event_idx,
                               std::uint16_t new_idx,
                               std::uint16_t old_idx) {
    return static_cast<std::uint16_t>(new_idx - event_idx - 1) <
           static_cast<std::uint16_t>(new_idx - old_idx);
}

bool Virtqueue::ShouldInterruptDriver() {
    if (!ready_) return false;

    std::uint16_t new_used = last_used_idx_;
    std::uint16_t old_used = last_used_signaled_;
    last_used_signaled_ = new_used;

    if (event_idx_) {
        std::uint16_t used_event = LoadUsedEvent();
        return VringNeedEvent(used_event, new_used, old_used);
    }
    return (LoadAvailFlags() & 1) == 0;
}

}  // namespace tinyvmm::virtio
