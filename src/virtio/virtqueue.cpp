#include "virtqueue.h"

#include "whp/snapshot_file.h"

#include <atomic>
#include <cstring>
#include <stdexcept>

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
    // Subtraction-form bounds check: any guest-controlled `gpa` near
    // UINT64_MAX would cause `off + bytes` in the natural form to wrap
    // and pass the upper-bound check. With subtraction we never add
    // attacker-controlled values together.
    const std::uint64_t base = mem_.gpa();
    if (gpa < base) return nullptr;
    const std::uint64_t off  = gpa - base;
    const std::uint64_t size = mem_.size();
    if (off >= size) return nullptr;
    if (static_cast<std::uint64_t>(bytes) > size - off) return nullptr;
    return static_cast<std::uint8_t*>(mem_.host_base()) + off;
}

// Same as HostFromGpa, but the GPA is constructed as (base_gpa + off)
// internally. We pre-validate that the sum doesn't wrap so that callers
// like `HostFromGpa(avail_gpa_ + slot * 2, ...)` can't sneak a wrap-
// around past the bounds check inside `HostFromGpa`.
void* Virtqueue::HostFromGpaOff(std::uint64_t base_gpa, std::uint64_t off,
                                std::uint32_t bytes) const {
    if (off > UINT64_MAX - base_gpa) return nullptr;
    return HostFromGpa(base_gpa + off, bytes);
}

std::uint16_t Virtqueue::LoadAvailIdx() const {
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpaOff(avail_gpa_, 2, sizeof(std::uint16_t)));
    if (!p) return last_avail_;
    return AcquireLoad16(p);
}
std::uint16_t Virtqueue::LoadAvailFlags() const {
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpaOff(avail_gpa_, 0, sizeof(std::uint16_t)));
    if (!p) return 0;
    return AcquireLoad16(p);
}
std::uint16_t Virtqueue::LoadAvailRing(std::uint16_t slot) const {
    std::uint64_t off = 4 + sizeof(std::uint16_t) * slot;
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpaOff(avail_gpa_, off, sizeof(std::uint16_t)));
    if (!p) return 0;
    return *p;
}
std::uint16_t Virtqueue::LoadUsedEvent() const {
    std::uint64_t off = 4 + sizeof(std::uint16_t) * size_;
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpaOff(avail_gpa_, off, sizeof(std::uint16_t)));
    if (!p) return 0;
    return AcquireLoad16(p);
}

void Virtqueue::StoreUsedIdx(std::uint16_t idx) {
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpaOff(used_gpa_, 2, sizeof(std::uint16_t)));
    if (!p) return;
    ReleaseStore16(p, idx);
}
void Virtqueue::StoreUsedRing(std::uint16_t slot, std::uint32_t id,
                              std::uint32_t len) {
    std::uint64_t off = 4 + sizeof(VringUsedElem) * slot;
    auto* p = static_cast<VringUsedElem*>(
        HostFromGpaOff(used_gpa_, off, sizeof(VringUsedElem)));
    if (!p) return;
    p->id = id;
    p->len = len;
}

void Virtqueue::StoreAvailEvent(std::uint16_t event_idx) {
    // `avail_event` lives at the tail of the used ring, after the
    // `flags(2) + idx(2) + ring[size]*8 = 4 + 8*size` prefix.
    std::uint64_t off = 4 + sizeof(VringUsedElem) * size_;
    auto* p = static_cast<std::uint16_t*>(
        HostFromGpaOff(used_gpa_, off, sizeof(std::uint16_t)));
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
        // Take a one-shot snapshot of the descriptor before any
        // validation. The descriptor table lives in guest-shared
        // memory and a hostile guest may mutate it between accesses,
        // which would turn a successful bounds check on `d.next` into
        // a use of a different `d.next` (TOCTOU) and let us index
        // `desc_table[OOB]`. Reading once via memcpy fixes that.
        VringDesc d;
        std::memcpy(&d, &desc_table[cur], sizeof(d));

        if (d.flags & kVringDescFIndirect) {
            std::uint32_t inner_count = d.len / sizeof(VringDesc);
            auto* inner = static_cast<VringDesc*>(HostFromGpa(d.addr, d.len));
            if (!inner) break;
            std::uint32_t i = 0;
            for (std::uint32_t step = 0; step < inner_count && step < size_;
                 ++step) {
                VringDesc id;
                std::memcpy(&id, &inner[i], sizeof(id));
                void* host = HostFromGpa(id.addr, id.len);
                if (host) {
                    out.bufs.push_back(ChainBuf{
                        std::span<std::uint8_t>(
                            static_cast<std::uint8_t*>(host), id.len),
                        (id.flags & kVringDescFWrite) != 0});
                }
                if (!(id.flags & kVringDescFNext)) break;
                if (id.next >= inner_count) break;
                i = id.next;
            }
        } else {
            void* host = HostFromGpa(d.addr, d.len);
            if (host) {
                out.bufs.push_back(ChainBuf{
                    std::span<std::uint8_t>(
                        static_cast<std::uint8_t*>(host), d.len),
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

// ----------------------- M33.4 save/restore ---------------------------

Virtqueue::State Virtqueue::CaptureState() const {
    State s;
    s.size               = size_;
    s.ready              = ready_ ? 1u : 0u;
    s.event_idx          = event_idx_ ? 1u : 0u;
    s.desc_gpa           = desc_gpa_;
    s.avail_gpa          = avail_gpa_;
    s.used_gpa           = used_gpa_;
    s.last_avail         = last_avail_;
    s.last_used_idx      = last_used_idx_;
    s.last_used_signaled = last_used_signaled_;
    return s;
}

void Virtqueue::ApplyState(const State& s) {
    size_                = s.size;
    ready_               = s.ready != 0;
    event_idx_           = s.event_idx != 0;
    desc_gpa_            = s.desc_gpa;
    avail_gpa_           = s.avail_gpa;
    used_gpa_            = s.used_gpa;
    last_avail_          = s.last_avail;
    last_used_idx_       = s.last_used_idx;
    last_used_signaled_  = s.last_used_signaled;
}

std::size_t Virtqueue::EncodeState(const State& s,
                                   std::vector<std::uint8_t>& out) {
    using namespace tinyvmm::whp::snapshot;
    const std::size_t start = out.size();
    out.resize(start + kEncodedSize, 0);
    std::uint8_t* p = out.data() + start;
    WriteLe32(p +  0, s.size);
    p[4] = s.ready;
    p[5] = s.event_idx;
    // p[6..7] = u16 pad (already zero)
    WriteLe64(p +  8, s.desc_gpa);
    WriteLe64(p + 16, s.avail_gpa);
    WriteLe64(p + 24, s.used_gpa);
    // p[32..33] = u16 last_avail
    p[32] = static_cast<std::uint8_t>(s.last_avail        & 0xFF);
    p[33] = static_cast<std::uint8_t>((s.last_avail >> 8) & 0xFF);
    p[34] = static_cast<std::uint8_t>(s.last_used_idx        & 0xFF);
    p[35] = static_cast<std::uint8_t>((s.last_used_idx >> 8) & 0xFF);
    p[36] = static_cast<std::uint8_t>(s.last_used_signaled        & 0xFF);
    p[37] = static_cast<std::uint8_t>((s.last_used_signaled >> 8) & 0xFF);
    // p[38..39] = u16 pad (already zero)
    return kEncodedSize;
}

Virtqueue::State Virtqueue::DecodeState(std::span<const std::uint8_t> bytes) {
    using namespace tinyvmm::whp::snapshot;
    if (bytes.size() < kEncodedSize) {
        throw std::runtime_error(
            "Virtqueue::DecodeState: payload too small");
    }
    const std::uint8_t* p = bytes.data();
    State s;
    s.size               = ReadLe32(p + 0);
    s.ready              = p[4];
    s.event_idx          = p[5];
    if (p[6] != 0 || p[7] != 0) {
        throw std::runtime_error("Virtqueue::DecodeState: nonzero pad@6");
    }
    s.desc_gpa           = ReadLe64(p +  8);
    s.avail_gpa          = ReadLe64(p + 16);
    s.used_gpa           = ReadLe64(p + 24);
    s.last_avail         = static_cast<std::uint16_t>(p[32] | (p[33] << 8));
    s.last_used_idx      = static_cast<std::uint16_t>(p[34] | (p[35] << 8));
    s.last_used_signaled = static_cast<std::uint16_t>(p[36] | (p[37] << 8));
    if (p[38] != 0 || p[39] != 0) {
        throw std::runtime_error("Virtqueue::DecodeState: nonzero pad@38");
    }
    return s;
}

}  // namespace tinyvmm::virtio
