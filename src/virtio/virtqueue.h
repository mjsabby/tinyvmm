#pragma once

// Split-virtqueue accessor (virtio v1.0+ layout, spec §2.7).
// One Virtqueue owns (size, desc_gpa, avail_gpa, used_gpa, ready). Memory
// for the rings lives in guest RAM and is dereferenced lazily via
// GuestMemory.

#include "../common.h"
#include "../whp/memory.h"
#include "virtio.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace tinyvmm::virtio {

// One element in a popped descriptor chain.
struct ChainBuf {
    void* host_addr;
    std::uint32_t len;
    bool write;       // device writes into this buffer
};

struct PoppedChain {
    std::uint16_t head_index;
    std::vector<ChainBuf> bufs;
};

class Virtqueue {
public:
    explicit Virtqueue(whp::GuestMemory& mem, std::uint32_t max_size)
        : mem_(mem), max_size_(max_size) {}

    void SetSize(std::uint32_t size) { size_ = size; }
    void SetDescGpa(std::uint64_t gpa) { desc_gpa_ = gpa; }
    void SetAvailGpa(std::uint64_t gpa) { avail_gpa_ = gpa; }
    void SetUsedGpa(std::uint64_t gpa) { used_gpa_ = gpa; }
    void SetReady(bool ready) { ready_ = ready; }
    void SetEventIdxEnabled(bool en) { event_idx_ = en; }
    void Reset();

    std::uint32_t size() const noexcept { return size_; }
    std::uint32_t max_size() const noexcept { return max_size_; }
    bool ready() const noexcept { return ready_; }
    std::uint64_t desc_gpa() const noexcept { return desc_gpa_; }
    std::uint64_t avail_gpa() const noexcept { return avail_gpa_; }
    std::uint64_t used_gpa() const noexcept { return used_gpa_; }

    std::optional<PoppedChain> Pop();
    void Push(std::uint16_t head_index, std::uint32_t used_len);

    // After Push()ing, ask whether the driver wants an interrupt now.
    bool ShouldInterruptDriver();

    // The §2.7.10 vring_need_event predicate, in static form.
    static bool VringNeedEvent(std::uint16_t event_idx,
                               std::uint16_t new_idx,
                               std::uint16_t old_idx);

private:
    void* HostFromGpa(std::uint64_t gpa, std::uint32_t bytes) const;

    std::uint16_t LoadAvailIdx() const;
    std::uint16_t LoadAvailRing(std::uint16_t slot) const;
    std::uint16_t LoadAvailFlags() const;
    std::uint16_t LoadUsedEvent() const;       // EVENT_IDX only

    void StoreUsedIdx(std::uint16_t idx);
    void StoreUsedRing(std::uint16_t slot, std::uint32_t id,
                       std::uint32_t len);
    // Writes the device's "kick me when avail.idx reaches this+1" hint
    // (`avail_event`) at the tail of the used ring. Only meaningful when
    // EVENT_IDX has been negotiated.
    void StoreAvailEvent(std::uint16_t event_idx);

    whp::GuestMemory& mem_;
    std::uint32_t max_size_;
    std::uint32_t size_ = 0;
    bool ready_ = false;
    bool event_idx_ = false;

    std::uint64_t desc_gpa_ = 0;
    std::uint64_t avail_gpa_ = 0;
    std::uint64_t used_gpa_ = 0;

    std::uint16_t last_avail_ = 0;
    std::uint16_t last_used_idx_ = 0;
    std::uint16_t last_used_signaled_ = 0;
};

}  // namespace tinyvmm::virtio
