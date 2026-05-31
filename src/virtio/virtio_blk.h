#pragma once

// virtio-blk device (spec §5.2). Pairs with any virtio transport (MMIO or
// PCI). Uses host::BlockFile as the async backend; one IOCP thread per disk
// drives completions.
//
// Threading model:
//   * vCPU thread (or whatever calls into MmioBus dispatch) invokes
//     NotifyQueue(0). That call drains the avail ring, decodes each
//     virtio_blk_req header, and posts the data segments to BlockFile.
//   * IOCP worker thread runs OnComplete(), which advances the per-request
//     state machine. After the last segment + status byte, it Push()es the
//     used ring and calls the IRQ callback the transport handed us.
//
// Synchronisation: queue Pop/Push run on different threads, but Pop touches
// only `last_avail_` and Push touches only `last_used_idx_` /
// `last_used_signaled_`. We still guard them with `queue_mu_` to make the
// model explicit + safe under tools like TSan; ShouldInterruptDriver() is
// always called under the same lock.

#include "common.h"
#include "host/block_file.h"
#include "whp/memory.h"
#include "virtio.h"
#include "virtqueue.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

namespace tinyvmm::virtio {

// virtio-blk feature bits (spec §5.2.3).
inline constexpr std::uint64_t kBlkFeatureSizeMax     = 1ULL << 1;
inline constexpr std::uint64_t kBlkFeatureSegMax      = 1ULL << 2;
inline constexpr std::uint64_t kBlkFeatureGeometry    = 1ULL << 4;
inline constexpr std::uint64_t kBlkFeatureRo          = 1ULL << 5;
inline constexpr std::uint64_t kBlkFeatureBlkSize     = 1ULL << 6;
inline constexpr std::uint64_t kBlkFeatureFlush       = 1ULL << 9;
inline constexpr std::uint64_t kBlkFeatureTopology    = 1ULL << 10;
inline constexpr std::uint64_t kBlkFeatureDiscard     = 1ULL << 13;
inline constexpr std::uint64_t kBlkFeatureWriteZeroes = 1ULL << 14;

// virtio_blk_req::type values.
inline constexpr std::uint32_t kBlkTypeIn          = 0;
inline constexpr std::uint32_t kBlkTypeOut         = 1;
inline constexpr std::uint32_t kBlkTypeFlush       = 4;
inline constexpr std::uint32_t kBlkTypeGetId       = 8;
inline constexpr std::uint32_t kBlkTypeDiscard     = 11;
inline constexpr std::uint32_t kBlkTypeWriteZeroes = 13;

// DISCARD / WRITE_ZEROES range descriptor (spec §5.2.6.2). Follows the
// 16-byte request header in the descriptor chain (one or more, then
// the trailing status byte).
struct BlkDiscardWriteZeroes {
    std::uint64_t sector;
    std::uint32_t num_sectors;
    std::uint32_t flags;   // bit 0 = unmap (WRITE_ZEROES only)
};
static_assert(sizeof(BlkDiscardWriteZeroes) == 16,
              "BlkDiscardWriteZeroes must be 16 bytes");
inline constexpr std::uint32_t kBlkWriteZeroesFlagUnmap = 1U << 0;

// Status byte values.
inline constexpr std::uint8_t kBlkStatusOk      = 0;
inline constexpr std::uint8_t kBlkStatusIoErr   = 1;
inline constexpr std::uint8_t kBlkStatusUnsupp  = 2;

inline constexpr std::uint32_t kBlkSectorSize   = 512;

class BlockDevice : public Device {
public:
    // IrqFn(qidx) is called by the IOCP worker after a request completes; the
    // wrapping transport plugs in something like
    //   [tx](uint32_t q){ tx->RaiseQueueInterrupt(q); }
    using IrqFn = std::function<void(std::uint32_t qidx)>;

    BlockDevice(whp::GuestMemory& mem, host::BlockFile& backend,
                IrqFn irq, std::uint32_t queue_max = 256);
    ~BlockDevice() override;

    // virtio::Device.
    std::uint32_t DeviceId() const override { return kDeviceIdBlk; }
    std::uint64_t DeviceFeatures() const override;
    bool          SetDriverFeatures(std::uint64_t acked) override;
    std::uint32_t QueueCount() const override { return 1; }
    std::uint32_t QueueMax(std::uint32_t idx) const override;
    Virtqueue*    GetQueue(std::uint32_t idx) override;
    void          NotifyQueue(std::uint32_t idx) override;
    void          DriverOk() override;
    void          Reset() override;
    std::uint32_t ReadConfig (std::uint32_t off, std::uint32_t size) override;
    void          WriteConfig(std::uint32_t off, std::uint32_t size,
                              std::uint32_t value) override;

    void SetIrqCallback(IrqFn fn) { irq_ = std::move(fn); }

    // Diagnostics.
    std::uint64_t ops_in()             const { return ops_in_.load(); }
    std::uint64_t ops_out()            const { return ops_out_.load(); }
    std::uint64_t ops_flush()          const { return ops_flush_.load(); }
    std::uint64_t ops_discard()        const { return ops_discard_.load(); }
    std::uint64_t ops_write_zeroes()   const { return ops_write_zeroes_.load(); }
    std::uint64_t ops_err()            const { return ops_err_.load(); }
    std::uint64_t ops_done()           const { return ops_done_.load(); }

    // Number of in-flight requests submitted to the backend but not yet
    // completed. Used by the Phase 33.6 quiesce-before-save loop: the
    // production --save path polls this until it reaches zero (or
    // refuses with a timeout). Thread-safe; takes pending_mu_.
    std::size_t PendingCount() const {
        std::lock_guard<std::mutex> g(pending_mu_);
        return pending_.size();
    }

    // ----- M33.4 save/restore -------------------------------------------
    // Captures the durable virtio-blk state. The backend (host BlockFile)
    // is reconstructed by the restore caller with the saved drive path +
    // readonly flag; this struct only carries device-level state.
    struct State {
        std::uint64_t driver_features = 0;
        std::uint8_t  blk_cfg[64]     = {};
    };
    static constexpr std::size_t kEncodedSize = 8 + 64;

    State CaptureState() const {
        State s;
        s.driver_features = driver_features_;
        std::memcpy(s.blk_cfg, blk_cfg_, sizeof(s.blk_cfg));
        return s;
    }
    void ApplyState(const State& s) {
        driver_features_ = s.driver_features;
        std::memcpy(blk_cfg_, s.blk_cfg, sizeof(blk_cfg_));
    }

    static std::size_t EncodeState(const State& s,
                                   std::vector<std::uint8_t>& out);
    static State       DecodeState(std::span<const std::uint8_t> bytes);

private:
    // Per virtio_blk request. Inherits the OVERLAPPED via BlockFile::Request.
    struct Req : public host::BlockFile::Request {
        BlockDevice*  dev = nullptr;
        std::uint16_t head_idx = 0;
        std::uint32_t type = 0;
        std::vector<ChainBuf> data_segs;
        std::size_t   cur_seg = 0;
        std::uint64_t cur_file_offset = 0;
        std::uint32_t total_done = 0;
        std::uint8_t* status_byte = nullptr;
        bool          failed = false;
    };

    void OnComplete(host::BlockFile::Request* req);
    void SubmitNext(Req* r);
    void FinishRequest(Req* r);
    void RaiseIrqIfNeeded();

    // Held as a reference only to pass through to Virtqueue at construction;
    // no method on BlockDevice itself accesses guest memory directly (all
    // I/O goes through descriptor chains owned by `queue_`).
    host::BlockFile&  backend_;
    IrqFn             irq_;

    std::mutex   queue_mu_;
    Virtqueue    queue_;
    std::uint64_t driver_features_ = 0;
    std::uint8_t  blk_cfg_[64] = {};

    mutable std::mutex pending_mu_;
    std::vector<std::unique_ptr<Req>> pending_;

    std::atomic<std::uint64_t> ops_in_{0};
    std::atomic<std::uint64_t> ops_out_{0};
    std::atomic<std::uint64_t> ops_flush_{0};
    std::atomic<std::uint64_t> ops_discard_{0};
    std::atomic<std::uint64_t> ops_write_zeroes_{0};
    std::atomic<std::uint64_t> ops_err_{0};
    std::atomic<std::uint64_t> ops_done_{0};
};

}  // namespace tinyvmm::virtio
