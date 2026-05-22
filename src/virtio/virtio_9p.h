#pragma once

// virtio-9p (M32). Spec §5.16 "9P Transport Device".
//
// One queue (requestq, qidx=0). Each chain is a single request/reply
// pair: the driver places the T-message (request) in the device-
// readable buffers, the device writes the R-message (reply) into the
// device-writable buffers in the same chain.
//
// 9P2000.L protocol used by Linux is documented in
//   Documentation/filesystems/9p.rst and `include/net/9p/9p.h` in the
//   kernel tree. We implement message types incrementally:
//
//   * Phase 1 (this file):  Tversion / Tattach -- enough for
//                            `mount -t 9p ...` to succeed.
//                            Everything else returns Rlerror(ENOSYS).
//   * Phase 2 (later):       Twalk, Tlopen, Tlcreate, Tread, Twrite,
//                            Tgetattr, Tsetattr, Treaddir, Tclunk,
//                            Tremove, Tfsync, Tflush.
//   * Phase 3 (later):       Tmkdir, Trename*, Tunlinkat, Tstatfs.
//
// Threading: NotifyQueue runs on whichever vCPU thread wrote the
// queue-notify MMIO. We serialise drains across vCPUs with notify_mu_;
// the host-side filesystem work (Phase 3) will additionally be
// thread-safe by virtue of Win32 file APIs being thread-safe per
// HANDLE.

#include "common.h"
#include "whp/memory.h"
#include "virtio.h"
#include "virtqueue.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace tinyvmm::virtio {

inline constexpr std::uint32_t kP9RequestQueueIdx = 0;
inline constexpr std::uint32_t kP9QueueCount      = 1;
inline constexpr std::uint32_t kP9QueueMax        = 128;

// Spec §5.16.3 -- the only 9P feature bit defined.
inline constexpr std::uint64_t kP9FeatureMountTag = 1ULL << 0;

// Protocol caps (Phase 1 hard-coded; tunable later).
inline constexpr std::uint32_t kP9MsizeMax = 1u << 20;  // 1 MiB
inline constexpr std::uint32_t kP9MsizeMin = 4096;       // sane floor

// 9P2000.L message type constants. Same numeric values as in the
// Linux kernel's include/net/9p/9p.h. Phase 1 only handles
// kP9TVersion / kP9TAttach; the rest are listed so the dispatch
// switch reads as self-documenting.
enum P9MsgType : std::uint8_t {
    kP9TLerror     = 6,   // unused on the wire (kept for symmetry)
    kP9RLerror     = 7,
    kP9TStatfs     = 8,    kP9RStatfs     = 9,
    kP9TLopen      = 12,   kP9RLopen      = 13,
    kP9TLcreate    = 14,   kP9RLcreate    = 15,
    kP9TSymlink    = 16,   kP9RSymlink    = 17,
    kP9TMknod      = 18,   kP9RMknod      = 19,
    kP9TRename     = 20,   kP9RRename     = 21,
    kP9TReadlink   = 22,   kP9RReadlink   = 23,
    kP9TGetattr    = 24,   kP9RGetattr    = 25,
    kP9TSetattr    = 26,   kP9RSetattr    = 27,
    kP9TXattrwalk  = 30,   kP9RXattrwalk  = 31,
    kP9TXattrcreate= 32,   kP9RXattrcreate= 33,
    kP9TReaddir    = 40,   kP9RReaddir    = 41,
    kP9TFsync      = 50,   kP9RFsync      = 51,
    kP9TLock       = 52,   kP9RLock       = 53,
    kP9TGetlock    = 54,   kP9RGetlock    = 55,
    kP9TLink       = 70,   kP9RLink       = 71,
    kP9TMkdir      = 72,   kP9RMkdir      = 73,
    kP9TRenameat   = 74,   kP9RRenameat   = 75,
    kP9TUnlinkat   = 76,   kP9RUnlinkat   = 77,
    kP9TVersion    = 100,  kP9RVersion    = 101,
    kP9TAuth       = 102,  kP9RAuth       = 103,
    kP9TAttach     = 104,  kP9RAttach     = 105,
    kP9TFlush      = 108,  kP9RFlush      = 109,
    kP9TWalk       = 110,  kP9RWalk       = 111,
    kP9TRead       = 116,  kP9RRead       = 117,
    kP9TWrite      = 118,  kP9RWrite      = 119,
    kP9TClunk      = 120,  kP9RClunk      = 121,
    kP9TRemove     = 122,  kP9RRemove     = 123,
};

// 9P QID type bits (spec §"qid"). type | version[4B] | path[8B] = 13B QID.
inline constexpr std::uint8_t kP9QTDir    = 0x80;
inline constexpr std::uint8_t kP9QTAppend = 0x40;
inline constexpr std::uint8_t kP9QTExcl   = 0x20;
inline constexpr std::uint8_t kP9QTAuth   = 0x08;
inline constexpr std::uint8_t kP9QTTmp    = 0x04;
inline constexpr std::uint8_t kP9QTSymlink= 0x02;
inline constexpr std::uint8_t kP9QTLink   = 0x01;
inline constexpr std::uint8_t kP9QTFile   = 0x00;

// FID sentinel used by Tattach when no auth FID is established.
inline constexpr std::uint32_t kP9NoFid = 0xFFFFFFFFu;

// Sentinel ecode in Rlerror replies for "we know about this op but
// haven't implemented it yet". Linux errno.h: ENOSYS = 38.
inline constexpr std::uint32_t kP9ErrNosys = 38;

// One host directory exposed by this device. One device = one share.
struct P9Share {
    std::string             tag;        // mount-tag advertised in cfg
    std::filesystem::path   host_root;  // absolute, canonical
    bool                    readonly;
};

class P9Device : public Device {
public:
    using IrqFn = std::function<void(std::uint32_t qidx)>;

    P9Device(whp::GuestMemory& mem, P9Share share, IrqFn irq = {});

    // ---------------------- Device interface --------------------------
    std::uint32_t DeviceId() const override { return kDeviceIdP9; }
    std::uint64_t DeviceFeatures() const override;
    bool SetDriverFeatures(std::uint64_t acked) override;

    std::uint32_t QueueCount() const override { return kP9QueueCount; }
    std::uint32_t QueueMax(std::uint32_t idx) const override;
    Virtqueue* GetQueue(std::uint32_t idx) override;

    void NotifyQueue(std::uint32_t idx) override;
    void DriverOk() override { driver_ok_ = true; }
    void Reset() override;

    // Config space: u16 tag_len + tag bytes (spec §5.16.4).
    std::uint32_t ReadConfig(std::uint32_t offset, std::uint32_t size) override;
    void WriteConfig(std::uint32_t, std::uint32_t, std::uint32_t) override {}

    void SetIrqCallback(IrqFn fn) { irq_ = std::move(fn); }

    // ---------------------- Diagnostics ------------------------------
    bool driver_ok() const noexcept { return driver_ok_; }
    std::uint64_t acked_features() const noexcept { return acked_features_; }
    std::uint32_t negotiated_msize() const noexcept { return negotiated_msize_; }
    std::uint64_t requests_handled() const noexcept {
        return requests_.load(std::memory_order_relaxed);
    }
    std::uint64_t rlerrors_emitted() const noexcept {
        return rlerrors_.load(std::memory_order_relaxed);
    }
    const P9Share& share() const noexcept { return share_; }
    Virtqueue& request_queue() noexcept { return queue_; }

private:
    // Per-FID state. Phase 1 only tracks ROOT_FID -> share.host_root.
    // Phase 2+ will extend this with open handles, mode flags, dir
    // iterators, etc.
    struct FidEntry {
        std::filesystem::path host_path;
        bool                  is_dir;
        // Stable 64-bit qid path. For Phase 1 we synthesise from a
        // counter rather than from FileIndex (which would require an
        // open handle); good enough until Phase 3 wires the real
        // Win32 backend.
        std::uint64_t         qid_path;
    };

    void DrainRequestQueue();

    // Concatenate the device-readable portion of |chain| into a
    // contiguous buffer for parsing. T-messages handled in Phase 1
    // are at most ~280 bytes; larger ones will arrive in later
    // phases but the 1 MiB msize cap keeps this trivially safe.
    static std::vector<std::uint8_t> ReadChain(const std::vector<ChainBuf>& bufs);

    // Scatter-copy |reply| into the device-writable portion of
    // |bufs| starting at the first write buffer. Returns the number
    // of bytes actually written (capped at total writable capacity).
    static std::uint32_t WriteChain(std::vector<ChainBuf>& bufs,
                                     const std::vector<std::uint8_t>& reply);

    // Build an Rlerror(ecode) reply with tag=|tag| in |reply|.
    static void BuildRlerror(std::vector<std::uint8_t>& reply,
                              std::uint16_t tag, std::uint32_t ecode);

    // Build the static config bytes (u16 tag_len + tag) once at ctor.
    static std::vector<std::uint8_t> BuildConfigBytes(const std::string& tag);

    // Wire encoders -- all little-endian, in-place append.
    static void Encode1(std::vector<std::uint8_t>& out, std::uint8_t v);
    static void Encode2(std::vector<std::uint8_t>& out, std::uint16_t v);
    static void Encode4(std::vector<std::uint8_t>& out, std::uint32_t v);
    static void Encode8(std::vector<std::uint8_t>& out, std::uint64_t v);
    static void EncodeString(std::vector<std::uint8_t>& out,
                              const std::string& s);
    static void EncodeQid(std::vector<std::uint8_t>& out,
                           std::uint8_t type, std::uint32_t version,
                           std::uint64_t path);
    // Fix up the size header at offset 0 of |out| to equal out.size().
    static void FinalizeMessage(std::vector<std::uint8_t>& out);

    // Wire decoders -- bounds-checked.
    static bool Decode1(const std::vector<std::uint8_t>& in,
                         std::size_t& off, std::uint8_t& v);
    static bool Decode2(const std::vector<std::uint8_t>& in,
                         std::size_t& off, std::uint16_t& v);
    static bool Decode4(const std::vector<std::uint8_t>& in,
                         std::size_t& off, std::uint32_t& v);
    static bool DecodeString(const std::vector<std::uint8_t>& in,
                              std::size_t& off, std::string& s);

    // ---- T-message handlers (Phase 1 implements: Tversion / Tattach /
    //                                              Tgetattr / Tclunk).
    //      Tgetattr returns synthetic root-dir attrs for any tracked fid
    //      so `mount -t 9p ...` succeeds; the proper Win32-backed stat
    //      lands in Phase 3. Tclunk releases the fid so umount + the
    //      kernel's normal fid-recycling don't leak entries.
    //      The rest TODO. All return the encoded R-message in |reply|. -
    void HandleTversion(std::uint16_t tag,
                         const std::vector<std::uint8_t>& body,
                         std::vector<std::uint8_t>& reply);
    void HandleTattach(std::uint16_t tag,
                        const std::vector<std::uint8_t>& body,
                        std::vector<std::uint8_t>& reply);
    void HandleTgetattr(std::uint16_t tag,
                         const std::vector<std::uint8_t>& body,
                         std::vector<std::uint8_t>& reply);
    void HandleTclunk(std::uint16_t tag,
                       const std::vector<std::uint8_t>& body,
                       std::vector<std::uint8_t>& reply);

    // -------------------------- state -------------------------------
    Virtqueue                   queue_;
    P9Share                     share_;
    std::vector<std::uint8_t>   config_bytes_;
    bool                        driver_ok_       = false;
    std::uint64_t               acked_features_  = 0;
    std::uint32_t               negotiated_msize_ = 0;
    // Set true when an Rversion has been sent. Pre-Tversion, the
    // protocol per spec is undefined for any T-msg other than
    // Tversion. We follow Linux's behaviour and just dispatch
    // normally; that's fine because Linux never sends anything else
    // before Tversion in practice.

    std::atomic<std::uint64_t>  requests_{0};
    std::atomic<std::uint64_t>  rlerrors_{0};

    std::mutex                                    fids_mu_;
    std::unordered_map<std::uint32_t, FidEntry>   fids_;
    // QID-path allocator. Phase 1 hands out monotonically-increasing
    // identifiers from this counter; Phase 3 will replace with
    // Win32 GetFileInformationByHandle.FileIndex.
    std::uint64_t                                 next_qid_path_ = 1;

    std::mutex notify_mu_;
    IrqFn      irq_;
};

}  // namespace tinyvmm::virtio
