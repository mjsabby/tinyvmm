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
//   * Phase 1 (shipped 1dd9abc):  Tversion / Tattach / Tgetattr-stub /
//                                  Tclunk -- enough for mount() to
//                                  succeed; everything else ENOSYS.
//   * Phase 2 (this file):        Full Win32 backend. Twalk / Tlopen /
//                                  Tlcreate / Tread / Twrite /
//                                  Treaddir / Tgetattr / Tsetattr /
//                                  Tremove / Tfsync / Tflush /
//                                  Tmkdir / Trename / Trenameat /
//                                  Tunlinkat / Tstatfs. Linux user-
//                                  space tools (ls, cat, echo, cp,
//                                  rm, mkdir, rmdir, mv) all work.
//   * Phase 3 (later):             ENOSYS stubs for symlink/lock/
//                                  xattr/etc. already in default arm.
//
// Threading: NotifyQueue runs on whichever vCPU thread wrote the
// queue-notify MMIO. We serialise drains across vCPUs with notify_mu_.
// Win32 calls happen inside the drain loop without holding fids_mu_
// (only the fid-table lookup/insert/erase steps take fids_mu_).
//
// Security model: a share root is *trusted* -- it's a directory the
// host operator chose to expose. We sanitise per-component (reject
// embedded slashes / NULs / reserved device names) and resolve "..",
// "." inside the wire path, so a misbehaving guest cannot escape
// the share via path-walking. Reparse points / junctions / symlinks
// inside the share are followed normally; we assume the operator
// only places those if they actually want them exposed.

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

// Protocol caps. Linux's virtio transport hard-caps msize at 512000
// bytes (VIRTQUEUE_NUM * PAGE_SIZE) so anything larger than that is
// wasted; we still negotiate up to 1 MiB so future transports work.
inline constexpr std::uint32_t kP9MsizeMax = 1u << 20;
inline constexpr std::uint32_t kP9MsizeMin = 4096;

// 9P2000.L message type constants. Same numeric values as in the
// Linux kernel's include/net/9p/9p.h.
enum P9MsgType : std::uint8_t {
    kP9TLerror      = 6,
    kP9RLerror      = 7,
    kP9TStatfs      = 8,    kP9RStatfs      = 9,
    kP9TLopen       = 12,   kP9RLopen       = 13,
    kP9TLcreate     = 14,   kP9RLcreate     = 15,
    kP9TSymlink     = 16,   kP9RSymlink     = 17,
    kP9TMknod       = 18,   kP9RMknod       = 19,
    kP9TRename      = 20,   kP9RRename      = 21,
    kP9TReadlink    = 22,   kP9RReadlink    = 23,
    kP9TGetattr     = 24,   kP9RGetattr     = 25,
    kP9TSetattr     = 26,   kP9RSetattr     = 27,
    kP9TXattrwalk   = 30,   kP9RXattrwalk   = 31,
    kP9TXattrcreate = 32,   kP9RXattrcreate = 33,
    kP9TReaddir     = 40,   kP9RReaddir     = 41,
    kP9TFsync       = 50,   kP9RFsync       = 51,
    kP9TLock        = 52,   kP9RLock        = 53,
    kP9TGetlock     = 54,   kP9RGetlock     = 55,
    kP9TLink        = 70,   kP9RLink        = 71,
    kP9TMkdir       = 72,   kP9RMkdir       = 73,
    kP9TRenameat    = 74,   kP9RRenameat    = 75,
    kP9TUnlinkat    = 76,   kP9RUnlinkat    = 77,
    kP9TVersion     = 100,  kP9RVersion     = 101,
    kP9TAuth        = 102,  kP9RAuth        = 103,
    kP9TAttach      = 104,  kP9RAttach      = 105,
    kP9TFlush       = 108,  kP9RFlush       = 109,
    kP9TWalk        = 110,  kP9RWalk        = 111,
    kP9TRead        = 116,  kP9RRead        = 117,
    kP9TWrite       = 118,  kP9RWrite       = 119,
    kP9TClunk       = 120,  kP9RClunk       = 121,
    kP9TRemove      = 122,  kP9RRemove      = 123,
};

// 9P QID type bits (spec §"qid").
inline constexpr std::uint8_t kP9QTDir     = 0x80;
inline constexpr std::uint8_t kP9QTAppend  = 0x40;
inline constexpr std::uint8_t kP9QTExcl    = 0x20;
inline constexpr std::uint8_t kP9QTAuth    = 0x08;
inline constexpr std::uint8_t kP9QTTmp     = 0x04;
inline constexpr std::uint8_t kP9QTSymlink = 0x02;
inline constexpr std::uint8_t kP9QTLink    = 0x01;
inline constexpr std::uint8_t kP9QTFile    = 0x00;

// Tgetattr request_mask bits. P9_STATS_BASIC covers the fields
// Linux's mount + stat path actually needs.
inline constexpr std::uint64_t kP9StatsBasic = 0x000007FFULL;

// FID sentinel used by Tattach when no auth FID is established.
inline constexpr std::uint32_t kP9NoFid = 0xFFFFFFFFu;

// Linux errno values used here. We don't pull <errno.h> because
// MSVC's errno values do not match Linux's.
inline constexpr std::uint32_t kP9Eperm        = 1;
inline constexpr std::uint32_t kP9Enoent       = 2;
inline constexpr std::uint32_t kP9Eio          = 5;
inline constexpr std::uint32_t kP9Ebadf        = 9;
inline constexpr std::uint32_t kP9Eacces       = 13;
inline constexpr std::uint32_t kP9Eexist       = 17;
inline constexpr std::uint32_t kP9Enotdir      = 20;
inline constexpr std::uint32_t kP9Eisdir       = 21;
inline constexpr std::uint32_t kP9Einval       = 22;
inline constexpr std::uint32_t kP9Emfile       = 24;
inline constexpr std::uint32_t kP9Enospc       = 28;
inline constexpr std::uint32_t kP9Erofs        = 30;
inline constexpr std::uint32_t kP9Enametoolong = 36;
inline constexpr std::uint32_t kP9Enosys       = 38;
inline constexpr std::uint32_t kP9Enotempty    = 39;
inline constexpr std::uint32_t kP9Eproto       = 71;

// 9P2000.L open flags (same numeric values as Linux <fcntl.h> on
// x86_64).
inline constexpr std::uint32_t kP9OAccmode    = 0x0003;
inline constexpr std::uint32_t kP9ORdonly     = 0x0000;
inline constexpr std::uint32_t kP9OWronly     = 0x0001;
inline constexpr std::uint32_t kP9ORdwr       = 0x0002;
inline constexpr std::uint32_t kP9OCreat      = 0x0040;
inline constexpr std::uint32_t kP9OExcl       = 0x0080;
inline constexpr std::uint32_t kP9OTrunc      = 0x0200;
inline constexpr std::uint32_t kP9OAppend     = 0x0400;
inline constexpr std::uint32_t kP9ODirectory  = 0x10000;
inline constexpr std::uint32_t kP9ONofollow   = 0x20000;

// Tsetattr valid bitmap (9P2000.L spec).
inline constexpr std::uint32_t kP9SetattrMode      = 0x00000001;
inline constexpr std::uint32_t kP9SetattrUid       = 0x00000002;
inline constexpr std::uint32_t kP9SetattrGid       = 0x00000004;
inline constexpr std::uint32_t kP9SetattrSize      = 0x00000008;
inline constexpr std::uint32_t kP9SetattrAtime     = 0x00000010;
inline constexpr std::uint32_t kP9SetattrMtime     = 0x00000020;
inline constexpr std::uint32_t kP9SetattrCtime     = 0x00000040;
inline constexpr std::uint32_t kP9SetattrAtimeSet  = 0x00000080;
inline constexpr std::uint32_t kP9SetattrMtimeSet  = 0x00000100;

// Tunlinkat flags.
inline constexpr std::uint32_t kP9AtRemoveDir = 0x200;

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
    ~P9Device() override;

    P9Device(const P9Device&)            = delete;
    P9Device& operator=(const P9Device&) = delete;

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

    // ---------------------- Test hooks --------------------------------
    // Bypass the virtqueue and feed one T-message body straight into
    // the dispatcher. Returns the encoded R-message. For unit tests
    // only. Bumps requests_/rlerrors_ counters as normal.
    std::vector<std::uint8_t> InjectMessage(
        const std::vector<std::uint8_t>& full_t_msg);

    // Last completed-iteration request/reply pair, for tests.
    std::uint64_t fids_size() noexcept;

private:
    // Per-FID state. Owns the Win32 HANDLE (if any) -- the dtor /
    // CloseFid() closes it. Move-only.
    struct FidEntry {
        std::filesystem::path host_path;
        bool                  is_dir       = false;
        std::uint64_t         qid_path     = 0;
        // Open-handle state (set by Tlopen / Tlcreate, cleared by
        // Tclunk / Tremove / Reset).
        void*                 handle       = nullptr;   // INVALID_HANDLE_VALUE sentinel
        bool                  opened       = false;
        std::uint32_t         open_flags   = 0;
        // Directory enumeration cache populated on first Treaddir.
        // Each entry: { qid, type, name }. Position is cookie-driven.
        struct DirEntryCached {
            std::uint8_t  qid_type;
            std::uint32_t qid_version;
            std::uint64_t qid_path;
            std::uint8_t  d_type;
            std::string   name;
        };
        std::vector<DirEntryCached> dir_cache;
        bool                        dir_cache_built = false;

        FidEntry() = default;
        FidEntry(FidEntry&&) noexcept;
        FidEntry& operator=(FidEntry&&) noexcept;
        FidEntry(const FidEntry&)            = delete;
        FidEntry& operator=(const FidEntry&) = delete;
        ~FidEntry();
        // Close any open handle without destroying the entry.
        void CloseHandle() noexcept;
    };

    void DrainRequestQueue();
    void DispatchMessage(const std::vector<std::uint8_t>& t_msg,
                         std::vector<std::uint8_t>&       reply,
                         std::uint32_t                    writable_cap);

    // Concatenate the device-readable portion of |chain| into a
    // contiguous buffer for parsing.
    static std::vector<std::uint8_t> ReadChain(const std::vector<ChainBuf>& bufs);

    // Scatter-copy |reply| into the device-writable portion of
    // |bufs| starting at the first write buffer. Returns the number
    // of bytes actually written (capped at total writable capacity).
    static std::uint32_t WriteChain(std::vector<ChainBuf>& bufs,
                                     const std::vector<std::uint8_t>& reply);

    // Total bytes of device-writable buffer capacity in this chain.
    static std::uint32_t WritableCapacity(const std::vector<ChainBuf>& bufs);

    // Build an Rlerror(ecode) reply with tag=|tag| in |reply|.
    static void BuildRlerror(std::vector<std::uint8_t>& reply,
                              std::uint16_t tag, std::uint32_t ecode);

    // Build the static config bytes (u16 tag_len + tag) once at ctor.
    static std::vector<std::uint8_t> BuildConfigBytes(const std::string& tag);

    // ---- Wire encoders / decoders (LE) -------------------------------
    static void Encode1(std::vector<std::uint8_t>& out, std::uint8_t v);
    static void Encode2(std::vector<std::uint8_t>& out, std::uint16_t v);
    static void Encode4(std::vector<std::uint8_t>& out, std::uint32_t v);
    static void Encode8(std::vector<std::uint8_t>& out, std::uint64_t v);
    static void EncodeString(std::vector<std::uint8_t>& out,
                              const std::string& s);
    static void EncodeQid(std::vector<std::uint8_t>& out,
                           std::uint8_t type, std::uint32_t version,
                           std::uint64_t path);
    static void FinalizeMessage(std::vector<std::uint8_t>& out);

    static bool Decode1(const std::vector<std::uint8_t>& in,
                         std::size_t& off, std::uint8_t& v);
    static bool Decode2(const std::vector<std::uint8_t>& in,
                         std::size_t& off, std::uint16_t& v);
    static bool Decode4(const std::vector<std::uint8_t>& in,
                         std::size_t& off, std::uint32_t& v);
    static bool Decode8(const std::vector<std::uint8_t>& in,
                         std::size_t& off, std::uint64_t& v);
    static bool DecodeString(const std::vector<std::uint8_t>& in,
                              std::size_t& off, std::string& s);

    // ---- Win32 helpers (implemented in virtio_9p.cpp) ----------------
    // Convert UTF-8 → UTF-16. Returns empty wstring on conversion
    // failure or embedded NUL. The caller treats empty input as
    // distinct.
    static std::wstring Utf8ToWide(const std::string& s, bool& ok);
    // Convert UTF-16 → UTF-8.
    static std::string  WideToUtf8(const wchar_t* s, std::size_t n);
    // Map GetLastError → 9p errno.
    static std::uint32_t Win32ErrnoToP9(unsigned long win_err);
    // Convert FILETIME ↔ POSIX (sec, nsec).
    static void          FileTimeToUnix(const struct _FILETIME& ft,
                                         std::uint64_t& sec,
                                         std::uint64_t& nsec);
    static void          UnixToFileTime(std::uint64_t sec, std::uint64_t nsec,
                                         struct _FILETIME& ft);
    // Prepend "\\?\" to make Win32 lift the MAX_PATH=260 limit.
    static std::wstring  ToWin32LongPath(const std::filesystem::path& p);

    // Returns true if |comp| is a safe pathname component:
    //   * non-empty
    //   * no '/', '\\', NUL, ':', '\1'-'\31'
    //   * not "." or ".." (the caller handles those separately if
    //     it cares; sanitize rejects)
    //   * not a Windows reserved DOS device name (CON, PRN, AUX,
    //     NUL, COM1..COM9, LPT1..LPT9, optionally with extension)
    //   * doesn't end with '.' or ' '
    static bool IsSafeNameComponent(const std::string& comp);

    // Build absolute resolved path from a base + one safe child
    // component (already sanitized). The dot-dot case is handled
    // by Twalk before calling this.
    static std::filesystem::path JoinChild(
        const std::filesystem::path& base,
        const std::string&           child);

    // Does this path (lexically_normal, lowercased on Windows) lie
    // inside |root| (also normal/lower)? Used as a defense-in-depth
    // after dot-dot walks.
    bool PathContained(const std::filesystem::path& p) const;

    // Open a Win32 HANDLE on |p| for ATTRS-only stat queries. Returns
    // INVALID_HANDLE_VALUE; sets |gle| on failure. Uses
    // FILE_FLAG_BACKUP_SEMANTICS so directories also open.
    void* OpenForAttrs(const std::filesystem::path& p,
                       unsigned long& gle);

    // Read attrs into a Rgetattr reply payload (no header).
    // Returns true on success; on failure sets |errno_out|.
    bool ReadAttrsByHandle(void* h,
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
                            std::uint32_t& errno_out);

    // Stat the path (without keeping a handle) and fill the qid +
    // is_dir + qid_path fields a FidEntry needs after a walk step.
    // Returns true on success; on failure sets |errno_out|.
    bool StatPathForFid(const std::filesystem::path& p,
                         std::uint8_t&  qid_type,
                         std::uint64_t& qid_path,
                         bool&          is_dir,
                         std::uint32_t& errno_out);

    // Build a 9P qid bytes (type/version/path) for a stat'd file.
    static void AppendQid(std::vector<std::uint8_t>& out,
                           std::uint8_t qid_type,
                           std::uint32_t qid_version,
                           std::uint64_t qid_path);

    // ---- T-message handlers ------------------------------------------
    void HandleTversion (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTattach  (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTwalk    (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTlopen   (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTlcreate (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTread    (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTwrite   (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTreaddir (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTgetattr (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTsetattr (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTclunk   (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTremove  (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTfsync   (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTflush   (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTmkdir   (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTrename  (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTrenameat(std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTunlinkat(std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);
    void HandleTstatfs  (std::uint16_t tag, const std::vector<std::uint8_t>& body,
                          std::vector<std::uint8_t>& reply, std::uint32_t cap);

    // Build a 0-payload reply (header only) for ops like Rclunk,
    // Rremove, Rfsync, Rflush, Rrename, Rrenameat, Rsetattr,
    // Runlinkat.
    static void BuildHeaderOnly(std::vector<std::uint8_t>& reply,
                                 std::uint8_t reply_type, std::uint16_t tag);

    // -------------------------- state -------------------------------
    Virtqueue                   queue_;
    P9Share                     share_;
    // Canonicalised share_.host_root, normalised + lowercased for
    // PathContained() comparisons. Cached once at ctor.
    std::wstring                share_root_norm_;
    std::vector<std::uint8_t>   config_bytes_;
    bool                        driver_ok_       = false;
    std::uint64_t               acked_features_  = 0;
    std::uint32_t               negotiated_msize_ = 0;

    std::atomic<std::uint64_t>  requests_{0};
    std::atomic<std::uint64_t>  rlerrors_{0};

    std::mutex                                    fids_mu_;
    std::unordered_map<std::uint32_t, FidEntry>   fids_;
    // QID-path allocator. Used as a fallback when GetFileInformation
    // ByHandle.FileIndex returns 0 (FAT, network mounts).
    std::uint64_t                                 next_qid_path_ = 1;

    std::mutex notify_mu_;
    IrqFn      irq_;
};

}  // namespace tinyvmm::virtio
