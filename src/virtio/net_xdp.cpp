#include "net_xdp.h"

#ifdef TINYVMM_NO_XDP
// ----- Stub-build path -----
// The XDP-for-Windows headers (`afxdp.h`, `xdpapi.h`) use C-style
// aggregate initialization that's compatible with MSVC's `cl.exe` but
// rejected by modern clang-cl (`XSK_BIND_IN Bind = {0};` — int→enum
// in aggregate init is a hard error in clang's C++20 mode regardless
// of -W flags). When the build pins clang-cl (e.g. for UBSan) we
// compile this stub instead, which keeps `XdpNetBackend` linkable but
// always reports the backend as unavailable.

#include "whp/partition.h"
#include "virtio_pci.h"

#include <string>

namespace tinyvmm::virtio {

struct XdpNetBackend::State {
    long          err_hr   = 0x80004001L;  // E_NOTIMPL
    std::string   err_phase = "TINYVMM_NO_XDP";
};

XdpNetBackend::XdpNetBackend(NetDevice& /*net*/,
                             whp::GuestMemory& /*mem*/,
                             const Options& /*opts*/)
    : state_(std::make_unique<State>()) {}

XdpNetBackend::~XdpNetBackend() = default;

void XdpNetBackend::Start(whp::Partition& /*p*/, PciTransport& /*t*/) {}
void XdpNetBackend::Stop() {}
void XdpNetBackend::OnQueueNotify(std::uint32_t /*qidx*/) {}

bool          XdpNetBackend::ready()              const noexcept { return false; }
std::uint64_t XdpNetBackend::tx_packets()         const noexcept { return 0; }
std::uint64_t XdpNetBackend::rx_packets()         const noexcept { return 0; }
std::uint64_t XdpNetBackend::tx_dropped()         const noexcept { return 0; }
std::uint64_t XdpNetBackend::rx_dropped()         const noexcept { return 0; }
long          XdpNetBackend::last_setup_error()   const noexcept { return state_->err_hr; }
const std::string& XdpNetBackend::last_setup_phase() const noexcept { return state_->err_phase; }

}  // namespace tinyvmm::virtio

#else  // !TINYVMM_NO_XDP

#include "whp/notification_port.h"
#include "whp/partition.h"
#include "virtio_net.h"
#include "virtio_pci.h"

// IMPORTANT: include order matters. The XDP headers need windows.h,
// winternl.h and ntstatus.h pulled in first; ask wincommon.h to do
// that with XDP_INCLUDE_WINCOMMON.
//
// We pin to XDP_API_VERSION_3 — that's the version that exposes its
// user-mode entry points as inline functions hitting the kernel via
// NtDeviceIoControlFile. Older versions (v1/v2) require xdpapi.dll
// at runtime, which we don't want to depend on.
#define XDP_INCLUDE_WINCOMMON
#include <xdp/apiversion.h>
#define XDP_API_VERSION XDP_API_VERSION_3
#include <xdp/wincommon.h>
#include <xdpapi.h>
#include <afxdp.h>
#include <afxdp_helper.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <unordered_map>

namespace tinyvmm::virtio {

namespace {

constexpr std::size_t kVirtioNetHdrSize = 12;
constexpr std::uint32_t kPageSize       = 4096;

// Encode a guest GPA into XDP's split (BaseAddress:48, Offset:16) form.
// Buffer must not cross a page boundary (chunk size).
inline std::uint64_t EncodeBufferAddress(std::uint64_t gpa) {
    XSK_BUFFER_ADDRESS ba{};
    ba.BaseAddress = gpa & ~static_cast<std::uint64_t>(kPageSize - 1);
    ba.Offset      = gpa &  static_cast<std::uint64_t>(kPageSize - 1);
    return ba.AddressAndOffset;
}

inline std::uint64_t DecodeBufferGpa(std::uint64_t encoded) {
    XSK_BUFFER_ADDRESS ba{};
    ba.AddressAndOffset = encoded;
    return (ba.BaseAddress) + ba.Offset;
}

}  // namespace

// ---------------------------------------------------------------------------
// Internal state (pImpl) — all XDP types are isolated here.
// ---------------------------------------------------------------------------
struct XdpNetBackend::State {
    NetDevice& net;
    whp::GuestMemory& mem;
    Options opts;

    PciTransport* xport = nullptr;
    whp::Partition* partition = nullptr;

    HANDLE socket  = nullptr;
    HANDLE program = nullptr;

    XSK_RING rx_ring{};
    XSK_RING rx_fill_ring{};
    XSK_RING tx_ring{};
    XSK_RING tx_comp_ring{};

    HANDLE tx_doorbell_evt = nullptr;   // owned by transport
    HANDLE rx_doorbell_evt = nullptr;
    HANDLE stop_evt        = nullptr;
    std::thread worker;
    std::atomic<bool> running{false};

    // RX inflight keyed by the encoded XSK_BUFFER_ADDRESS we posted to the
    // Fill ring. When the buffer returns on the RX ring, we look up the
    // guest chain and put it on the used ring.
    struct RxInflight {
        std::uint16_t head_index;
        std::uint64_t hdr_gpa;
        std::uint32_t hdr_len;
        std::uint64_t payload_gpa;
        std::uint32_t payload_len;
    };
    std::unordered_map<std::uint64_t, RxInflight> rx_inflight;

    // TX inflight keyed by encoded XSK_BUFFER_ADDRESS.
    std::unordered_map<std::uint64_t, std::uint16_t> tx_inflight;

    std::atomic<std::uint64_t> tx_packets{0};
    std::atomic<std::uint64_t> rx_packets{0};
    std::atomic<std::uint64_t> tx_dropped{0};
    std::atomic<std::uint64_t> rx_dropped{0};

    HRESULT setup_error = S_OK;
    std::string setup_phase;

    State(NetDevice& n, whp::GuestMemory& m, const Options& o)
        : net(n), mem(m), opts(o) {}

    bool OpenAndConfigureSocket();
    void CloseSocket();
    void WorkerLoop();
    void PumpTx();
    void PumpRx();
    void PumpTxCompletion();
    void RefillRxFromGuest();
};

// ---------------------------------------------------------------------------
// Public ctor / dtor
// ---------------------------------------------------------------------------
XdpNetBackend::XdpNetBackend(NetDevice& net,
                             whp::GuestMemory& mem,
                             const Options& opts)
    : state_(std::make_unique<State>(net, mem, opts)) {}

XdpNetBackend::~XdpNetBackend() { Stop(); }

bool XdpNetBackend::ready() const noexcept {
    return state_ && state_->socket != nullptr;
}
std::uint64_t XdpNetBackend::tx_packets() const noexcept {
    return state_ ? state_->tx_packets.load() : 0;
}
std::uint64_t XdpNetBackend::rx_packets() const noexcept {
    return state_ ? state_->rx_packets.load() : 0;
}
std::uint64_t XdpNetBackend::tx_dropped() const noexcept {
    return state_ ? state_->tx_dropped.load() : 0;
}
std::uint64_t XdpNetBackend::rx_dropped() const noexcept {
    return state_ ? state_->rx_dropped.load() : 0;
}
long XdpNetBackend::last_setup_error() const noexcept {
    return state_ ? state_->setup_error : 0;
}
const std::string& XdpNetBackend::last_setup_phase() const noexcept {
    static const std::string empty;
    return state_ ? state_->setup_phase : empty;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
void XdpNetBackend::Start(whp::Partition& partition, PciTransport& transport) {
    state_->partition = &partition;
    state_->xport     = &transport;

    if (!state_->OpenAndConfigureSocket()) {
        std::fprintf(stderr,
            "[xdp-net] setup failed at %s: hr=0x%08lX -- backend disabled\n",
            state_->setup_phase.c_str(),
            static_cast<unsigned long>(state_->setup_error));
        return;
    }

    state_->tx_doorbell_evt =
        transport.InstallQueueDoorbell(partition, kTxQueueIdx);
    state_->rx_doorbell_evt =
        transport.InstallQueueDoorbell(partition, kRxQueueIdx);

    state_->stop_evt = CreateEventW(nullptr, /*manual*/TRUE,
                                    /*initial*/FALSE, nullptr);
    if (!state_->stop_evt) {
        state_->setup_error = HRESULT_FROM_WIN32(GetLastError());
        state_->setup_phase = "CreateEvent(stop)";
        state_->CloseSocket();
        return;
    }
    state_->running.store(true);
    state_->worker = std::thread([s = state_.get()]{ s->WorkerLoop(); });

    std::printf("[xdp-net] up on ifindex=%u queue=%u ring_size=%u (%s)\n",
                state_->opts.if_index, state_->opts.queue_id,
                state_->opts.ring_size,
                state_->opts.require_native ? "NATIVE/ZC" : "auto");
}

void XdpNetBackend::Stop() {
    if (!state_) return;
    if (state_->running.exchange(false)) {
        if (state_->stop_evt) SetEvent(state_->stop_evt);
        if (state_->worker.joinable()) state_->worker.join();
    }
    state_->CloseSocket();
    if (state_->stop_evt) { CloseHandle(state_->stop_evt); state_->stop_evt = nullptr; }
    state_->rx_inflight.clear();
    state_->tx_inflight.clear();
}

void XdpNetBackend::OnQueueNotify(std::uint32_t /*qidx*/) {
    // No-op: we drive everything off doorbells installed at BAR-map.
    // The notify-MMIO write should not reach this function in steady
    // state (doorbells suppress the exit); but if it does, the worker
    // will pick up the work on its next wake.
}

// ---------------------------------------------------------------------------
// State::OpenAndConfigureSocket
// ---------------------------------------------------------------------------
bool XdpNetBackend::State::OpenAndConfigureSocket() {
    auto fail = [this](const char* phase, HRESULT hr) {
        setup_phase = phase;
        setup_error = hr;
        CloseSocket();
        return false;
    };

    HRESULT hr = XskCreate(&socket);
    if (FAILED(hr)) return fail("XskCreate", hr);

    XSK_UMEM_REG umem{};
    umem.TotalSize = mem.size();
    umem.ChunkSize = kPageSize;
    umem.Headroom  = 0;
    umem.Address   = mem.host_base();
    hr = XskSetSockopt(socket, XSK_SOCKOPT_UMEM_REG, &umem, sizeof(umem));
    if (FAILED(hr)) return fail("XSK_SOCKOPT_UMEM_REG", hr);

    const std::uint32_t rs = opts.ring_size;
    hr = XskSetSockopt(socket, XSK_SOCKOPT_RX_RING_SIZE, &rs, sizeof(rs));
    if (FAILED(hr)) return fail("XSK_SOCKOPT_RX_RING_SIZE", hr);
    hr = XskSetSockopt(socket, XSK_SOCKOPT_RX_FILL_RING_SIZE, &rs, sizeof(rs));
    if (FAILED(hr)) return fail("XSK_SOCKOPT_RX_FILL_RING_SIZE", hr);
    hr = XskSetSockopt(socket, XSK_SOCKOPT_TX_RING_SIZE, &rs, sizeof(rs));
    if (FAILED(hr)) return fail("XSK_SOCKOPT_TX_RING_SIZE", hr);
    hr = XskSetSockopt(socket, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &rs, sizeof(rs));
    if (FAILED(hr)) return fail("XSK_SOCKOPT_TX_COMPLETION_RING_SIZE", hr);

    const XSK_BIND_FLAGS bind_flags =
        static_cast<XSK_BIND_FLAGS>(
            XSK_BIND_FLAG_RX | XSK_BIND_FLAG_TX |
            (opts.require_native ? XSK_BIND_FLAG_NATIVE : 0));
    hr = XskBind(socket, opts.if_index, opts.queue_id, bind_flags);
    if (FAILED(hr)) return fail("XskBind", hr);

    hr = XskActivate(socket, XSK_ACTIVATE_FLAG_NONE);
    if (FAILED(hr)) return fail("XskActivate", hr);

    XSK_RING_INFO_SET ring_info{};
    UINT32 len = sizeof(ring_info);
    hr = XskGetSockopt(socket, XSK_SOCKOPT_RING_INFO, &ring_info, &len);
    if (FAILED(hr)) return fail("XSK_SOCKOPT_RING_INFO", hr);

    XskRingInitialize(&rx_ring,      &ring_info.Rx);
    XskRingInitialize(&rx_fill_ring, &ring_info.Fill);
    XskRingInitialize(&tx_ring,      &ring_info.Tx);
    XskRingInitialize(&tx_comp_ring, &ring_info.Completion);

    if (opts.install_xdp_program) {
        const XDP_HOOK_ID hook_rx_l2_inspect = {
            XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INSPECT,
        };
        XDP_RULE rule{};
        rule.Match = XDP_MATCH_ALL;
        rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
        rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
        rule.Redirect.Target = socket;
        hr = XdpCreateProgram(opts.if_index, &hook_rx_l2_inspect,
                              opts.queue_id, XDP_CREATE_PROGRAM_FLAG_NONE,
                              &rule, 1, &program);
        if (FAILED(hr)) return fail("XdpCreateProgram", hr);
    }

    setup_error = S_OK;
    setup_phase.clear();
    return true;
}

void XdpNetBackend::State::CloseSocket() {
    if (program) { CloseHandle(program); program = nullptr; }
    if (socket)  { CloseHandle(socket);  socket  = nullptr; }
}

// ---------------------------------------------------------------------------
// Worker loop
// ---------------------------------------------------------------------------
void XdpNetBackend::State::WorkerLoop() {
    HANDLE waits[3] = { stop_evt, tx_doorbell_evt, rx_doorbell_evt };
    const DWORD n_waits = 3;

    while (running.load()) {
        // 1 ms poll keeps us responsive without spinning. With a real
        // workload the doorbell signals usually fire first.
        DWORD wr = WaitForMultipleObjectsEx(n_waits, waits, FALSE, 1, FALSE);
        if (wr == WAIT_OBJECT_0) break;  // stop
        (void)wr;

        RefillRxFromGuest();
        PumpTx();
        PumpRx();
        PumpTxCompletion();
    }
}

// ---------------------------------------------------------------------------
// RX side: post guest payload buffers to the XSK Fill ring.
// ---------------------------------------------------------------------------
void XdpNetBackend::State::RefillRxFromGuest() {
    auto& rxq = net.rx_queue();
    if (!rxq.ready()) return;

    // How many slots are free in the Fill ring?
    UINT32 producer_idx = 0;
    UINT32 free_slots = XskRingProducerReserve(
        &rx_fill_ring, rx_fill_ring.Size, &producer_idx);
    if (free_slots == 0) return;

    UINT32 reserved = 0;
    while (reserved < free_slots) {
        auto chain = rxq.Pop();
        if (!chain) break;

        // We expect 2 descs: hdr (12B writable) + payload (1 page writable).
        // If the layout differs we'll just truncate, ie post the largest
        // writable buffer we can find as the payload.
        std::uint64_t hdr_gpa = 0, payload_gpa = 0;
        std::uint32_t hdr_len = 0, payload_len = 0;
        for (auto& b : chain->bufs) {
            if (!b.write) continue;
            // GPA = host_addr - host_base. (Both pointers into mem.)
            auto* host_p   = b.bytes.data();
            auto* host_base = static_cast<std::uint8_t*>(mem.host_base());
            const std::uint64_t gpa =
                static_cast<std::uint64_t>(host_p - host_base);
            const auto buf_len = static_cast<std::uint32_t>(b.bytes.size());
            if (hdr_gpa == 0) {
                hdr_gpa = gpa; hdr_len = buf_len;
            } else if (payload_gpa == 0) {
                payload_gpa = gpa; payload_len = buf_len;
            }
        }
        if (payload_gpa == 0) {
            // Single-buffer (mrg_rxbuf-style) or no writable bufs at all:
            // give the entire space to payload; we'll synthesize hdr into
            // the same buffer on completion.
            payload_gpa = hdr_gpa; payload_len = hdr_len;
            hdr_gpa = 0; hdr_len = 0;
        }
        if (payload_gpa == 0 || payload_len < kVirtioNetHdrSize) {
            // Unusable.
            rxq.Push(chain->head_index, 0);
            rx_dropped.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        // Cap payload to page boundary (chunk size).
        const std::uint64_t page_end =
            (payload_gpa & ~static_cast<std::uint64_t>(kPageSize - 1)) + kPageSize;
        if (payload_gpa + payload_len > page_end) {
            payload_len = static_cast<std::uint32_t>(page_end - payload_gpa);
        }

        const std::uint64_t encoded = EncodeBufferAddress(payload_gpa);

        // Write the Fill ring element (8-byte XSK_BUFFER_ADDRESS).
        auto* slot = static_cast<std::uint64_t*>(
            XskRingGetElement(&rx_fill_ring, producer_idx + reserved));
        *slot = encoded;
        rx_inflight[encoded] = RxInflight{
            chain->head_index, hdr_gpa, hdr_len, payload_gpa, payload_len };
        ++reserved;
    }

    if (reserved > 0) {
        XskRingProducerSubmit(&rx_fill_ring, reserved);
        if (XskRingProducerNeedPoke(&rx_fill_ring)) {
            XSK_NOTIFY_RESULT_FLAGS r{};
            XskNotifySocket(socket, XSK_NOTIFY_FLAG_POKE_RX, 0, &r);
        }
    }
}

// ---------------------------------------------------------------------------
// TX side: drain guest TX virtq into XSK TX ring.
// ---------------------------------------------------------------------------
void XdpNetBackend::State::PumpTx() {
    auto& txq = net.tx_queue();
    if (!txq.ready()) return;

    UINT32 producer_idx = 0;
    UINT32 free_slots = XskRingProducerReserve(
        &tx_ring, tx_ring.Size, &producer_idx);
    if (free_slots == 0) return;

    UINT32 reserved = 0;
    while (reserved < free_slots) {
        auto chain = txq.Pop();
        if (!chain) break;

        // Linux virtio-net (without MRG_RXBUF or hdr_data merging on TX)
        // sends [hdr_desc (read-only, 12B), payload_desc (read-only)].
        // We forward the payload as a single XSK TX descriptor.
        std::uint64_t payload_gpa = 0;
        std::uint32_t payload_len = 0;
        std::size_t hdr_remaining = kVirtioNetHdrSize;
        for (auto& b : chain->bufs) {
            if (b.write) continue;
            auto* host_p   = b.bytes.data();
            auto* host_base = static_cast<std::uint8_t*>(mem.host_base());
            std::uint64_t gpa = static_cast<std::uint64_t>(host_p - host_base);
            std::uint32_t len = static_cast<std::uint32_t>(b.bytes.size());
            if (hdr_remaining > 0) {
                std::uint32_t skip = static_cast<std::uint32_t>(
                    std::min<std::size_t>(hdr_remaining, len));
                hdr_remaining -= skip;
                gpa += skip; len -= skip;
            }
            if (len > 0 && payload_gpa == 0) {
                payload_gpa = gpa;
                payload_len = len;
                break;  // single-payload-buffer simplification
            }
        }
        if (payload_gpa == 0 || payload_len == 0) {
            txq.Push(chain->head_index, 0);
            tx_dropped.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        // Cap to page.
        const std::uint64_t page_end =
            (payload_gpa & ~static_cast<std::uint64_t>(kPageSize - 1)) + kPageSize;
        if (payload_gpa + payload_len > page_end) {
            payload_len = static_cast<std::uint32_t>(page_end - payload_gpa);
        }

        const std::uint64_t encoded = EncodeBufferAddress(payload_gpa);
        auto* desc = static_cast<XSK_BUFFER_DESCRIPTOR*>(
            XskRingGetElement(&tx_ring, producer_idx + reserved));
        desc->Address.AddressAndOffset = encoded;
        desc->Length = payload_len;
        desc->Reserved = 0;
        tx_inflight[encoded] = chain->head_index;
        ++reserved;
    }

    if (reserved > 0) {
        XskRingProducerSubmit(&tx_ring, reserved);
        if (XskRingProducerNeedPoke(&tx_ring)) {
            XSK_NOTIFY_RESULT_FLAGS r{};
            XskNotifySocket(socket, XSK_NOTIFY_FLAG_POKE_TX, 0, &r);
        }
    }
}

// ---------------------------------------------------------------------------
// TX completion drain.
// ---------------------------------------------------------------------------
void XdpNetBackend::State::PumpTxCompletion() {
    auto& txq = net.tx_queue();
    if (!txq.ready()) return;

    UINT32 cidx = 0;
    UINT32 n = XskRingConsumerReserve(&tx_comp_ring, tx_comp_ring.Size, &cidx);
    if (n == 0) return;

    bool any = false;
    for (UINT32 i = 0; i < n; ++i) {
        auto* slot = static_cast<std::uint64_t*>(
            XskRingGetElement(&tx_comp_ring, cidx + i));
        const std::uint64_t encoded = *slot;
        auto it = tx_inflight.find(encoded);
        if (it != tx_inflight.end()) {
            txq.Push(it->second, /*used_len=*/0);
            tx_inflight.erase(it);
            tx_packets.fetch_add(1, std::memory_order_relaxed);
            any = true;
        }
    }
    XskRingConsumerRelease(&tx_comp_ring, n);
    if (any && xport) xport->RaiseQueueInterrupt(kTxQueueIdx);
}

// ---------------------------------------------------------------------------
// RX drain.
// ---------------------------------------------------------------------------
void XdpNetBackend::State::PumpRx() {
    auto& rxq = net.rx_queue();
    if (!rxq.ready()) return;

    UINT32 cidx = 0;
    UINT32 n = XskRingConsumerReserve(&rx_ring, rx_ring.Size, &cidx);
    if (n == 0) return;

    bool any = false;
    for (UINT32 i = 0; i < n; ++i) {
        auto* buf = static_cast<XSK_BUFFER_DESCRIPTOR*>(
            XskRingGetElement(&rx_ring, cidx + i));
        const std::uint64_t encoded = buf->Address.AddressAndOffset;
        auto it = rx_inflight.find(encoded);
        if (it == rx_inflight.end()) {
            // Unknown buffer; just count and skip.
            rx_dropped.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const auto& info = it->second;
        // Synthesize a zeroed virtio_net_hdr_v1 into the hdr buffer (if
        // we had a separate one; otherwise we'd be smashing the payload).
        std::uint32_t reported_len = buf->Length;
        if (info.hdr_len >= kVirtioNetHdrSize) {
            auto* hdr_host =
                static_cast<std::uint8_t*>(mem.host_base()) + info.hdr_gpa;
            std::memset(hdr_host, 0, kVirtioNetHdrSize);
            reported_len += static_cast<std::uint32_t>(kVirtioNetHdrSize);
        }
        rxq.Push(info.head_index, reported_len);
        rx_inflight.erase(it);
        rx_packets.fetch_add(1, std::memory_order_relaxed);
        any = true;
    }
    XskRingConsumerRelease(&rx_ring, n);
    if (any && xport) xport->RaiseQueueInterrupt(kRxQueueIdx);
}

}  // namespace tinyvmm::virtio

#endif  // !TINYVMM_NO_XDP
