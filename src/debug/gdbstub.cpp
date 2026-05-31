// SPDX-License-Identifier: MIT
//
// tinyvmm -- GDB stub implementation (M35 phase 1).
//
// Phase 1 scope: TCP listener + RSP framing + handshake packets.
// Phases 2-7 add register R/W, memory R/W, breakpoints, step,
// continue, and Ctrl-C interrupt.
//
// RSP framing (per gdb/doc/gdb/Overview-of-the-Remote-Serial-Protocol):
//   * Packets are "$<payload>#<checksum>".
//   * Checksum is the 8-bit sum of the payload bytes (mod 256),
//     hex-encoded as two ASCII characters.
//   * Receiver replies "+" to acknowledge or "-" to request resend.
//   * After QStartNoAckMode is accepted, the ack/nak round-trip is
//     skipped entirely.
//   * A bare 0x03 byte sent at any time means "interrupt".
//
// Reply conventions:
//   * Stop reasons: "S05" (signal 5 = SIGTRAP) or richer
//     "T05swbreak:;thread:1;" for breakpoints.
//   * Empty packet "$#00" means "unsupported", which is the modern
//     way to politely decline q/v packets without breaking the link.
//   * Error: "E<2-hex>".

#include "gdbstub.h"

#include "common.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace tinyvmm::debug {

namespace {

constexpr std::size_t kMaxPacketSize = 16 * 1024;

// 8-bit modular checksum of payload bytes.
std::uint8_t PacketChecksum(const char* p, std::size_t n) {
    std::uint32_t s = 0;
    for (std::size_t i = 0; i < n; ++i) {
        s += static_cast<std::uint8_t>(p[i]);
    }
    return static_cast<std::uint8_t>(s & 0xFF);
}

inline char HexNibble(std::uint8_t v) {
    return static_cast<char>(v < 10 ? '0' + v : 'a' + (v - 10));
}

// Append a byte as two hex chars to a string.
void AppendHexByte(std::string& out, std::uint8_t v) {
    out += HexNibble(v >> 4);
    out += HexNibble(v & 0xF);
}

// Parse two ASCII hex chars into a byte. Returns -1 on bad input.
int ParseHexByte(char hi, char lo) {
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    int h = digit(hi), l = digit(lo);
    if (h < 0 || l < 0) return -1;
    return (h << 4) | l;
}

// Returns true if the prefix p is at the start of s.
bool StartsWith(const std::string& s, const char* p) {
    const std::size_t n = std::strlen(p);
    return s.size() >= n && std::memcmp(s.data(), p, n) == 0;
}

}  // namespace

// ============================================================
// Impl
// ============================================================
struct GdbStub::Impl {
    whp::Partition&   part;
    whp::Vcpu&        vcpu;
    whp::GuestMemory& mem;
    std::uint16_t     port;

    SOCKET listener = INVALID_SOCKET;
    SOCKET client   = INVALID_SOCKET;
    bool   wsa_started = false;

    // Set after QStartNoAckMode succeeds; once true, neither side
    // sends '+' or '-' acks.
    std::atomic<bool> no_ack_mode{false};

    // ReportStop -> action handshake. The vCPU thread calls
    // ReportStop, which sets `stop_pending=true` and notifies the I/O
    // thread to send a stop-reason packet. The I/O thread, after
    // sending the packet and receiving the next continue/step packet,
    // sets `next_action` and clears `stop_pending`, then notifies the
    // vCPU thread which returns from ReportStop.
    std::mutex                mu;
    std::condition_variable   cv;
    bool                      stop_pending = false;
    bool                      action_ready = false;
    Action                    next_action = Action::Continue;
    std::uint8_t              last_exception_vec = 0;
    std::uint64_t             last_rip = 0;

    // Pending stop flag readable from the run loop on the hot path
    // (without locking).
    std::atomic<bool>         pending_stop_flag{false};

    // I/O thread handle.
    std::thread               io_thread;
    std::atomic<bool>         io_thread_should_exit{false};
    bool                      first_connect_done = false;

    Impl(whp::Partition& p, whp::Vcpu& v, whp::GuestMemory& m,
         std::uint16_t prt)
        : part(p), vcpu(v), mem(m), port(prt) {}

    ~Impl() {
        io_thread_should_exit.store(true, std::memory_order_release);
        if (client != INVALID_SOCKET) {
            ::shutdown(client, SD_BOTH);
            ::closesocket(client);
            client = INVALID_SOCKET;
        }
        if (listener != INVALID_SOCKET) {
            ::closesocket(listener);
            listener = INVALID_SOCKET;
        }
        if (io_thread.joinable()) {
            io_thread.join();
        }
        if (wsa_started) {
            ::WSACleanup();
            wsa_started = false;
        }
    }

    // ---- TCP setup -------------------------------------------------
    void Bind() {
        WSADATA wsa{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            Fatal("GdbStub: WSAStartup failed");
        }
        wsa_started = true;

        listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) {
            Fatal("GdbStub: socket() failed");
        }
        BOOL on = TRUE;
        ::setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&on), sizeof(on));

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
        sa.sin_port = ::htons(port);
        if (::bind(listener, reinterpret_cast<sockaddr*>(&sa),
                   sizeof(sa)) != 0) {
            std::fprintf(stderr,
                "[gdbstub] bind 127.0.0.1:%u failed: %d\n",
                static_cast<unsigned>(port), ::WSAGetLastError());
            Fatal("GdbStub: bind failed");
        }
        if (::listen(listener, 1) != 0) {
            Fatal("GdbStub: listen failed");
        }
        std::fprintf(stderr,
            "[gdbstub] listening on 127.0.0.1:%u "
            "(connect with `target remote :%u`)\n",
            static_cast<unsigned>(port),
            static_cast<unsigned>(port));
    }

    // Block until a GDB client TCP-connects. Single client; subsequent
    // accepts are rejected (we close the listener after).
    void AcceptClient() {
        sockaddr_in peer{};
        int peer_len = sizeof(peer);
        SOCKET s = ::accept(listener,
                             reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (s == INVALID_SOCKET) {
            Fatal("GdbStub: accept failed");
        }
        BOOL nodelay = TRUE;
        ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&nodelay),
                     sizeof(nodelay));
        client = s;
        std::fprintf(stderr,
            "[gdbstub] client connected from %d.%d.%d.%d:%u\n",
            peer.sin_addr.S_un.S_un_b.s_b1,
            peer.sin_addr.S_un.S_un_b.s_b2,
            peer.sin_addr.S_un.S_un_b.s_b3,
            peer.sin_addr.S_un.S_un_b.s_b4,
            static_cast<unsigned>(::ntohs(peer.sin_port)));
        first_connect_done = true;
    }

    // ---- low-level I/O --------------------------------------------
    bool SendAll(const char* buf, std::size_t n) {
        std::size_t sent = 0;
        while (sent < n) {
            int r = ::send(client, buf + sent,
                            static_cast<int>(n - sent), 0);
            if (r <= 0) return false;
            sent += static_cast<std::size_t>(r);
        }
        return true;
    }

    bool SendPacket(const std::string& payload) {
        // "$payload#cksum"
        std::string raw;
        raw.reserve(payload.size() + 4);
        raw += '$';
        raw += payload;
        raw += '#';
        AppendHexByte(raw, PacketChecksum(payload.data(), payload.size()));
        return SendAll(raw.data(), raw.size());
    }

    // Recv one byte. Returns -1 on EOF / error.
    int RecvByte() {
        char c;
        int r = ::recv(client, &c, 1, 0);
        if (r <= 0) return -1;
        return static_cast<int>(static_cast<std::uint8_t>(c));
    }

    // Receive one RSP packet. Returns false on disconnect.
    // Sets `out` to the payload (without $..#cksum framing).
    // Handles Ctrl-C (0x03) by setting pending_stop_flag and
    // calling Vcpu::Cancel; loops to wait for the next real packet.
    bool RecvPacket(std::string& out) {
        out.clear();
        for (;;) {
            int c = RecvByte();
            if (c < 0) return false;
            if (c == 0x03) {
                // Ctrl-C interrupt. Set pending-stop flag and ask the
                // vCPU to cancel. The vCPU thread will see
                // pending_stop_flag and call ReportStop on its next
                // iteration; we wait for that here by returning a
                // sentinel that signals "no packet, but interrupt
                // happened" -- represented as out="\x03" so the caller
                // knows.
                pending_stop_flag.store(true, std::memory_order_release);
                try {
                    vcpu.Cancel();
                } catch (...) {}
                out = std::string(1, '\x03');
                return true;
            }
            if (c == '+' || c == '-') {
                // Stray ack (we don't pipeline) -- ignore.
                continue;
            }
            if (c != '$') {
                // Garbage; resync on next '$'.
                continue;
            }
            // Read payload until '#'.
            std::string payload;
            payload.reserve(256);
            for (;;) {
                int b = RecvByte();
                if (b < 0) return false;
                if (b == '#') break;
                if (payload.size() >= kMaxPacketSize) return false;
                payload += static_cast<char>(b);
            }
            int h = RecvByte();
            int l = RecvByte();
            if (h < 0 || l < 0) return false;
            const int got_cksum = ParseHexByte(static_cast<char>(h),
                                               static_cast<char>(l));
            const std::uint8_t want_cksum =
                PacketChecksum(payload.data(), payload.size());
            const bool ok = (got_cksum >= 0) &&
                            (static_cast<std::uint8_t>(got_cksum) == want_cksum);
            if (!no_ack_mode.load(std::memory_order_acquire)) {
                const char ack = ok ? '+' : '-';
                if (!SendAll(&ack, 1)) return false;
            }
            if (!ok) {
                // Bad checksum; wait for resend.
                continue;
            }
            out = std::move(payload);
            return true;
        }
    }

    // ---- packet dispatch ------------------------------------------
    // Returns false to terminate the I/O loop (e.g. disconnect).
    bool Handle(const std::string& pkt) {
        // 0x03 interrupt sentinel: nothing to reply yet; the vCPU
        // thread will call ReportStop, which will send the stop-reason
        // packet from inside the I/O loop's wait branch.
        if (pkt.size() == 1 && pkt[0] == '\x03') return true;

        if (pkt.empty()) return SendPacket("");

        switch (pkt[0]) {
            case '?':
                // Stop reason. Phase 1: we always say SIGTRAP at entry.
                // Phase 3+ will report richer reasons (T05swbreak:;...).
                return SendPacket("S05");

            case 'q':
                return HandleQ(pkt);

            case 'Q':
                return HandleQUpper(pkt);

            case 'v':
                return HandleV(pkt);

            case 'H':
                // Set current thread for following g/G/m/M (Hg) or
                // c/s (Hc) ops. Single-thread VM => always OK.
                return SendPacket("OK");

            case 'D':
                // Detach. Phase 1: just shut down the connection;
                // letting the VM continue freely.
                SendPacket("OK");
                return false;

            case 'k':
                // Kill. Treat as detach for v1.
                return false;

            case 'g': case 'G': case 'p': case 'P':
                // Register R/W -- Phase 2.
                return SendPacket("");  // unsupported for now

            case 'm': case 'M':
                // Memory R/W -- Phase 3.
                return SendPacket("");

            case 'c': case 's':
                // Continue / step -- Phase 4/5.
                return SendPacket("");

            case 'Z': case 'z':
                // Breakpoints -- Phase 6.
                return SendPacket("");

            default:
                return SendPacket("");
        }
    }

    bool HandleQ(const std::string& pkt) {
        if (StartsWith(pkt, "qSupported")) {
            std::string r =
                "PacketSize=";
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%x",
                          static_cast<unsigned>(kMaxPacketSize));
            r += buf;
            r += ";swbreak+;hwbreak-;qXfer:features:read+;QStartNoAckMode+";
            return SendPacket(r);
        }
        if (pkt == "qAttached") {
            return SendPacket("1");
        }
        if (pkt == "qC") {
            return SendPacket("QC1");
        }
        if (pkt == "qfThreadInfo") {
            return SendPacket("m1");
        }
        if (pkt == "qsThreadInfo") {
            return SendPacket("l");
        }
        if (StartsWith(pkt, "qSymbol")) {
            return SendPacket("OK");
        }
        if (StartsWith(pkt, "qXfer:features:read:target.xml:")) {
            // Phase 2 will return a real x86_64 target description.
            return SendPacket("E00");
        }
        if (StartsWith(pkt, "qOffsets")) {
            // No relocation -- the kernel runs at its linked addresses.
            return SendPacket("Text=0;Data=0;Bss=0");
        }
        return SendPacket("");  // unknown q -- empty
    }

    bool HandleQUpper(const std::string& pkt) {
        if (pkt == "QStartNoAckMode") {
            // GDB sends this very early. We send "OK" with normal ack
            // framing for THIS packet (per spec), then both sides stop
            // ack'ing for subsequent packets.
            bool ok = SendPacket("OK");
            no_ack_mode.store(true, std::memory_order_release);
            return ok;
        }
        return SendPacket("");
    }

    bool HandleV(const std::string& pkt) {
        if (pkt == "vMustReplyEmpty") {
            return SendPacket("");
        }
        if (pkt == "vCont?") {
            return SendPacket("vCont;c;s");
        }
        if (StartsWith(pkt, "vCont")) {
            // Phase 4/5.
            return SendPacket("");
        }
        return SendPacket("");
    }

    // ---- I/O thread loop ------------------------------------------
    // The I/O thread is the *only* writer to the socket. Two state
    // machines run concurrently:
    //
    //   * vCPU thread: enters the run loop, occasionally calls
    //     ReportStop(vec, rip) on a debug exception or pending
    //     interrupt. ReportStop sets stop_pending=true and blocks
    //     until the I/O thread sets next_action.
    //
    //   * I/O thread: polls the socket with a 50 ms timeout. On
    //     incoming data, parses one or more RSP packets. On
    //     stop_pending && push_stop, sends a T-packet and waits
    //     for the next continue/step packet (which signals the vCPU).
    //
    // GDB's all-stop protocol: when the inferior is running, GDB only
    // sends 0x03 (interrupt); when stopped, GDB freely chats. The
    // stub must therefore NOT push a T-packet UNTIL after the client
    // has issued at least one ``c``/``s``/``vCont`` and the inferior
    // has stopped again. On INITIAL connection (before any resume),
    // the stub waits silently for the client's ``?`` query and only
    // then sends the stop-reason T-packet.
    void IoThreadMain() {
        bool push_stop = false;          // unsolicited T-packet pending
        bool stop_sent = false;          // T-packet already sent for current stop

        while (!io_thread_should_exit.load(std::memory_order_acquire)) {
            // (1) If a stop is pending AND a previous resume has
            // bottomed out (push_stop), surface the T-packet.
            {
                std::unique_lock<std::mutex> lock(mu);
                if (stop_pending && push_stop && !stop_sent) {
                    std::uint8_t vec = last_exception_vec;
                    (void)last_rip;
                    lock.unlock();
                    if (!SendStopPacket(vec)) return;
                    stop_sent = true;
                    push_stop = false;
                    continue;
                }
            }

            // (2) Poll the socket for incoming data with a short
            // timeout so we wake up periodically to check stop_pending.
            WSAPOLLFD f{};
            f.fd = client;
            f.events = POLLRDNORM;
            int pr = ::WSAPoll(&f, 1, /*timeout_ms=*/50);
            if (pr < 0) return;                       // socket error
            if (pr == 0) continue;                    // timeout, re-check
            if (!(f.revents & POLLRDNORM)) {
                if (f.revents & (POLLERR | POLLHUP)) return;
                continue;
            }

            // (3) Receive one packet (or interrupt).
            std::string pkt;
            if (!RecvPacket(pkt)) return;

            if (pkt.size() == 1 && pkt[0] == '\x03') {
                // 0x03 interrupt: pending_stop_flag set, vCPU
                // cancelled. The vCPU will exit and call ReportStop,
                // which sets stop_pending. push_stop=true so (1)
                // surfaces the T-packet on the next iteration.
                push_stop = true;
                stop_sent = false;
                continue;
            }

            // (4) Resume packets (c/s/vCont;c|s) wake the vCPU and
            // set push_stop so the next ReportStop emits a T-packet.
            const bool is_c = (pkt == "c" || pkt == "vCont;c" ||
                                StartsWith(pkt, "vCont;c:"));
            const bool is_s = (pkt == "s" || pkt == "vCont;s" ||
                                StartsWith(pkt, "vCont;s:"));
            if (is_c || is_s) {
                std::unique_lock<std::mutex> lock(mu);
                next_action = is_s ? Action::Step : Action::Continue;
                action_ready = true;
                stop_pending = false;
                stop_sent = false;
                pending_stop_flag.store(false, std::memory_order_release);
                cv.notify_all();
                push_stop = true;  // next ReportStop should surface T
                continue;
            }

            // (5) "?" stop-reason query: if a stop is already pending,
            // reply with the T-packet now; otherwise reply generic
            // SIGTRAP (shouldn't normally happen).
            if (pkt == "?") {
                std::unique_lock<std::mutex> lock(mu);
                if (stop_pending) {
                    std::uint8_t vec = last_exception_vec;
                    lock.unlock();
                    if (!SendStopPacket(vec)) return;
                    stop_sent = true;
                    push_stop = false;
                } else {
                    lock.unlock();
                    if (!SendPacket("S05")) return;
                }
                continue;
            }

            if (!Handle(pkt)) return;
        }
    }

    bool SendStopPacket(std::uint8_t vec) {
        std::string r;
        if (vec == 3) {
            r = "T05swbreak:;thread:1;";
        } else if (vec == 1) {
            r = "T05thread:1;";
        } else if (vec == 0xFE) {
            // 0xFE = Ctrl-C interrupt sentinel.
            r = "T02thread:1;";
        } else {
            // Generic SIGTRAP (initial entry pause, or unknown).
            r = "T05thread:1;";
        }
        return SendPacket(r);
    }
};

// ============================================================
// GdbStub
// ============================================================
GdbStub::GdbStub(whp::Partition& part, whp::Vcpu& vcpu,
                  whp::GuestMemory& mem, std::uint16_t port)
    : impl_(std::make_unique<Impl>(part, vcpu, mem, port)) {
    impl_->Bind();
}

GdbStub::~GdbStub() = default;

void GdbStub::WaitForFirstConnection() {
    impl_->AcceptClient();
    // Start the I/O thread. The vCPU has NOT entered the run loop
    // yet; the caller of WaitForFirstConnection is expected to then
    // call ReportStop(0xFF, entry_rip) before entering the run loop
    // (or, equivalently, gate the run loop on PendingDebuggerStop()
    // which we set below).
    impl_->pending_stop_flag.store(true, std::memory_order_release);
    impl_->io_thread = std::thread([impl = impl_.get()] {
        impl->IoThreadMain();
    });
    std::fprintf(stderr, "[gdbstub] client connected; vCPU halted at "
                         "entry (resume via 'c' in gdb)\n");
}

GdbStub::Action GdbStub::ReportStop(std::uint8_t exception_vec,
                                     std::uint64_t rip) {
    std::unique_lock<std::mutex> lock(impl_->mu);
    impl_->last_exception_vec = exception_vec;
    impl_->last_rip = rip;
    impl_->stop_pending = true;
    impl_->pending_stop_flag.store(true, std::memory_order_release);
    // Wake the I/O thread if it's blocked.
    impl_->cv.notify_all();
    // Wait until the I/O thread sets next_action.
    impl_->action_ready = false;
    impl_->cv.wait(lock, [&]{
        return impl_->action_ready ||
               impl_->io_thread_should_exit.load(std::memory_order_acquire);
    });
    if (impl_->io_thread_should_exit.load(std::memory_order_acquire)) {
        return Action::Shutdown;
    }
    impl_->action_ready = false;
    return impl_->next_action;
}

bool GdbStub::PendingDebuggerStop() const noexcept {
    return impl_->pending_stop_flag.load(std::memory_order_acquire);
}

}  // namespace tinyvmm::debug
