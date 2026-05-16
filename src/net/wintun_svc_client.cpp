#include "wintun_svc_client.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace tinyvmm::net {

namespace {

constexpr const wchar_t* kPipeName    = LR"(\\.\pipe\wintunsvc)";
constexpr std::size_t    kMaxLineSize = 64 * 1024;   // matches server limit
constexpr std::size_t    kReadChunk   = 4096;

// ---- Tiny strict JSON helpers --------------------------------------------
// The wintunsvc protocol is tiny and fixed (see crates/wintunsvc-proto/src/lib.rs).
// We hand-roll a strict-but-narrow parser/encoder so we don't pull a JSON
// library just for this. The parser reads the few keys we care about
// (`ok`, `code`, `message`, `data.name`, `data.luid`, `data.guid`) and
// rejects malformed input.

bool IsWs(char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

// Returns position past the value at p, or std::string::npos on parse error.
std::size_t SkipWs(const std::string& s, std::size_t p) noexcept {
    while (p < s.size() && IsWs(s[p])) ++p;
    return p;
}

// Decode a JSON string starting at s[p] (which must be '"'). On success
// stores the decoded value in `out` and returns the position past the
// closing quote. On failure returns std::string::npos.
std::size_t ParseString(const std::string& s, std::size_t p, std::string& out) {
    if (p >= s.size() || s[p] != '"') return std::string::npos;
    ++p;
    out.clear();
    while (p < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[p]);
        if (c == '"') return p + 1;
        if (c == '\\') {
            if (p + 1 >= s.size()) return std::string::npos;
            char n = s[p + 1];
            switch (n) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    // \uXXXX -- accept BMP code points; encode as UTF-8.
                    if (p + 5 >= s.size()) return std::string::npos;
                    unsigned cp = 0;
                    for (int i = 0; i < 4; ++i) {
                        char h = s[p + 2 + i];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= unsigned(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= unsigned(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= unsigned(h - 'A' + 10);
                        else return std::string::npos;
                    }
                    if (cp < 0x80) {
                        out.push_back(static_cast<char>(cp));
                    } else if (cp < 0x800) {
                        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    } else {
                        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    }
                    p += 4;
                    break;
                }
                default: return std::string::npos;
            }
            p += 2;
        } else if (c < 0x20) {
            return std::string::npos;
        } else {
            out.push_back(static_cast<char>(c));
            ++p;
        }
    }
    return std::string::npos;
}

// Parse an unsigned 64-bit integer starting at p. Stops at first
// non-digit. Returns position past the number, or std::string::npos.
std::size_t ParseU64(const std::string& s, std::size_t p, std::uint64_t& out) {
    if (p >= s.size() || s[p] < '0' || s[p] > '9') return std::string::npos;
    std::uint64_t v = 0;
    while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
        std::uint64_t d = static_cast<std::uint64_t>(s[p] - '0');
        if (v > (UINT64_MAX - d) / 10) return std::string::npos;
        v = v * 10 + d;
        ++p;
    }
    out = v;
    return p;
}

// Locate a top-level (depth-1) key in a JSON object string. The search is
// extremely narrow: it scans for `"key":` outside of strings, tracking
// brace/bracket depth. Returns the position of the value, or npos.
std::size_t FindTopLevelKey(const std::string& s,
                            const std::string& key) noexcept {
    if (s.empty() || s.front() != '{') return std::string::npos;
    int obj_depth = 0;
    int arr_depth = 0;
    bool in_str = false;
    bool escaped = false;
    std::string quoted = '"' + key + '"';
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (in_str) {
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') {
            if (obj_depth == 1 && arr_depth == 0 &&
                s.compare(i, quoted.size(), quoted) == 0) {
                std::size_t after = i + quoted.size();
                after = SkipWs(s, after);
                if (after < s.size() && s[after] == ':') {
                    return SkipWs(s, after + 1);
                }
            }
            in_str = true;
        } else if (c == '{') {
            ++obj_depth;
        } else if (c == '}') {
            --obj_depth;
        } else if (c == '[') {
            ++arr_depth;
        } else if (c == ']') {
            --arr_depth;
        }
    }
    return std::string::npos;
}

bool LooksLikeTrue(const std::string& s, std::size_t p) noexcept {
    return p + 4 <= s.size() && s.compare(p, 4, "true") == 0;
}

// Extract a nested object substring. On entry s[p] must be '{'.
std::size_t ExtractObject(const std::string& s, std::size_t p,
                          std::string& out) {
    if (p >= s.size() || s[p] != '{') return std::string::npos;
    int depth = 0;
    bool in_str = false;
    bool escaped = false;
    std::size_t start = p;
    while (p < s.size()) {
        char c = s[p];
        if (in_str) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_str = false;
        } else if (c == '"') {
            in_str = true;
        } else if (c == '{') {
            ++depth;
        } else if (c == '}') {
            --depth;
            if (depth == 0) {
                out.assign(s, start, p - start + 1);
                return p + 1;
            }
        }
        ++p;
    }
    return std::string::npos;
}

}  // namespace

WintunSvcClient::WintunSvcClient(std::chrono::milliseconds io_timeout)
    : timeout_(io_timeout) {}

WintunSvcClient::~WintunSvcClient() {
    if (pipe_ != INVALID_HANDLE_VALUE) {
        ::CancelIoEx(pipe_, nullptr);
        ::CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
    if (evt_) {
        ::CloseHandle(evt_);
        evt_ = nullptr;
    }
}

void WintunSvcClient::Connect() {
    evt_ = ::CreateEventW(nullptr, /*manual reset=*/TRUE,
                          /*initial=*/FALSE, nullptr);
    if (!evt_) {
        throw HrError(HRESULT_FROM_WIN32(::GetLastError()),
                      "WintunSvcClient: CreateEvent failed");
    }

    pipe_ = ::CreateFileW(kPipeName,
                          GENERIC_READ | GENERIC_WRITE,
                          0, nullptr, OPEN_EXISTING,
                          FILE_FLAG_OVERLAPPED, nullptr);
    if (pipe_ == INVALID_HANDLE_VALUE) {
        const DWORD e = ::GetLastError();
        const char* hint = (e == ERROR_FILE_NOT_FOUND)
            ? " -- is the WintunSvc Windows service installed and running? "
              "(check `sc query WintunSvc`)"
            : (e == ERROR_ACCESS_DENIED)
                ? " -- pipe denied access; check WINTUNSVC_PIPE_GROUP "
                  "membership"
                : "";
        std::string msg = "WintunSvcClient::Connect: CreateFileW(\\\\.\\pipe\\wintunsvc) failed";
        msg += hint;
        throw HrError(HRESULT_FROM_WIN32(e), msg.c_str());
    }

    // Server accepts either byte or message mode; we choose byte.
    DWORD mode = PIPE_READMODE_BYTE;
    if (!::SetNamedPipeHandleState(pipe_, &mode, nullptr, nullptr)) {
        throw HrError(HRESULT_FROM_WIN32(::GetLastError()),
                      "WintunSvcClient: SetNamedPipeHandleState failed");
    }
}

void WintunSvcClient::SendRequest(const std::string& json_line) {
    if (json_line.size() > kMaxLineSize) {
        throw HrError(E_INVALIDARG,
                      "WintunSvcClient: request line too large");
    }

    OVERLAPPED ov{};
    ov.hEvent = evt_;
    ::ResetEvent(evt_);

    DWORD written = 0;
    BOOL ok = ::WriteFile(pipe_, json_line.data(),
                          util::checked_int_cast<DWORD>(json_line.size()),
                          &written, &ov);
    DWORD err = ::GetLastError();
    if (!ok && err != ERROR_IO_PENDING) {
        throw HrError(HRESULT_FROM_WIN32(err),
                      "WintunSvcClient: WriteFile failed");
    }
    DWORD wr = ::WaitForSingleObject(
        evt_, util::checked_int_cast<DWORD>(timeout_.count()));
    if (wr != WAIT_OBJECT_0) {
        ::CancelIoEx(pipe_, &ov);
        DWORD ignored = 0;
        ::GetOverlappedResult(pipe_, &ov, &ignored, /*wait=*/TRUE);
        throw HrError(HRESULT_FROM_WIN32(ERROR_TIMEOUT),
                      "WintunSvcClient: timed out writing to pipe");
    }
    if (!::GetOverlappedResult(pipe_, &ov, &written, FALSE)) {
        throw HrError(HRESULT_FROM_WIN32(::GetLastError()),
                      "WintunSvcClient: WriteFile (overlapped) failed");
    }
    if (written != json_line.size()) {
        throw HrError(E_FAIL, "WintunSvcClient: short write to pipe");
    }
}

std::string WintunSvcClient::ReadOneLine() {
    // Return everything up to and including the first '\n', minus the
    // trailing '\n'. If we have carryover from a previous read with a
    // newline already in it, satisfy from there first.
    auto take_line = [&]() -> std::optional<std::string> {
        for (std::size_t i = 0; i < rd_carry_.size(); ++i) {
            if (rd_carry_[i] == '\n') {
                std::string line(rd_carry_.data(), i);
                rd_carry_.erase(rd_carry_.begin(),
                                rd_carry_.begin() + static_cast<std::ptrdiff_t>(i + 1));
                return line;
            }
        }
        return std::nullopt;
    };

    if (auto first = take_line()) return std::move(*first);

    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    std::vector<char> buf(kReadChunk);

    while (rd_carry_.size() <= kMaxLineSize) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw HrError(HRESULT_FROM_WIN32(ERROR_TIMEOUT),
                          "WintunSvcClient: timed out reading from pipe");
        }
        const auto remaining_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        OVERLAPPED ov{};
        ov.hEvent = evt_;
        ::ResetEvent(evt_);

        DWORD got = 0;
        BOOL ok = ::ReadFile(pipe_, buf.data(),
                             util::checked_int_cast<DWORD>(buf.size()),
                             &got, &ov);
        DWORD err = ::GetLastError();
        if (!ok && err != ERROR_IO_PENDING) {
            throw HrError(HRESULT_FROM_WIN32(err),
                          "WintunSvcClient: ReadFile failed");
        }
        DWORD wr = ::WaitForSingleObject(
            evt_, util::checked_int_cast<DWORD>(remaining_ms));
        if (wr != WAIT_OBJECT_0) {
            ::CancelIoEx(pipe_, &ov);
            DWORD ignored = 0;
            ::GetOverlappedResult(pipe_, &ov, &ignored, /*wait=*/TRUE);
            throw HrError(HRESULT_FROM_WIN32(ERROR_TIMEOUT),
                          "WintunSvcClient: timed out reading from pipe");
        }
        if (!::GetOverlappedResult(pipe_, &ov, &got, FALSE)) {
            throw HrError(HRESULT_FROM_WIN32(::GetLastError()),
                          "WintunSvcClient: ReadFile (overlapped) failed");
        }
        if (got == 0) {
            throw HrError(HRESULT_FROM_WIN32(ERROR_BROKEN_PIPE),
                          "WintunSvcClient: pipe closed before newline");
        }
        rd_carry_.insert(rd_carry_.end(), buf.begin(),
                         buf.begin() + static_cast<std::ptrdiff_t>(got));
        if (auto line = take_line()) return std::move(*line);
    }
    throw HrError(E_FAIL,
                  "WintunSvcClient: response exceeded 64 KiB without newline");
}

std::wstring WintunSvcClient::Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    const int s_size = util::checked_int_cast<int>(s.size());
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), s_size, nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), s_size, w.data(), n);
    return w;
}

std::string WintunSvcClient::WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int w_size = util::checked_int_cast<int>(w.size());
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), w_size,
                                  nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), w_size,
                          s.data(), n, nullptr, nullptr);
    return s;
}

std::string WintunSvcClient::JsonEscape(const std::wstring& s) {
    // Caller passes already-validated wide name; we transcode to UTF-8
    // then escape per RFC 8259. Service-side validators reject control
    // chars and path separators in names, so this is just hygiene.
    std::string u = WideToUtf8(s);
    std::string out;
    out.reserve(u.size() + 2);
    for (unsigned char c : u) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

namespace {

// Common response handling. On `ok: false`, throws with code/message.
// On `ok: true`, returns the body (possibly empty) of the `data` field
// or an empty string.
std::string DecodeOkResponse(const std::string& line, const char* what) {
    std::size_t p = SkipWs(line, 0);
    if (p >= line.size() || line[p] != '{') {
        throw HrError(E_FAIL,
                      (std::string(what) + ": response is not a JSON object").c_str());
    }
    std::size_t okp = FindTopLevelKey(line, "ok");
    if (okp == std::string::npos) {
        throw HrError(E_FAIL,
                      (std::string(what) + ": missing 'ok' in response").c_str());
    }
    if (!LooksLikeTrue(line, okp)) {
        std::string code, message;
        std::size_t cp = FindTopLevelKey(line, "code");
        if (cp != std::string::npos) ParseString(line, cp, code);
        std::size_t mp = FindTopLevelKey(line, "message");
        if (mp != std::string::npos) ParseString(line, mp, message);
        std::string msg = std::string(what) + ": service returned error (code=";
        msg += code.empty() ? "?" : code;
        msg += ", message=";
        msg += message;
        msg += ")";
        throw HrError(E_FAIL, msg.c_str());
    }
    std::size_t dp = FindTopLevelKey(line, "data");
    if (dp == std::string::npos) return {};
    if (line[dp] != '{') return {};
    std::string obj;
    if (ExtractObject(line, dp, obj) == std::string::npos) return {};
    return obj;
}

}  // namespace

void WintunSvcClient::Ping() {
    SendRequest("{\"cmd\":\"ping\"}\n");
    std::string line = ReadOneLine();
    (void) DecodeOkResponse(line, "Ping");
}

WintunSvcAdapterInfo WintunSvcClient::EnsureAdapter(
    const std::wstring& name, const std::wstring& tunnel_type) {
    std::string req = "{\"cmd\":\"ensure_adapter\",\"name\":\"";
    req += JsonEscape(name);
    req += "\",\"tunnel_type\":\"";
    req += JsonEscape(tunnel_type);
    req += "\"}\n";
    SendRequest(req);

    std::string line = ReadOneLine();
    std::string data = DecodeOkResponse(line, "EnsureAdapter");
    if (data.empty()) {
        throw HrError(E_FAIL,
                      "EnsureAdapter: ok response missing `data` object");
    }
    WintunSvcAdapterInfo info{};

    std::size_t pn = FindTopLevelKey(data, "name");
    if (pn != std::string::npos) {
        std::string s;
        if (ParseString(data, pn, s) != std::string::npos) {
            info.name = Utf8ToWide(s);
        }
    }

    std::size_t pl = FindTopLevelKey(data, "luid");
    if (pl == std::string::npos) {
        throw HrError(E_FAIL, "EnsureAdapter: response missing luid");
    }
    std::uint64_t luid_val = 0;
    if (ParseU64(data, pl, luid_val) == std::string::npos) {
        throw HrError(E_FAIL, "EnsureAdapter: response luid not a number");
    }
    info.luid.Value = luid_val;

    std::size_t pg = FindTopLevelKey(data, "guid");
    if (pg != std::string::npos) {
        std::string s;
        if (ParseString(data, pg, s) != std::string::npos) {
            info.guid = Utf8ToWide(s);
        }
    }
    return info;
}

void WintunSvcClient::ConfigureAdapterIpv4(const std::wstring& name,
                                           const std::string& cidr,
                                           std::uint32_t mtu) {
    std::string req = "{\"cmd\":\"configure_adapter\",\"name\":\"";
    req += JsonEscape(name);
    req += "\",\"addresses\":[\"";
    // cidr is an internally-generated ASCII string; minimal escaping needed.
    for (char c : cidr) {
        if (c == '\"' || c == '\\') req.push_back('\\');
        req.push_back(c);
    }
    req += "\"],\"mtu\":";
    char numbuf[32];
    std::snprintf(numbuf, sizeof(numbuf), "%u", mtu);
    req += numbuf;
    // routes is REQUIRED by the server (non-Option). Always send an empty
    // array to mean "don't add anything", which is the correct default
    // for a host-local /24 + on-link route Windows installs for us.
    req += ",\"routes\":[]}\n";
    SendRequest(req);

    std::string line = ReadOneLine();
    (void) DecodeOkResponse(line, "ConfigureAdapter");
}

void WintunSvcClient::DeleteAdapter(const std::wstring& name) {
    std::string req = "{\"cmd\":\"delete_adapter\",\"name\":\"";
    req += JsonEscape(name);
    req += "\"}\n";
    SendRequest(req);
    std::string line = ReadOneLine();
    (void) DecodeOkResponse(line, "DeleteAdapter");
}

namespace {

// Parse `data` object, extracting a single u64 keyed by `key`. Throws
// `HrError` on missing/non-numeric.
std::uint64_t RequireU64(const std::string& data, const char* key,
                         const char* ctx) {
    std::size_t kp = FindTopLevelKey(data, key);
    if (kp == std::string::npos) {
        std::string m = std::string(ctx) + ": response missing `" + key + "`";
        throw HrError(E_FAIL, m.c_str());
    }
    std::uint64_t v = 0;
    if (ParseU64(data, kp, v) == std::string::npos) {
        std::string m = std::string(ctx) + ": response `" + key + "` not a number";
        throw HrError(E_FAIL, m.c_str());
    }
    return v;
}

}  // namespace

WintunSvcSessionHandles WintunSvcClient::OpenSession(const std::wstring& name,
                                                    std::uint32_t capacity) {
    std::string req = "{\"cmd\":\"open_session\",\"name\":\"";
    req += JsonEscape(name);
    req += "\"";
    if (capacity != 0) {
        char numbuf[32];
        std::snprintf(numbuf, sizeof(numbuf), ",\"capacity\":%u", capacity);
        req += numbuf;
    }
    req += "}\n";
    SendRequest(req);

    std::string line = ReadOneLine();
    std::string data = DecodeOkResponse(line, "OpenSession");
    if (data.empty()) {
        throw HrError(E_FAIL,
                      "OpenSession: ok response missing `data` object");
    }

    WintunSvcSessionHandles h{};
    const std::uint64_t section          = RequireU64(data, "section", "OpenSession");
    const std::uint64_t send_tail_moved  = RequireU64(data, "send_tail_moved", "OpenSession");
    const std::uint64_t recv_tail_moved  = RequireU64(data, "recv_tail_moved", "OpenSession");
    const std::uint64_t capacity_val     = RequireU64(data, "capacity", "OpenSession");
    const std::uint64_t ring_size        = RequireU64(data, "ring_size", "OpenSession");
    const std::uint64_t send_ring_offset = RequireU64(data, "send_ring_offset", "OpenSession");
    const std::uint64_t recv_ring_offset = RequireU64(data, "recv_ring_offset", "OpenSession");
    const std::uint64_t total_size       = RequireU64(data, "total_size", "OpenSession");

    if (capacity_val > UINT32_MAX || ring_size > UINT32_MAX ||
        send_ring_offset > UINT32_MAX || recv_ring_offset > UINT32_MAX) {
        throw HrError(E_FAIL, "OpenSession: numeric field overflows u32");
    }

    h.section          = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(section));
    h.send_tail_moved  = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(send_tail_moved));
    h.recv_tail_moved  = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(recv_tail_moved));
    h.capacity         = static_cast<std::uint32_t>(capacity_val);
    h.ring_size        = static_cast<std::uint32_t>(ring_size);
    h.send_ring_offset = static_cast<std::uint32_t>(send_ring_offset);
    h.recv_ring_offset = static_cast<std::uint32_t>(recv_ring_offset);
    h.total_size       = total_size;
    return h;
}

void WintunSvcClient::CloseSession() {
    SendRequest("{\"cmd\":\"close_session\"}\n");
    std::string line = ReadOneLine();
    (void) DecodeOkResponse(line, "CloseSession");
}

}  // namespace tinyvmm::net
