#pragma once

// winsock2.h must precede Windows.h. We do this globally here so any
// later <iphlpapi.h>, <ws2tcpip.h>, third-party `wintun.h`, etc.
// include in any translation unit gets the right typedefs.
#include <winsock2.h>

#include <Windows.h>
#include <winerror.h>

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

namespace tinyvmm {

// HRESULT-bearing exception. Anything that calls into WHP throws this on
// failure rather than smearing error-checking through the codebase.
class HrError : public std::runtime_error {
public:
    HrError(HRESULT hr, const char* what)
        : std::runtime_error(format(hr, what)), hr_(hr) {}

    HRESULT hr() const noexcept { return hr_; }

private:
    HRESULT hr_;

    static std::string format(HRESULT hr, const char* what) {
        char buf[256];
        std::snprintf(buf, sizeof(buf), "%s: HRESULT=0x%08lX", what,
                      static_cast<unsigned long>(hr));
        return std::string(buf);
    }
};

inline void ThrowIfFailed(HRESULT hr, const char* what) {
    if (FAILED(hr)) {
        throw HrError(hr, what);
    }
}

// Print to stderr and abort. For programmer-error checks where recovery is not
// meaningful (e.g. unreachable enum cases).
[[noreturn]] inline void Fatal(const char* what) {
    std::fputs("tinyvmm fatal: ", stderr);
    std::fputs(what, stderr);
    std::fputc('\n', stderr);
    std::abort();
}

// Page-aligned size constants used throughout. Guest physical memory and
// virtio queue layouts care about these.
constexpr std::size_t kPageSize = 4096;
constexpr std::size_t kPageMask = kPageSize - 1;

constexpr std::uint64_t AlignDown(std::uint64_t v, std::uint64_t a) {
    return v & ~(a - 1);
}
constexpr std::uint64_t AlignUp(std::uint64_t v, std::uint64_t a) {
    return AlignDown(v + a - 1, a);
}

namespace util {

// Narrowing integer cast with overflow detection. Throws
// HrError(E_INVALIDARG) if `v` cannot be represented as `To`. Use this
// whenever a guest- or attacker-influenced integer must fit into a
// smaller (or differently-signed) integer type before being handed to
// a Win32 API, a printf "%.*s" width, or other downstream consumer
// that would silently truncate.
//
// Implementation note: std::in_range<To>(v) from C++20 <utility>
// already encodes all four signed/unsigned combinations correctly
// (with sign-preserving comparisons under the hood), so we just defer
// to it and throw on out-of-range.
template <typename To, typename From>
constexpr To checked_int_cast(From v) {
    static_assert(std::is_integral_v<To> && std::is_integral_v<From>,
                  "checked_int_cast requires integral types");
    if (!std::in_range<To>(v)) {
        throw HrError(E_INVALIDARG, "checked_int_cast: value out of range");
    }
    return static_cast<To>(v);
}

}  // namespace util

}  // namespace tinyvmm
