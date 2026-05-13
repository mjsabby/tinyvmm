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

}  // namespace tinyvmm
