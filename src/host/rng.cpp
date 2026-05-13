#include "rng.h"

#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace tinyvmm::host {

void RandomFill(void* buf, std::size_t len) {
    if (len == 0) return;
    // BCryptGenRandom uses ULONG for length; cap at ULONG_MAX and loop.
    auto* p = static_cast<unsigned char*>(buf);
    while (len > 0) {
        const ULONG chunk = static_cast<ULONG>(
            len > 0x40000000u ? 0x40000000u : len);
        const NTSTATUS s = BCryptGenRandom(
            nullptr, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (s != 0 /* STATUS_SUCCESS */) {
            ThrowIfFailed(HRESULT_FROM_NT(s), "BCryptGenRandom");
        }
        p   += chunk;
        len -= chunk;
    }
}

}  // namespace tinyvmm::host
