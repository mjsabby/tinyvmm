#pragma once

// Cryptographically-strong random bytes from the Windows CNG API.
//
// Used as the entropy source for virtio-rng (M17). We use
// `BCryptGenRandom(... BCRYPT_USE_SYSTEM_PREFERRED_RNG)` so we don't
// have to manage an algorithm provider handle — Windows resolves it to
// the kernel's `SystemPrng`/`RNG` provider per call.

#include "common.h"

#include <cstddef>

namespace tinyvmm::host {

// Fill `buf` with `len` cryptographically-random bytes. Throws HrError
// on the (extremely unlikely) BCrypt failure.
void RandomFill(void* buf, std::size_t len);

}  // namespace tinyvmm::host
