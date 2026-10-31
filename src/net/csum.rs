//! The RFC 1071 internet checksum. Kept apart from `wire.rs` so the protocol
//! code stays free of `unsafe`: this sums 16-bit words with AVX2 when the CPU
//! has it.

/// RFC 1071 ones-complement checksum of the concatenation of `parts`.
pub fn checksum16(parts: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    let mut leftover: Option<u8> = None;
    for part in parts {
        let mut data = *part;
        if let Some(hi) = leftover.take() {
            if let Some((&lo, rest)) = data.split_first() {
                sum += u64::from(u16::from_be_bytes([hi, lo]));
                data = rest;
            } else {
                leftover = Some(hi);
            }
        }
        let (words, odd) = data.split_at(data.len() & !1);
        sum += u64::from(sum_be16(words));
        if let Some(&b) = odd.first() {
            leftover = Some(b);
        }
    }
    if let Some(hi) = leftover {
        sum += u64::from(hi) << 8;
    }
    !fold16(sum)
}

/// Fold a ones-complement sum to 16 bits with end-around carries.
fn fold16(mut sum: u64) -> u16 {
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// Folded ones-complement sum of the big-endian 16-bit words of `words` (even
/// length). It sums little-endian words and swaps the folded sum's bytes, which
/// is the same (RFC 1071 §2(B)) and lets whole words load as they lie. This
/// runs over every payload byte of UDP datagrams to the guest and of guest
/// frames whose TX offloads finish in software: a byte pair at a time it ran
/// at ~3.7 GB/s; [`sum_le16`] runs at ~31 GB/s and [`sum_le16_avx2`] at ~52
/// (1400-byte packets, reference host).
fn sum_be16(words: &[u8]) -> u16 {
    #[cfg(target_arch = "x86_64")]
    if words.len() >= 128 && std::arch::is_x86_feature_detected!("avx2") {
        // SAFETY: the CPU supports AVX2 (checked just above).
        return fold16(unsafe { sum_le16_avx2(words) }).swap_bytes();
    }
    fold16(sum_le16(words)).swap_bytes()
}

/// Unfolded sum of the little-endian 16-bit words of `words` (even length),
/// four bytes at a time: a 32-bit word folds to the sum of its two halves.
fn sum_le16(words: &[u8]) -> u64 {
    let (quads, tail) = words.as_chunks::<4>();
    let mut sum: u64 = quads
        .iter()
        .map(|q| u64::from(u32::from_le_bytes(*q)))
        .sum();
    if let [lo, hi] = *tail {
        sum += u64::from(u16::from_le_bytes([lo, hi]));
    }
    sum
}

/// [`sum_le16`] 64 bytes at a time: four accumulators of 32-bit lanes add the
/// low and the high 16-bit halves of each 32-bit lane of input.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn sum_le16_avx2(words: &[u8]) -> u64 {
    use std::arch::x86_64::*;

    let mask = _mm256_set1_epi32(0xFFFF);
    let load = |b: &[u8]| {
        assert!(b.len() >= 32);
        // SAFETY: `b` has at least 32 readable bytes; the load is unaligned.
        unsafe { _mm256_loadu_si256(b.as_ptr().cast()) }
    };
    let (blocks, rest) = words.as_chunks::<64>();
    let mut sum = sum_le16(rest);
    // A lane gains at most 0xFFFF per block, so 2^16 blocks can't overflow it.
    for group in blocks.chunks(1 << 16) {
        let mut acc = [_mm256_setzero_si256(); 4];
        for b in group {
            let (v0, v1) = (load(&b[..32]), load(&b[32..]));
            acc[0] = _mm256_add_epi32(acc[0], _mm256_and_si256(v0, mask));
            acc[1] = _mm256_add_epi32(acc[1], _mm256_srli_epi32::<16>(v0));
            acc[2] = _mm256_add_epi32(acc[2], _mm256_and_si256(v1, mask));
            acc[3] = _mm256_add_epi32(acc[3], _mm256_srli_epi32::<16>(v1));
        }
        // Widen the lanes to 64 bits to add them up.
        let zero = _mm256_setzero_si256();
        let mut wide = zero;
        for a in acc {
            wide = _mm256_add_epi64(wide, _mm256_unpacklo_epi32(a, zero));
            wide = _mm256_add_epi64(wide, _mm256_unpackhi_epi32(a, zero));
        }
        let mut lanes = [0u64; 4];
        // SAFETY: `lanes` is 32 writable bytes; the store is unaligned.
        unsafe { _mm256_storeu_si256(lanes.as_mut_ptr().cast(), wide) };
        sum += lanes.iter().sum::<u64>();
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte-pair loop `checksum16` used to be.
    fn checksum16_byte_pairs(parts: &[&[u8]]) -> u16 {
        let mut sum = 0u64;
        for pair in parts.concat().chunks(2) {
            sum += u64::from(pair[0]) << 8 | u64::from(pair.get(1).copied().unwrap_or(0));
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Each word-summing path matches the byte-pair loop: AVX2 and the portable
    /// one, around the 64-byte blocks and the AVX2 cutover, for parts split at
    /// odd offsets, and past 2^16 all-ones blocks, where a lane would overflow.
    #[test]
    fn checksum16_matches_byte_pair_loop() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let noise: Vec<u8> = (0..70_000)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed >> 24) as u8
            })
            .collect();
        let ones = vec![0xFFu8; (64 << 16) + 70];
        for data in [&noise[..], &[0u8; 3000][..], &ones[..]] {
            for len in (0..300).chain([1400, 9001, data.len()]) {
                let d = &data[..len.min(data.len())];
                assert_eq!(checksum16(&[d]), checksum16_byte_pairs(&[d]), "len {len}");
                let words = &d[..d.len() & !1];
                let want = !checksum16_byte_pairs(&[words]);
                assert_eq!(fold16(sum_le16(words)).swap_bytes(), want, "len {len}");
                #[cfg(target_arch = "x86_64")]
                if std::arch::is_x86_feature_detected!("avx2") {
                    // SAFETY: the CPU supports AVX2 (checked just above).
                    let avx2 = fold16(unsafe { sum_le16_avx2(words) });
                    assert_eq!(avx2.swap_bytes(), want, "len {len}");
                }
            }
        }
        let d = &noise[1..5000];
        for (a, b) in [(0, 0), (1, 1), (3, 700), (131, 2048), (12, 4999)] {
            let parts = [&d[..a], &d[a..b], &d[b..]];
            assert_eq!(checksum16(&parts), checksum16_byte_pairs(&parts), "{a},{b}");
        }
    }
}
