//! The two 64-byte digests that feed the FairPlay session key: an MD5 variant keyed by
//! the running key, and a scrambling hash built around the blender.

use crate::crypto::fairplay_blender::blend;
use crate::crypto::fairplay_data::*;

/// MD5 step constants, `floor(2^32 * |sin(i + 1)|)`, as a fixed table.
///
/// Computing them at run time would depend on the platform's `sin`, which is not
/// guaranteed to be bit-identical everywhere, and a 1-ULP difference would silently
/// corrupt the key.
const STEP_CONSTANTS: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Rotation amounts, four per group of sixteen steps.
const STEP_ROTATIONS: [[u32; 4]; 4] = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21],
];

fn le_words(bytes: &[u8; 16]) -> [u32; 4] {
    std::array::from_fn(|i| {
        u32::from_le_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ])
    })
}

fn le_bytes(words: [u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    out
}

/// Add two 16-byte values word by word, little endian.
pub(crate) fn add_words(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let (a, b) = (le_words(a), le_words(b));
    le_bytes(std::array::from_fn(|i| a[i].wrapping_add(b[i])))
}

/// MD5 over one 64-byte block, started from `chain` instead of the standard state.
///
/// Halfway through, after step 31, five pairs of message words trade places, picked by
/// the current state. Message words are read big endian.
pub(crate) fn md5_variant(input: &[u8; 64], chain: &[u8; 16]) -> [u8; 16] {
    let mut block = *input;
    let start = le_words(chain);
    let [mut a, mut b, mut c, mut d] = start;

    for step in 0..64usize {
        let (mixed, index) = match step / 16 {
            0 => ((b & c) | (!b & d), step),
            1 => ((b & d) | (c & !d), (5 * step + 1) % 16),
            2 => (b ^ c ^ d, (3 * step + 5) % 16),
            _ => (c ^ (b | !d), (7 * step) % 16),
        };
        let word = u32::from_be_bytes([
            block[4 * index],
            block[4 * index + 1],
            block[4 * index + 2],
            block[4 * index + 3],
        ]);
        let rotation = STEP_ROTATIONS[step / 16][step % 4];
        let sum = a
            .wrapping_add(word)
            .wrapping_add(STEP_CONSTANTS[step])
            .wrapping_add(mixed);
        let next = sum.rotate_left(rotation).wrapping_add(b);
        (a, b, c, d) = (d, next, b, c);

        if step == 31 {
            let pairs = [
                (a & 15, b & 15),
                (c & 15, d & 15),
                ((a >> 4) & 15, (b >> 4) & 15),
                ((a >> 8) & 15, (b >> 8) & 15),
                ((a >> 12) & 15, (b >> 12) & 15),
            ];
            for (x, y) in pairs {
                for byte in 0..4 {
                    block.swap(4 * x as usize + byte, 4 * y as usize + byte);
                }
            }
        }
    }

    le_bytes([
        start[0].wrapping_add(a),
        start[1].wrapping_add(b),
        start[2].wrapping_add(c),
        start[3].wrapping_add(d),
    ])
}

/// Scrambling hash of one 64-byte block.
///
/// The block is stretched to 210 bytes with each four-byte group reversed, stirred, run
/// through the blender together with fixed seed buffers, and folded into 16 bytes.
pub(crate) fn scramble(block: &[u8; 64]) -> [u8; 16] {
    let mut lane0 = BLEND_SEED_0;
    let mut lane1 = [0u8; 210];
    let mut lane2 = BLEND_SEED_2;
    let mut lane3 = [0u8; 132];

    for (i, slot) in lane1.iter_mut().enumerate() {
        let p = i % 64;
        *slot = block[(p & !3) + 3 - (p % 4)];
    }

    // The look-back distances are taken modulo 210 on a wrapping 32-bit counter.
    for i in 0u32..840 {
        let at = |back: u32| lane1[i.wrapping_sub(back) as usize % 210];
        let (x, y, z) = (at(155), at(57), at(13));
        let slot = i as usize % 210;
        lane1[slot] = y
            .rotate_left(5)
            .wrapping_add(z.rotate_left(3) ^ lane1[slot])
            .wrapping_sub(x.rotate_left(7));
    }

    blend(&mut lane0, &mut lane1, &mut lane2, &mut lane3, &BLEND_AUX);

    let mut out = [0xe1u8; 16];
    for (i, byte) in out.iter_mut().enumerate().take(OUT_TAPS.len()) {
        *byte = if i == 3 {
            0x3d
        } else {
            byte.wrapping_add(lane3[OUT_TAPS[i] as usize * 4])
        };
    }
    for lane in [&lane0[..], &lane2[..], &lane1[..]] {
        for (i, &byte) in lane.iter().enumerate() {
            out[i % 16] ^= byte;
        }
    }
    for _ in 0..16 {
        for i in 0..16 {
            out[i] = out[(i + 9) % 16].rotate_left(1)
                ^ out[i]
                ^ out[(i + 11) % 16].rotate_left(6)
                ^ out[(i + 15) % 16].rotate_left(5);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    const REAL_BLOCK: [u8; 64] = [
        0xfa, 0x9c, 0xad, 0x4d, 0x4b, 0x68, 0x26, 0x8c, 0x7f, 0xf3, 0x88, 0x99, 0xde, 0x92, 0x2e,
        0x95, 0x1e, 0xef, 0xbf, 0x61, 0x64, 0x43, 0xab, 0x48, 0x6b, 0x70, 0x0a, 0x3f, 0x74, 0x3d,
        0xf2, 0x0d, 0xdd, 0x71, 0x85, 0x35, 0x46, 0xf2, 0xef, 0x51, 0x5d, 0x63, 0xe2, 0x7a, 0x37,
        0xc5, 0x10, 0xde, 0x09, 0x71, 0x85, 0x35, 0x46, 0xf2, 0xef, 0x51, 0x5d, 0x63, 0xe2, 0x7a,
        0x37, 0xc5, 0x10, 0xde,
    ];
    const REAL_CHAIN: [u8; 16] = [
        0xdc, 0xdc, 0xf3, 0xb9, 0x0b, 0x74, 0xdc, 0xfb, 0x86, 0x7f, 0xf7, 0x60, 0x16, 0x72, 0x90,
        0x51,
    ];

    #[test]
    fn md5_variant_vectors() {
        assert_eq!(
            to_hex(&md5_variant(&[0u8; 64], &[0u8; 16])),
            "971ccdf7813648a532d8682b39a60cf9"
        );
        assert_eq!(
            to_hex(&md5_variant(&[0x41u8; 64], &[0x41u8; 16])),
            "695b0c3715d9d4ceb4bfee317c92de79"
        );
        assert_eq!(
            to_hex(&md5_variant(&REAL_BLOCK, &REAL_CHAIN)),
            "47da73bfb135d7aaf2934e953f6372ed"
        );
        let block: [u8; 64] = std::array::from_fn(|i| i as u8);
        let chain: [u8; 16] = std::array::from_fn(|i| (i + 64) as u8);
        assert_eq!(
            to_hex(&md5_variant(&block, &chain)),
            "086862637e36ec8ccfeed2d71d459bf0"
        );
    }

    #[test]
    fn scramble_vector() {
        assert_eq!(
            to_hex(&scramble(&REAL_BLOCK)),
            "b638c90d9db20392b91613624eb07ba4"
        );
    }
}
