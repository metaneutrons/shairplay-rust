//! Block-cipher parts of the FairPlay key exchange.
//!
//! Three pieces live here: the key schedule, the cipher that unwraps the 16-byte
//! session key, and the chained cipher that opens the 128-byte payload of the second
//! handshake message. All three are table driven and share one byte shuffle.

use crate::crypto::fairplay_data::*;

/// A 16-byte cipher block.
pub(crate) type Block = [u8; 16];

/// Round constants of the key schedule.
const ROUND_CONSTANTS: [u8; 11] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
];

/// Number of rounds of the key unwrap cipher, not counting the first and last key addition.
const UNWRAP_ROUNDS: usize = 9;

/// Offset of the last key block inside the per-mode message key (`0x80`).
const MESSAGE_LAST_BASE: usize = 0x80;

/// Which input byte feeds output byte `k` in every shuffle step.
const fn source_of(k: usize) -> usize {
    (13 * k) % 16
}

/// Rotate-and-substitute step shared by all three ciphers: output byte `k` is
/// `f(k, input[source_of(k)])`, with all inputs taken from the block as it was before the call.
fn shuffle(block: &mut Block, f: impl Fn(usize, u8) -> u8) {
    let input = *block;
    for (k, out) in block.iter_mut().enumerate() {
        *out = f(k, input[source_of(k)]);
    }
}

fn word_at(bytes: &[u8], index: usize) -> u32 {
    u32::from_le_bytes([
        bytes[4 * index],
        bytes[4 * index + 1],
        bytes[4 * index + 2],
        bytes[4 * index + 3],
    ])
}

fn xor_words(block: &mut Block, key: &[u32; 4]) {
    for (chunk, k) in block.as_chunks_mut::<4>().0.iter_mut().zip(key) {
        *chunk = (u32::from_le_bytes(*chunk) ^ k).to_le_bytes();
    }
}

/// The eleven 128-bit round keys derived from 16 bytes of key material.
pub(crate) struct RoundKeys(pub(crate) [[u32; 4]; 11]);

impl RoundKeys {
    pub(crate) fn derive(material: &[u8; 16]) -> Self {
        let mut state: Block = std::array::from_fn(|i| material[i] ^ MASK_T[i]);
        let mut keys = [[0u32; 4]; 11];

        for (round, key) in keys.iter_mut().enumerate() {
            for (index, word) in key.iter_mut().enumerate() {
                *word = word_at(&state, index);
            }

            // Four substitution pages per round, picked in a fixed stride.
            let page = |n: usize| &KS_PAGES[((31 * (4 * round + n)) % 40) << 8..][..256];
            state[0] ^= page(0)[state[13] as usize] ^ ROUND_CONSTANTS[round];
            state[1] ^= page(1)[state[14] as usize];
            state[2] ^= page(2)[state[15] as usize];
            state[3] ^= page(3)[state[12] as usize];

            // Each word absorbs the one before it.
            let mut carry = word_at(&state, 0);
            for index in 1..4 {
                carry ^= word_at(&state, index);
                state[4 * index..4 * index + 4].copy_from_slice(&carry.to_le_bytes());
            }
        }
        Self(keys)
    }
}

/// Run the unwrap cipher over one block in place.
pub(crate) fn unwrap_block(block: &mut Block, keys: &RoundKeys) {
    xor_words(block, &keys.0[10]);
    shuffle(block, |k, v| PERM_FWD[(((5 * k) % 16) << 8) + v as usize]);

    for round in 0..UNWRAP_ROUNDS {
        let key = &keys.0[UNWRAP_ROUNDS - round];
        for (column, word) in block.as_chunks_mut::<4>().0.iter_mut().zip(key) {
            let k = word.to_le_bytes();
            let mixed = MIX_0[(column[3] ^ k[3]) as usize]
                ^ MIX_1[(column[2] ^ k[2]) as usize]
                ^ MIX_2[(column[1] ^ k[1]) as usize]
                ^ MIX_3[(column[0] ^ k[0]) as usize];
            *column = mixed.to_le_bytes();
        }
        let first = (UNWRAP_ROUNDS - 1 - round) * 16;
        shuffle(block, |k, v| {
            PERM_PAGES[(((71 * (first + k)) % 144) << 8) + v as usize]
        });
    }

    xor_words(block, &keys.0[0]);
}

/// Open the 128-byte payload that follows the header of the second handshake message.
///
/// `message` is the whole 164-byte message, byte 12 selects the mode. Modes 0 to 2
/// chain the blocks front to back, mode 3 back to front.
pub(crate) fn open_message(message: &[u8], out: &mut [u8; 128]) {
    let mode = message[12] as usize;
    let key = &MSG_KEYS[mode * 144..(mode + 1) * 144];
    let iv = &MSG_IVS[mode * 16..(mode + 1) * 16];
    let reversed = mode == 3;

    for i in 0..8 {
        let at = if reversed { 0x70 - 0x10 * i } else { 0x10 * i };
        let mut block: Block = std::array::from_fn(|j| message[at + 0x10 + j]);

        for round in 0..UNWRAP_ROUNDS {
            let base = MESSAGE_LAST_BASE - 0x10 * round;
            shuffle(&mut block, |k, v| {
                MSG_PAGES[(((97 * (base + k)) % 144) << 8) + v as usize] ^ key[base + k]
            });
            for column in block.as_chunks_mut::<4>().0 {
                let mixed = MIX_MSG[column[0] as usize]
                    ^ MIX_MSG[0x100 + column[1] as usize]
                    ^ MIX_MSG[0x200 + column[2] as usize]
                    ^ MIX_MSG[0x300 + column[3] as usize];
                *column = mixed.to_le_bytes();
            }
        }
        shuffle(&mut block, |k, v| PERM_OUT[(k << 8) + v as usize]);

        let chained = if reversed { i < 7 } else { i > 0 };
        let previous = if chained { &message[at..at + 16] } else { iv };
        for j in 0..16 {
            out[at + j] = block[j] ^ previous[j];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn unwrap_with_zero_round_keys() {
        let mut block: Block = std::array::from_fn(|i| i as u8 + 1);
        unwrap_block(&mut block, &RoundKeys([[0u32; 4]; 11]));
        assert_eq!(to_hex(&block), "d8dfd3c32f1de7b4d16e65e92e6d3f27");
    }

    #[test]
    fn open_message_vector() {
        let mut msg = [0x41u8; 164];
        msg[..4].copy_from_slice(b"FPLY");
        msg[4] = 0x03;
        msg[12] = 0x01;
        let mut opened = [0u8; 128];
        open_message(&msg, &mut opened);
        assert_eq!(to_hex(&opened[..16]), "efbf616443ab486b700a3f743df20ddd");
        assert_eq!(to_hex(&opened[112..]), "71853546f2ef515d63e27a37c510de09");
    }
}
