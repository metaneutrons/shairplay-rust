//! AES-128-CTR streaming cipher for video packet decryption.
//!
//! Video packets use AES-CTR with a key derived from the FairPlay session.
//! The cipher maintains partial block state across packets (streaming mode).

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

/// Streaming AES-128-CTR cipher that maintains state across packets.
pub struct VideoCipher {
    cipher: Ctr128BE<Aes128>,
    /// Leftover keystream bytes from the previous partial block.
    leftover: [u8; 16],
    /// Number of leftover bytes to apply before resuming CTR.
    leftover_count: usize,
}

impl VideoCipher {
    /// Create a new video cipher from a 16-byte key and 16-byte IV.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Ctr128BE::<Aes128>::new(key.into(), iv.into()),
            leftover: [0u8; 16],
            leftover_count: 0,
        }
    }

    /// Decrypt a video payload in-place, maintaining streaming CTR state.
    pub fn decrypt(&mut self, payload: &mut [u8]) {
        let n = self.leftover_count;

        // Apply leftover keystream from previous partial block
        if n > 0 {
            let apply = n.min(payload.len());
            for (p, &k) in payload[..apply].iter_mut().zip(&self.leftover[(16 - n)..]) {
                *p ^= k;
            }
            if apply < n {
                self.leftover_count = n - apply;
                return;
            }
        }

        // Decrypt full blocks
        let offset = n;
        let remaining = payload.len() - offset;
        let full_len = (remaining / 16) * 16;
        self.cipher.apply_keystream(&mut payload[offset..offset + full_len]);

        // Handle trailing partial block
        let rest_len = remaining % 16;
        if rest_len > 0 {
            let rest_start = payload.len() - rest_len;
            self.leftover = [0u8; 16];
            self.leftover[..rest_len].copy_from_slice(&payload[rest_start..]);
            self.cipher.apply_keystream(&mut self.leftover);
            payload[rest_start..].copy_from_slice(&self.leftover[..rest_len]);
            self.leftover_count = 16 - rest_len;
        } else {
            self.leftover_count = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_full_blocks() {
        let key = [0x01u8; 16];
        let iv = [0x00u8; 16];
        let mut cipher1 = VideoCipher::new(&key, &iv);
        let mut cipher2 = VideoCipher::new(&key, &iv);

        // Encrypt with cipher1, decrypt with cipher2
        let original = vec![0xAA; 32];
        let mut data = original.clone();
        cipher1.decrypt(&mut data); // "encrypt" (CTR is symmetric)
        assert_ne!(data, original);
        cipher2.decrypt(&mut data); // decrypt
        assert_eq!(data, original);
    }

    #[test]
    fn decrypt_partial_blocks_streaming() {
        let key = [0x42u8; 16];
        let iv = [0x00u8; 16];

        // Single cipher, two chunks that don't align to 16 bytes
        let mut cipher_a = VideoCipher::new(&key, &iv);
        let mut chunk1 = vec![0u8; 10];
        let mut chunk2 = vec![0u8; 22]; // 10 + 22 = 32 = 2 full blocks
        cipher_a.decrypt(&mut chunk1);
        cipher_a.decrypt(&mut chunk2);

        // Same key, one 32-byte chunk
        let mut cipher_b = VideoCipher::new(&key, &iv);
        let mut full = vec![0u8; 32];
        cipher_b.decrypt(&mut full);

        // Results must match
        assert_eq!(&chunk1[..], &full[..10]);
        assert_eq!(&chunk2[..], &full[10..]);
    }
}
