use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::Aes128;

const BLOCK_SIZE: usize = 16;

/// Streaming AES-128-CTR cipher context. Equivalent to AES_CTR_CTX in aes_ctr.h.
///
/// Manually implements CTR mode to exactly match the C code's behavior:
/// encrypts counter with AES-ECB (the C code uses CBC with zeroed IV, which is
/// equivalent to ECB for a single block), XORs with plaintext, increments counter.
pub struct AesCtr {
    cipher: Aes128,
    counter: [u8; BLOCK_SIZE],
    state: [u8; BLOCK_SIZE],
    available: usize,
}

impl AesCtr {
    /// Initialize with a 128-bit key and 128-bit nonce/IV.
    /// Equivalent to AES_ctr_set_key with AES_MODE_128.
    pub fn new(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut counter = [0u8; BLOCK_SIZE];
        counter.copy_from_slice(nonce);
        Self {
            cipher,
            counter,
            state: [0u8; BLOCK_SIZE],
            available: 0,
        }
    }

    /// Increment the 128-bit counter (big-endian). Equivalent to ctr128_inc.
    fn inc_counter(&mut self) {
        let mut carry: u16 = 1;
        for i in (0..BLOCK_SIZE).rev() {
            carry += self.counter[i] as u16;
            self.counter[i] = carry as u8;
            carry >>= 8;
        }
    }

    /// Encrypt (or decrypt) data in-place. Equivalent to AES_ctr_encrypt.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        let mut idx = 0;
        while idx < data.len() {
            if self.available == 0 {
                // Encrypt counter block (ECB = CBC with zero IV on single block)
                let mut block = GenericArray::clone_from_slice(&self.counter);
                self.cipher.encrypt_block(&mut block);
                self.state.copy_from_slice(&block);
                self.available = BLOCK_SIZE;
                self.inc_counter();
            }
            let offset = BLOCK_SIZE - self.available;
            let n = self.available.min(data.len() - idx);
            for i in 0..n {
                data[idx] ^= self.state[offset + i];
                idx += 1;
            }
            self.available -= n;
        }
    }

    /// Encrypt from src into dst. Equivalent to AES_ctr_encrypt with separate buffers.
    pub fn encrypt_to(&mut self, src: &[u8], dst: &mut [u8]) {
        dst[..src.len()].copy_from_slice(src);
        self.encrypt(&mut dst[..src.len()]);
    }
}
