//! ChaCha20-Poly1305 encrypted transport for AirPlay 2 RTSP sessions.
//!
//! After pair-setup/pair-verify, all RTSP traffic is encrypted in blocks:
//! `[u16 LE: block_len] [ciphertext: block_len bytes] [auth_tag: 16 bytes]`
//!
//! The block_len (plaintext size) is used as AAD. Max block size is 1024 bytes.
//! Nonce: `[0,0,0,0, counter_u64_LE]`, counter increments per block.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::CryptoError;

const MAX_BLOCK_LEN: usize = 0x400; // 1024
const TAG_LEN: usize = 16;

/// Encrypted channel (one direction: either encrypt or decrypt).
pub struct CipherContext {
    key: [u8; 32],
    counter: u64,
}

impl CipherContext {
    /// Create a new encryption context from a 256-bit key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    /// Encrypt plaintext into framed blocks. Returns the full wire bytes.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.is_empty() {
            return Err(CryptoError::Aes("empty plaintext".into()));
        }

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nblocks = plaintext.len().div_ceil(MAX_BLOCK_LEN);
        let mut out = Vec::with_capacity(nblocks * (2 + MAX_BLOCK_LEN + TAG_LEN));

        for chunk in plaintext.chunks(MAX_BLOCK_LEN) {
            let block_len = (chunk.len() as u16).to_le_bytes();
            let nonce = self.nonce();

            let ct = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: chunk,
                        aad: &block_len,
                    },
                )
                .map_err(|_| CryptoError::Aes("ChaCha20 encrypt failed".into()))?;

            // ct includes ciphertext + 16-byte tag appended by the AEAD
            out.extend_from_slice(&block_len);
            out.extend_from_slice(&ct);
            self.counter += 1;
        }
        Ok(out)
    }

    /// Decrypt framed blocks. Returns (plaintext, bytes_consumed).
    /// May consume less than input if a block is incomplete.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, usize), CryptoError> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut plain = Vec::new();
        let mut pos = 0;

        while pos + 2 <= ciphertext.len() {
            let block_len = u16::from_le_bytes([ciphertext[pos], ciphertext[pos + 1]]) as usize;
            let frame_len = 2 + block_len + TAG_LEN;
            if pos + frame_len > ciphertext.len() {
                break; // Incomplete block
            }

            let block_len_bytes = [ciphertext[pos], ciphertext[pos + 1]];
            let ct_with_tag = &ciphertext[pos + 2..pos + 2 + block_len + TAG_LEN];
            let nonce = self.nonce();

            let pt = cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ct_with_tag,
                        aad: &block_len_bytes,
                    },
                )
                .map_err(|_| CryptoError::Aes("ChaCha20 decrypt failed".into()))?;

            plain.extend_from_slice(&pt);
            pos += frame_len;
            self.counter += 1;
        }
        Ok((plain, pos))
    }
}

/// Bidirectional encrypted channel for an RTSP connection.
pub struct EncryptedChannel {
    /// Encrypts outgoing RTSP responses.
    pub encrypt_ctx: CipherContext,
    /// Decrypts incoming RTSP requests.
    pub decrypt_ctx: CipherContext,
}

impl EncryptedChannel {
    /// Create from shared secret + HKDF salt/info pairs for write and read keys.
    pub fn new(
        shared_secret: &[u8],
        write_salt: &str,
        write_info: &str,
        read_salt: &str,
        read_info: &str,
    ) -> Result<Self, CryptoError> {
        let mut write_key = [0u8; 32];
        let mut read_key = [0u8; 32];

        let hk = Hkdf::<Sha512>::new(Some(write_salt.as_bytes()), shared_secret);
        hk.expand(write_info.as_bytes(), &mut write_key)
            .map_err(|_| CryptoError::Aes("HKDF write key failed".into()))?;

        let hk = Hkdf::<Sha512>::new(Some(read_salt.as_bytes()), shared_secret);
        hk.expand(read_info.as_bytes(), &mut read_key)
            .map_err(|_| CryptoError::Aes("HKDF read key failed".into()))?;

        Ok(Self {
            encrypt_ctx: CipherContext::new(write_key),
            decrypt_ctx: CipherContext::new(read_key),
        })
    }

    /// Create a control channel (channel 3 = server-side control).
    pub fn control(shared_secret: &[u8]) -> Result<Self, CryptoError> {
        Self::new(
            shared_secret,
            "Control-Salt",
            "Control-Read-Encryption-Key",
            "Control-Salt",
            "Control-Write-Encryption-Key",
        )
    }

    /// Create an event channel (channel 4 = server-side events).
    pub fn events(shared_secret: &[u8]) -> Result<Self, CryptoError> {
        Self::new(
            shared_secret,
            "Events-Salt",
            "Events-Write-Encryption-Key",
            "Events-Salt",
            "Events-Read-Encryption-Key",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_single_block() {
        let key = [0x42u8; 32];
        let mut enc = CipherContext::new(key);
        let mut dec = CipherContext::new(key);

        let plain = b"Hello, AirPlay 2!";
        let ct = enc.encrypt(plain).unwrap();
        let (pt, consumed) = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, plain);
        assert_eq!(consumed, ct.len());
    }

    #[test]
    fn roundtrip_multi_block() {
        let key = [0xAB; 32];
        let mut enc = CipherContext::new(key);
        let mut dec = CipherContext::new(key);

        // 2500 bytes → 3 blocks (1024 + 1024 + 452)
        let plain: Vec<u8> = (0u16..2500).map(|i| (i & 0xff) as u8).collect();
        let ct = enc.encrypt(&plain).unwrap();
        assert_eq!(enc.counter, 3);

        let (pt, consumed) = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, plain);
        assert_eq!(consumed, ct.len());
        assert_eq!(dec.counter, 3);
    }

    #[test]
    fn incremental_decrypt() {
        let key = [0x99; 32];
        let mut enc = CipherContext::new(key);
        let mut dec = CipherContext::new(key);

        let ct = enc.encrypt(b"test data here").unwrap();

        // Feed partial data — should consume 0
        let (pt, consumed) = dec.decrypt(&ct[..5]).unwrap();
        assert!(pt.is_empty());
        assert_eq!(consumed, 0);

        // Feed full data
        let (pt, consumed) = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, b"test data here");
        assert_eq!(consumed, ct.len());
    }

    #[test]
    fn corrupted_tag_rejected() {
        let key = [0x11; 32];
        let mut enc = CipherContext::new(key);
        let mut dec = CipherContext::new(key);

        let mut ct = enc.encrypt(b"secret").unwrap();
        // Corrupt the auth tag (last byte)
        let last = ct.len() - 1;
        ct[last] ^= 0xff;

        assert!(dec.decrypt(&ct).is_err());
    }

    #[test]
    fn encrypted_channel_control() {
        let secret = [0x55u8; 64];
        let server = EncryptedChannel::control(&secret).unwrap();
        assert_ne!(server.encrypt_ctx.key, [0u8; 32]);
        assert_ne!(server.decrypt_ctx.key, [0u8; 32]);
        assert_ne!(server.encrypt_ctx.key, server.decrypt_ctx.key);
    }

    // --- C-verified test vectors (generated from OpenSSL EVP_chacha20_poly1305) ---

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn c_vector_single_block() {
        let key = [0x42u8; 32];
        let mut enc = CipherContext::new(key);
        let ct = enc.encrypt(b"Hello, AirPlay 2!").unwrap();
        assert_eq!(
            hex_encode(&ct),
            "1100110388477298138c85d304589e56888a9fdf4df47289f10c4d8bf4f3052c1b7014"
        );
    }

    #[test]
    fn c_vector_counter_0() {
        let key = [0xABu8; 32];
        let mut enc = CipherContext::new(key);
        let plain: Vec<u8> = (0u8..100).collect();
        let ct = enc.encrypt(&plain).unwrap();
        assert_eq!(
            hex_encode(&ct),
            "6400fc234f2ff9641f53b69282ced5d3db3a905abec11c50765d3feaf6b95907eefb45cf47144c23bcb8161bf17f4c69d22000e4ea6613470d6d0f2add85c1d6632543b4743faa7dc0b7062269547848333fbb3e710d924ddb1842565064cc9b798a195c4ecd42b8c19601d82418a5feb8b4602d2f03"
        );
    }

    #[test]
    fn c_vector_counter_1() {
        let key = [0xABu8; 32];
        let mut enc = CipherContext::new(key);
        enc.counter = 1; // Skip to counter=1
        let plain: Vec<u8> = (0u8..100).collect();
        let ct = enc.encrypt(&plain).unwrap();
        assert_eq!(
            hex_encode(&ct),
            "640045346fcf726e4b4441b946c3cb11349fa4d76e62ad4def44f687160d02f815a8a68327a66659f0967be92837b3a829734aa74c0301a654fd1756a1867981a4feceb4fa3087ceb2874e583bdbea63e028d71489f412f9581f9c21d5277c0749bbf01c3bd37a6cfbd586ecdf00f187b4beaa07491c"
        );
    }
}
