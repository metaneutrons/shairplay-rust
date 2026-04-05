//! RSA key handling for the well-known AirPort Express private key.

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::PrehashSigner;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey};

use crate::error::CryptoError;
use crate::util::base64::Base64;

/// RSA key for RAOP authentication. Equivalent to rsakey_t.
pub struct RsaKey {
    key: RsaPrivateKey,
    base64: Base64,
}

impl RsaKey {
    /// Load an RSA private key from a PEM string. Equivalent to rsakey_init_pem.
    pub fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        let key = RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| CryptoError::RsaKey(e.to_string()))?;
        Ok(Self {
            key,
            base64: Base64::new(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                false,
                false,
            ),
        })
    }

    /// Sign an Apple challenge-response. Equivalent to rsakey_sign.
    ///
    /// Constructs: challenge_bytes || ip_addr || hw_addr (min 32 bytes),
    /// signs with PKCS#1 v1.5 type 1 padding (no hash OID prefix),
    /// returns base64-encoded signature.
    pub fn sign_challenge(&self, b64_challenge: &str, ip_addr: &[u8], hw_addr: &[u8]) -> Result<String, CryptoError> {
        let challenge = self
            .base64
            .decode(b64_challenge)
            .ok_or_else(|| CryptoError::RsaKey("invalid base64 challenge".into()))?;

        // Build the data to sign: challenge + ip + hwaddr, min 32 bytes
        let mut data = Vec::with_capacity(32);
        data.extend_from_slice(&challenge);
        data.extend_from_slice(ip_addr);
        data.extend_from_slice(hw_addr);
        // Pad with zeros to minimum 32 bytes (matching C behavior)
        if data.len() < 32 {
            data.resize(32, 0);
        }

        // PKCS#1 v1.5 sign without hash OID prefix (matching C's manual padding)
        let signing_key: SigningKey<sha1::Sha1> = SigningKey::new_unprefixed(self.key.clone());
        let signature = signing_key
            .sign_prehash(&data)
            .map_err(|e| CryptoError::RsaKey(e.to_string()))?;

        Ok(self.base64.encode(&signature.to_vec()))
    }

    /// Base64-decode and RSA-OAEP-decrypt (SHA-1) to extract an AES key.
    /// Equivalent to rsakey_decrypt.
    pub fn decrypt(&self, b64_input: &str) -> Result<Vec<u8>, CryptoError> {
        let ciphertext = self.base64.decode(b64_input).ok_or(CryptoError::RsaDecrypt)?;

        let key_len = self.key.n().bits() / 8;
        // Pad ciphertext to key length (matching C: memcpy to end of buffer)
        let mut padded = vec![0u8; key_len];
        let offset = key_len.saturating_sub(ciphertext.len());
        padded[offset..offset + ciphertext.len()].copy_from_slice(&ciphertext);

        let padding = Oaep::new::<sha1::Sha1>();
        self.key.decrypt(padding, &padded).map_err(|_| CryptoError::RsaDecrypt)
    }

    /// Base64-decode only (no decryption). Equivalent to rsakey_decode.
    pub fn decode(&self, b64_input: &str) -> Result<Vec<u8>, CryptoError> {
        self.base64
            .decode(b64_input)
            .ok_or_else(|| CryptoError::RsaKey("invalid base64 input".into()))
    }
}
