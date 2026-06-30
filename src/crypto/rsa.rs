//! RSA key handling for the well-known AirPort Express private key.

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::PrehashSigner;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey};

use base64::Engine as _;

use crate::error::CryptoError;

/// Standard-alphabet base64 used by RAOP: unpadded on encode, and padding-indifferent
/// plus trailing-bit-lenient on decode — matching the original RTSP base64 behaviour
/// (accepts both padded and unpadded peer input).
const B64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// RSA key for RAOP authentication. Equivalent to rsakey_t.
pub(crate) struct RsaKey {
    key: RsaPrivateKey,
}

impl RsaKey {
    /// Load an RSA private key from a PEM string. Equivalent to rsakey_init_pem.
    pub(crate) fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        let key = RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| CryptoError::RsaKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Sign an Apple-Challenge for the `Apple-Response` RAOP auth header.
    /// Equivalent to rsakey_sign.
    ///
    /// The signed payload is `challenge ‖ ip_addr ‖ hw_addr` — the base64-decoded
    /// challenge, then the receiver's IP address, then its hardware (MAC) address,
    /// concatenated in exactly that order and zero-padded to a minimum of 32 bytes.
    /// The client reconstructs the same byte layout to validate the response, so the
    /// field order and padding must match the AirPort/shairport reference exactly.
    /// Signed with PKCS#1 v1.5 (type 1 padding, no hash-OID prefix); returns the
    /// base64-encoded signature.
    pub(crate) fn sign_challenge(
        &self,
        b64_challenge: &str,
        ip_addr: &[u8],
        hw_addr: &[u8],
    ) -> Result<String, CryptoError> {
        let challenge = B64
            .decode(b64_challenge)
            .map_err(|_| CryptoError::RsaKey("invalid base64 challenge".into()))?;

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

        Ok(B64.encode(signature.to_vec()))
    }

    /// Base64-decode and RSA-OAEP-decrypt (SHA-1) to extract an AES key.
    /// Equivalent to rsakey_decrypt.
    pub(crate) fn decrypt(&self, b64_input: &str) -> Result<Vec<u8>, CryptoError> {
        let ciphertext = B64.decode(b64_input).map_err(|_| CryptoError::RsaDecrypt)?;

        let key_len = self.key.n().bits() / 8;
        // Reject ciphertext larger than the modulus: it cannot be a valid RSA
        // block, and copying it into the modulus-sized buffer below would panic.
        if ciphertext.len() > key_len {
            return Err(CryptoError::RsaDecrypt);
        }
        // Pad ciphertext to key length (matching C: memcpy to end of buffer)
        let mut padded = vec![0u8; key_len];
        let offset = key_len.saturating_sub(ciphertext.len());
        padded[offset..offset + ciphertext.len()].copy_from_slice(&ciphertext);

        let padding = Oaep::new::<sha1::Sha1>();
        self.key.decrypt(padding, &padded).map_err(|_| CryptoError::RsaDecrypt)
    }

    /// Base64-decode only (no decryption). Equivalent to rsakey_decode.
    pub(crate) fn decode(&self, b64_input: &str) -> Result<Vec<u8>, CryptoError> {
        B64.decode(b64_input)
            .map_err(|_| CryptoError::RsaKey("invalid base64 input".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AIRPORT_KEY: &str = include_str!("../../airport.key");

    #[test]
    fn decrypt_rejects_oversized_ciphertext() {
        let key = RsaKey::from_pem(AIRPORT_KEY).expect("airport.key valid");
        // 1024 base64 chars decode to 768 bytes, far larger than the 256-byte
        // RSA-2048 modulus. Must return Err rather than panic copying into the
        // modulus-sized buffer.
        let oversized = "A".repeat(1024);
        assert!(key.decrypt(&oversized).is_err());
    }

    // --- base64 engine parity (was src/util/base64.rs, C base64_encode/decode vectors) ---

    #[test]
    fn b64_encode_is_unpadded_standard() {
        assert_eq!(B64.encode(b"Hello, AirPlay!"), "SGVsbG8sIEFpclBsYXkh");
        assert_eq!(B64.encode(b"AB"), "QUI"); // unpadded (C: use_padding = false)
        assert_eq!(B64.encode(b"ABC"), "QUJD");
        assert_eq!(B64.encode([0xff]), "/w");
        assert_eq!(B64.encode(b""), "");
    }

    #[test]
    fn b64_decode_is_padding_indifferent() {
        assert_eq!(B64.decode("SGVsbG8sIEFpclBsYXkh").unwrap(), b"Hello, AirPlay!");
        // Accepts both unpadded and padded forms of the same input.
        assert_eq!(B64.decode("QUI").unwrap(), b"AB");
        assert_eq!(B64.decode("QUI=").unwrap(), b"AB");
    }

    #[test]
    fn b64_decode_rejects_invalid() {
        assert!(B64.decode("!!!").is_err());
    }
}
