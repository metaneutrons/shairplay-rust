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
        let key =
            RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| CryptoError::RsaKey(e.to_string()))?;
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
        self.key
            .decrypt(padding, &padded)
            .map_err(|_| CryptoError::RsaDecrypt)
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
        assert_eq!(
            B64.decode("SGVsbG8sIEFpclBsYXkh").unwrap(),
            b"Hello, AirPlay!"
        );
        // Accepts both unpadded and padded forms of the same input.
        assert_eq!(B64.decode("QUI").unwrap(), b"AB");
        assert_eq!(B64.decode("QUI=").unwrap(), b"AB");
    }

    #[test]
    fn b64_decode_rejects_invalid() {
        assert!(B64.decode("!!!").is_err());
    }

    /// SHA-1 (FIPS 180-4 "abc") as used for the OAEP label hash and MGF1.
    #[test]
    fn sha1_fips_abc() {
        use sha1::Digest as _;
        let digest = sha1::Sha1::digest(b"abc");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    // --- RSA known-answer tests (OpenSSL-generated with the same airport.key) ---

    const KAT_CHALLENGE_B64: &str = "AAECAwQFBgcICQoLDA0ODw";
    const KAT_SIGNATURE_B64: &str = "OXD+/WO+hbuelKU8d2/wqWVaNgfYM3sAH7EsteIB0e1A+HYj0NxdjGwVCqD8v4ujCQIGK5MlRQR99dNKbwgCEJYSoCv+MdiSX2xa8QDrSsLzq5fyBcdSH75RcPuMnqW3e9mtuNkR9S0KImOnNitDO7yNVkSnC5Q7RQnC9/mhjKfqKYh+Dw1iwpep1sIyQfGdS419Z5rKkv1+RrVz+LjqhQXv5PdUDgttVZrtvpHIPtxNxZUQx620dWh95Kw71xyJ4m+0TCHthwsPheWc++KJ8Hprx51PUlYhxaqET4c9dajtrauqgt7C/JqcqhpE2ytPcUWEJBBWqP/VNI6feu7utQ";
    /// OAEP(SHA-1, MGF1-SHA-1) ciphertext of bytes 0x10..0x20 (padded Base64).
    const KAT_OAEP_B64: &str = "K+UepOxpNCNNolPusSm7jqDnURX28G//G4Z6mpg+OnLtLXk0ASdcqgaElkxkZR5io6CI90bDqAukzcxJ4UMKbyuz+ht6uQZO5g4qUpkkgwHLzgctRhg/Fz6fbFRzNnYjweA9MNEZ7KK16Ew0/pxKrVjAiWxnol0DD480zyCpvir+ptlPVR8FdKxcXIe1fi9pfap1T+rdUgD42IB5zlcBUFWM+wjRTqkVLiVWeb1JCoEUsk4BZE1eRDQn2MB/5ok+/yid5wyXDMaChq0hJABJg51D7tIbaZeLE8QRBQFh5HinPK8pXxSs+T/PoQtvvyVOVc4Z9EMCB2cdF7yTZ8+32w==";

    /// PKCS#1 v1.5 (type 1, no DigestInfo) signing is deterministic, so the
    /// whole `Apple-Response` must match OpenSSL byte for byte.
    #[test]
    fn sign_challenge_known_answer() {
        let key = RsaKey::from_pem(AIRPORT_KEY).unwrap();
        let sig = key
            .sign_challenge(
                KAT_CHALLENGE_B64,
                &[192, 168, 1, 50],
                &[0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22],
            )
            .unwrap();
        assert_eq!(sig, KAT_SIGNATURE_B64);
        // The padded Base64 form of the challenge is accepted as well.
        let sig2 = key
            .sign_challenge(
                "AAECAwQFBgcICQoLDA0ODw==",
                &[192, 168, 1, 50],
                &[0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22],
            )
            .unwrap();
        assert_eq!(sig2, sig);
        // Payloads under 32 bytes are zero-padded: 00 01 02 + 29 zero bytes signs identically.
        let short = key.sign_challenge("AAEC", &[], &[]).unwrap();
        let explicit = key
            .sign_challenge("AAECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &[], &[])
            .unwrap();
        assert_eq!(short, explicit);
        assert_eq!(short.len(), 342); // 256-byte signature, unpadded Base64
        assert!(key.sign_challenge("!!!", &[], &[]).is_err());
    }

    /// RSA-OAEP with SHA-1 (label hash and MGF1) must open an OpenSSL ciphertext,
    /// with padded or unpadded Base64.
    #[test]
    fn decrypt_oaep_sha1_known_answer() {
        let key = RsaKey::from_pem(AIRPORT_KEY).unwrap();
        let expected: Vec<u8> = (0x10u8..0x20).collect();
        assert_eq!(key.decrypt(KAT_OAEP_B64).unwrap(), expected);
        assert_eq!(
            key.decrypt(KAT_OAEP_B64.trim_end_matches('=')).unwrap(),
            expected
        );
        // A flipped ciphertext bit must be rejected, not decrypted to garbage.
        let mut raw = key.decode(KAT_OAEP_B64).unwrap();
        raw[100] ^= 0x01;
        assert!(key.decrypt(&B64.encode(raw)).is_err());
    }

    /// Trailing non-zero bits in the last Base64 symbol are tolerated on decode
    /// (peers send such input), while garbage is still rejected. The URL-safe
    /// alphabet is not part of RAOP and stays rejected.
    #[test]
    fn b64_decode_lenient_trailing_bits_but_standard_alphabet_only() {
        assert_eq!(B64.decode("QUJ").unwrap(), b"AB"); // 'J' carries non-zero trailing bits
        assert_eq!(B64.decode("QUJD").unwrap(), b"ABC");
        assert_eq!(B64.decode("/w").unwrap(), [0xff]);
        assert_eq!(B64.decode("/w==").unwrap(), [0xff]);
        assert!(B64.decode("_w").is_err());
        assert!(B64.decode("-w").is_err());
        assert!(B64.decode("QU=I").is_err());
        // Encode is unpadded standard alphabet with '+' and '/'.
        assert_eq!(B64.encode([0xfb, 0xff, 0xbe]), "+/++");
        assert_eq!(B64.encode([0xfb]), "+w");
    }
}
