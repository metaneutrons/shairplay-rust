//! Ed25519/Curve25519 pair-setup and pair-verify for AP1.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::crypto::aes::AesCtr;
use crate::error::CryptoError;

const SALT_KEY: &[u8] = b"Pair-Verify-AES-Key";
const SALT_IV: &[u8] = b"Pair-Verify-AES-IV";

/// Long-lived pairing identity holding an Ed25519 keypair. Equivalent to pairing_t.
pub struct Pairing {
    signing_key: SigningKey,
}

impl Pairing {
    /// Generate a new random pairing identity. Equivalent to pairing_init_generate.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            signing_key: SigningKey::generate(&mut UnwrapErr(SysRng)),
        })
    }

    /// Create from a known 32-byte seed. Equivalent to pairing_init_seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Get the Ed25519 public key. Equivalent to pairing_get_public_key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Create a new pairing session. Equivalent to pairing_session_init.
    pub fn create_session(&self) -> PairingSession {
        PairingSession {
            status: Status::Initial,
            ed_signing_key: self.signing_key.clone(),
            ed_theirs: [0u8; 32],
            ecdh_ours: [0u8; 32],
            ecdh_theirs: [0u8; 32],
            ecdh_secret: [0u8; 32],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Status {
    Initial,
    Handshake,
    Finished,
}

/// State machine for a single pair-verify handshake. Equivalent to pairing_session_t.
pub struct PairingSession {
    status: Status,
    ed_signing_key: SigningKey,
    ed_theirs: [u8; 32],
    ecdh_ours: [u8; 32],
    ecdh_theirs: [u8; 32],
    ecdh_secret: [u8; 32],
}

impl PairingSession {
    fn derive_key_internal(&self, salt: &[u8], key_len: usize) -> Result<Vec<u8>, CryptoError> {
        if key_len > 64 {
            return Err(CryptoError::PairingHandshake("key_len > 64".into()));
        }
        let mut hasher = Sha512::new();
        hasher.update(salt);
        hasher.update(self.ecdh_secret);
        let hash = hasher.finalize();
        Ok(hash[..key_len].to_vec())
    }

    fn derive_aes(&self) -> Result<(AesCtr, [u8; 16], [u8; 16]), CryptoError> {
        let k = self.derive_key_internal(SALT_KEY, 16)?;
        let i = self.derive_key_internal(SALT_IV, 16)?;
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        key.copy_from_slice(&k);
        iv.copy_from_slice(&i);
        Ok((AesCtr::new(&key, &iv), key, iv))
    }

    /// Perform the ECDH handshake. Equivalent to pairing_session_handshake.
    pub fn handshake(&mut self, ecdh_key: &[u8; 32], ed_key: &[u8; 32]) -> Result<(), CryptoError> {
        if self.status == Status::Finished {
            return Err(CryptoError::PairingHandshake("already finished".into()));
        }

        let our_secret = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let our_public = X25519PublicKey::from(&our_secret);
        let their_public = X25519PublicKey::from(*ecdh_key);
        let shared = our_secret.diffie_hellman(&their_public);

        self.ecdh_theirs = *ecdh_key;
        self.ed_theirs = *ed_key;
        self.ecdh_ours = our_public.to_bytes();
        self.ecdh_secret = *shared.as_bytes();
        self.status = Status::Handshake;
        Ok(())
    }

    /// Get our ECDH public key. Equivalent to pairing_session_get_public_key.
    pub fn get_public_key(&self) -> Result<[u8; 32], CryptoError> {
        if self.status != Status::Handshake {
            return Err(CryptoError::PairingHandshake(
                "not in handshake state".into(),
            ));
        }
        Ok(self.ecdh_ours)
    }

    /// Get our Ed25519 signature, encrypted with AES-CTR.
    /// Equivalent to pairing_session_get_signature.
    pub fn get_signature(&self) -> Result<[u8; 64], CryptoError> {
        if self.status != Status::Handshake {
            return Err(CryptoError::PairingHandshake(
                "not in handshake state".into(),
            ));
        }

        // Sign: ecdh_ours || ecdh_theirs
        let mut sig_msg = [0u8; 64];
        sig_msg[..32].copy_from_slice(&self.ecdh_ours);
        sig_msg[32..].copy_from_slice(&self.ecdh_theirs);
        let signature = self.ed_signing_key.sign(&sig_msg);
        let mut sig_bytes = signature.to_bytes();

        // Encrypt with AES-CTR
        let (mut aes, _, _) = self.derive_aes()?;
        aes.encrypt(&mut sig_bytes);
        Ok(sig_bytes)
    }

    /// Verify the remote's signature. Equivalent to pairing_session_finish.
    pub(crate) fn finish(&mut self, signature: &[u8; 64]) -> Result<(), CryptoError> {
        if self.status != Status::Handshake {
            return Err(CryptoError::PairingHandshake(
                "not in handshake state".into(),
            ));
        }

        let (mut aes, _, _) = self.derive_aes()?;

        // One fake round to advance CTR state (matching C code)
        let mut dummy = [0u8; 64];
        aes.encrypt(&mut dummy);

        // Decrypt the actual signature
        let mut sig_buf = *signature;
        aes.encrypt(&mut sig_buf);

        // Verify: ecdh_theirs || ecdh_ours (reversed from get_signature)
        let mut sig_msg = [0u8; 64];
        sig_msg[..32].copy_from_slice(&self.ecdh_theirs);
        sig_msg[32..].copy_from_slice(&self.ecdh_ours);

        let verifying_key =
            VerifyingKey::from_bytes(&self.ed_theirs).map_err(|_| CryptoError::PairingVerify)?;
        let sig = Signature::from_bytes(&sig_buf);
        verifying_key
            .verify(&sig_msg, &sig)
            .map_err(|_| CryptoError::PairingVerify)?;

        self.status = Status::Finished;
        Ok(())
    }

    /// Derive a key from the shared secret. Equivalent to pairing_session_derive_key.
    pub fn derive_key(&self, salt: &[u8], key_len: usize) -> Result<Vec<u8>, CryptoError> {
        self.derive_key_internal(salt, key_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    fn hex64(s: &str) -> [u8; 64] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    /// Session in handshake state with fixed ECDH material (no randomness).
    fn fixed_session(seed: u8, theirs_ed: Option<&str>) -> PairingSession {
        let mut s = Pairing::from_seed(&[seed; 32]).create_session();
        s.status = Status::Handshake;
        s.ecdh_ours = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        s.ecdh_theirs = hex32("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        s.ecdh_secret = hex32("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        if let Some(k) = theirs_ed {
            s.ed_theirs = hex32(k);
        }
        s
    }

    // Expected values: Python hashlib (SHA-512 key/IV derivation), OpenSSL
    // (Ed25519 signature, AES-128-CTR).

    #[test]
    fn seed_to_public_key_known_answer() {
        let p = Pairing::from_seed(&[0xAA; 32]);
        assert_eq!(
            hex_encode(&p.public_key()),
            "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
        );
    }

    #[test]
    fn key_derivation_known_answer() {
        let s = fixed_session(0xAA, None);
        assert_eq!(
            hex_encode(&s.derive_key(b"Pair-Verify-AES-Key", 16).unwrap()),
            "51aa4800c253bfbef66b2a092d6f5b2a"
        );
        assert_eq!(
            hex_encode(&s.derive_key(b"Pair-Verify-AES-IV", 16).unwrap()),
            "493a1314d424ae8460b5f422a9159eb0"
        );
        assert_eq!(
            hex_encode(&s.derive_key(b"test-salt", 16).unwrap()),
            "2bdce52abcb816e2a64a4c59e98b2e9b"
        );
        assert!(s.derive_key(b"x", 65).is_err());
    }

    /// Server signature `ecdh_ours || ecdh_theirs`, Ed25519-signed and then
    /// AES-CTR-encrypted with the derived key/IV.
    #[test]
    fn get_signature_known_answer() {
        let s = fixed_session(0xAA, None);
        let sig = s.get_signature().unwrap();
        assert_eq!(
            hex_encode(&sig),
            "ead07ce7b4705706d9deddf772c57665f0811340ab3f96332ba356d709a9addaa41ea96e9ebe66e7963be15b189714ac669a0fab8ca075828736de731782d063"
        );

        // Decrypting yields the plain Ed25519 signature, which verifies.
        let (mut aes, _, _) = s.derive_aes().unwrap();
        let mut plain = sig;
        aes.encrypt(&mut plain);
        assert_eq!(
            hex_encode(&plain),
            "0dd4580181f58ff941807f67c49549f7cda492d7042b71f0edb049b49c651be124bd18982458ff4573ed6b7db0ab36193bd0165bf94205586701886ef8f7f106"
        );
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&s.ecdh_ours);
        msg[32..].copy_from_slice(&s.ecdh_theirs);
        VerifyingKey::from_bytes(&hex32(
            "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58",
        ))
        .unwrap()
        .verify(&msg, &Signature::from_bytes(&plain))
        .unwrap();
    }

    /// `finish` accepts the remote's encrypted signature over
    /// `ecdh_theirs || ecdh_ours` and rejects a corrupted one.
    #[test]
    fn finish_known_answer() {
        let mut s = fixed_session(
            0xAA,
            Some("7d59c5623dd40a74aa4d5a32ac645d3b3f95daeae4c22be25476dd6a486f7382"),
        );
        s.finish(&hex64("6480a8b6aacae6dd2e2936bb6dcc1091fd548616b860db79ab17c7cda5b185f3b6e89348649480968dcaa980264ff69a3c4a62191f2636178c116ff9aba2c6d3")).unwrap();
        assert_eq!(s.status, Status::Finished);

        let mut bad = hex64(
            "6480a8b6aacae6dd2e2936bb6dcc1091fd548616b860db79ab17c7cda5b185f3b6e89348649480968dcaa980264ff69a3c4a62191f2636178c116ff9aba2c6d3",
        );
        bad[10] ^= 0x01;
        let mut s = fixed_session(
            0xAA,
            Some("7d59c5623dd40a74aa4d5a32ac645d3b3f95daeae4c22be25476dd6a486f7382"),
        );
        assert!(s.finish(&bad).is_err());
        assert_eq!(s.status, Status::Handshake);

        // Signature from the wrong identity must not verify either.
        let mut s = fixed_session(
            0xAA,
            Some("e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"),
        );
        assert!(s.finish(&hex64("6480a8b6aacae6dd2e2936bb6dcc1091fd548616b860db79ab17c7cda5b185f3b6e89348649480968dcaa980264ff69a3c4a62191f2636178c116ff9aba2c6d3")).is_err());
    }

    /// The real handshake mixes in fresh randomness on every call.
    #[test]
    fn handshake_uses_fresh_ephemeral_keys() {
        let p = Pairing::from_seed(&[0xAA; 32]);
        let mut s1 = p.create_session();
        let mut s2 = p.create_session();
        s1.handshake(&[0x11; 32], &[0x22; 32]).unwrap();
        s2.handshake(&[0x11; 32], &[0x22; 32]).unwrap();
        assert_ne!(s1.ecdh_ours, s2.ecdh_ours);
        assert_ne!(s1.ecdh_secret, s2.ecdh_secret);
    }

    #[test]
    fn generate_gives_distinct_identities() {
        let a = Pairing::generate().unwrap();
        let b = Pairing::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }
}
