//! Ed25519/Curve25519 pair-setup and pair-verify for AP1.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
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
            signing_key: SigningKey::generate(&mut OsRng),
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
    /// Returns the ECDH shared secret (available after handshake).
    pub fn ecdh_secret(&self) -> &[u8; 32] {
        &self.ecdh_secret
    }
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
    pub fn handshake(
        &mut self,
        ecdh_key: &[u8; 32],
        ed_key: &[u8; 32],
    ) -> Result<(), CryptoError> {
        if self.status == Status::Finished {
            return Err(CryptoError::PairingHandshake("already finished".into()));
        }

        let our_secret = StaticSecret::random_from_rng(OsRng);
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
            return Err(CryptoError::PairingHandshake("not in handshake state".into()));
        }
        Ok(self.ecdh_ours)
    }

    /// Get our Ed25519 signature, encrypted with AES-CTR.
    /// Equivalent to pairing_session_get_signature.
    pub fn get_signature(&self) -> Result<[u8; 64], CryptoError> {
        if self.status != Status::Handshake {
            return Err(CryptoError::PairingHandshake("not in handshake state".into()));
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
    pub fn finish(&mut self, signature: &[u8; 64]) -> Result<(), CryptoError> {
        if self.status != Status::Handshake {
            return Err(CryptoError::PairingHandshake("not in handshake state".into()));
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

        let verifying_key = VerifyingKey::from_bytes(&self.ed_theirs)
            .map_err(|_| CryptoError::PairingVerify)?;
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
