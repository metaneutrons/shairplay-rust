//! HomeKit pairing (SRP-6a, HKDF-SHA512, Ed25519, ChaCha20-Poly1305).
//!
//! Implements PAIR_SERVER_HOMEKIT for AirPlay 2 pair-setup and pair-verify.

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::{Digest, Sha512};

use crate::crypto::tlv::{TlvType, TlvValues};
use crate::error::CryptoError;

const USERNAME: &str = "Pair-Setup";
const TRANSIENT_PIN: &str = "3939";

// RFC 5054 3072-bit group
const N_3072_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B\
139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485\
B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1F\
E649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23\
DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32\
905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF69558\
17183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521\
ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D7\
1E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B1817\
7B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82\
D120A93AD2CAFFFFFFFFFFFFFFFF";
const G_3072: u32 = 5;
const N_3072_LEN: usize = 384; // bytes

/// SRP-6a server state for HomeKit pairing.
pub struct SrpServer {
    n: BigUint,
    g: BigUint,
    salt: Vec<u8>,
    v: BigUint,
    b: BigUint,
    big_b: BigUint,
    session_key: Vec<u8>,
    m2: Vec<u8>,
    is_transient: bool,
    verified: bool,
}

impl SrpServer {
    /// Create a new SRP server for the given PIN.
    pub fn new(pin: Option<&str>) -> Result<Self, CryptoError> {
        let pin = pin.unwrap_or(TRANSIENT_PIN);
        let n = BigUint::parse_bytes(N_3072_HEX.as_bytes(), 16)
            .ok_or_else(|| CryptoError::PairingHandshake("Failed to parse N".into()))?;
        let g = BigUint::from(G_3072);

        // Generate random salt (16 bytes)
        let mut salt_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt_bytes);
        let salt = BigUint::from_bytes_be(&salt_bytes);

        // x = H(salt || H("Pair-Setup:pin"))
        let x = calculate_x(&salt, USERNAME, pin.as_bytes());

        // v = g^x mod N
        let v = g.modpow(&x, &n);

        // k = H(pad(N) || pad(g))
        let k = h_nn_pad(&n, &g, N_3072_LEN);

        // b = random 256-bit
        let mut b_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b_bytes);
        let b = BigUint::from_bytes_be(&b_bytes);

        // B = (k*v + g^b) mod N
        let kv = (&k * &v) % &n;
        let gb = g.modpow(&b, &n);
        let big_b = (kv + gb) % &n;

        Ok(Self {
            n,
            g,
            salt: salt_bytes.to_vec(),
            v,
            b,
            big_b,
            session_key: Vec::new(),
            m2: Vec::new(),
            is_transient: false,
            verified: false,
        })
    }

    /// Process M1 from client. Returns (salt, B) for M2 response.
    pub fn process_m1(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let tlv = TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;

        let method = tlv
            .get_type(TlvType::Method)
            .ok_or_else(|| CryptoError::PairingHandshake("Missing Method".into()))?;
        if method != [0] {
            return Err(CryptoError::PairingHandshake("Unexpected pairing method".into()));
        }

        self.is_transient = tlv
            .get_type(TlvType::Flags)
            .map(|f| f.len() == 1 && f[0] == 0x10)
            .unwrap_or(false);

        Ok(())
    }

    /// Build M2 response: State=2, Salt, PublicKey(B).
    pub fn build_m2(&self) -> Vec<u8> {
        let mut tlv = TlvValues::new();
        tlv.add(TlvType::State as u8, &[2]);
        tlv.add(TlvType::Salt as u8, &self.salt);
        let b_bytes = to_bytes_be_padded(&self.big_b, N_3072_LEN);
        tlv.add(TlvType::PublicKey as u8, &b_bytes);
        tlv.encode()
    }

    /// Process M3 from client (PublicKey=A, Proof=M1). Returns true if auth succeeded.
    pub fn process_m3(&mut self, data: &[u8]) -> Result<bool, CryptoError> {
        let tlv = TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;

        let pk_bytes = tlv
            .get_type(TlvType::PublicKey)
            .ok_or_else(|| CryptoError::PairingHandshake("Missing PublicKey".into()))?;
        let proof = tlv
            .get_type(TlvType::Proof)
            .ok_or_else(|| CryptoError::PairingHandshake("Missing Proof".into()))?;
        if proof.len() != 64 {
            return Err(CryptoError::PairingHandshake("Invalid proof length".into()));
        }

        let big_a = BigUint::from_bytes_be(pk_bytes);

        // Safety check: A mod N != 0
        if (&big_a % &self.n) == BigUint::ZERO {
            return Err(CryptoError::PairingHandshake("A mod N is zero".into()));
        }

        // u = H(pad(A) || pad(B))
        let u = h_nn_pad(&big_a, &self.big_b, N_3072_LEN);

        // S = (A * v^u)^b mod N
        let vu = self.v.modpow(&u, &self.n);
        let avu = (&big_a * &vu) % &self.n;
        let big_s = avu.modpow(&self.b, &self.n);

        // session_key = H(S)
        let s_bytes = to_bytes_be(&big_s);
        self.session_key = sha512(&s_bytes).to_vec();

        // Calculate expected M1
        let salt_bn = BigUint::from_bytes_be(&self.salt);
        let expected_m = calculate_m(
            &self.n,
            &self.g,
            USERNAME,
            &salt_bn,
            &big_a,
            &self.big_b,
            &self.session_key,
        );

        if proof != expected_m.as_slice() {
            self.verified = false;
            return Ok(false);
        }

        // Calculate M2 = H(A || M || session_key)
        self.m2 = calculate_h_amk(&big_a, &expected_m, &self.session_key).to_vec();
        self.verified = true;
        Ok(true)
    }

    /// Build M4 response: State=4, Proof(M2).
    /// For transient pairing, this completes the handshake.
    pub fn build_m4(&self) -> Result<Vec<u8>, CryptoError> {
        if !self.verified {
            // Return auth error TLV
            let mut tlv = TlvValues::new();
            tlv.add(TlvType::State as u8, &[4]);
            tlv.add(TlvType::Error as u8, &[2]); // TLVError_Authentication
            return Ok(tlv.encode());
        }

        let mut tlv = TlvValues::new();
        tlv.add(TlvType::State as u8, &[4]);
        tlv.add(TlvType::Proof as u8, &self.m2);
        Ok(tlv.encode())
    }

    /// Returns the shared secret (SRP session key) after successful transient pairing.
    pub fn shared_secret(&self) -> Option<&[u8]> {
        if self.verified && self.is_transient {
            Some(&self.session_key)
        } else {
            None
        }
    }

    /// Whether this is a transient (PIN-less) pairing session.
    pub fn is_transient(&self) -> bool {
        self.is_transient
    }
    /// Whether pair-verify completed successfully.
    pub fn is_verified(&self) -> bool {
        self.verified
    }
    /// Returns the derived session key (only available after successful pair-verify).
    pub fn session_key(&self) -> Option<&[u8]> {
        if self.verified {
            Some(&self.session_key)
        } else {
            None
        }
    }
}

// --- SRP helper functions ---

fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn to_bytes_be(n: &BigUint) -> Vec<u8> {
    let b = n.to_bytes_be();
    if b.is_empty() {
        vec![0]
    } else {
        b
    }
}

fn to_bytes_be_padded(n: &BigUint, len: usize) -> Vec<u8> {
    let b = n.to_bytes_be();
    if b.len() >= len {
        b
    } else {
        let mut padded = vec![0u8; len - b.len()];
        padded.extend_from_slice(&b);
        padded
    }
}

/// H(pad(n1, padded_len) || pad(n2, padded_len)) → BigUint
fn h_nn_pad(n1: &BigUint, n2: &BigUint, padded_len: usize) -> BigUint {
    let mut buf = Vec::with_capacity(2 * padded_len);
    buf.extend_from_slice(&to_bytes_be_padded(n1, padded_len));
    buf.extend_from_slice(&to_bytes_be_padded(n2, padded_len));
    BigUint::from_bytes_be(&sha512(&buf))
}

/// x = H(salt_bytes || H("username:password"))
fn calculate_x(salt: &BigUint, username: &str, password: &[u8]) -> BigUint {
    // Inner hash: H(username:password)
    let mut hasher = Sha512::new();
    hasher.update(username.as_bytes());
    hasher.update(b":");
    hasher.update(password);
    let ucp_hash = hasher.finalize();

    // H_ns: H(salt_bytes || ucp_hash)
    let salt_bytes = to_bytes_be(salt);
    let mut buf = Vec::with_capacity(salt_bytes.len() + 64);
    buf.extend_from_slice(&salt_bytes);
    buf.extend_from_slice(&ucp_hash);
    BigUint::from_bytes_be(&sha512(&buf))
}

/// M = H(H(N) XOR H(g) || H(username) || salt || A || B || K)
fn calculate_m(
    n: &BigUint,
    g: &BigUint,
    username: &str,
    salt: &BigUint,
    big_a: &BigUint,
    big_b: &BigUint,
    session_key: &[u8],
) -> [u8; 64] {
    let h_n = sha512(&to_bytes_be(n));
    let h_g = sha512(&to_bytes_be(g));
    let mut h_xor = [0u8; 64];
    for i in 0..64 {
        h_xor[i] = h_n[i] ^ h_g[i];
    }
    let h_i = sha512(username.as_bytes());

    let mut hasher = Sha512::new();
    hasher.update(h_xor);
    hasher.update(h_i);
    hasher.update(to_bytes_be(salt));
    hasher.update(to_bytes_be(big_a));
    hasher.update(to_bytes_be(big_b));
    hasher.update(session_key);
    hasher.finalize().into()
}

/// H_AMK = H(A || M || K)
fn calculate_h_amk(big_a: &BigUint, m: &[u8], session_key: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(to_bytes_be(big_a));
    hasher.update(m);
    hasher.update(session_key);
    hasher.finalize().into()
}

// --- HKDF + ChaCha20-Poly1305 helpers ---

fn hkdf_derive(ikm: &[u8], salt: &str, info: &str, out: &mut [u8]) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha512>::new(Some(salt.as_bytes()), ikm);
    hk.expand(info.as_bytes(), out)
        .map_err(|_| CryptoError::PairingHandshake("HKDF expand failed".into()))
}

fn encrypt_chacha(key: &[u8; 32], nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::PairingHandshake("ChaCha20 encrypt failed".into()))
}

fn decrypt_chacha(key: &[u8; 32], nonce_bytes: &[u8; 12], ciphertext_with_tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| CryptoError::PairingHandshake("ChaCha20 decrypt failed".into()))
}

/// Deterministic Ed25519 keypair from device_id (matches C server_keypair).
pub fn server_keypair(device_id: &str) -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; 32];
    let bytes = device_id.as_bytes();
    let len = bytes.len().min(32);
    seed[..len].copy_from_slice(&bytes[..len]);
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn make_nonce(tag: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let len = tag.len().min(8);
    nonce[4..4 + len].copy_from_slice(&tag[..len]);
    nonce
}

// --- Non-transient pair-setup M5/M6 (extends SrpServer) ---

impl SrpServer {
    /// Process M5 from client: encrypted TLV with device identifier, Ed25519 signature, public key.
    /// Returns (identifier, Ed25519 public key) for persistent storage.
    pub fn process_m5(&mut self, data: &[u8]) -> Result<(String, [u8; 32]), CryptoError> {
        if !self.verified {
            return Err(CryptoError::PairingHandshake(
                "M5: pair-setup not verified (M3 must succeed first)".into(),
            ));
        }
        if self.is_transient {
            return Err(CryptoError::PairingHandshake(
                "M5: not allowed for transient pairing".into(),
            ));
        }
        let tlv = TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;

        let enc = tlv
            .get_type(TlvType::EncryptedData)
            .ok_or_else(|| CryptoError::PairingHandshake("M5: missing encrypted data".into()))?;

        let mut derived_key = [0u8; 32];
        hkdf_derive(
            &self.session_key,
            "Pair-Setup-Encrypt-Salt",
            "Pair-Setup-Encrypt-Info",
            &mut derived_key,
        )?;

        let nonce = make_nonce(b"PS-Msg05");
        let decrypted = decrypt_chacha(&derived_key, &nonce, enc)?;

        let inner = TlvValues::decode(&decrypted).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;
        let identifier = inner
            .get_type(TlvType::Identifier)
            .ok_or_else(|| CryptoError::PairingHandshake("M5: missing identifier".into()))?;
        let signature = inner
            .get_type(TlvType::Signature)
            .ok_or_else(|| CryptoError::PairingHandshake("M5: missing signature".into()))?;
        let client_pk = inner
            .get_type(TlvType::PublicKey)
            .ok_or_else(|| CryptoError::PairingHandshake("M5: missing public key".into()))?;

        let mut device_x = [0u8; 32];
        hkdf_derive(
            &self.session_key,
            "Pair-Setup-Controller-Sign-Salt",
            "Pair-Setup-Controller-Sign-Info",
            &mut device_x,
        )?;

        let mut info = Vec::new();
        info.extend_from_slice(&device_x);
        info.extend_from_slice(identifier);
        info.extend_from_slice(client_pk);

        let pk_array: [u8; 32] = client_pk
            .try_into()
            .map_err(|_| CryptoError::PairingHandshake("M5: invalid public key length".into()))?;
        let vk = VerifyingKey::from_bytes(&pk_array)
            .map_err(|_| CryptoError::PairingHandshake("M5: invalid public key".into()))?;
        let sig = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| CryptoError::PairingHandshake("M5: invalid signature length".into()))?,
        );
        vk.verify(&info, &sig).map_err(|_| CryptoError::PairingVerify)?;

        let id_str = String::from_utf8(identifier.to_vec())
            .map_err(|_| CryptoError::PairingHandshake("M5: invalid identifier encoding".into()))?;

        Ok((id_str, pk_array))
    }

    /// Build M6 response: encrypted TLV with server identifier, signature, public key.
    pub fn build_m6(&self, device_id: &str) -> Result<Vec<u8>, CryptoError> {
        let (sk, vk) = server_keypair(device_id);

        // Derive signing material
        let mut device_x = [0u8; 32];
        hkdf_derive(
            &self.session_key,
            "Pair-Setup-Accessory-Sign-Salt",
            "Pair-Setup-Accessory-Sign-Info",
            &mut device_x,
        )?;

        let mut info = Vec::new();
        info.extend_from_slice(&device_x);
        info.extend_from_slice(device_id.as_bytes());
        info.extend_from_slice(vk.as_bytes());

        let signature = sk.sign(&info);

        // Build inner TLV
        let mut inner = TlvValues::new();
        inner.add(TlvType::Identifier as u8, device_id.as_bytes());
        inner.add(TlvType::Signature as u8, &signature.to_bytes());
        inner.add(TlvType::PublicKey as u8, vk.as_bytes());
        let plaintext = inner.encode();

        // Encrypt
        let mut derived_key = [0u8; 32];
        hkdf_derive(
            &self.session_key,
            "Pair-Setup-Encrypt-Salt",
            "Pair-Setup-Encrypt-Info",
            &mut derived_key,
        )?;
        let nonce = make_nonce(b"PS-Msg06");
        let encrypted = encrypt_chacha(&derived_key, &nonce, &plaintext)?;

        let mut tlv = TlvValues::new();
        tlv.add(TlvType::State as u8, &[6]);
        tlv.add(TlvType::EncryptedData as u8, &encrypted);
        Ok(tlv.encode())
    }
}

/// Lookup function for resolving a client identifier to its stored Ed25519 public key.
pub type PairingKeyLookup<'a> = Option<&'a dyn Fn(&str) -> Option<[u8; 32]>>;

// --- Pair-Verify (server side) ---

/// Server-side pair-verify using Curve25519 ECDH + Ed25519 signatures.
pub struct PairVerifyServer {
    device_id: String,
    server_sk: SigningKey,
    server_eph_sk: [u8; 32],
    server_eph_pk: [u8; 32],
    client_eph_pk: [u8; 32],
    shared_secret: [u8; 32],
    completed: bool,
}

impl PairVerifyServer {
    /// Create a new pair-verify server for the given device ID.
    pub fn new(device_id: &str) -> Self {
        let (sk, _) = server_keypair(device_id);

        // Generate ephemeral Curve25519 keypair
        let mut eph_sk_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut eph_sk_bytes);
        let static_secret = x25519_dalek::StaticSecret::from(eph_sk_bytes);
        let eph_pk = x25519_dalek::PublicKey::from(&static_secret);

        Self {
            device_id: device_id.to_string(),
            server_sk: sk,
            server_eph_sk: eph_sk_bytes,
            server_eph_pk: *eph_pk.as_bytes(),
            client_eph_pk: [0u8; 32],
            shared_secret: [0u8; 32],
            completed: false,
        }
    }

    /// Process verify M1 from client (ephemeral public key). Returns M2 response.
    pub fn process_m1_build_m2(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let tlv = TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;
        let client_pk = tlv
            .get_type(TlvType::PublicKey)
            .ok_or_else(|| CryptoError::PairingHandshake("Verify M1: missing public key".into()))?;
        if client_pk.len() != 32 {
            return Err(CryptoError::PairingHandshake("Verify M1: invalid key length".into()));
        }
        self.client_eph_pk.copy_from_slice(client_pk);

        // ECDH shared secret
        let secret = x25519_dalek::StaticSecret::from(self.server_eph_sk);
        let client_pub = x25519_dalek::PublicKey::from(self.client_eph_pk);
        self.shared_secret = *secret.diffie_hellman(&client_pub).as_bytes();

        // Sign: server_eph_pk || device_id || client_eph_pk
        let mut info = Vec::new();
        info.extend_from_slice(&self.server_eph_pk);
        info.extend_from_slice(self.device_id.as_bytes());
        info.extend_from_slice(&self.client_eph_pk);
        let signature = self.server_sk.sign(&info);

        // Build inner TLV
        let mut inner = TlvValues::new();
        inner.add(TlvType::Identifier as u8, self.device_id.as_bytes());
        inner.add(TlvType::Signature as u8, &signature.to_bytes());
        let plaintext = inner.encode();

        // Encrypt with HKDF-derived key
        let mut derived_key = [0u8; 32];
        hkdf_derive(
            &self.shared_secret,
            "Pair-Verify-Encrypt-Salt",
            "Pair-Verify-Encrypt-Info",
            &mut derived_key,
        )?;
        let nonce = make_nonce(b"PV-Msg02");
        let encrypted = encrypt_chacha(&derived_key, &nonce, &plaintext)?;

        // Build response TLV
        let mut resp = TlvValues::new();
        resp.add(TlvType::State as u8, &[2]);
        resp.add(TlvType::PublicKey as u8, &self.server_eph_pk);
        resp.add(TlvType::EncryptedData as u8, &encrypted);
        Ok(resp.encode())
    }

    /// Process verify M3 from client. Returns M4 response and shared secret.
    /// `lookup` resolves a client identifier to its stored Ed25519 public key.
    /// If `lookup` is `None` or returns `None`, signature verification is skipped (transient).
    pub fn process_m3_build_m4(&mut self, data: &[u8], lookup: PairingKeyLookup<'_>) -> Result<Vec<u8>, CryptoError> {
        let tlv = TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;
        let enc = tlv
            .get_type(TlvType::EncryptedData)
            .ok_or_else(|| CryptoError::PairingHandshake("Verify M3: missing encrypted data".into()))?;

        let mut derived_key = [0u8; 32];
        hkdf_derive(
            &self.shared_secret,
            "Pair-Verify-Encrypt-Salt",
            "Pair-Verify-Encrypt-Info",
            &mut derived_key,
        )?;
        let nonce = make_nonce(b"PV-Msg03");
        let decrypted = decrypt_chacha(&derived_key, &nonce, enc)?;

        let inner = TlvValues::decode(&decrypted).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;
        let identifier = inner
            .get_type(TlvType::Identifier)
            .ok_or_else(|| CryptoError::PairingHandshake("Verify M3: missing identifier".into()))?;
        let signature = inner
            .get_type(TlvType::Signature)
            .ok_or_else(|| CryptoError::PairingHandshake("Verify M3: missing signature".into()))?;

        if let Some(ltpk) = lookup.and_then(|f| f(std::str::from_utf8(identifier).unwrap_or(""))) {
            let mut info = Vec::new();
            info.extend_from_slice(&self.client_eph_pk);
            info.extend_from_slice(identifier);
            info.extend_from_slice(&self.server_eph_pk);

            let vk = VerifyingKey::from_bytes(&ltpk)
                .map_err(|_| CryptoError::PairingHandshake("Verify M3: invalid stored key".into()))?;
            let sig = Signature::from_bytes(
                signature
                    .try_into()
                    .map_err(|_| CryptoError::PairingHandshake("Verify M3: invalid signature length".into()))?,
            );
            vk.verify(&info, &sig).map_err(|_| CryptoError::PairingVerify)?;
            tracing::info!("Pair-verify: client signature verified");
        }

        self.completed = true;

        let mut resp = TlvValues::new();
        resp.add(TlvType::State as u8, &[4]);
        Ok(resp.encode())
    }

    /// Returns the shared secret derived during pair-verify (for HKDF key derivation).
    pub fn shared_secret(&self) -> Option<&[u8; 32]> {
        if self.completed {
            Some(&self.shared_secret)
        } else {
            None
        }
    }

    /// Returns the ECDH shared secret computed during M1 processing.
    /// Available before M3 completes — needed for video key derivation.
    pub fn ecdh_shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_pairing_self_test() {
        // Simulate a transient pair-setup between our server and a mock client
        let mut server = SrpServer::new(Some("3939")).unwrap();

        // Client sends M1
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        m1.add(TlvType::Flags as u8, &[0x10]); // transient
        server.process_m1(&m1.encode()).unwrap();
        assert!(server.is_transient());

        // Server builds M2 (salt + B)
        let m2_data = server.build_m2();
        let m2 = TlvValues::decode(&m2_data).unwrap();
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b = m2.get_type(TlvType::PublicKey).unwrap();
        assert_eq!(salt.len(), 16);
        assert!(pk_b.len() <= N_3072_LEN);

        // Mock client: compute A, M1 proof using same SRP math
        let n = BigUint::parse_bytes(N_3072_HEX.as_bytes(), 16).unwrap();
        let g = BigUint::from(G_3072);

        let mut a_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        let big_a = g.modpow(&a, &n);

        let salt_bn = BigUint::from_bytes_be(salt);
        let big_b = BigUint::from_bytes_be(pk_b);

        let k = h_nn_pad(&n, &g, N_3072_LEN);
        let u = h_nn_pad(&big_a, &big_b, N_3072_LEN);
        let x = calculate_x(&salt_bn, USERNAME, b"3939");

        // S = (B - k*g^x)^(a + u*x) mod N
        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        // Handle potential underflow: (B + N - kgx) mod N
        let base = (&big_b + &n - &kgx) % &n;

        let big_s = base.modpow(&(&a + &u * &x), &n);

        let session_key = sha512(&to_bytes_be(&big_s));
        let client_m = calculate_m(&n, &g, USERNAME, &salt_bn, &big_a, &big_b, &session_key);

        // Client sends M3
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        let a_padded = to_bytes_be(&big_a);
        m3.add(TlvType::PublicKey as u8, &a_padded);
        m3.add(TlvType::Proof as u8, &client_m);
        let auth_ok = server.process_m3(&m3.encode()).unwrap();
        assert!(auth_ok, "SRP authentication should succeed");

        // Server builds M4
        let m4_data = server.build_m4().unwrap();
        let m4 = TlvValues::decode(&m4_data).unwrap();
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));
        let server_proof = m4.get_type(TlvType::Proof).unwrap();

        // Client verifies M2 proof
        let expected_hamk = calculate_h_amk(&big_a, &client_m, &session_key);
        assert_eq!(server_proof, &expected_hamk[..]);

        // Shared secret should match
        assert_eq!(server.shared_secret().unwrap(), &session_key[..]);
    }

    /// C-verified: HKDF-SHA512 with known IKM (0x00..0x3f), salt, info.
    /// Generated from OpenSSL EVP_PKEY_HKDF.
    #[test]
    fn c_vector_hkdf_sha512() {
        use hkdf::Hkdf;
        use sha2::Sha512;

        let ikm: Vec<u8> = (0u8..64).collect();

        // Pair-Setup-Encrypt-Salt / Pair-Setup-Encrypt-Info
        let hk = Hkdf::<Sha512>::new(Some(b"Pair-Setup-Encrypt-Salt"), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"Pair-Setup-Encrypt-Info", &mut okm).unwrap();
        assert_eq!(
            hex_encode(&okm),
            "b6335536162d6629e4c0bade85f1b712c85a364bab0dedb25014cfb814489273"
        );

        // Control-Salt / Control-Write-Encryption-Key
        let hk = Hkdf::<Sha512>::new(Some(b"Control-Salt"), &ikm);
        hk.expand(b"Control-Write-Encryption-Key", &mut okm).unwrap();
        assert_eq!(
            hex_encode(&okm),
            "5a6cb19bcbe7d4df2dd8279f39562f7fae2dbf73eb5a4f98849c245c82b2fe96"
        );

        // Control-Salt / Control-Read-Encryption-Key
        let hk = Hkdf::<Sha512>::new(Some(b"Control-Salt"), &ikm);
        hk.expand(b"Control-Read-Encryption-Key", &mut okm).unwrap();
        assert_eq!(
            hex_encode(&okm),
            "c2f56f1912e2fc1f6604fd5bccab619272f687345aa4bce1c3c857421bd3b821"
        );
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Full non-transient pair-setup self-test: SRP → M5/M6 with encrypted Ed25519.
    #[test]
    fn normal_pairing_m5_m6_self_test() {
        let device_id = "TestDevice42";
        let mut server = SrpServer::new(Some("1234")).unwrap();

        // --- SRP rounds (same as transient but with PIN "1234") ---
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        // No Flags → non-transient
        server.process_m1(&m1.encode()).unwrap();
        assert!(!server.is_transient());

        let m2_data = server.build_m2();
        let m2 = TlvValues::decode(&m2_data).unwrap();
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b = m2.get_type(TlvType::PublicKey).unwrap();

        // Mock client SRP
        let n = BigUint::parse_bytes(N_3072_HEX.as_bytes(), 16).unwrap();
        let g = BigUint::from(G_3072);
        let mut a_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        let big_a = g.modpow(&a, &n);
        let salt_bn = BigUint::from_bytes_be(salt);
        let big_b = BigUint::from_bytes_be(pk_b);
        let k = h_nn_pad(&n, &g, N_3072_LEN);
        let u = h_nn_pad(&big_a, &big_b, N_3072_LEN);
        let x = calculate_x(&salt_bn, USERNAME, b"1234");
        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        let base = (&big_b + &n - &kgx) % &n;
        let big_s = base.modpow(&(&a + &u * &x), &n);
        let session_key = sha512(&to_bytes_be(&big_s));
        let client_m = calculate_m(&n, &g, USERNAME, &salt_bn, &big_a, &big_b, &session_key);

        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &to_bytes_be(&big_a));
        m3.add(TlvType::Proof as u8, &client_m);
        assert!(server.process_m3(&m3.encode()).unwrap());

        // Transient would stop here, but non-transient continues to M5/M6
        assert!(server.shared_secret().is_none()); // not transient → no secret yet

        // --- M5: Client sends encrypted device info ---
        let client_sk = SigningKey::generate(&mut rand::thread_rng());
        let client_vk = client_sk.verifying_key();
        let client_device_id = "MockClient01";

        // Derive device_x for signing
        let mut device_x = [0u8; 32];
        hkdf_derive(
            &session_key,
            "Pair-Setup-Controller-Sign-Salt",
            "Pair-Setup-Controller-Sign-Info",
            &mut device_x,
        )
        .unwrap();

        let mut sign_info = Vec::new();
        sign_info.extend_from_slice(&device_x);
        sign_info.extend_from_slice(client_device_id.as_bytes());
        sign_info.extend_from_slice(client_vk.as_bytes());
        let signature = client_sk.sign(&sign_info);

        let mut inner = TlvValues::new();
        inner.add(TlvType::Identifier as u8, client_device_id.as_bytes());
        inner.add(TlvType::Signature as u8, &signature.to_bytes());
        inner.add(TlvType::PublicKey as u8, client_vk.as_bytes());
        let plaintext = inner.encode();

        let mut enc_key = [0u8; 32];
        hkdf_derive(
            &session_key,
            "Pair-Setup-Encrypt-Salt",
            "Pair-Setup-Encrypt-Info",
            &mut enc_key,
        )
        .unwrap();
        let nonce = make_nonce(b"PS-Msg05");
        let encrypted = encrypt_chacha(&enc_key, &nonce, &plaintext).unwrap();

        let mut m5 = TlvValues::new();
        m5.add(TlvType::State as u8, &[5]);
        m5.add(TlvType::EncryptedData as u8, &encrypted);
        server.process_m5(&m5.encode()).unwrap();

        // --- M6: Server responds with its encrypted device info ---
        let m6_data = server.build_m6(device_id).unwrap();
        let m6 = TlvValues::decode(&m6_data).unwrap();
        assert_eq!(m6.get_type(TlvType::State), Some(&[6u8][..]));
        let m6_enc = m6.get_type(TlvType::EncryptedData).unwrap();

        // Client decrypts M6
        let nonce6 = make_nonce(b"PS-Msg06");
        let decrypted = decrypt_chacha(&enc_key, &nonce6, m6_enc).unwrap();
        let m6_inner = TlvValues::decode(&decrypted).unwrap();

        let server_id = m6_inner.get_type(TlvType::Identifier).unwrap();
        let server_sig = m6_inner.get_type(TlvType::Signature).unwrap();
        let server_pk = m6_inner.get_type(TlvType::PublicKey).unwrap();

        assert_eq!(server_id, device_id.as_bytes());
        assert_eq!(server_pk.len(), 32);

        // Verify server signature
        let mut acc_x = [0u8; 32];
        hkdf_derive(
            &session_key,
            "Pair-Setup-Accessory-Sign-Salt",
            "Pair-Setup-Accessory-Sign-Info",
            &mut acc_x,
        )
        .unwrap();
        let mut verify_info = Vec::new();
        verify_info.extend_from_slice(&acc_x);
        verify_info.extend_from_slice(server_id);
        verify_info.extend_from_slice(server_pk);

        let svk = VerifyingKey::from_bytes(server_pk.try_into().unwrap()).unwrap();
        let ssig = Signature::from_bytes(server_sig.try_into().unwrap());
        svk.verify(&verify_info, &ssig)
            .expect("Server M6 signature should verify");
    }

    /// Pair-verify self-test: server + mock client ECDH handshake.
    #[test]
    fn pair_verify_self_test() {
        let device_id = "VerifyDev01";
        let mut server = PairVerifyServer::new(device_id);

        // Client generates ephemeral key
        let mut client_eph_sk_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_eph_sk_bytes);
        let client_secret = x25519_dalek::StaticSecret::from(client_eph_sk_bytes);
        let client_eph_pk = x25519_dalek::PublicKey::from(&client_secret);

        // Client → M1
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::PublicKey as u8, client_eph_pk.as_bytes());

        // Server processes M1, builds M2
        let m2_data = server.process_m1_build_m2(&m1.encode()).unwrap();
        let m2 = TlvValues::decode(&m2_data).unwrap();
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let server_eph_pk_bytes = m2.get_type(TlvType::PublicKey).unwrap();
        assert_eq!(server_eph_pk_bytes.len(), 32);

        // Client computes shared secret
        let server_pub = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(server_eph_pk_bytes).unwrap());
        let client_shared = client_secret.diffie_hellman(&server_pub);

        // Client builds M3 (encrypted identifier + signature)
        let (client_sk, _) = server_keypair("ClientDev01"); // reuse helper for test
        let mut sign_info = Vec::new();
        sign_info.extend_from_slice(client_eph_pk.as_bytes());
        sign_info.extend_from_slice(server_eph_pk_bytes);
        let signature = client_sk.sign(&sign_info);

        let mut inner = TlvValues::new();
        inner.add(TlvType::Identifier as u8, b"ClientDev01");
        inner.add(TlvType::Signature as u8, &signature.to_bytes());
        let plaintext = inner.encode();

        let mut derived_key = [0u8; 32];
        hkdf_derive(
            client_shared.as_bytes(),
            "Pair-Verify-Encrypt-Salt",
            "Pair-Verify-Encrypt-Info",
            &mut derived_key,
        )
        .unwrap();
        let nonce = make_nonce(b"PV-Msg03");
        let encrypted = encrypt_chacha(&derived_key, &nonce, &plaintext).unwrap();

        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::EncryptedData as u8, &encrypted);

        let m4_data = server.process_m3_build_m4(&m3.encode(), None).unwrap();
        let m4 = TlvValues::decode(&m4_data).unwrap();
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));

        // Both sides should have the same shared secret
        let server_secret = server.shared_secret().expect("should be completed");
        assert_eq!(server_secret, client_shared.as_bytes());
    }
}
