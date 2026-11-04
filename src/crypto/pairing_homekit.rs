//! HomeKit pairing (SRP-6a, HKDF-SHA512, Ed25519, ChaCha20-Poly1305).
//!
//! Implements PAIR_SERVER_HOMEKIT for AirPlay 2 pair-setup and pair-verify.

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

use crate::crypto::tlv::{TlvType, TlvValues};
use crate::error::CryptoError;

const USERNAME: &str = "Pair-Setup";
const TRANSIENT_PIN: &str = "3939";
const PAIRING_METHOD_PAIR_SETUP: u8 = 0x00;
const PAIRING_FLAGS_TRANSIENT: u8 = 0x10;
const TLV_ERROR_AUTHENTICATION: u8 = 0x02;

// HKDF salt/info labels reused across the pair-setup and pair-verify handshakes.
const PS_ENCRYPT_SALT: &str = "Pair-Setup-Encrypt-Salt";
const PS_ENCRYPT_INFO: &str = "Pair-Setup-Encrypt-Info";
const PV_ENCRYPT_SALT: &str = "Pair-Verify-Encrypt-Salt";
const PV_ENCRYPT_INFO: &str = "Pair-Verify-Encrypt-Info";

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
pub(crate) struct SrpServer {
    n: BigUint,
    g: BigUint,
    salt: Vec<u8>,
    v: BigUint,
    b: BigUint,
    big_b: BigUint,
    session_key: Vec<u8>,
    m2: Vec<u8>,
    is_transient: bool,
    allow_transient: bool,
    verified: bool,
}

impl SrpServer {
    /// Create a new SRP server for the given PIN.
    ///
    /// `None` keeps the shairport-sync-style transient profile, using the fixed
    /// transient PIN 3939. `Some(pin)` requires normal M1-M6 HomeKit pairing.
    pub(crate) fn new(pin: Option<&str>) -> Result<Self, CryptoError> {
        // Random salt (16 bytes) and random 256-bit private value b.
        let mut salt_bytes = [0u8; 16];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut salt_bytes);
        let mut b_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut b_bytes);
        Self::with_entropy(pin, salt_bytes, b_bytes)
    }

    /// SRP server setup from explicit entropy (salt and private value `b`).
    /// Split from [`SrpServer::new`] so the verifier math has known-answer tests.
    fn with_entropy(
        pin: Option<&str>,
        salt_bytes: [u8; 16],
        b_bytes: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let allow_transient = pin.is_none();
        let pin = pin.unwrap_or(TRANSIENT_PIN);
        let n = BigUint::parse_bytes(N_3072_HEX.as_bytes(), 16)
            .ok_or_else(|| CryptoError::PairingHandshake("Failed to parse N".into()))?;
        let g = BigUint::from(G_3072);

        let salt = BigUint::from_bytes_be(&salt_bytes);

        // x = H(salt || H("Pair-Setup:pin"))
        let x = calculate_x(&salt, USERNAME, pin.as_bytes());

        // v = g^x mod N
        let v = g.modpow(&x, &n);

        // k = H(pad(N) || pad(g))
        let k = h_nn_pad(&n, &g, N_3072_LEN);

        // b = random 256-bit
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
            allow_transient,
            verified: false,
        })
    }

    /// Process M1 from client. Returns (salt, B) for M2 response.
    pub(crate) fn process_m1(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let tlv =
            TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;

        let method = tlv
            .get_type(TlvType::Method)
            .ok_or_else(|| CryptoError::PairingHandshake("Missing Method".into()))?;
        if method != [PAIRING_METHOD_PAIR_SETUP] {
            return Err(CryptoError::PairingHandshake(
                "Unexpected pairing method".into(),
            ));
        }

        self.is_transient = tlv
            .get_type(TlvType::Flags)
            .map(|f| f.len() == 1 && f[0] == PAIRING_FLAGS_TRANSIENT)
            .unwrap_or(false);
        if self.is_transient && !self.allow_transient {
            return Err(CryptoError::PairingHandshake(
                "transient pair-setup is disabled when a PIN is configured".into(),
            ));
        }

        Ok(())
    }

    /// Build M2 response: State=2, Salt, PublicKey(B).
    pub(crate) fn build_m2(&self) -> Vec<u8> {
        let mut tlv = TlvValues::new();
        tlv.add(TlvType::State as u8, &[2]);
        tlv.add(TlvType::Salt as u8, &self.salt);
        let b_bytes = to_bytes_be_padded(&self.big_b, N_3072_LEN);
        tlv.add(TlvType::PublicKey as u8, &b_bytes);
        tlv.encode()
    }

    /// Process M3 from client (PublicKey=A, Proof=M1). Returns true if auth succeeded.
    pub(crate) fn process_m3(&mut self, data: &[u8]) -> Result<bool, CryptoError> {
        let tlv =
            TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;

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

        // Constant-time comparison of the client's SRP proof.
        if !bool::from(proof.ct_eq(expected_m.as_slice())) {
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
    pub(crate) fn build_m4(&self) -> Result<Vec<u8>, CryptoError> {
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
    pub(crate) fn shared_secret(&self) -> Option<&[u8]> {
        if self.verified && self.is_transient {
            Some(&self.session_key)
        } else {
            None
        }
    }

    /// Whether this is a transient (PIN-less) pairing session.
    pub(crate) fn is_transient(&self) -> bool {
        self.is_transient
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
    if b.is_empty() { vec![0] } else { b }
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

fn encrypt_chacha(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from(*nonce_bytes);
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::PairingHandshake("ChaCha20 encrypt failed".into()))
}

fn decrypt_chacha(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from(*nonce_bytes);
    cipher
        .decrypt(&nonce, ciphertext_with_tag)
        .map_err(|_| CryptoError::PairingHandshake("ChaCha20 decrypt failed".into()))
}

/// Build the accessory's long-term Ed25519 identity keypair from a 32-byte secret seed.
///
/// This is the secure path: `seed` must come from a CSPRNG (see
/// [`generate_identity_seed`]) and be persisted across restarts via
/// [`PairingStore::load_identity`]/[`save_identity`]. The resulting verifying key
/// is what gets advertised in the mDNS `pk` record and used to sign pair-setup M6
/// and pair-verify M2.
///
/// [`PairingStore::load_identity`]: crate::raop::PairingStore::load_identity
/// [`save_identity`]: crate::raop::PairingStore::save_identity
pub fn identity_keypair(seed: &[u8; 32]) -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::from_bytes(seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Generate a fresh random 32-byte Ed25519 identity seed from the OS CSPRNG.
pub fn generate_identity_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
    seed
}

/// **INSECURE** — deterministic Ed25519 keypair derived from the public `device_id`
/// (matches the original C `server_keypair`, i.e. libsodium `crypto_sign_seed_keypair`
/// over the zero-padded device id).
///
/// The device id is advertised publicly over mDNS, so the derived private key
/// contains no secret entropy and is trivially reconstructable by anyone on the
/// network — it must not be used as a real accessory identity. Retained only for
/// byte-compatible C interop and golden-vector tests. For a real identity use
/// [`identity_keypair`] seeded from [`generate_identity_seed`] and persist it via
/// [`PairingStore`](crate::raop::PairingStore); to opt back into the legacy
/// behaviour, have `load_identity` return this seed (zero-padded device id).
pub fn server_keypair(device_id: &str) -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; 32];
    let bytes = device_id.as_bytes();
    let len = bytes.len().min(32);
    seed[..len].copy_from_slice(&bytes[..len]);
    identity_keypair(&seed)
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
    pub(crate) fn process_m5(&mut self, data: &[u8]) -> Result<(String, [u8; 32]), CryptoError> {
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
        setup_verify_client_identity(&self.session_key, data)
    }

    /// Build M6 response: encrypted TLV with server identifier, signature, public key.
    ///
    /// `device_id` is the public accessory identifier (placed in the TLV); the
    /// signature is produced with the secret long-term identity key built from
    /// `identity_seed`.
    pub(crate) fn build_m6(
        &self,
        device_id: &str,
        identity_seed: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        setup_build_accessory_identity(&self.session_key, device_id, identity_seed)
    }
}

// --- Pair-Setup M5/M6 identity exchange ---
//
// The HomeKit identity-exchange steps layered on top of the SRP-6a session key:
// M5 verifies the controller's Ed25519 long-term identity, M6 returns the
// accessory's. Split out as pure functions over the session key to keep the
// identity crypto separate from SrpServer's SRP state machine.

/// Verify the controller's encrypted M5 identity TLV.
/// Returns the controller's `(identifier, Ed25519 public key)` for persistent storage.
fn setup_verify_client_identity(
    session_key: &[u8],
    data: &[u8],
) -> Result<(String, [u8; 32]), CryptoError> {
    let inner = decrypt_setup_m5(session_key, data)?;
    let identifier = inner
        .get_type(TlvType::Identifier)
        .ok_or_else(|| CryptoError::PairingHandshake("M5: missing identifier".into()))?;
    let signature = inner
        .get_type(TlvType::Signature)
        .ok_or_else(|| CryptoError::PairingHandshake("M5: missing signature".into()))?;
    let client_pk = inner
        .get_type(TlvType::PublicKey)
        .ok_or_else(|| CryptoError::PairingHandshake("M5: missing public key".into()))?;

    let public_key = verify_controller_identity(session_key, identifier, signature, client_pk)?;
    let identifier = String::from_utf8(identifier.to_vec())
        .map_err(|_| CryptoError::PairingHandshake("M5: invalid identifier encoding".into()))?;
    Ok((identifier, public_key))
}

fn decrypt_setup_m5(session_key: &[u8], data: &[u8]) -> Result<TlvValues, CryptoError> {
    let tlv = TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;
    let enc = tlv
        .get_type(TlvType::EncryptedData)
        .ok_or_else(|| CryptoError::PairingHandshake("M5: missing encrypted data".into()))?;
    let mut derived_key = [0u8; 32];
    hkdf_derive(
        session_key,
        PS_ENCRYPT_SALT,
        PS_ENCRYPT_INFO,
        &mut derived_key,
    )?;
    let nonce = make_nonce(b"PS-Msg05");
    let decrypted = decrypt_chacha(&derived_key, &nonce, enc)?;
    TlvValues::decode(&decrypted).map_err(|e| CryptoError::PairingHandshake(e.to_string()))
}

fn verify_controller_identity(
    session_key: &[u8],
    identifier: &[u8],
    signature: &[u8],
    client_pk: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut device_x = [0u8; 32];
    hkdf_derive(
        session_key,
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
    vk.verify(&info, &sig)
        .map_err(|_| CryptoError::PairingVerify)?;
    Ok(pk_array)
}

/// Build the accessory's encrypted M6 identity TLV, signed with the long-term identity key.
fn setup_build_accessory_identity(
    session_key: &[u8],
    device_id: &str,
    identity_seed: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let (sk, vk) = identity_keypair(identity_seed);

    // Derive signing material
    let mut device_x = [0u8; 32];
    hkdf_derive(
        session_key,
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
        session_key,
        PS_ENCRYPT_SALT,
        PS_ENCRYPT_INFO,
        &mut derived_key,
    )?;
    let nonce = make_nonce(b"PS-Msg06");
    let encrypted = encrypt_chacha(&derived_key, &nonce, &plaintext)?;

    let mut tlv = TlvValues::new();
    tlv.add(TlvType::State as u8, &[6]);
    tlv.add(TlvType::EncryptedData as u8, &encrypted);
    Ok(tlv.encode())
}

/// Lookup function for resolving a client identifier to its stored Ed25519 public key.
pub(crate) type PairingKeyLookup<'a> = Option<&'a dyn Fn(&str) -> Option<[u8; 32]>>;

/// Build a HomeKit pairing error TLV for request handlers.
pub(crate) fn pairing_error_response(state: u8) -> Vec<u8> {
    let mut tlv = TlvValues::new();
    tlv.add(TlvType::State as u8, &[state]);
    tlv.add(TlvType::Error as u8, &[TLV_ERROR_AUTHENTICATION]);
    tlv.encode()
}

// --- Pair-Verify (server side) ---

/// Server-side pair-verify using Curve25519 ECDH + Ed25519 signatures.
pub(crate) struct PairVerifyServer {
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
    ///
    /// `device_id` is the public accessory identifier; M2 is signed with the
    /// secret long-term identity key built from `identity_seed`.
    pub(crate) fn new(device_id: &str, identity_seed: &[u8; 32]) -> Self {
        let (sk, _) = identity_keypair(identity_seed);

        // Generate ephemeral Curve25519 keypair
        let mut eph_sk_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut eph_sk_bytes);
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
    pub(crate) fn process_m1_build_m2(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let tlv =
            TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;
        let client_pk = tlv
            .get_type(TlvType::PublicKey)
            .ok_or_else(|| CryptoError::PairingHandshake("Verify M1: missing public key".into()))?;
        if client_pk.len() != 32 {
            return Err(CryptoError::PairingHandshake(
                "Verify M1: invalid key length".into(),
            ));
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
            PV_ENCRYPT_SALT,
            PV_ENCRYPT_INFO,
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
    /// If `lookup` is `None`, signature verification is skipped for transient sessions.
    /// If a lookup callback is provided, unknown clients fail verification.
    pub(crate) fn process_m3_build_m4(
        &mut self,
        data: &[u8],
        lookup: PairingKeyLookup<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        let tlv =
            TlvValues::decode(data).map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;
        let enc = tlv.get_type(TlvType::EncryptedData).ok_or_else(|| {
            CryptoError::PairingHandshake("Verify M3: missing encrypted data".into())
        })?;

        let mut derived_key = [0u8; 32];
        hkdf_derive(
            &self.shared_secret,
            PV_ENCRYPT_SALT,
            PV_ENCRYPT_INFO,
            &mut derived_key,
        )?;
        let nonce = make_nonce(b"PV-Msg03");
        let decrypted = decrypt_chacha(&derived_key, &nonce, enc)?;

        let inner = TlvValues::decode(&decrypted)
            .map_err(|e| CryptoError::PairingHandshake(e.to_string()))?;
        let identifier = inner
            .get_type(TlvType::Identifier)
            .ok_or_else(|| CryptoError::PairingHandshake("Verify M3: missing identifier".into()))?;
        let signature = inner
            .get_type(TlvType::Signature)
            .ok_or_else(|| CryptoError::PairingHandshake("Verify M3: missing signature".into()))?;

        if let Some(lookup) = lookup {
            let identifier = std::str::from_utf8(identifier).map_err(|_| {
                CryptoError::PairingHandshake("Verify M3: invalid identifier encoding".into())
            })?;
            let ltpk = lookup(identifier).ok_or(CryptoError::PairingVerify)?;
            let mut info = Vec::new();
            info.extend_from_slice(&self.client_eph_pk);
            info.extend_from_slice(identifier.as_bytes());
            info.extend_from_slice(&self.server_eph_pk);

            let vk = VerifyingKey::from_bytes(&ltpk).map_err(|_| {
                CryptoError::PairingHandshake("Verify M3: invalid stored key".into())
            })?;
            let sig = Signature::from_bytes(signature.try_into().map_err(|_| {
                CryptoError::PairingHandshake("Verify M3: invalid signature length".into())
            })?);
            vk.verify(&info, &sig)
                .map_err(|_| CryptoError::PairingVerify)?;
            tracing::info!("Pair-verify: client signature verified");
        } else {
            // No key lookup provided → client signature is NOT verified. This is only
            // safe for transient sessions; the shipped server always passes a real
            // lookup (see handlers_ap2). Warn so an accidental None can't pass silently.
            tracing::warn!(
                "Pair-verify M3: no key lookup — skipping client signature verification"
            );
        }

        self.completed = true;

        let mut resp = TlvValues::new();
        resp.add(TlvType::State as u8, &[4]);
        Ok(resp.encode())
    }

    /// Returns the shared secret derived during pair-verify (for HKDF key derivation).
    pub(crate) fn shared_secret(&self) -> Option<&[u8; 32]> {
        if self.completed {
            Some(&self.shared_secret)
        } else {
            None
        }
    }

    /// Returns the **unauthenticated** Curve25519 ECDH shared secret from M1.
    ///
    /// Exposed before M3 completes specifically for AP2 *video* key derivation,
    /// where it is hashed together with a FairPlay key. It is not authenticated on
    /// its own — never use it directly as a confidential key.
    pub(crate) fn ecdh_shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_pairing_self_test() {
        // Simulate a transient pair-setup between our server and a mock client
        let mut server = SrpServer::new(None).unwrap();

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
        rand::Rng::fill_bytes(&mut rand::rng(), &mut a_bytes);
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

    #[test]
    fn pin_pairing_rejects_transient_flag() {
        let mut server = SrpServer::new(Some("1234")).unwrap();
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[PAIRING_METHOD_PAIR_SETUP]);
        m1.add(TlvType::Flags as u8, &[PAIRING_FLAGS_TRANSIENT]);
        assert!(server.process_m1(&m1.encode()).is_err());
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
        hk.expand(b"Control-Write-Encryption-Key", &mut okm)
            .unwrap();
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
        data.iter().map(|b| format!("{b:02x}")).collect()
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
        rand::Rng::fill_bytes(&mut rand::rng(), &mut a_bytes);
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
        let client_sk = SigningKey::generate(&mut rand::rng());
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
        let m6_data = server.build_m6(device_id, &[0x42u8; 32]).unwrap();
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
        let mut server = PairVerifyServer::new(device_id, &[0x42u8; 32]);

        // Client generates ephemeral key
        let mut client_eph_sk_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut client_eph_sk_bytes);
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
        let server_pub =
            x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(server_eph_pk_bytes).unwrap());
        let client_shared = client_secret.diffie_hellman(&server_pub);

        // Client builds M3 (encrypted identifier + signature)
        let client_id = "ClientDev01";
        let (client_sk, client_vk) = server_keypair(client_id); // reuse helper for test
        let mut sign_info = Vec::new();
        sign_info.extend_from_slice(client_eph_pk.as_bytes());
        sign_info.extend_from_slice(client_id.as_bytes());
        sign_info.extend_from_slice(server_eph_pk_bytes);
        let signature = client_sk.sign(&sign_info);

        let mut inner = TlvValues::new();
        inner.add(TlvType::Identifier as u8, client_id.as_bytes());
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

        let client_pk = *client_vk.as_bytes();
        let lookup = |id: &str| (id == client_id).then_some(client_pk);
        let m4_data = server
            .process_m3_build_m4(&m3.encode(), Some(&lookup))
            .unwrap();
        let m4 = TlvValues::decode(&m4_data).unwrap();
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));

        // Both sides should have the same shared secret
        let server_secret = server.shared_secret().expect("should be completed");
        assert_eq!(server_secret, client_shared.as_bytes());
    }

    #[test]
    fn pair_verify_rejects_unknown_persistent_client() {
        let mut server = PairVerifyServer::new("VerifyDev01", &[0x42u8; 32]);

        let mut client_eph_sk_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut client_eph_sk_bytes);
        let client_secret = x25519_dalek::StaticSecret::from(client_eph_sk_bytes);
        let client_eph_pk = x25519_dalek::PublicKey::from(&client_secret);

        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::PublicKey as u8, client_eph_pk.as_bytes());

        let m2_data = server.process_m1_build_m2(&m1.encode()).unwrap();
        let m2 = TlvValues::decode(&m2_data).unwrap();
        let server_eph_pk_bytes = m2.get_type(TlvType::PublicKey).unwrap();
        let server_pub =
            x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(server_eph_pk_bytes).unwrap());
        let client_shared = client_secret.diffie_hellman(&server_pub);

        let mut inner = TlvValues::new();
        inner.add(TlvType::Identifier as u8, b"UnknownClient");
        inner.add(TlvType::Signature as u8, &[0u8; 64]);

        let mut derived_key = [0u8; 32];
        hkdf_derive(
            client_shared.as_bytes(),
            "Pair-Verify-Encrypt-Salt",
            "Pair-Verify-Encrypt-Info",
            &mut derived_key,
        )
        .unwrap();
        let encrypted =
            encrypt_chacha(&derived_key, &make_nonce(b"PV-Msg03"), &inner.encode()).unwrap();

        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::EncryptedData as u8, &encrypted);

        let lookup = |_id: &str| None;
        let result = server.process_m3_build_m4(&m3.encode(), Some(&lookup));

        assert!(matches!(result, Err(CryptoError::PairingVerify)));
        assert!(server.shared_secret().is_none());
    }

    // --- Known-answer tests pinned before the RustCrypto/dalek/rand migration ---
    //
    // Expected values come from independent computations: Python big-integer
    // arithmetic and hashlib for SRP/HKDF/ChaCha20-Poly1305, OpenSSL for
    // Ed25519/X25519, plus the RFC 8032 and RFC 7748 published vectors.

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const KAT_SALT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const KAT_B: &str = "0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0";
    // Client private value a = f0e1d2c3b4a5968778695a4b3c2d1e0f0123456789abcdeffedcba9876543210
    // (only its public value A below enters the server computation).
    const KAT_BIG_B: &str = "\
5b7f01e012bbcc51c784f8df051b3111752527891081f1f44a53dbd5a21c80d0\
12569949f74f9380cf8d1257c63cc8d9e43ae0eaa2ec947f9f7bcc2d338e7e94\
7a4d964eaf90ca2e75aad3daf0a491be9ed88b749459d3c63a9e690cdd28dd16\
59836671c1a03572c4e716b1c2c39f750f11ddc67222c10a398fe2950b846774\
98c6552630f93a2f8afd6e97d3e504c04f64ed50713dbb0b27920f15c48047ac\
3a9c84c6ccea4a8b3896999bea4ba7093395087301c773ceb8119e76ff23b314\
9b602f6a24269b227da3fc3a2a058453959f575a1677a5e9a418afc9eff17fc5\
2d332c6d8301c5c2e802973e7a0ceb2dbc817aa7a512abe25b5739f965b75141\
33b32b37bcc8297c7df47026b84af86896543dadd3c5ae5938ed1b6a693155ff\
789fc516d9ad0b1b0d59c53fea687c0595e12438d56f7bf10a8394a87d68e58f\
4db59b6dffe946a176e6a6f8fc728d133d4f002a7383723eda5be90fcb44d29f\
a94c1e0ca267b6ff6939852592fdca1b33f1f78a542597f4faebc7593de6a9cf";
    const KAT_BIG_A: &str = "\
059fcd62d5fb921382ae0b9d25ed26d568220b3e5774af2b4ba4dee105bb7b9a\
c59400f3de4998d953b1c1819b7bcf844d63123dcc31597311028c0b817fbf70\
0ace82a3b398c215dbabcb5c2b40fdc0732dbc82b8a02b220380fe73205205bf\
0d5953aba6ae08cf55295befadf80a3a477179b1332a9b76c9a5a181fa074f06\
083a7c33a7da4ebacae1d780da0fe170c0bd5ef6abcf6c6c38bf7a63e22c3299\
faa75a6e245171f895c1e5df48b937a8d8e09e115a8033cf24e336d0ce073e48\
acf7a4d17b06da62d7654a3756ea02a1f4a63fc7c11ec14c122b7f5f7e75a735\
9adba79f6e12f43403e6f9264a22aa4ffafd4d31d197fb7efad405a60d716a18\
416b492018db80d94e909b1304e189d957d98e1ca862b7b2ec4e108bbbaf445c\
85cbdc6966379959e53635cabce42940f2fc79e73a767f6b21c6787d74a127d1\
f126dd202b60f0e738f46c3f9cebb86b250e64fabca09432a74e854d9d359b0b\
7a881ec96a71d1c08ddc320336262cf17312bb102ea0df627fbfbfdfa36be923";
    const KAT_K: &str = "08ca63c5261ea5ce20200d89748dfd66589e7f4e86c50ad4cd669c0df28f37ed6fea7c34969a868980e98068c2f6a39e8b5c3c1bb4e626e1321c5799c23dea1e";
    const KAT_M1: &str = "ada032feb95d1defbb2826baeade5ff9b07bda83b25a622cfac98a829f43b6901ce1b381aecf186b9286f39001daf0500dddb2ae04a784a594b0de32c711e405";
    const KAT_HAMK: &str = "e9920c0d5acd32e793fd660bce75ed2c97f3c71ca899e567825eadb4edb936a6fdbfc53ea37b77547b66f6d75540b47060376e7b1c472a5b68a8cf5f320f751a";

    fn kat_server() -> SrpServer {
        let salt: [u8; 16] = hex_decode(KAT_SALT).try_into().unwrap();
        let b: [u8; 32] = hex_decode(KAT_B).try_into().unwrap();
        SrpServer::with_entropy(None, salt, b).unwrap()
    }

    fn transient_m1() -> Vec<u8> {
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        m1.add(TlvType::Flags as u8, &[PAIRING_FLAGS_TRANSIENT]);
        m1.encode()
    }

    /// Complete SRP-6a transient handshake with fixed salt, `b` and `a`:
    /// B (server public), M1 (client proof), K (session key) and the server
    /// proof M2 must equal the independently computed constants.
    #[test]
    fn srp_transient_known_answer() {
        let mut server = kat_server();
        server.process_m1(&transient_m1()).unwrap();

        let m2 = TlvValues::decode(&server.build_m2()).unwrap();
        assert_eq!(hex_encode(m2.get_type(TlvType::Salt).unwrap()), KAT_SALT);
        assert_eq!(
            hex_encode(m2.get_type(TlvType::PublicKey).unwrap()),
            KAT_BIG_B
        );

        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &hex_decode(KAT_BIG_A));
        m3.add(TlvType::Proof as u8, &hex_decode(KAT_M1));
        assert!(server.process_m3(&m3.encode()).unwrap());

        assert_eq!(hex_encode(server.shared_secret().unwrap()), KAT_K);
        let m4 = TlvValues::decode(&server.build_m4().unwrap()).unwrap();
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));
        assert_eq!(hex_encode(m4.get_type(TlvType::Proof).unwrap()), KAT_HAMK);
    }

    /// Same client keys, one flipped proof bit: authentication must fail and
    /// no shared secret may be exposed.
    #[test]
    fn srp_rejects_flipped_proof_bit() {
        let mut server = kat_server();
        server.process_m1(&transient_m1()).unwrap();
        let mut proof = hex_decode(KAT_M1);
        proof[63] ^= 0x01;
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &hex_decode(KAT_BIG_A));
        m3.add(TlvType::Proof as u8, &proof);
        assert!(!server.process_m3(&m3.encode()).unwrap());
        assert!(server.shared_secret().is_none());
    }

    /// `a = 0` style public values (A mod N == 0) are refused.
    #[test]
    fn srp_rejects_zero_public_value() {
        let mut server = kat_server();
        server.process_m1(&transient_m1()).unwrap();
        let n = hex_decode(N_3072_HEX);
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &n);
        m3.add(TlvType::Proof as u8, &[0u8; 64]);
        assert!(server.process_m3(&m3.encode()).is_err());
    }

    /// Big-number building blocks with leading-zero and size edge cases.
    #[test]
    fn srp_byte_conversions() {
        assert_eq!(to_bytes_be(&BigUint::from(0u32)), vec![0]);
        assert_eq!(to_bytes_be(&BigUint::from(0x0102u32)), vec![1, 2]);
        assert_eq!(
            to_bytes_be_padded(&BigUint::from(0x0102u32), 4),
            vec![0, 0, 1, 2]
        );
        assert_eq!(BigUint::from_bytes_be(&[0, 0, 1, 2]), BigUint::from(258u32));
        let n = BigUint::parse_bytes(N_3072_HEX.as_bytes(), 16).unwrap();
        assert_eq!(n.bits(), 3072);
        assert_eq!(to_bytes_be(&n).len(), N_3072_LEN);
        assert_eq!(
            hex_encode(&to_bytes_be(&n)),
            N_3072_HEX.to_ascii_lowercase()
        );
        // 5^e mod N for a small exponent, checked against Python pow().
        let g = BigUint::from(G_3072);
        assert_eq!(
            g.modpow(&BigUint::from(1000u32), &n) % BigUint::from(1_000_000_007u64),
            BigUint::from(169547125u64)
        );
    }

    /// SHA-512 as used throughout pair-setup (FIPS 180-4 "abc").
    #[test]
    fn sha512_fips_abc() {
        assert_eq!(
            hex_encode(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    /// Ed25519 per RFC 8032 section 7.1 (tests 1 to 3), through the same
    /// `identity_keypair`/`Signer`/`Verifier` API used for pair-setup and verify.
    #[test]
    fn ed25519_rfc8032_vectors() {
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed, pk, msg, sig) in cases {
            let seed: [u8; 32] = hex_decode(seed).try_into().unwrap();
            let msg = hex_decode(msg);
            let (sk, vk) = identity_keypair(&seed);
            assert_eq!(hex_encode(vk.as_bytes()), pk);
            let signature = sk.sign(&msg);
            assert_eq!(hex_encode(&signature.to_bytes()), sig);
            vk.verify(&msg, &signature).unwrap();
            // Verify via a key re-imported from the wire bytes, as the handlers do.
            let vk2 = VerifyingKey::from_bytes(&hex_decode(pk).try_into().unwrap()).unwrap();
            vk2.verify(
                &msg,
                &Signature::from_bytes(&hex_decode(sig).try_into().unwrap()),
            )
            .unwrap();
            // Tampered message and tampered signature are rejected.
            let mut bad_msg = msg.clone();
            bad_msg.push(0);
            assert!(vk.verify(&bad_msg, &signature).is_err());
            let mut bad_sig = signature.to_bytes();
            bad_sig[0] ^= 1;
            assert!(vk.verify(&msg, &Signature::from_bytes(&bad_sig)).is_err());
        }
    }

    /// X25519 per RFC 7748 section 6.1 with the `StaticSecret` API used by pair-verify.
    #[test]
    fn x25519_rfc7748_vectors() {
        let a_sk: [u8; 32] =
            hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .try_into()
                .unwrap();
        let b_sk: [u8; 32] =
            hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .try_into()
                .unwrap();
        let a = x25519_dalek::StaticSecret::from(a_sk);
        let b = x25519_dalek::StaticSecret::from(b_sk);
        let a_pk = x25519_dalek::PublicKey::from(&a);
        let b_pk = x25519_dalek::PublicKey::from(&b);
        assert_eq!(
            hex_encode(a_pk.as_bytes()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex_encode(b_pk.as_bytes()),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(hex_encode(a.diffie_hellman(&b_pk).as_bytes()), expected);
        assert_eq!(hex_encode(b.diffie_hellman(&a_pk).as_bytes()), expected);
    }

    /// Pair-verify/pair-setup AEAD framing: HKDF key plus the 4-zero-byte +
    /// 8-byte-tag nonce and no AAD, as `PV-Msg02`/`PS-Msg05` use it.
    #[test]
    fn homekit_chacha_known_answer() {
        let ikm: Vec<u8> = (0u8..64).collect();
        let mut key = [0u8; 32];
        hkdf_derive(&ikm, PV_ENCRYPT_SALT, PV_ENCRYPT_INFO, &mut key).unwrap();
        assert_eq!(
            hex_encode(&key),
            "8f806335e1847b59c5004b131c4689e951ce9808993aed540856475e0dee353b"
        );

        let plain = b"homekit pair-verify inner TLV payload!!";
        let ct = encrypt_chacha(&key, &make_nonce(b"PV-Msg02"), plain).unwrap();
        assert_eq!(
            hex_encode(&ct),
            "790c31d9cfe8a1a68d235c61609dfe9c114fc77ec626feb0776121013182a8562ef8b556d97c3475e6f4451dc769557442ad48a9e34c41"
        );
        assert_eq!(
            decrypt_chacha(&key, &make_nonce(b"PV-Msg02"), &ct).unwrap(),
            plain
        );

        let ct = encrypt_chacha(&key, &make_nonce(b"PS-Msg05"), plain).unwrap();
        assert_eq!(
            hex_encode(&ct),
            "006fb900a8e0a8086f06e953aac6320624da2fce017988deb5f2ddf1d9cf3ba11d9019d1b0f20216949f52114488619900cef99834d67c"
        );
        // Wrong nonce label must not decrypt.
        assert!(decrypt_chacha(&key, &make_nonce(b"PS-Msg06"), &ct).is_err());
    }

    /// Identity seed generation draws fresh entropy on every call.
    #[test]
    fn identity_seed_is_random() {
        let a = generate_identity_seed();
        let b = generate_identity_seed();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    /// Fresh `SrpServer` instances use fresh salt and `b`.
    #[test]
    fn srp_new_uses_fresh_entropy() {
        let s1 = SrpServer::new(None).unwrap();
        let s2 = SrpServer::new(None).unwrap();
        assert_ne!(s1.salt, s2.salt);
        assert_ne!(s1.big_b, s2.big_b);
        assert_eq!(s1.salt.len(), 16);
    }
}
