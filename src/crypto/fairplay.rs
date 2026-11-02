//! FairPlay DRM handshake (fp-setup M1/M2) for AirPlay authentication.
//!
//! The iPhone sends two fp-setup requests:
//! - **M1** (16 bytes): mode selection → server replies with 142-byte pre-computed response
//! - **M2** (164 bytes): key message → server replies with 32-byte header + echo
//!
//! After M2, the server can unwrap the 72-byte AES session key with the key derived
//! from the M2 message.
//!
//! Provenance and licensing: see `docs/fairplay-provenance.md`.
//!
//! The building blocks live in sibling modules: the block ciphers in
//! `fairplay_cipher`, the two digests in `fairplay_digest`, the blender in
//! `fairplay_blender` and the constant tables as binary files in `fairplay_data/`.

use crate::crypto::fairplay_cipher::{Block, RoundKeys, open_message, unwrap_block};
use crate::crypto::fairplay_data::*;
use crate::crypto::fairplay_digest::{add_words, md5_variant, scramble};
use crate::error::CryptoError;

/// Number of handshake modes (reply messages, message keys and IVs).
const MODES: usize = 4;

/// Length of one pre-computed M1 reply.
const REPLY_LEN: usize = 142;

/// FairPlay handshake state machine.
///
/// Holds the 164-byte key message from M2, used to unwrap the AES session key.
pub struct FairPlay {
    keymsg: [u8; 164],
    keymsglen: usize,
}

impl Default for FairPlay {
    fn default() -> Self {
        Self::new()
    }
}

impl FairPlay {
    /// Create a new FairPlay handshake state.
    pub fn new() -> Self {
        Self {
            keymsg: [0u8; 164],
            keymsglen: 0,
        }
    }

    /// Process M1 (mode selection). Returns the 142-byte pre-computed reply.
    pub fn setup(&mut self, request: &[u8; 16]) -> Result<[u8; 142], CryptoError> {
        if request[4] != 0x03 {
            return Err(CryptoError::FairPlay("unsupported version".into()));
        }
        let mode = request[14] as usize;
        if mode >= MODES {
            return Err(CryptoError::FairPlay("invalid mode".into()));
        }
        self.keymsglen = 0;
        let mut reply = [0u8; REPLY_LEN];
        reply.copy_from_slice(&REPLIES[mode * REPLY_LEN..(mode + 1) * REPLY_LEN]);
        Ok(reply)
    }

    /// Process M2 (key message). Stores the key message and returns the 32-byte reply.
    pub fn handshake(&mut self, request: &[u8; 164]) -> Result<[u8; 32], CryptoError> {
        if request[4] != 0x03 {
            return Err(CryptoError::FairPlay("unsupported version".into()));
        }
        // The `mode` byte (offset 12) later selects a key and IV in `open_message`, so
        // reject an out-of-range mode here before storing the key message. Mirrors the
        // M1 mode check in `setup`.
        if request[12] as usize >= MODES {
            return Err(CryptoError::FairPlay("invalid mode".into()));
        }
        self.keymsg.copy_from_slice(request);
        self.keymsglen = 164;
        let mut res = [0u8; 32];
        res[..12].copy_from_slice(&HEADER);
        res[12..].copy_from_slice(&request[144..164]);
        Ok(res)
    }

    /// Unwrap the 72-byte AES session key. Must be called after handshake().
    pub(crate) fn decrypt(&self, input: &[u8; 72]) -> Result<[u8; 16], CryptoError> {
        if self.keymsglen != 164 {
            return Err(CryptoError::FairPlay("handshake not complete".into()));
        }
        Ok(unwrap_key(&self.keymsg, input))
    }
}

/// Unwrap the AES key from the 72-byte wrapped value, using the key message of M2.
fn unwrap_key(message: &[u8; 164], wrapped: &[u8; 72]) -> [u8; 16] {
    let keys = RoundKeys::derive(&session_key(message));

    let mut block: Block = std::array::from_fn(|i| wrapped[56 + i] ^ MASK_Z[i]);
    unwrap_block(&mut block, &keys);

    std::array::from_fn(|i| block[i] ^ wrapped[16 + i] ^ MASK_X[i] ^ MASK_Z[i])
}

/// Derive the 16-byte session key from the key message.
///
/// The opened payload is assembled with fixed parts into five 64-byte blocks. Each
/// block is run through both digests, the second result is added to the first, and
/// the sum becomes the key of the next block.
fn session_key(message: &[u8]) -> [u8; 16] {
    let mut opened = [0u8; 128];
    open_message(message, &mut opened);

    let parts: [&[u8]; 4] = [&STATIC_A, &opened, &SAP_DEFAULT[0x80..0x100], &STATIC_B];
    let mut stream = [0u8; 320];
    let mut at = 0;
    for part in parts {
        stream[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    debug_assert_eq!(at, stream.len());

    let mut key = SESSION_INIT;
    for chunk in stream.as_chunks::<64>().0 {
        key = add_words(&scramble(chunk), &md5_variant(chunk, &key));
    }

    for word in key.as_chunks_mut::<4>().0 {
        word.reverse();
    }
    key.map(|b| b ^ 121)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sample_message() -> [u8; 164] {
        let mut msg = [0x41u8; 164];
        msg[..4].copy_from_slice(b"FPLY");
        msg[4] = 0x03;
        msg[12] = 0x01;
        msg
    }

    #[test]
    fn unwrap_key_vector() {
        let mut wrapped = [0x42u8; 72];
        wrapped[..4].copy_from_slice(b"FPLY");
        assert_eq!(
            to_hex(&unwrap_key(&sample_message(), &wrapped)),
            "51e601d65942f9bd660b57bf98800cdf"
        );
    }

    #[test]
    fn session_key_vector() {
        assert_eq!(
            to_hex(&session_key(&sample_message())),
            "4c8323c42e6b9b50fa961f0039cc90f3"
        );
    }

    #[test]
    fn handshake_rejects_out_of_range_mode() {
        // The M2 `mode` byte (offset 12) selects one of four keys and IVs in
        // `open_message`; an out-of-range value must be rejected at handshake time
        // rather than panicking later when the AES key is unwrapped.
        let mut msg = [0x41u8; 164];
        msg[4] = 0x03;

        let mut fp = FairPlay::new();
        msg[12] = 0x01; // valid mode
        assert!(fp.handshake(&msg).is_ok());

        let mut fp = FairPlay::new();
        msg[12] = 0xff; // out-of-range mode
        assert!(fp.handshake(&msg).is_err());
    }

    #[test]
    fn setup_returns_a_reply_for_every_mode() {
        let mut fp = FairPlay::new();
        for mode in 0..4u8 {
            let mut req = [0u8; 16];
            req[4] = 0x03; // version
            req[14] = mode;
            let res = fp.setup(&req).unwrap();
            assert_eq!(res.len(), 142);
            assert_eq!(&res[..4], b"FPLY");
        }
    }

    #[test]
    fn handshake_echoes_the_trailing_bytes() {
        let mut fp = FairPlay::new();
        let mut req = [0u8; 164];
        req[4] = 0x03;
        for (i, b) in req.iter_mut().enumerate().skip(144) {
            *b = i as u8;
        }
        let res = fp.handshake(&req).unwrap();
        assert_eq!(&res[..4], b"FPLY");
        assert_eq!(&res[12..32], &req[144..164]);
    }

    #[test]
    fn setup_rejects_a_bad_version() {
        let mut fp = FairPlay::new();
        let mut req = [0u8; 16];
        req[4] = 0x02;
        assert!(fp.setup(&req).is_err());
    }
}
