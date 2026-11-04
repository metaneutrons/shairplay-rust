//! AP2 screen-mirroring video key derivation (SHA-512 based).
//!
//! Derivation scheme (from SteeBono/airplayreceiver):
//! - `eaesKey   = SHA-512(fairplay_key ‖ ecdh_shared)[0..16]`
//! - `streamKey = SHA-512("AirPlayStreamKey{id}" ‖ seed)[0..16]`
//! - `streamIV  = SHA-512("AirPlayStreamIV{id}"  ‖ seed)[0..16]`
//!
//! where `seed` is either the audio AES key directly (Stage-3 path) or `eaesKey`
//! (full FairPlay + ECDH path). See `AP2-STATUS.md` for the protocol background.

use sha2::{Digest, Sha512};

fn sha512_16(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Derive the intermediate `eaesKey` from the FairPlay-decrypted key and the
/// pair-verify ECDH shared secret: `SHA-512(fairplay_key ‖ ecdh)[0..16]`.
pub(crate) fn derive_eaes_key(fairplay_key: &[u8; 16], ecdh_shared: &[u8; 32]) -> [u8; 16] {
    sha512_16(&[fairplay_key, ecdh_shared])
}

/// Derive the per-stream `(key, iv)` for a video stream from a 16-byte `seed`
/// (either the audio AES key or [`derive_eaes_key`]) and the stream connection id.
pub(crate) fn derive_stream_key_iv(
    seed: &[u8; 16],
    stream_connection_id: u64,
) -> ([u8; 16], [u8; 16]) {
    let key = sha512_16(&[
        format!("AirPlayStreamKey{stream_connection_id}").as_bytes(),
        seed,
    ]);
    let iv = sha512_16(&[
        format!("AirPlayStreamIV{stream_connection_id}").as_bytes(),
        seed,
    ]);
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn eaes_key_known_answer() {
        let fp: [u8; 16] = std::array::from_fn(|i| i as u8);
        let ecdh: [u8; 32] = std::array::from_fn(|i| 100 + i as u8);
        assert_eq!(
            hex_encode(&derive_eaes_key(&fp, &ecdh)),
            "8bb46dd24d1d37bfbad9ccd07edb7828"
        );
    }

    #[test]
    fn stream_key_iv_known_answer() {
        let seed: [u8; 16] = std::array::from_fn(|i| i as u8);
        let (key, iv) = derive_stream_key_iv(&seed, 1_234_567_890);
        assert_eq!(hex_encode(&key), "69d267de5cd56e2d2cda2f2d9fc1d5d5");
        assert_eq!(hex_encode(&iv), "ebb81481e427947b5298263fda24fcb9");
        // A different connection id yields different material.
        let (key2, iv2) = derive_stream_key_iv(&seed, 1_234_567_891);
        assert_ne!(key, key2);
        assert_ne!(iv, iv2);
    }
}
