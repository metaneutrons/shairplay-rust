//! Shared AP2 RTP audio-pipeline helpers used by the realtime (type 96) and
//! buffered (type 103) receivers — chiefly the ChaCha20-Poly1305 frame decrypt,
//! kept in one place so a fix to this security-sensitive code can't diverge.

use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::Aead, aead::Payload};

/// RTP fixed header length (bytes).
pub(crate) const RTP_HEADER_LEN: usize = 12;
/// Trailing per-packet nonce length appended after the ciphertext (bytes).
pub(crate) const NONCE_TRAIL_LEN: usize = 8;

/// Decrypt an AP2 RTP audio packet (ChaCha20-Poly1305).
///
/// Frame layout: `[RTP header (12 B)] [ciphertext] [nonce tail (8 B)]`. The
/// 12-byte AEAD nonce is `[0; 4] ++ nonce_tail`, the AAD is RTP header bytes
/// `[4..12]`. Returns the plaintext, or `None` if the packet is too short to
/// contain a header + tail or the authentication tag fails.
pub fn decrypt_rtp_chacha(cipher: &ChaCha20Poly1305, packet: &[u8]) -> Option<Vec<u8>> {
    let pkt_len = packet.len();
    if pkt_len <= RTP_HEADER_LEN + NONCE_TRAIL_LEN {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&packet[pkt_len - NONCE_TRAIL_LEN..]);
    let aad = &packet[4..12];
    let ciphertext = &packet[RTP_HEADER_LEN..pkt_len - NONCE_TRAIL_LEN];
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{KeyInit, aead::Aead, aead::Payload};

    fn encrypt_frame(cipher: &ChaCha20Poly1305, header: [u8; 12], nonce_tail: [u8; 8], plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&nonce_tail);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &header[4..12],
                },
            )
            .unwrap();
        let mut pkt = header.to_vec();
        pkt.extend_from_slice(&ct);
        pkt.extend_from_slice(&nonce_tail);
        pkt
    }

    #[test]
    fn decrypt_rtp_chacha_roundtrip() {
        let cipher = ChaCha20Poly1305::new((&[7u8; 32]).into());
        let header = [0x80, 0x60, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
        let pkt = encrypt_frame(&cipher, header, [9u8; 8], b"alac payload bytes");
        assert_eq!(
            decrypt_rtp_chacha(&cipher, &pkt).as_deref(),
            Some(&b"alac payload bytes"[..])
        );
    }

    #[test]
    fn decrypt_rtp_chacha_rejects_short_and_tampered() {
        let cipher = ChaCha20Poly1305::new((&[7u8; 32]).into());
        assert!(decrypt_rtp_chacha(&cipher, &[0u8; RTP_HEADER_LEN + NONCE_TRAIL_LEN]).is_none());
        let header = [0x80, 0x60, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
        let mut pkt = encrypt_frame(&cipher, header, [9u8; 8], b"payload");
        pkt[RTP_HEADER_LEN] ^= 0xff; // corrupt ciphertext → tag fails
        assert!(decrypt_rtp_chacha(&cipher, &pkt).is_none());
    }
}
