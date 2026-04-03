//! AirPlay 2 buffered audio processor (type 103 streams).
//!
//! Receives encrypted audio over TCP with length-prefixed framing:
//! `[u16 BE: total_len] [total_len - 2 bytes: RTP header + encrypted AAC + nonce]`
//!
//! Each packet is decrypted with ChaCha20-Poly1305 using the `shk` from SETUP.

use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::codec::aac;
use crate::error::NetworkError;

const RTP_HEADER_LEN: usize = 12;
const NONCE_TRAIL_LEN: usize = 8;

pub struct BufferedAudioProcessor {
    pub listener: TcpListener,
    pub port: u16,
}

impl BufferedAudioProcessor {
    pub async fn bind() -> Result<Self, NetworkError> {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    pub async fn run<F>(self, shk: [u8; 32], sample_rate: u32, channels: u8, mut on_audio: F)
    where
        F: FnMut(&[u8], u32, u32),
    {
        let (stream, addr) = match self.listener.accept().await {
            Ok(s) => s,
            Err(e) => { warn!("Buffered audio accept failed: {e}"); return; }
        };
        info!(%addr, "Buffered audio client connected");
        Self::process(stream, &shk, sample_rate, channels, &mut on_audio).await;
    }

    async fn process<F>(
        mut stream: TcpStream, shk: &[u8; 32],
        sample_rate: u32, channels: u8, on_audio: &mut F,
    ) where F: FnMut(&[u8], u32, u32) {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead, Nonce, aead::Payload};

        let cipher = ChaCha20Poly1305::new(shk.into());
        let mut len_buf = [0u8; 2];

        loop {
            if stream.read_exact(&mut len_buf).await.is_err() {
                debug!("Buffered audio connection closed");
                break;
            }
            let total_len = u16::from_be_bytes(len_buf) as usize;
            if total_len < 2 { break; }
            let data_len = total_len - 2;

            let mut packet = vec![0u8; data_len];
            if stream.read_exact(&mut packet).await.is_err() { break; }
            if packet.len() <= RTP_HEADER_LEN + NONCE_TRAIL_LEN { continue; }

            let seq_no = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) & 0x7FFFFF;
            let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

            // Nonce: last 8 bytes, front-padded to 12
            let pkt_len = packet.len();
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&packet[pkt_len - NONCE_TRAIL_LEN..]);

            // AAD: packet[4..12] (timestamp + SSRC)
            let aad = packet[4..12].to_vec();
            // Ciphertext + tag: packet[12..len-8]
            let ciphertext = &packet[RTP_HEADER_LEN..pkt_len - NONCE_TRAIL_LEN];

            match cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad: &aad }) {
                Ok(plaintext) => {
                    let adts_frame = aac::wrap_adts(&plaintext, sample_rate, channels);
                    on_audio(&adts_frame, timestamp, seq_no);
                }
                Err(_) => {
                    debug!(seq_no, "Audio decrypt failed");
                }
            }
        }
    }
}
