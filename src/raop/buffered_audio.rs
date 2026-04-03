//! AirPlay 2 buffered audio processor (type 103 streams).
//!
//! Receives encrypted AAC audio over TCP, decrypts with ChaCha20-Poly1305,
//! wraps with ADTS headers, and outputs raw AAC+ADTS frames to the audio handler.
//! Actual AAC→PCM decoding is done downstream (by the audio handler or a future
//! symphonia integration).

use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

use crate::crypto::chacha_transport::CipherContext;
use crate::codec::aac;
use crate::error::NetworkError;

/// RTP-like header at the start of each buffered audio packet (12 bytes).
const BUFFERED_HEADER_LEN: usize = 12;

/// Buffered audio processor that accepts a TCP connection and processes
/// encrypted audio packets.
pub struct BufferedAudioProcessor {
    pub listener: TcpListener,
    pub port: u16,
}

impl BufferedAudioProcessor {
    /// Bind a TCP listener for buffered audio.
    pub async fn bind() -> Result<Self, NetworkError> {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        debug!(port, "Buffered audio listening");
        Ok(Self { listener, port })
    }

    /// Run: accept connection, read encrypted audio, decrypt, extract AAC frames.
    /// Calls `on_audio` for each decoded audio packet (ADTS-wrapped AAC).
    pub async fn run<F>(
        self,
        mut decrypt: CipherContext,
        sample_rate: u32,
        channels: u8,
        mut on_audio: F,
    ) where
        F: FnMut(&[u8], u32, u32), // (audio_data, timestamp, seq_no)
    {
        let (stream, addr) = match self.listener.accept().await {
            Ok(s) => s,
            Err(e) => { warn!("Buffered audio accept failed: {e}"); return; }
        };
        debug!(%addr, "Buffered audio client connected");
        Self::process(stream, &mut decrypt, sample_rate, channels, &mut on_audio).await;
    }

    async fn process<F>(
        mut stream: TcpStream,
        decrypt: &mut CipherContext,
        sample_rate: u32,
        channels: u8,
        on_audio: &mut F,
    ) where
        F: FnMut(&[u8], u32, u32),
    {
        let mut buf = vec![0u8; 64 * 1024];
        let mut encrypted_buf = Vec::new();

        loop {
            match stream.read(&mut buf).await {
                Ok(0) => { debug!("Buffered audio connection closed"); break; }
                Ok(n) => {
                    encrypted_buf.extend_from_slice(&buf[..n]);

                    // Decrypt as many complete blocks as possible
                    match decrypt.decrypt(&encrypted_buf) {
                        Ok((plain, consumed)) => {
                            if consumed > 0 {
                                encrypted_buf.drain(..consumed);
                            }
                            if plain.len() > BUFFERED_HEADER_LEN {
                                // Parse RTP-like header: seq_no (bytes 0-3), timestamp (bytes 4-7)
                                let seq_no = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) & 0x7FFFFF;
                                let timestamp = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]);
                                let payload = &plain[BUFFERED_HEADER_LEN..];

                                // Wrap with ADTS header and deliver
                                let adts_frame = aac::wrap_adts(payload, sample_rate, channels);
                                on_audio(&adts_frame, timestamp, seq_no);
                            }
                        }
                        Err(e) => { warn!("Buffered audio decrypt error: {e}"); break; }
                    }
                }
                Err(e) => { warn!("Buffered audio read error: {e}"); break; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn buffered_processor_binds() {
        let proc = BufferedAudioProcessor::bind().await.unwrap();
        assert!(proc.port > 0);
    }

    #[tokio::test]
    async fn buffered_processor_receives_audio() {
        let proc = BufferedAudioProcessor::bind().await.unwrap();
        let port = proc.port;

        let key = [0x77u8; 32];
        let mut enc = CipherContext::new(key);
        let dec = CipherContext::new(key);

        // Build a fake buffered audio packet: 12-byte header + AAC payload
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x00000001u32.to_be_bytes()); // seq_no = 1
        packet.extend_from_slice(&0x00001000u32.to_be_bytes()); // timestamp
        packet.extend_from_slice(&0x00000000u32.to_be_bytes()); // ssrc
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);   // fake AAC payload

        let encrypted = enc.encrypt(&packet).unwrap();

        use std::sync::{Arc, Mutex};
        let received = Arc::new(Mutex::new(Vec::new()));
        let received2 = received.clone();

        let handle = tokio::spawn(async move {
            proc.run(dec, 44100, 2, move |data, ts, seq| {
                received2.lock().unwrap().push((data.to_vec(), ts, seq));
            }).await;
        });

        // Client sends encrypted audio
        let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        client.write_all(&encrypted).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(client);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

        let frames = received.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1, 0x1000); // timestamp
        assert_eq!(frames[0].2, 1);       // seq_no
        // First 2 bytes should be ADTS sync word
        assert_eq!(&frames[0].0[..2], &[0xFF, 0xF9]);
        // Payload should be at offset 7
        assert_eq!(&frames[0].0[7..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
