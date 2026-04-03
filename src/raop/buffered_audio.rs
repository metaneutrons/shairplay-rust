//! AirPlay 2 buffered audio processor (type 103 streams).
//!
//! Receives audio over TCP with simple length-prefixed framing:
//! `[u16 BE: total_len] [total_len - 2 bytes: RTP header + AAC payload]`
//! The RTP header is 12 bytes (seq_no, timestamp, SSRC).

use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::codec::aac;
use crate::error::NetworkError;

const RTP_HEADER_LEN: usize = 12;

/// Buffered audio processor that accepts a TCP connection and processes audio packets.
pub struct BufferedAudioProcessor {
    pub listener: TcpListener,
    pub port: u16,
}

impl BufferedAudioProcessor {
    pub async fn bind() -> Result<Self, NetworkError> {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        debug!(port, "Buffered audio listening");
        Ok(Self { listener, port })
    }

    /// Run: accept connection, read length-prefixed audio packets.
    pub async fn run<F>(self, sample_rate: u32, channels: u8, mut on_audio: F)
    where
        F: FnMut(&[u8], u32, u32), // (audio_data, timestamp, seq_no)
    {
        let (stream, addr) = match self.listener.accept().await {
            Ok(s) => s,
            Err(e) => { warn!("Buffered audio accept failed: {e}"); return; }
        };
        info!(%addr, "Buffered audio client connected");
        Self::process(stream, sample_rate, channels, &mut on_audio).await;
    }

    async fn process<F>(mut stream: TcpStream, sample_rate: u32, channels: u8, on_audio: &mut F)
    where
        F: FnMut(&[u8], u32, u32),
    {
        let mut len_buf = [0u8; 2];
        loop {
            // Read 2-byte BE length prefix
            if stream.read_exact(&mut len_buf).await.is_err() {
                debug!("Buffered audio connection closed");
                break;
            }
            let total_len = u16::from_be_bytes(len_buf) as usize;
            if total_len < 2 {
                warn!(total_len, "Invalid buffered audio packet length");
                break;
            }
            let data_len = total_len - 2; // length includes the 2-byte length field itself

            // Read the packet data
            let mut packet = vec![0u8; data_len];
            if stream.read_exact(&mut packet).await.is_err() {
                debug!("Buffered audio read incomplete");
                break;
            }

            if packet.len() <= RTP_HEADER_LEN {
                continue;
            }

            // Parse RTP-like header
            let seq_no = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) & 0x7FFFFF;
            let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
            let payload = &packet[RTP_HEADER_LEN..];

            tracing::info!(
                seq_no, timestamp, payload_len = payload.len(),
                rtp_header = ?&packet[..RTP_HEADER_LEN.min(packet.len())],
                first_bytes = ?&payload[..payload.len().min(16)],
                "Buffered audio packet"
            );

            // Wrap with ADTS header
            let adts_frame = aac::wrap_adts(payload, sample_rate, channels);
            on_audio(&adts_frame, timestamp, seq_no);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn buffered_processor_receives_audio() {
        let proc = BufferedAudioProcessor::bind().await.unwrap();
        let port = proc.port;

        // Build a fake buffered audio packet: 12-byte header + AAC payload
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x00800001u32.to_be_bytes()); // marker + seq_no = 1
        packet.extend_from_slice(&0x00001000u32.to_be_bytes()); // timestamp
        packet.extend_from_slice(&0x00000000u32.to_be_bytes()); // ssrc
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);   // fake AAC payload

        // Length prefix: total_len = data_len + 2
        let total_len = (packet.len() + 2) as u16;

        use std::sync::{Arc, Mutex};
        let received = Arc::new(Mutex::new(Vec::new()));
        let received2 = received.clone();

        let handle = tokio::spawn(async move {
            proc.run(44100, 2, move |data, ts, seq| {
                received2.lock().unwrap().push((data.to_vec(), ts, seq));
            }).await;
        });

        let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        client.write_all(&total_len.to_be_bytes()).await.unwrap();
        client.write_all(&packet).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(client);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

        let frames = received.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1, 0x1000); // timestamp
        assert_eq!(&frames[0].0[0..2], &[0xFF, 0xF9]); // ADTS sync
        assert_eq!(&frames[0].0[7..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
