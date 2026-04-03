//! Video stream receiver for AirPlay 2 screen mirroring (stream type 110).
//!
//! Accepts a TCP connection, reads 128-byte headers + variable-length payloads,
//! classifies packets, decrypts Payload types, and delivers to VideoSession.

use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::crypto::video_cipher::VideoCipher;
use crate::raop::video::{PacketKind, VideoPacket, VideoSession};

const VIDEO_HEADER_LEN: usize = 128;

/// Run the video stream receiver. Accepts one TCP connection and processes packets.
pub async fn run(
    listener: TcpListener,
    cipher: VideoCipher,
    session: Box<dyn VideoSession>,
) {
    let (stream, addr) = match listener.accept().await {
        Ok(s) => s,
        Err(e) => { warn!("Video stream accept failed: {e}"); return; }
    };
    info!(%addr, "Video stream client connected");
    process(stream, cipher, session).await;
}

async fn process(
    mut stream: TcpStream,
    mut cipher: VideoCipher,
    mut session: Box<dyn VideoSession>,
) {
    let mut header = [0u8; VIDEO_HEADER_LEN];

    loop {
        // Read 128-byte header
        if stream.read_exact(&mut header).await.is_err() {
            debug!("Video stream ended");
            break;
        }

        // Parse header fields (little-endian)
        let payload_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let packet_type = u16::from_le_bytes([header[4], header[5]]);
        let timestamp = u64::from_le_bytes([
            header[8], header[9], header[10], header[11],
            header[12], header[13], header[14], header[15],
        ]);

        if payload_len == 0 {
            continue;
        }

        // Read payload
        let mut payload = BytesMut::zeroed(payload_len);
        if stream.read_exact(&mut payload).await.is_err() {
            debug!("Video stream ended during payload read");
            break;
        }

        // Classify packet
        let kind = match packet_type {
            1 => {
                if payload.len() >= 8 && &payload[4..8] == b"hvc1" {
                    PacketKind::HvcC
                } else {
                    PacketKind::AvcC
                }
            }
            0 | 4096 => PacketKind::Payload,
            5 => PacketKind::Plist,
            other => PacketKind::Other(other),
        };

        // Decrypt payload packets
        if matches!(kind, PacketKind::Payload) {
            cipher.decrypt(&mut payload);
        }

        debug!(?kind, timestamp, payload_len, "Video packet");
        session.on_video(VideoPacket { kind, timestamp, payload });
    }
}
