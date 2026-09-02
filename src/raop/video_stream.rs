//! Video stream receiver for AirPlay 2 screen mirroring (stream type 110).
//!
//! Accepts a TCP connection, reads 128-byte headers + variable-length payloads,
//! classifies packets, decrypts Payload types, and delivers to VideoSession.

use std::time::Duration;

use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, trace, warn};

use crate::crypto::video_cipher::VideoCipher;
use crate::raop::video::{PacketKind, VideoPacket, VideoSession};

const VIDEO_HEADER_LEN: usize = 128;
const MAX_VIDEO_PAYLOAD_LEN: usize = 32 * 1024 * 1024;
/// Drop a video connection whose peer stalls mid-read, freeing the task and port.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct VideoHeader {
    payload_len: usize,
    packet_type: u16,
    timestamp: u64,
}

fn parse_header(header: &[u8; VIDEO_HEADER_LEN]) -> VideoHeader {
    VideoHeader {
        payload_len: u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize,
        packet_type: u16::from_le_bytes([header[4], header[5]]),
        timestamp: u64::from_le_bytes([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15],
        ]),
    }
}

fn classify_packet(packet_type: u16, payload: &[u8]) -> PacketKind {
    match packet_type {
        1 if payload.len() >= 8 && &payload[4..8] == b"hvc1" => PacketKind::HvcC,
        1 => PacketKind::AvcC,
        0 | 4096 => PacketKind::Payload,
        5 => PacketKind::Plist,
        other => PacketKind::Other(other),
    }
}

async fn read_with_timeout(stream: &mut TcpStream, buffer: &mut [u8], part: &str) -> bool {
    match tokio::time::timeout(READ_TIMEOUT, stream.read_exact(buffer)).await {
        Ok(Ok(_)) => true,
        Ok(Err(_)) => {
            debug!(part, "Video stream ended during read");
            false
        }
        Err(_) => {
            debug!(part, "Video stream read timed out");
            false
        }
    }
}

/// Run the video stream receiver. Accepts one TCP connection and processes packets.
pub(crate) async fn run(
    listener: TcpListener,
    cipher: VideoCipher,
    session: Box<dyn VideoSession>,
) {
    let (stream, addr) = match listener.accept().await {
        Ok(s) => s,
        Err(e) => {
            warn!("Video stream accept failed: {e}");
            return;
        }
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
        if !read_with_timeout(&mut stream, &mut header, "header").await {
            break;
        }
        let metadata = parse_header(&header);
        if metadata.payload_len == 0 {
            continue;
        }
        if metadata.payload_len > MAX_VIDEO_PAYLOAD_LEN {
            warn!(
                payload_len = metadata.payload_len,
                "Video payload exceeds maximum allowed size"
            );
            break;
        }

        let mut payload = BytesMut::zeroed(metadata.payload_len);
        if !read_with_timeout(&mut stream, &mut payload, "payload").await {
            break;
        }
        let kind = classify_packet(metadata.packet_type, &payload);
        if matches!(kind, PacketKind::Payload) {
            cipher.decrypt(&mut payload);
        }

        trace!(
            ?kind,
            timestamp = metadata.timestamp,
            payload_len = metadata.payload_len,
            "Video packet"
        );
        session.on_video(VideoPacket {
            kind,
            timestamp: metadata.timestamp,
            payload: payload.freeze(),
        });
    }
    session.on_video_end();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_little_endian_header_fields() {
        let mut header = [0u8; VIDEO_HEADER_LEN];
        header[..4].copy_from_slice(&0x1234_u32.to_le_bytes());
        header[4..6].copy_from_slice(&0x5678_u16.to_le_bytes());
        header[8..16].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());

        let parsed = parse_header(&header);
        assert_eq!(parsed.payload_len, 0x1234);
        assert_eq!(parsed.packet_type, 0x5678);
        assert_eq!(parsed.timestamp, 0x0102_0304_0506_0708);
    }

    #[test]
    fn classifies_supported_packet_types() {
        assert_eq!(classify_packet(1, b"....hvc1"), PacketKind::HvcC);
        assert_eq!(classify_packet(1, b"short"), PacketKind::AvcC);
        assert_eq!(classify_packet(0, b""), PacketKind::Payload);
        assert_eq!(classify_packet(4096, b""), PacketKind::Payload);
        assert_eq!(classify_packet(5, b""), PacketKind::Plist);
        assert_eq!(classify_packet(42, b""), PacketKind::Other(42));
    }
}
