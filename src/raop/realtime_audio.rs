//! Realtime ALAC audio receiver (stream type 96).
//!
//! Receives UDP packets with RTP headers, decrypts with ChaCha20-Poly1305,
//! decodes ALAC, resamples/mixes down, and delivers F32LE PCM immediately.

use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead, Nonce, aead::Payload};

use crate::codec::resample::StreamResampler;
use crate::raop::{AudioHandler, AudioFormat, AudioCodec};

const RTP_HEADER_LEN: usize = 12;
const NONCE_TRAIL_LEN: usize = 8;

/// Output configuration for resampling/mixdown.
pub struct OutputConfig {
    pub sample_rate: Option<u32>,
    pub max_channels: Option<u8>,
}

/// Run the realtime audio receiver loop.
pub async fn run(
    socket: UdpSocket,
    shk: [u8; 32],
    handler: Arc<dyn AudioHandler>,
    output_config: OutputConfig,
) {
    let cipher = ChaCha20Poly1305::new((&shk).into());
    let mut buf = vec![0u8; 4096];
    let mut decoder: Option<crate::codec::alac::AlacDecoder> = None;
    let mut resampler: Option<StreamResampler> = None;
    let mut session: Option<Box<dyn crate::raop::AudioSession>> = None;
    #[allow(unused_assignments)]
    let mut src_sr: u32 = 44100;
    let mut src_ch: u8 = 2;
    let mut out_ch: u8 = 2;

    info!("Realtime ALAC receiver started");

    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => { warn!("Realtime audio recv error: {e}"); break; }
        };

        let packet = &buf[..n];
        if packet.len() <= RTP_HEADER_LEN + NONCE_TRAIL_LEN { continue; }

        // Lazy init decoder + session on first packet
        if session.is_none() {
            src_sr = 44100;
            src_ch = 2;
            let target_sr = output_config.sample_rate.unwrap_or(src_sr);
            out_ch = output_config.max_channels.map(|m| src_ch.min(m)).unwrap_or(src_ch);

            decoder = Some(crate::codec::alac::AlacDecoder::new(16, src_ch as i32));
            if target_sr != src_sr {
                resampler = StreamResampler::new(src_sr, target_sr, out_ch as usize);
            }

            let format = AudioFormat {
                codec: AudioCodec::Pcm,
                bits: 32,
                channels: out_ch,
                sample_rate: output_config.sample_rate.unwrap_or(src_sr),
            };
            info!(?format, "Realtime audio session initialized");
            session = Some(handler.audio_init(format));
        }

        // Decrypt: nonce from trailing 8 bytes, AAD from RTP header bytes 4..12
        let pkt_len = packet.len();
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&packet[pkt_len - NONCE_TRAIL_LEN..]);
        let aad = &packet[4..12];
        let ciphertext = &packet[RTP_HEADER_LEN..pkt_len - NONCE_TRAIL_LEN];

        let plaintext = match cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: ciphertext, aad },
        ) {
            Ok(p) => p,
            Err(_) => { debug!("Realtime audio decrypt failed"); continue; }
        };

        // Decode ALAC → f32 PCM
        let Some(mut samples) = decoder.as_mut().and_then(|d| d.decode_frame_f32(&plaintext)) else {
            continue;
        };

        // Mixdown if needed
        if src_ch > out_ch {
            samples = crate::codec::resample::mixdown(&samples, src_ch as usize, out_ch as usize);
        }

        // Resample if needed
        if let Some(ref mut rs) = resampler {
            samples = rs.process(&samples);
        }

        // Deliver immediately (realtime = no playout buffer)
        if let Some(ref mut sess) = session {
            let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
            sess.audio_process(&bytes);
        }
    }

    debug!("Realtime ALAC receiver ended");
}
