//! AirPlay 2 buffered audio processor with format-aware decoding.
//!
//! Detects audio format from SSRC, decodes AAC via symphonia, resamples
//! via rubato if needed, mixes down channels if needed, delivers F32 PCM.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Condvar};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::codec::aac::{AudioSsrc, AacDecoder};
use crate::error::NetworkError;
use crate::raop::{AudioHandler, AudioFormat, AudioCodec};

const RTP_HEADER_LEN: usize = 12;
const NONCE_TRAIL_LEN: usize = 8;

#[derive(Debug, Clone)]
pub struct OutputConfig {
    pub sample_rate: Option<u32>,   // None = native
    pub max_channels: Option<u8>,   // None = pass through
}

#[derive(Debug)]
pub enum PlayoutCommand {
    SetRate { anchor_rtp: u32, anchor_time_ns: u64, rate: u32 },
    Flush { from_seq: u32, until_seq: u32 },
    Stop,
    Volume(f32),
    Metadata(Vec<u8>),
    Coverart(Vec<u8>),
    Progress { start: u32, current: u32, end: u32 },
}

struct PlayoutState {
    buffer: BTreeMap<u32, Vec<u8>>, // rtp_timestamp → F32 PCM bytes
    anchor_rtp: u32,
    anchor_local_ns: u64,
    rate: u32,
    sample_rate: u32,
    channels: u8,
    stopped: bool,
    format_changed: bool,
    pending_meta: Vec<PlayoutCommand>, // Volume/Metadata/Coverart/Progress
}

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

    pub fn start(
        self,
        shk: [u8; 32],
        output_config: OutputConfig,
        handler: Arc<dyn AudioHandler>,
    ) -> tokio::sync::mpsc::UnboundedSender<PlayoutCommand> {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let default_sr = output_config.sample_rate.unwrap_or(44100);

        let state = Arc::new((
            Mutex::new(PlayoutState {
                buffer: BTreeMap::new(),
                anchor_rtp: 0,
                anchor_local_ns: 0,
                rate: 0,
                sample_rate: default_sr,
                channels: 2,
                stopped: false,
                format_changed: false,
                pending_meta: Vec::new(),
            }),
            Condvar::new(),
        ));

        // Delivery thread
        let state2 = state.clone();
        let handler2 = handler.clone();
        let output_config2 = output_config.clone();
        std::thread::spawn(move || {
            delivery_loop(state2, handler2, output_config2);
        });

        // Command handler
        let state3 = state.clone();
        let mut cmd_rx = cmd_rx;
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                let (lock, cvar) = &*state3;
                let mut s = lock.lock().unwrap();
                match cmd {
                    PlayoutCommand::SetRate { anchor_rtp, anchor_time_ns: _, rate } => {
                        s.anchor_rtp = anchor_rtp;
                        let was_paused = s.rate == 0;
                        s.rate = rate;
                        if rate == 0 {
                            info!("Playout paused");
                        } else {
                            s.anchor_local_ns = now_ns();
                            let stale: Vec<u32> = s.buffer.keys()
                                .filter(|&&ts| (s.anchor_rtp.wrapping_sub(ts) as i32) > 0)
                                .copied().collect();
                            if !stale.is_empty() {
                                debug!(discarded = stale.len(), "Discarded stale frames");
                            }
                            for k in stale { s.buffer.remove(&k); }
                            if was_paused {
                                info!(anchor_rtp, "Playout started");
                            }
                        }
                        cvar.notify_all();
                    }
                    PlayoutCommand::Flush { from_seq, until_seq } => {
                        let keys: Vec<u32> = s.buffer.keys()
                            .filter(|&&ts| ts >= from_seq && ts <= until_seq)
                            .copied().collect();
                        for k in &keys { s.buffer.remove(k); }
                        debug!(flushed = keys.len(), "Flushed");
                    }
                    PlayoutCommand::Stop => {
                        s.stopped = true;
                        s.buffer.clear();
                        cvar.notify_all();
                        break;
                    }
                    cmd @ (PlayoutCommand::Volume(_) | PlayoutCommand::Metadata(_) |
                           PlayoutCommand::Coverart(_) | PlayoutCommand::Progress { .. }) => {
                        s.pending_meta.push(cmd);
                        cvar.notify_all();
                    }
                }
            }
        });

        // Receiver task
        let state4 = state.clone();

        tokio::spawn(async move {
            let (stream, addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(e) => { warn!("Buffered audio accept failed: {e}"); return; }
            };
            info!(%addr, "Buffered audio client connected");
            receive_loop(stream, &shk, output_config, state4).await;
        });

        cmd_tx
    }
}

async fn receive_loop(
    mut stream: TcpStream,
    shk: &[u8; 32],
    output_config: OutputConfig,
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
) {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead, Nonce, aead::Payload};

    let cipher = ChaCha20Poly1305::new(shk.into());
    let mut len_buf = [0u8; 2];
    let mut decoder: Option<AacDecoder> = None;
    let mut current_ssrc = AudioSsrc::None;
    let mut stream_resampler: Option<crate::codec::resample::StreamResampler> = None;
    let mut source_channels: u8 = 2;
    let mut output_channels: u8 = 2;

    loop {
        if stream.read_exact(&mut len_buf).await.is_err() { break; }
        let total_len = u16::from_be_bytes(len_buf) as usize;
        if total_len < 2 { break; }

        let mut packet = vec![0u8; total_len - 2];
        if stream.read_exact(&mut packet).await.is_err() { break; }
        if packet.len() <= RTP_HEADER_LEN + NONCE_TRAIL_LEN { continue; }

        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let ssrc_val = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let ssrc = AudioSsrc::from_u32(ssrc_val);

        // Detect format change
        if ssrc != AudioSsrc::None && ssrc != current_ssrc {
            current_ssrc = ssrc;
            let src_sr = ssrc.sample_rate();
            let src_ch = ssrc.channels();
            info!(ssrc = ?ssrc, src_sr, src_ch, "Audio format detected");

            decoder = AacDecoder::new(src_sr, src_ch).ok();
            if decoder.is_none() {
                warn!("Failed to create AAC decoder for {:?}", ssrc);
            }

            let target_sr = output_config.sample_rate.unwrap_or(src_sr);
            let target_ch = output_config.max_channels
                .map(|max| src_ch.min(max))
                .unwrap_or(src_ch);

            stream_resampler = crate::codec::resample::StreamResampler::new(src_sr, target_sr, target_ch as usize);
            if stream_resampler.is_some() {
                debug!(from = src_sr, to = target_sr, "Resampler initialized");
            }

            source_channels = src_ch;
            output_channels = target_ch;

            // Signal format change to delivery thread
            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            s.sample_rate = target_sr;
            s.channels = target_ch;
            s.format_changed = true;
            cvar.notify_all();
        }

        // Decrypt
        let pkt_len = packet.len();
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&packet[pkt_len - NONCE_TRAIL_LEN..]);
        let aad = packet[4..12].to_vec();
        let ciphertext = &packet[RTP_HEADER_LEN..pkt_len - NONCE_TRAIL_LEN];

        let plaintext = match cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad: &aad }) {
            Ok(p) => p,
            Err(_) => { debug!("Audio decrypt failed"); continue; }
        };

        // Decode
        let pcm = if let Some(dec) = &mut decoder {
            dec.decode(&plaintext)
        } else {
            None
        };

        if let Some(pcm_data) = pcm {
            // Convert bytes to f32 samples for processing
            let mut samples: Vec<f32> = pcm_data.chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();

            // Channel mixdown if needed
            if source_channels > output_channels {
                samples = crate::codec::resample::mixdown(&samples, source_channels as usize, output_channels as usize);
            }

            // Resample if needed
            if let Some(ref mut rs) = stream_resampler {
                samples = rs.process(&samples);
            }

            // Convert back to bytes
            let mut out_bytes = Vec::with_capacity(samples.len() * 4);
            for s in &samples {
                out_bytes.extend_from_slice(&s.to_le_bytes());
            }

            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            s.buffer.insert(timestamp, out_bytes);
            cvar.notify_all();
        }
    }
    debug!("Buffered audio receive loop ended");
}

fn delivery_loop(
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
    handler: Arc<dyn AudioHandler>,
    _output_config: OutputConfig,
) {
    let (lock, cvar) = &*state;
    let mut session: Option<Box<dyn crate::raop::AudioSession>> = None;

    loop {
        let mut s = lock.lock().unwrap();

        while !s.stopped && (s.rate == 0 || s.buffer.is_empty()) {
            s = cvar.wait(s).unwrap();
        }
        if s.stopped { break; }

        // Lazy init or reinit session on format change
        if session.is_none() || s.format_changed {
            s.format_changed = false;
            let format = AudioFormat {
                codec: AudioCodec::Pcm,
                bits: 32,
                channels: s.channels,
                sample_rate: s.sample_rate,
            };
            info!(?format, "Audio session initialized");
            session = Some(handler.audio_init(format));
        }

        let now = now_ns();
        let elapsed_ns = now.saturating_sub(s.anchor_local_ns);
        let elapsed_frames = (elapsed_ns as u128 * s.sample_rate as u128 / 1_000_000_000) as u32;
        let target_rtp = s.anchor_rtp.wrapping_add(elapsed_frames);

        let ready: Vec<(u32, Vec<u8>)> = s.buffer
            .iter()
            .filter(|(&ts, _)| (target_rtp.wrapping_sub(ts) as i32) >= 0)
            .map(|(&ts, data)| (ts, data.clone()))
            .collect();

        for (ts, _) in &ready { s.buffer.remove(ts); }
        let meta: Vec<PlayoutCommand> = s.pending_meta.drain(..).collect();
        drop(s);

        if let Some(ref mut sess) = session {
            for cmd in meta {
                match cmd {
                    PlayoutCommand::Volume(v) => sess.audio_set_volume(v),
                    PlayoutCommand::Metadata(d) => sess.audio_set_metadata(&d),
                    PlayoutCommand::Coverart(d) => sess.audio_set_coverart(&d),
                    PlayoutCommand::Progress { start, current, end } => sess.audio_set_progress(start, current, end),
                    _ => {}
                }
            }
            for (_, frame) in &ready {
                sess.audio_process(frame);
            }
        }

        if ready.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    info!("Delivery loop ended");
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
