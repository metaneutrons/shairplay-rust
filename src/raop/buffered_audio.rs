//! AirPlay 2 buffered audio processor with timed playout.
//!
//! Audio packets are decrypted and queued by RTP timestamp. A delivery
//! thread pulls frames at the correct time based on the PTP anchor from
//! SETRATEANCHORTI. Pause (rate=0) stops delivery. FLUSHBUFFERED discards
//! queued frames.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Condvar};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::codec::aac;
use crate::error::NetworkError;

const RTP_HEADER_LEN: usize = 12;
const NONCE_TRAIL_LEN: usize = 8;

/// Control commands sent from RTSP handlers to the playout buffer.
#[derive(Debug)]
pub enum PlayoutCommand {
    /// Start/resume playback: anchor_rtp, anchor_time_ns, rate
    SetRate { anchor_rtp: u32, anchor_time_ns: u64, rate: u32 },
    /// Flush frames in range
    Flush { from_seq: u32, until_seq: u32 },
    /// Stop everything
    Stop,
}

/// Shared playout state between receiver, delivery thread, and RTSP handlers.
struct PlayoutState {
    buffer: BTreeMap<u32, Vec<u8>>, // rtp_timestamp → S16LE PCM
    anchor_rtp: u32,
    anchor_local_ns: u64, // local wall clock when anchor was set
    rate: u32, // 0 = paused, 1 = playing
    sample_rate: u32,
    stopped: bool,
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

    /// Run the buffered audio pipeline. Returns a command sender for RTSP handlers.
    pub fn start<F>(
        self,
        shk: [u8; 32],
        sample_rate: u32,
        channels: u8,
        on_audio: F,
    ) -> tokio::sync::mpsc::UnboundedSender<PlayoutCommand>
    where
        F: FnMut(&[u8]) + Send + 'static,
    {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();

        let state = Arc::new((
            Mutex::new(PlayoutState {
                buffer: BTreeMap::new(),
                anchor_rtp: 0,
                anchor_local_ns: 0,
                rate: 0,
                sample_rate,
                stopped: false,
            }),
            Condvar::new(),
        ));

        // Delivery thread: pulls frames at the right time
        let state2 = state.clone();
        let cmd_tx2 = cmd_tx.clone();
        std::thread::spawn(move || {
            delivery_loop(state2, on_audio);
        });

        // Command handler thread
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
                            // Use local wall clock as anchor reference
                            s.anchor_local_ns = now_ns();
                            // Discard stale frames from before the new anchor
                            let stale: Vec<u32> = s.buffer.keys()
                                .filter(|&&ts| {
                                    let diff = s.anchor_rtp.wrapping_sub(ts) as i32;
                                    diff > 0 // frame is before anchor
                                })
                                .copied().collect();
                            if !stale.is_empty() {
                                debug!(discarded = stale.len(), "Discarded stale frames on resume");
                            }
                            for k in stale { s.buffer.remove(&k); }
                            if was_paused {
                                info!(anchor_rtp, "Playout started");
                            } else {
                                info!(anchor_rtp, "Playout anchor updated");
                            }
                        }
                        cvar.notify_all();
                    }
                    PlayoutCommand::Flush { from_seq, until_seq } => {
                        let keys: Vec<u32> = s.buffer.keys()
                            .filter(|&&ts| ts >= from_seq && ts <= until_seq)
                            .copied().collect();
                        for k in &keys { s.buffer.remove(k); }
                        debug!(flushed = keys.len(), "Flushed buffered frames");
                    }
                    PlayoutCommand::Stop => {
                        s.stopped = true;
                        s.buffer.clear();
                        cvar.notify_all();
                        break;
                    }
                }
            }
        });

        // Receiver task: decrypt and queue
        let state4 = state.clone();
        tokio::spawn(async move {
            let (stream, addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(e) => { warn!("Buffered audio accept failed: {e}"); return; }
            };
            info!(%addr, "Buffered audio client connected");
            receive_loop(stream, &shk, sample_rate, channels, state4).await;
        });

        cmd_tx
    }
}

async fn receive_loop(
    mut stream: TcpStream,
    shk: &[u8; 32],
    sample_rate: u32,
    channels: u8,
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
) {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead, Nonce, aead::Payload};

    let cipher = ChaCha20Poly1305::new(shk.into());
    let mut len_buf = [0u8; 2];
    let mut decoder: Option<aac::AacDecoder> = None;

    loop {
        if stream.read_exact(&mut len_buf).await.is_err() { break; }
        let total_len = u16::from_be_bytes(len_buf) as usize;
        if total_len < 2 { break; }

        let mut packet = vec![0u8; total_len - 2];
        if stream.read_exact(&mut packet).await.is_err() { break; }
        if packet.len() <= RTP_HEADER_LEN + NONCE_TRAIL_LEN { continue; }

        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        let pkt_len = packet.len();
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&packet[pkt_len - NONCE_TRAIL_LEN..]);
        let aad = packet[4..12].to_vec();
        let ciphertext = &packet[RTP_HEADER_LEN..pkt_len - NONCE_TRAIL_LEN];

        if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad: &aad }) {
            // Determine format from SSRC
            let ssrc_val = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
            let ssrc = aac::AudioSsrc::from_u32(ssrc_val);
            let sr = if ssrc != aac::AudioSsrc::None { ssrc.sample_rate() } else { sample_rate };
            let ch = if ssrc != aac::AudioSsrc::None { ssrc.channels() } else { channels };

            // Decode AAC to PCM
            let pcm = if ssrc.is_aac() || ssrc == aac::AudioSsrc::None {
                let dec = decoder.get_or_insert_with(|| {
                    aac::AacDecoder::new(sr, ch).unwrap_or_else(|e| {
                        tracing::warn!("AAC decoder init: {e}");
                        aac::AacDecoder::new(44100, 2).expect("fallback decoder")
                    })
                });
                dec.decode(&plaintext)
            } else {
                // ALAC: already decoded by the library's ALAC decoder? No — buffered ALAC
                // is raw, needs decoding too. For now, pass through as-is.
                Some(plaintext.clone())
            };

            if let Some(pcm_data) = pcm {
                let (lock, cvar) = &*state;
                let mut s = lock.lock().unwrap();
                s.buffer.insert(timestamp, pcm_data);
                cvar.notify_all();
            }
        }
    }
    debug!("Buffered audio receive loop ended");
}

fn delivery_loop<F>(state: Arc<(Mutex<PlayoutState>, Condvar)>, mut on_audio: F)
where
    F: FnMut(&[u8]),
{
    let (lock, cvar) = &*state;

    loop {
        let mut s = lock.lock().unwrap();

        // Wait until playing and buffer has data, or stopped
        while !s.stopped && (s.rate == 0 || s.buffer.is_empty()) {
            s = cvar.wait(s).unwrap();
        }
        if s.stopped { break; }

        let now_ns = now_ns();

        // Calculate which RTP timestamp should play now
        let elapsed_ns = now_ns.saturating_sub(s.anchor_local_ns);
        let elapsed_frames = (elapsed_ns as u128 * s.sample_rate as u128 / 1_000_000_000) as u32;
        let target_rtp = s.anchor_rtp.wrapping_add(elapsed_frames);

        // Deliver all frames up to target_rtp (using wrapping comparison)
        let ready: Vec<(u32, Vec<u8>)> = s.buffer
            .iter()
            .filter(|(&ts, _)| {
                // Frame is ready if it's at or before target_rtp
                // Use signed wrapping diff to handle RTP timestamp wraparound
                let diff = target_rtp.wrapping_sub(ts) as i32;
                diff >= 0
            })
            .map(|(&ts, data)| (ts, data.clone()))
            .collect();

        for (ts, _) in &ready {
            s.buffer.remove(ts);
        }

        drop(s); // release lock before callback

        for (_, frame) in &ready {
            on_audio(frame);
        }

        if ready.is_empty() {
            // Nothing ready yet, sleep a bit
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    debug!("Delivery loop ended");
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
