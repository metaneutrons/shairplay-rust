//! AP1 RTP audio streaming — UDP and TCP receiver with ALAC decode.
//!
//! Manages the full AP1 audio receive pipeline:
//!
//! ```text
//! iPhone → RTP/UDP or RTP/TCP → RaopRtp → RaopBuffer (decrypt+decode) → AudioSession
//! ```
//!
//! Two transport modes:
//! - **UDP** (default): data, control, and timing on separate UDP sockets.
//!   Control channel carries retransmit responses (payload type 0x56).
//! - **TCP**: single TCP connection with `$`-prefixed interleaved framing.
//!   No retransmits (reliable transport).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};
use tracing::info;

use crate::error::{NetworkError, ShairplayError};
use crate::raop::buffer::{RaopBuffer, RAOP_PACKET_LEN};
use crate::raop::{AudioHandler, AudioFormat, AudioCodec};

/// Sentinel value for [`RtpState::flush`] indicating no flush is pending.
const NO_FLUSH: i32 = -42;

/// Parse the SDP `c=` remote address to raw IP bytes for DACP callbacks.
/// Handles "IP6 ::1" prefix and IPv4-mapped IPv6 addresses.
fn remote_addr_bytes(remote: &str) -> Vec<u8> {
    let addr_str = remote.strip_prefix("IP6 ").unwrap_or(remote);
    if let Ok(ip) = addr_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    } else {
        vec![]
    }
}

/// Mutable state shared between the RTP receive loop and the RTSP handler thread.
/// Updated via async message passing (tokio Mutex), consumed in the receive loop.
struct RtpState {
    /// Current volume in dB (0.0 = max, -144.0 = mute).
    volume: f32,
    /// Set to true when volume changes; cleared after delivery.
    volume_changed: bool,
    /// Pending DMAP track metadata (binary).
    metadata: Option<Vec<u8>>,
    /// Pending album artwork (JPEG/PNG).
    coverart: Option<Vec<u8>>,
    /// DACP ID for remote control discovery.
    dacp_id: Option<String>,
    /// Active-Remote token for DACP authentication.
    active_remote: Option<String>,
    /// Pending playback progress (start, current, end in RTP timestamps).
    progress: Option<(u32, u32, u32)>,
    /// Sequence number to flush to, or [`NO_FLUSH`] if no flush pending.
    flush: i32,
}

/// AP1 RTP streaming session.
///
/// Owns the UDP/TCP sockets, the packet buffer, and the ALAC decoder.
/// Created by [`handle_announce`](super::handlers::handle_announce) when
/// the iPhone sends the SDP ANNOUNCE. Started by
/// [`handle_setup`](super::handlers::handle_setup) which binds ports and
/// spawns the receive task.
///
/// Dropped when the RTSP connection closes, which sends a shutdown signal
/// to the receive task via the [`watch`] channel.
pub struct RaopRtp {
    handler: Arc<dyn AudioHandler>,
    /// SDP `c=` remote address string (e.g. "192.168.1.5").
    remote: String,
    /// Local IP address to bind sockets to (matches the RTSP connection's interface).
    local_addr: IpAddr,
    /// If set, resample decoded audio to this rate before delivery.
    output_sample_rate: Option<u32>,
    /// Shared packet buffer (decrypt + decode on queue, dequeue in order).
    buffer: Arc<Mutex<RaopBuffer>>,
    /// Shared mutable state for cross-task event delivery.
    state: Arc<Mutex<RtpState>>,
    /// Send `true` to shut down the receive task.
    shutdown_tx: Option<watch::Sender<bool>>,
    /// iPhone's control port (0 = no retransmits).
    control_rport: u16,
    /// Local control port (bound by us).
    control_lport: u16,
    /// Local timing port (bound by us).
    timing_lport: u16,
    /// Local data port (bound by us).
    data_lport: u16,
}

impl RaopRtp {
    /// Create a new RTP session from SDP parameters and AES session keys.
    /// Does not bind sockets or start receiving — call [`start`](Self::start) for that.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        callbacks: Arc<dyn AudioHandler>,
        remote: &str,
        local_addr: IpAddr,
        rtpmap: &str,
        fmtp: &str,
        aes_key: &[u8; 16],
        aes_iv: &[u8; 16],
        output_sample_rate: Option<u32>,
    ) -> Self {
        let buffer = RaopBuffer::new(rtpmap, fmtp, aes_key, aes_iv);
        Self {
            handler: callbacks,
            remote: remote.to_string(),
            local_addr,
            output_sample_rate,
            buffer: Arc::new(Mutex::new(buffer)),
            state: Arc::new(Mutex::new(RtpState {
                volume: 0.0, volume_changed: false,
                metadata: None, coverart: None,
                dacp_id: None, active_remote: None,
                progress: None, flush: NO_FLUSH,
            })),
            shutdown_tx: None,
            control_rport: 0,
            control_lport: 0,
            timing_lport: 0,
            data_lport: 0,
        }
    }

    /// Bind UDP/TCP sockets and spawn the async receive task.
    ///
    /// Returns `(control_port, timing_port, data_port)` — the local ports
    /// that the iPhone should send RTP packets to.
    ///
    /// # Transport modes
    ///
    /// - `use_udp = true`: binds 3 UDP sockets (data, control, timing).
    ///   Control channel receives retransmit responses (RTP payload type 0x56).
    /// - `use_udp = false`: binds 1 TCP listener. iPhone connects and sends
    ///   `$`-prefixed interleaved RTP frames.
    pub async fn start(
        &mut self,
        use_udp: bool,
        control_rport: u16,
        _timing_rport: u16,
    ) -> Result<(u16, u16, u16), ShairplayError> {
        self.control_rport = control_rport;
        info!(use_udp, control_rport, "AP1 RTP starting");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        if use_udp {
            let bind_addr = SocketAddr::new(self.local_addr, 0);
            let csock = UdpSocket::bind(bind_addr).await.map_err(NetworkError::Io)?;
            let tsock = UdpSocket::bind(bind_addr).await.map_err(NetworkError::Io)?;
            let dsock = UdpSocket::bind(bind_addr).await.map_err(NetworkError::Io)?;
            self.control_lport = csock.local_addr().map_err(NetworkError::Io)?.port();
            self.timing_lport = tsock.local_addr().map_err(NetworkError::Io)?.port();
            self.data_lport = dsock.local_addr().map_err(NetworkError::Io)?.port();

            let config = {
                let buf = self.buffer.lock().await;
                buf.config().clone()
            };
            let mut session = self.handler.audio_init(AudioFormat { codec: AudioCodec::Pcm,
                bits: 32, channels: config.num_channels,
                sample_rate: config.sample_rate,
            });

            #[cfg(feature = "resample")]
            let mut resampler = if let Some(target) = self.output_sample_rate {
                if target != config.sample_rate {
                    crate::codec::resample::StreamResampler::new(config.sample_rate, target, config.num_channels as usize)
                } else { None }
            } else { None };

            let buffer = self.buffer.clone();
            let state = self.state.clone();
            // If control_rport is 0, the iPhone doesn't support retransmits.
            let no_resend = control_rport == 0;
            let remote_for_task = self.remote.clone();

            tokio::spawn(async move {
                let mut shutdown_rx = shutdown_rx;
                let mut data_packet = [0u8; RAOP_PACKET_LEN];
                let mut ctrl_packet = [0u8; RAOP_PACKET_LEN];
                loop {
                    // Drain pending events from the RTSP handler thread.
                    {
                        let mut st = state.lock().await;
                        if st.volume_changed {
                            session.audio_set_volume(st.volume);
                            st.volume_changed = false;
                        }
                        if st.flush != NO_FLUSH {
                            buffer.lock().await.flush(st.flush);
                            session.audio_flush();
                            st.flush = NO_FLUSH;
                        }
                        if let Some(m) = st.metadata.take() { session.audio_set_metadata(&m); }
                        if let Some(c) = st.coverart.take() { session.audio_set_coverart(&c); }
                        if let (Some(d), Some(a)) = (st.dacp_id.take(), st.active_remote.take()) {
                            let addr_bytes = remote_addr_bytes(&remote_for_task);
                            session.audio_remote_control_id(&d, &a, addr_bytes.as_slice());
                            let remote = Arc::new(crate::raop::DacpRemoteControl::new(&d, &a, addr_bytes.as_slice()));
                            session.remote_control_available(remote);
                        }
                        if let Some((s, c, e)) = st.progress.take() {
                            session.audio_set_progress(s, c, e);
                        }
                    }

                    tokio::select! {
                        // Data channel: audio RTP packets.
                        result = dsock.recv_from(&mut data_packet) => {
                            if let Ok((len, _)) = result {
                                if len >= 12 {
                                    let mut buf = buffer.lock().await;
                                    buf.queue(&data_packet[..len], true);
                                    while let Some(audio) = buf.dequeue(no_resend) {
                                        {
                                            #[cfg(feature = "resample")]
                                            if let Some(ref mut rs) = resampler {
                                                let samples: Vec<f32> = audio.chunks_exact(4).map(|c| f32::from_le_bytes([c[0],c[1],c[2],c[3]])).collect();
                                                let resampled = rs.process(&samples);
                                                let bytes: Vec<u8> = resampled.iter().flat_map(|s| s.to_le_bytes()).collect();
                                                session.audio_process(&bytes);
                                            }
                                            #[cfg(not(feature = "resample"))]
                                            session.audio_process(audio);
                                        }
                                    }
                                }
                            }
                        }
                        // Control channel: retransmit responses (payload type 0x56).
                        result = csock.recv_from(&mut ctrl_packet) => {
                            if let Ok((len, _)) = result {
                                if len >= 12 && (ctrl_packet[1] & !0x80) == 0x56 {
                                    let mut buf = buffer.lock().await;
                                    // Retransmit packets have a 4-byte header before the original RTP.
                                    if len > 4 { buf.queue(&ctrl_packet[4..len], true); }
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => break,
                    }
                }
                // AudioSession dropped here → triggers cleanup in the app.
            });
        } else {
            // TCP interleaved mode: single connection, `$`-prefixed framing.
            let listener = tokio::net::TcpListener::bind(SocketAddr::new(self.local_addr, 0)).await.map_err(NetworkError::Io)?;
            self.data_lport = listener.local_addr().map_err(NetworkError::Io)?.port();

            let config = {
                let buf = self.buffer.lock().await;
                buf.config().clone()
            };
            let mut session = self.handler.audio_init(AudioFormat { codec: AudioCodec::Pcm,
                bits: 32, channels: config.num_channels,
                sample_rate: self.output_sample_rate.unwrap_or(config.sample_rate),
            });

            #[cfg(feature = "resample")]
            let mut resampler = if let Some(target) = self.output_sample_rate {
                if target != config.sample_rate {
                    crate::codec::resample::StreamResampler::new(config.sample_rate, target, config.num_channels as usize)
                } else { None }
            } else { None };

            let buffer = self.buffer.clone();
            let state = self.state.clone();
            let remote_for_tcp = self.remote.clone();

            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut shutdown_rx = shutdown_rx;

                // Wait for the iPhone to connect.
                let stream = tokio::select! {
                    result = listener.accept() => match result {
                        Ok((s, _)) => s,
                        Err(_) => return,
                    },
                    _ = shutdown_rx.changed() => return,
                };

                let mut reader = tokio::io::BufReader::new(stream);
                let mut packet_buf = Vec::with_capacity(RAOP_PACKET_LEN + 4);
                let mut read_buf = [0u8; 4096];

                loop {
                    // Drain pending events.
                    {
                        let mut st = state.lock().await;
                        if st.volume_changed { session.audio_set_volume(st.volume); st.volume_changed = false; }
                        if st.flush != NO_FLUSH { buffer.lock().await.flush(st.flush); session.audio_flush(); st.flush = NO_FLUSH; }
                        if let Some(m) = st.metadata.take() { session.audio_set_metadata(&m); }
                        if let Some(c) = st.coverart.take() { session.audio_set_coverart(&c); }
                        if let (Some(d), Some(a)) = (st.dacp_id.take(), st.active_remote.take()) { session.audio_remote_control_id(&d, &a, remote_addr_bytes(&remote_for_tcp).as_slice()); }
                        if let Some((s, c, e)) = st.progress.take() { session.audio_set_progress(s, c, e); }
                    }

                    tokio::select! {
                        result = reader.read(&mut read_buf) => {
                            match result {
                                Ok(0) | Err(_) => break,
                                Ok(n) => packet_buf.extend_from_slice(&read_buf[..n]),
                            }
                            // TCP interleaved: each frame is `$ <channel> <len_hi> <len_lo> <rtp...>`.
                            while packet_buf.len() >= 4 {
                                if packet_buf[0] != b'$' || packet_buf[1] != 0 { break; }
                                let rtp_len = ((packet_buf[2] as usize) << 8) | packet_buf[3] as usize;
                                if packet_buf.len() < 4 + rtp_len { break; }
                                let mut buf = buffer.lock().await;
                                buf.queue(&packet_buf[4..4 + rtp_len], false);
                                if let Some(audio) = buf.dequeue(true) {
                                    {
                                            #[cfg(feature = "resample")]
                                            if let Some(ref mut rs) = resampler {
                                                let samples: Vec<f32> = audio.chunks_exact(4).map(|c| f32::from_le_bytes([c[0],c[1],c[2],c[3]])).collect();
                                                let resampled = rs.process(&samples);
                                                let bytes: Vec<u8> = resampled.iter().flat_map(|s| s.to_le_bytes()).collect();
                                                session.audio_process(&bytes);
                                            }
                                            #[cfg(not(feature = "resample"))]
                                            session.audio_process(audio);
                                        }
                                }
                                drop(buf);
                                packet_buf.drain(..4 + rtp_len);
                            }
                        }
                        _ = shutdown_rx.changed() => break,
                    }
                }
            });
        }

        Ok((self.control_lport, self.timing_lport, self.data_lport))
    }

    /// Set the playback volume. Delivered to the AudioSession on the next loop iteration.
    /// Volume is in dB: 0.0 = max, -144.0 = mute.
    pub fn set_volume(&self, volume: f32) {
        let v = volume.clamp(-144.0, 0.0);
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut st = state.lock().await;
            st.volume = v;
            st.volume_changed = true;
        });
    }

    /// Queue DMAP track metadata for delivery to the AudioSession.
    pub fn set_metadata(&self, data: &[u8]) {
        let d = data.to_vec();
        let state = self.state.clone();
        tokio::spawn(async move { state.lock().await.metadata = Some(d); });
    }

    /// Queue album artwork for delivery to the AudioSession.
    pub fn set_coverart(&self, data: &[u8]) {
        let d = data.to_vec();
        let state = self.state.clone();
        tokio::spawn(async move { state.lock().await.coverart = Some(d); });
    }

    /// Set DACP remote control identifiers. Triggers remote control discovery
    /// and delivers a [`RemoteControl`](super::RemoteControl) handle to the AudioSession.
    pub fn set_remote_control_id(&self, dacp_id: &str, active_remote: &str) {
        info!(dacp_id, "DACP remote control available");
        let d = dacp_id.to_string();
        let a = active_remote.to_string();
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut st = state.lock().await;
            st.dacp_id = Some(d);
            st.active_remote = Some(a);
        });
    }

    /// Queue playback progress for delivery to the AudioSession.
    /// Values are in RTP timestamp units (sample clock).
    pub fn set_progress(&self, start: u32, curr: u32, end: u32) {
        let state = self.state.clone();
        tokio::spawn(async move { state.lock().await.progress = Some((start, curr, end)); });
    }

    /// Request a buffer flush up to the given sequence number.
    /// Pass -1 to flush everything.
    pub fn flush(&self, next_seq: i32) {
        let state = self.state.clone();
        tokio::spawn(async move { state.lock().await.flush = next_seq; });
    }

    /// Stop the receive task and flush the buffer.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        self.buffer.lock().await.flush(-1);
    }
}
