use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};

use crate::error::{NetworkError, ShairplayError};
use crate::raop::buffer::{RaopBuffer, RAOP_PACKET_LEN};
use crate::raop::{AudioHandler, AudioFormat};

const NO_FLUSH: i32 = -42;

/// Parse the SDP remote string to IP address bytes.
fn remote_addr_bytes(remote: &str) -> Vec<u8> {
    // remote is like "192.168.1.5" or "IP6 ::1" or "::ffff:10.0.0.1"
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

/// Determines the bind address based on the remote connection string from SDP.
/// The C code parses "IN IP4 <addr>" or "IN IP6 <addr>" and uses the family
/// to decide IPv4 vs IPv6 socket binding.
fn bind_addr_from_remote(remote: &str) -> SocketAddr {
    let use_ipv6 = remote.contains("IP6") || remote.contains(':');
    if use_ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }
}


struct RtpState {
    volume: f32,
    volume_changed: bool,
    metadata: Option<Vec<u8>>,
    coverart: Option<Vec<u8>>,
    dacp_id: Option<String>,
    active_remote: Option<String>,
    progress: Option<(u32, u32, u32)>,
    flush: i32,
}

/// RTP streaming session. Equivalent to raop_rtp_t.
pub struct RaopRtp {
    handler: Arc<dyn AudioHandler>,
    remote: String,
    buffer: Arc<Mutex<RaopBuffer>>,
    state: Arc<Mutex<RtpState>>,
    shutdown_tx: Option<watch::Sender<bool>>,
    control_rport: u16,
    control_lport: u16,
    timing_lport: u16,
    data_lport: u16,
}

impl RaopRtp {
    pub fn new(
        callbacks: Arc<dyn AudioHandler>,
        remote: &str,
        rtpmap: &str,
        fmtp: &str,
        aes_key: &[u8; 16],
        aes_iv: &[u8; 16],
    ) -> Self {
        let buffer = RaopBuffer::new(rtpmap, fmtp, aes_key, aes_iv);
        Self {
            handler: callbacks,
            remote: remote.to_string(),
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

    pub async fn start(
        &mut self,
        use_udp: bool,
        control_rport: u16,
        _timing_rport: u16,
    ) -> Result<(u16, u16, u16), ShairplayError> {
        self.control_rport = control_rport;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        if use_udp {
            let bind_addr = bind_addr_from_remote(&self.remote);
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
            let mut session = self.handler.audio_init(AudioFormat {
                bits: config.bit_depth, channels: config.num_channels,
                sample_rate: config.sample_rate,
            });

            let buffer = self.buffer.clone();
            let state = self.state.clone();
            let no_resend = control_rport == 0;
            let remote_for_task = self.remote.clone();

            tokio::spawn(async move {
                let mut shutdown_rx = shutdown_rx;
                let mut data_packet = [0u8; RAOP_PACKET_LEN];
                let mut ctrl_packet = [0u8; RAOP_PACKET_LEN];
                loop {
                    // Process events
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
                            session.audio_remote_control_id(&d, &a, remote_addr_bytes(&remote_for_task).as_slice());
                        }
                        if let Some((s, c, e)) = st.progress.take() {
                            session.audio_set_progress(s, c, e);
                        }
                    }

                    tokio::select! {
                        result = dsock.recv_from(&mut data_packet) => {
                            if let Ok((len, _)) = result {
                                if len >= 12 {
                                    let mut buf = buffer.lock().await;
                                    buf.queue(&data_packet[..len], true);
                                    while let Some(audio) = buf.dequeue(no_resend) {
                                        session.audio_process(audio);
                                    }
                                }
                            }
                        }
                        result = csock.recv_from(&mut ctrl_packet) => {
                            if let Ok((len, _)) = result {
                                if len >= 12 && (ctrl_packet[1] & !0x80) == 0x56 {
                                    let mut buf = buffer.lock().await;
                                    if len > 4 { buf.queue(&ctrl_packet[4..len], true); }
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => break,
                    }
                }
                // session dropped here = audio_destroy
            });
        } else {
            // TCP mode
            let listener = tokio::net::TcpListener::bind(bind_addr_from_remote(&self.remote)).await.map_err(NetworkError::Io)?;
            self.data_lport = listener.local_addr().map_err(NetworkError::Io)?.port();

            let config = {
                let buf = self.buffer.lock().await;
                buf.config().clone()
            };
            let mut session = self.handler.audio_init(AudioFormat {
                bits: config.bit_depth, channels: config.num_channels,
                sample_rate: config.sample_rate,
            });

            let buffer = self.buffer.clone();
            let state = self.state.clone();
            let remote_for_tcp = self.remote.clone();

            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut shutdown_rx = shutdown_rx;

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
                    // Process events (same as UDP)
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
                            // Process complete TCP-interleaved packets
                            while packet_buf.len() >= 4 {
                                if packet_buf[0] != b'$' || packet_buf[1] != 0 { break; }
                                let rtp_len = ((packet_buf[2] as usize) << 8) | packet_buf[3] as usize;
                                if packet_buf.len() < 4 + rtp_len { break; }
                                let mut buf = buffer.lock().await;
                                buf.queue(&packet_buf[4..4 + rtp_len], false);
                                if let Some(audio) = buf.dequeue(true) {
                                    session.audio_process(audio);
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

    pub fn set_volume(&self, volume: f32) {
        let v = volume.clamp(-144.0, 0.0);
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut st = state.lock().await;
            st.volume = v;
            st.volume_changed = true;
        });
    }

    pub fn set_metadata(&self, data: &[u8]) {
        let d = data.to_vec();
        let state = self.state.clone();
        tokio::spawn(async move { state.lock().await.metadata = Some(d); });
    }

    pub fn set_coverart(&self, data: &[u8]) {
        let d = data.to_vec();
        let state = self.state.clone();
        tokio::spawn(async move { state.lock().await.coverart = Some(d); });
    }

    pub fn set_remote_control_id(&self, dacp_id: &str, active_remote: &str) {
        let d = dacp_id.to_string();
        let a = active_remote.to_string();
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut st = state.lock().await;
            st.dacp_id = Some(d);
            st.active_remote = Some(a);
        });
    }

    pub fn set_progress(&self, start: u32, curr: u32, end: u32) {
        let state = self.state.clone();
        tokio::spawn(async move { state.lock().await.progress = Some((start, curr, end)); });
    }

    pub fn flush(&self, next_seq: i32) {
        let state = self.state.clone();
        tokio::spawn(async move { state.lock().await.flush = next_seq; });
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        self.buffer.lock().await.flush(-1);
    }
}
