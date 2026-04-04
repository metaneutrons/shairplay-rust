//! RTSP request handlers for AP1 and AP2 AirPlay sessions.

use std::sync::Arc;

use crate::crypto::fairplay::FairPlay;
use crate::crypto::pairing::{Pairing, PairingSession};
use crate::crypto::rsa::RsaKey;
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::proto::sdp::Sdp;
use crate::raop::rtp::RaopRtp;
use crate::raop::AudioHandler;

#[cfg(feature = "ap2")]
use crate::crypto::pairing_homekit::{PairVerifyServer, SrpServer};

/// Per-connection state for RTSP handler dispatch. Equivalent to raop_conn_t.
pub(crate) struct RaopConnection {
    pub raop_rtp: Option<RaopRtp>,
    pub fairplay: FairPlay,
    pub pairing: PairingSession,
    pub local_addr: Vec<u8>,
    #[allow(dead_code)] // read in AP2 event channel binding
    pub remote_addr: Vec<u8>,
    pub remote_socket: std::net::SocketAddr,
    pub nonce: String,
    // Shared references from the server
    pub rsakey: Arc<RsaKey>,
    pub pairing_identity: Arc<Pairing>,
    pub hwaddr: Vec<u8>,
    pub password: String,
    pub handler: Arc<dyn AudioHandler>,
    // AirPlay 2 state
    #[cfg(feature = "ap2")]
    pub device_id: String,
    #[cfg(feature = "ap2")]
    pub srp_server: Option<SrpServer>,
    #[cfg(feature = "ap2")]
    pub pair_verify: Option<PairVerifyServer>,
    #[cfg(feature = "ap2")]
    pub ap2_shared_secret: Option<Vec<u8>>,
    /// X25519 shared secret from pair-verify (32 bytes). Used for video key derivation.
    #[cfg(feature = "ap2")]
    pub pair_verify_secret: Option<[u8; 32]>,
    #[cfg(feature = "ap2")]
    pub is_ap2: bool,
    #[cfg(feature = "ap2")]
    #[allow(dead_code)] // read in AP2 pair-setup M5 handler
    pub pairing_store: Arc<dyn crate::raop::PairingStore>,
    #[cfg(feature = "ap2")]
    pub playout_cmd: Option<tokio::sync::mpsc::UnboundedSender<crate::raop::buffered_audio::PlayoutCommand>>,
    #[allow(dead_code)] // read when resample or ap2 feature enabled
    pub output_sample_rate: Option<u32>,
    #[allow(dead_code)] // read when ap2 feature enabled
    pub output_max_channels: Option<u8>,
    #[cfg(feature = "ap2")]
    pub pin: Option<String>,
    #[cfg(feature = "ap2")]
    pub event_sender: Option<crate::raop::event_channel::EventSender>,
    #[cfg(feature = "video")]
    pub video_handler: Option<Arc<dyn crate::raop::video::VideoHandler>>,
    #[cfg(feature = "video")]
    pub ekey: Option<[u8; 16]>,
    #[cfg(feature = "video")]
    pub eiv: Option<[u8; 16]>,
    /// Shared video encryption keys (set by audio connection, read by video connection).
    #[cfg(feature = "video")]
    pub shared_video_ekey: Arc<std::sync::RwLock<Option<[u8; 16]>>>,
    #[cfg(feature = "video")]
    pub shared_video_eiv: Arc<std::sync::RwLock<Option<[u8; 16]>>>,
    #[cfg(feature = "hls")]
    pub hls_handler: Option<Arc<dyn crate::raop::hls::HlsHandler>>,
    #[cfg(feature = "hls")]
    pub hls_state: std::sync::Arc<std::sync::Mutex<crate::raop::hls::HlsState>>,
}

/// Returns the connection's local IP address.
pub(crate) fn local_ip_from(conn: &RaopConnection) -> std::net::IpAddr {
    ip_from_bytes(&conn.local_addr)
}

pub(crate) fn ip_from_bytes(bytes: &[u8]) -> std::net::IpAddr {
    if bytes.len() == 16 {
        let ip: [u8; 16] = bytes[..16].try_into().unwrap_or([0; 16]);
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip))
    } else {
        let ip: [u8; 4] = bytes[..4].try_into().unwrap_or([0; 4]);
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip))
    }
}

/// Returns a bind address string matching the connection's local interface.
/// Returns a bind address string for sub-listeners (buffered audio, event channel, etc.).
/// Uses the specific local IP for routable addresses (respects BindConfig).
/// Falls back to unspecified for link-local IPv6.
#[cfg(feature = "ap2")]
pub(crate) fn bind_addr_for(conn: &RaopConnection) -> String {
    let ip = local_ip_from(conn);
    let bind_ip = match ip {
        std::net::IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }
        other => other,
    };
    format!("{}:0", bind_ip)
}
/// AP1 pair-setup: return Ed25519 public key.
pub(crate) fn handle_pair_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    if data.len() != 32 {
        return None;
    }
    let public_key = conn.pairing_identity.public_key();
    response.add_header("Content-Type", "application/octet-stream");
    Some(public_key.to_vec())
}

/// AP1 pair-verify: Ed25519/Curve25519 handshake (M1/M2).
pub(crate) fn handle_pair_verify(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    if data.len() < 4 {
        return None;
    }

    match data[0] {
        1 => {
            if data.len() != 4 + 32 + 32 {
                return None;
            }
            let ecdh_key: &[u8; 32] = data[4..36].try_into().ok()?;
            let ed_key: &[u8; 32] = data[36..68].try_into().ok()?;
            let _ = conn.pairing.handshake(ecdh_key, ed_key);
            let public_key = conn.pairing.get_public_key().ok()?;
            let signature = conn.pairing.get_signature().ok()?;
            response.add_header("Content-Type", "application/octet-stream");
            let mut resp = Vec::with_capacity(96);
            resp.extend_from_slice(&public_key);
            resp.extend_from_slice(&signature);
            Some(resp)
        }
        0 => {
            if data.len() != 4 + 64 {
                return None;
            }
            let sig: &[u8; 64] = data[4..68].try_into().ok()?;
            if conn.pairing.finish(sig).is_err() {
                response.set_disconnect(true);
            }
            None
        }
        _ => None,
    }
}

/// FairPlay DRM handshake (fp-setup M1/M2).
pub(crate) fn handle_fp_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    tracing::debug!(data_len = data.len(), "fp-setup");
    match data.len() {
        16 => {
            let req: &[u8; 16] = data.try_into().ok()?;
            let res = conn.fairplay.setup(req).ok()?;
            Some(res.to_vec())
        }
        164 => {
            let req: &[u8; 164] = data.try_into().ok()?;
            let res = conn.fairplay.handshake(req).ok()?;
            Some(res.to_vec())
        }
        _ => None,
    }
}

/// RTSP OPTIONS: return supported methods.
pub(crate) fn handle_options(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    #[cfg(feature = "ap2")]
    response.add_header(
        "Public",
        "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, FLUSHBUFFERED, TEARDOWN, OPTIONS, POST, GET, PUT",
    );
    #[cfg(not(feature = "ap2"))]
    response.add_header(
        "Public",
        "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER",
    );
    None
}

/// RTSP ANNOUNCE: parse SDP, extract AES keys, create RTP session.
pub(crate) fn handle_announce(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    let sdp_str = std::str::from_utf8(data).ok()?;
    let sdp = Sdp::parse(sdp_str);

    let remote = sdp.connection()?;
    let rtpmap = sdp.rtpmap()?;
    let fmtp = sdp.fmtp()?;
    let aesiv_str = sdp.aesiv()?;

    let mut aeskey = [0u8; 16];
    let mut aesiv = [0u8; 16];

    // Decrypt AES key from RSA or FairPlay
    let key_bytes = if let Some(rsa_key_str) = sdp.rsaaeskey() {
        conn.rsakey.decrypt(rsa_key_str).ok()
    } else if let Some(fp_key_str) = sdp.fpaeskey() {
        let fp_data = conn.rsakey.decode(fp_key_str).ok()?;
        if fp_data.len() == 72 {
            let input: &[u8; 72] = fp_data.as_slice().try_into().ok()?;
            let key = conn.fairplay.decrypt(input).ok()?;
            Some(key.to_vec())
        } else {
            None
        }
    } else {
        None
    };

    let key_bytes = key_bytes?;
    if key_bytes.len() >= 16 {
        aeskey.copy_from_slice(&key_bytes[..16]);
    }

    let iv_bytes = conn.rsakey.decode(aesiv_str).ok()?;
    if iv_bytes.len() >= 16 {
        aesiv.copy_from_slice(&iv_bytes[..16]);
    }

    // Destroy existing RTP session if any
    conn.raop_rtp = None;

    conn.raop_rtp = Some(RaopRtp::new(
        conn.handler.clone(),
        crate::raop::rtp::RtpConfig {
            remote: remote.to_string(),
            local_addr: local_ip_from(conn),
            rtpmap: rtpmap.to_string(),
            fmtp: fmtp.to_string(),
            aes_key: aeskey,
            aes_iv: aesiv,
            output_sample_rate: conn.output_sample_rate,
            remote_socket: conn.remote_socket,
        },
    ));

    if conn.raop_rtp.is_none() {
        response.set_disconnect(true);
    }
    None
}

/// AP1 RTSP SETUP: bind RTP ports and start audio receiver.
pub(crate) fn handle_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let transport = request.header("Transport")?;
    tracing::debug!(transport, "AP1 SETUP");

    // Check for DACP remote control headers
    if let (Some(dacp_id), Some(active_remote)) = (request.header("DACP-ID"), request.header("Active-Remote")) {
        if let Some(rtp) = &conn.raop_rtp {
            rtp.set_remote_control_id(dacp_id, active_remote);
        }
    }

    let use_udp = !transport.starts_with("RTP/AVP/TCP");
    let mut remote_cport = 0u16;
    let mut remote_tport = 0u16;

    if use_udp {
        for part in transport.split(';') {
            if let Some(val) = part.strip_prefix("control_port=") {
                remote_cport = val.parse().unwrap_or(0);
            } else if let Some(val) = part.strip_prefix("timing_port=") {
                remote_tport = val.parse().unwrap_or(0);
            }
        }
    }

    if let Some(rtp) = &mut conn.raop_rtp {
        // We need to start RTP in a blocking context — store params for later
        // For now, use tokio::runtime::Handle to block

        let (cport, tport, dport) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(rtp.start(use_udp, remote_cport, remote_tport))
        })
        .ok()?;

        let transport_resp = if use_udp {
            format!(
                "RTP/AVP/UDP;unicast;mode=record;timing_port={};events;control_port={};server_port={}",
                tport, cport, dport
            )
        } else {
            format!("RTP/AVP/TCP;unicast;interleaved=0-1;mode=record;server_port={}", dport)
        };
        response.add_header("Transport", &transport_resp);
        response.add_header("Session", "DEADBEEF");
    } else {
        response.set_disconnect(true);
    }
    None
}

/// RTSP GET_PARAMETER: return volume or other parameters.
pub(crate) fn handle_get_parameter(
    _conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let content_type = request.header("Content-Type")?;
    if content_type != "text/parameters" {
        return None;
    }

    let data = request.data()?;
    let text = std::str::from_utf8(data).ok()?;
    if text.contains("volume") {
        response.add_header("Content-Type", "text/parameters");
        return Some(b"volume: 0.000000\r\n".to_vec());
    }
    None
}

/// RTSP SET_PARAMETER: handle volume, metadata, artwork, progress.
pub(crate) fn handle_set_parameter(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let content_type = request.header("Content-Type")?;
    let data = request.data()?;
    tracing::debug!(content_type, len = data.len(), "SET_PARAMETER");

    // AP2: forward via playout command channel
    #[cfg(feature = "ap2")]
    if let Some(tx) = &conn.playout_cmd {
        let cmd = match content_type {
            "text/parameters" => {
                let text = std::str::from_utf8(data).ok()?;
                if let Some(rest) = text.strip_prefix("volume: ") {
                    rest.trim()
                        .parse::<f32>()
                        .ok()
                        .map(crate::raop::buffered_audio::PlayoutCommand::Volume)
                } else if let Some(rest) = text.strip_prefix("progress: ") {
                    let p: Vec<&str> = rest.trim().split('/').collect();
                    if p.len() == 3 {
                        Some(crate::raop::buffered_audio::PlayoutCommand::Progress {
                            start: p[0].parse().unwrap_or(0),
                            current: p[1].parse().unwrap_or(0),
                            end: p[2].parse().unwrap_or(0),
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            "image/jpeg" | "image/png" => Some(crate::raop::buffered_audio::PlayoutCommand::Coverart(data.to_vec())),
            "application/x-dmap-tagged" => Some(crate::raop::buffered_audio::PlayoutCommand::Metadata(data.to_vec())),
            _ => None,
        };
        if let Some(c) = cmd {
            let _ = tx.send(c);
        }
        return None;
    }

    // AP1: forward via raop_rtp
    let rtp = conn.raop_rtp.as_ref()?;
    match content_type {
        "text/parameters" => {
            let text = std::str::from_utf8(data).ok()?;
            if let Some(rest) = text.strip_prefix("volume: ") {
                if let Ok(vol) = rest.trim().parse::<f32>() {
                    rtp.set_volume(vol);
                }
            } else if let Some(rest) = text.strip_prefix("progress: ") {
                let parts: Vec<&str> = rest.trim().split('/').collect();
                if parts.len() == 3 {
                    let s = parts[0].parse().unwrap_or(0);
                    let c = parts[1].parse().unwrap_or(0);
                    let e = parts[2].parse().unwrap_or(0);
                    rtp.set_progress(s, c, e);
                }
            }
        }
        "image/jpeg" | "image/png" => {
            rtp.set_coverart(data);
        }
        "application/x-dmap-tagged" => {
            rtp.set_metadata(data);
        }
        _ => {}
    }
    None
}

// --- AirPlay 2 handlers ---
