use std::sync::Arc;

use crate::crypto::fairplay::FairPlay;
use crate::crypto::pairing::{Pairing, PairingSession};
use crate::crypto::rsa::RsaKey;
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::proto::sdp::Sdp;
use crate::raop::rtp::RaopRtp;
use crate::raop::AudioHandler;

#[cfg(feature = "airplay2")]
use crate::crypto::pairing_homekit::{SrpServer, PairVerifyServer};

/// Per-connection state for RTSP handler dispatch. Equivalent to raop_conn_t.
pub(crate) struct RaopConnection {
    pub raop_rtp: Option<RaopRtp>,
    pub fairplay: FairPlay,
    pub pairing: PairingSession,
    pub local_addr: Vec<u8>,
    #[allow(dead_code)]
    pub remote_addr: Vec<u8>,
    pub nonce: String,
    // Shared references from the server
    pub rsakey: Arc<RsaKey>,
    pub pairing_identity: Arc<Pairing>,
    pub hwaddr: Vec<u8>,
    pub password: String,
    pub handler: Arc<dyn AudioHandler>,
    // AirPlay 2 state
    #[cfg(feature = "airplay2")]
    pub device_id: String,
    #[cfg(feature = "airplay2")]
    pub srp_server: Option<SrpServer>,
    #[cfg(feature = "airplay2")]
    pub pair_verify: Option<PairVerifyServer>,
    #[cfg(feature = "airplay2")]
    pub ap2_shared_secret: Option<Vec<u8>>,
    #[cfg(feature = "airplay2")]
    pub is_ap2: bool,
}

pub(crate) fn handle_none(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    None
}

pub(crate) fn handle_pair_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    if data.len() != 32 { return None; }
    let public_key = conn.pairing_identity.public_key();
    response.add_header("Content-Type", "application/octet-stream");
    Some(public_key.to_vec())
}

pub(crate) fn handle_pair_verify(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    if data.len() < 4 { return None; }

    match data[0] {
        1 => {
            if data.len() != 4 + 32 + 32 { return None; }
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
            if data.len() != 4 + 64 { return None; }
            let sig: &[u8; 64] = data[4..68].try_into().ok()?;
            if conn.pairing.finish(sig).is_err() {
                response.set_disconnect(true);
            }
            None
        }
        _ => None,
    }
}

pub(crate) fn handle_fp_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
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

pub(crate) fn handle_options(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    response.add_header("Public", "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER");
    None
}

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
    if key_bytes.len() >= 16 { aeskey.copy_from_slice(&key_bytes[..16]); }

    let iv_bytes = conn.rsakey.decode(aesiv_str).ok()?;
    if iv_bytes.len() >= 16 { aesiv.copy_from_slice(&iv_bytes[..16]); }

    // Destroy existing RTP session if any
    conn.raop_rtp = None;

    conn.raop_rtp = Some(RaopRtp::new(
        conn.handler.clone(), remote, rtpmap, fmtp, &aeskey, &aesiv,
    ));

    if conn.raop_rtp.is_none() {
        response.set_disconnect(true);
    }
    None
}

pub(crate) fn handle_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let transport = request.header("Transport")?;

    // Check for DACP remote control headers
    if let (Some(dacp_id), Some(active_remote)) = (
        request.header("DACP-ID"),
        request.header("Active-Remote"),
    ) {
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
            tokio::runtime::Handle::current().block_on(
                rtp.start(use_udp, remote_cport, remote_tport)
            )
        }).ok()?;

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

pub(crate) fn handle_get_parameter(
    _conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let content_type = request.header("Content-Type")?;
    if content_type != "text/parameters" { return None; }

    let data = request.data()?;
    let text = std::str::from_utf8(data).ok()?;
    if text.contains("volume") {
        response.add_header("Content-Type", "text/parameters");
        return Some(b"volume: 0.000000\r\n".to_vec());
    }
    None
}

pub(crate) fn handle_set_parameter(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let content_type = request.header("Content-Type")?;
    let data = request.data()?;
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

#[cfg(feature = "airplay2")]
pub(crate) fn handle_pair_setup_ap2(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    response.add_header("Content-Type", "application/octet-stream");

    // Try AP2 TLV-based pairing first; fall back to AP1 if not valid TLV
    let tlv = match crate::crypto::tlv::TlvValues::decode(data) {
        Ok(t) if t.get(6).is_some() => t, // Must have State field
        _ => return handle_pair_setup(conn, request, response),
    };
    let state = *tlv.get(6)?.first()?;

    match state {
        1 => {
            // M1: client initiates pair-setup
            let mut srp = SrpServer::new(None).ok()?;
            srp.process_m1(data).ok()?;
            let m2 = srp.build_m2();
            conn.srp_server = Some(srp);
            Some(m2)
        }
        3 => {
            // M3: client sends A + proof
            let srp = conn.srp_server.as_mut()?;
            let ok = srp.process_m3(data).ok()?;
            let m4 = srp.build_m4().ok()?;
            if ok && srp.is_transient() {
                conn.ap2_shared_secret = srp.shared_secret().map(|s| s.to_vec());
                conn.is_ap2 = true;
            }
            Some(m4)
        }
        5 => {
            // M5: non-transient, client sends encrypted device info
            let srp = conn.srp_server.as_mut()?;
            srp.process_m5(data).ok()?;
            let m6 = srp.build_m6(&conn.device_id).ok()?;
            conn.ap2_shared_secret = Some(srp.session_key().to_vec());
            conn.is_ap2 = true;
            Some(m6)
        }
        _ => None,
    }
}

#[cfg(feature = "airplay2")]
pub(crate) fn handle_pair_verify_ap2(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    response.add_header("Content-Type", "application/octet-stream");

    let tlv = match crate::crypto::tlv::TlvValues::decode(data) {
        Ok(t) if t.get(6).is_some() => t,
        _ => return handle_pair_verify(conn, request, response),
    };
    let state = *tlv.get(6)?.first()?;

    match state {
        1 => {
            let mut pv = PairVerifyServer::new(&conn.device_id);
            let m2 = pv.process_m1_build_m2(data).ok()?;
            conn.pair_verify = Some(pv);
            Some(m2)
        }
        3 => {
            let pv = conn.pair_verify.as_mut()?;
            let m4 = pv.process_m3_build_m4(data).ok()?;
            conn.ap2_shared_secret = pv.shared_secret().map(|s| s.to_vec());
            conn.is_ap2 = true;
            Some(m4)
        }
        _ => None,
    }
}

#[cfg(feature = "airplay2")]
pub(crate) fn handle_get_info(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    use crate::net::mdns;

    let features_lo = mdns::AP2_FEATURES & 0xFFFFFFFF;
    let features_hi = (mdns::AP2_FEATURES >> 32) & 0xFFFFFFFF;

    let (_, vk) = crate::crypto::pairing_homekit::server_keypair(&conn.device_id);
    let pk_hex: String = vk.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();

    let hw = crate::util::hwaddr_airplay(&conn.hwaddr);

    let mut dict = plist::Dictionary::new();
    dict.insert("deviceID".into(), plist::Value::String(hw));
    dict.insert("features".into(), plist::Value::Integer((mdns::AP2_FEATURES as i64).into()));
    dict.insert("model".into(), plist::Value::String(mdns::GLOBAL_MODEL.into()));
    dict.insert("protocolVersion".into(), plist::Value::String(mdns::AP2_PROTOVERS.into()));
    dict.insert("sourceVersion".into(), plist::Value::String(mdns::AP2_SRCVERS.into()));
    dict.insert("statusFlags".into(), plist::Value::Integer((mdns::AP2_STATUS_FLAGS as i64).into()));
    dict.insert("pk".into(), plist::Value::String(pk_hex));

    let mut buf = Vec::new();
    plist::to_writer_binary(&mut buf, &dict).ok()?;

    response.add_header("Content-Type", "application/x-apple-binary-plist");
    Some(buf)
}

#[cfg(feature = "airplay2")]
pub(crate) fn handle_setup_2(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    let plist_val: plist::Value = plist::from_bytes(data).ok()?;
    let dict = plist_val.as_dictionary()?;

    // Check if this is an initial setup (no "streams") or a stream setup
    if dict.get("streams").is_some() {
        // Stream setup — delegate to Phase 9
        return None;
    }

    // Initial setup: check timingProtocol
    let timing = dict.get("timingProtocol")
        .and_then(|v| v.as_string())
        .unwrap_or("None");

    let mut resp_dict = plist::Dictionary::new();

    if timing == "PTP" {
        let mut tpi = plist::Dictionary::new();
        let addrs = vec![plist::Value::String("0.0.0.0".into())];
        tpi.insert("Addresses".into(), plist::Value::Array(addrs));
        tpi.insert("ID".into(), plist::Value::String("0.0.0.0".into()));
        resp_dict.insert("timingPeerInfo".into(), plist::Value::Dictionary(tpi));
    }

    let event_port: u64 = 0;
    resp_dict.insert("eventPort".into(), plist::Value::Integer(event_port.into()));

    let mut buf = Vec::new();
    plist::to_writer_binary(&mut buf, &resp_dict).ok()?;
    response.add_header("Content-Type", "application/x-apple-binary-plist");
    Some(buf)
}
