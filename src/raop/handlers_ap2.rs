//! AP2 RTSP request handlers — pairing, encrypted SETUP, buffered audio, video.

use crate::codec::alac::AlacFormat;
use crate::crypto::pairing_homekit::{self, PairVerifyServer, SrpServer};
#[cfg(feature = "video")]
use crate::error::CryptoError;
use crate::error::{ProtocolError, ShairplayError};
use crate::proto::http::{HttpRequest, HttpResponse};
#[cfg(feature = "video")]
use crate::raop::rtp::RaopRtp;

use super::handlers_ap1::{RaopConnection, bind_addr_for, local_ip_from};

#[cfg(feature = "ap2")]
fn bind_tcp(addr: std::net::SocketAddr) -> Option<tokio::net::TcpListener> {
    let listener = std::net::TcpListener::bind(addr).ok()?;
    listener.set_nonblocking(true).ok()?;
    tokio::net::TcpListener::from_std(listener).ok()
}

#[cfg(feature = "ap2")]
fn bind_udp(addr: std::net::SocketAddr) -> Option<tokio::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr).ok()?;
    socket.set_nonblocking(true).ok()?;
    tokio::net::UdpSocket::from_std(socket).ok()
}

#[cfg(feature = "ap2")]
impl RaopConnection {
    /// Decouple network event stream listener spawning from high-level RTSP handlers.
    pub(crate) fn spawn_event_channel(
        &mut self,
        event_listener: tokio::net::TcpListener,
        event_channel_cipher: crate::crypto::chacha_transport::EncryptedChannel,
        rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        tokio::spawn(async move {
            if let Ok((stream, addr)) = event_listener.accept().await {
                tracing::info!(%addr, "RC event channel client connected");
                crate::raop::event_channel::EventChannel::handle_stream(stream, event_channel_cipher, rx).await;
            }
        });
    }
}

#[cfg(feature = "ap2")]
/// AP2 pair-setup: SRP-6a + HomeKit pairing (M1→M5).
pub(crate) fn handle_pair_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    response.add_header("Content-Type", "application/octet-stream");

    // Try AP2 TLV-based pairing first; fall back to AP1 if not valid TLV
    let tlv = match crate::crypto::tlv::TlvValues::decode(data) {
        Ok(t) if t.get(6).is_some() => t, // Must have State field
        _ => return super::handlers_ap1::handle_pair_setup(conn, request, response),
    };
    let state = *tlv.get(6)?.first()?;

    match state {
        1 => {
            tracing::info!("AP2 pair-setup M1 received");
            let mut srp = match SrpServer::new(conn.shared.pin.as_deref()) {
                Ok(srp) => srp,
                Err(e) => {
                    tracing::warn!("pair-setup M1 init failed: {e}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                    return Some(pairing_homekit::pairing_error_response(2));
                }
            };
            if let Err(e) = srp.process_m1(data) {
                tracing::warn!("pair-setup M1 failed: {e}");
                conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                return Some(pairing_homekit::pairing_error_response(2));
            }
            let m2 = srp.build_m2();
            conn.srp_server = Some(srp);
            Some(m2)
        }
        3 => {
            let srp = conn.srp_server.as_mut()?;
            let ok = srp.process_m3(data).ok()?;
            let m4 = srp.build_m4().ok()?;
            if ok && srp.is_transient() {
                conn.ap2_shared_secret = srp.shared_secret().map(|s| s.to_vec());
                conn.is_ap2 = true;
                tracing::info!("AP2 transient pair-setup complete");
            }
            Some(m4)
        }
        5 => {
            let srp = conn.srp_server.as_mut()?;
            match srp.process_m5(data) {
                Ok((client_id, client_pk)) => {
                    let m6 = srp.build_m6(&conn.shared.device_id, &conn.shared.identity_seed).ok()?;
                    conn.shared.pairing_store.put(&client_id, client_pk);
                    tracing::info!(client_id, "AP2 normal pair-setup complete, client key stored");
                    Some(m6)
                }
                Err(e) => {
                    tracing::warn!("pair-setup M5 failed: {e}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                    let mut tlv = crate::crypto::tlv::TlvValues::new();
                    tlv.add(6, &[6]); // State=6
                    tlv.add(7, &[2]); // Error=Authentication
                    Some(tlv.encode())
                }
            }
        }
        _ => None,
    }
}

#[cfg(feature = "ap2")]
/// AP2 pair-verify: Ed25519 verify + HKDF shared secret derivation.
pub(crate) fn handle_pair_verify(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    response.add_header("Content-Type", "application/octet-stream");

    let tlv = match crate::crypto::tlv::TlvValues::decode(data) {
        Ok(t) if t.get(6).is_some() => t,
        _ => {
            tracing::debug!(
                data_len = data.len(),
                "pair-verify: no TLV state, falling back to legacy"
            );
            return super::handlers_ap1::handle_pair_verify(conn, request, response);
        }
    };
    let state = *tlv.get(6)?.first()?;
    tracing::debug!(state, data_len = data.len(), "pair-verify TLV state");

    match state {
        1 => {
            tracing::info!("AP2 pair-verify M1 received");
            let mut pv = PairVerifyServer::new(&conn.shared.device_id, &conn.shared.identity_seed);
            match pv.process_m1_build_m2(data) {
                Ok(m2) => {
                    tracing::debug!(m2_len = m2.len(), "pair-verify M2 built");
                    // Store ECDH shared secret immediately (needed for video even if M3 never arrives)
                    conn.pair_verify_secret = Some(*pv.ecdh_shared_secret());
                    conn.pair_verify = Some(pv);
                    Some(m2)
                }
                Err(e) => {
                    tracing::warn!("pair-verify M1 failed: {e}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                    None
                }
            }
        }
        3 => {
            let pv = conn.pair_verify.as_mut()?;
            let store = conn.shared.pairing_store.clone();
            match pv.process_m3_build_m4(data, Some(&|id| store.get(id))) {
                Ok(m4) => {
                    conn.pair_verify_secret = pv.shared_secret().copied();
                    conn.ap2_shared_secret = pv.shared_secret().map(|s| s.to_vec());
                    conn.is_ap2 = true;
                    tracing::info!("AP2 pair-verify complete, encrypted RTSP active");
                    Some(m4)
                }
                Err(e) => {
                    tracing::warn!("pair-verify M3 failed: {e}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                    None
                }
            }
        }
        _ => None,
    }
}

#[cfg(feature = "ap2")]
/// AP2 GET /info: return device capabilities as binary plist.
pub(crate) fn handle_info(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    use crate::raop::config;

    let (_, vk) = crate::crypto::pairing_homekit::identity_keypair(&conn.shared.identity_seed);
    let pk_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();

    let hw = crate::util::hwaddr_airplay(&conn.shared.hwaddr);

    let mut dict = plist::Dictionary::new();
    dict.insert("deviceID".into(), plist::Value::String(hw.clone()));
    dict.insert("macAddress".into(), plist::Value::String(hw));
    dict.insert("pi".into(), plist::Value::String(conn.shared.pairing_id.clone()));
    dict.insert("name".into(), plist::Value::String(conn.shared.airplay_name.clone()));
    dict.insert(
        "features".into(),
        plist::Value::Integer(
            (crate::net::features::receiver_features_for_pairing(conn.shared.pin.is_some()) as i64).into(),
        ),
    );
    dict.insert("model".into(), plist::Value::String(config::GLOBAL_MODEL.into()));
    dict.insert(
        "protocolVersion".into(),
        plist::Value::String(config::AP2_PROTOVERS.into()),
    );
    dict.insert("sourceVersion".into(), plist::Value::String(config::AP2_SRCVERS.into()));
    dict.insert(
        "statusFlags".into(),
        plist::Value::Integer(
            (config::ap2_status_flags(conn.shared.pin.is_some(), conn.shared.pairing_store.has_any_pairing()) as i64)
                .into(),
        ),
    );
    dict.insert("pk".into(), plist::Value::String(pk_hex));

    // Video: advertise a display so the iPhone offers screen mirroring
    #[cfg(feature = "video")]
    if conn.shared.video_handler.is_some() {
        let display = plist::Dictionary::from_iter([
            (
                "widthPixels".to_string(),
                plist::Value::Integer(config::MIRRORING_WIDTH.into()),
            ),
            (
                "heightPixels".to_string(),
                plist::Value::Integer(config::MIRRORING_HEIGHT.into()),
            ),
            ("uuid".to_string(), plist::Value::String(config::MIRRORING_UUID.into())),
            (
                "maxFPS".to_string(),
                plist::Value::Integer(config::MIRRORING_FPS.into()),
            ),
            (
                "features".to_string(),
                plist::Value::Integer(config::MIRRORING_FEATURES.into()),
            ),
        ]);
        dict.insert(
            "displays".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(display)]),
        );
    }

    response.set_plist_body(&dict)
}

#[cfg(feature = "ap2")]
/// AP2 `/pair-pin-start`: acknowledge that the accessory is ready for PIN entry.
///
/// macOS sends this after seeing PIN-required mDNS/status flags and aborts
/// normal pair-setup if the receiver answers 404.
pub(crate) fn handle_pair_pin_start(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    response.add_header("Content-Type", "application/octet-stream");
    None
}

#[cfg(feature = "ap2")]
/// Build the `updateInfo` `POST /command` message queued on a freshly-opened
/// event channel (status flags, features, model, versions). Identical for the
/// RC-only and normal event channels.
fn build_update_info_message(requires_pin_pairing: bool, already_paired: bool) -> Option<Vec<u8>> {
    use crate::raop::config;

    let mut update_info = plist::Dictionary::new();
    update_info.insert("type".into(), plist::Value::String("updateInfo".into()));
    let mut value = plist::Dictionary::new();
    value.insert(
        "statusFlags".into(),
        plist::Value::Integer((config::ap2_status_flags(requires_pin_pairing, already_paired) as i64).into()),
    );
    value.insert(
        "features".into(),
        plist::Value::Integer(
            (crate::net::features::receiver_features_for_pairing(requires_pin_pairing) as i64).into(),
        ),
    );
    value.insert("model".into(), plist::Value::String(config::GLOBAL_MODEL.into()));
    value.insert("sourceVersion".into(), plist::Value::String(config::AP2_SRCVERS.into()));
    value.insert(
        "protocolVersion".into(),
        plist::Value::String(config::AP2_PROTOVERS.into()),
    );
    update_info.insert("value".into(), plist::Value::Dictionary(value));

    let mut body = Vec::new();
    plist::to_writer_binary(&mut body, &update_info).ok()?;
    let rtsp = format!(
        "POST /command RTSP/1.0\r\nContent-Length: {}\r\nContent-Type: application/x-apple-binary-plist\r\nCSeq: 0\r\n\r\n",
        body.len()
    );
    let mut msg = rtsp.into_bytes();
    msg.extend_from_slice(&body);
    Some(msg)
}

#[cfg(feature = "ap2")]
/// AP2 SETUP: configure streams (type 96/103/110/130), event channel, timing.
pub(crate) fn handle_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    let plist_val: plist::Value = plist::from_bytes(data).ok()?;
    let dict = plist_val.as_dictionary()?;
    let keys: Vec<_> = dict.keys().collect();
    let has_streams = dict.get("streams").is_some();
    let is_mirror = dict
        .get("isScreenMirroringSession")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);
    let has_ekey = dict.get("ekey").is_some();
    let timing = dict.get("timingProtocol").and_then(|v| v.as_string()).unwrap_or("");
    tracing::info!(?keys, has_streams, is_mirror, has_ekey, timing, "SETUP plist");

    let resp_dict = if let Some(streams) = dict.get("streams").and_then(|v| v.as_array()) {
        setup_streams(conn, streams)?
    } else {
        setup_initial(conn, dict)?
    };

    response.set_plist_body(&resp_dict)
}

#[cfg(feature = "ap2")]
/// Stream SETUP (`streams` present): dispatch by stream type, then add the shared control port.
fn setup_streams(conn: &mut RaopConnection, streams: &[plist::Value]) -> Option<plist::Dictionary> {
    // Stream SETUP — type 96 (realtime) or type 103 (buffered) or type 110 (video)
    let stream0 = streams.first()?.as_dictionary()?;
    let stream_type = stream0.get("type")?.as_unsigned_integer()?;
    let stream_keys: Vec<_> = stream0.keys().collect();
    tracing::info!(stream_type, ?stream_keys, "Stream SETUP");

    let mut stream_resp = plist::Dictionary::new();
    stream_resp.insert("type".into(), plist::Value::Integer(stream_type.into()));

    match stream_type {
        96 => setup_stream_realtime(conn, stream0, &mut stream_resp)?,
        103 => setup_stream_buffered(conn, stream0, &mut stream_resp)?,
        130 => setup_stream_rc(conn, stream0, &mut stream_resp)?,
        #[cfg(feature = "video")]
        110 => setup_stream_video(conn, stream0, &mut stream_resp)?,
        _ => {
            // Type 120 = Apple Music video (animated album art / music videos). Not implemented.
            tracing::warn!(stream_type, "Unknown AP2 stream type");
        }
    }

    // Control port (shared across streams)
    let ctrl_sock = std::net::UdpSocket::bind(bind_addr_for(conn)).ok()?;
    let ctrl_port = ctrl_sock.local_addr().ok()?.port();
    drop(ctrl_sock);
    stream_resp.insert("controlPort".into(), plist::Value::Integer(ctrl_port.into()));

    let mut resp_dict = plist::Dictionary::new();
    resp_dict.insert(
        "streams".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream_resp)]),
    );
    Some(resp_dict)
}

#[cfg(feature = "ap2")]
/// Initial SETUP (no `streams`): capture FairPlay keys (video), establish the event
/// channel and timing, and return the response dictionary.
fn setup_initial(conn: &mut RaopConnection, dict: &plist::Dictionary) -> Option<plist::Dictionary> {
    let mut resp_dict = plist::Dictionary::new();
    let timing = dict.get("timingProtocol").and_then(|v| v.as_string()).unwrap_or("None");

    // Capture FairPlay encryption keys for video.
    // The audio connection provides ekey (72 bytes, FairPlay-encrypted) + eiv (16 bytes).
    // The video connection (separate RTSP session) reads them from shared state.
    #[cfg(feature = "video")]
    {
        if let Some(ekey_data) = dict.get("ekey").and_then(|v| v.as_data())
            && ekey_data.len() == 72
            && let Ok(input) = <[u8; 72]>::try_from(ekey_data)
        {
            match conn.fairplay.decrypt(&input) {
                Ok(fp_key) => {
                    // SHA-512 two-step: hash FairPlay key with ECDH shared secret
                    // Stage 2: hash with ECDH only if AP2 pairing was used.
                    // With UxPlay-style features (bit 27 off), no pairing occurs
                    // and the raw FairPlay key is used directly.
                    let derived = if let Some(ref secret) = conn.ap2_shared_secret {
                        use sha2::{Digest, Sha512};
                        let mut hasher = Sha512::new();
                        hasher.update(fp_key);
                        hasher.update(secret);
                        let hash = hasher.finalize();
                        let mut key = [0u8; 16];
                        key.copy_from_slice(&hash[..16]);
                        key
                    } else {
                        fp_key
                    };
                    conn.ekey = Some(derived);
                    // Store in shared state for the video connection
                    if let Ok(mut shared) = conn.shared.video_ekey.write() {
                        *shared = Some(derived);
                        tracing::debug!("Video ekey stored in shared state");
                    }
                }
                Err(e) => {
                    tracing::warn!("FairPlay decrypt failed: {e:?}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                }
            }
        }
        if let Some(eiv_data) = dict.get("eiv").and_then(|v| v.as_data())
            && let Ok(iv) = <[u8; 16]>::try_from(eiv_data)
        {
            conn.eiv = Some(iv);
            if let Ok(mut shared) = conn.shared.video_eiv.write() {
                *shared = Some(iv);
                tracing::debug!("Video eiv stored in shared state");
            }
        }
    }

    let is_rc_only = dict
        .get("isRemoteControlOnly")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    if is_rc_only {
        tracing::info!("Remote Control Only connection - establishing event channel");

        let event_port_resp = if let Some(shared_secret) = conn.ap2_shared_secret.as_ref() {
            let event_listener = bind_tcp(bind_addr_for(conn))?;
            let event_port = event_listener.local_addr().ok()?.port();

            if let Ok(event_channel_cipher) = crate::crypto::chacha_transport::EncryptedChannel::events(shared_secret) {
                let event_sender = {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

                    if let Some(msg) = build_update_info_message(
                        conn.shared.pin.is_some(),
                        conn.shared.pairing_store.has_any_pairing(),
                    ) {
                        let _ = tx.send(msg);
                        tracing::debug!("updateInfo queued for RC event channel");
                    }

                    let sender = crate::raop::event_channel::EventSender::from_tx(tx);
                    conn.spawn_event_channel(event_listener, event_channel_cipher, rx);
                    sender
                };
                conn.event_sender = Some(event_sender);
            }
            event_port as u64
        } else {
            0
        };

        resp_dict.insert("eventPort".into(), plist::Value::Integer(event_port_resp.into()));

        return Some(resp_dict);
    }

    if timing == "PTP" {
        let mut tpi = plist::Dictionary::new();
        let self_ip = local_ip_from(conn).to_string();
        tracing::debug!(self_ip, "timingPeerInfo address");
        let addrs = vec![plist::Value::String(self_ip.clone())];
        tpi.insert("Addresses".into(), plist::Value::Array(addrs));
        tpi.insert("ID".into(), plist::Value::String(self_ip));
        resp_dict.insert("timingPeerInfo".into(), plist::Value::Dictionary(tpi));
    }

    // Bind event port on same address family as the client connection
    let event_listener = bind_tcp(bind_addr_for(conn))?;
    let event_port = event_listener.local_addr().ok()?.port();
    tracing::info!(event_port, "Event channel opened");

    // Derive event channel encryption keys from shared secret (AP2 only).
    // In legacy mode there's no shared secret — skip the encrypted event channel.
    if let Some(shared_secret) = conn.ap2_shared_secret.as_ref()
        && let Ok(event_channel_cipher) = crate::crypto::chacha_transport::EncryptedChannel::events(shared_secret)
    {
        // Spawn bidirectional event channel
        let event_sender = {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

            // Queue updateInfo so it's sent immediately when client connects
            if let Some(msg) =
                build_update_info_message(conn.shared.pin.is_some(), conn.shared.pairing_store.has_any_pairing())
            {
                let _ = tx.send(msg);
                tracing::debug!("updateInfo queued for event channel");
            }

            let sender = crate::raop::event_channel::EventSender::from_tx(tx);
            tokio::spawn(async move {
                if let Ok((stream, addr)) = event_listener.accept().await {
                    tracing::info!(%addr, "Event channel client connected");
                    crate::raop::event_channel::EventChannel::handle_stream(stream, event_channel_cipher, rx).await;
                }
            });
            sender
        };
        conn.event_sender = Some(event_sender);
    }

    // In legacy mode, event channel is not encrypted — return port 0 like UxPlay.
    let event_port_resp = if conn.ap2_shared_secret.is_some() {
        event_port as u64
    } else {
        0
    };
    resp_dict.insert("eventPort".into(), plist::Value::Integer(event_port_resp.into()));

    // Legacy mode: bind a standalone NTP timing socket and return its port.
    // The iPhone needs NTP sync before it sends the stream SETUP.
    // RaopRtp is created later in the stream SETUP with real ALAC parameters.
    #[cfg(feature = "video")]
    let timing_port = if !conn.is_ap2 && conn.ekey.is_some() {
        let timing_rport = dict
            .get("timingPort")
            .and_then(|v| v.as_unsigned_integer())
            .unwrap_or(0) as u16;
        let tport = bind_udp(bind_addr_for(conn))
            .and_then(|tsock| {
                let local_port = tsock.local_addr().ok()?.port();
                let mut remote_timing = conn.remote_socket;
                remote_timing.set_port(timing_rport);
                crate::raop::ntp::spawn_ntp_responder(tsock, remote_timing);
                Some(local_port)
            })
            .unwrap_or(0);
        tracing::debug!(tport, timing_rport, "Legacy video: NTP timing socket bound");
        tport
    } else {
        0
    };
    #[cfg(not(feature = "video"))]
    let timing_port: u16 = 0;

    resp_dict.insert("timingPort".into(), plist::Value::Integer((timing_port as u64).into()));

    Some(resp_dict)
}

#[cfg(feature = "ap2")]
/// Stream type 96 — realtime ALAC (ChaCha20 per-packet), or legacy AES-CBC ALAC under `video`.
fn setup_stream_realtime(
    conn: &mut RaopConnection,
    stream0: &plist::Dictionary,
    stream_resp: &mut plist::Dictionary,
) -> Option<()> {
    let sr = stream0.get("sr").and_then(|v| v.as_unsigned_integer()).unwrap_or(44100);
    let spf = stream0.get("spf").and_then(|v| v.as_unsigned_integer()).unwrap_or(352);
    let audio_format = stream0
        .get("audioFormat")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0) as u32;
    let alac_format = AlacFormat::from_audio_format(audio_format).unwrap_or(AlacFormat {
        sample_rate: sr as u32,
        bit_depth: 16,
        channels: 2,
    });
    let shk = stream0.get("shk").and_then(|v| v.as_data()).unwrap_or(&[]);

    if shk.len() == 32 {
        // AP2 realtime ALAC — ChaCha20-Poly1305 per-packet encryption.
        tracing::info!(
            stream_type = 96,
            sample_rate = sr,
            samples_per_frame = spf,
            audio_format,
            alac_format = ?alac_format,
            "AP2 realtime ALAC (ChaCha20)"
        );
        if AlacFormat::from_audio_format(audio_format).is_none() {
            tracing::warn!(
                audio_format,
                sample_rate = sr,
                "Unknown AP2 realtime ALAC audioFormat; falling back to SETUP sr and 16-bit stereo"
            );
        }
        let mut shk_arr = [0u8; 32];
        shk_arr.copy_from_slice(shk);

        let socket = bind_udp(bind_addr_for(conn))?;
        let audio_port = socket.local_addr().ok()?.port();

        let handler = conn.shared.handler.clone();
        let output_config = crate::raop::realtime_audio::OutputConfig {
            source_sample_rate: alac_format.sample_rate,
            samples_per_frame: spf as u32,
            channels: alac_format.channels,
            bit_depth: alac_format.bit_depth,
            sample_rate: conn.shared.output_sample_rate,
            max_channels: conn.shared.output_max_channels,
        };

        let handle = tokio::spawn(crate::raop::realtime_audio::run(
            socket,
            shk_arr,
            handler,
            output_config,
        ));
        conn.shared.set_active_audio(Box::new(move || handle.abort()));

        stream_resp.insert("dataPort".into(), plist::Value::Integer(audio_port.into()));
    } else {
        // Legacy ALAC — only available with video feature (UxPlay-style features).
        #[cfg(feature = "video")]
        {
            tracing::info!(stream_type = 96, sample_rate = sr, "Legacy ALAC (AES-CBC via ekey)");

            let aes_key = conn.ekey.unwrap_or([0u8; 16]);
            let aes_iv = conn.eiv.unwrap_or([0u8; 16]);
            let fmtp = format!("96 {spf} 0 16 40 10 14 2 255 0 0 {sr}");
            conn.raop_rtp = RaopRtp::new(
                conn.shared.handler.clone(),
                crate::raop::rtp::RtpConfig {
                    remote: conn.remote_socket.ip().to_string(),
                    local_addr: local_ip_from(conn),
                    rtpmap: "96 AppleLossless".to_string(),
                    fmtp,
                    aes_key,
                    aes_iv,
                    output_sample_rate: conn.shared.output_sample_rate,
                    remote_socket: conn.remote_socket,
                },
            );
            if let Some(rtp) = &mut conn.raop_rtp {
                let control_port = stream0
                    .get("controlPort")
                    .and_then(|v| v.as_unsigned_integer())
                    .unwrap_or(0) as u16;
                let (cport, _tport, dport) = rtp.start(true, control_port, 0).ok()?;
                stream_resp.insert("dataPort".into(), plist::Value::Integer(dport.into()));
                stream_resp.insert("controlPort".into(), plist::Value::Integer(cport.into()));
            }
        }
        #[cfg(not(feature = "video"))]
        {
            tracing::warn!("Type 96 without shk — requires video feature");
            conn.shared
                .handler
                .on_error(&ShairplayError::Protocol(ProtocolError::InvalidRtsp(
                    "realtime (type 96) SETUP requires a shared key or the video feature".into(),
                )));
            return None;
        }
    }
    Some(())
}

#[cfg(feature = "ap2")]
/// Stream type 103 — buffered audio over TCP with a timed playout buffer.
fn setup_stream_buffered(
    conn: &mut RaopConnection,
    stream0: &plist::Dictionary,
    stream_resp: &mut plist::Dictionary,
) -> Option<()> {
    let audio_format = stream0
        .get("audioFormat")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0);
    tracing::info!(stream_type = 103, audio_format, "AP2 buffered audio stream setup");

    let shk = stream0.get("shk").and_then(|v| v.as_data()).unwrap_or(&[]);
    if shk.len() != 32 {
        tracing::warn!(len = shk.len(), "Invalid shk length");
        conn.shared
            .handler
            .on_error(&ShairplayError::Protocol(ProtocolError::InvalidRtsp(format!(
                "buffered (type 103) SETUP: invalid shk length {}",
                shk.len()
            ))));
        return None;
    }
    let mut shk_arr = [0u8; 32];
    shk_arr.copy_from_slice(shk);

    let listener = bind_tcp(bind_addr_for(conn))?;
    let audio_port = listener.local_addr().ok()?.port();
    tracing::info!(audio_port, "Buffered audio TCP port opened");

    let handler = conn.shared.handler.clone();
    let output_config = crate::raop::buffered_audio::OutputConfig {
        sample_rate: conn.shared.output_sample_rate,
        max_channels: conn.shared.output_max_channels,
    };

    let proc = crate::raop::buffered_audio::BufferedAudioProcessor { listener };
    let cmd_tx = proc.start(shk_arr, output_config, handler);
    conn.playout_cmd = Some(cmd_tx.clone());
    conn.shared.set_active_audio(Box::new(move || {
        let _ = cmd_tx.send(crate::raop::buffered_audio::PlayoutCommand::Stop);
    }));

    stream_resp.insert("dataPort".into(), plist::Value::Integer(audio_port.into()));
    stream_resp.insert("audioBufferSize".into(), plist::Value::Integer(0x10_0000_i64.into())); // 1 MB
    Some(())
}

#[cfg(feature = "ap2")]
/// Stream type 130 — remote-control data channel (acknowledged on PTP, opened on RC).
fn setup_stream_rc(
    conn: &mut RaopConnection,
    stream0: &plist::Dictionary,
    stream_resp: &mut plist::Dictionary,
) -> Option<()> {
    tracing::info!("Remote Control stream setup (type 130)");

    // On PTP connections, type 130 is just acknowledged.
    // On RC connections, it sets up an encrypted data channel.
    if let Some(_seed) = stream0.get("seed").and_then(|v| v.as_unsigned_integer()) {
        let data_listener = bind_tcp(bind_addr_for(conn))?;
        let data_port = data_listener.local_addr().ok()?.port();
        tracing::debug!(data_port, "RC data channel opened");

        tokio::spawn(async move {
            if let Ok((_, addr)) = data_listener.accept().await {
                tracing::info!(%addr, "RC data channel client connected");
            }
        });

        stream_resp.insert("streamID".into(), plist::Value::Integer(1_i64.into()));
        stream_resp.insert("dataPort".into(), plist::Value::Integer(data_port.into()));
    } else {
        stream_resp.insert("streamID".into(), plist::Value::Integer(1_i64.into()));
    }
    Some(())
}

#[cfg(feature = "video")]
/// Stream type 110 — screen-mirroring video. Derives the per-stream AES key/IV
/// (see [`crate::crypto::video_key`]) and spawns the video receiver.
fn setup_stream_video(
    conn: &mut RaopConnection,
    stream0: &plist::Dictionary,
    stream_resp: &mut plist::Dictionary,
) -> Option<()> {
    let stream_connection_id = stream0
        .get("streamConnectionID")
        .and_then(|v| v.as_signed_integer())
        .unwrap_or(0) as u64;
    tracing::info!(stream_type = 110, stream_connection_id, "AP2 video stream setup");

    // Seed is either the audio AES key directly (Stage-3) or
    // eaesKey = SHA-512(fairplay_key ‖ ecdh) (full FairPlay + ECDH path).
    let (ekey, eiv) = if let Some(aeskey_audio) = conn
        .ekey
        .or_else(|| conn.shared.video_ekey.read().ok()?.as_ref().copied())
    {
        tracing::debug!("Video key: Stage 3 derivation from aeskey_audio");
        crate::crypto::video_key::derive_stream_key_iv(&aeskey_audio, stream_connection_id)
    } else if let Some(ecdh) = conn.pair_verify_secret.as_ref() {
        let fp_key = conn.shared.video_ekey.read().ok().and_then(|k| *k);
        if let Some(fp_key) = fp_key {
            let eaes_key = crate::crypto::video_key::derive_eaes_key(&fp_key, ecdh);
            let (key, iv) = crate::crypto::video_key::derive_stream_key_iv(&eaes_key, stream_connection_id);
            tracing::debug!(
                derived_key = %hex::encode(key),
                derived_iv = %hex::encode(iv),
                "Video key: 3-step derivation (FairPlay + ECDH)"
            );
            (key, iv)
        } else {
            // iOS 18+ with HomeKit pairing does not send ekey; derivation is unsolved
            // (see AP2-STATUS.md). Decline the stream rather than installing a zeroed key
            // and feeding the app undecryptable "garbage" NAL units.
            tracing::warn!("Video: no ekey available — iOS 18 HomeKit video decryption unsupported; declining stream");
            conn.shared
                .handler
                .on_error(&ShairplayError::Crypto(CryptoError::FairPlay(
                    "video stream key derivation: no ekey (iOS 18 HomeKit unsupported)".into(),
                )));
            return None;
        }
    } else {
        tracing::warn!("Video stream: no encryption keys available");
        conn.shared
            .handler
            .on_error(&ShairplayError::Crypto(CryptoError::FairPlay(
                "video stream key derivation: no encryption keys available".into(),
            )));
        return None;
    };

    let cipher = crate::crypto::video_cipher::VideoCipher::new(&ekey, &eiv);

    let listener = bind_tcp(bind_addr_for(conn))?;
    let video_port = listener.local_addr().ok()?.port();
    tracing::info!(video_port, "Video stream TCP port opened");

    if let Some(vh) = &conn.shared.video_handler {
        let session = vh.video_init();
        tokio::spawn(crate::raop::video_stream::run(listener, cipher, session));
    }

    stream_resp.insert("dataPort".into(), plist::Value::Integer(video_port.into()));
    Some(())
}

#[cfg(feature = "ap2")]
/// AP2 RECORD: start buffered audio playout.
pub(crate) fn handle_record(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    tracing::debug!("RECORD");
    response.add_header("Audio-Latency", "0");
    None
}

#[cfg(feature = "ap2")]
/// AP2 SETRATEANCHORTI: set PTP anchor for timed playout.
pub(crate) fn handle_set_rate_anchor_time(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    let plist_val: plist::Value = plist::from_bytes(data).ok()?;
    let dict = plist_val.as_dictionary()?;

    let rate = dict.get("rate").and_then(|v| v.as_unsigned_integer()).unwrap_or(0) as u32;
    let rtp_time = dict.get("rtpTime").and_then(|v| v.as_unsigned_integer()).unwrap_or(0) as u32;
    let net_secs = dict
        .get("networkTimeSecs")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0);
    let net_frac = dict
        .get("networkTimeFrac")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0);

    // Convert network time to nanoseconds (saturating: net_secs is peer-supplied).
    let frac_ns = ((net_frac >> 32) * 1_000_000_000) >> 32;
    let anchor_time_ns = net_secs.saturating_mul(1_000_000_000).saturating_add(frac_ns);

    if rate & 1 != 0 {
        tracing::info!(rtp_time, anchor_time_ns, "AP2 play start");
    } else {
        tracing::info!("AP2 play pause");
    }

    if let Some(cmd) = &conn.playout_cmd {
        let _ = cmd.send(crate::raop::buffered_audio::PlayoutCommand::SetRate {
            anchor_rtp: rtp_time,
            anchor_time_ns,
            rate,
        });
    }

    None
}

#[cfg(feature = "ap2")]
/// AP2 SETPEERS: receive PTP peer addresses (informational).
pub(crate) fn handle_set_peers(
    _conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    if let Some(data) = request.data()
        && let Ok(plist_val) = plist::from_bytes::<plist::Value>(data)
        && let Some(arr) = plist_val.as_array()
    {
        let peers: Vec<&str> = arr.iter().filter_map(|v| v.as_string()).collect();
        tracing::debug!(?peers, "SETPEERS");
    }
    None
}

#[cfg(feature = "ap2")]
/// AP2 FLUSHBUFFERED: flush playout buffer up to sequence/timestamp.
pub(crate) fn handle_flush_buffered(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    if let Some(data) = request.data()
        && let Ok(plist_val) = plist::from_bytes::<plist::Value>(data)
    {
        let dict = plist_val.as_dictionary();
        let from_seq = dict
            .and_then(|d| d.get("flushFromSeq"))
            .and_then(|v| v.as_unsigned_integer())
            .unwrap_or(0) as u32;
        let until_seq = dict
            .and_then(|d| d.get("flushUntilSeq"))
            .and_then(|v| v.as_unsigned_integer())
            .unwrap_or(0) as u32;
        tracing::debug!(from_seq, until_seq, "FLUSHBUFFERED");
        if let Some(cmd) = &conn.playout_cmd {
            let _ = cmd.send(crate::raop::buffered_audio::PlayoutCommand::Flush { from_seq, until_seq });
        }
    }
    None
}

// --- AP2 POST sub-handlers ---

#[cfg(feature = "ap2")]
/// AP2 POST /feedback: empty response (required by protocol).
pub(crate) fn handle_feedback(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    // Only return stream info when audio is actually playing (matches shairport-sync)
    #[cfg(feature = "ap2")]
    if conn.playout_cmd.is_some() {
        let mut stream_dict = plist::Dictionary::new();
        stream_dict.insert("type".into(), plist::Value::Integer(103_i64.into()));
        stream_dict.insert("sr".into(), plist::Value::Real(44100.0));
        let mut resp_dict = plist::Dictionary::new();
        resp_dict.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream_dict)]),
        );
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, &resp_dict).ok()?;
        response.add_header("Content-Type", "application/x-apple-binary-plist");
        return Some(buf);
    }
    let _ = conn;
    None
}

#[cfg(feature = "ap2")]
/// AP2 POST /command: forward binary plist commands to event channel.
pub(crate) fn handle_command(
    _conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    if let Some(data) = request.data()
        && let Ok(plist_val) = plist::from_bytes::<plist::Value>(data)
        && let Some(dict) = plist_val.as_dictionary()
    {
        let cmd_type = dict.get("type").and_then(|v| v.as_string()).unwrap_or("unknown");
        tracing::debug!(cmd_type, "POST /command");
        if cmd_type == "updateMRSupportedCommands" {}
    }
    None
}

#[cfg(feature = "ap2")]
/// AP2 POST /audioMode: acknowledge audio mode change.
pub(crate) fn handle_audio_mode(
    _conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    if let Some(data) = request.data()
        && let Ok(plist_val) = plist::from_bytes::<plist::Value>(data)
        && let Some(dict) = plist_val.as_dictionary()
    {
        let mode = dict.get("audioMode").and_then(|v| v.as_string()).unwrap_or("unknown");
        tracing::debug!(mode, "POST /audioMode");
    }
    None
}
