//! AP2 RTSP request handlers — pairing, encrypted SETUP, buffered audio, video.

use crate::crypto::pairing_homekit::{PairVerifyServer, SrpServer};
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::raop::rtp::RaopRtp;

use super::handlers_ap1::{RaopConnection, bind_addr_for, local_ip_from};

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
            let mut srp = SrpServer::new(conn.pin.as_deref()).ok()?;
            srp.process_m1(data).ok()?;
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
                    let m6 = srp.build_m6(&conn.device_id).ok()?;
                    conn.pairing_store.put(&client_id, client_pk);
                    tracing::info!(client_id, "AP2 normal pair-setup complete, client key stored");
                    conn.ap2_shared_secret = srp.session_key().map(|s| s.to_vec());
                    conn.is_ap2 = true;
                    Some(m6)
                }
                Err(e) => {
                    tracing::warn!("pair-setup M5 failed: {e}");
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
            let mut pv = PairVerifyServer::new(&conn.device_id);
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
                    None
                }
            }
        }
        3 => {
            let pv = conn.pair_verify.as_mut()?;
            let store = conn.pairing_store.clone();
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
    use crate::net::mdns;

    let _features_lo = crate::net::features::receiver_features() & 0xFFFFFFFF;
    let _features_hi = (crate::net::features::receiver_features() >> 32) & 0xFFFFFFFF;

    let (_, vk) = crate::crypto::pairing_homekit::server_keypair(&conn.device_id);
    let pk_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();

    let hw = crate::util::hwaddr_airplay(&conn.hwaddr);

    let mut dict = plist::Dictionary::new();
    dict.insert("deviceID".into(), plist::Value::String(hw));
    dict.insert(
        "features".into(),
        plist::Value::Integer((crate::net::features::receiver_features() as i64).into()),
    );
    dict.insert("model".into(), plist::Value::String(mdns::GLOBAL_MODEL.into()));
    dict.insert(
        "protocolVersion".into(),
        plist::Value::String(mdns::AP2_PROTOVERS.into()),
    );
    dict.insert("sourceVersion".into(), plist::Value::String(mdns::AP2_SRCVERS.into()));
    dict.insert(
        "statusFlags".into(),
        plist::Value::Integer((mdns::AP2_STATUS_FLAGS as i64).into()),
    );
    dict.insert("pk".into(), plist::Value::String(pk_hex));

    // Video: advertise a display so the iPhone offers screen mirroring
    #[cfg(feature = "video")]
    if conn.video_handler.is_some() {
        let display = plist::Dictionary::from_iter([
            ("widthPixels".to_string(), plist::Value::Integer(1920.into())),
            ("heightPixels".to_string(), plist::Value::Integer(1080.into())),
            ("uuid".to_string(), plist::Value::String("shairplay_display".into())),
            ("maxFPS".to_string(), plist::Value::Integer(60.into())),
            ("features".to_string(), plist::Value::Integer(2.into())),
        ]);
        dict.insert(
            "displays".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(display)]),
        );
    }

    let mut buf = Vec::new();
    plist::to_writer_binary(&mut buf, &dict).ok()?;

    response.add_header("Content-Type", "application/x-apple-binary-plist");
    Some(buf)
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

    let mut resp_dict = plist::Dictionary::new();

    if let Some(streams) = dict.get("streams").and_then(|v| v.as_array()) {
        // Stream SETUP — type 96 (realtime) or type 103 (buffered) or type 110 (video)
        let stream0 = streams.first()?.as_dictionary()?;
        let stream_type = stream0.get("type")?.as_unsigned_integer()?;
        let stream_keys: Vec<_> = stream0.keys().collect();
        tracing::info!(stream_type, ?stream_keys, "Stream SETUP");

        let mut stream_resp = plist::Dictionary::new();
        stream_resp.insert("type".into(), plist::Value::Integer(stream_type.into()));

        match stream_type {
            96 => {
                let sr = stream0.get("sr").and_then(|v| v.as_unsigned_integer()).unwrap_or(44100);
                let spf = stream0.get("spf").and_then(|v| v.as_unsigned_integer()).unwrap_or(352);
                let shk = stream0.get("shk").and_then(|v| v.as_data()).unwrap_or(&[]);

                if shk.len() == 32 {
                    // AP2 realtime ALAC — ChaCha20-Poly1305 per-packet encryption.
                    tracing::info!(stream_type = 96, sample_rate = sr, "AP2 realtime ALAC (ChaCha20)");
                    let mut shk_arr = [0u8; 32];
                    shk_arr.copy_from_slice(shk);

                    let bind_addr = bind_addr_for(conn);
                    let socket = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(tokio::net::UdpSocket::bind(&bind_addr))
                    })
                    .ok()?;
                    let audio_port = socket.local_addr().ok()?.port();

                    let handler = conn.handler.clone();
                    let output_config = crate::raop::realtime_audio::OutputConfig {
                        sample_rate: conn.output_sample_rate,
                        max_channels: conn.output_max_channels,
                    };

                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().spawn(crate::raop::realtime_audio::run(
                            socket,
                            shk_arr,
                            handler,
                            output_config,
                        ));
                    });

                    stream_resp.insert("dataPort".into(), plist::Value::Integer(audio_port.into()));
                } else {
                    // Legacy ALAC — only available with video feature (UxPlay-style features).
                    #[cfg(feature = "video")]
                    {
                        tracing::info!(stream_type = 96, sample_rate = sr, "Legacy ALAC (AES-CBC via ekey)");

                        let aes_key = conn.ekey.unwrap_or([0u8; 16]);
                        let aes_iv = conn.eiv.unwrap_or([0u8; 16]);
                        let fmtp = format!("96 {spf} 0 16 40 10 14 2 255 0 0 {sr}");
                        conn.raop_rtp = Some(RaopRtp::new(
                            conn.handler.clone(),
                            crate::raop::rtp::RtpConfig {
                                remote: conn.remote_socket.ip().to_string(),
                                local_addr: local_ip_from(conn),
                                rtpmap: "96 AppleLossless".to_string(),
                                fmtp,
                                aes_key,
                                aes_iv,
                                output_sample_rate: conn.output_sample_rate,
                                remote_socket: conn.remote_socket,
                            },
                        ));
                        if let Some(rtp) = &mut conn.raop_rtp {
                            let control_port = stream0
                                .get("controlPort")
                                .and_then(|v| v.as_unsigned_integer())
                                .unwrap_or(0) as u16;
                            let (cport, _tport, dport) = tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current().block_on(rtp.start(true, control_port, 0))
                            })
                            .ok()?;
                            stream_resp.insert("dataPort".into(), plist::Value::Integer(dport.into()));
                            stream_resp.insert("controlPort".into(), plist::Value::Integer(cport.into()));
                        }
                    } // cfg(feature = "video")
                    #[cfg(not(feature = "video"))]
                    {
                        tracing::warn!("Type 96 without shk — requires video feature");
                        return None;
                    }
                }
            }
            103 => {
                // Buffered audio — bind TCP port and spawn processor
                let audio_format = stream0
                    .get("audioFormat")
                    .and_then(|v| v.as_unsigned_integer())
                    .unwrap_or(0);
                tracing::info!(stream_type = 103, audio_format, "AP2 buffered audio stream setup");

                // Get the shared key from the stream setup
                let shk = stream0.get("shk").and_then(|v| v.as_data()).unwrap_or(&[]);
                if shk.len() != 32 {
                    tracing::warn!(len = shk.len(), "Invalid shk length");
                    return None;
                }
                let mut shk_arr = [0u8; 32];
                shk_arr.copy_from_slice(shk);

                let bind_addr = bind_addr_for(conn);
                let listener = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(tokio::net::TcpListener::bind(bind_addr))
                })
                .ok()?;
                let audio_port = listener.local_addr().ok()?.port();
                tracing::info!(audio_port, "Buffered audio TCP port opened");

                let handler = conn.handler.clone();
                let output_config = crate::raop::buffered_audio::OutputConfig {
                    sample_rate: conn.output_sample_rate,
                    max_channels: conn.output_max_channels,
                };

                let cmd_tx = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let proc = crate::raop::buffered_audio::BufferedAudioProcessor {
                            listener,
                            port: audio_port,
                        };
                        proc.start(shk_arr, output_config, handler)
                    })
                });
                conn.playout_cmd = Some(cmd_tx);

                stream_resp.insert("dataPort".into(), plist::Value::Integer(audio_port.into()));
                stream_resp.insert("audioBufferSize".into(), plist::Value::Integer(0x10_0000_i64.into()));
                // 1 MB
            }
            130 => {
                // Remote Control data channel
                tracing::info!("Remote Control stream setup (type 130)");

                // On PTP connections, type 130 is just acknowledged
                // On RC connections, it sets up an encrypted data channel
                if let Some(_seed) = stream0.get("seed").and_then(|v| v.as_unsigned_integer()) {
                    let bind_addr = bind_addr_for(conn);
                    let data_listener = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(tokio::net::TcpListener::bind(bind_addr))
                    })
                    .ok()?;
                    let data_port = data_listener.local_addr().ok()?.port();
                    tracing::debug!(data_port, "RC data channel opened");

                    // Spawn listener (just accept + log for now)
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().spawn(async move {
                            if let Ok((_, addr)) = data_listener.accept().await {
                                tracing::info!(%addr, "RC data channel client connected");
                            }
                        })
                    });

                    stream_resp.insert("streamID".into(), plist::Value::Integer(1_i64.into()));
                    stream_resp.insert("dataPort".into(), plist::Value::Integer(data_port.into()));
                } else {
                    stream_resp.insert("streamID".into(), plist::Value::Integer(1_i64.into()));
                }
            }
            #[cfg(feature = "video")]
            110 => {
                // Video (screen mirroring) stream
                let stream_connection_id = stream0
                    .get("streamConnectionID")
                    .and_then(|v| v.as_signed_integer())
                    .unwrap_or(0) as u64;
                tracing::info!(stream_type = 110, stream_connection_id, "AP2 video stream setup");

                // Video decryption key derivation (from SteeBono/airplayreceiver):
                // Step 1: eaesKey = SHA-512(fairplay_decrypted_key, ecdh_shared)[0..16]
                // Step 2: streamKey = SHA-512("AirPlayStreamKey{id}", eaesKey)[0..16]
                // Step 3: streamIV = SHA-512("AirPlayStreamIV{id}", eaesKey)[0..16]
                //
                // fairplay_decrypted_key comes from ekey (audio SETUP) or shared state.
                // ecdh_shared comes from pair-verify M1 (X25519 key agreement).
                let (ekey, eiv) = if let Some(aeskey_audio) = conn
                    .ekey
                    .or_else(|| conn.shared_video_ekey.read().ok()?.as_ref().copied())
                {
                    // Stage 3: derive stream key/IV from aeskey_audio + streamConnectionID
                    use sha2::{Digest, Sha512};
                    let mut h1 = Sha512::new();
                    h1.update(format!("AirPlayStreamKey{stream_connection_id}").as_bytes());
                    h1.update(aeskey_audio);
                    let key_hash = h1.finalize();
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&key_hash[..16]);

                    let mut h2 = Sha512::new();
                    h2.update(format!("AirPlayStreamIV{stream_connection_id}").as_bytes());
                    h2.update(aeskey_audio);
                    let iv_hash = h2.finalize();
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(&iv_hash[..16]);

                    tracing::debug!("Video key: Stage 3 derivation from aeskey_audio");
                    (key, iv)
                } else if let Some(ecdh) = conn.pair_verify_secret.as_ref() {
                    use sha2::{Digest, Sha512};

                    // Get FairPlay decrypted key from shared state or this connection
                    let fp_key = conn.shared_video_ekey.read().ok().and_then(|k| *k);

                    if let Some(fp_key) = fp_key {
                        // Full 3-step derivation
                        let mut h0 = Sha512::new();
                        h0.update(fp_key);
                        h0.update(ecdh);
                        let eaes = h0.finalize();
                        let eaes_key = &eaes[..16];

                        let mut h1 = Sha512::new();
                        h1.update(format!("AirPlayStreamKey{stream_connection_id}").as_bytes());
                        h1.update(eaes_key);
                        let key_hash = h1.finalize();
                        let mut key = [0u8; 16];
                        key.copy_from_slice(&key_hash[..16]);

                        let mut h2 = Sha512::new();
                        h2.update(format!("AirPlayStreamIV{stream_connection_id}").as_bytes());
                        h2.update(eaes_key);
                        let iv_hash = h2.finalize();
                        let mut iv = [0u8; 16];
                        iv.copy_from_slice(&iv_hash[..16]);

                        tracing::debug!(
                            derived_key = %hex::encode(key),
                            derived_iv = %hex::encode(iv),
                            "Video key: 3-step derivation (FairPlay + ECDH)"
                        );
                        (key, iv)
                    } else {
                        // iOS 18+ with HomeKit pairing does not send ekey.
                        // The video key derivation for this case is unsolved.
                        // See VIDEO-RESEARCH.md for details.
                        tracing::warn!("Video: no ekey available — iOS 18 HomeKit video decryption unsupported");
                        tracing::warn!("Video stream will connect but frames cannot be decrypted");
                        // Use zeroed key — stream will connect but produce garbage
                        ([0u8; 16], [0u8; 16])
                    }
                } else {
                    tracing::warn!("Video stream: no encryption keys available");
                    return None;
                };

                let cipher = crate::crypto::video_cipher::VideoCipher::new(&ekey, &eiv);

                let bind_addr = bind_addr_for(conn);
                let listener = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(tokio::net::TcpListener::bind(bind_addr))
                })
                .ok()?;
                let video_port = listener.local_addr().ok()?.port();
                tracing::info!(video_port, "Video stream TCP port opened");

                if let Some(vh) = &conn.video_handler {
                    let session = vh.video_init();
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current()
                            .spawn(crate::raop::video_stream::run(listener, cipher, session));
                    });
                }

                stream_resp.insert("dataPort".into(), plist::Value::Integer(video_port.into()));
            }
            _ => {
                // Type 120 = Apple Music video (animated album art / music videos).
                // Not yet implemented.
                tracing::warn!(stream_type, "Unknown AP2 stream type");
            }
        }

        // Control port (shared across streams)
        let ctrl_sock = std::net::UdpSocket::bind(bind_addr_for(conn)).ok()?;
        let ctrl_port = ctrl_sock.local_addr().ok()?.port();
        drop(ctrl_sock);
        stream_resp.insert("controlPort".into(), plist::Value::Integer(ctrl_port.into()));

        let streams_array = vec![plist::Value::Dictionary(stream_resp)];
        resp_dict.insert("streams".into(), plist::Value::Array(streams_array));
    } else {
        // Initial setup (no streams): timingProtocol, event channel
        let timing = dict.get("timingProtocol").and_then(|v| v.as_string()).unwrap_or("None");

        // Capture FairPlay encryption keys for video.
        // The audio connection provides ekey (72 bytes, FairPlay-encrypted) + eiv (16 bytes).
        // The video connection (separate RTSP session) reads them from shared state.
        #[cfg(feature = "video")]
        {
            if let Some(ekey_data) = dict.get("ekey").and_then(|v| v.as_data()) {
                if ekey_data.len() == 72 {
                    if let Ok(input) = <[u8; 72]>::try_from(ekey_data) {
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
                                if let Ok(mut shared) = conn.shared_video_ekey.write() {
                                    *shared = Some(derived);
                                    tracing::debug!("Video ekey stored in shared state");
                                }
                            }
                            Err(e) => {
                                tracing::warn!("FairPlay decrypt failed: {e:?}");
                            }
                        }
                    }
                }
            }
            if let Some(eiv_data) = dict.get("eiv").and_then(|v| v.as_data()) {
                if let Ok(iv) = <[u8; 16]>::try_from(eiv_data) {
                    conn.eiv = Some(iv);
                    if let Ok(mut shared) = conn.shared_video_eiv.write() {
                        *shared = Some(iv);
                        tracing::debug!("Video eiv stored in shared state");
                    }
                }
            }
        }

        let is_rc_only = dict
            .get("isRemoteControlOnly")
            .and_then(|v| v.as_boolean())
            .unwrap_or(false);

        if is_rc_only {
            tracing::info!("Remote Control Only connection");
            // RC connections don't need timingPeerInfo or eventPort
            let mut buf = Vec::new();
            plist::to_writer_binary(&mut buf, &resp_dict).ok()?;
            response.add_header("Content-Type", "application/x-apple-binary-plist");
            return Some(buf);
        }

        if timing == "PTP" {
            let mut tpi = plist::Dictionary::new();
            let self_ip = match conn.local_addr.len() {
                4 => {
                    let ip: [u8; 4] = conn.local_addr[..4].try_into().unwrap_or([0; 4]);
                    std::net::Ipv4Addr::from(ip).to_string()
                }
                16 => {
                    let ip: [u8; 16] = conn.local_addr[..16].try_into().unwrap_or([0; 16]);
                    std::net::Ipv6Addr::from(ip).to_string()
                }
                _ => "0.0.0.0".to_string(),
            };
            tracing::debug!(self_ip, "timingPeerInfo address");
            let addrs = vec![plist::Value::String(self_ip.clone())];
            tpi.insert("Addresses".into(), plist::Value::Array(addrs));
            tpi.insert("ID".into(), plist::Value::String(self_ip));
            resp_dict.insert("timingPeerInfo".into(), plist::Value::Dictionary(tpi));
        }

        // Bind event port on same address family as the client connection
        let bind_addr = bind_addr_for(conn);
        let event_ch = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let listener = tokio::net::TcpListener::bind(bind_addr).await?;
                let port = listener.local_addr()?.port();
                Ok::<_, std::io::Error>((listener, port))
            })
        })
        .ok()?;
        let (event_listener, event_port) = event_ch;
        tracing::info!(event_port, "Event channel opened");

        // Derive event channel encryption keys from shared secret (AP2 only).
        // In legacy mode there's no shared secret — skip the encrypted event channel.
        if let Some(shared_secret) = conn.ap2_shared_secret.as_ref() {
            if let Ok(event_channel_cipher) = crate::crypto::chacha_transport::EncryptedChannel::events(shared_secret) {
                // Spawn bidirectional event channel
                let event_sender = tokio::task::block_in_place(|| {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

                    // Queue updateInfo so it's sent immediately when client connects
                    let mut update_info = plist::Dictionary::new();
                    update_info.insert("type".into(), plist::Value::String("updateInfo".into()));
                    let mut value = plist::Dictionary::new();
                    value.insert(
                        "statusFlags".into(),
                        plist::Value::Integer((crate::net::mdns::AP2_STATUS_FLAGS as i64).into()),
                    );
                    value.insert(
                        "features".into(),
                        plist::Value::Integer((crate::net::features::receiver_features() as i64).into()),
                    );
                    value.insert(
                        "model".into(),
                        plist::Value::String(crate::net::mdns::GLOBAL_MODEL.into()),
                    );
                    value.insert(
                        "sourceVersion".into(),
                        plist::Value::String(crate::net::mdns::AP2_SRCVERS.into()),
                    );
                    value.insert(
                        "protocolVersion".into(),
                        plist::Value::String(crate::net::mdns::AP2_PROTOVERS.into()),
                    );
                    update_info.insert("value".into(), plist::Value::Dictionary(value));
                    let mut body = Vec::new();
                    if plist::to_writer_binary(&mut body, &update_info).is_ok() {
                        let rtsp = format!(
                            "POST /command RTSP/1.0\r\nContent-Length: {}\r\nContent-Type: application/x-apple-binary-plist\r\nCSeq: 0\r\n\r\n",
                            body.len()
                        );
                        let mut msg = rtsp.into_bytes();
                        msg.extend_from_slice(&body);
                        let _ = tx.send(msg);
                        tracing::debug!("updateInfo queued for event channel");
                    }

                    let sender = crate::raop::event_channel::EventSender::from_tx(tx);
                    tokio::runtime::Handle::current().spawn(async move {
                        if let Ok((stream, addr)) = event_listener.accept().await {
                            tracing::info!(%addr, "Event channel client connected");
                            crate::raop::event_channel::EventChannel::handle_stream(stream, event_channel_cipher, rx)
                                .await;
                        }
                    });
                    sender
                });
                conn.event_sender = Some(event_sender);
            }
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
            let bind_addr = bind_addr_for(conn);
            let tport = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let tsock = tokio::net::UdpSocket::bind(&bind_addr).await?;
                    let local_port = tsock.local_addr()?.port();
                    let mut remote_timing = conn.remote_socket;
                    remote_timing.set_port(timing_rport);
                    crate::raop::ntp::spawn_ntp_responder(tsock, remote_timing);
                    Ok::<_, std::io::Error>(local_port)
                })
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
    }

    let mut buf = Vec::new();
    plist::to_writer_binary(&mut buf, &resp_dict).ok()?;
    tracing::debug!(buf_len = buf.len(), "SETUP response");
    response.add_header("Content-Type", "application/x-apple-binary-plist");
    Some(buf)
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

    // Convert network time to nanoseconds
    let frac_ns = ((net_frac >> 32) * 1_000_000_000) >> 32;
    let anchor_time_ns = net_secs * 1_000_000_000 + frac_ns;

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
    if let Some(data) = request.data() {
        if let Ok(plist_val) = plist::from_bytes::<plist::Value>(data) {
            if let Some(arr) = plist_val.as_array() {
                let peers: Vec<&str> = arr.iter().filter_map(|v| v.as_string()).collect();
                tracing::debug!(?peers, "SETPEERS");
            }
        }
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
    if let Some(data) = request.data() {
        if let Ok(plist_val) = plist::from_bytes::<plist::Value>(data) {
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
    if let Some(data) = request.data() {
        if let Ok(plist_val) = plist::from_bytes::<plist::Value>(data) {
            if let Some(dict) = plist_val.as_dictionary() {
                let cmd_type = dict.get("type").and_then(|v| v.as_string()).unwrap_or("unknown");
                tracing::debug!(cmd_type, "POST /command");
                if cmd_type == "updateMRSupportedCommands" {}
            }
        }
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
    if let Some(data) = request.data() {
        if let Ok(plist_val) = plist::from_bytes::<plist::Value>(data) {
            if let Some(dict) = plist_val.as_dictionary() {
                let mode = dict.get("audioMode").and_then(|v| v.as_string()).unwrap_or("unknown");
                tracing::debug!(mode, "POST /audioMode");
            }
        }
    }
    None
}
