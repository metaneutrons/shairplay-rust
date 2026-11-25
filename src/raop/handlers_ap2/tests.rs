//! Dispatcher-level regression tests for legacy type 96 stream SETUP.
//!
//! Each test sends a serialized SETUP through [`rtsp::dispatch`] and checks the
//! serialized RTSP status, the response body, the receiver state on the connection
//! and the errors reported to the application.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::crypto::pairing::Pairing;
use crate::crypto::rsa::RsaKey;
use crate::error::ShairplayError;
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::raop::connection::RaopShared;
use crate::raop::handlers_ap1::RaopConnection;
use crate::raop::rtsp;
use crate::raop::{AudioFormat, AudioHandler, AudioSession, MemoryPairingStore};

/// Records every error passed to `on_error` and accepts audio sessions.
#[derive(Default)]
struct RecordingHandler {
    errors: Mutex<Vec<String>>,
    audio_frames: Arc<AtomicUsize>,
}

struct CountingSession(Arc<AtomicUsize>);

impl AudioSession for CountingSession {
    fn audio_process(&mut self, samples: &[f32]) {
        if !samples.is_empty() {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl AudioHandler for RecordingHandler {
    fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
        Box::new(CountingSession(self.audio_frames.clone()))
    }
    fn on_error(&self, error: &ShairplayError) {
        self.errors.lock().unwrap().push(error.to_string());
    }
}

/// How the test connection's FairPlay state is prepared before SETUP.
#[derive(Clone, Copy)]
enum Keys {
    Present,
    Missing,
}

fn test_connection(
    handler: Arc<RecordingHandler>,
    local_ip: [u8; 4],
    keys: Keys,
) -> RaopConnection {
    let shared = test_shared(handler);
    let (ekey, eiv) = match keys {
        Keys::Present => (Some([0x11; 16]), Some([0x22; 16])),
        Keys::Missing => (None, None),
    };
    RaopConnection {
        raop_rtp: None,
        fairplay: crate::crypto::fairplay::FairPlay::new(),
        pairing: shared.pairing.create_session(),
        local_addr: local_ip.to_vec(),
        remote_addr: vec![127, 0, 0, 1],
        remote_socket: "127.0.0.1:5000".parse().unwrap(),
        nonce: String::new(),
        srp_server: None,
        pair_verify: None,
        ap2_shared_secret: None,
        pair_verify_secret: None,
        is_ap2: true,
        playout_cmd: None,
        event_sender: None,
        ekey,
        eiv,
        #[cfg(feature = "hls")]
        hls_state: crate::raop::hls::HlsState::new(),
        shared,
    }
}

fn test_shared(handler: Arc<RecordingHandler>) -> Arc<RaopShared> {
    Arc::new(RaopShared {
        rsakey: Arc::new(RsaKey::from_pem(include_str!("../../../airport.key")).unwrap()),
        pairing: Arc::new(Pairing::generate().unwrap()),
        hwaddr: vec![0u8; 6],
        password: String::new(),
        #[cfg(feature = "pipewire-auth-setup-compat")]
        pipewire_auth_setup_compat: false,
        handler,
        pairing_store: Arc::new(MemoryPairingStore::default()),
        identity_seed: [0u8; 32],
        output_sample_rate: None,
        output_max_channels: None,
        audio_buffer_size: 100_000,
        pin: None,
        video_handler: None,
        video_ekey: Arc::new(std::sync::RwLock::new(None)),
        video_eiv: Arc::new(std::sync::RwLock::new(None)),
        pairing_id: String::new(),
        device_id: String::new(),
        airplay_name: String::new(),
        active_audio: std::sync::Mutex::new(None),
        #[cfg(feature = "hls")]
        hls_handler: None,
    })
}

/// A serialized SETUP whose single type 96 stream (no `shk`) carries `fields`.
fn stream_setup(fields: &[(&str, plist::Value)]) -> HttpRequest {
    let mut stream = plist::Dictionary::new();
    stream.insert("type".into(), plist::Value::Integer(96u64.into()));
    for (key, value) in fields {
        stream.insert((*key).into(), value.clone());
    }
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "streams".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
    );
    let mut body = Vec::new();
    plist::to_writer_binary(&mut body, &dict).unwrap();

    let mut msg = format!(
        "SETUP rtsp://127.0.0.1/1 RTSP/1.0\r\nCSeq: 7\r\n\
         Content-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    msg.extend_from_slice(&body);
    let mut request = HttpRequest::new();
    request.add_data(&msg).unwrap();
    assert!(request.is_complete(), "SETUP request should parse");
    request
}

fn uint(value: u64) -> plist::Value {
    plist::Value::Integer(value.into())
}

fn status_line(response: &HttpResponse) -> String {
    let data = response.get_data();
    let end = data.windows(2).position(|w| w == b"\r\n").unwrap();
    String::from_utf8(data[..end].to_vec()).unwrap()
}

fn body(response: &HttpResponse) -> &[u8] {
    let data = response.get_data();
    let start = data.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    &data[start..]
}

fn response_ports(response: &HttpResponse) -> (u16, u16) {
    let reply: plist::Value = plist::from_bytes(body(response)).unwrap();
    let stream = reply.as_dictionary().unwrap()["streams"]
        .as_array()
        .unwrap()[0]
        .as_dictionary()
        .unwrap();
    let control = stream["controlPort"].as_unsigned_integer().unwrap() as u16;
    let data = stream["dataPort"].as_unsigned_integer().unwrap() as u16;
    (control, data)
}

const AAC_ELD_PNS: &[u8] = &[0x04, 0xa0, 0xd0, 0xc0, 0x14, 0x1a, 0x18, 0x00];
const AAC_ELD_SILENT: &[u8] = &[0x00, 0xa0, 0x50, 0x00];

fn rtp_packet(seqnum: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    packet[2..4].copy_from_slice(&seqnum.to_be_bytes());
    packet[4..8].copy_from_slice(&(u32::from(seqnum) * 480).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn control_retransmit_packet(seqnum: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 0x56, 0, 0];
    packet.extend_from_slice(&rtp_packet(seqnum, payload));
    packet
}

fn send_udp(port: u16, packet: &[u8]) {
    let socket = std::net::UdpSocket::bind(std::net::SocketAddr::from((LOCALHOST, 0))).unwrap();
    socket
        .send_to(packet, std::net::SocketAddr::from((LOCALHOST, port)))
        .unwrap();
}

async fn wait_for_audio_frames(handler: &RecordingHandler, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while handler.audio_frames.load(Ordering::Relaxed) < expected {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("audio receiver should process the UDP packet");
}

async fn wait_for_udp_port_to_close(port: u16) {
    let addr = std::net::SocketAddr::from((LOCALHOST, port));
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(socket) = std::net::UdpSocket::bind(addr) {
                drop(socket);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("replaced receiver should release its UDP ports");
}

/// Dispatch `request` on a fresh connection and assert a rejected SETUP: the given
/// status, no body, no receiver and exactly one application error.
fn assert_rejected(request: HttpRequest, local_ip: [u8; 4], keys: Keys, expected: &str) {
    let handler = Arc::new(RecordingHandler::default());
    let mut conn = test_connection(handler.clone(), local_ip, keys);

    let response = rtsp::dispatch(&mut conn, &request);

    assert_eq!(status_line(&response), expected);
    assert!(
        response.get_data().windows(9).any(|w| w == b"CSeq: 7\r\n"),
        "the replacement status keeps the request CSeq"
    );
    assert!(body(&response).is_empty(), "a rejected SETUP has no body");
    assert!(
        conn.raop_rtp.is_none(),
        "a rejected SETUP leaves no receiver"
    );
    let errors = handler.errors.lock().unwrap();
    assert_eq!(errors.len(), 1, "on_error should fire once: {errors:?}");
}

const LOCALHOST: [u8; 4] = [127, 0, 0, 1];

#[tokio::test]
async fn supported_aac_eld_setup_returns_ports_and_receiver() {
    let handler = Arc::new(RecordingHandler::default());
    let mut conn = test_connection(handler.clone(), LOCALHOST, Keys::Present);
    let request = stream_setup(&[
        ("ct", uint(8)),
        ("sr", uint(44100)),
        ("spf", uint(480)),
        ("controlPort", uint(6001)),
    ]);

    let response = rtsp::dispatch(&mut conn, &request);

    assert_eq!(status_line(&response), "RTSP/1.0 200 OK");
    let (control_port, data_port) = response_ports(&response);
    assert_ne!(control_port, 0);
    assert_ne!(data_port, 0);
    assert!(conn.raop_rtp.is_some(), "receiver should be installed");
    send_udp(data_port, &rtp_packet(1, AAC_ELD_PNS));
    wait_for_audio_frames(&handler, 1).await;
    send_udp(data_port, &rtp_packet(3, AAC_ELD_SILENT));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(handler.audio_frames.load(Ordering::Relaxed), 1);
    send_udp(control_port, &control_retransmit_packet(2, AAC_ELD_SILENT));
    wait_for_audio_frames(&handler, 3).await;
    assert!(handler.errors.lock().unwrap().is_empty());
    conn.raop_rtp.take().unwrap().stop();
}

#[tokio::test]
async fn failed_constructor_replacement_keeps_old_udp_receiver_playing() {
    let handler = Arc::new(RecordingHandler::default());
    let mut conn = test_connection(handler.clone(), LOCALHOST, Keys::Present);
    let initial = rtsp::dispatch(
        &mut conn,
        &stream_setup(&[("ct", uint(8)), ("sr", uint(44100)), ("spf", uint(480))]),
    );
    assert_eq!(status_line(&initial), "RTSP/1.0 200 OK");
    let (_, old_data_port) = response_ports(&initial);

    let failed = rtsp::dispatch(
        &mut conn,
        &stream_setup(&[("ct", uint(8)), ("sr", uint(44100)), ("spf", uint(123))]),
    );

    assert_eq!(status_line(&failed), "RTSP/1.0 400 Bad Request");
    assert!(
        conn.raop_rtp.is_some(),
        "old receiver must remain installed"
    );
    send_udp(old_data_port, &rtp_packet(1, AAC_ELD_PNS));
    wait_for_audio_frames(&handler, 1).await;
    assert_eq!(handler.errors.lock().unwrap().len(), 1);
    conn.raop_rtp.take().unwrap().stop();
}

#[tokio::test]
async fn failed_bind_replacement_keeps_old_udp_receiver_playing() {
    let handler = Arc::new(RecordingHandler::default());
    let mut conn = test_connection(handler.clone(), LOCALHOST, Keys::Present);
    let initial = rtsp::dispatch(
        &mut conn,
        &stream_setup(&[("ct", uint(8)), ("sr", uint(44100)), ("spf", uint(480))]),
    );
    assert_eq!(status_line(&initial), "RTSP/1.0 200 OK");
    let (_, old_data_port) = response_ports(&initial);

    let original_local_addr = conn.local_addr.clone();
    conn.local_addr = vec![192, 0, 2, 1];
    let failed = rtsp::dispatch(
        &mut conn,
        &stream_setup(&[("ct", uint(8)), ("sr", uint(44100)), ("spf", uint(480))]),
    );
    conn.local_addr = original_local_addr;

    assert_eq!(status_line(&failed), "RTSP/1.0 500 Internal Server Error");
    assert!(
        conn.raop_rtp.is_some(),
        "old receiver must remain installed"
    );
    send_udp(old_data_port, &rtp_packet(1, AAC_ELD_PNS));
    wait_for_audio_frames(&handler, 1).await;
    assert_eq!(handler.errors.lock().unwrap().len(), 1);
    conn.raop_rtp.take().unwrap().stop();
}

#[tokio::test]
async fn successful_replacement_moves_playback_to_new_udp_receiver() {
    let handler = Arc::new(RecordingHandler::default());
    let mut conn = test_connection(handler.clone(), LOCALHOST, Keys::Present);
    let initial = rtsp::dispatch(
        &mut conn,
        &stream_setup(&[("ct", uint(8)), ("sr", uint(44100)), ("spf", uint(480))]),
    );
    assert_eq!(status_line(&initial), "RTSP/1.0 200 OK");
    let (_, old_data_port) = response_ports(&initial);

    let replacement = rtsp::dispatch(
        &mut conn,
        &stream_setup(&[("ct", uint(8)), ("sr", uint(44100)), ("spf", uint(480))]),
    );

    assert_eq!(status_line(&replacement), "RTSP/1.0 200 OK");
    let (_, new_data_port) = response_ports(&replacement);
    assert_ne!(old_data_port, new_data_port);
    wait_for_udp_port_to_close(old_data_port).await;
    send_udp(old_data_port, &rtp_packet(1, AAC_ELD_PNS));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(handler.audio_frames.load(Ordering::Relaxed), 0);

    send_udp(new_data_port, &rtp_packet(1, AAC_ELD_PNS));
    wait_for_audio_frames(&handler, 1).await;
    assert!(handler.errors.lock().unwrap().is_empty());
    conn.raop_rtp.take().unwrap().stop();
}

#[tokio::test]
async fn unsupported_codec_type_is_rejected() {
    let request = stream_setup(&[("ct", uint(4)), ("spf", uint(480))]);
    assert_rejected(
        request,
        LOCALHOST,
        Keys::Present,
        "RTSP/1.0 400 Bad Request",
    );
}

#[tokio::test]
async fn codec_type_that_wraps_to_aac_eld_is_rejected() {
    // 264 = 256 + 8 previously narrowed to AAC-ELD (`ct=8`).
    let request = stream_setup(&[("ct", uint(264)), ("spf", uint(480))]);
    assert_rejected(
        request,
        LOCALHOST,
        Keys::Present,
        "RTSP/1.0 400 Bad Request",
    );
}

#[tokio::test]
async fn negative_codec_type_is_rejected() {
    let request = stream_setup(&[("ct", plist::Value::Integer((-1i64).into()))]);
    assert_rejected(
        request,
        LOCALHOST,
        Keys::Present,
        "RTSP/1.0 400 Bad Request",
    );
}

#[tokio::test]
async fn out_of_range_sample_rate_is_rejected() {
    // Would previously wrap to 44100.
    let request = stream_setup(&[
        ("ct", uint(8)),
        ("sr", uint((1 << 32) + 44100)),
        ("spf", uint(480)),
    ]);
    assert_rejected(
        request,
        LOCALHOST,
        Keys::Present,
        "RTSP/1.0 400 Bad Request",
    );
}

#[tokio::test]
async fn out_of_range_frame_size_is_rejected() {
    // Would previously wrap to 480.
    let request = stream_setup(&[("ct", uint(8)), ("spf", uint((1 << 32) + 480))]);
    assert_rejected(
        request,
        LOCALHOST,
        Keys::Present,
        "RTSP/1.0 400 Bad Request",
    );
}

#[tokio::test]
async fn out_of_range_control_port_is_rejected() {
    let request = stream_setup(&[
        ("ct", uint(8)),
        ("spf", uint(480)),
        ("controlPort", uint(65536 + 6001)),
    ]);
    assert_rejected(
        request,
        LOCALHOST,
        Keys::Present,
        "RTSP/1.0 400 Bad Request",
    );
}

#[tokio::test]
async fn missing_fairplay_keys_are_rejected() {
    let request = stream_setup(&[("ct", uint(8)), ("spf", uint(480))]);
    assert_rejected(
        request,
        LOCALHOST,
        Keys::Missing,
        "RTSP/1.0 400 Bad Request",
    );
}

#[tokio::test]
async fn receiver_construction_failure_is_rejected() {
    // AAC-ELD frames are 480 or 512 samples, so the receiver cannot be built.
    let request = stream_setup(&[("ct", uint(8)), ("spf", uint(123))]);
    assert_rejected(
        request,
        LOCALHOST,
        Keys::Present,
        "RTSP/1.0 400 Bad Request",
    );
}

#[tokio::test]
async fn receiver_start_failure_is_an_internal_error() {
    // 192.0.2.1 (TEST-NET-1) is not a local address, so binding RTP sockets fails.
    let request = stream_setup(&[("ct", uint(8)), ("spf", uint(480))]);
    assert_rejected(
        request,
        [192, 0, 2, 1],
        Keys::Present,
        "RTSP/1.0 500 Internal Server Error",
    );
}

#[test]
fn invalid_integer_values_report_bounded_type_summaries() {
    let mut nested_dict = plist::Dictionary::new();
    nested_dict.insert(
        "payload".to_string(),
        plist::Value::Data(vec![0x5a; 1_048_576]),
    );
    let nested = plist::Value::Array(vec![plist::Value::Dictionary(nested_dict)]);
    let invalid_values = [
        (plist::Value::Data(vec![0x5a; 1_048_576]), "data"),
        (nested, "array"),
    ];

    for (value, expected_type) in invalid_values {
        let handler = Arc::new(RecordingHandler::default());
        let mut conn = test_connection(handler.clone(), LOCALHOST, Keys::Present);
        let response = rtsp::dispatch(&mut conn, &stream_setup(&[("spf", value)]));

        assert_eq!(status_line(&response), "RTSP/1.0 400 Bad Request");
        let errors = handler.errors.lock().unwrap();
        let error = errors.first().expect("invalid value should be reported");
        assert!(error.len() < 160, "error grew to {} bytes", error.len());
        assert!(error.contains(&format!("value type: {expected_type}")));
        assert!(
            !error.contains("ZZZ"),
            "error should not include data bytes"
        );
        assert_eq!(errors.len(), 1);
    }
}
