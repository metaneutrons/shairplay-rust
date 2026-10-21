//! Dispatcher-level regression tests for legacy type 96 stream SETUP.
//!
//! Each test sends a serialized SETUP through [`rtsp::dispatch`] and checks the
//! serialized RTSP status, the response body, the receiver state on the connection
//! and the errors reported to the application.

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
}

struct NullSession;

impl AudioSession for NullSession {
    fn audio_process(&mut self, _samples: &[f32]) {}
}

impl AudioHandler for RecordingHandler {
    fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
        Box::new(NullSession)
    }
    fn on_error(&self, error: &ShairplayError) {
        self.errors.lock().unwrap().push(error.to_string());
    }
}

/// How the test connection's FairPlay state is prepared before SETUP.
enum Keys {
    Present,
    Missing,
}

fn test_connection(
    handler: Arc<RecordingHandler>,
    local_ip: [u8; 4],
    keys: Keys,
) -> RaopConnection {
    let shared = Arc::new(RaopShared {
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
    });
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
    let request = stream_setup(&[("ct", uint(8)), ("sr", uint(44100)), ("spf", uint(480))]);

    let response = rtsp::dispatch(&mut conn, &request);

    assert_eq!(status_line(&response), "RTSP/1.0 200 OK");
    let reply: plist::Value = plist::from_bytes(body(&response)).unwrap();
    let stream = reply.as_dictionary().unwrap()["streams"]
        .as_array()
        .unwrap()[0]
        .as_dictionary()
        .unwrap();
    assert!(stream.get("dataPort").is_some(), "dataPort: {stream:?}");
    assert!(conn.raop_rtp.is_some(), "receiver should be installed");
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
