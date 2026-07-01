//! Integration tests: start a real RaopServer, connect via TCP, exercise the RTSP protocol.
//! Tests are serialized to avoid mDNS registration conflicts.

use serial_test::serial;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use shairplay::{AudioFormat, AudioHandler, AudioSession, RaopServer, TrackMetadata};

struct TestHandler {
    inits: Arc<Mutex<Vec<AudioFormat>>>,
    volumes: Arc<Mutex<Vec<f32>>>,
    metadata: Arc<Mutex<Vec<TrackMetadata>>>,
    coverart: Arc<Mutex<Vec<Vec<u8>>>>,
}

struct TestSession;

impl AudioHandler for TestHandler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        self.inits.lock().unwrap().push(format);
        Box::new(TestSession)
    }
    fn on_volume(&self, volume: f32) {
        self.volumes.lock().unwrap().push(volume);
    }
    fn on_metadata(&self, metadata: &TrackMetadata) {
        self.metadata.lock().unwrap().push(metadata.clone());
    }
    fn on_coverart(&self, data: &[u8]) {
        self.coverart.lock().unwrap().push(data.to_vec());
    }
}

impl AudioSession for TestSession {
    fn audio_process(&mut self, _samples: &[f32]) {}
}

struct TestState {
    volumes: Arc<Mutex<Vec<f32>>>,
    metadata: Arc<Mutex<Vec<TrackMetadata>>>,
    coverart: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn start_server() -> (RaopServer, u16, TestState) {
    let inits = Arc::new(Mutex::new(Vec::new()));
    let volumes = Arc::new(Mutex::new(Vec::new()));
    let metadata = Arc::new(Mutex::new(Vec::new()));
    let coverart = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(TestHandler {
        inits: inits.clone(),
        volumes: volumes.clone(),
        metadata: metadata.clone(),
        coverart: coverart.clone(),
    });
    let mut server = RaopServer::builder()
        .name("IntegrationTest")
        .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        .port(0)
        .build(handler)
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    let state = TestState {
        volumes,
        metadata,
        coverart,
    };
    (server, port, state)
}

async fn send_rtsp(stream: &mut TcpStream, request: &str) -> String {
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

fn empty_handler() -> Arc<TestHandler> {
    Arc::new(TestHandler {
        inits: Arc::new(Mutex::new(Vec::new())),
        volumes: Arc::new(Mutex::new(Vec::new())),
        metadata: Arc::new(Mutex::new(Vec::new())),
        coverart: Arc::new(Mutex::new(Vec::new())),
    })
}

#[test]
fn default_hwaddr_is_locally_administered_unicast() {
    let server = RaopServer::builder()
        .name("RandomHwaddrTest")
        .port(0)
        .build(empty_handler())
        .unwrap();
    let info = server.service_info();
    let hwaddr_hex = info.raop_name.split('@').next().unwrap();
    let first_octet = u8::from_str_radix(&hwaddr_hex[..2], 16).unwrap();

    assert_eq!(hwaddr_hex.len(), 12);
    assert_eq!(first_octet & 0x02, 0x02);
    assert_eq!(first_octet & 0x01, 0);
}

#[test]
fn builder_rejects_invalid_hwaddr_length() {
    let result = RaopServer::builder()
        .name("InvalidHwaddrTest")
        .hwaddr(vec![0xAA; 5])
        .build(empty_handler());

    assert!(matches!(
        result,
        Err(shairplay::ShairplayError::Server(
            shairplay::error::ServerError::InvalidHwAddr(5)
        ))
    ));
}

#[tokio::test]
#[serial]
async fn server_start_stop() {
    let (mut server, port, _) = start_server().await;
    assert!(server.is_running());
    assert!(port > 0);

    let info = server.service_info();
    assert_eq!(info.port, port);
    assert_eq!(info.airplay_name, "IntegrationTest");
    assert_eq!(
        info.raop_txt.iter().find(|(k, _)| k == "cn").map(|(_, v)| v.as_str()),
        Some("0,1")
    );

    server.stop().await;
    assert!(!server.is_running());
}

#[tokio::test]
#[serial]
async fn tcp_connect_and_options() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let resp = send_rtsp(&mut stream, "OPTIONS * HTTP/1.0\r\nCSeq: 1\r\n\r\n").await;

    assert!(resp.contains("RTSP/1.0 200 OK"), "got: {resp}");
    assert!(resp.contains("CSeq: 1"));
    assert!(resp.contains("Public:"));
    assert!(resp.contains("ANNOUNCE"));
    assert!(resp.contains("SETUP"));

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn unknown_rtsp_method_returns_404() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let resp = send_rtsp(&mut stream, "BOGUS * RTSP/1.0\r\nCSeq: 7\r\n\r\n").await;

    assert!(resp.contains("RTSP/1.0 404 Not Found"), "got: {resp}");
    assert!(resp.contains("CSeq: 7"));

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn ap1_record_returns_200() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let resp = send_rtsp(&mut stream, "RECORD /test RTSP/1.0\r\nCSeq: 8\r\n\r\n").await;

    assert!(resp.contains("RTSP/1.0 200 OK"), "got: {resp}");
    assert!(resp.contains("CSeq: 8"));
    // Parity with the AP2 RECORD response (clients expect this header).
    assert!(resp.contains("Audio-Latency: 0"), "got: {resp}");

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn oversized_header_returns_400_and_closes_connection() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let request = format!(
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nX-Oversized: {}\r\n\r\n",
        "A".repeat(65 * 1024)
    );
    let resp = send_rtsp(&mut stream, &request).await;

    assert!(resp.contains("RTSP/1.0 400 Bad Request"), "got: {resp}");
    assert!(resp.contains("Connection: close"));

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn pair_setup_returns_public_key() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // Send 32 bytes of dummy pair-setup data
    let body = [0x42u8; 32];
    let req =
        "POST /pair-setup HTTP/1.0\r\nCSeq: 1\r\nContent-Length: 32\r\nContent-Type: application/octet-stream\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.contains("200 OK"), "got: {resp}");
    assert!(resp.contains("Content-Length: 32")); // Ed25519 public key = 32 bytes

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn fp_setup_returns_142_bytes() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // FairPlay setup: 16 bytes with version=3, mode=0
    let mut body = [0u8; 16];
    body[4] = 0x03; // version
    body[14] = 0x00; // mode
    let req = "POST /fp-setup HTTP/1.0\r\nCSeq: 1\r\nContent-Length: 16\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.contains("200 OK"), "got: {resp}");
    assert!(resp.contains("Content-Length: 142")); // FairPlay setup response

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn unauthorized_without_password_header() {
    let mut server = RaopServer::builder()
        .name("AuthTest")
        .hwaddr([0xAA; 6])
        .port(0)
        .password("secret123")
        .build(empty_handler())
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    // ANNOUNCE without Authorization header should get 401
    let resp = send_rtsp(&mut stream, "ANNOUNCE /test HTTP/1.0\r\nCSeq: 1\r\n\r\n").await;

    assert!(resp.contains("401 Unauthorized"), "got: {resp}");
    assert!(resp.contains("WWW-Authenticate: Digest"));

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn multiple_connections() {
    let (mut server, port, _) = start_server().await;

    // Open 3 concurrent connections
    let mut streams = Vec::new();
    for _ in 0..3 {
        streams.push(TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap());
    }

    // All should respond to OPTIONS
    for stream in &mut streams {
        let resp = send_rtsp(stream, "OPTIONS * HTTP/1.0\r\nCSeq: 1\r\n\r\n").await;
        assert!(resp.contains("200 OK"));
    }

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn teardown_closes_connection() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let resp = send_rtsp(&mut stream, "TEARDOWN /test HTTP/1.0\r\nCSeq: 1\r\n\r\n").await;
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("Connection: close"));

    // Server must close the connection after TEARDOWN
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("server did not close connection within 2s")
        .unwrap();
    assert_eq!(n, 0, "expected EOF after TEARDOWN");

    server.stop().await;
}

// --- AirPlay 2 integration tests ---

#[cfg(feature = "ap2")]
mod ap2_tests {
    use super::*;
    use shairplay::crypto::tlv::{TlvType, TlvValues};

    #[tokio::test]
    #[serial]
    async fn ap2_transient_pair_setup() {
        let (mut server, port, _) = start_server().await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

        // M1: State=1, Method=0, Flags=0x10 (transient)
        let mut m1_tlv = TlvValues::new();
        m1_tlv.add(TlvType::State as u8, &[1]);
        m1_tlv.add(TlvType::Method as u8, &[0]);
        m1_tlv.add(TlvType::Flags as u8, &[0x10]);
        let m1_body = m1_tlv.encode();

        let req = format!(
            "POST /pair-setup RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            m1_body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(&m1_body).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp.contains("200 OK"),
            "M2 should be 200, got: {}",
            &resp[..resp.len().min(100)]
        );

        // Parse M2 response body — find the body after \r\n\r\n
        let header_end = resp.find("\r\n\r\n").unwrap() + 4;
        let body = &buf[header_end..n];
        let m2 = TlvValues::decode(body).expect("M2 should be valid TLV");
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b = m2.get_type(TlvType::PublicKey).unwrap();
        assert_eq!(salt.len(), 16);
        assert!(!pk_b.is_empty() && pk_b.len() <= 384);

        server.stop().await;
    }

    #[test]
    fn ap2_pin_pairing_service_info_advertises_persistent_pairing() {
        let server = RaopServer::builder()
            .name("PersistentPairingTest")
            .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .port(0)
            .pin("1234")
            .build(empty_handler())
            .unwrap();
        let info = server.service_info();
        let raop = |key: &str| info.raop_txt.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        let airplay = |key: &str| info.airplay_txt.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());

        let expected_features = if cfg!(feature = "video") {
            "0x527FFEE6,0x0"
        } else {
            "0x405D4A00,0x14340"
        };
        assert_eq!(raop("ft"), Some(expected_features));
        assert_eq!(raop("sf"), Some("0x204"));
        assert_eq!(airplay("features"), Some(expected_features));
        assert_eq!(airplay("flags"), Some("0x204"));
    }

    #[tokio::test]
    #[serial]
    async fn ap2_pair_pin_start_is_acknowledged() {
        let handler = empty_handler();
        let mut server = RaopServer::builder()
            .name("PinStartTest")
            .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .port(0)
            .pin("1234")
            .build(handler)
            .unwrap();
        server.start().await.unwrap();
        let port = server.service_info().port;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let resp = send_rtsp(
            &mut stream,
            "POST /pair-pin-start RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
        )
        .await;

        assert!(resp.contains("RTSP/1.0 200 OK"), "got: {resp}");
        assert!(resp.contains("CSeq: 1"), "got: {resp}");
        assert!(resp.contains("Content-Type: application/octet-stream"), "got: {resp}");

        server.stop().await;
    }

    #[tokio::test]
    #[serial]
    async fn ap2_full_transient_pair_setup_m1_to_m4() {
        use num_bigint::BigUint;

        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

        // Helper to send RTSP and read response
        async fn rtsp_post(stream: &mut TcpStream, url: &str, cseq: u32, body: &[u8]) -> (String, Vec<u8>) {
            let req = format!(
                "POST {} RTSP/1.0\r\nCSeq: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                url,
                cseq,
                body.len()
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = stream.read(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf[..n]).to_string();
            let header_end = resp.find("\r\n\r\n").map(|p| p + 4).unwrap_or(n);
            let resp_body = buf[header_end..n].to_vec();
            (resp, resp_body)
        }

        // M1: pair-verify (will fail but server accepts it)
        let mut m1_verify = TlvValues::new();
        m1_verify.add(TlvType::State as u8, &[1]);
        m1_verify.add(TlvType::PublicKey as u8, &[0u8; 32]); // dummy key
        let (resp, _) = rtsp_post(&mut stream, "/pair-verify", 0, &m1_verify.encode()).await;
        assert!(resp.contains("200"), "pair-verify M1");

        // M1: pair-setup (transient)
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        m1.add(TlvType::Flags as u8, &[0x10]);
        let (resp, body) = rtsp_post(&mut stream, "/pair-setup", 1, &m1.encode()).await;
        assert!(resp.contains("200"), "M2 response");
        let m2 = TlvValues::decode(&body).expect("M2 TLV");
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b_bytes = m2.get_type(TlvType::PublicKey).unwrap();

        // Client SRP: compute A and M1 proof
        let n_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
        let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
        let g = BigUint::from(5u32);
        let mut a_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        let big_a = g.modpow(&a, &n);

        let salt_bn = BigUint::from_bytes_be(salt);
        let big_b = BigUint::from_bytes_be(pk_b_bytes);

        // SRP math (simplified — same as pairing_homekit self-test)
        use sha2::{Digest, Sha512};
        fn to_bytes_be(n: &BigUint) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.is_empty() { vec![0] } else { b }
        }
        fn to_padded(n: &BigUint, len: usize) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.len() >= len {
                b
            } else {
                let mut p = vec![0u8; len - b.len()];
                p.extend(&b);
                p
            }
        }
        fn sha512(d: &[u8]) -> [u8; 64] {
            let mut h = Sha512::new();
            h.update(d);
            h.finalize().into()
        }
        fn h_nn_pad(n1: &BigUint, n2: &BigUint, l: usize) -> BigUint {
            let mut b = Vec::new();
            b.extend(&to_padded(n1, l));
            b.extend(&to_padded(n2, l));
            BigUint::from_bytes_be(&sha512(&b))
        }

        let k = h_nn_pad(&n, &g, 384);
        let u = h_nn_pad(&big_a, &big_b, 384);

        let mut h = Sha512::new();
        h.update(b"Pair-Setup");
        h.update(b":");
        h.update(b"3939");
        let ucp = h.finalize();
        let mut buf2 = Vec::new();
        buf2.extend(&to_bytes_be(&salt_bn));
        buf2.extend(&ucp);
        let x = BigUint::from_bytes_be(&sha512(&buf2));

        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        let base = (&big_b + &n - &kgx) % &n;
        let big_s = base.modpow(&(&a + &u * &x), &n);
        let session_key = sha512(&to_bytes_be(&big_s));

        // Calculate M1 proof
        let h_n = sha512(&to_bytes_be(&n));
        let h_g = sha512(&to_bytes_be(&g));
        let mut h_xor = [0u8; 64];
        for i in 0..64 {
            h_xor[i] = h_n[i] ^ h_g[i];
        }
        let h_i = sha512(b"Pair-Setup");
        let mut h = Sha512::new();
        h.update(h_xor);
        h.update(h_i);
        h.update(to_bytes_be(&salt_bn));
        h.update(to_bytes_be(&big_a));
        h.update(to_bytes_be(&big_b));
        h.update(session_key);
        let client_m: [u8; 64] = h.finalize().into();

        // M3: send A + proof
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &to_bytes_be(&big_a));
        m3.add(TlvType::Proof as u8, &client_m);
        let (resp, body) = rtsp_post(&mut stream, "/pair-setup", 2, &m3.encode()).await;
        assert!(resp.contains("200"), "M4 response");

        // Verify M4: State=4, Proof present (no error)
        let m4 = TlvValues::decode(&body).expect("M4 TLV");
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));
        assert!(m4.get_type(TlvType::Proof).is_some(), "M4 should have server proof");
        assert!(m4.get_type(TlvType::Error).is_none(), "M4 should not have error");

        // Verify server proof
        let server_proof = m4.get_type(TlvType::Proof).unwrap();
        let mut h = Sha512::new();
        h.update(to_bytes_be(&big_a));
        h.update(client_m);
        h.update(session_key);
        let expected_hamk: [u8; 64] = h.finalize().into();
        assert_eq!(server_proof, &expected_hamk[..], "Server proof should match");

        server.stop().await;
    }

    #[tokio::test]
    #[serial]
    async fn ap2_get_info_plist_correctness() {
        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

        let req = "GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 16384];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);

        assert!(resp.contains("200 OK"), "GET /info should be 200 OK");
        assert!(
            resp.contains("Content-Type: application/x-apple-binary-plist"),
            "must return binary plist"
        );

        let header_end = resp.find("\r\n\r\n").unwrap() + 4;
        let body = &buf[header_end..n];

        let cursor = std::io::Cursor::new(body);
        let plist_val = plist::Value::from_reader(cursor).expect("body should be a valid plist");
        let dict = plist_val.as_dictionary().expect("plist should be a dictionary");

        assert!(dict.contains_key("pi"), "should contain pairing_id (pi)");
        assert!(dict.contains_key("name"), "should contain name");
        assert!(dict.contains_key("macAddress"), "should contain macAddress");
        assert!(dict.contains_key("deviceID"), "should contain deviceID");

        let pi_val = dict.get("pi").unwrap().as_string().unwrap();
        let name_val = dict.get("name").unwrap().as_string().unwrap();
        let mac_val = dict.get("macAddress").unwrap().as_string().unwrap();

        assert_eq!(name_val, "IntegrationTest");
        assert_eq!(mac_val, "00:11:22:33:44:55");
        assert_eq!(pi_val.len(), 36);

        server.stop().await;
    }

    async fn perform_transient_pairing(stream: &mut TcpStream) -> [u8; 64] {
        use num_bigint::BigUint;
        use sha2::{Digest, Sha512};

        // Helper to send RTSP and read response
        async fn rtsp_post(stream: &mut TcpStream, url: &str, cseq: u32, body: &[u8]) -> (String, Vec<u8>) {
            let req = format!(
                "POST {} RTSP/1.0\r\nCSeq: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                url,
                cseq,
                body.len()
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = stream.read(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf[..n]).to_string();
            let header_end = resp.find("\r\n\r\n").map(|p| p + 4).unwrap_or(n);
            let resp_body = buf[header_end..n].to_vec();
            (resp, resp_body)
        }

        // M1: pair-verify (will fail but server accepts it)
        let mut m1_verify = TlvValues::new();
        m1_verify.add(TlvType::State as u8, &[1]);
        m1_verify.add(TlvType::PublicKey as u8, &[0u8; 32]); // dummy key
        let (resp, _) = rtsp_post(stream, "/pair-verify", 0, &m1_verify.encode()).await;
        assert!(resp.contains("200"), "pair-verify M1");

        // M1: pair-setup (transient)
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        m1.add(TlvType::Flags as u8, &[0x10]);
        let (resp, body) = rtsp_post(stream, "/pair-setup", 1, &m1.encode()).await;
        assert!(resp.contains("200"), "M2 response");
        let m2 = TlvValues::decode(&body).expect("M2 TLV");
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b_bytes = m2.get_type(TlvType::PublicKey).unwrap();

        // Client SRP: compute A and M1 proof
        let n_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
        let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
        let g = BigUint::from(5u32);
        let mut a_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        let big_a = g.modpow(&a, &n);

        let salt_bn = BigUint::from_bytes_be(salt);
        let big_b = BigUint::from_bytes_be(pk_b_bytes);

        // SRP math (simplified — same as pairing_homekit self-test)
        fn to_bytes_be(n: &BigUint) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.is_empty() { vec![0] } else { b }
        }
        fn to_padded(n: &BigUint, len: usize) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.len() >= len {
                b
            } else {
                let mut p = vec![0u8; len - b.len()];
                p.extend(&b);
                p
            }
        }
        fn sha512(d: &[u8]) -> [u8; 64] {
            let mut h = Sha512::new();
            h.update(d);
            h.finalize().into()
        }
        fn h_nn_pad(n1: &BigUint, n2: &BigUint, l: usize) -> BigUint {
            let mut b = Vec::new();
            b.extend(&to_padded(n1, l));
            b.extend(&to_padded(n2, l));
            BigUint::from_bytes_be(&sha512(&b))
        }

        let k = h_nn_pad(&n, &g, 384);
        let u = h_nn_pad(&big_a, &big_b, 384);

        let mut h = Sha512::new();
        h.update(b"Pair-Setup");
        h.update(b":");
        h.update(b"3939");
        let ucp = h.finalize();
        let mut buf2 = Vec::new();
        buf2.extend(&to_bytes_be(&salt_bn));
        buf2.extend(&ucp);
        let x = BigUint::from_bytes_be(&sha512(&buf2));

        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        let base = (&big_b + &n - &kgx) % &n;
        let big_s = base.modpow(&(&a + &u * &x), &n);
        let session_key = sha512(&to_bytes_be(&big_s));

        // Calculate M1 proof
        let h_n = sha512(&to_bytes_be(&n));
        let h_g = sha512(&to_bytes_be(&g));
        let mut h_xor = [0u8; 64];
        for i in 0..64 {
            h_xor[i] = h_n[i] ^ h_g[i];
        }
        let h_i = sha512(b"Pair-Setup");
        let mut h = Sha512::new();
        h.update(h_xor);
        h.update(h_i);
        h.update(to_bytes_be(&salt_bn));
        h.update(to_bytes_be(&big_a));
        h.update(to_bytes_be(&big_b));
        h.update(session_key);
        let client_m: [u8; 64] = h.finalize().into();

        // M3: send A + proof
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &to_bytes_be(&big_a));
        m3.add(TlvType::Proof as u8, &client_m);
        let (resp, body) = rtsp_post(stream, "/pair-setup", 2, &m3.encode()).await;
        assert!(resp.contains("200"), "M4 response");

        // Verify M4: State=4, Proof present (no error)
        let m4 = TlvValues::decode(&body).expect("M4 TLV");
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));
        assert!(m4.get_type(TlvType::Proof).is_some(), "M4 should have server proof");

        session_key
    }

    #[tokio::test]
    #[serial]
    async fn ap2_remote_control_only_setup() {
        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

        // Perform pairing first to populate conn.ap2_shared_secret and get session key
        let session_key = perform_transient_pairing(&mut stream).await;

        // Derive client-side transport cipher context (swapped write/read relative to server)
        let mut client_cipher = shairplay::crypto::chacha_transport::EncryptedChannel::new(
            &session_key,
            "Control-Salt",
            "Control-Write-Encryption-Key",
            "Control-Salt",
            "Control-Read-Encryption-Key",
        )
        .unwrap();

        let mut dict = plist::Dictionary::new();
        dict.insert("isRemoteControlOnly".into(), plist::Value::Boolean(true));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &dict).unwrap();

        let req_header = format!(
            "SETUP rtsp://127.0.0.1/{} RTSP/1.0\r\nCSeq: 3\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
            port,
            body.len()
        );
        let mut plaintext = req_header.into_bytes();
        plaintext.extend_from_slice(&body);

        let encrypted_req = client_cipher.encrypt_ctx.encrypt(&plaintext).unwrap();
        stream.write_all(&encrypted_req).await.unwrap();

        // Read and decrypt the response from the server
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let (decrypted_resp, _) = client_cipher.decrypt_ctx.decrypt(&buf[..n]).unwrap();
        let resp = String::from_utf8_lossy(&decrypted_resp).to_string();
        assert!(resp.contains("200 OK"), "SETUP should be 200, got: {resp}");

        let header_end = resp.find("\r\n\r\n").unwrap() + 4;
        let body_bytes = &decrypted_resp[header_end..];
        let cursor = std::io::Cursor::new(body_bytes);
        let plist_val = plist::Value::from_reader(cursor).expect("SETUP body should be plist");
        let resp_dict = plist_val.as_dictionary().expect("should be dictionary");

        assert!(resp_dict.contains_key("eventPort"), "should contain eventPort");
        let event_port = resp_dict.get("eventPort").unwrap().as_unsigned_integer().unwrap();
        assert!(event_port > 0, "eventPort should be valid");

        // Verify we can connect to that event port!
        let event_stream = TcpStream::connect(format!("127.0.0.1:{event_port}")).await;
        assert!(event_stream.is_ok(), "should be able to connect to eventPort");

        server.stop().await;
    }
}

#[tokio::test]
#[serial]
async fn set_parameter_volume_calls_handler() {
    let (mut server, port, state) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    let body = "volume: -20.000000\r\n";
    let req = format!(
        "SET_PARAMETER rtsp://127.0.0.1/{} RTSP/1.0\r\nCSeq: 1\r\nContent-Type: text/parameters\r\nContent-Length: {}\r\n\r\n{}",
        port,
        body.len(),
        body
    );
    let resp = send_rtsp(&mut stream, &req).await;
    assert!(resp.contains("200 OK"));

    {
        let volumes = state.volumes.lock().unwrap();
        assert_eq!(volumes.len(), 1);
        assert!((volumes[0] - (-20.0)).abs() < 0.01);
    }

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn set_parameter_metadata_calls_handler() {
    let (mut server, port, state) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // Minimal DMAP: mlit container with minm("Test")
    let dmap: &[u8] = &[
        0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x0c, 0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x54, 0x65,
        0x73, 0x74,
    ];
    let header = format!(
        "SET_PARAMETER rtsp://127.0.0.1/{} RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-dmap-tagged\r\nContent-Length: {}\r\n\r\n",
        port,
        dmap.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(dmap).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200 OK"));

    {
        let meta = state.metadata.lock().unwrap();
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0].title.as_deref(), Some("Test"));
    }

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn set_parameter_coverart_calls_handler() {
    let (mut server, port, state) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    let jpeg = b"\xff\xd8\xff\xe0fake-jpeg-data";
    let header = format!(
        "SET_PARAMETER rtsp://127.0.0.1/{} RTSP/1.0\r\nCSeq: 1\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
        port,
        jpeg.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(jpeg).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200 OK"));

    {
        let art = state.coverart.lock().unwrap();
        assert_eq!(art.len(), 1);
        assert_eq!(&art[0], jpeg);
    }

    server.stop().await;
}
