//! Integration tests: start a real RaopServer, connect via TCP, exercise the RTSP protocol.
//! Tests are serialized to avoid mDNS registration conflicts.

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use serial_test::serial;

use shairplay::{AudioFormat, AudioHandler, AudioSession, RaopServer};

struct TestHandler {
    inits: Arc<Mutex<Vec<AudioFormat>>>,
}

struct TestSession {
    samples: Arc<Mutex<Vec<Vec<f32>>>>,
}

impl AudioHandler for TestHandler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        self.inits.lock().unwrap().push(format);
        Box::new(TestSession { samples: Arc::new(Mutex::new(Vec::new())) })
    }
}

impl AudioSession for TestSession {
    fn audio_process(&mut self, samples: &[f32]) {
        self.samples.lock().unwrap().push(samples.to_vec());
    }
}



async fn start_server() -> (RaopServer, u16, Arc<Mutex<Vec<AudioFormat>>>) {
    let inits = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(TestHandler { inits: inits.clone() });
    let mut server = RaopServer::builder()
        .name("IntegrationTest")
        
        .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        .port(0) // auto-assign
        .build(handler)
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    (server, port, inits)
}

async fn send_rtsp(stream: &mut TcpStream, request: &str) -> String {
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
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
    assert_eq!(info.raop_txt.iter().find(|(k,_)| k == "cn").map(|(_,v)| v.as_str()), Some("0,1"));

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
async fn pair_setup_returns_public_key() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // Send 32 bytes of dummy pair-setup data
    let body = [0x42u8; 32];
    let req = format!(
        "POST /pair-setup HTTP/1.0\r\nCSeq: 1\r\nContent-Length: 32\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
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
    let handler = Arc::new(TestHandler { inits: Arc::new(Mutex::new(Vec::new())) });
    let mut server = RaopServer::builder()
        .name("AuthTest")
        
        .hwaddr([0xAA; 6])
        .port(0)
        .password("secret123")
        .build(handler)
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
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut buf),
    ).await.expect("server did not close connection within 2s").unwrap();
    assert_eq!(n, 0, "expected EOF after TEARDOWN");

    server.stop().await;
}

// --- AirPlay 2 integration tests ---

#[cfg(feature = "ap2")]
mod ap2_tests {
    use super::*;
    use shairplay::crypto::tlv::{TlvValues, TlvType};
    use shairplay::crypto::pairing_homekit;
    use num_bigint::BigUint;

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
        assert!(resp.contains("200 OK"), "M2 should be 200, got: {}", &resp[..resp.len().min(100)]);

        // Parse M2 response body — find the body after \r\n\r\n
        let header_end = resp.find("\r\n\r\n").unwrap() + 4;
        let body = &buf[header_end..n];
        let m2 = TlvValues::decode(body).expect("M2 should be valid TLV");
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b = m2.get_type(TlvType::PublicKey).unwrap();
        assert_eq!(salt.len(), 16);
        assert!(pk_b.len() > 0 && pk_b.len() <= 384);

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
                url, cseq, body.len()
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
        use sha2::{Sha512, Digest};
        fn to_bytes_be(n: &BigUint) -> Vec<u8> { let b = n.to_bytes_be(); if b.is_empty() { vec![0] } else { b } }
        fn to_padded(n: &BigUint, len: usize) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.len() >= len { b } else { let mut p = vec![0u8; len - b.len()]; p.extend(&b); p }
        }
        fn sha512(d: &[u8]) -> [u8; 64] { let mut h = Sha512::new(); h.update(d); h.finalize().into() }
        fn h_nn_pad(n1: &BigUint, n2: &BigUint, l: usize) -> BigUint {
            let mut b = Vec::new(); b.extend(&to_padded(n1, l)); b.extend(&to_padded(n2, l));
            BigUint::from_bytes_be(&sha512(&b))
        }

        let k = h_nn_pad(&n, &g, 384);
        let u = h_nn_pad(&big_a, &big_b, 384);

        let mut h = Sha512::new(); h.update(b"Pair-Setup"); h.update(b":"); h.update(b"3939");
        let ucp = h.finalize();
        let mut buf2 = Vec::new(); buf2.extend(&to_bytes_be(&salt_bn)); buf2.extend(&ucp);
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
        for i in 0..64 { h_xor[i] = h_n[i] ^ h_g[i]; }
        let h_i = sha512(b"Pair-Setup");
        let mut h = Sha512::new();
        h.update(&h_xor); h.update(&h_i); h.update(&to_bytes_be(&salt_bn));
        h.update(&to_bytes_be(&big_a)); h.update(&to_bytes_be(&big_b));
        h.update(&session_key);
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
        h.update(&to_bytes_be(&big_a)); h.update(&client_m); h.update(&session_key);
        let expected_hamk: [u8; 64] = h.finalize().into();
        assert_eq!(server_proof, &expected_hamk[..], "Server proof should match");

        server.stop().await;
    }
}
