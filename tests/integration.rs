//! Integration tests: start a real RaopServer, connect via TCP, exercise the RTSP protocol.

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use shairplay::{AudioFormat, AudioHandler, AudioSession, RaopServer};

struct TestHandler {
    inits: Arc<Mutex<Vec<AudioFormat>>>,
}

struct TestSession {
    samples: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AudioHandler for TestHandler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        self.inits.lock().unwrap().push(format);
        Box::new(TestSession { samples: Arc::new(Mutex::new(Vec::new())) })
    }
}

impl AudioSession for TestSession {
    fn audio_process(&mut self, buffer: &[u8]) {
        self.samples.lock().unwrap().push(buffer.to_vec());
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
async fn server_start_stop() {
    let (mut server, port, _) = start_server().await;
    assert!(server.is_running());
    assert!(port > 0);

    let info = server.service_info();
    assert_eq!(info.port, port);
    assert_eq!(info.airplay_name, "IntegrationTest");
    assert_eq!(info.raop_txt.get("ch").map(|s| s.as_str()), Some("2"));

    server.stop().await;
    assert!(!server.is_running());
}

#[tokio::test]
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
