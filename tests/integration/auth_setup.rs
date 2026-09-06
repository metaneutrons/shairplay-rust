//! Baseline for the source-derived PipeWire probe; no compatibility route yet.

use super::{ap1_builder, empty_handler, raop_txt, start_server};
use md5::{Digest, Md5};
use serial_test::serial;
use shairplay::proto::http::HttpRequest;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const IO_TIMEOUT: Duration = Duration::from_secs(2);

fn probe() -> Vec<u8> {
    hex::decode(include_str!("../fixtures/pipewire-auth-setup.hex").trim())
        .expect("valid source-derived probe hex")
}

fn request(cseq: u32, authorization: Option<&str>) -> Vec<u8> {
    let body = probe();
    let mut wire = format!(
        "POST /auth-setup RTSP/1.0\r\nCSeq: {cseq}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(authorization) = authorization {
        wire.push_str(&format!("Authorization: {authorization}\r\n"));
    }
    wire.push_str("\r\n");
    let mut wire = wire.into_bytes();
    wire.extend_from_slice(&body);
    wire
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        let mut values = self
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name));
        let value = values.next().map(|(_, value)| value.as_str());
        assert!(values.next().is_none(), "duplicate response header: {name}");
        value
    }

    fn assert_empty(&self, status: u16, cseq: &str) {
        assert_eq!(self.status, status);
        assert_eq!(self.header("CSeq"), Some(cseq));
        assert_eq!(self.header("Server"), Some("AirTunes/105.1"));
        assert!(self.body.is_empty());
    }
}

async fn connect(port: u16) -> BufReader<TcpStream> {
    BufReader::new(
        tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
            .await
            .expect("connection deadline")
            .expect("connect to receiver"),
    )
}

async fn write(client: &mut BufReader<TcpStream>, wire: &[u8]) {
    tokio::time::timeout(IO_TIMEOUT, client.get_mut().write_all(wire))
        .await
        .expect("write deadline")
        .expect("write request");
}

async fn read_response(client: &mut BufReader<TcpStream>) -> Response {
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut wire = Vec::new();
        // Read one bounded header block without assuming a TCP read is a message.
        while !wire.ends_with(b"\r\n\r\n") {
            assert!(wire.len() < 8192, "response headers exceed test budget");
            wire.push(client.read_u8().await.expect("complete response headers"));
        }
        assert!(wire.starts_with(b"RTSP/1.0 "));
        wire[..4].copy_from_slice(b"HTTP");
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        assert_eq!(
            parsed.parse(&wire).expect("valid response framing"),
            httparse::Status::Complete(wire.len())
        );
        let mut response = Response {
            status: parsed.code.expect("response status"),
            headers: parsed
                .headers
                .iter()
                .map(|header| {
                    (
                        header.name.to_owned(),
                        std::str::from_utf8(header.value)
                            .expect("UTF-8 response header")
                            .to_owned(),
                    )
                })
                .collect(),
            body: Vec::new(),
        };
        assert!(response.header("Transfer-Encoding").is_none());
        let length: usize = response
            .header("Content-Length")
            .unwrap_or("0")
            .parse()
            .expect("valid response length");
        assert!(length <= 8192, "response body exceeds test budget");
        response.body.resize(length, 0);
        client
            .read_exact(&mut response.body)
            .await
            .expect("complete response body");
        response
    })
    .await
    .expect("response deadline")
}

#[test]
fn source_probe_survives_every_body_split() {
    let body = probe();
    assert_eq!(body.len(), 33);
    assert_eq!(body[0], 1);
    let wire = request(1, None);
    let body_start = wire.len() - body.len();
    for split in body_start..=wire.len() {
        let mut parsed = HttpRequest::new();
        parsed
            .add_data(&wire[..split])
            .unwrap_or_else(|error| panic!("split {split}: {error}"));
        assert_eq!(parsed.is_complete(), split == wire.len());
        parsed.add_data(&wire[split..]).unwrap();
        assert!(parsed.is_complete(), "split at {split}");
        assert_eq!(parsed.method(), Some("POST"));
        assert_eq!(parsed.url(), Some("/auth-setup"));
        assert_eq!(
            parsed.header("Content-Type"),
            Some("application/octet-stream")
        );
        assert_eq!(parsed.data(), Some(body.as_slice()));
    }
}

#[tokio::test]
#[serial]
async fn unavailable_probe_keeps_pipeline_and_discovery_intact() {
    let (mut server, port, state) = start_server().await;
    let before = server.service_info();
    let mut client = connect(port).await;
    let mut wire = request(1, None);
    wire.extend_from_slice(b"OPTIONS * RTSP/1.0\r\nCSeq: 2\r\n\r\n");
    wire.extend_from_slice(&request(3, None));
    write(&mut client, &wire).await;

    read_response(&mut client).await.assert_empty(404, "1");
    read_response(&mut client).await.assert_empty(200, "2");
    read_response(&mut client).await.assert_empty(404, "3");
    assert_eq!(server.service_info().raop_txt, before.raop_txt);
    assert_eq!(server.service_info().airplay_txt, before.airplay_txt);
    assert!(state.inits.lock().unwrap().is_empty());
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn unavailable_probe_in_explicit_ap1_mode_keeps_et_unchanged() {
    let mut server = ap1_builder("AuthSetupAp1Baseline")
        .build(empty_handler())
        .unwrap();
    assert_eq!(raop_txt(&server.service_info(), "et"), "0");
    server.start().await.unwrap();
    let mut client = connect(server.service_info().port).await;
    write(&mut client, &request(1, None)).await;
    read_response(&mut client).await.assert_empty(404, "1");
    assert_eq!(raop_txt(&server.service_info(), "et"), "0");
    server.stop().await;
}

fn authorization(nonce: &str, password: &str) -> String {
    // Independent client calculation: do not ask the server validator for its answer.
    let ha1 = format!("{:x}", Md5::digest(format!("user:airplay:{password}")));
    let ha2 = format!("{:x}", Md5::digest(b"POST:/auth-setup"));
    let response = format!("{:x}", Md5::digest(format!("{ha1}:{nonce}:{ha2}")));
    format!(
        "Digest username=\"user\", realm=\"airplay\", nonce=\"{nonce}\", uri=\"/auth-setup\", response=\"{response}\""
    )
}

#[tokio::test]
#[serial]
async fn digest_remains_required_for_each_probe_even_after_valid_authorization() {
    let mut server = ap1_builder("AuthSetupDigestBaseline")
        .password("test-password")
        .build(empty_handler())
        .unwrap();
    server.start().await.unwrap();
    let mut client = connect(server.service_info().port).await;

    write(&mut client, b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n").await;
    let options = read_response(&mut client).await;
    options.assert_empty(200, "1");
    assert!(options.header("WWW-Authenticate").is_none());

    write(&mut client, &request(2, None)).await;
    let challenge = read_response(&mut client).await;
    challenge.assert_empty(401, "2");
    let nonce = challenge
        .header("WWW-Authenticate")
        .unwrap()
        .strip_prefix("Digest realm=\"airplay\", nonce=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap();

    for (cseq, password, expected) in [(3, "incorrect", 401), (4, "test-password", 404)] {
        write(
            &mut client,
            &request(cseq, Some(&authorization(nonce, password))),
        )
        .await;
        read_response(&mut client)
            .await
            .assert_empty(expected, &cseq.to_string());
    }
    write(&mut client, &request(5, None)).await;
    read_response(&mut client).await.assert_empty(401, "5");
    server.stop().await;
}
