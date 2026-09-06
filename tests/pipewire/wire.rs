use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Exchange {
    pub(super) request: String,
    pub(super) status: u16,
    pub(super) response_bytes: usize,
    pub(super) normal_headers: bool,
    pub(super) exact_probe: bool,
}

pub(super) fn verify(events: &[Exchange], expected: u16) {
    let mut sequence = Vec::new();
    for event in events {
        assert!(event.normal_headers, "{event:?}");
        if event.request == "POST /auth-setup" {
            assert!(event.exact_probe);
            assert_eq!(event.status, expected);
            assert_eq!(event.response_bytes, 0);
        }
        if event.request != "SET_PARAMETER" {
            sequence.push(event.request.as_str());
        }
        if expected == 200 {
            assert_eq!(event.status, 200);
        }
    }
    if expected == 200 {
        assert_eq!(
            sequence,
            [
                "OPTIONS",
                "POST /auth-setup",
                "ANNOUNCE",
                "SETUP",
                "RECORD",
                "TEARDOWN"
            ]
        );
    } else {
        assert_eq!(sequence, ["OPTIONS", "POST /auth-setup"]);
    }
}

struct Message {
    raw: Vec<u8>,
    first_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Message {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

async fn message(stream: &mut BufReader<TcpStream>) -> Option<Message> {
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        match stream.read_u8().await {
            Ok(byte) => raw.push(byte),
            Err(error) if raw.is_empty() && error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return None;
            }
            Err(error) => panic!("incomplete RTSP message: {error}"),
        }
        assert!(raw.len() <= 65536);
    }
    let end = raw.windows(2).position(|w| w == b"\r\n").unwrap();
    let first_line = std::str::from_utf8(&raw[..end]).unwrap().to_owned();
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let httparse::Status::Complete((_, headers)) =
        httparse::parse_headers(&raw[end + 2..], &mut headers).unwrap()
    else {
        panic!("incomplete headers");
    };
    let headers: Vec<_> = headers
        .iter()
        .map(|h| {
            (
                h.name.to_owned(),
                std::str::from_utf8(h.value).unwrap().to_owned(),
            )
        })
        .collect();
    let mut result = Message {
        raw,
        first_line,
        headers,
        body: Vec::new(),
    };
    let length = result
        .header("Content-Length")
        .unwrap_or("0")
        .parse::<usize>()
        .unwrap();
    assert!(length <= 65536);
    result.body.resize(length, 0);
    stream.read_exact(&mut result.body).await.unwrap();
    result.raw.extend_from_slice(&result.body);
    Some(result)
}

pub(super) struct Proxy {
    pub(super) port: u16,
    events: Arc<Mutex<Vec<Exchange>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    task: JoinHandle<()>,
}

impl Proxy {
    pub(super) async fn start(receiver_port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let events = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (records, done) = (events.clone(), closed.clone());
        let task = tokio::spawn(async move {
            loop {
                let (client, _) = listener.accept().await.unwrap();
                done.store(false, std::sync::atomic::Ordering::SeqCst);
                let mut client = BufReader::new(client);
                let mut receiver = BufReader::new(
                    TcpStream::connect(("127.0.0.1", receiver_port))
                        .await
                        .unwrap(),
                );
                while let Some(request) = message(&mut client).await {
                    receiver.get_mut().write_all(&request.raw).await.unwrap();
                    let response = message(&mut receiver).await.expect("receiver response");
                    let event = exchange(&request, &response);
                    client.get_mut().write_all(&response.raw).await.unwrap();
                    let mut events = records.lock().unwrap();
                    assert!(events.len() < 64, "excessive RTSP exchanges");
                    events.push(event);
                }
                done.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        Self {
            port,
            events,
            closed,
            task,
        }
    }

    pub(super) fn events(&self) -> Vec<Exchange> {
        self.events.lock().unwrap().clone()
    }

    pub(super) async fn wait_for(&self, start: usize, request: &str, status: u16) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if self.events()[start..]
                    .iter()
                    .any(|e| e.request == request && e.status == status)
                {
                    break;
                }
                assert!(!self.task.is_finished(), "RTSP observer stopped");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing {request} -> {status}: {:?}", self.events()));
    }

    pub(super) async fn wait_closed(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.closed.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("sender must close rejected connection");
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn exchange(request: &Message, response: &Message) -> Exchange {
    let mut parts = request.first_line.split_whitespace();
    let method = parts.next().unwrap();
    let target = parts.next().unwrap();
    let name = if target == "/auth-setup" {
        assert_eq!(method, "POST");
        assert_eq!(
            request.header("Content-Type"),
            Some("application/octet-stream")
        );
        assert_eq!(request.header("Content-Length"), Some("33"));
        if response.first_line.split_whitespace().nth(1) == Some("200") {
            assert_eq!(response.header("Content-Length"), Some("0"));
        }
        "POST /auth-setup"
    } else {
        method
    };
    if method == "ANNOUNCE" {
        let sdp = std::str::from_utf8(&request.body).unwrap();
        assert!(sdp.contains("a=rtpmap:96 AppleLossless\r\n"));
        assert!(!sdp.contains("rsaaeskey") && !sdp.contains("aesiv"));
    }
    Exchange {
        request: name.to_owned(),
        status: response
            .first_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap(),
        response_bytes: response.body.len(),
        normal_headers: request.header("CSeq").is_some()
            && request.header("CSeq") == response.header("CSeq")
            && response.header("Server") == Some("AirTunes/105.1"),
        exact_probe: target == "/auth-setup"
            && request.body
                == hex::decode(include_str!("../fixtures/pipewire-auth-setup.hex").trim()).unwrap(),
    }
}

#[test]
fn exchange_sequence_oracle_rejects_missing_reordered_or_failed_steps() {
    let events: Vec<_> = [
        "OPTIONS",
        "POST /auth-setup",
        "ANNOUNCE",
        "SETUP",
        "RECORD",
        "TEARDOWN",
    ]
    .into_iter()
    .map(|method| Exchange {
        request: method.into(),
        status: 200,
        response_bytes: 0,
        normal_headers: true,
        exact_probe: method == "POST /auth-setup",
    })
    .collect();
    verify(&events, 200);
    assert!(std::panic::catch_unwind(|| verify(&events[..5], 200)).is_err());
    let mut swapped = events.clone();
    swapped.swap(2, 3);
    assert!(std::panic::catch_unwind(|| verify(&swapped, 200)).is_err());
    let mut failed = events.clone();
    failed[4].status = 400;
    assert!(std::panic::catch_unwind(|| verify(&failed, 200)).is_err());
    let mut headers = events;
    headers[1].normal_headers = false;
    assert!(std::panic::catch_unwind(|| verify(&headers, 200)).is_err());
}

#[test]
fn rejected_probe_must_not_proceed_to_announce() {
    for status in [401, 404] {
        let mut events: Vec<_> = ["OPTIONS", "POST /auth-setup"]
            .into_iter()
            .map(|method| Exchange {
                request: method.into(),
                status: if method == "OPTIONS" { 200 } else { status },
                response_bytes: 0,
                normal_headers: true,
                exact_probe: method == "POST /auth-setup",
            })
            .collect();
        verify(&events, status);
        events.push(Exchange {
            request: "ANNOUNCE".into(),
            status: 200,
            response_bytes: 0,
            normal_headers: true,
            exact_probe: false,
        });
        assert!(std::panic::catch_unwind(|| verify(&events, status)).is_err());
    }
}
