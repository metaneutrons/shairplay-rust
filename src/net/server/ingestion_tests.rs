use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::DuplexStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{advance, timeout};

use super::*;

const BODY_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Observations {
    policies: AtomicUsize,
    dispatches: AtomicUsize,
    headers: Notify,
}

#[derive(Default)]
struct BoundedHandler {
    observed: Arc<Observations>,
    #[cfg(feature = "ap2")]
    channel: Option<crate::crypto::chacha_transport::EncryptedChannel>,
}

impl ConnectionHandler for BoundedHandler {
    fn request_body_policy(
        &self,
        request: &HttpRequest,
    ) -> Result<RequestBodyPolicy, ProtocolError> {
        self.observed.policies.fetch_add(1, Ordering::SeqCst);
        self.observed.headers.notify_one();
        if request.url() != Some("/bounded") {
            return Ok(RequestBodyPolicy::default());
        }
        if request.header("content-length").is_none() {
            return Err(ProtocolError::InvalidRtsp("length required".into()));
        }
        Ok(RequestBodyPolicy {
            max_bytes: 33,
            completion_timeout: Some(BODY_TIMEOUT),
        })
    }

    fn conn_request(&mut self, request: &HttpRequest) -> HttpResponse {
        self.observed.dispatches.fetch_add(1, Ordering::SeqCst);
        let mut response = HttpResponse::new("RTSP/1.0", 200, "OK");
        response.add_header(
            "Body-Bytes",
            &request.data().map_or(0, <[u8]>::len).to_string(),
        );
        response.finish(None);
        response
    }

    #[cfg(feature = "ap2")]
    fn is_encrypted(&self) -> bool {
        self.channel.is_some()
    }

    #[cfg(feature = "ap2")]
    fn decrypt_incoming(&mut self, data: &[u8]) -> Option<(Vec<u8>, usize)> {
        self.channel.as_mut().map_or_else(
            || Some((data.to_vec(), data.len())),
            |channel| channel.decrypt_ctx.decrypt(data).ok(),
        )
    }

    #[cfg(feature = "ap2")]
    fn encrypt_outgoing(&mut self, data: &[u8]) -> Vec<u8> {
        self.channel.as_mut().map_or_else(
            || data.to_vec(),
            |channel| channel.encrypt_ctx.encrypt(data).unwrap(),
        )
    }
}

fn spawn(handler: BoundedHandler) -> (DuplexStream, JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let task = tokio::spawn(process_connection(
        server,
        Box::new(handler),
        "127.0.0.1:5000".parse().unwrap(),
        ConnectionConfig::default(),
    ));
    (client, task)
}

async fn read_closed(client: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn headers(path: &str, size: usize) -> Vec<u8> {
    format!("POST {path} RTSP/1.0\r\nContent-Length: {size}\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn rejects_from_headers_without_waiting_for_body_or_dispatching() {
    for metadata in [
        "",
        "Content-Length: 34\r\n",
        "Content-Length: nope\r\n",
        "Content-Length: 33\r\nContent-Length: 33\r\n",
        "Content-Length: 33\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let handler = BoundedHandler::default();
        let observed = handler.observed.clone();
        let (mut client, task) = spawn(handler);
        let wire = format!("POST /bounded RTSP/1.0\r\n{metadata}\r\n");
        client.write_all(wire.as_bytes()).await.unwrap();
        let response = String::from_utf8(read_closed(&mut client).await).unwrap();
        assert!(
            response.starts_with("RTSP/1.0 400"),
            "{metadata}: {response}"
        );
        assert!(response.contains("Connection: close\r\n"));
        assert_eq!(observed.dispatches.load(Ordering::SeqCst), 0);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn reapplies_policy_to_pipeline_and_preserves_larger_endpoint() {
    let handler = BoundedHandler::default();
    let observed = handler.observed.clone();
    let (mut client, task) = spawn(handler);
    let mut wire = headers("/bounded", 33);
    wire.extend_from_slice(&[1; 33]);
    wire.extend_from_slice(&headers("/large", 128 * 1024));
    wire.resize(wire.len() + 128 * 1024, b'x');
    wire.extend_from_slice(&headers("/bounded", 34));
    // The invalid last request is already buffered; no further read is required to reject it.
    client.write_all(&wire).await.unwrap();
    let response = String::from_utf8(read_closed(&mut client).await).unwrap();
    assert_eq!(response.matches("RTSP/1.0 200").count(), 2);
    assert_eq!(response.matches("RTSP/1.0 400").count(), 1);
    assert!(response.contains("Body-Bytes: 33\r\n"));
    assert!(response.contains("Body-Bytes: 131072\r\n"));
    assert_eq!(observed.policies.load(Ordering::SeqCst), 3);
    assert_eq!(observed.dispatches.load(Ordering::SeqCst), 2);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn absolute_body_deadline_does_not_slide_and_starts_after_headers() {
    let handler = BoundedHandler::default();
    let observed = handler.observed.clone();
    let (mut client, task) = spawn(handler);
    client.write_all(b"POST /bounded R").await.unwrap();
    advance(BODY_TIMEOUT * 2).await;
    assert!(!task.is_finished());
    assert_eq!(observed.policies.load(Ordering::SeqCst), 0);
    client
        .write_all(b"TSP/1.0\r\nContent-Length: 33\r\n\r\n")
        .await
        .unwrap();
    observed.headers.notified().await;
    for _ in 0..4 {
        advance(Duration::from_secs(1)).await;
        client.write_all(b"x").await.unwrap();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
    }
    advance(Duration::from_secs(1)).await;
    assert!(read_closed(&mut client).await.is_empty());
    task.await.unwrap();
    assert_eq!(observed.policies.load(Ordering::SeqCst), 1);
    assert_eq!(observed.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn completed_body_clears_deadline_and_next_request_gets_its_own() {
    let handler = BoundedHandler::default();
    let observed = handler.observed.clone();
    let mut pending = PendingRequest::default();
    pending
        .add_data(&handler, &headers("/bounded", 33))
        .unwrap();
    let first_deadline = pending.body_deadline.unwrap();
    advance(Duration::from_secs(4)).await;
    pending.add_data(&handler, &[1; 33]).unwrap();
    assert!(pending.body_deadline.is_none());
    let (mut client, mut server) = tokio::io::duplex(1024);
    let mut handler = handler;
    assert!(
        send_completed_responses(
            &mut server,
            &mut handler,
            &mut pending,
            ConnectionConfig::default()
        )
        .await
    );
    pending
        .add_data(&handler, &headers("/bounded", 33))
        .unwrap();
    assert_eq!(
        pending.body_deadline.unwrap(),
        first_deadline + Duration::from_secs(4)
    );
    assert_eq!(observed.policies.load(Ordering::SeqCst), 2);
    let mut response = [0; 128];
    assert!(client.read(&mut response).await.unwrap() > 0);
}

struct BoundedCallbacks(Arc<Observations>);

impl HttpdCallbacks for BoundedCallbacks {
    fn conn_init(
        self: Arc<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
    ) -> Option<Box<dyn ConnectionHandler>> {
        Some(Box::new(BoundedHandler {
            observed: self.0.clone(),
            #[cfg(feature = "ap2")]
            channel: None,
        }))
    }
}

#[tokio::test]
async fn deadline_releases_real_tcp_client_slot() {
    let observed = Arc::new(Observations::default());
    let callbacks = Arc::new(BoundedCallbacks(observed.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let semaphore = Arc::new(Semaphore::new(1));
    let (shutdown, receiver) = watch::channel(false);
    spawn_accept_loop(
        listener,
        callbacks,
        semaphore.clone(),
        receiver,
        ConnectionConfig::default(),
    );
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(&headers("/bounded", 33)).await.unwrap();
    observed.headers.notified().await;
    assert_eq!(semaphore.available_permits(), 0);
    // Real TCP readiness is driven by the OS, not Tokio's virtual test clock.
    let mut response = Vec::new();
    timeout(
        BODY_TIMEOUT + TEST_TIMEOUT,
        client.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.is_empty());
    assert_eq!(semaphore.available_permits(), 1);
    let mut next = tokio::net::TcpStream::connect(address).await.unwrap();
    next.write_all(b"OPTIONS * RTSP/1.0\r\n\r\n").await.unwrap();
    next.shutdown().await.unwrap();
    assert!(read_closed(&mut next).await.starts_with(b"RTSP/1.0 200"));
    shutdown.send(true).unwrap();
}

#[tokio::test]
async fn encrypted_buffer_limit_is_checked_before_copying() {
    let mut handler = BoundedHandler::default();
    let mut pending = PendingRequest::default();
    let mut raw = vec![0; MAX_ENCRYPTED_BUFFER_LEN];
    let mut sink = tokio::io::sink();
    assert!(
        !ingest_encrypted_data(
            &mut sink,
            &mut handler,
            &mut pending,
            &mut raw,
            b"x",
            ConnectionConfig::default()
        )
        .await
    );
    assert_eq!(raw.len(), MAX_ENCRYPTED_BUFFER_LEN);
}

#[cfg(feature = "ap2")]
fn encrypted_pair() -> (
    BoundedHandler,
    crate::crypto::chacha_transport::EncryptedChannel,
) {
    use crate::crypto::chacha_transport::EncryptedChannel;
    let secret = [42; 32];
    let handler = BoundedHandler {
        channel: Some(EncryptedChannel::control(&secret).unwrap()),
        ..BoundedHandler::default()
    };
    let client = EncryptedChannel::new(
        &secret,
        "Control-Salt",
        "Control-Write-Encryption-Key",
        "Control-Salt",
        "Control-Read-Encryption-Key",
    )
    .unwrap();
    (handler, client)
}

#[cfg(feature = "ap2")]
#[tokio::test]
async fn encrypted_fragments_and_pipeline_use_identical_policy() {
    let (mut handler, mut peer) = encrypted_pair();
    let mut wire = headers("/bounded", 33);
    wire.extend_from_slice(&[1; 33]);
    wire.extend_from_slice(&headers("/large", 2048));
    wire.extend_from_slice(&[2; 2048]);
    wire.extend_from_slice(&headers("/bounded", 34));
    let ciphertext = peer.encrypt_ctx.encrypt(&wire).unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let mut pending = PendingRequest::default();
    let mut raw = Vec::new();
    let mut accepted = true;
    for byte in ciphertext {
        assert!(accepted);
        assert!(
            ingest_encrypted_data(
                &mut server,
                &mut handler,
                &mut pending,
                &mut raw,
                &[byte],
                ConnectionConfig::default()
            )
            .await
        );
        accepted = send_completed_responses(
            &mut server,
            &mut handler,
            &mut pending,
            ConnectionConfig::default(),
        )
        .await;
    }
    assert!(!accepted);
    let response = read_closed(&mut client).await;
    let (plain, consumed) = peer.decrypt_ctx.decrypt(&response).unwrap();
    assert_eq!(consumed, response.len());
    let plain = String::from_utf8(plain).unwrap();
    assert_eq!(plain.matches("RTSP/1.0 200").count(), 2);
    assert_eq!(plain.matches("RTSP/1.0 400").count(), 1);
    assert!(plain.contains("Body-Bytes: 2048\r\n"));
    assert_eq!(handler.observed.policies.load(Ordering::SeqCst), 3);
    assert_eq!(handler.observed.dispatches.load(Ordering::SeqCst), 2);
}

#[cfg(feature = "ap2")]
#[tokio::test(start_paused = true)]
async fn encrypted_partial_frame_cannot_extend_body_deadline() {
    let (handler, mut peer) = encrypted_pair();
    let observed = handler.observed.clone();
    let (mut client, task) = spawn(handler);
    let wire = peer.encrypt_ctx.encrypt(&headers("/bounded", 33)).unwrap();
    client.write_all(&wire).await.unwrap();
    observed.headers.notified().await;
    advance(Duration::from_secs(4)).await;
    let body = peer.encrypt_ctx.encrypt(&[1; 33]).unwrap();
    client.write_all(&body[..body.len() - 1]).await.unwrap();
    tokio::task::yield_now().await;
    advance(Duration::from_secs(1)).await;
    assert!(read_closed(&mut client).await.is_empty());
    task.await.unwrap();
    assert_eq!(observed.dispatches.load(Ordering::SeqCst), 0);
}
