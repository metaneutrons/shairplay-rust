use super::*;
use shairplay::{RaopServer, RaopServerBuilder};

#[path = "enabled/playback.rs"]
mod playback;

#[cfg(feature = "ap2")]
#[path = "enabled/ap2.rs"]
mod ap2;

fn builder() -> RaopServerBuilder {
    ap1_builder("PipeWireCompatibility")
        .hwaddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
        .pipewire_auth_setup_compat(true)
}

async fn start() -> (RaopServer, std::sync::Arc<crate::TestHandler>) {
    let handler = empty_handler();
    let mut server = builder().build(handler.clone()).unwrap();
    server.start().await.unwrap();
    (server, handler)
}

fn wire(method: &str, path: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut result = format!("{method} {path} RTSP/1.0\r\nCSeq: 1\r\n{headers}\r\n").into_bytes();
    result.extend_from_slice(body);
    result
}

async fn assert_closed(client: &mut BufReader<TcpStream>) {
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(IO_TIMEOUT, client.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

async fn reject(port: u16, wire: &[u8], routed: bool) {
    let mut client = connect(port).await;
    write(&mut client, wire).await;
    let response = read_response(&mut client).await;
    assert_eq!(response.status, 400);
    assert_eq!(response.header("Connection"), Some("close"));
    assert!(response.body.is_empty());
    if routed {
        response.assert_empty(400, "1");
        assert_eq!(response.header("Content-Length"), Some("0"));
    }
    assert_closed(&mut client).await;
}

#[test]
fn opt_in_does_not_change_ap1_discovery() {
    let disabled = builder()
        .pipewire_auth_setup_compat(false)
        .build(empty_handler())
        .unwrap();
    let enabled = builder().build(empty_handler()).unwrap();
    assert_eq!(
        enabled.service_info().raop_txt,
        disabled.service_info().raop_txt
    );
    assert_eq!(
        enabled.service_info().airplay_txt,
        disabled.service_info().airplay_txt
    );
    assert_eq!(raop_txt(&enabled.service_info(), "et"), "0");
}

#[cfg(feature = "ap2")]
#[test]
fn enabling_in_ap2_mode_is_rejected_without_changing_defaults() {
    let result = RaopServer::builder()
        .pipewire_auth_setup_compat(true)
        .build(empty_handler());
    assert!(matches!(
        result,
        Err(shairplay::ShairplayError::Server(
            shairplay::error::ServerError::InvalidConfiguration(
                "PipeWire auth-setup compatibility requires AirPlayMode::AirPlay1"
            )
        ))
    ));
    let disabled = RaopServer::builder()
        .pipewire_auth_setup_compat(false)
        .build(empty_handler())
        .unwrap();
    assert_eq!(raop_txt(&disabled.service_info(), "et"), "0,3,5");
}

#[tokio::test]
#[serial]
async fn opt_in_can_be_explicitly_disabled_again() {
    let mut server = builder()
        .pipewire_auth_setup_compat(false)
        .build(empty_handler())
        .unwrap();
    server.start().await.unwrap();
    let mut client = connect(server.service_info().port).await;
    let request = wire("POST", "/auth-setup", "Content-Length: 34\r\n", &[0; 34]);
    write(&mut client, &request).await;
    read_response(&mut client).await.assert_empty(404, "1");
    drop(client);
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn accepts_only_exact_probe_with_supported_media_type() {
    let (mut server, handler) = start().await;
    let mut client = connect(server.service_info().port).await;
    for (length, media_type) in [
        ("33", "application/octet-stream"),
        ("0033", "APPLICATION/OCTET-STREAM"),
        ("\t33 \t", " \tApplication/Octet-Stream\t "),
    ] {
        let headers = format!("Content-Length: {length}\r\nContent-Type: {media_type}\r\n");
        write(
            &mut client,
            &wire("POST", "/auth-setup", &headers, &probe()),
        )
        .await;
        let response = read_response(&mut client).await;
        response.assert_empty(200, "1");
        assert_eq!(response.header("Content-Length"), Some("0"));
        assert!(response.header("WWW-Authenticate").is_none());
    }
    assert!(handler.inits.lock().unwrap().is_empty());
    drop(client);
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn every_probe_bit_mutation_is_rejected_and_closed() {
    let (mut server, handler) = start().await;
    let original = probe();
    for index in 0..original.len() {
        for bit in 0..8 {
            let mut body = original.clone();
            body[index] ^= 1 << bit;
            let request = wire(
                "POST",
                "/auth-setup",
                "Content-Length: 33\r\nContent-Type: application/octet-stream\r\n",
                &body,
            );
            reject(server.service_info().port, &request, true).await;
        }
    }
    assert!(handler.inits.lock().unwrap().is_empty());
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn rejects_missing_or_unsupported_media_type() {
    let (mut server, _) = start().await;
    for extra in [
        "",
        "Content-Type:\r\n",
        "Content-Type: application/json\r\n",
        "Content-Type: application/octet-stream; charset=binary\r\n",
        "Content-Type: application/octet-stream, application/octet-stream\r\n",
    ] {
        let headers = format!("Content-Length: 33\r\n{extra}");
        reject(
            server.service_info().port,
            &wire("POST", "/auth-setup", &headers, &probe()),
            true,
        )
        .await;
    }
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn rejects_bad_framing_from_headers_without_waiting_for_body() {
    let (mut server, _) = start().await;
    for framing in [
        "",
        "Content-Length: 0\r\n",
        "Content-Length: 32\r\n",
        "Content-Length: 34\r\n",
        "Content-Length: 1048576\r\n",
        "Content-Length: -33\r\n",
        "Content-Length: +33\r\n",
        "Content-Length: x\r\n",
        "Content-Length: 33,33\r\n",
        "Content-Length: 33\r\ncOnTeNt-LeNgTh: 33\r\n",
        "Content-Length: 33\r\nContent-Length: 34\r\n",
        "Content-Length: 33\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: 33\r\nContent-Type: application/octet-stream\r\n",
    ] {
        let headers = format!("Content-Type: application/octet-stream\r\n{framing}");
        reject(
            server.service_info().port,
            &wire("POST", "/auth-setup", &headers, &[]),
            false,
        )
        .await;
    }
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn strict_target_matching_preserves_other_routes() {
    let (mut server, _) = start().await;
    let mut client = connect(server.service_info().port).await;
    for (method, path, status) in [
        ("GET", "/auth-setup", 404),
        ("PUT", "/auth-setup", 404),
        ("POST", "/auth-setup?x=1", 404),
        ("POST", "/auth-setup#fragment", 404),
        ("POST", "/auth-setup/", 404),
        ("POST", "/AUTH-SETUP", 404),
        ("POST", "/auth%2Dsetup", 404),
        ("POST", "rtsp://127.0.0.1/auth-setup", 404),
        ("OPTIONS", "/auth-setup?x=1", 200),
        ("OPTIONS", "*", 200),
    ] {
        write(
            &mut client,
            &wire(method, path, "Content-Length: 34\r\n", &[0; 34]),
        )
        .await;
        read_response(&mut client).await.assert_empty(status, "1");
    }
    drop(client);
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn enabled_probe_preserves_digest_on_every_request() {
    verify_digest(true).await;
}

#[tokio::test]
#[serial]
async fn digest_precedes_semantic_validation_but_not_length_rejection() {
    let mut server = builder()
        .password("test-password")
        .build(empty_handler())
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    let mut client = connect(port).await;
    let invalid = wire(
        "POST",
        "/auth-setup",
        "Content-Length: 33\r\nContent-Type: application/json\r\n",
        &[0; 33],
    );
    write(&mut client, &invalid).await;
    let challenge = read_response(&mut client).await;
    challenge.assert_empty(401, "1");
    let nonce = challenge
        .header("WWW-Authenticate")
        .unwrap()
        .strip_prefix("Digest realm=\"airplay\", nonce=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap();
    let headers = format!(
        "Content-Length: 33\r\nContent-Type: application/octet-stream\r\nAuthorization: {}\r\n",
        authorization(nonce, "test-password")
    );
    write(
        &mut client,
        &wire("POST", "/auth-setup", &headers, &[0; 33]),
    )
    .await;
    read_response(&mut client).await.assert_empty(400, "1");
    assert_closed(&mut client).await;
    reject(
        port,
        &wire("POST", "/auth-setup", "Content-Length: 34\r\n", &[]),
        false,
    )
    .await;
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn enabled_pipeline_preserves_large_bodies_and_discovery() {
    let (mut server, handler) = start().await;
    let before = server.service_info();
    let mut client = connect(before.port).await;
    let art = vec![0x55; 128 * 1024];
    let mut pipeline = request(1, None);
    pipeline.extend_from_slice(&wire(
        "SET_PARAMETER",
        "/stream",
        &format!(
            "Content-Type: image/jpeg\r\nContent-Length: {}\r\n",
            art.len()
        ),
        &art,
    ));
    pipeline.extend_from_slice(&request(2, None));
    write(&mut client, &pipeline).await;
    for cseq in ["1", "1", "2"] {
        read_response(&mut client).await.assert_empty(200, cseq);
    }
    assert_eq!(*handler.coverart.lock().unwrap(), vec![art]);
    assert!(handler.inits.lock().unwrap().is_empty());
    assert_eq!(server.service_info().raop_txt, before.raop_txt);
    assert_eq!(server.service_info().airplay_txt, before.airplay_txt);
    drop(client);
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn incomplete_body_uses_absolute_deadline_and_releases_client_slot() {
    let mut server = builder().max_clients(1).build(empty_handler()).unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    let mut client = connect(port).await;
    let wire = request(1, None);
    tokio::time::timeout(Duration::from_secs(7), async {
        write(&mut client, &wire[..wire.len() - 32]).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        write(&mut client, &[probe()[1]]).await;
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    })
    .await
    .expect("body deadline must not slide with each byte");
    let mut next = connect(port).await;
    write(&mut next, &request(2, None)).await;
    read_response(&mut next).await.assert_empty(200, "2");
    drop(next);
    server.stop().await;
}
