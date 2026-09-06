use shairplay::crypto::chacha_transport::EncryptedChannel;

use super::*;

async fn encrypted_response(stream: &mut TcpStream, cipher: &mut EncryptedChannel) -> String {
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut raw = Vec::new();
        let mut plain = Vec::new();
        let mut chunk = [0; 1024];
        while !plain.ends_with(b"\r\n\r\n") {
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            raw.extend_from_slice(&chunk[..count]);
            let (bytes, consumed) = cipher.decrypt_ctx.decrypt(&raw).unwrap();
            plain.extend_from_slice(&bytes);
            raw.drain(..consumed);
            assert!(raw.len() < 8192 && plain.len() < 8192);
        }
        assert!(raw.is_empty());
        String::from_utf8(plain).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
#[serial]
async fn ap2_paired_connection_cannot_use_classic_compatibility_ack() {
    let (mut server, handler) = start().await;
    let mut client = connect(server.service_info().port).await;
    write(&mut client, &request(1, None)).await;
    read_response(&mut client).await.assert_empty(200, "1");
    let mut stream = client.into_inner();
    let secret = tokio::time::timeout(
        Duration::from_secs(6),
        crate::ap2_tests::perform_transient_pairing(&mut stream),
    )
    .await
    .unwrap();
    let mut cipher = EncryptedChannel::new(
        &secret,
        "Control-Salt",
        "Control-Write-Encryption-Key",
        "Control-Salt",
        "Control-Read-Encryption-Key",
    )
    .unwrap();
    for body in [probe(), vec![0; 34]] {
        let clear = wire(
            "POST",
            "/auth-setup",
            &format!(
                "Content-Length: {}\r\nContent-Type: application/octet-stream\r\n",
                body.len()
            ),
            &body,
        );
        let encrypted = cipher.encrypt_ctx.encrypt(&clear).unwrap();
        tokio::time::timeout(IO_TIMEOUT, stream.write_all(&encrypted))
            .await
            .unwrap()
            .unwrap();
        let reply = encrypted_response(&mut stream, &mut cipher).await;
        assert!(reply.starts_with("RTSP/1.0 404 Not Found\r\n"));
        assert!(reply.contains("\r\nCSeq: 1\r\n"));
        assert!(reply.contains("\r\nServer: AirTunes/105.1\r\n"));
    }
    assert!(handler.inits.lock().unwrap().is_empty());
    drop(stream);
    server.stop().await;
}
