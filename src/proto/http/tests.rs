use super::*;

fn parse_fragmented(wire: &[u8]) -> HttpRequest {
    let mut request = HttpRequest::new();
    for byte in wire {
        request.add_data(std::slice::from_ref(byte)).unwrap();
    }
    assert!(request.is_complete());
    request
}

#[test]
fn translates_only_the_request_line_version() {
    for protocol in ["HTTP/1.0", "HTTP/1.1", "RTSP/1.0"] {
        for newline in ["\r\n", "\n"] {
            let wire = format!(
                "{newline}POST /RTSP/1.0 {protocol}{newline}X-Version: RTSP/1.0{newline}Content-Length: 8{newline}{newline}RTSP/1.0"
            );
            let request = parse_fragmented(wire.as_bytes());
            assert_eq!(request.url(), Some("/RTSP/1.0"));
            assert_eq!(request.header("x-version"), Some("RTSP/1.0"));
            assert_eq!(request.data(), Some(b"RTSP/1.0".as_slice()));
        }
    }
    for protocol in ["RTSP/1.1", "RTSP/2.0", "HTTP/2.0", "R", "RTSP/1.00"] {
        let wire = format!("GET /RTSP/1.0 {protocol}\r\nX: RTSP/1.0\r\n\r\n");
        assert!(HttpRequest::new().add_data(wire.as_bytes()).is_err());
    }
}

#[test]
fn rejects_ambiguous_body_framing_and_latches_failure() {
    for headers in [
        "Content-Length: nope",
        "Content-Length:",
        "Content-Length: +1",
        "Content-Length: -1",
        "Content-Length: 1 0",
        "Content-Length: 1, 1",
        "Content-Length: 999999999999999999999999999999999999999",
        "Content-Length: 1\r\ncOnTeNt-LeNgTh: 1",
        "Content-Length: 1\r\nContent-Length: 2",
        "Transfer-Encoding: chunked",
        "Transfer-Encoding: identity\r\nContent-Length: 1",
        "Content-Type: a\r\nCONTENT-TYPE: b",
    ] {
        let wire = format!("POST /test RTSP/1.0\r\n{headers}\r\n\r\nx");
        for split in 0..=wire.len() {
            let mut request = HttpRequest::new();
            let first = request.add_data(&wire.as_bytes()[..split]);
            assert!(
                first.is_err() || request.add_data(&wire.as_bytes()[split..]).is_err(),
                "{headers}, split {split}"
            );
            let retained = request.buffer.len();
            assert!(request.add_data(b"OPTIONS * RTSP/1.0\r\n\r\n").is_err());
            assert_eq!(request.buffer.len(), retained);
            assert!(!request.is_complete());
            assert!(request.data().is_none());
        }
    }
}

#[test]
fn policy_runs_once_before_coalesced_body_allocation() {
    let mut wire = b"POST /small RTSP/1.0\r\nContent-Length: 1048576\r\n\r\n".to_vec();
    wire.resize(wire.len() + 1024 * 1024, 0x55);
    let mut request = HttpRequest::new();
    let result = request.add_data_with_body_limit(&wire, |headers| {
        assert!(headers.headers_complete());
        assert!(headers.buffer.is_empty());
        assert!(headers.data().is_none());
        Ok(33)
    });
    assert!(result.is_err());
    assert!(request.buffer.is_empty());
    assert!(request.buffer.capacity() <= MAX_HEADER_BYTES);

    let mut request = HttpRequest::new();
    request
        .add_data_with_body_limit(
            b"POST /small RTSP/1.0\r\nContent-Length: 3\r\n\r\na",
            |_| Ok(3),
        )
        .unwrap();
    request
        .add_data_with_body_limit(b"bc", |_| panic!("policy must not run twice"))
        .unwrap();
    assert_eq!(request.data(), Some(b"abc".as_slice()));
}

#[test]
fn policy_can_require_length_without_breaking_bodyless_requests() {
    let wire = b"OPTIONS * RTSP/1.0\r\n\r\n";
    assert!(parse_fragmented(wire).data().is_none());
    let mut request = HttpRequest::new();
    let result = request.add_data_with_body_limit(wire, |headers| {
        headers
            .header("content-length")
            .ok_or_else(|| ProtocolError::InvalidRtsp("length required".into()))?;
        Ok(33)
    });
    assert!(result.is_err());
    assert!(!request.is_complete());
}

#[test]
fn preserves_pipelined_bytes_and_takes_them_once() {
    let next = b"OPTIONS * RTSP/1.0\r\n\r\n";
    let mut wire = b"POST /small RTSP/1.0\r\nContent-Length: 3\r\n\r\nabc".to_vec();
    wire.extend_from_slice(next);
    let mut request = HttpRequest::new();
    request.add_data_with_body_limit(&wire, |_| Ok(3)).unwrap();
    assert_eq!(request.data(), Some(b"abc".as_slice()));
    assert_eq!(request.take_leftover(), next);
    assert!(request.take_leftover().is_empty());
}

#[test]
fn header_limits_exclude_coalesced_bodies_and_include_terminators() {
    let prefix = b"GET / RTSP/1.0\r\nX: ";
    for extra in [0, 1] {
        let mut wire = prefix.to_vec();
        wire.resize(MAX_HEADER_BYTES - 4 + extra, 0x55);
        wire.extend_from_slice(b"\r\n\r\n");
        let mut request = HttpRequest::new();
        assert_eq!(request.add_data(&wire).is_ok(), extra == 0);
        assert!(request.buffer.len() <= MAX_HEADER_BYTES);
    }
    let size = MAX_HEADER_BYTES + 1;
    let mut wire = format!("POST /large RTSP/1.0\r\nContent-Length: {size}\r\n\r\n").into_bytes();
    wire.resize(wire.len() + size, 0x55);
    let mut request = HttpRequest::new();
    request.add_data(&wire).unwrap();
    assert_eq!(request.data().unwrap().len(), size);
}

#[test]
fn global_body_and_header_count_limits_cannot_be_widened() {
    for size in [MAX_BODY_BYTES, MAX_BODY_BYTES + 1] {
        let wire = format!("POST /large RTSP/1.0\r\nContent-Length: {size}\r\n\r\n");
        let mut request = HttpRequest::new();
        assert_eq!(
            request
                .add_data_with_body_limit(wire.as_bytes(), |_| Ok(usize::MAX))
                .is_ok(),
            size == MAX_BODY_BYTES
        );
        assert!(!request.is_complete());
    }
    for count in [MAX_HEADER_COUNT, MAX_HEADER_COUNT + 1] {
        let wire = format!("GET / RTSP/1.0\r\n{}\r\n", "X: x\r\n".repeat(count));
        assert_eq!(
            HttpRequest::new().add_data(wire.as_bytes()).is_ok(),
            count == MAX_HEADER_COUNT
        );
    }
    let request = parse_fragmented(b"POST / RTSP/1.0\r\nContent-Length: \t003 \t\r\n\r\nabc");
    assert_eq!(request.data(), Some(b"abc".as_slice()));
}
