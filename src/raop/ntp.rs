//! NTP timing responder for AirPlay legacy connections.
//!
//! Sends timing requests to the iPhone and responds to incoming
//! timing requests. Required for legacy (non-PTP) AirPlay connections.

/// timing requests and sends periodic keepalives. Required for legacy AirPlay
/// connections where the iPhone expects NTP sync before streaming audio.
pub(crate) fn spawn_ntp_responder(tsock: tokio::net::UdpSocket, remote_timing: std::net::SocketAddr) {
    tokio::spawn(async move {
        let mut buf = [0u8; 128];

        let ntp_now = || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let secs = (now.as_secs() + 0x83AA7E80) as u32;
            let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;
            (secs, frac as u32)
        };

        let put_ntp = |buf: &mut [u8], off: usize, secs: u32, frac: u32| {
            buf[off..off + 4].copy_from_slice(&secs.to_be_bytes());
            buf[off + 4..off + 8].copy_from_slice(&frac.to_be_bytes());
        };

        // Send initial timing requests to iPhone
        if remote_timing.port() > 0 {
            tracing::debug!(%remote_timing, "NTP: sending initial timing requests");
            for _ in 0..3 {
                let mut req = [0u8; 32];
                req[0] = 0x80;
                req[1] = 0xd2;
                req[2] = 0x00;
                req[3] = 0x07;
                let (s, f) = ntp_now();
                put_ntp(&mut req, 24, s, f);
                let _ = tsock.send_to(&req, remote_timing).await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        loop {
            let timeout = tokio::time::sleep(std::time::Duration::from_secs(3));
            tokio::select! {
                result = tsock.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) if len >= 32 && buf[1] & 0x7f == 0x52 => {
                            // Timing request — send response
                            let mut resp = [0u8; 32];
                            resp[..32].copy_from_slice(&buf[..32]);
                            resp[1] = 0xd3;
                            resp[8..16].copy_from_slice(&buf[24..32]);
                            let (s, f) = ntp_now();
                            put_ntp(&mut resp, 16, s, f);
                            put_ntp(&mut resp, 24, s, f);
                            let _ = tsock.send_to(&resp, addr).await;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                _ = timeout => {
                    if remote_timing.port() > 0 {
                        let mut req = [0u8; 32];
                        req[0] = 0x80;
                        req[1] = 0xd2;
                        req[2] = 0x00;
                        req[3] = 0x07;
                        let (s, f) = ntp_now();
                        put_ntp(&mut req, 24, s, f);
                        let _ = tsock.send_to(&req, remote_timing).await;
                    }
                }
            }
        }
    });
}
