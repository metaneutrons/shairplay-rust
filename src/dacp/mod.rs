//! DACP (Digital Audio Control Protocol) client for remote-controlling Apple devices.
//!
//! When an iPhone/iPad/Mac streams audio via AirPlay, it advertises a `_dacp._tcp` mDNS
//! service. This module discovers that service and sends HTTP commands back to control
//! playback (play/pause, next, previous, volume, etc.).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::NetworkError;
use tracing::debug;

/// Browse `_dacp._tcp` via mDNS and return the port for the given DACP-ID.
/// Returns None if not found within 2 seconds.
#[cfg(not(target_os = "macos"))]
fn discover_dacp_port(dacp_id: &str, _remote_ip: std::net::IpAddr) -> Option<u16> {
    let daemon = mdns_sd::ServiceDaemon::new().ok()?;
    let receiver = daemon.browse("_dacp._tcp.local.").ok()?;
    let target = dacp_id.to_uppercase();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);

    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(deadline.duration_since(std::time::Instant::now())) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                if info.get_fullname().to_uppercase().contains(&target) {
                    let port = info.get_port();
                    let _ = daemon.shutdown();
                    return Some(port);
                }
            }
            Err(_) => break,
            _ => continue,
        }
    }
    let _ = daemon.shutdown();
    None
}

/// Browse `_dacp._tcp` via Bonjour and return the port for the given DACP-ID.
/// Always returns None on macOS — astro-dnssd doesn't expose a synchronous
/// browse+resolve API. The caller falls back to port 3689.
#[cfg(target_os = "macos")]
fn discover_dacp_port(dacp_id: &str, _remote_ip: std::net::IpAddr) -> Option<u16> {
    let _ = dacp_id;
    None
}

/// Client for sending DACP remote control commands to an Apple device.
///
/// Created from the DACP ID and Active-Remote header received via
/// [`AudioSession::audio_remote_control_id`](crate::AudioSession::audio_remote_control_id).
///
/// # Example
/// ```rust,no_run
/// use shairplay::dacp::DacpClient;
///
/// let mut client = DacpClient::new("7711DA8B47838CB5", "1986535575");
/// client.discover_from_remote("192.168.1.5".parse().unwrap());
/// // Then in an async context:
/// // client.play_pause().await.ok();
/// ```
#[derive(Debug)]
/// HTTP client for sending DACP playback commands to the iPhone.
pub struct DacpClient {
    /// DACP-ID from the RTSP session. Identifies the `_dacp._tcp` mDNS service.
    dacp_id: String,
    active_remote: String,
    addr: Option<SocketAddr>,
}

impl DacpClient {
    /// Create a new DACP client from the values received in the AirPlay session.
    pub fn new(dacp_id: &str, active_remote: &str) -> Self {
        Self {
            dacp_id: dacp_id.to_string(),
            active_remote: active_remote.to_string(),
            addr: None,
        }
    }

    /// Discover the Apple device's DACP service via mDNS.
    ///
    /// Browses `_dacp._tcp.local.` for a service matching the DACP-ID,
    /// with a 2-second timeout. Falls back to port 3689 on the remote IP
    /// if mDNS discovery fails.
    pub fn discover_from_remote(&mut self, remote_ip: std::net::IpAddr) {
        self.addr = match discover_dacp_port(&self.dacp_id, remote_ip) {
            Some(port) => {
                debug!(port, dacp_id = %self.dacp_id, "DACP service discovered via mDNS");
                Some(SocketAddr::new(remote_ip, port))
            }
            None => {
                debug!(dacp_id = %self.dacp_id, "DACP mDNS discovery failed, falling back to port 3689");
                Some(SocketAddr::new(remote_ip, 3689))
            }
        };
    }

    /// Set the device address directly (skip mDNS discovery).
    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.addr = Some(addr);
    }

    /// Toggle play/pause.
    pub async fn play_pause(&self) -> Result<(), NetworkError> {
        debug!("DACP: play_pause");
        self.command("/ctrl-int/1/playpause").await
    }

    /// Next track.
    pub async fn next(&self) -> Result<(), NetworkError> {
        debug!("DACP: next");
        self.command("/ctrl-int/1/nextitem").await
    }

    /// Previous track.
    pub async fn prev(&self) -> Result<(), NetworkError> {
        debug!("DACP: prev");
        self.command("/ctrl-int/1/previtem").await
    }

    /// Stop playback.
    pub async fn stop(&self) -> Result<(), NetworkError> {
        self.command("/ctrl-int/1/stop").await
    }

    /// Set volume (0–100).
    pub async fn set_volume(&self, volume: u8) -> Result<(), NetworkError> {
        let vol = volume.min(100);
        self.command(&format!("/ctrl-int/1/setproperty?dmcp.volume={vol}")).await
    }

    /// Set shuffle state (true = on).
    pub async fn set_shuffle(&self, on: bool) -> Result<(), NetworkError> {
        let v = if on { 1 } else { 0 };
        self.command(&format!("/ctrl-int/1/setproperty?dacp.shufflestate={v}")).await
    }

    /// Set repeat state (0 = off, 1 = single, 2 = all).
    pub async fn set_repeat(&self, state: u8) -> Result<(), NetworkError> {
        self.command(&format!("/ctrl-int/1/setproperty?dacp.repeatstate={state}")).await
    }

    /// Send a raw DACP command (GET request with Active-Remote header).
    pub async fn command(&self, path: &str) -> Result<(), NetworkError> {
        let addr = self.addr.ok_or_else(|| {
            NetworkError::Mdns("DACP not discovered yet — call discover() first".into())
        })?;

        let mut stream = TcpStream::connect(addr).await?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nActive-Remote: {}\r\nHost: {addr}\r\n\r\n",
            self.active_remote
        );
        stream.write_all(request.as_bytes()).await?;

        // Read response (we don't parse it, just ensure the connection succeeds)
        let mut buf = [0u8; 1024];
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
        Ok(())
    }
}
