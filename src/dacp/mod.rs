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

/// Client for sending DACP remote control commands to an Apple device.
///
/// Created from the DACP ID and Active-Remote header received via
/// [`AudioSession::audio_remote_control_id`](crate::AudioSession::audio_remote_control_id).
///
/// # Example
/// ```rust,no_run
/// use shairplay::dacp::DacpClient;
///
/// # async fn example() {
/// let mut client = DacpClient::new("7711DA8B47838CB5", "1986535575");
/// if client.discover().await.is_ok() {
///     client.play_pause().await.ok();
///     client.next().await.ok();
///     client.set_volume(80).await.ok();
/// }
/// # }
/// ```
pub struct DacpClient {
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
    /// Browses `_dacp._tcp.local.` for a service whose instance name contains
    /// the DACP ID. Times out after 5 seconds if not found.
    pub async fn discover(&mut self) -> Result<SocketAddr, NetworkError> {
        let daemon = mdns_sd::ServiceDaemon::new()
            .map_err(|e| NetworkError::Mdns(e.to_string()))?;
        let receiver = daemon.browse("_dacp._tcp.local.")
            .map_err(|e| NetworkError::Mdns(e.to_string()))?;

        let dacp_id = self.dacp_id.clone();
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match receiver.recv_async().await {
                    Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                        if info.get_fullname().contains(&dacp_id) {
                            let port = info.get_port();
                            if let Some(addr) = info.get_addresses().iter().next() {
                                return Ok(SocketAddr::new(*addr, port));
                            }
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => return Err(NetworkError::Mdns(e.to_string())),
                }
            }
        }).await;

        let _ = daemon.shutdown();

        let addr = match result {
            Ok(Ok(addr)) => addr,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(NetworkError::Mdns(format!(
                "DACP service '{}' not found within 5s", self.dacp_id
            ))),
        };

        self.addr = Some(addr);
        Ok(addr)
    }

    /// Set the device address directly (skip mDNS discovery).
    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.addr = Some(addr);
    }

    /// Toggle play/pause.
    pub async fn play_pause(&self) -> Result<(), NetworkError> {
        self.command("/ctrl-int/1/playpause").await
    }

    /// Next track.
    pub async fn next(&self) -> Result<(), NetworkError> {
        self.command("/ctrl-int/1/nextitem").await
    }

    /// Previous track.
    pub async fn prev(&self) -> Result<(), NetworkError> {
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
