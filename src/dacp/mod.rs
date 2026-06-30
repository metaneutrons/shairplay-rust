//! DACP (Digital Audio Control Protocol) client for remote-controlling Apple devices.
//!
//! When an iPhone/iPad/Mac streams audio via AirPlay, it advertises a `_dacp._tcp` mDNS
//! service. This module discovers that service and sends HTTP commands back to control
//! playback (play/pause, next, previous, volume, etc.).

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::NetworkError;
use tracing::debug;

/// Default DACP port, used when mDNS discovery of the `_dacp._tcp` service fails.
const DACP_DEFAULT_PORT: u16 = 3689;

const PLAY_PAUSE_PATH: &str = "/ctrl-int/1/playpause";
const NEXT_PATH: &str = "/ctrl-int/1/nextitem";
const PREVIOUS_PATH: &str = "/ctrl-int/1/previtem";
const STOP_PATH: &str = "/ctrl-int/1/stop";

fn volume_path(volume: u8) -> String {
    format!("/ctrl-int/1/setproperty?dmcp.volume={}", volume.min(100))
}

fn shuffle_path(on: bool) -> String {
    let state = if on { 1 } else { 0 };
    format!("/ctrl-int/1/setproperty?dacp.shufflestate={state}")
}

fn repeat_path(state: u8) -> String {
    format!("/ctrl-int/1/setproperty?dacp.repeatstate={state}")
}

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
/// Created from the DACP ID and Active-Remote header received by the AirPlay session.
///
/// # Example
/// ```text
/// let mut client = DacpClient::new("7711DA8B47838CB5", "1986535575");
/// client.discover_from_remote("192.168.1.5".parse().unwrap());
/// // Then from a synchronous remote-control callback:
/// // client.play_pause_blocking().ok();
/// ```
/// HTTP client for sending DACP playback commands to the iPhone.
#[derive(Debug)]
pub(crate) struct DacpClient {
    /// DACP-ID from the RTSP session. Identifies the `_dacp._tcp` mDNS service.
    dacp_id: String,
    active_remote: String,
    addr: Option<SocketAddr>,
}

impl DacpClient {
    /// Create a new DACP client from the values received in the AirPlay session.
    pub(crate) fn new(dacp_id: &str, active_remote: &str) -> Self {
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
    pub(crate) fn discover_from_remote(&mut self, remote_ip: std::net::IpAddr) {
        self.addr = match discover_dacp_port(&self.dacp_id, remote_ip) {
            Some(port) => {
                debug!(port, dacp_id = %self.dacp_id, "DACP service discovered via mDNS");
                Some(SocketAddr::new(remote_ip, port))
            }
            None => {
                debug!(dacp_id = %self.dacp_id, "DACP mDNS discovery failed, falling back to port 3689");
                Some(SocketAddr::new(remote_ip, DACP_DEFAULT_PORT))
            }
        };
    }

    /// Send a raw DACP command from synchronous callbacks.
    pub(crate) fn command_blocking(&self, path: &str) -> Result<(), NetworkError> {
        let addr = self
            .addr
            .ok_or_else(|| NetworkError::Mdns("DACP not discovered yet — call discover() first".into()))?;

        let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let request = self.command_request(path, addr);
        stream.write_all(request.as_bytes())?;

        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        Ok(())
    }

    pub(crate) fn play_pause_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(PLAY_PAUSE_PATH)
    }

    pub(crate) fn next_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(NEXT_PATH)
    }

    pub(crate) fn prev_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(PREVIOUS_PATH)
    }

    pub(crate) fn stop_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(STOP_PATH)
    }

    pub(crate) fn set_volume_blocking(&self, volume: u8) -> Result<(), NetworkError> {
        self.command_blocking(&volume_path(volume))
    }

    pub(crate) fn set_shuffle_blocking(&self, on: bool) -> Result<(), NetworkError> {
        self.command_blocking(&shuffle_path(on))
    }

    pub(crate) fn set_repeat_blocking(&self, state: u8) -> Result<(), NetworkError> {
        self.command_blocking(&repeat_path(state))
    }

    fn command_request(&self, path: &str, addr: SocketAddr) -> String {
        format!(
            "GET {path} HTTP/1.1\r\nActive-Remote: {}\r\nHost: {addr}\r\n\r\n",
            self.active_remote
        )
    }
}
