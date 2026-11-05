//! RAOP/AirPlay server core — connection handling, audio pipeline, and public API.

pub use crate::proto::dmap::TrackMetadata;

#[cfg(feature = "ap2")]
pub mod audio_pipeline;
#[cfg(feature = "pipewire-auth-setup-compat")]
mod auth_setup;
pub mod buffer;
#[cfg(feature = "ap2")]
pub mod buffered_audio;
#[cfg(feature = "ap2")]
pub(crate) mod event_channel;
pub(crate) mod handlers_ap1;
#[cfg(feature = "ap2")]
pub(crate) mod handlers_ap2;
#[cfg(feature = "hls")]
pub(crate) mod handlers_hls;
#[cfg(feature = "hls")]
pub mod hls;
pub(crate) mod ntp;
#[cfg(feature = "ap2")]
pub(crate) mod realtime_audio;
pub(crate) mod rtp;
mod rtsp;
#[cfg(feature = "video")]
pub mod video;
#[cfg(feature = "video")]
pub(crate) mod video_stream;

pub(crate) mod config;

/// Maximum hardware address length in bytes.
pub(crate) const MAX_HWADDR_LEN: usize = 6;
/// Maximum password length in bytes.
pub(crate) const MAX_PASSWORD_LEN: usize = 64;
/// Maximum HTTP Digest nonce length in bytes.
pub(crate) const MAX_NONCE_LEN: usize = 32;

mod types;
pub use types::*;

mod connection;
mod server;
pub use server::{RaopServer, RaopServerBuilder};

pub(crate) struct DacpRemoteControl {
    client: crate::dacp::DacpClient,
}

impl DacpRemoteControl {
    /// Create a new DACP remote control client for the given iPhone.
    pub(crate) fn new(dacp_id: &str, active_remote: &str, remote_addr: &[u8]) -> Self {
        let mut client = crate::dacp::DacpClient::new(dacp_id, active_remote);
        let ip = match remote_addr.len() {
            4 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                remote_addr[0],
                remote_addr[1],
                remote_addr[2],
                remote_addr[3],
            )),
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(remote_addr);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            _ => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        client.discover_from_remote(ip);
        Self { client }
    }
}

impl RemoteControl for DacpRemoteControl {
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError> {
        let result = match cmd {
            // not playpause: a play to a sender that plays (a receiver resuming it) would pause it
            RemoteCommand::Play => self.client.play_blocking(),
            RemoteCommand::Pause => self.client.pause_blocking(),
            RemoteCommand::NextTrack => self.client.next_blocking(),
            RemoteCommand::PreviousTrack => self.client.prev_blocking(),
            RemoteCommand::SetVolume(v) => self.client.set_volume_blocking(v),
            RemoteCommand::ToggleShuffle => self.client.set_shuffle_blocking(true),
            RemoteCommand::ToggleRepeat => self.client.set_repeat_blocking(1),
            RemoteCommand::Stop => self.client.stop_blocking(),
        };
        result.map_err(crate::error::ShairplayError::Network)
    }

    fn available_commands(&self) -> Vec<RemoteCommand> {
        vec![
            RemoteCommand::Play,
            RemoteCommand::Pause,
            RemoteCommand::NextTrack,
            RemoteCommand::PreviousTrack,
            RemoteCommand::SetVolume(0),
            RemoteCommand::ToggleShuffle,
            RemoteCommand::ToggleRepeat,
            RemoteCommand::Stop,
        ]
    }
}

#[cfg(test)]
mod dacp_tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn play_and_pause_send_their_own_commands() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            (0..2)
                .map(|_| {
                    let (mut conn, _) = listener.accept().unwrap();
                    let mut buf = [0u8; 256];
                    let n = conn.read(&mut buf).unwrap();
                    let request = String::from_utf8_lossy(&buf[..n]);
                    request.lines().next().unwrap().to_string()
                })
                .collect::<Vec<_>>()
        });
        let remote = DacpRemoteControl {
            client: crate::dacp::DacpClient::new("id", "1").with_addr(addr),
        };
        remote.send_command(RemoteCommand::Play).unwrap();
        remote.send_command(RemoteCommand::Pause).unwrap();
        assert_eq!(
            sender.join().unwrap(),
            [
                "GET /ctrl-int/1/play HTTP/1.1",
                "GET /ctrl-int/1/pause HTTP/1.1"
            ]
        );
    }
}
