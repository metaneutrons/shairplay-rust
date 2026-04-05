//! RAOP/AirPlay server core — connection handling, audio pipeline, and public API.

pub use crate::proto::dmap::TrackMetadata;

pub mod buffer;
#[cfg(feature = "ap2")]
pub mod buffered_audio;
#[cfg(feature = "ap2")]
pub mod event_channel;
pub mod handlers;
#[cfg(feature = "ap2")]
pub mod handlers_ap2;
#[cfg(feature = "hls")]
pub mod handlers_hls;
#[cfg(feature = "hls")]
pub mod hls;
#[cfg(feature = "ap2")]
pub mod realtime_audio;
pub mod rtp;
mod rtsp;
#[cfg(feature = "video")]
pub mod video;
#[cfg(feature = "video")]
pub mod video_stream;

/// Maximum hardware address length in bytes.
pub const MAX_HWADDR_LEN: usize = 6;
/// Maximum password length in bytes.
pub const MAX_PASSWORD_LEN: usize = 64;
/// Maximum HTTP Digest nonce length in bytes.
pub const MAX_NONCE_LEN: usize = 32;

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
    pub fn new(dacp_id: &str, active_remote: &str, remote_addr: &[u8]) -> Self {
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
        let rt = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| {
            rt.block_on(async {
                match cmd {
                    RemoteCommand::Play => self.client.play_pause().await,
                    RemoteCommand::Pause => self.client.play_pause().await,
                    RemoteCommand::NextTrack => self.client.next().await,
                    RemoteCommand::PreviousTrack => self.client.prev().await,
                    RemoteCommand::SetVolume(v) => self.client.set_volume(v).await,
                    RemoteCommand::ToggleShuffle => self.client.set_shuffle(true).await,
                    RemoteCommand::ToggleRepeat => self.client.set_repeat(1).await,
                    RemoteCommand::Stop => self.client.stop().await,
                }
            })
        })
        .map_err(|e| {
            crate::error::ShairplayError::Network(crate::error::NetworkError::Io(std::io::Error::other(e.to_string())))
        })
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
