//! RAOP/AirPlay server core — connection handling, audio pipeline, and public API.

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

use std::net::SocketAddr;
use std::sync::Arc;

use crate::crypto::fairplay::FairPlay;
use crate::crypto::pairing::Pairing;
use crate::crypto::rsa::RsaKey;
use crate::error::ShairplayError;
use crate::net::mdns::{AirPlayServiceInfo, MdnsService};
use crate::net::server::{ConnectionHandler, HttpServer, HttpdCallbacks};
use crate::proto::digest;
use crate::proto::http::{HttpRequest, HttpResponse};

/// Maximum hardware address length in bytes.
pub const MAX_HWADDR_LEN: usize = 6;
/// Maximum password length in bytes.
pub const MAX_PASSWORD_LEN: usize = 64;
/// Maximum HTTP Digest nonce length in bytes.
pub const MAX_NONCE_LEN: usize = 32;

/// Audio codec type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// Decoded PCM (f32 interleaved). Always delivered regardless of AP1/AP2.
    Pcm,
}

/// Audio format descriptor passed to [`AudioHandler::audio_init`].
#[derive(Debug, Clone, Copy)]
pub struct AudioFormat {
    /// Audio codec (always PCM for decoded output).
    pub codec: AudioCodec,
    /// Bits per sample (always 32 — samples are delivered as `&[f32]`).
    pub bits: u8,
    /// Number of channels.
    pub channels: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Trait for receiving decoded audio data from AirPlay clients.
///
/// Implement this trait to handle audio output. A new [`AudioSession`] is created
/// for each client connection via [`audio_init`](AudioHandler::audio_init).
pub trait AudioHandler: Send + Sync + 'static {
    /// Called when a new audio stream starts. Return a session to receive PCM data.
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession>;
    /// Called when a client connects.
    fn on_client_connected(&self, _addr: &str) {}
    /// Called when a client disconnects.
    fn on_client_disconnected(&self, _addr: &str) {}
    /// Called on runtime errors. Default: log at warn level.
    fn on_error(&self, error: &crate::error::ShairplayError) {
        tracing::warn!(%error, "AirPlay error");
    }
}

/// Storage for paired device keys. Implement this to persist pairing across restarts.
///
/// Without persistence, iPhones that previously paired will send encrypted data
/// on connect and fail because the server has no cached keys.
#[cfg(feature = "ap2")]
pub trait PairingStore: Send + Sync + 'static {
    /// Look up a paired device's Ed25519 public key by device ID.
    fn get(&self, device_id: &str) -> Option<[u8; 32]>;
    /// Save a paired device's Ed25519 public key.
    fn put(&self, device_id: &str, public_key: [u8; 32]);
    /// Remove a paired device.
    fn remove(&self, device_id: &str);
}

/// In-memory pairing store (lost on restart). Use for testing or wrap with file I/O.
#[cfg(feature = "ap2")]
#[derive(Default)]
pub struct MemoryPairingStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
}

#[cfg(feature = "ap2")]
impl PairingStore for MemoryPairingStore {
    fn get(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.lock().ok()?.get(device_id).copied()
    }
    fn put(&self, device_id: &str, public_key: [u8; 32]) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(device_id.to_string(), public_key);
        }
    }
    fn remove(&self, device_id: &str) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.remove(device_id);
        }
    }
}

/// Per-connection audio session receiving decoded PCM samples.
///
/// Created by [`AudioHandler::audio_init`]. Dropped when the client disconnects.
pub trait AudioSession: Send + Sync {
    /// Receive decoded f32 interleaved PCM audio samples.
    fn audio_process(&mut self, samples: &[f32]);
    /// Flush the audio buffer (e.g. on seek).
    fn audio_flush(&mut self) {}
    /// Volume change in dB (0.0 = max, -144.0 = mute).
    fn audio_set_volume(&mut self, _volume: f32) {}
    /// DMAP track metadata (binary).
    fn audio_set_metadata(&mut self, _metadata: &[u8]) {}
    /// Album artwork (JPEG or PNG).
    fn audio_set_coverart(&mut self, _coverart: &[u8]) {}
    /// DACP remote control identifiers (AP1 only).
    fn audio_remote_control_id(&mut self, _dacp_id: &str, _active_remote: &str, _remote_addr: &[u8]) {}
    /// Playback progress (start, current, end in RTP timestamps).
    fn audio_set_progress(&mut self, _start: u32, _current: u32, _end: u32) {}
    /// Called when a remote control interface becomes available (AP1 DACP).
    fn remote_control_available(&mut self, _remote: Arc<dyn RemoteControl>) {}
}

/// Playback command to send to the source device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCommand {
    /// Start playback.
    Play,
    /// Pause playback.
    Pause,
    /// Skip to next track.
    NextTrack,
    /// Skip to previous track.
    PreviousTrack,
    /// Set volume (0-100).
    SetVolume(u8),
    /// Toggle shuffle mode.
    ToggleShuffle,
    /// Toggle repeat mode.
    ToggleRepeat,
    /// Stop playback.
    Stop,
}

/// Unified remote control interface for AP1 (DACP) and AP2 (MediaRemote).
pub trait RemoteControl: Send + Sync {
    /// Send a playback command to the source device.
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError>;
    /// Commands the source device supports. AP1 returns all; AP2 returns advertised set.
    fn available_commands(&self) -> Vec<RemoteCommand>;
}

/// Shared state passed to each connection.
struct RaopShared {
    rsakey: Arc<RsaKey>,
    pairing: Arc<Pairing>,
    hwaddr: Vec<u8>,
    password: String,
    handler: Arc<dyn AudioHandler>,
    #[cfg(feature = "ap2")]
    pairing_store: Arc<dyn PairingStore>,
    output_sample_rate: Option<u32>,
    output_max_channels: Option<u8>,
    #[cfg(feature = "ap2")]
    pin: Option<String>,
    #[cfg(feature = "video")]
    video_handler: Option<Arc<dyn crate::raop::video::VideoHandler>>,
    /// Shared video encryption keys — set by audio SETUP, read by video SETUP.
    #[cfg(feature = "video")]
    video_ekey: Arc<std::sync::RwLock<Option<[u8; 16]>>>,
    #[cfg(feature = "video")]
    video_eiv: Arc<std::sync::RwLock<Option<[u8; 16]>>>,
    #[cfg(feature = "hls")]
    hls_handler: Option<Arc<dyn crate::raop::hls::HlsHandler>>,
}

impl HttpdCallbacks for RaopShared {
    fn conn_init(&self, local: SocketAddr, remote: SocketAddr) -> Option<Box<dyn ConnectionHandler>> {
        let local_bytes = match local.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let remote_bytes = match remote.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };

        let conn = handlers::RaopConnection {
            raop_rtp: None,
            fairplay: FairPlay::new(),
            pairing: self.pairing.create_session(),
            local_addr: local_bytes,
            remote_addr: remote_bytes,
            remote_socket: remote,
            nonce: digest::generate_nonce(MAX_NONCE_LEN),
            rsakey: self.rsakey.clone(),
            pairing_identity: self.pairing.clone(),
            hwaddr: self.hwaddr.clone(),
            password: self.password.clone(),
            handler: self.handler.clone(),
            #[cfg(feature = "ap2")]
            device_id: crate::util::hwaddr_airplay(&self.hwaddr),
            #[cfg(feature = "ap2")]
            srp_server: None,
            #[cfg(feature = "ap2")]
            pair_verify: None,
            #[cfg(feature = "ap2")]
            ap2_shared_secret: None,
            #[cfg(feature = "ap2")]
            pair_verify_secret: None,
            #[cfg(feature = "ap2")]
            is_ap2: false,
            #[cfg(feature = "ap2")]
            pairing_store: self.pairing_store.clone(),
            #[cfg(feature = "ap2")]
            playout_cmd: None,
            output_sample_rate: self.output_sample_rate,
            output_max_channels: self.output_max_channels,
            #[cfg(feature = "ap2")]
            pin: self.pin.clone(),
            #[cfg(feature = "ap2")]
            event_sender: None,
            #[cfg(feature = "video")]
            video_handler: self.video_handler.clone(),
            #[cfg(feature = "video")]
            ekey: None,
            #[cfg(feature = "video")]
            eiv: None,
            #[cfg(feature = "video")]
            shared_video_ekey: self.video_ekey.clone(),
            #[cfg(feature = "video")]
            shared_video_eiv: self.video_eiv.clone(),
            #[cfg(feature = "hls")]
            hls_handler: self.hls_handler.clone(),
            #[cfg(feature = "hls")]
            hls_state: crate::raop::hls::HlsState::new(),
        };
        let remote_str = remote.ip().to_string();
        conn.handler.on_client_connected(&remote_str);
        Some(Box::new(RaopConnectionHandler {
            conn,
            remote_addr: remote_str,
            #[cfg(feature = "ap2")]
            cipher: None,
            #[cfg(feature = "ap2")]
            pending_secret: None,
        }))
    }
}

struct RaopConnectionHandler {
    conn: handlers::RaopConnection,
    remote_addr: String,
    #[cfg(feature = "ap2")]
    cipher: Option<crate::crypto::chacha_transport::EncryptedChannel>,
    #[cfg(feature = "ap2")]
    pending_secret: Option<Vec<u8>>,
}

impl Drop for RaopConnectionHandler {
    fn drop(&mut self) {
        self.conn.handler.on_client_disconnected(&self.remote_addr);
    }
}

impl ConnectionHandler for RaopConnectionHandler {
    fn conn_request(&mut self, request: &HttpRequest) -> HttpResponse {
        let resp = rtsp::dispatch(&mut self.conn, request);

        // Queue encryption activation for AFTER this response is sent
        #[cfg(feature = "ap2")]
        if self.cipher.is_none() {
            if let Some(secret) = &self.conn.ap2_shared_secret {
                self.pending_secret = Some(secret.clone());
            }
        }

        resp
    }

    fn is_encrypted(&self) -> bool {
        #[cfg(feature = "ap2")]
        {
            self.cipher.is_some()
        }
        #[cfg(not(feature = "ap2"))]
        {
            false
        }
    }

    fn after_response(&mut self) {
        #[cfg(feature = "ap2")]
        if self.cipher.is_none() {
            if let Some(secret) = self.pending_secret.take() {
                tracing::debug!(secret_len = secret.len(), "Activating cipher from pending_secret");
                match crate::crypto::chacha_transport::EncryptedChannel::control(&secret) {
                    Ok(ch) => {
                        tracing::info!("Encrypted RTSP transport activated");
                        self.cipher = Some(ch);
                    }
                    Err(e) => tracing::warn!("Failed to create cipher: {e}"),
                }
            }
        }
    }

    fn decrypt_incoming(&mut self, data: &[u8]) -> Option<(Vec<u8>, usize)> {
        #[cfg(feature = "ap2")]
        if let Some(ch) = &mut self.cipher {
            return ch.decrypt_ctx.decrypt(data).ok();
        }
        Some((data.to_vec(), data.len()))
    }

    fn encrypt_outgoing(&mut self, data: &[u8]) -> Vec<u8> {
        #[cfg(feature = "ap2")]
        if let Some(ch) = &mut self.cipher {
            return ch.encrypt_ctx.encrypt(data).unwrap_or_else(|_| data.to_vec());
        }
        data.to_vec()
    }
}

// On drop, RTP session is cleaned up automatically (RaopRtp dropped → shutdown sent)

/// The well-known RSA private key from the Apple AirPort Express firmware.
/// Used by all open-source AirPlay receiver implementations.
/// Apple devices use the corresponding public key to encrypt session keys.
const AIRPORT_KEY: &str = include_str!("../../airport.key");

fn airport_rsakey() -> Arc<RsaKey> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Arc<RsaKey>> = OnceLock::new();
    KEY.get_or_init(|| Arc::new(RsaKey::from_pem(AIRPORT_KEY).expect("built-in airport.key is invalid")))
        .clone()
}

pub use crate::net::server::BindConfig;

/// Builder for [`RaopServer`].
pub struct RaopServerBuilder {
    max_clients: usize,
    hwaddr: Option<Vec<u8>>,
    password: Option<String>,
    name: String,
    bind: BindConfig,
    #[cfg(feature = "ap2")]
    pairing_store: Option<Arc<dyn PairingStore>>,
    output_sample_rate: Option<u32>,
    output_max_channels: Option<u8>,
    #[cfg(feature = "ap2")]
    pin: Option<String>,
    #[cfg(feature = "video")]
    video_handler: Option<Arc<dyn crate::raop::video::VideoHandler>>,
    #[cfg(feature = "hls")]
    hls_handler: Option<Arc<dyn crate::raop::hls::HlsHandler>>,
}

impl Default for RaopServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RaopServerBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            max_clients: 10,
            hwaddr: None,
            password: None,
            name: "Shairplay".to_string(),
            bind: BindConfig::default(),
            #[cfg(feature = "ap2")]
            pairing_store: None,
            output_sample_rate: None,
            output_max_channels: None,
            #[cfg(feature = "ap2")]
            pin: None,
            #[cfg(feature = "video")]
            video_handler: None,
            #[cfg(feature = "hls")]
            hls_handler: None,
        }
    }

    /// Set the maximum number of concurrent connections. Default: 10.
    pub fn max_clients(mut self, n: usize) -> Self {
        self.max_clients = n;
        self
    }
    /// Set the 6-byte hardware address for mDNS registration.
    pub fn hwaddr(mut self, addr: impl Into<Vec<u8>>) -> Self {
        self.hwaddr = Some(addr.into());
        self
    }
    /// Set an optional HTTP Digest authentication password.
    pub fn password(mut self, pw: impl Into<String>) -> Self {
        self.password = Some(pw.into());
        self
    }
    /// Set the RTSP listening port. Default: 5000.
    pub fn port(mut self, port: u16) -> Self {
        self.bind.port = port;
        self
    }
    /// Set full bind configuration (address, port, auto-sensing, IPv6).
    pub fn bind(mut self, config: BindConfig) -> Self {
        self.bind = config;
        self
    }
    /// Set the AirPlay display name. Default: "Shairplay".
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set a pairing store for persisting device keys across restarts.
    /// Without this, iPhones must re-pair on every server restart.
    #[cfg(feature = "ap2")]
    pub fn pairing_store(mut self, store: Arc<dyn PairingStore>) -> Self {
        self.pairing_store = Some(store);
        self
    }

    /// Set the desired output sample rate. The library resamples to this rate.
    /// Default: source native rate (no resampling).
    pub fn output_sample_rate(mut self, rate: u32) -> Self {
        self.output_sample_rate = Some(rate);
        self
    }

    /// Set the maximum output channels. Sources with more channels are mixed down.
    /// Sources with fewer channels are passed through (no upmixing).
    /// Default: pass through native channel count.
    pub fn output_max_channels(mut self, channels: u8) -> Self {
        self.output_max_channels = Some(channels);
        self
    }

    #[cfg(feature = "ap2")]
    /// Set the HomeKit pairing PIN. Default: "3939".
    pub fn pin(mut self, pin: impl Into<String>) -> Self {
        self.pin = Some(pin.into());
        self
    }

    #[cfg(feature = "video")]
    /// Set a video handler for screen mirroring (experimental).
    pub fn video_handler(mut self, handler: Arc<dyn crate::raop::video::VideoHandler>) -> Self {
        self.video_handler = Some(handler);
        self
    }

    #[cfg(feature = "hls")]
    /// Set an HLS handler for YouTube/video URL playback.
    pub fn hls_handler(mut self, handler: Arc<dyn crate::raop::hls::HlsHandler>) -> Self {
        self.hls_handler = Some(handler);
        self
    }

    /// Build the server with the given audio handler.
    pub fn build(self, handler: Arc<dyn AudioHandler>) -> Result<RaopServer, ShairplayError> {
        let rsakey = airport_rsakey();
        let pairing = Arc::new(Pairing::generate()?);
        let hwaddr = self.hwaddr.unwrap_or_else(|| vec![0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22]);

        let shared = Arc::new(RaopShared {
            rsakey,
            pairing,
            hwaddr: hwaddr.clone(),
            password: self.password.unwrap_or_default(),
            handler,
            #[cfg(feature = "ap2")]
            pairing_store: self
                .pairing_store
                .unwrap_or_else(|| Arc::new(MemoryPairingStore::default())),
            output_sample_rate: self.output_sample_rate,
            output_max_channels: self.output_max_channels,
            #[cfg(feature = "ap2")]
            pin: self.pin,
            #[cfg(feature = "video")]
            video_handler: self.video_handler,
            #[cfg(feature = "video")]
            video_ekey: Arc::new(std::sync::RwLock::new(None)),
            #[cfg(feature = "video")]
            video_eiv: Arc::new(std::sync::RwLock::new(None)),
            #[cfg(feature = "hls")]
            hls_handler: self.hls_handler,
        });

        let mut httpd = HttpServer::new(shared.clone(), self.max_clients);
        httpd.set_bind_config(self.bind.clone());

        Ok(RaopServer {
            shared,
            httpd,
            mdns: None,
            bind: self.bind,
            name: self.name,
            hwaddr,
        })
    }
}

/// The main AirPlay/RAOP server.
///
/// Listens for RTSP connections, handles pairing and encryption,
/// decodes audio, and delivers f32 PCM samples via [`AudioSession`].
/// Automatically registers mDNS services for network discovery.
pub struct RaopServer {
    shared: Arc<RaopShared>,
    httpd: HttpServer,
    mdns: Option<MdnsService>,
    bind: BindConfig,
    name: String,
    hwaddr: Vec<u8>,
}

impl RaopServer {
    /// Create a new server builder.
    pub fn builder() -> RaopServerBuilder {
        RaopServerBuilder::new()
    }

    /// Start the server: bind ports, register mDNS services, begin accepting connections.
    ///
    /// mDNS registration is skipped when the `CI` environment variable is set
    /// (Bonjour/Avahi is typically unavailable on CI runners).
    pub async fn start(&mut self) -> Result<(), ShairplayError> {
        let _actual_port = self.httpd.start(self.bind.port).await?;

        if std::env::var("CI").is_err() {
            let info = self.service_info();
            let mut mdns = MdnsService::new()?;
            mdns.register_raop(&info)?;
            #[cfg(feature = "ap2")]
            mdns.register_airplay(&info)?;
            self.mdns = Some(mdns);
        }

        Ok(())
    }

    /// Whether the server is currently running.
    pub fn is_running(&self) -> bool {
        self.httpd.is_running()
    }

    /// Stop the server: unregister mDNS services and close all listeners.
    pub async fn stop(&mut self) {
        if let Some(mut mdns) = self.mdns.take() {
            mdns.unregister_raop();
            mdns.unregister_airplay();
        }
        self.httpd.stop().await;
    }

    /// Get the mDNS service info for this server.
    pub fn service_info(&self) -> AirPlayServiceInfo {
        #[cfg(feature = "ap2")]
        {
            let device_id = crate::util::hwaddr_airplay(&self.hwaddr);
            let (_, vk) = crate::crypto::pairing_homekit::server_keypair(&device_id);
            let pk_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            let pi = uuid::Uuid::new_v4().to_string();
            AirPlayServiceInfo::new_airplay2(
                &self.name,
                self.httpd.port(),
                &self.hwaddr,
                !self.shared.password.is_empty(),
                &pk_hex,
                &pi,
            )
        }
        #[cfg(not(feature = "ap2"))]
        {
            AirPlayServiceInfo::new(
                &self.name,
                self.httpd.port(),
                &self.hwaddr,
                !self.shared.password.is_empty(),
            )
        }
    }
}

/// AP1 remote control via DACP (HTTP to iPhone port 3689).
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
