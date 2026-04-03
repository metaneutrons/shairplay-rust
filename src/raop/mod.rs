pub mod buffer;
#[cfg(feature = "airplay2")]
pub mod buffered_audio;
#[cfg(feature = "airplay2")]
pub mod event_channel;
pub mod handlers;
pub mod rtp;
mod rtsp;

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

pub const MAX_HWADDR_LEN: usize = 6;
pub const MAX_PASSWORD_LEN: usize = 64;
pub const MAX_NONCE_LEN: usize = 32;

#[derive(Debug, Clone, Copy)]
/// Audio format descriptor passed to [`AudioHandler::audio_init`].
pub struct AudioFormat {
    pub bits: u8,
    pub channels: u8,
    pub sample_rate: u32,
}

/// Trait for handling audio output. Equivalent to raop_callbacks_t.
/// Trait for receiving decoded audio data from AirPlay clients.
///
/// Implement this trait to handle audio output. A new [`AudioSession`] is created
/// for each client connection via [`audio_init`](AudioHandler::audio_init).
pub trait AudioHandler: Send + Sync + 'static {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession>;
}

/// Per-connection audio session.
/// Per-connection audio session receiving decoded PCM samples.
///
/// Created by [`AudioHandler::audio_init`]. Dropped when the client disconnects.
pub trait AudioSession: Send + Sync {
    fn audio_process(&mut self, buffer: &[u8]);
    fn audio_flush(&mut self) {}
    fn audio_set_volume(&mut self, _volume: f32) {}
    fn audio_set_metadata(&mut self, _metadata: &[u8]) {}
    fn audio_set_coverart(&mut self, _coverart: &[u8]) {}
    fn audio_remote_control_id(&mut self, _dacp_id: &str, _active_remote: &str, _remote_addr: &[u8]) {}
    fn audio_set_progress(&mut self, _start: u32, _current: u32, _end: u32) {}
}

/// Shared state passed to each connection.
struct RaopShared {
    rsakey: Arc<RsaKey>,
    pairing: Arc<Pairing>,
    hwaddr: Vec<u8>,
    password: String,
    handler: Arc<dyn AudioHandler>,
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
            nonce: digest::generate_nonce(MAX_NONCE_LEN),
            rsakey: self.rsakey.clone(),
            pairing_identity: self.pairing.clone(),
            hwaddr: self.hwaddr.clone(),
            password: self.password.clone(),
            handler: self.handler.clone(),
            #[cfg(feature = "airplay2")]
            device_id: crate::util::hwaddr_airplay(&self.hwaddr),
            #[cfg(feature = "airplay2")]
            srp_server: None,
            #[cfg(feature = "airplay2")]
            pair_verify: None,
            #[cfg(feature = "airplay2")]
            ap2_shared_secret: None,
            #[cfg(feature = "airplay2")]
            is_ap2: false,
        };
        Some(Box::new(RaopConnectionHandler(conn)))
    }
}

struct RaopConnectionHandler(handlers::RaopConnection);

impl ConnectionHandler for RaopConnectionHandler {
    fn conn_request(&mut self, request: &HttpRequest) -> HttpResponse {
        rtsp::dispatch(&mut self.0, request)
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
    KEY.get_or_init(|| Arc::new(RsaKey::from_pem(AIRPORT_KEY).expect("built-in airport.key is invalid"))).clone()
}

/// The main AirPlay/RAOP server.
///
/// Listens for RTSP connections, handles pairing and encryption,
/// decodes ALAC audio, and delivers PCM samples via [`AudioSession`].
/// Automatically registers mDNS services for network discovery.
pub use crate::net::server::BindConfig;

pub struct RaopServerBuilder {
    max_clients: usize,
    hwaddr: Option<Vec<u8>>,
    password: Option<String>,
    name: String,
    bind: BindConfig,
}

impl Default for RaopServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RaopServerBuilder {
    pub fn new() -> Self {
        Self {
            max_clients: 10,
            hwaddr: None,
            password: None,
            name: "Shairplay".to_string(),
            bind: BindConfig::default(),
        }
    }

    pub fn max_clients(mut self, n: usize) -> Self { self.max_clients = n; self }
    pub fn hwaddr(mut self, addr: impl Into<Vec<u8>>) -> Self { self.hwaddr = Some(addr.into()); self }
    pub fn password(mut self, pw: impl Into<String>) -> Self { self.password = Some(pw.into()); self }
    /// Set the RTSP listening port. Default: 5000.
    pub fn port(mut self, port: u16) -> Self { self.bind.port = port; self }
    /// Set full bind configuration (address, port, auto-sensing, IPv6).
    pub fn bind(mut self, config: BindConfig) -> Self { self.bind = config; self }
    pub fn name(mut self, name: impl Into<String>) -> Self { self.name = name.into(); self }

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

/// The main RAOP/AirPlay server. Equivalent to raop_t.
/// The main AirPlay/RAOP server.
///
/// Listens for RTSP connections, handles pairing and encryption,
/// decodes ALAC audio, and delivers PCM samples via [`AudioSession`].
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
    pub fn builder() -> RaopServerBuilder {
        RaopServerBuilder::new()
    }

    pub async fn start(&mut self) -> Result<(), ShairplayError> {
        let _actual_port = self.httpd.start(self.bind.port).await?;
        

        // Register mDNS services
        let info = self.service_info();
        let mut mdns = MdnsService::new()?;
        mdns.register_raop(&info)?;
        mdns.register_airplay(&info)?;
        self.mdns = Some(mdns);

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.httpd.is_running()
    }

    pub async fn stop(&mut self) {
        if let Some(mut mdns) = self.mdns.take() {
            mdns.unregister_raop();
            mdns.unregister_airplay();
        }
        self.httpd.stop().await;
    }

    pub fn service_info(&self) -> AirPlayServiceInfo {
        AirPlayServiceInfo::new(
            &self.name,
            self.httpd.port(),
            &self.hwaddr,
            !self.shared.password.is_empty(),
        )
    }
}
