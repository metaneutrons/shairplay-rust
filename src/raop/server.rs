//! AirPlay server builder and lifecycle.

use super::connection::RaopShared;
use super::types::*;
use crate::crypto::pairing::Pairing;
use crate::crypto::rsa::RsaKey;
use crate::error::{ServerError, ShairplayError};
use crate::net::mdns::{AirPlayServiceInfo, MdnsService};
use crate::net::server::{BindConfig, HttpServer};
use std::sync::Arc;

const AIRPORT_KEY: &str = include_str!("../../airport.key");

fn airport_rsakey() -> Arc<RsaKey> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Arc<RsaKey>> = OnceLock::new();
    KEY.get_or_init(|| Arc::new(RsaKey::from_pem(AIRPORT_KEY).expect("built-in airport.key is invalid")))
        .clone()
}

fn random_hwaddr() -> Vec<u8> {
    use rand::RngCore;

    let mut hwaddr = [0u8; super::MAX_HWADDR_LEN];
    rand::thread_rng().fill_bytes(&mut hwaddr);
    // Locally administered, unicast MAC address.
    hwaddr[0] = (hwaddr[0] | 0x02) & !0x01;
    hwaddr.to_vec()
}

#[cfg(feature = "ap2")]
fn derive_pi_from_hwaddr(hwaddr: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(hwaddr);
    let hash = hasher.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0],
        hash[1],
        hash[2],
        hash[3],
        hash[4],
        hash[5],
        (hash[6] & 0x0f) | 0x40, // version 4
        hash[7],
        (hash[8] & 0x3f) | 0x80, // variant 1
        hash[9],
        hash[10],
        hash[11],
        hash[12],
        hash[13],
        hash[14],
        hash[15]
    )
}

/// Builder for [`RaopServer`].
pub struct RaopServerBuilder {
    max_clients: usize,
    hwaddr: Option<Vec<u8>>,
    password: Option<String>,
    name: String,
    bind: BindConfig,
    #[cfg(feature = "ap2")]
    pairing_store: Option<Arc<dyn PairingStore>>,
    #[cfg(feature = "ap2")]
    mode: AirPlayMode,
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
            #[cfg(feature = "ap2")]
            mode: AirPlayMode::default(),
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

    /// Set the AirPlay protocol mode. Default: [`AirPlayMode::AirPlay2`].
    ///
    /// Use [`AirPlayMode::AirPlay1`] to advertise as a classic receiver even
    /// when the `ap2` feature is compiled in.
    #[cfg(feature = "ap2")]
    pub fn mode(mut self, mode: AirPlayMode) -> Self {
        self.mode = mode;
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
    /// Require normal HomeKit pair-setup with this one-time PIN.
    ///
    /// Without a PIN, AP2 uses the shairport-sync-style transient pairing
    /// profile. Setting a PIN changes mDNS/GET /info status flags so clients
    /// perform persistent M1-M6 pair-setup and later use pair-verify.
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
        if self.max_clients == 0 {
            return Err(ServerError::MaxClients(0).into());
        }
        if let Some(password) = self.password.as_ref()
            && password.len() > super::MAX_PASSWORD_LEN
        {
            return Err(ServerError::InvalidPassword(password.len()).into());
        }
        let rsakey = airport_rsakey();
        let pairing = Arc::new(Pairing::generate()?);
        let hwaddr = match self.hwaddr {
            Some(addr) if addr.len() == super::MAX_HWADDR_LEN => addr,
            Some(addr) => return Err(ServerError::InvalidHwAddr(addr.len()).into()),
            None => random_hwaddr(),
        };

        #[cfg(feature = "ap2")]
        let pairing_id = derive_pi_from_hwaddr(&hwaddr);
        #[cfg(feature = "ap2")]
        let device_id = crate::util::hwaddr_airplay(&hwaddr);
        #[cfg(feature = "ap2")]
        let airplay_name = self.name.clone();

        #[cfg(feature = "ap2")]
        let pairing_store: Arc<dyn PairingStore> = self
            .pairing_store
            .unwrap_or_else(|| Arc::new(MemoryPairingStore::default()));
        // Resolve the accessory's long-term identity once: reuse a persisted seed
        // if the store has one, otherwise generate a random seed and hand it back
        // for persistence. (A store with no identity persistence — e.g. the default
        // in-memory one — yields a fresh identity each start; persist it via
        // `PairingStore::load_identity`/`save_identity` to avoid re-pairing.)
        #[cfg(feature = "ap2")]
        let identity_seed = pairing_store.load_identity().unwrap_or_else(|| {
            let seed = crate::crypto::pairing_homekit::generate_identity_seed();
            pairing_store.save_identity(seed);
            seed
        });

        let shared = Arc::new(RaopShared {
            rsakey,
            pairing,
            hwaddr: hwaddr.clone(),
            password: self.password.unwrap_or_default(),
            handler,
            #[cfg(feature = "ap2")]
            pairing_store,
            #[cfg(feature = "ap2")]
            identity_seed,
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
            #[cfg(feature = "ap2")]
            pairing_id,
            #[cfg(feature = "ap2")]
            device_id,
            #[cfg(feature = "ap2")]
            airplay_name,
            #[cfg(feature = "ap2")]
            active_audio: std::sync::Mutex::new(None),
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
            #[cfg(feature = "ap2")]
            mode: self.mode,
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
    #[cfg(feature = "ap2")]
    mode: AirPlayMode,
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

        // AirPlay 2 PTP sink: accept the sender's clock on 319/320 so it doesn't
        // stall the buffered-audio start. No-op if the ports can't be bound.
        #[cfg(feature = "ap2")]
        if self.mode == AirPlayMode::AirPlay2 {
            crate::net::ptp::spawn_ptp_sink().await;
        }

        if std::env::var("CI").is_err() {
            let info = self.service_info();
            let mut mdns = MdnsService::new()?;
            mdns.register_raop(&info)?;
            #[cfg(feature = "ap2")]
            if self.mode == AirPlayMode::AirPlay2 {
                mdns.register_airplay(&info)?;
            }
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
            if self.mode == AirPlayMode::AirPlay2 {
                let (_, vk) = crate::crypto::pairing_homekit::identity_keypair(&self.shared.identity_seed);
                let pk_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                let pi = self.shared.pairing_id.clone();
                return AirPlayServiceInfo::new_airplay2(
                    &self.name,
                    self.httpd.port(),
                    &self.hwaddr,
                    !self.shared.password.is_empty(),
                    &pk_hex,
                    &pi,
                    self.shared.pin.is_some(),
                    self.shared.pairing_store.has_any_pairing(),
                );
            }
        }
        AirPlayServiceInfo::new(
            &self.name,
            self.httpd.port(),
            &self.hwaddr,
            !self.shared.password.is_empty(),
        )
    }
}
