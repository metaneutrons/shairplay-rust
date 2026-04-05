//! mDNS service registration for AirPlay network discovery.
//!
//! Platform-conditional: uses `astro-dnssd` (native Bonjour) on macOS,
//! `mdns-sd` (pure Rust) on Linux and other platforms.

use crate::error::NetworkError;
use crate::util;

// --- AP1 mDNS TXT record constants ---

/// TXT record version.
pub const RAOP_TXTVERS: &str = "1";
/// Audio channels.
pub const RAOP_CH: &str = "2";
/// Codecs: 0=PCM, 1=ALAC.
pub const RAOP_CN: &str = "0,1";
/// Encryption types: 0=none, 1=RSA.
pub const RAOP_ET: &str = "0,1";
/// Server version flag.
pub const RAOP_SV: &str = "false";
/// Digest auth supported.
pub const RAOP_DA: &str = "true";
/// Sample rate.
pub const RAOP_SR: &str = "44100";
/// Sample size (bits).
pub const RAOP_SS: &str = "16";
/// Protocol version.
pub const RAOP_VN: &str = "3";
/// Transport protocols.
pub const RAOP_TP: &str = "TCP,UDP";
/// Metadata types: 0=text, 1=artwork, 2=progress.
pub const RAOP_MD: &str = "0,1,2";
/// System managed.
pub const RAOP_SM: &str = "false";
/// Encryption key type.
pub const RAOP_EK: &str = "1";

/// Global feature bitmask for AP1 discovery.
pub const GLOBAL_FEATURES: u32 = 0x7;
/// Device model identifier.
pub const GLOBAL_MODEL: &str = "AppleTV2,1";
/// Software version string.
pub const GLOBAL_VERSION: &str = "130.14";

// --- AP2 mDNS TXT record constants ---

/// Status flags (0x4 = audio receiver).
#[cfg(feature = "ap2")]
pub const AP2_STATUS_FLAGS: u32 = 0x4;
/// Source version string.
#[cfg(feature = "ap2")]
pub const AP2_SRCVERS: &str = "377.40.00";
/// OS version string.
#[cfg(feature = "ap2")]
pub const AP2_OSVERS: &str = "15.6";
/// Firmware version string.
#[cfg(feature = "ap2")]
pub const AP2_FW_VERSION: &str = "77.40.00";
/// Protocol version string.
#[cfg(feature = "ap2")]
pub const AP2_PROTOVERS: &str = "1.1";

/// mDNS service information for AirPlay network discovery.
#[derive(Debug, Clone)]
pub struct AirPlayServiceInfo {
    /// RAOP service name ("AABBCCDDEEFF@Display Name").
    pub raop_name: String,
    /// AirPlay display name.
    pub airplay_name: String,
    /// RTSP listening port.
    pub port: u16,
    /// TXT records for _raop._tcp.
    pub raop_txt: Vec<(String, String)>,
    /// TXT records for _airplay._tcp.
    pub airplay_txt: Vec<(String, String)>,
}

impl AirPlayServiceInfo {
    /// Create AP1 service info for mDNS registration.
    pub fn new(name: &str, port: u16, hwaddr: &[u8], password: bool) -> Self {
        let hw_raop = util::hwaddr_raop(hwaddr);
        let hw_airplay = util::hwaddr_airplay(hwaddr);
        let raop_name = format!("{hw_raop}@{name}");

        let raop_txt = vec![
            ("txtvers".into(), RAOP_TXTVERS.into()),
            ("ch".into(), RAOP_CH.into()),
            ("cn".into(), RAOP_CN.into()),
            ("et".into(), RAOP_ET.into()),
            ("sv".into(), RAOP_SV.into()),
            ("da".into(), RAOP_DA.into()),
            ("sr".into(), RAOP_SR.into()),
            ("ss".into(), RAOP_SS.into()),
            ("pw".into(), (if password { "true" } else { "false" }).into()),
            ("vn".into(), RAOP_VN.into()),
            ("tp".into(), RAOP_TP.into()),
            ("md".into(), RAOP_MD.into()),
            ("vs".into(), GLOBAL_VERSION.into()),
            ("sm".into(), RAOP_SM.into()),
            ("ek".into(), RAOP_EK.into()),
        ];

        let airplay_txt = vec![
            ("deviceid".into(), hw_airplay),
            ("features".into(), format!("0x{GLOBAL_FEATURES:x}")),
            ("model".into(), GLOBAL_MODEL.into()),
        ];

        Self {
            raop_name,
            airplay_name: name.to_string(),
            port,
            raop_txt,
            airplay_txt,
        }
    }

    /// Create AP2 service info with full AirPlay 2 feature flags.
    /// `pk_hex` is the hex-encoded Ed25519 public key, `pi` is the pairing identifier (UUID).
    #[cfg(feature = "ap2")]
    pub fn new_airplay2(name: &str, port: u16, hwaddr: &[u8], password: bool, pk_hex: &str, pi: &str) -> Self {
        let hw_raop = util::hwaddr_raop(hwaddr);
        let hw_airplay = util::hwaddr_airplay(hwaddr);
        let raop_name = format!("{hw_raop}@{name}");

        let features_lo = super::features::receiver_features() & 0xFFFFFFFF;
        let features_hi = (super::features::receiver_features() >> 32) & 0xFFFFFFFF;
        let ft = format!("0x{features_lo:X},0x{features_hi:X}");

        let raop_txt = vec![
            // AP1 compatibility fields (allows classic AirPlay fallback)
            ("cn".into(), "0,1".into()),
            ("da".into(), "true".into()),
            ("et".into(), "0,3,5".into()),
            ("pw".into(), (if password { "true" } else { "false" }).into()),
            // AP2 fields
            ("ft".into(), ft.clone()),
            ("fv".into(), AP2_FW_VERSION.into()),
            ("sf".into(), format!("0x{AP2_STATUS_FLAGS:X}")),
            ("md".into(), "0,1,2".into()),
            ("am".into(), GLOBAL_MODEL.into()),
            ("pk".into(), pk_hex.into()),
            ("tp".into(), "TCP,UDP".into()), // TCP for AP1 fallback, UDP for AP2
            ("vn".into(), "65537".into()),
            ("vs".into(), AP2_SRCVERS.into()),
            ("ov".into(), AP2_OSVERS.into()),
        ];

        let airplay_txt = vec![
            ("acl".into(), "0".into()),
            ("btaddr".into(), "00:00:00:00:00:00".into()),
            ("deviceid".into(), hw_airplay),
            ("features".into(), ft),
            ("flags".into(), format!("0x{AP2_STATUS_FLAGS:X}")),
            ("gid".into(), pi.into()),
            ("igl".into(), "0".into()),
            ("gcgl".into(), "0".into()),
            ("model".into(), GLOBAL_MODEL.into()),
            ("protovers".into(), AP2_PROTOVERS.into()),
            ("pi".into(), pi.into()),
            ("pk".into(), pk_hex.into()),
            ("srcvers".into(), AP2_SRCVERS.into()),
            ("osvers".into(), AP2_OSVERS.into()),
            ("vv".into(), "2".into()),
            ("fv".into(), AP2_FW_VERSION.into()),
        ];

        Self {
            raop_name,
            airplay_name: name.to_string(),
            port,
            raop_txt,
            airplay_txt,
        }
    }
}

/// Convert TXT record pairs to a `HashMap` for mDNS registration.
fn txt_map(txt: &[(String, String)]) -> std::collections::HashMap<String, String> {
    txt.iter().cloned().collect()
}

// --- macOS: native Bonjour via astro-dnssd ---

/// mDNS service registration for AirPlay.
///
/// On macOS, uses native Bonjour via `astro-dnssd`.
/// On Linux and other platforms, uses pure Rust `mdns-sd`.
#[cfg(target_os = "macos")]
pub struct MdnsService {
    _raop_reg: Option<astro_dnssd::RegisteredDnsService>,
    _airplay_reg: Option<astro_dnssd::RegisteredDnsService>,
}

#[cfg(target_os = "macos")]
impl MdnsService {
    /// Create a new mDNS service manager.
    pub fn new() -> Result<Self, NetworkError> {
        Ok(Self {
            _raop_reg: None,
            _airplay_reg: None,
        })
    }

    /// Register the _raop._tcp mDNS service.
    pub fn register_raop(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let reg = astro_dnssd::DNSServiceBuilder::new("_raop._tcp", info.port)
            .with_name(&info.raop_name)
            .with_txt_record(txt_map(&info.raop_txt))
            .register()
            .map_err(|e| NetworkError::Mdns(format!("{e:?}")))?;
        tracing::info!(name = %info.raop_name, port = info.port, "mDNS: _raop._tcp registered");
        self._raop_reg = Some(reg);
        Ok(())
    }

    /// Register the _airplay._tcp mDNS service.
    pub fn register_airplay(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let reg = astro_dnssd::DNSServiceBuilder::new("_airplay._tcp", info.port)
            .with_name(&info.airplay_name)
            .with_txt_record(txt_map(&info.airplay_txt))
            .register()
            .map_err(|e| NetworkError::Mdns(format!("{e:?}")))?;
        tracing::info!(name = %info.airplay_name, port = info.port, "mDNS: _airplay._tcp registered");
        self._airplay_reg = Some(reg);
        Ok(())
    }

    /// Unregister the _raop._tcp mDNS service.
    pub fn unregister_raop(&mut self) {
        self._raop_reg = None;
    }
    /// Unregister the _airplay._tcp mDNS service.
    pub fn unregister_airplay(&mut self) {
        self._airplay_reg = None;
    }
}

#[cfg(target_os = "macos")]
impl Drop for MdnsService {
    fn drop(&mut self) {
        self.unregister_raop();
        self.unregister_airplay();
    }
}

// --- Linux/other: pure Rust mdns-sd ---

#[cfg(not(target_os = "macos"))]
/// mDNS service registration for AirPlay (Linux: pure Rust mdns-sd).
pub struct MdnsService {
    daemon: mdns_sd::ServiceDaemon,
    raop_fullname: Option<String>,
    airplay_fullname: Option<String>,
}

#[cfg(not(target_os = "macos"))]
impl MdnsService {
    /// Create a new mDNS service manager.
    pub fn new() -> Result<Self, NetworkError> {
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        Ok(Self {
            daemon,
            raop_fullname: None,
            airplay_fullname: None,
        })
    }

    /// Register the _raop._tcp mDNS service.
    pub fn register_raop(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let svc = mdns_sd::ServiceInfo::new(
            "_raop._tcp.local.",
            &info.raop_name,
            &format!("{}.local.", gethostname::gethostname().to_string_lossy()),
            "",
            info.port,
            txt_map(&info.raop_txt),
        )
        .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        self.raop_fullname = Some(svc.get_fullname().to_string());
        self.daemon
            .register(svc)
            .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        tracing::info!(name = %info.raop_name, port = info.port, "mDNS: _raop._tcp registered");
        Ok(())
    }

    /// Register the _airplay._tcp mDNS service.
    pub fn register_airplay(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let svc = mdns_sd::ServiceInfo::new(
            "_airplay._tcp.local.",
            &info.airplay_name,
            &format!("{}.local.", gethostname::gethostname().to_string_lossy()),
            "",
            info.port,
            txt_map(&info.airplay_txt),
        )
        .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        self.airplay_fullname = Some(svc.get_fullname().to_string());
        self.daemon
            .register(svc)
            .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        tracing::info!(name = %info.airplay_name, port = info.port, "mDNS: _airplay._tcp registered");
        Ok(())
    }

    /// Unregister the _raop._tcp mDNS service.
    pub fn unregister_raop(&mut self) {
        if let Some(name) = self.raop_fullname.take() {
            let _ = self.daemon.unregister(&name);
        }
    }

    /// Unregister the _airplay._tcp mDNS service.
    pub fn unregister_airplay(&mut self) {
        if let Some(name) = self.airplay_fullname.take() {
            let _ = self.daemon.unregister(&name);
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl Drop for MdnsService {
    fn drop(&mut self) {
        self.unregister_raop();
        self.unregister_airplay();
        let _ = self.daemon.shutdown();
    }
}

#[cfg(all(test, feature = "ap2"))]
mod tests {
    use super::*;

    #[test]
    fn ap2_raop_txt_has_required_fields() {
        let info = AirPlayServiceInfo::new_airplay2(
            "Test Speaker",
            7000,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            false,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "12345678-1234-1234-1234-123456789abc",
        );

        let find = |key: &str| info.raop_txt.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());

        // AP2 _raop._tcp must have these fields (matching shairport-sync)
        assert_eq!(find("vn"), Some("65537")); // AP2 version, not "3"
        assert_eq!(find("tp"), Some("TCP,UDP")); // TCP for AP1 fallback, UDP for AP2
        assert!(find("ft").unwrap().contains(",")); // features has hi,lo
        assert!(find("pk").is_some()); // Ed25519 public key
        assert!(find("sf").is_some()); // status flags
        assert_eq!(find("cn"), Some("0,1"));
        assert_eq!(find("da"), Some("true"));
        assert_eq!(find("pw"), Some("false"));
    }

    #[test]
    fn ap2_airplay_txt_has_required_fields() {
        let info = AirPlayServiceInfo::new_airplay2(
            "Test Speaker",
            7000,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            false,
            "abcd1234",
            "my-uuid-here",
        );

        let find = |key: &str| info.airplay_txt.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());

        // AP2 _airplay._tcp required fields
        assert_eq!(find("acl"), Some("0"));
        assert!(find("deviceid").is_some());
        assert!(find("features").is_some());
        assert!(find("flags").is_some());
        assert!(find("gid").is_some());
        assert_eq!(find("model"), Some("AppleTV2,1"));
        assert_eq!(find("protovers"), Some("1.1"));
        assert!(find("pi").is_some());
        assert!(find("pk").is_some());
        assert_eq!(find("vv"), Some("2"));
    }

    #[test]
    fn ap2_raop_name_format() {
        let info = AirPlayServiceInfo::new_airplay2(
            "My Speaker",
            5000,
            &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
            false,
            "pk",
            "pi",
        );
        assert_eq!(info.raop_name, "123456789ABC@My Speaker");
        assert_eq!(info.airplay_name, "My Speaker");
    }
}
