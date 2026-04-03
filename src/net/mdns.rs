use crate::error::NetworkError;
use crate::util;

pub const RAOP_TXTVERS: &str = "1";
pub const RAOP_CH: &str = "2";
pub const RAOP_CN: &str = "0,1";
pub const RAOP_ET: &str = "0,1";
pub const RAOP_SV: &str = "false";
pub const RAOP_DA: &str = "true";
pub const RAOP_SR: &str = "44100";
pub const RAOP_SS: &str = "16";
pub const RAOP_VN: &str = "3";
pub const RAOP_TP: &str = "TCP,UDP";
pub const RAOP_MD: &str = "0,1,2";
pub const RAOP_SM: &str = "false";
pub const RAOP_EK: &str = "1";

pub const GLOBAL_FEATURES: u32 = 0x7;
pub const GLOBAL_MODEL: &str = "AppleTV2,1";
pub const GLOBAL_VERSION: &str = "130.14";

// AirPlay 2 defaults (from shairport-sync bonjour_strings.c)
#[cfg(feature = "airplay2")]
pub const AP2_FEATURES: u64 = 0x1C340405D4A00;
#[cfg(feature = "airplay2")]
pub const AP2_STATUS_FLAGS: u32 = 0x4;
#[cfg(feature = "airplay2")]
pub const AP2_SRCVERS: &str = "377.40.00";
#[cfg(feature = "airplay2")]
pub const AP2_OSVERS: &str = "15.6";
#[cfg(feature = "airplay2")]
pub const AP2_FW_VERSION: &str = "77.40.00";
#[cfg(feature = "airplay2")]
pub const AP2_PROTOVERS: &str = "1.1";

/// mDNS service information for AirPlay network discovery.
#[derive(Debug, Clone)]
pub struct AirPlayServiceInfo {
    pub raop_name: String,
    pub airplay_name: String,
    pub port: u16,
    pub raop_txt: Vec<(String, String)>,
    pub airplay_txt: Vec<(String, String)>,
}

impl AirPlayServiceInfo {
    pub fn new(name: &str, port: u16, hwaddr: &[u8], password: bool) -> Self {
        let hw_raop = util::hwaddr_raop(hwaddr);
        let hw_airplay = util::hwaddr_airplay(hwaddr);
        let raop_name = format!("{}@{}", hw_raop, name);

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
            ("features".into(), format!("0x{:x}", GLOBAL_FEATURES)),
            ("model".into(), GLOBAL_MODEL.into()),
        ];

        Self { raop_name, airplay_name: name.to_string(), port, raop_txt, airplay_txt }
    }

    /// Create AP2 service info with full AirPlay 2 feature flags.
    /// `pk_hex` is the hex-encoded Ed25519 public key, `pi` is the pairing identifier (UUID).
    #[cfg(feature = "airplay2")]
    pub fn new_airplay2(
        name: &str, port: u16, hwaddr: &[u8], password: bool,
        pk_hex: &str, pi: &str,
    ) -> Self {
        let hw_raop = util::hwaddr_raop(hwaddr);
        let hw_airplay = util::hwaddr_airplay(hwaddr);
        let raop_name = format!("{}@{}", hw_raop, name);

        let features_lo = AP2_FEATURES & 0xFFFFFFFF;
        let features_hi = (AP2_FEATURES >> 32) & 0xFFFFFFFF;
        let ft = format!("0x{:X},0x{:X}", features_lo, features_hi);

        let raop_txt = vec![
            // AP1 compatibility fields (allows classic AirPlay fallback)
            ("cn".into(), "0,1".into()),
            ("da".into(), "true".into()),
            ("et".into(), "0,3,5".into()),
            ("pw".into(), (if password { "true" } else { "false" }).into()),
            // AP2 fields
            ("ft".into(), ft.clone()),
            ("fv".into(), AP2_FW_VERSION.into()),
            ("sf".into(), format!("0x{:X}", AP2_STATUS_FLAGS)),
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
            ("flags".into(), format!("0x{:X}", AP2_STATUS_FLAGS)),
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

        Self { raop_name, airplay_name: name.to_string(), port, raop_txt, airplay_txt }
    }
}

/// mDNS service registrar using mdns-sd (pure Rust, cross-platform).
pub struct MdnsService {
    daemon: mdns_sd::ServiceDaemon,
    raop_fullname: Option<String>,
    airplay_fullname: Option<String>,
}

impl MdnsService {
    pub fn new() -> Result<Self, NetworkError> {
        let daemon = mdns_sd::ServiceDaemon::new()
            .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        Ok(Self { daemon, raop_fullname: None, airplay_fullname: None })
    }

    fn txt_map(txt: &[(String, String)]) -> std::collections::HashMap<String, String> {
        txt.iter().cloned().collect()
    }

    fn host_name() -> String {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .map(|h| if h.ends_with(".local.") { h } else { format!("{h}.local.") })
            .unwrap_or_else(|| "shairplay.local.".into())
    }

    pub fn register_raop(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let svc = mdns_sd::ServiceInfo::new(
            "_raop._tcp.local.",
            &info.raop_name,
            &Self::host_name(),
            "",
            info.port,
            Self::txt_map(&info.raop_txt),
        ).map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        self.raop_fullname = Some(svc.get_fullname().to_string());
        self.daemon.register(svc).map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        tracing::info!(name = %info.raop_name, port = info.port, "mDNS: _raop._tcp registered");
        Ok(())
    }

    pub fn register_airplay(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let svc = mdns_sd::ServiceInfo::new(
            "_airplay._tcp.local.",
            &info.airplay_name,
            &Self::host_name(),
            "",
            info.port,
            Self::txt_map(&info.airplay_txt),
        ).map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        self.airplay_fullname = Some(svc.get_fullname().to_string());
        self.daemon.register(svc).map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        tracing::info!(name = %info.airplay_name, port = info.port, "mDNS: _airplay._tcp registered");
        Ok(())
    }

    pub fn unregister_raop(&mut self) {
        if let Some(name) = self.raop_fullname.take() {
            let _ = self.daemon.unregister(&name);
        }
    }

    pub fn unregister_airplay(&mut self) {
        if let Some(name) = self.airplay_fullname.take() {
            let _ = self.daemon.unregister(&name);
        }
    }
}

impl Drop for MdnsService {
    fn drop(&mut self) {
        self.unregister_raop();
        self.unregister_airplay();
        let _ = self.daemon.shutdown();
    }
}

#[cfg(all(test, feature = "airplay2"))]
mod tests {
    use super::*;

    #[test]
    fn ap2_raop_txt_has_required_fields() {
        let info = AirPlayServiceInfo::new_airplay2(
            "Test Speaker", 7000, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            false, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "12345678-1234-1234-1234-123456789abc",
        );

        let find = |key: &str| info.raop_txt.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());

        // AP2 _raop._tcp must have these fields (matching shairport-sync)
        assert_eq!(find("vn"), Some("65537")); // AP2 version, not "3"
        assert_eq!(find("tp"), Some("TCP,UDP")); // TCP for AP1 fallback, UDP for AP2
        assert!(find("ft").unwrap().contains(","));  // features has hi,lo
        assert!(find("pk").is_some());         // Ed25519 public key
        assert!(find("sf").is_some());         // status flags
        assert_eq!(find("cn"), Some("0,1"));
        assert_eq!(find("da"), Some("true"));
        assert_eq!(find("pw"), Some("false"));
    }

    #[test]
    fn ap2_airplay_txt_has_required_fields() {
        let info = AirPlayServiceInfo::new_airplay2(
            "Test Speaker", 7000, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            false, "abcd1234", "my-uuid-here",
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
            "My Speaker", 5000, &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
            false, "pk", "pi",
        );
        assert_eq!(info.raop_name, "123456789ABC@My Speaker");
        assert_eq!(info.airplay_name, "My Speaker");
    }
}
