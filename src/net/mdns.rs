//! mDNS service registration for AirPlay network discovery.
//!
//! Platform-conditional: uses `astro-dnssd` (native Bonjour) on macOS,
//! `mdns-sd` (pure Rust) on Linux and other platforms.

use crate::error::NetworkError;
use crate::net::mdns_scope::{MdnsScopeApplied, ScopePlan};
use crate::raop::config::Ap1Advertisement;
use crate::util;

// --- AP1 mDNS TXT record constants ---

/// TXT record version.
pub(crate) const RAOP_TXTVERS: &str = "1";
/// Audio channels.
pub(crate) const RAOP_CH: &str = "2";
/// Server version flag.
pub(crate) const RAOP_SV: &str = "false";
/// Digest auth supported.
pub(crate) const RAOP_DA: &str = "true";
/// Sample rate.
pub(crate) const RAOP_SR: &str = "44100";
/// Sample size (bits).
pub(crate) const RAOP_SS: &str = "16";
/// Protocol version.
pub(crate) const RAOP_VN: &str = "3";
/// Transport protocols.
pub(crate) const RAOP_TP: &str = "TCP,UDP";
/// Metadata types: 0=text, 1=artwork, 2=progress.
pub(crate) const RAOP_MD: &str = "0,1,2";
/// System managed.
pub(crate) const RAOP_SM: &str = "false";
/// Encryption key type.
pub(crate) const RAOP_EK: &str = "1";
/// AP2 codecs advertised in `_raop` TXT (0=PCM, 1=ALAC) — AP2 supports both.
#[cfg(feature = "ap2")]
pub(crate) const RAOP_AP2_CN: &str = "0,1";
/// AP2 encryption types advertised in `_raop` TXT
/// (0=none, 3=FairPlay, 5=FairPlay SAP 2.5; 4=MFi-SAP is not advertised).
#[cfg(feature = "ap2")]
pub(crate) const RAOP_AP2_ET: &str = "0,3,5";
/// AP2 `_raop` protocol version (65537 = 0x10001).
#[cfg(feature = "ap2")]
pub(crate) const RAOP_AP2_VN: &str = "65537";

/// Global feature bitmask for AP1 discovery.
pub(crate) const GLOBAL_FEATURES: u32 = 0x7;
/// Device model identifier.
pub(crate) const GLOBAL_MODEL: &str = crate::raop::config::GLOBAL_MODEL;
/// Software version string.
pub(crate) const GLOBAL_VERSION: &str = "130.14";

// --- AP2 mDNS TXT record constants ---

/// Source version string.
#[cfg(feature = "ap2")]
pub(crate) const AP2_SRCVERS: &str = crate::raop::config::AP2_SRCVERS;
/// OS version string.
#[cfg(feature = "ap2")]
pub(crate) const AP2_OSVERS: &str = "15.6";
/// Firmware version string.
#[cfg(feature = "ap2")]
pub(crate) const AP2_FW_VERSION: &str = "77.40.00";
/// Protocol version string.
#[cfg(feature = "ap2")]
pub(crate) const AP2_PROTOVERS: &str = crate::raop::config::AP2_PROTOVERS;

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
    /// Create AP1 service info with the default advertised capabilities.
    pub fn new(name: &str, port: u16, hwaddr: &[u8], password: bool) -> Self {
        Self::new_with_ap1_advertisement(name, port, hwaddr, password, &Ap1Advertisement::default())
    }

    /// Create AP1 service info with a validated server advertisement.
    pub(crate) fn new_with_ap1_advertisement(
        name: &str,
        port: u16,
        hwaddr: &[u8],
        password: bool,
        advertisement: &Ap1Advertisement,
    ) -> Self {
        let hw_raop = util::hwaddr_raop(hwaddr);
        let hw_airplay = util::hwaddr_airplay(hwaddr);
        let raop_name = format!("{hw_raop}@{name}");

        let raop_txt = vec![
            ("txtvers".into(), RAOP_TXTVERS.into()),
            ("ch".into(), RAOP_CH.into()),
            ("cn".into(), advertisement.codecs_txt().into()),
            ("et".into(), advertisement.encryption_txt().into()),
            ("sv".into(), RAOP_SV.into()),
            ("da".into(), RAOP_DA.into()),
            ("sr".into(), RAOP_SR.into()),
            ("ss".into(), RAOP_SS.into()),
            (
                "pw".into(),
                (if password { "true" } else { "false" }).into(),
            ),
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
    #[allow(clippy::too_many_arguments)]
    pub fn new_airplay2(
        name: &str,
        port: u16,
        hwaddr: &[u8],
        password: bool,
        pk_hex: &str,
        pi: &str,
        requires_pin_pairing: bool,
        already_paired: bool,
    ) -> Self {
        let hw_raop = util::hwaddr_raop(hwaddr);
        let hw_airplay = util::hwaddr_airplay(hwaddr);
        let raop_name = format!("{hw_raop}@{name}");

        let features = super::features::receiver_features_for_pairing(requires_pin_pairing);
        let features_lo = features & 0xFFFFFFFF;
        let features_hi = (features >> 32) & 0xFFFFFFFF;
        let ft = format!("0x{features_lo:X},0x{features_hi:X}");
        let status_flags =
            crate::raop::config::ap2_status_flags(requires_pin_pairing, already_paired);

        let raop_txt = vec![
            // AP1 compatibility fields (allows classic AirPlay fallback)
            ("cn".into(), RAOP_AP2_CN.into()),
            ("da".into(), RAOP_DA.into()),
            ("et".into(), RAOP_AP2_ET.into()),
            (
                "pw".into(),
                (if password { "true" } else { "false" }).into(),
            ),
            // AP2 fields
            ("ft".into(), ft.clone()),
            ("fv".into(), AP2_FW_VERSION.into()),
            ("sf".into(), format!("0x{status_flags:X}")),
            ("md".into(), RAOP_MD.into()),
            ("am".into(), GLOBAL_MODEL.into()),
            ("pk".into(), pk_hex.into()),
            ("tp".into(), RAOP_TP.into()), // TCP for AP1 fallback, UDP for AP2
            ("vn".into(), RAOP_AP2_VN.into()),
            ("vs".into(), AP2_SRCVERS.into()),
            ("ov".into(), AP2_OSVERS.into()),
        ];

        let airplay_txt = vec![
            ("acl".into(), "0".into()),
            ("btaddr".into(), "00:00:00:00:00:00".into()),
            ("deviceid".into(), hw_airplay),
            ("features".into(), ft),
            ("flags".into(), format!("0x{status_flags:X}")),
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
pub(crate) struct MdnsService {
    /// One registration per interface index. A scope needs one per interface, no scope one for
    /// all interfaces (index 0).
    _raop_regs: Vec<astro_dnssd::RegisteredDnsService>,
    _airplay_regs: Vec<astro_dnssd::RegisteredDnsService>,
    /// Interface indexes to register on. `[0]` means every interface.
    indexes: Vec<u32>,
    applied: MdnsScopeApplied,
}

#[cfg(target_os = "macos")]
impl MdnsService {
    /// Create a new mDNS service manager.
    ///
    /// With a `plan`, every service is registered once per interface of the plan, with that
    /// interface's index. Bonjour then announces the service records on those interfaces only.
    /// The address records of the host belong to the system and stay on every interface.
    pub(crate) fn new(plan: Option<&ScopePlan>) -> Result<Self, NetworkError> {
        let (indexes, applied) = match plan {
            None => (vec![0], MdnsScopeApplied::All),
            Some(plan) => {
                let mut indexes = Vec::with_capacity(plan.interfaces.len());
                for (name, index) in plan.interfaces.iter().zip(&plan.indexes) {
                    let Some(index) = index else {
                        return Err(NetworkError::Mdns(format!(
                            "mDNS scope: interface {name} reports no index"
                        )));
                    };
                    indexes.push(*index);
                }
                tracing::info!(interfaces = ?plan.interfaces, "mDNS: announcement limited");
                (
                    indexes,
                    MdnsScopeApplied::Interfaces(plan.interfaces.clone()),
                )
            }
        };
        Ok(Self {
            _raop_regs: Vec::new(),
            _airplay_regs: Vec::new(),
            indexes,
            applied,
        })
    }

    /// What was done with the requested scope.
    pub(crate) fn applied(&self) -> &MdnsScopeApplied {
        &self.applied
    }

    /// Register `regtype` once per interface index.
    fn register_all(
        &self,
        regtype: &str,
        name: &str,
        port: u16,
        txt: &[(String, String)],
    ) -> Result<Vec<astro_dnssd::RegisteredDnsService>, NetworkError> {
        let mut regs = Vec::with_capacity(self.indexes.len());
        for &index in &self.indexes {
            let reg = astro_dnssd::DNSServiceBuilder::new(regtype, port)
                .with_name(name)
                .with_txt_record(txt_map(txt))
                .with_interface_index(index)
                .register()
                .map_err(|e| NetworkError::Mdns(format!("{e:?}")))?;
            regs.push(reg);
        }
        Ok(regs)
    }

    /// Register the _raop._tcp mDNS service.
    pub(crate) fn register_raop(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        self._raop_regs =
            self.register_all("_raop._tcp", &info.raop_name, info.port, &info.raop_txt)?;
        tracing::info!(name = %info.raop_name, port = info.port, "mDNS: _raop._tcp registered");
        Ok(())
    }

    /// Register the _airplay._tcp mDNS service.
    #[cfg(feature = "ap2")]
    pub(crate) fn register_airplay(
        &mut self,
        info: &AirPlayServiceInfo,
    ) -> Result<(), NetworkError> {
        self._airplay_regs = self.register_all(
            "_airplay._tcp",
            &info.airplay_name,
            info.port,
            &info.airplay_txt,
        )?;
        tracing::info!(name = %info.airplay_name, port = info.port, "mDNS: _airplay._tcp registered");
        Ok(())
    }

    /// Unregister the _raop._tcp mDNS service.
    pub(crate) fn unregister_raop(&mut self) {
        self._raop_regs.clear();
    }
    /// Unregister the _airplay._tcp mDNS service.
    pub(crate) fn unregister_airplay(&mut self) {
        self._airplay_regs.clear();
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
pub(crate) struct MdnsService {
    daemon: mdns_sd::ServiceDaemon,
    raop_fullname: Option<String>,
    airplay_fullname: Option<String>,
    applied: MdnsScopeApplied,
}

#[cfg(not(target_os = "macos"))]
impl MdnsService {
    /// Create a new mDNS service manager.
    ///
    /// With a `plan`, the daemon is limited to the interfaces that carry its addresses
    /// before anything is registered, so no record leaves on another interface.
    pub(crate) fn new(plan: Option<&ScopePlan>) -> Result<Self, NetworkError> {
        let daemon =
            mdns_sd::ServiceDaemon::new().map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        let applied = match plan {
            None => MdnsScopeApplied::All,
            Some(plan) => {
                let limit = || -> Result<(), mdns_sd::Error> {
                    daemon.disable_interface(mdns_sd::IfKind::All)?;
                    for addr in &plan.addrs {
                        daemon.enable_interface(mdns_sd::IfKind::Addr(*addr))?;
                    }
                    Ok(())
                };
                if let Err(e) = limit() {
                    let _ = daemon.shutdown();
                    return Err(NetworkError::Mdns(format!("mDNS scope: {e}")));
                }
                tracing::info!(interfaces = ?plan.interfaces, "mDNS: announcement limited");
                MdnsScopeApplied::Interfaces(plan.interfaces.clone())
            }
        };
        Ok(Self {
            daemon,
            raop_fullname: None,
            airplay_fullname: None,
            applied,
        })
    }

    /// What was done with the requested scope.
    pub(crate) fn applied(&self) -> &MdnsScopeApplied {
        &self.applied
    }

    /// Register the _raop._tcp mDNS service.
    pub(crate) fn register_raop(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let svc = mdns_sd::ServiceInfo::new(
            "_raop._tcp.local.",
            &info.raop_name,
            &format!("{}.local.", gethostname::gethostname().to_string_lossy()),
            "",
            info.port,
            txt_map(&info.raop_txt),
        )
        .map(|svc| svc.enable_addr_auto())
        .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        self.raop_fullname = Some(svc.get_fullname().to_string());
        self.daemon
            .register(svc)
            .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        tracing::info!(name = %info.raop_name, port = info.port, "mDNS: _raop._tcp registered");
        Ok(())
    }

    /// Register the _airplay._tcp mDNS service.
    #[cfg(feature = "ap2")]
    pub(crate) fn register_airplay(
        &mut self,
        info: &AirPlayServiceInfo,
    ) -> Result<(), NetworkError> {
        let svc = mdns_sd::ServiceInfo::new(
            "_airplay._tcp.local.",
            &info.airplay_name,
            &format!("{}.local.", gethostname::gethostname().to_string_lossy()),
            "",
            info.port,
            txt_map(&info.airplay_txt),
        )
        .map(|svc| svc.enable_addr_auto())
        .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        self.airplay_fullname = Some(svc.get_fullname().to_string());
        self.daemon
            .register(svc)
            .map_err(|e| NetworkError::Mdns(format!("{e}")))?;
        tracing::info!(name = %info.airplay_name, port = info.port, "mDNS: _airplay._tcp registered");
        Ok(())
    }

    /// Unregister the _raop._tcp mDNS service.
    pub(crate) fn unregister_raop(&mut self) {
        if let Some(name) = self.raop_fullname.take() {
            self.unregister(&name);
        }
    }

    /// Unregister the _airplay._tcp mDNS service.
    pub(crate) fn unregister_airplay(&mut self) {
        if let Some(name) = self.airplay_fullname.take() {
            self.unregister(&name);
        }
    }

    /// Unregister a service and wait until the daemon has sent its goodbye (it answers after the first one), so a
    /// process that exits right after stopping the server still tells the browsers' caches the records are gone.
    fn unregister(&self, name: &str) {
        if let Ok(done) = self.daemon.unregister(name) {
            let _ = done.recv_timeout(std::time::Duration::from_secs(1));
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
            false,
            false,
        );

        let find = |key: &str| {
            info.raop_txt
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };

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
            false,
            false,
        );

        let find = |key: &str| {
            info.airplay_txt
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };

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
            false,
            false,
        );
        assert_eq!(info.raop_name, "123456789ABC@My Speaker");
        assert_eq!(info.airplay_name, "My Speaker");
    }

    #[test]
    #[cfg(not(feature = "video"))]
    fn ap2_pin_pairing_txt_changes_features_and_flags() {
        let info = AirPlayServiceInfo::new_airplay2(
            "Test Speaker",
            7000,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            false,
            "abcd1234",
            "my-uuid-here",
            true,
            false,
        );
        let raop = |key: &str| {
            info.raop_txt
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        let airplay = |key: &str| {
            info.airplay_txt
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };

        assert_eq!(raop("ft"), Some("0x405D4A00,0x14340"));
        assert_eq!(airplay("features"), Some("0x405D4A00,0x14340"));
        assert_eq!(raop("sf"), Some("0x204"));
        assert_eq!(airplay("flags"), Some("0x204"));
    }

    #[test]
    #[cfg(feature = "video")]
    fn ap2_pin_pairing_txt_changes_flags_with_video_features() {
        let info = AirPlayServiceInfo::new_airplay2(
            "Test Speaker",
            7000,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            false,
            "abcd1234",
            "my-uuid-here",
            true,
            false,
        );
        let raop = |key: &str| {
            info.raop_txt
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        let airplay = |key: &str| {
            info.airplay_txt
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };

        assert_eq!(raop("ft"), Some("0x527FFEE6,0x0"));
        assert_eq!(airplay("features"), Some("0x527FFEE6,0x0"));
        assert_eq!(raop("sf"), Some("0x204"));
        assert_eq!(airplay("flags"), Some("0x204"));
    }
}
