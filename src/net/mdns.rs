use std::collections::HashMap;

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

/// All information needed to register AirPlay services via mDNS.
#[derive(Debug, Clone)]
/// mDNS service information for AirPlay network discovery.
///
/// Contains all TXT records and service names needed to register
/// `_raop._tcp` and `_airplay._tcp` services. Can be used for
/// manual mDNS registration if the built-in registration is not suitable.
pub struct AirPlayServiceInfo {
    pub raop_name: String,
    pub airplay_name: String,
    pub port: u16,
    pub raop_txt: HashMap<String, String>,
    pub airplay_txt: HashMap<String, String>,
}

impl AirPlayServiceInfo {
    pub fn new(name: &str, port: u16, hwaddr: &[u8], password: bool) -> Self {
        let hw_raop = util::hwaddr_raop(hwaddr);
        let hw_airplay = util::hwaddr_airplay(hwaddr);
        let raop_name = format!("{}@{}", hw_raop, name);

        let mut raop_txt = HashMap::new();
        raop_txt.insert("txtvers".into(), RAOP_TXTVERS.into());
        raop_txt.insert("ch".into(), RAOP_CH.into());
        raop_txt.insert("cn".into(), RAOP_CN.into());
        raop_txt.insert("et".into(), RAOP_ET.into());
        raop_txt.insert("sv".into(), RAOP_SV.into());
        raop_txt.insert("da".into(), RAOP_DA.into());
        raop_txt.insert("sr".into(), RAOP_SR.into());
        raop_txt.insert("ss".into(), RAOP_SS.into());
        raop_txt.insert("pw".into(), if password { "true" } else { "false" }.into());
        raop_txt.insert("vn".into(), RAOP_VN.into());
        raop_txt.insert("tp".into(), RAOP_TP.into());
        raop_txt.insert("md".into(), RAOP_MD.into());
        raop_txt.insert("vs".into(), GLOBAL_VERSION.into());
        raop_txt.insert("sm".into(), RAOP_SM.into());
        raop_txt.insert("ek".into(), RAOP_EK.into());

        let mut airplay_txt = HashMap::new();
        airplay_txt.insert("deviceid".into(), hw_airplay);
        airplay_txt.insert("features".into(), format!("0x{:x}", GLOBAL_FEATURES));
        airplay_txt.insert("model".into(), GLOBAL_MODEL.into());

        Self {
            raop_name,
            airplay_name: name.to_string(),
            port,
            raop_txt,
            airplay_txt,
        }
    }
}

/// mDNS service registrar using mdns-sd. Equivalent to dnssd_t.
pub struct MdnsService {
    daemon: mdns_sd::ServiceDaemon,
    raop_fullname: Option<String>,
    airplay_fullname: Option<String>,
}

impl MdnsService {
    pub fn new() -> Result<Self, NetworkError> {
        let daemon = mdns_sd::ServiceDaemon::new()
            .map_err(|e| NetworkError::Mdns(e.to_string()))?;
        Ok(Self { daemon, raop_fullname: None, airplay_fullname: None })
    }

    pub fn register_raop(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let mut props = Vec::new();
        for (k, v) in &info.raop_txt {
            props.push((k.as_str(), v.as_str()));
        }
        let svc = mdns_sd::ServiceInfo::new(
            "_raop._tcp.local.",
            &info.raop_name,
            &format!("{}.local.", info.raop_name.replace(['@', ' '], "-")),
            "",
            info.port,
            &props[..],
        ).map_err(|e| NetworkError::Mdns(e.to_string()))?;
        self.raop_fullname = Some(svc.get_fullname().to_string());
        self.daemon.register(svc).map_err(|e| NetworkError::Mdns(e.to_string()))?;
        Ok(())
    }

    pub fn register_airplay(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let mut props = Vec::new();
        for (k, v) in &info.airplay_txt {
            props.push((k.as_str(), v.as_str()));
        }
        let svc = mdns_sd::ServiceInfo::new(
            "_airplay._tcp.local.",
            &info.airplay_name,
            &format!("{}.local.", info.airplay_name.replace(' ', "-")),
            "",
            info.port,
            &props[..],
        ).map_err(|e| NetworkError::Mdns(e.to_string()))?;
        self.airplay_fullname = Some(svc.get_fullname().to_string());
        self.daemon.register(svc).map_err(|e| NetworkError::Mdns(e.to_string()))?;
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
