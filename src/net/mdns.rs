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

/// mDNS service information for AirPlay network discovery.
///
/// Contains all TXT records and service names needed to register
/// `_raop._tcp` and `_airplay._tcp` services.
#[derive(Debug, Clone)]
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

/// Build a DNS-SD TXT record from a HashMap, with txtvers first.
fn build_txt(txt: &HashMap<String, String>) -> HashMap<String, String> {
    // astro-dnssd uses HashMap internally, but we ensure txtvers is present
    txt.clone()
}

/// Build an ordered TXT record as key=value pairs for astro-dnssd.
/// Uses a Vec of tuples to preserve insertion order via with_key_value().
fn register_service(regtype: &str, name: &str, port: u16, txt: &HashMap<String, String>) -> Result<astro_dnssd::RegisteredDnsService, NetworkError> {
    let mut builder = astro_dnssd::DNSServiceBuilder::new(regtype, port)
        .with_name(name);

    // Add txtvers first (Apple devices expect it first)
    if let Some(v) = txt.get("txtvers") {
        builder = builder.with_key_value("txtvers".to_string(), v.to_string());
    }
    // Add remaining keys in deterministic order
    let mut keys: Vec<&String> = txt.keys().filter(|k| k.as_str() != "txtvers").collect();
    keys.sort();
    for k in keys {
        builder = builder.with_key_value(k.to_string(), txt[k].to_string());
    }

    builder.register().map_err(|e| NetworkError::Mdns(format!("{e:?}")))
}

/// mDNS service registrar using the system's native DNS-SD (Bonjour/Avahi).
pub struct MdnsService {
    _raop_reg: Option<astro_dnssd::RegisteredDnsService>,
    _airplay_reg: Option<astro_dnssd::RegisteredDnsService>,
}

impl MdnsService {
    pub fn new() -> Result<Self, NetworkError> {
        Ok(Self { _raop_reg: None, _airplay_reg: None })
    }

    pub fn register_raop(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        self._raop_reg = Some(register_service("_raop._tcp", &info.raop_name, info.port, &info.raop_txt)?);
        Ok(())
    }

    pub fn register_airplay(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        self._airplay_reg = Some(register_service("_airplay._tcp", &info.airplay_name, info.port, &info.airplay_txt)?);
        Ok(())
    }

    pub fn unregister_raop(&mut self) { self._raop_reg = None; }
    pub fn unregister_airplay(&mut self) { self._airplay_reg = None; }
}

impl Drop for MdnsService {
    fn drop(&mut self) {
        self.unregister_raop();
        self.unregister_airplay();
    }
}
