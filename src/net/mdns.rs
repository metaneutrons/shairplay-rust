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
}

/// mDNS service registrar using native DNS-SD (Bonjour/Avahi).
pub struct MdnsService {
    _raop_reg: Option<astro_dnssd::RegisteredDnsService>,
    _airplay_reg: Option<astro_dnssd::RegisteredDnsService>,
}

impl MdnsService {
    pub fn new() -> Result<Self, NetworkError> {
        Ok(Self { _raop_reg: None, _airplay_reg: None })
    }

    pub fn register_raop(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let reg = astro_dnssd::DNSServiceBuilder::new("_raop._tcp", info.port)
            .with_name(&info.raop_name)
            .with_txt_ordered(info.raop_txt.clone())
            .register()
            .map_err(|e| NetworkError::Mdns(format!("{e:?}")))?;
        self._raop_reg = Some(reg);
        Ok(())
    }

    pub fn register_airplay(&mut self, info: &AirPlayServiceInfo) -> Result<(), NetworkError> {
        let reg = astro_dnssd::DNSServiceBuilder::new("_airplay._tcp", info.port)
            .with_name(&info.airplay_name)
            .with_txt_ordered(info.airplay_txt.clone())
            .register()
            .map_err(|e| NetworkError::Mdns(format!("{e:?}")))?;
        self._airplay_reg = Some(reg);
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
