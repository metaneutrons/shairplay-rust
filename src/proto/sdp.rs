/// RAOP-specific SDP parser. Extracts fields needed for AirPlay audio streaming.
/// Equivalent to sdp.c.
pub struct Sdp {
    version: Option<String>,
    origin: Option<String>,
    session: Option<String>,
    connection: Option<String>,
    time: Option<String>,
    media: Option<String>,
    rtpmap: Option<String>,
    fmtp: Option<String>,
    rsaaeskey: Option<String>,
    fpaeskey: Option<String>,
    aesiv: Option<String>,
    min_latency: Option<String>,
}

impl Sdp {
    /// Parse SDP data. Equivalent to sdp_init + parse_sdp_data.
    pub fn parse(data: &str) -> Self {
        let mut sdp = Self {
            version: None,
            origin: None,
            session: None,
            connection: None,
            time: None,
            media: None,
            rtpmap: None,
            fmtp: None,
            rsaaeskey: None,
            fpaeskey: None,
            aesiv: None,
            min_latency: None,
        };

        for line in data.lines() {
            let line = line.trim_end_matches('\r');
            if line.len() < 2 || line.as_bytes()[1] != b'=' {
                continue;
            }
            let value = &line[2..];
            match line.as_bytes()[0] {
                b'v' => sdp.version = Some(value.to_string()),
                b'o' => sdp.origin = Some(value.to_string()),
                b's' => sdp.session = Some(value.to_string()),
                b'c' => sdp.connection = Some(value.to_string()),
                b't' => sdp.time = Some(value.to_string()),
                b'm' => sdp.media = Some(value.to_string()),
                b'a' => {
                    if let Some(colon) = value.find(':') {
                        let key = &value[..colon];
                        let val = &value[colon + 1..];
                        match key {
                            "rtpmap" if sdp.rtpmap.is_none() => {
                                sdp.rtpmap = Some(val.to_string());
                            }
                            "fmtp" if sdp.fmtp.is_none() => {
                                sdp.fmtp = Some(val.to_string());
                            }
                            "rsaaeskey" => sdp.rsaaeskey = Some(val.to_string()),
                            "fpaeskey" => sdp.fpaeskey = Some(val.to_string()),
                            "aesiv" => sdp.aesiv = Some(val.to_string()),
                            "min-latency" => sdp.min_latency = Some(val.to_string()),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        sdp
    }

    pub fn version(&self) -> Option<&str> { self.version.as_deref() }
    pub fn origin(&self) -> Option<&str> { self.origin.as_deref() }
    pub fn session(&self) -> Option<&str> { self.session.as_deref() }
    pub fn connection(&self) -> Option<&str> { self.connection.as_deref() }
    pub fn time(&self) -> Option<&str> { self.time.as_deref() }
    pub fn media(&self) -> Option<&str> { self.media.as_deref() }
    pub fn rtpmap(&self) -> Option<&str> { self.rtpmap.as_deref() }
    pub fn fmtp(&self) -> Option<&str> { self.fmtp.as_deref() }
    pub fn rsaaeskey(&self) -> Option<&str> { self.rsaaeskey.as_deref() }
    pub fn fpaeskey(&self) -> Option<&str> { self.fpaeskey.as_deref() }
    pub fn aesiv(&self) -> Option<&str> { self.aesiv.as_deref() }
    pub fn min_latency(&self) -> Option<&str> { self.min_latency.as_deref() }
}
