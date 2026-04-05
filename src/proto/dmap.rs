//! DMAP (Digital Media Access Protocol) parser.
//!
//! Parses the binary TLV format used by AirPlay for track metadata.
//! Format: 4-byte ASCII tag + 4-byte BE length + data.

/// Parsed track metadata from DMAP.
#[derive(Debug, Clone, Default)]
pub struct TrackMetadata {
    /// Track title (`minm`).
    pub title: Option<String>,
    /// Artist name (`asar`).
    pub artist: Option<String>,
    /// Album name (`asal`).
    pub album: Option<String>,
    /// Genre (`asgn`).
    pub genre: Option<String>,
    /// Duration in milliseconds (`astm`).
    pub duration_ms: Option<u32>,
    /// Track number (`astn`).
    pub track_number: Option<u16>,
    /// Disc number (`asdk`).
    pub disc_number: Option<u16>,
}

impl TrackMetadata {
    /// Parse DMAP binary data into structured metadata.
    pub fn from_dmap(data: &[u8]) -> Self {
        let mut meta = Self::default();
        let mut pos = 8; // skip mlit header
        while pos + 8 <= data.len() {
            let tag = &data[pos..pos + 4];
            let len = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
            pos += 8;
            if pos + len > data.len() {
                break;
            }
            let chunk = &data[pos..pos + len];
            let as_str = || std::str::from_utf8(chunk).ok().map(String::from);
            let as_u32 = || chunk.try_into().ok().map(u32::from_be_bytes);
            let as_u16 = || chunk.try_into().ok().map(u16::from_be_bytes);
            match tag {
                b"minm" => meta.title = as_str(),
                b"asar" => meta.artist = as_str(),
                b"asal" => meta.album = as_str(),
                b"asgn" => meta.genre = as_str(),
                b"astm" => meta.duration_ms = as_u32(),
                b"astn" => meta.track_number = as_u16(),
                b"asdk" => meta.disc_number = as_u16(),
                _ => {
                    tracing::trace!(tag = %String::from_utf8_lossy(tag), len, "DMAP: unknown tag");
                }
            }
            pos += len;
        }
        tracing::debug!(?meta, "Track metadata parsed");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::TrackMetadata;

    const DMAP_FULL: &[u8] = &[
        0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x57, 0x6d, 0x69, 0x6b, 0x64, 0x00, 0x00, 0x00, 0x01, 0x02, 0x6d,
        0x69, 0x6e, 0x6d, 0x00, 0x00, 0x00, 0x11, 0x42, 0x6f, 0x68, 0x65, 0x6d, 0x69, 0x61, 0x6e, 0x20, 0x52, 0x68,
        0x61, 0x70, 0x73, 0x6f, 0x64, 0x79, 0x61, 0x73, 0x61, 0x72, 0x00, 0x00, 0x00, 0x05, 0x51, 0x75, 0x65, 0x65,
        0x6e, 0x61, 0x73, 0x61, 0x6c, 0x00, 0x00, 0x00, 0x14, 0x41, 0x20, 0x4e, 0x69, 0x67, 0x68, 0x74, 0x20, 0x61,
        0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x61, 0x73, 0x67, 0x6e, 0x00, 0x00, 0x00,
        0x04, 0x52, 0x6f, 0x63, 0x6b,
    ];

    #[test]
    fn dmap_parse_full() {
        let meta = TrackMetadata::from_dmap(DMAP_FULL);
        assert_eq!(meta.title.as_deref(), Some("Bohemian Rhapsody"));
        assert_eq!(meta.artist.as_deref(), Some("Queen"));
        assert_eq!(meta.album.as_deref(), Some("A Night at the Opera"));
        assert_eq!(meta.genre.as_deref(), Some("Rock"));
    }

    #[test]
    fn dmap_parse_title_only() {
        let data: &[u8] = &[
            0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x0d, 0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00, 0x00, 0x05, 0x48, 0x65,
            0x6c, 0x6c, 0x6f,
        ];
        let meta = TrackMetadata::from_dmap(data);
        assert_eq!(meta.title.as_deref(), Some("Hello"));
        assert_eq!(meta.artist, None);
    }

    #[test]
    fn dmap_parse_empty() {
        let meta = TrackMetadata::from_dmap(&[]);
        assert_eq!(meta.title, None);
    }

    #[test]
    fn dmap_parse_truncated() {
        let meta = TrackMetadata::from_dmap(&DMAP_FULL[..8]);
        assert_eq!(meta.title, None);
    }

    #[test]
    fn dmap_parse_corrupt_length() {
        let data: &[u8] = &[
            0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x0d, 0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00, 0xff, 0xff, 0x48, 0x65,
            0x6c, 0x6c, 0x6f,
        ];
        let meta = TrackMetadata::from_dmap(data);
        assert_eq!(meta.title, None);
    }
}
