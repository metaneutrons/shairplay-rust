//! AAC decoder with ADTS framing for AirPlay 2 buffered audio.
//!
//! Raw AAC packets from the buffered audio stream need ADTS headers
//! prepended before they can be decoded. Ported from ap2_buffered_audio_processor.c.

/// Construct a 7-byte ADTS header for a raw AAC packet.
///
/// `packet_len` is the total length including the 7-byte header itself.
/// `rate` is the sample rate (44100 or 48000).
/// `channels` is the channel configuration (2 = stereo).
pub fn adts_header(packet_len: usize, rate: u32, channels: u8) -> [u8; 7] {
    let profile = 2u8; // AAC-LC
    let freq_idx: u8 = match rate {
        48000 => 3,
        44100 => 4,
        _ => 4, // default to 44100
    };
    let chan_cfg = channels;

    let len = packet_len as u16;
    [
        0xFF,
        0xF9,
        ((profile - 1) << 6) | (freq_idx << 2) | (chan_cfg >> 2),
        ((chan_cfg & 3) << 6) | ((len >> 11) as u8),
        ((len & 0x7FF) >> 3) as u8,
        (((len & 7) as u8) << 5) | 0x1F,
        0xFC,
    ]
}

/// Wrap a raw AAC frame with an ADTS header.
pub fn wrap_adts(raw_aac: &[u8], rate: u32, channels: u8) -> Vec<u8> {
    let total_len = raw_aac.len() + 7;
    let header = adts_header(total_len, rate, channels);
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&header);
    out.extend_from_slice(raw_aac);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // C-verified test vectors from addADTStoPacket()

    #[test]
    fn c_vector_adts_44100_stereo_107() {
        let h = adts_header(107, 44100, 2);
        assert_eq!(hex_encode(&h), "fff950800d7ffc");
    }

    #[test]
    fn c_vector_adts_48000_stereo_507() {
        let h = adts_header(507, 48000, 2);
        assert_eq!(hex_encode(&h), "fff94c803f7ffc");
    }

    #[test]
    fn c_vector_adts_44100_stereo_1031() {
        let h = adts_header(1031, 44100, 2);
        assert_eq!(hex_encode(&h), "fff9508080fffc");
    }

    #[test]
    fn wrap_adts_prepends_header() {
        let raw = vec![0xDE, 0xAD];
        let wrapped = wrap_adts(&raw, 44100, 2);
        assert_eq!(wrapped.len(), 9); // 7 header + 2 payload
        assert_eq!(&wrapped[0..2], &[0xFF, 0xF9]); // sync word
        assert_eq!(&wrapped[7..], &[0xDE, 0xAD]); // payload preserved
    }
}
