//! AAC decoder with ADTS framing for AirPlay 2 buffered audio.
//!
//! Raw AAC packets from the buffered audio stream need ADTS headers
//! prepended before they can be decoded. Ported from ap2_buffered_audio_processor.c.

/// SSRC values identifying the audio format (from shairport-sync player.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
/// Audio format identifier from the RTP SSRC field. Apple uses magic values to signal codec/rate.
pub enum AudioSsrc {
    /// Unknown or unrecognized format.
    None = 0,
    /// ALAC 44100 Hz 16-bit stereo.
    Alac44100S16Stereo = 0x0000FACE,
    /// ALAC 48000 Hz 24-bit stereo.
    Alac48000S24Stereo = 0x15000000,
    /// AAC 44100 Hz 24-bit float stereo.
    Aac44100F24Stereo = 0x16000000,
    /// AAC 48000 Hz 24-bit float stereo.
    Aac48000F24Stereo = 0x17000000,
    /// AAC 48000 Hz 24-bit float 5.1 surround.
    Aac48000F24Surround51 = 0x27000000,
    /// AAC 48000 Hz 24-bit float 7.1 surround.
    Aac48000F24Surround71 = 0x28000000,
}

impl AudioSsrc {
    /// Parse an SSRC value into a known audio format.
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x0000FACE => Self::Alac44100S16Stereo,
            0x15000000 => Self::Alac48000S24Stereo,
            0x16000000 => Self::Aac44100F24Stereo,
            0x17000000 => Self::Aac48000F24Stereo,
            0x27000000 => Self::Aac48000F24Surround51,
            0x28000000 => Self::Aac48000F24Surround71,
            _ => Self::None,
        }
    }

    /// Whether this format uses AAC encoding.
    pub fn is_aac(self) -> bool {
        matches!(self, Self::Aac44100F24Stereo | Self::Aac48000F24Stereo | Self::Aac48000F24Surround51 | Self::Aac48000F24Surround71)
    }

    /// Source sample rate for this format.
    pub fn sample_rate(self) -> u32 {
        match self {
            Self::Alac44100S16Stereo | Self::Aac44100F24Stereo => 44100,
            _ => 48000,
        }
    }

    /// Number of audio channels for this format.
    pub fn channels(self) -> u8 {
        match self {
            Self::Aac48000F24Surround51 => 6,
            Self::Aac48000F24Surround71 => 8,
            _ => 2,
        }
    }

    /// ADTS channel configuration index for this format.
    pub fn adts_channel_config(self) -> u8 {
        match self {
            Self::Aac48000F24Surround51 => 6,
            Self::Aac48000F24Surround71 => 7,
            _ => 2,
        }
    }
}

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

/// Persistent AAC decoder using symphonia. Decodes ADTS-wrapped AAC to F32LE PCM.
pub struct AacDecoder {
    decoder: Box<dyn symphonia::core::codecs::Decoder>,
    sample_rate: u32,
    channels: u8,
}

impl AacDecoder {
    /// Create a new decoder for the given format.
    pub fn new(sample_rate: u32, channels: u8) -> Result<Self, String> {
        use symphonia::core::codecs::{CodecParameters, DecoderOptions, CODEC_TYPE_AAC};
        use symphonia::core::audio::Channels;

        let mut params = CodecParameters::new();
        params.for_codec(CODEC_TYPE_AAC).with_sample_rate(sample_rate);

        let ch = match channels {
            1 => Channels::FRONT_CENTRE,
            2 => Channels::FRONT_LEFT | Channels::FRONT_RIGHT,
            6 => Channels::FRONT_LEFT | Channels::FRONT_RIGHT | Channels::FRONT_CENTRE
                | Channels::REAR_LEFT | Channels::REAR_RIGHT | Channels::LFE1,
            8 => Channels::FRONT_LEFT | Channels::FRONT_RIGHT | Channels::FRONT_CENTRE
                | Channels::SIDE_LEFT | Channels::SIDE_RIGHT
                | Channels::REAR_LEFT | Channels::REAR_RIGHT | Channels::LFE1,
            _ => Channels::FRONT_LEFT | Channels::FRONT_RIGHT,
        };
        params.with_channels(ch);

        let decoder = symphonia::default::get_codecs()
            .make(&params, &DecoderOptions::default())
            .map_err(|e| format!("AAC decoder init failed: {e}"))?;

        Ok(Self { decoder, sample_rate, channels })
    }

    /// Decode a raw AAC frame (without ADTS header) to interleaved F32 PCM.
    pub fn decode(&mut self, raw_aac: &[u8]) -> Option<Vec<u8>> {
        use symphonia::core::audio::SampleBuffer;
        use symphonia::core::formats::Packet;

        let packet = Packet::new_from_slice(0, 0, 1024, raw_aac);
        let decoded = self.decoder.decode(&packet).ok()?;
        let spec = *decoded.spec();
        let duration = decoded.capacity() as u64;
        let mut sample_buf = SampleBuffer::<f32>::new(duration, spec);
        sample_buf.copy_interleaved_ref(decoded);
        let samples = sample_buf.samples();
        let mut pcm = Vec::with_capacity(samples.len() * 4);
        for &s in samples {
            pcm.extend_from_slice(&s.to_le_bytes());
        }
        Some(pcm)
    }

    /// Source sample rate for this format.
    pub fn sample_rate(&self) -> u32 { self.sample_rate }
    /// Number of audio channels for this format.
    pub fn channels(&self) -> u8 { self.channels }
}
