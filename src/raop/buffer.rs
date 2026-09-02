//! AP1 RTP packet buffer with AES-CBC decryption and codec decode to f32.
//!
//! Incoming RTP packets are queued by sequence number into a fixed-size circular
//! buffer. Each packet is decrypted (AES-128-CBC) and decoded on arrival — either
//! ALAC (`a=rtpmap:… AppleLossless`) or raw PCM (`a=rtpmap:… L16/<rate>/<ch>`).
//! The consumer dequeues packets in order, with silence substitution for missing
//! packets and optional retransmit requests for gaps.

use crate::codec::alac::{AlacConfig, AlacDecoder};
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use std::borrow::Cow;

/// AES-128 key length in bytes.
pub const RAOP_AESKEY_LEN: usize = 16;
/// AES-128 IV length in bytes.
pub const RAOP_AESIV_LEN: usize = 16;
/// Maximum RTP packet size (including 12-byte header).
pub(crate) const RAOP_PACKET_LEN: usize = 32768;
/// Number of slots in the circular buffer. Must be a power of two for modulo indexing.
const RAOP_BUFFER_LENGTH: usize = 32;
/// Default silence-frame length (samples per channel) for PCM streams before the
/// first packet establishes the real frame size. 352 matches the classic AirPlay
/// ALAC frame; it is only used to size silence for a missing *first* packet.
const PCM_DEFAULT_FRAME_SAMPLES: usize = 352;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Clone, Copy)]
struct AesSession {
    key: [u8; RAOP_AESKEY_LEN],
    iv: [u8; RAOP_AESIV_LEN],
}

/// Raw-PCM (`L16`) stream configuration, parsed from the SDP `rtpmap` attribute.
#[derive(Debug, Clone)]
pub(crate) struct PcmConfig {
    /// Number of audio channels.
    pub(crate) num_channels: u8,
    /// Sample rate in Hz.
    pub(crate) sample_rate: u32,
}

/// Output stream format, independent of the wire codec. Consumed by the RTP
/// layer to build the [`AudioFormat`](crate::raop::AudioFormat) for `audio_init`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamFormat {
    /// Number of audio channels.
    pub(crate) num_channels: u8,
    /// Source sample rate in Hz.
    pub(crate) sample_rate: u32,
}

/// The negotiated wire codec plus its decoder state.
enum Codec {
    /// Apple Lossless — the classic AirPlay codec. Also covers PipeWire's
    /// `raop.audio.codec=PCM`, which is really uncompressed-ALAC on the wire.
    Alac { config: AlacConfig, decoder: AlacDecoder },
    /// Raw linear PCM (`L16`): big-endian interleaved S16, no compression.
    Pcm { config: PcmConfig },
}

/// Validated codec parameters parsed from the SDP `rtpmap` attribute.
enum CodecConfig {
    Alac,
    Pcm(PcmConfig),
}

/// A single slot in the circular buffer holding one decoded audio frame.
struct BufferEntry {
    /// Whether this slot contains a valid decoded frame.
    available: bool,
    /// RTP flags byte (first byte of RTP header).
    flags: u8,
    /// RTP payload type byte (second byte of RTP header).
    entry_type: u8,
    /// RTP sequence number.
    seqnum: u16,
    /// RTP timestamp (sample clock).
    timestamp: u32,
    /// RTP synchronization source identifier.
    ssrc: u32,
    /// Decoded F32 audio samples. Pre-allocated to the per-entry capacity.
    audio_buffer: Vec<f32>,
    /// Actual number of valid samples in `audio_buffer`.
    audio_buffer_len: usize,
}

/// Compare two RTP sequence numbers with wrapping (handles 16-bit overflow).
/// Returns negative if s1 is before s2, positive if after, zero if equal.
fn seqnum_cmp(s1: u16, s2: u16) -> i16 {
    s1.wrapping_sub(s2) as i16
}

/// Parse the SDP `fmtp` attribute into an ALAC configuration.
/// Format: `96 <frame_length> <compat_version> <bit_depth> <pb> <mb> <kb> <channels> <max_run> <max_frame_bytes> <avg_bitrate> <sample_rate>`.
fn parse_fmtp(fmtp: &str) -> Option<AlacConfig> {
    let vals: Vec<&str> = fmtp.split(' ').collect();
    if vals.len() < 12 {
        return None;
    }
    // Every field must be a valid integer — a non-numeric field is malformed
    // input and must be rejected, not silently coerced to 0 (a 0 here yields a
    // zero-size audio buffer and a 0-channel decoder downstream).
    let p = |i: usize| vals[i].parse::<u32>().ok();
    let config = AlacConfig {
        frame_length: p(1)?,
        compatible_version: p(2)? as u8,
        bit_depth: p(3)? as u8,
        pb: p(4)? as u8,
        mb: p(5)? as u8,
        kb: p(6)? as u8,
        num_channels: p(7)? as u8,
        max_run: p(8)? as u16,
        max_frame_bytes: p(9)?,
        avg_bit_rate: p(10)?,
        sample_rate: p(11)?,
    };
    // Reject configs that would produce degenerate buffers / decoder state.
    if config.frame_length == 0 || config.num_channels == 0 || config.bit_depth == 0 || config.sample_rate == 0 {
        return None;
    }
    Some(config)
}

/// Parse an `L16/<rate>[/<channels>]` rtpmap encoding into a [`PcmConfig`].
/// Per RFC 3551, `L16` defaults to a single channel when the count is omitted.
fn parse_l16(encoding: &str) -> Option<PcmConfig> {
    let mut parts = encoding.split('/');
    if !parts.next()?.eq_ignore_ascii_case("L16") {
        return None;
    }
    let sample_rate: u32 = parts.next()?.parse().ok()?;
    let num_channels: u8 = match parts.next() {
        Some(ch) => ch.parse().ok()?,
        None => 1,
    };
    if parts.next().is_some() || sample_rate == 0 || num_channels == 0 {
        return None;
    }
    Some(PcmConfig {
        num_channels,
        sample_rate,
    })
}

/// Parse and validate an SDP `rtpmap` value (`"<payload-type> <encoding>"`).
fn parse_codec(rtpmap: &str) -> Option<CodecConfig> {
    let mut fields = rtpmap.split_whitespace();
    fields.next()?.parse::<u8>().ok()?;
    let encoding = fields.next()?;
    if fields.next().is_some() {
        return None;
    }

    let name = encoding.split('/').next()?;
    if name.eq_ignore_ascii_case("AppleLossless") {
        Some(CodecConfig::Alac)
    } else {
        parse_l16(encoding).map(CodecConfig::Pcm)
    }
}

/// Build the 48-byte decoder info block expected by `AlacDecoder::set_info`.
/// Layout matches the ALACSpecificConfig in the Apple ALAC reference decoder.
fn build_decoder_info(config: &AlacConfig) -> [u8; 48] {
    let mut info = [0u8; 48];
    info[24..28].copy_from_slice(&config.frame_length.to_be_bytes());
    info[28] = config.compatible_version;
    info[29] = config.bit_depth;
    info[30] = config.pb;
    info[31] = config.mb;
    info[32] = config.kb;
    info[33] = config.num_channels;
    info[34..36].copy_from_slice(&config.max_run.to_be_bytes());
    info[36..40].copy_from_slice(&config.max_frame_bytes.to_be_bytes());
    info[40..44].copy_from_slice(&config.avg_bit_rate.to_be_bytes());
    info[44..48].copy_from_slice(&config.sample_rate.to_be_bytes());
    info
}

/// Circular RTP packet buffer with decrypt-on-queue and codec decode.
///
/// Packets are inserted by [`queue`](Self::queue) and consumed by
/// [`dequeue`](Self::dequeue). The buffer holds a fixed number of
/// frames. Sequence number wrapping is handled correctly.
///
/// # Audio pipeline
///
/// ```text
/// RTP packet → AES-128-CBC decrypt → ALAC or L16 decode → f32 → buffer slot
/// ```
pub struct RaopBuffer {
    aes: Option<AesSession>,
    codec: Codec,
    is_empty: bool,
    /// Sequence number of the next frame to dequeue (oldest buffered).
    first_seqnum: u16,
    /// Sequence number of the newest buffered frame.
    last_seqnum: u16,
    entries: Vec<BufferEntry>,
    /// Number of f32 samples one decoded frame's buffer can hold (allocation size).
    frame_capacity: usize,
    /// Number of f32 samples to emit when substituting silence for a lost frame.
    /// Constant for ALAC (fixed frame size); tracks the last real frame for PCM.
    silence_samples: usize,
}

impl RaopBuffer {
    /// Create a new encrypted buffer from SDP parameters and AES session keys.
    ///
    /// `rtpmap` selects the codec (`AppleLossless` → ALAC, `L16/...` → PCM);
    /// `fmtp` supplies the ALAC config (ignored for PCM). The decoder is
    /// initialized immediately.
    ///
    /// Returns `None` if the (peer-supplied) `rtpmap`/`fmtp` attributes are
    /// malformed or name an unsupported codec.
    pub fn new(
        rtpmap: &str,
        fmtp: &str,
        aes_key: &[u8; RAOP_AESKEY_LEN],
        aes_iv: &[u8; RAOP_AESIV_LEN],
    ) -> Option<Self> {
        Self::build(
            rtpmap,
            fmtp,
            Some(AesSession {
                key: *aes_key,
                iv: *aes_iv,
            }),
        )
    }

    /// Create a new unencrypted buffer from SDP parameters.
    pub fn new_unencrypted(rtpmap: &str, fmtp: &str) -> Option<Self> {
        Self::build(rtpmap, fmtp, None)
    }

    fn build(rtpmap: &str, fmtp: &str, aes: Option<AesSession>) -> Option<Self> {
        let (codec, frame_capacity, silence_samples) = match parse_codec(rtpmap)? {
            CodecConfig::Pcm(config) => {
                // PCM frames are variable-length: size each slot to the largest RTP
                // payload (worst case) so a big packet never overflows the slot.
                let capacity = (RAOP_PACKET_LEN - 12) / 2;
                let silence = PCM_DEFAULT_FRAME_SAMPLES * config.num_channels as usize;
                (Codec::Pcm { config }, capacity, silence)
            }
            CodecConfig::Alac => {
                let config = parse_fmtp(fmtp)?;
                // ALAC outputs one f32 per sample: frame_length × channels.
                let frame_samples = config.frame_length as usize * config.num_channels as usize;
                let mut decoder = AlacDecoder::new(config.bit_depth as i32, config.num_channels as i32);
                decoder.set_info(&build_decoder_info(&config));
                (Codec::Alac { config, decoder }, frame_samples, frame_samples)
            }
        };

        let entries = (0..RAOP_BUFFER_LENGTH)
            .map(|_| BufferEntry {
                available: false,
                flags: 0,
                entry_type: 0,
                seqnum: 0,
                timestamp: 0,
                ssrc: 0,
                audio_buffer: vec![0.0f32; frame_capacity],
                audio_buffer_len: 0,
            })
            .collect();

        Some(Self {
            aes,
            codec,
            is_empty: true,
            first_seqnum: 0,
            last_seqnum: 0,
            entries,
            frame_capacity,
            silence_samples,
        })
    }

    /// Returns the output stream format (channels + source sample rate).
    pub(crate) fn format(&self) -> StreamFormat {
        match &self.codec {
            Codec::Alac { config, .. } => StreamFormat {
                num_channels: config.num_channels,
                sample_rate: config.sample_rate,
            },
            Codec::Pcm { config } => StreamFormat {
                num_channels: config.num_channels,
                sample_rate: config.sample_rate,
            },
        }
    }

    /// Queue an RTP packet: decrypt, decode (ALAC or L16), store f32 in buffer.
    ///
    /// Returns 1 on success, 0 if duplicate/stale, -1 if packet is malformed.
    /// If the sequence number is far ahead of the current window, the buffer is
    /// flushed to avoid stalling on lost packets.
    pub fn queue(&mut self, data: &[u8], use_seqnum: bool) -> i32 {
        let datalen = data.len();
        if !(12..=RAOP_PACKET_LEN).contains(&datalen) {
            return -1;
        }

        // Extract sequence number from RTP header bytes 2-3 (big-endian).
        let seqnum = if use_seqnum {
            ((data[2] as u16) << 8) | data[3] as u16
        } else {
            self.first_seqnum
        };

        // Drop packets older than our current window.
        if !self.is_empty && seqnum_cmp(seqnum, self.first_seqnum) < 0 {
            return 0;
        }
        // If too far ahead, flush the buffer to resync.
        if seqnum_cmp(seqnum, self.first_seqnum.wrapping_add(RAOP_BUFFER_LENGTH as u16)) >= 0 {
            self.flush(seqnum as i32);
        }

        let idx = seqnum as usize % RAOP_BUFFER_LENGTH;
        // Skip exact duplicates.
        if self.entries[idx].available && seqnum_cmp(self.entries[idx].seqnum, seqnum) == 0 {
            return 0;
        }

        // A failed replacement must not leave stale data available in this slot.
        self.entries[idx].available = false;
        self.entries[idx].audio_buffer_len = 0;

        // AES-128-CBC decrypt: only full 16-byte blocks are encrypted,
        // trailing bytes (< 16) are sent in the clear.
        let payload = &data[12..];
        let encrypted_len = (payload.len() / 16) * 16;

        // Unencrypted sessions borrow the payload directly. Encrypted sessions
        // allocate only when at least one complete AES block is present.
        let packet_buf: Cow<[u8]> = if let (Some(aes), true) = (self.aes, encrypted_len > 0) {
            let decryptor = Aes128CbcDec::new((&aes.key).into(), (&aes.iv).into());
            let mut buf = payload.to_vec();
            decryptor
                .decrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut buf[..encrypted_len])
                .unwrap_or(&[]);
            Cow::Owned(buf)
        } else {
            Cow::Borrowed(payload)
        };

        // Decode into the slot's f32 buffer.
        let capacity = self.frame_capacity;
        let num_samples = match &mut self.codec {
            Codec::Alac { decoder, .. } => {
                // ALAC decode → S16LE, then convert to f32 samples.
                let mut s16_buf = vec![0u8; capacity * 2];
                let output_size = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decoder.decode_frame(&packet_buf, &mut s16_buf)
                }))
                .unwrap_or(0);
                if output_size == 0 {
                    return 0;
                }
                let limit = output_size.min(s16_buf.len());
                let out = &mut self.entries[idx].audio_buffer;
                let mut n = 0;
                for (chunk, out_sample) in s16_buf[..limit].as_chunks::<2>().0.iter().zip(out.iter_mut()) {
                    *out_sample = i16::from_le_bytes(*chunk) as f32 / 32768.0;
                    n += 1;
                }
                n
            }
            Codec::Pcm { config } => {
                // Raw L16: big-endian (network order) interleaved S16 → f32.
                let frame_width = usize::from(config.num_channels) * size_of::<i16>();
                if packet_buf.is_empty() || !packet_buf.len().is_multiple_of(frame_width) {
                    return -1;
                }
                let out = &mut self.entries[idx].audio_buffer;
                let mut n = 0;
                for (chunk, out_sample) in packet_buf.as_chunks::<2>().0.iter().zip(out.iter_mut()) {
                    *out_sample = i16::from_be_bytes(*chunk) as f32 / 32768.0;
                    n += 1;
                }
                if n == 0 {
                    return 0;
                }
                // Remember this frame size so a lost packet substitutes a
                // similarly-sized block of silence rather than a fixed guess.
                self.silence_samples = n;
                n
            }
        };

        let entry = &mut self.entries[idx];
        entry.flags = data[0];
        entry.entry_type = data[1];
        entry.seqnum = seqnum;
        entry.timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        entry.ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        entry.audio_buffer_len = num_samples;
        entry.available = true;

        // Update buffer window.
        if self.is_empty {
            self.first_seqnum = seqnum;
            self.last_seqnum = seqnum;
            self.is_empty = false;
        }
        if seqnum_cmp(seqnum, self.last_seqnum) > 0 {
            self.last_seqnum = seqnum;
        }
        1
    }

    /// Dequeue the next frame in sequence order.
    ///
    /// Returns the decoded f32 audio samples, or `None` if the buffer is empty.
    /// If the next frame is missing and `no_resend` is false, returns `None`
    /// to allow time for a retransmit. If `no_resend` is true (or the buffer
    /// is full), substitutes silence for the missing frame.
    pub fn dequeue(&mut self, no_resend: bool) -> Option<&[f32]> {
        let buflen = seqnum_cmp(self.last_seqnum, self.first_seqnum) as i32 + 1;
        if self.is_empty || buflen <= 0 {
            return None;
        }

        let idx = self.first_seqnum as usize % RAOP_BUFFER_LENGTH;
        // Wait for retransmit unless buffer is full or retransmits are disabled.
        if !no_resend && !self.entries[idx].available && (buflen as usize) < RAOP_BUFFER_LENGTH {
            return None;
        }

        self.first_seqnum = self.first_seqnum.wrapping_add(1);

        // Substitute silence for missing frames.
        if !self.entries[idx].available {
            let size = self.silence_samples.min(self.frame_capacity);
            self.entries[idx].audio_buffer[..size].fill(0.0);
            self.entries[idx].audio_buffer_len = size;
        }
        self.entries[idx].available = false;
        let len = self.entries[idx].audio_buffer_len;
        self.entries[idx].audio_buffer_len = 0;
        Some(&self.entries[idx].audio_buffer[..len])
    }

    /// Flush the buffer, discarding all queued frames.
    ///
    /// If `next_seq` is a valid 16-bit value (0..=0xFFFF), the buffer resets
    /// to expect that sequence number next. Otherwise the buffer is fully emptied.
    pub fn flush(&mut self, next_seq: i32) {
        for entry in &mut self.entries {
            entry.available = false;
            entry.audio_buffer_len = 0;
        }
        if !(0..=0xffff).contains(&next_seq) {
            self.is_empty = true;
        } else {
            self.first_seqnum = next_seq as u16;
            self.last_seqnum = (next_seq as u16).wrapping_sub(1);
        }
    }
}
