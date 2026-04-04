//! AP1 RTP packet buffer with AES-CBC decryption and ALAC decode to f32.
//!
//! Incoming RTP packets are queued by sequence number into a fixed-size circular
//! buffer. Each packet is decrypted (AES-128-CBC) and decoded (ALAC) on arrival.
//! The consumer dequeues packets in order, with silence substitution for missing
//! packets and optional retransmit requests for gaps.

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use crate::codec::alac::{AlacConfig, AlacDecoder};

/// AES-128 key length in bytes.
pub const RAOP_AESKEY_LEN: usize = 16;
/// AES-128 IV length in bytes.
pub const RAOP_AESIV_LEN: usize = 16;
/// Maximum RTP packet size (including 12-byte header).
pub const RAOP_PACKET_LEN: usize = 32768;
/// Number of slots in the circular buffer. Must be a power of two for modulo indexing.
const RAOP_BUFFER_LENGTH: usize = 32;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// Callback invoked when missing packets are detected.
/// Parameters: (first_missing_seqnum, count_of_missing_packets).
pub type ResendCallback = Box<dyn Fn(u16, u16) -> i32 + Send + Sync>;

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
    /// Decoded F32 audio samples. Pre-allocated to max frame size.
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
/// Format: "96 <frame_length> <compat_version> <bit_depth> <pb> <mb> <kb> <channels> <max_run> <max_frame_bytes> <avg_bitrate> <sample_rate>"
fn parse_fmtp(fmtp: &str) -> Option<AlacConfig> {
    let vals: Vec<&str> = fmtp.split(' ').collect();
    if vals.len() < 12 { return None; }
    let p = |i: usize| vals[i].parse::<u32>().unwrap_or(0);
    Some(AlacConfig {
        frame_length: p(1),
        compatible_version: p(2) as u8,
        bit_depth: p(3) as u8,
        pb: p(4) as u8,
        mb: p(5) as u8,
        kb: p(6) as u8,
        num_channels: p(7) as u8,
        max_run: p(8) as u16,
        max_frame_bytes: p(9),
        avg_bit_rate: p(10),
        sample_rate: p(11),
    })
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

/// Circular RTP packet buffer with decrypt-on-queue and ALAC decode.
///
/// Packets are inserted by [`queue`](Self::queue) and consumed by
/// [`dequeue`](Self::dequeue). The buffer holds up to [`RAOP_BUFFER_LENGTH`]
/// frames. Sequence number wrapping is handled correctly.
///
/// # Audio pipeline
///
/// ```text
/// RTP packet → AES-128-CBC decrypt → ALAC decode → S16 → f32 → buffer slot
/// ```
pub struct RaopBuffer {
    aeskey: [u8; RAOP_AESKEY_LEN],
    aesiv: [u8; RAOP_AESIV_LEN],
    alac_config: AlacConfig,
    alac: AlacDecoder,
    is_empty: bool,
    /// Sequence number of the next frame to dequeue (oldest buffered).
    first_seqnum: u16,
    /// Sequence number of the newest buffered frame.
    last_seqnum: u16,
    entries: Vec<BufferEntry>,
    /// Number of f32 samples in one decoded audio frame.
    audio_buffer_size: usize,
}

impl RaopBuffer {
    /// Create a new buffer from SDP parameters and AES session keys.
    ///
    /// `fmtp` is parsed to determine ALAC frame size, channel count, and sample rate.
    /// The ALAC decoder is initialized immediately.
    pub fn new(
        _rtpmap: &str,
        fmtp: &str,
        aes_key: &[u8; RAOP_AESKEY_LEN],
        aes_iv: &[u8; RAOP_AESIV_LEN],
    ) -> Self {
        let config = parse_fmtp(fmtp).expect("invalid fmtp");
        // ALAC outputs S16LE; we convert to F32 (one f32 per sample).
        let s16_buffer_size = config.frame_length as usize
            * config.num_channels as usize
            * config.bit_depth as usize / 8;
        let audio_buffer_size = s16_buffer_size / 2; // num samples

        let mut alac = AlacDecoder::new(config.bit_depth as i32, config.num_channels as i32);
        let decoder_info = build_decoder_info(&config);
        alac.set_info(&decoder_info);

        let entries = (0..RAOP_BUFFER_LENGTH)
            .map(|_| BufferEntry {
                available: false, flags: 0, entry_type: 0, seqnum: 0,
                timestamp: 0, ssrc: 0,
                audio_buffer: vec![0.0f32; audio_buffer_size],
                audio_buffer_len: 0,
            })
            .collect();

        Self {
            aeskey: *aes_key,
            aesiv: *aes_iv,
            alac_config: config,
            alac,
            is_empty: true,
            first_seqnum: 0,
            last_seqnum: 0,
            entries,
            audio_buffer_size,
        }
    }

    /// Returns the ALAC configuration parsed from the SDP fmtp attribute.
    pub fn config(&self) -> &AlacConfig {
        &self.alac_config
    }

    /// Queue an RTP packet: decrypt, decode ALAC, convert to f32, store in buffer.
    ///
    /// Returns 1 on success, 0 if duplicate/stale, -1 if packet is malformed.
    /// If the sequence number is far ahead of the current window, the buffer is
    /// flushed to avoid stalling on lost packets.
    pub fn queue(&mut self, data: &[u8], use_seqnum: bool) -> i32 {
        let datalen = data.len();
        if !(12..=RAOP_PACKET_LEN).contains(&datalen) { return -1; }

        // Extract sequence number from RTP header bytes 2-3 (big-endian).
        let seqnum = if use_seqnum {
            ((data[2] as u16) << 8) | data[3] as u16
        } else {
            self.first_seqnum
        };

        // Drop packets older than our current window.
        if !self.is_empty && seqnum_cmp(seqnum, self.first_seqnum) < 0 { return 0; }
        // If too far ahead, flush the buffer to resync.
        if seqnum_cmp(seqnum, self.first_seqnum.wrapping_add(RAOP_BUFFER_LENGTH as u16)) >= 0 {
            self.flush(seqnum as i32);
        }

        let idx = seqnum as usize % RAOP_BUFFER_LENGTH;
        // Skip exact duplicates.
        if self.entries[idx].available && seqnum_cmp(self.entries[idx].seqnum, seqnum) == 0 {
            return 0;
        }

        // Parse RTP header fields.
        self.entries[idx].flags = data[0];
        self.entries[idx].entry_type = data[1];
        self.entries[idx].seqnum = seqnum;
        self.entries[idx].timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        self.entries[idx].ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        self.entries[idx].available = true;

        // AES-128-CBC decrypt: only full 16-byte blocks are encrypted,
        // trailing bytes (< 16) are sent in the clear.
        let payload = &data[12..];
        let encrypted_len = (payload.len() / 16) * 16;
        let mut packet_buf = vec![0u8; payload.len()];

        if encrypted_len > 0 {
            let decryptor = Aes128CbcDec::new(
                self.aeskey[..].into(),
                self.aesiv[..].into(),
            );
            let mut encrypted = payload[..encrypted_len].to_vec();
            decryptor.decrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut encrypted)
                .unwrap_or(&[]);
            packet_buf[..encrypted_len].copy_from_slice(&encrypted);
        }
        packet_buf[encrypted_len..].copy_from_slice(&payload[encrypted_len..]);

        // ALAC decode → S16LE, then convert to f32 samples.
        let mut s16_buf = vec![0u8; self.audio_buffer_size * 2];
        let output_size = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.alac.decode_frame(&packet_buf, &mut s16_buf)
        })).unwrap_or(0);
        if output_size == 0 { return 0; }
        let num_samples = output_size / 2;
        for i in 0..num_samples {
            let s = i16::from_le_bytes([s16_buf[i * 2], s16_buf[i * 2 + 1]]);
            self.entries[idx].audio_buffer[i] = s as f32 / 32768.0;
        }
        self.entries[idx].audio_buffer_len = num_samples;

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
        if self.is_empty || buflen <= 0 { return None; }

        let idx = self.first_seqnum as usize % RAOP_BUFFER_LENGTH;
        // Wait for retransmit unless buffer is full or retransmits are disabled.
        if !no_resend && !self.entries[idx].available && (buflen as usize) < RAOP_BUFFER_LENGTH {
            return None;
        }

        self.first_seqnum = self.first_seqnum.wrapping_add(1);

        // Substitute silence for missing frames.
        if !self.entries[idx].available {
            let size = self.audio_buffer_size;
            self.entries[idx].audio_buffer[..size].fill(0.0);
            self.entries[idx].audio_buffer_len = size;
        }
        self.entries[idx].available = false;
        let len = self.entries[idx].audio_buffer_len;
        self.entries[idx].audio_buffer_len = 0;
        Some(&self.entries[idx].audio_buffer[..len])
    }

    /// Scan for gaps in the buffer and request retransmission via `resend_cb`.
    ///
    /// Walks from `first_seqnum` forward until it finds an available entry,
    /// then calls the callback with the starting sequence number and count
    /// of consecutive missing packets.
    pub fn handle_resends(&self, resend_cb: &ResendCallback) {
        if seqnum_cmp(self.first_seqnum, self.last_seqnum) >= 0 { return; }

        let mut seqnum = self.first_seqnum;
        while seqnum_cmp(seqnum, self.last_seqnum) < 0 {
            let idx = seqnum as usize % RAOP_BUFFER_LENGTH;
            if self.entries[idx].available { break; }
            seqnum = seqnum.wrapping_add(1);
        }
        if seqnum_cmp(seqnum, self.first_seqnum) == 0 { return; }
        let count = seqnum_cmp(seqnum, self.first_seqnum) as u16;
        resend_cb(self.first_seqnum, count);
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
