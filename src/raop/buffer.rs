use aes::cipher::{BlockDecryptMut, KeyIvInit};
use crate::codec::alac::{AlacConfig, AlacDecoder};

pub const RAOP_AESKEY_LEN: usize = 16;
pub const RAOP_AESIV_LEN: usize = 16;
pub const RAOP_PACKET_LEN: usize = 32768;
const RAOP_BUFFER_LENGTH: usize = 32;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub type ResendCallback = Box<dyn Fn(u16, u16) -> i32 + Send + Sync>;

struct BufferEntry {
    available: bool,
    flags: u8,
    entry_type: u8,
    seqnum: u16,
    timestamp: u32,
    ssrc: u32,
    audio_buffer: Vec<u8>,
    audio_buffer_len: usize,
}

fn seqnum_cmp(s1: u16, s2: u16) -> i16 {
    s1.wrapping_sub(s2) as i16
}

fn parse_fmtp(fmtp: &str) -> Option<AlacConfig> {
    let vals: Vec<&str> = fmtp.split(' ').collect();
    if vals.len() < 12 { return None; }
    let p = |i: usize| vals[i].parse::<u32>().unwrap_or(0);
    let config = AlacConfig {
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
    };
    Some(config)
}

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

/// RTP packet buffer with AES-CBC decryption and ALAC decoding. Equivalent to raop_buffer_t.
pub struct RaopBuffer {
    aeskey: [u8; RAOP_AESKEY_LEN],
    aesiv: [u8; RAOP_AESIV_LEN],
    alac_config: AlacConfig,
    alac: AlacDecoder,
    is_empty: bool,
    first_seqnum: u16,
    last_seqnum: u16,
    entries: Vec<BufferEntry>,
    audio_buffer_size: usize,
}

impl RaopBuffer {
    pub fn new(
        _rtpmap: &str,
        fmtp: &str,
        aes_key: &[u8; RAOP_AESKEY_LEN],
        aes_iv: &[u8; RAOP_AESIV_LEN],
    ) -> Self {
        let config = parse_fmtp(fmtp).expect("invalid fmtp");
        let audio_buffer_size = config.frame_length as usize
            * config.num_channels as usize
            * config.bit_depth as usize / 8;

        let mut alac = AlacDecoder::new(config.bit_depth as i32, config.num_channels as i32);
        let decoder_info = build_decoder_info(&config);
        alac.set_info(&decoder_info);

        let entries = (0..RAOP_BUFFER_LENGTH)
            .map(|_| BufferEntry {
                available: false, flags: 0, entry_type: 0, seqnum: 0,
                timestamp: 0, ssrc: 0,
                audio_buffer: vec![0u8; audio_buffer_size],
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

    pub fn config(&self) -> &AlacConfig {
        &self.alac_config
    }

    pub fn queue(&mut self, data: &[u8], use_seqnum: bool) -> i32 {
        let datalen = data.len();
        if !(12..=RAOP_PACKET_LEN).contains(&datalen) { return -1; }

        let seqnum = if use_seqnum {
            ((data[2] as u16) << 8) | data[3] as u16
        } else {
            self.first_seqnum
        };

        if !self.is_empty && seqnum_cmp(seqnum, self.first_seqnum) < 0 { return 0; }
        if seqnum_cmp(seqnum, self.first_seqnum.wrapping_add(RAOP_BUFFER_LENGTH as u16)) >= 0 {
            self.flush(seqnum as i32);
        }

        let idx = seqnum as usize % RAOP_BUFFER_LENGTH;
        if self.entries[idx].available && seqnum_cmp(self.entries[idx].seqnum, seqnum) == 0 {
            return 0; // duplicate
        }

        self.entries[idx].flags = data[0];
        self.entries[idx].entry_type = data[1];
        self.entries[idx].seqnum = seqnum;
        self.entries[idx].timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        self.entries[idx].ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        self.entries[idx].available = true;

        // AES-CBC decrypt
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

        // ALAC decode
        let output_size = self.alac.decode_frame(&packet_buf, &mut self.entries[idx].audio_buffer);
        self.entries[idx].audio_buffer_len = output_size;

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

    pub fn dequeue(&mut self, no_resend: bool) -> Option<&[u8]> {
        let buflen = seqnum_cmp(self.last_seqnum, self.first_seqnum) as i32 + 1;
        if self.is_empty || buflen <= 0 { return None; }

        let idx = self.first_seqnum as usize % RAOP_BUFFER_LENGTH;
        if !no_resend && !self.entries[idx].available && (buflen as usize) < RAOP_BUFFER_LENGTH {
            return None;
        }

        self.first_seqnum = self.first_seqnum.wrapping_add(1);

        if !self.entries[idx].available {
            let size = self.audio_buffer_size;
            self.entries[idx].audio_buffer[..size].fill(0);
            self.entries[idx].audio_buffer_len = size;
        }
        self.entries[idx].available = false;
        let len = self.entries[idx].audio_buffer_len;
        self.entries[idx].audio_buffer_len = 0;
        Some(&self.entries[idx].audio_buffer[..len])
    }

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
