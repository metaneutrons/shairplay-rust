//! Apple Lossless Audio Codec (ALAC) decoder.

/// ALAC decoder configuration, parsed from the fmtp SDP attribute.
#[derive(Debug, Clone)]
pub(crate) struct AlacConfig {
    /// Samples per frame.
    pub(crate) frame_length: u32,
    /// ALAC version.
    pub(crate) compatible_version: u8,
    /// Bits per sample (16 or 24).
    pub(crate) bit_depth: u8,
    /// Rice parameter history mult.
    pub(crate) pb: u8,
    /// Rice initial history.
    pub(crate) mb: u8,
    /// Rice limit.
    pub(crate) kb: u8,
    /// Number of audio channels.
    pub(crate) num_channels: u8,
    /// Maximum run length.
    pub(crate) max_run: u16,
    /// Maximum encoded frame size.
    pub(crate) max_frame_bytes: u32,
    /// Average bit rate.
    pub(crate) avg_bit_rate: u32,
    /// Sample rate in Hz.
    pub(crate) sample_rate: u32,
}

/// ALAC format selected in an AirPlay 2 `audioFormat` SETUP field.
// Consumed by the AP2 RTSP SETUP handler (and the unit tests). Dead in the
// default `--lib` build where neither is compiled.
#[cfg_attr(not(feature = "ap2"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AlacFormat {
    pub(crate) sample_rate: u32,
    pub(crate) bit_depth: u8,
    pub(crate) channels: u8,
}

impl AlacFormat {
    /// Parse AP2 audio format bit values.
    ///
    /// These are format-capability bit values, not RTP SSRC values. For example,
    /// `0x00040000` is ALAC/44100/16/2.
    #[cfg_attr(not(feature = "ap2"), allow(dead_code))]
    pub(crate) fn from_audio_format(v: u32) -> Option<Self> {
        match v {
            0x0004_0000 => Some(Self {
                sample_rate: 44_100,
                bit_depth: 16,
                channels: 2,
            }),
            0x0008_0000 => Some(Self {
                sample_rate: 44_100,
                bit_depth: 24,
                channels: 2,
            }),
            0x0010_0000 => Some(Self {
                sample_rate: 48_000,
                bit_depth: 16,
                channels: 2,
            }),
            0x0020_0000 => Some(Self {
                sample_rate: 48_000,
                bit_depth: 24,
                channels: 2,
            }),
            _ => None,
        }
    }
}

/// Bitstream reader for ALAC decoding.
struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize, // byte position
    bit: u32,   // bit accumulator (0-7)
}

impl<'a> BitReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, bit: 0 }
    }

    fn readbits_16(&mut self, bits: u32) -> u32 {
        let b = self.buf;
        let p = self.pos;
        // Guard against reading past end of buffer (matches C behavior of reading garbage)
        let b0 = if p < b.len() { b[p] as u32 } else { 0 };
        let b1 = if p + 1 < b.len() { b[p + 1] as u32 } else { 0 };
        let b2 = if p + 2 < b.len() { b[p + 2] as u32 } else { 0 };
        let result = (b0 << 16) | (b1 << 8) | b2;
        let result = (result << self.bit) & 0x00ffffff;
        let result = result >> (24 - bits);
        let new_acc = self.bit + bits;
        self.pos += (new_acc >> 3) as usize;
        self.bit = new_acc & 7;
        result
    }

    fn readbits(&mut self, mut bits: u32) -> u32 {
        let mut result = 0u32;
        if bits > 16 {
            bits -= 16;
            result = self.readbits_16(16) << bits;
        }
        result | self.readbits_16(bits)
    }

    fn readbit(&mut self) -> u32 {
        let result = if self.pos < self.buf.len() {
            self.buf[self.pos] as u32
        } else {
            0
        };
        let result = (result << self.bit) >> 7 & 1;
        let new_acc = self.bit + 1;
        self.pos += (new_acc / 8) as usize;
        self.bit = new_acc % 8;
        result
    }

    fn unreadbits(&mut self, bits: u32) {
        let total = (self.pos as i64 * 8) + self.bit as i64 - bits as i64;
        debug_assert!(total >= 0, "unreadbits underflow");
        self.pos = (total / 8) as usize;
        // rem_euclid keeps the bit offset in 0..8 even if `total` were negative.
        self.bit = total.rem_euclid(8) as u32;
    }
}

fn count_leading_zeros(input: u32) -> u32 {
    if input == 0 { 32 } else { input.leading_zeros() }
}

fn sign_extend_32(val: i32, bits: u32) -> i32 {
    (val << (32 - bits)) >> (32 - bits)
}

fn sign_extend_24(val: i32) -> i32 {
    (val << 8) >> 8
}

fn sign_only(v: i32) -> i32 {
    if v < 0 {
        -1
    } else if v > 0 {
        1
    } else {
        0
    }
}

const RICE_THRESHOLD: u32 = 8;

fn entropy_decode_value(reader: &mut BitReader, read_sample_size: u32, k: u32, rice_kmodifier_mask: u32) -> i32 {
    let mut x: u32 = 0;
    while x <= RICE_THRESHOLD && reader.readbit() != 0 {
        x += 1;
    }
    if x > RICE_THRESHOLD {
        let value = reader.readbits(read_sample_size) & (0xffffffffu32 >> (32 - read_sample_size));
        x = value;
    } else if k != 1 {
        let extra_bits = reader.readbits(k);
        x *= ((1 << k) - 1) & rice_kmodifier_mask;
        if extra_bits > 1 {
            x += extra_bits - 1;
        } else {
            reader.unreadbits(1);
        }
    }
    x as i32
}

/// Rice coding parameters for entropy decoding.
struct RiceParams {
    initial_history: u32,
    k_modifier: u32,
    history_mult: u32,
    k_modifier_mask: u32,
}

/// Per-channel predictor header parsed from a compressed ALAC subframe.
struct PredictorHeader {
    pred_quant: u32,
    ricemod: u32,
    pred_num: usize,
    pred_table: [i16; 32],
}

/// Parse the leading subframe header shared by mono and stereo elements.
/// Updates `output_samples`/`output_size` when an explicit frame size is present
/// and returns `(uncompressed_bytes, is_not_compressed)`.
fn parse_subframe_header(
    reader: &mut BitReader,
    output_samples: &mut usize,
    output_size: &mut usize,
    bytes_per_sample: usize,
) -> (u32, u32) {
    reader.readbits(4);
    reader.readbits(12);
    let has_size = reader.readbits(1);
    let uncompressed_bytes = reader.readbits(2);
    let is_not_compressed = reader.readbits(1);

    if has_size != 0 {
        *output_samples = reader.readbits(32) as usize;
        *output_size = *output_samples * bytes_per_sample;
    }

    (uncompressed_bytes, is_not_compressed)
}

/// Read one channel's predictor header (type/quant/rice-modifier/coefficients).
fn read_predictor_header(reader: &mut BitReader) -> PredictorHeader {
    let _pred_type = reader.readbits(4);
    let pred_quant = reader.readbits(4);
    let ricemod = reader.readbits(3);
    let pred_num = reader.readbits(5) as usize;
    let mut pred_table = [0i16; 32];
    pred_table[..pred_num]
        .iter_mut()
        .for_each(|v| *v = reader.readbits(16) as i16);
    PredictorHeader {
        pred_quant,
        ricemod,
        pred_num,
        pred_table,
    }
}

fn entropy_rice_decode(
    reader: &mut BitReader,
    output: &mut [i32],
    output_size: usize,
    read_sample_size: u32,
    rice: &RiceParams,
) {
    let mut history = rice.initial_history as i32;
    let mut sign_modifier = 0i32;
    let mut i = 0;

    while i < output_size {
        let k = {
            let v = 31i32 - rice.k_modifier as i32 - count_leading_zeros(((history >> 9) + 3) as u32) as i32;
            if v < 0 {
                (v + rice.k_modifier as i32) as u32
            } else {
                rice.k_modifier
            }
        };

        let decoded_value = entropy_decode_value(reader, read_sample_size, k, 0xFFFFFFFF) + sign_modifier;
        let final_value = {
            let v = (decoded_value + 1) / 2;
            if decoded_value & 1 != 0 { -v } else { v }
        };
        output[i] = final_value;
        sign_modifier = 0;

        history += decoded_value * rice.history_mult as i32 - ((history * rice.history_mult as i32) >> 9);
        if decoded_value > 0xFFFF {
            history = 0xFFFF;
        }

        if (history < 128) && (i + 1 < output_size) {
            sign_modifier = 1;
            let k = count_leading_zeros(history as u32) + ((history as u32 + 16) / 64) - 24;
            let block_size = entropy_decode_value(reader, 16, k, rice.k_modifier_mask);
            if block_size > 0 {
                let end = (i + 1 + block_size as usize).min(output_size);
                output[i + 1..end].fill(0);
                i = end - 1;
            }
            if block_size > 0xFFFF {
                sign_modifier = 0;
            }
            history = 0;
        }
        i += 1;
    }
}

fn predictor_decompress_fir_adapt(
    error_buffer: &[i32],
    buffer_out: &mut [i32],
    output_size: usize,
    readsamplesize: u32,
    predictor_coef_table: &mut [i16],
    predictor_coef_num: usize,
    predictor_quantitization: i32,
) {
    if output_size == 0 || error_buffer.is_empty() || buffer_out.is_empty() {
        return;
    }

    buffer_out[0] = error_buffer[0];

    if predictor_coef_num == 0 {
        if output_size <= 1 {
            return;
        }
        buffer_out[1..output_size].copy_from_slice(&error_buffer[1..output_size]);
        return;
    }

    if predictor_coef_num == 0x1f {
        if output_size <= 1 {
            return;
        }
        for i in 0..output_size - 1 {
            buffer_out[i + 1] = sign_extend_32(buffer_out[i].wrapping_add(error_buffer[i + 1]), readsamplesize);
        }
        return;
    }

    // Warm-up samples
    for i in 0..predictor_coef_num {
        let val = sign_extend_32(buffer_out[i].wrapping_add(error_buffer[i + 1]), readsamplesize);
        buffer_out[i + 1] = val;
    }

    // General case — use a sliding window via offset
    if predictor_coef_num > 0 {
        for (off, &error_val) in error_buffer[predictor_coef_num + 1..output_size].iter().enumerate() {
            let mut sum = 0i64;

            for j in 0..predictor_coef_num {
                sum += (buffer_out[off + predictor_coef_num - j] - buffer_out[off]) as i64
                    * predictor_coef_table[j] as i64;
            }

            let mut outval = ((1i64 << (predictor_quantitization - 1)) + sum) >> predictor_quantitization;
            outval += buffer_out[off] as i64 + error_val as i64;
            let outval = sign_extend_32(outval as i32, readsamplesize);
            buffer_out[off + predictor_coef_num + 1] = outval;

            if error_val > 0 {
                let mut pn = predictor_coef_num as i32 - 1;
                let mut ev = error_val;
                while pn >= 0 && ev > 0 {
                    let val = buffer_out[off] - buffer_out[off + predictor_coef_num - pn as usize];
                    let sign = sign_only(val);
                    predictor_coef_table[pn as usize] -= sign as i16;
                    let val = val * sign;
                    ev -= (val >> predictor_quantitization) * (predictor_coef_num as i32 - pn);
                    pn -= 1;
                }
            } else if error_val < 0 {
                let mut pn = predictor_coef_num as i32 - 1;
                let mut ev = error_val;
                while pn >= 0 && ev < 0 {
                    let val = buffer_out[off] - buffer_out[off + predictor_coef_num - pn as usize];
                    let sign = -sign_only(val);
                    predictor_coef_table[pn as usize] -= sign as i16;
                    let val = val * sign;
                    ev -= (val >> predictor_quantitization) * (predictor_coef_num as i32 - pn);
                    pn -= 1;
                }
            }
        }
    }
}

fn deinterlace_16(
    buf_a: &[i32],
    buf_b: &[i32],
    out: &mut [u8],
    num_channels: usize,
    num_samples: usize,
    shift: u8,
    leftweight: u8,
) {
    let _out_i16: &mut [i16] = {
        // Safe reinterpretation: out is aligned and sized for i16
        let _ptr = out.as_mut_ptr() as *mut i16;
        let _len = out.len() / 2;
        // SAFETY: not needed — we write byte-by-byte instead
        &mut []
    };

    for i in 0..num_samples {
        let (left, right) = if leftweight != 0 {
            let mid = buf_a[i];
            let diff = buf_b[i];
            let r = mid - ((diff * leftweight as i32) >> shift);
            (r + diff, r)
        } else {
            (buf_a[i], buf_b[i])
        };
        let li = (i * num_channels) * 2;
        let ri = (i * num_channels + 1) * 2;
        out[li..li + 2].copy_from_slice(&(left as i16).to_le_bytes());
        out[ri..ri + 2].copy_from_slice(&(right as i16).to_le_bytes());
    }
}

/// Parameters for 24-bit stereo deinterlacing.
struct Deinterlace24Params<'a> {
    buf_a: &'a [i32],
    buf_b: &'a [i32],
    uncompressed_bytes: u32,
    uncomp_a: &'a [i32],
    uncomp_b: &'a [i32],
    num_channels: usize,
    num_samples: usize,
    shift: u8,
    leftweight: u8,
}

fn deinterlace_24(p: &Deinterlace24Params, out: &mut [u8]) {
    for i in 0..p.num_samples {
        let (mut left, mut right) = if p.leftweight != 0 {
            let mid = p.buf_a[i];
            let diff = p.buf_b[i];
            let r = mid - ((diff * p.leftweight as i32) >> p.shift);
            (r + diff, r)
        } else {
            (p.buf_a[i], p.buf_b[i])
        };

        if p.uncompressed_bytes > 0 {
            let mask = !(0xFFFFFFFFu32 << (p.uncompressed_bytes * 8)) as i32;
            left = (left << (p.uncompressed_bytes * 8)) | (p.uncomp_a[i] & mask);
            right = (right << (p.uncompressed_bytes * 8)) | (p.uncomp_b[i] & mask);
        }

        let base = i * p.num_channels * 3;
        out[base] = left as u8;
        out[base + 1] = (left >> 8) as u8;
        out[base + 2] = (left >> 16) as u8;
        out[base + 3] = right as u8;
        out[base + 4] = (right >> 8) as u8;
        out[base + 5] = (right >> 16) as u8;
    }
}

/// Apple Lossless Audio Codec decoder. Equivalent to alac_file.
pub(crate) struct AlacDecoder {
    num_channels: i32,
    bytes_per_sample: i32,

    max_samples_per_frame: u32,
    sample_size_config: u8,
    rice_history_mult: u8,
    rice_initial_history: u8,
    rice_k_modifier: u8,
    max_run: u16,
    max_frame_bytes: u32,
    avg_bit_rate: u32,
    sample_rate: u32,

    predicterror_buffer_a: Vec<i32>,
    predicterror_buffer_b: Vec<i32>,
    outputsamples_buffer_a: Vec<i32>,
    outputsamples_buffer_b: Vec<i32>,
    uncompressed_bytes_buffer_a: Vec<i32>,
    uncompressed_bytes_buffer_b: Vec<i32>,
}

impl AlacDecoder {
    /// Create a new ALAC decoder for the given sample size (bits) and channel count.
    pub(crate) fn new(sample_size: i32, num_channels: i32) -> Self {
        Self {
            num_channels,
            bytes_per_sample: (sample_size / 8) * num_channels,
            max_samples_per_frame: 0,
            sample_size_config: 0,
            rice_history_mult: 0,
            rice_initial_history: 0,
            rice_k_modifier: 0,
            max_run: 0,
            max_frame_bytes: 0,
            avg_bit_rate: 0,
            sample_rate: 0,
            predicterror_buffer_a: Vec::new(),
            predicterror_buffer_b: Vec::new(),
            outputsamples_buffer_a: Vec::new(),
            outputsamples_buffer_b: Vec::new(),
            uncompressed_bytes_buffer_a: Vec::new(),
            uncompressed_bytes_buffer_b: Vec::new(),
        }
    }

    /// Initialize the decoder with a 48-byte ALACSpecificConfig block.
    pub(crate) fn set_info(&mut self, config: &[u8]) {
        // The ALACSpecificConfig fields live in config[24..48]; ignore anything
        // shorter rather than panic on out-of-bounds indexing (the RTSP caller
        // always passes a fixed 48-byte block, but this keeps the API safe).
        if config.len() < 48 {
            return;
        }
        let mut p = 24; // skip: size(4) + frma(4) + alac(4) + size(4) + alac(4) + 0(4)
        self.max_samples_per_frame = u32::from_be_bytes([config[p], config[p + 1], config[p + 2], config[p + 3]]);
        p += 4;
        p += 1; // 7a
        self.sample_size_config = config[p];
        p += 1;
        self.rice_history_mult = config[p];
        p += 1;
        self.rice_initial_history = config[p];
        p += 1;
        self.rice_k_modifier = config[p];
        p += 1;
        p += 1; // 7f
        self.max_run = u16::from_be_bytes([config[p], config[p + 1]]);
        p += 2;
        self.max_frame_bytes = u32::from_be_bytes([config[p], config[p + 1], config[p + 2], config[p + 3]]);
        p += 4;
        self.avg_bit_rate = u32::from_be_bytes([config[p], config[p + 1], config[p + 2], config[p + 3]]);
        p += 4;
        self.sample_rate = u32::from_be_bytes([config[p], config[p + 1], config[p + 2], config[p + 3]]);
        self.allocate_buffers();
    }

    /// Allocate internal decode buffers. Called automatically by set_info.
    pub(crate) fn allocate_buffers(&mut self) {
        let n = self.max_samples_per_frame as usize;
        self.predicterror_buffer_a = vec![0i32; n];
        self.predicterror_buffer_b = vec![0i32; n];
        self.outputsamples_buffer_a = vec![0i32; n];
        self.outputsamples_buffer_b = vec![0i32; n];
        self.uncompressed_bytes_buffer_a = vec![0i32; n];
        self.uncompressed_bytes_buffer_b = vec![0i32; n];
    }

    /// Decode one ALAC frame. Returns the number of bytes written to output (little-endian PCM).
    pub(crate) fn decode_frame(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        if self.max_samples_per_frame == 0 || self.bytes_per_sample <= 0 {
            return 0;
        }

        let mut reader = BitReader::new(input);
        let mut output_samples = self.max_samples_per_frame as usize;
        let channels = reader.readbits(3);
        let mut output_size = output_samples * self.bytes_per_sample as usize;

        match channels {
            0 => self.decode_mono(&mut reader, output, &mut output_samples, &mut output_size),
            1 => self.decode_stereo(&mut reader, output, &mut output_samples, &mut output_size),
            _ => {}
        }
        output_size
    }

    /// Decode an ALAC frame and return F32LE interleaved samples.
    // Consumed by the AP2 realtime audio path (and the unit tests). Dead in the
    // default `--lib` build where neither is compiled.
    #[cfg_attr(not(feature = "ap2"), allow(dead_code))]
    pub(crate) fn decode_frame_f32(&mut self, input: &[u8]) -> Option<Vec<f32>> {
        if self.max_samples_per_frame == 0 || self.bytes_per_sample <= 0 {
            return None;
        }

        let max_output_size = self.max_samples_per_frame as usize * self.bytes_per_sample as usize;
        let mut pcm_buf = vec![0u8; max_output_size];
        let len = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.decode_frame(input, &mut pcm_buf)))
            .unwrap_or(0);
        if len == 0 {
            return None;
        }

        match self.sample_size_config {
            16 => Some(
                pcm_buf[..len]
                    .chunks_exact(2)
                    .map(|c| i16::from_le_bytes([c[0], c[1]]) as f32 / 32768.0)
                    .collect(),
            ),
            24 => Some(
                pcm_buf[..len]
                    .chunks_exact(3)
                    .map(|c| {
                        let raw = c[0] as i32 | ((c[1] as i32) << 8) | ((c[2] as i32) << 16);
                        let sample = (raw << 8) >> 8;
                        sample as f32 / 8_388_608.0
                    })
                    .collect(),
            ),
            _ => None,
        }
    }

    /// Rice-decode then FIR-predict one channel into the A (`false`) or B
    /// (`true`) buffers. Shared by the mono (one call) and stereo (two calls) paths.
    fn decode_channel(
        &mut self,
        reader: &mut BitReader,
        channel_b: bool,
        output_samples: usize,
        readsamplesize: u32,
        hdr: &PredictorHeader,
    ) {
        let rice = RiceParams {
            initial_history: self.rice_initial_history as u32,
            k_modifier: self.rice_k_modifier as u32,
            history_mult: hdr.ricemod * self.rice_history_mult as u32 / 4,
            k_modifier_mask: (1 << self.rice_k_modifier) - 1,
        };
        let (prederr, out) = if channel_b {
            (&mut self.predicterror_buffer_b, &mut self.outputsamples_buffer_b)
        } else {
            (&mut self.predicterror_buffer_a, &mut self.outputsamples_buffer_a)
        };
        entropy_rice_decode(reader, prederr, output_samples, readsamplesize, &rice);
        let mut pred_table = hdr.pred_table;
        predictor_decompress_fir_adapt(
            &prederr.clone(),
            out,
            output_samples,
            readsamplesize,
            &mut pred_table,
            hdr.pred_num,
            hdr.pred_quant as i32,
        );
    }

    fn decode_mono(
        &mut self,
        reader: &mut BitReader,
        output: &mut [u8],
        output_samples: &mut usize,
        output_size: &mut usize,
    ) {
        let (uncompressed_bytes, is_not_compressed) =
            parse_subframe_header(reader, output_samples, output_size, self.bytes_per_sample as usize);
        if *output_samples == 0 {
            *output_size = 0;
            return;
        }

        let readsamplesize = self.sample_size_config as u32 - uncompressed_bytes * 8;

        if is_not_compressed == 0 {
            // Unused interlacing shift/leftweight (always present in the stream).
            reader.readbits(8);
            reader.readbits(8);
            let hdr = read_predictor_header(reader);

            if uncompressed_bytes > 0 {
                self.uncompressed_bytes_buffer_a[..*output_samples]
                    .iter_mut()
                    .for_each(|v| *v = reader.readbits(uncompressed_bytes * 8) as i32);
            }

            self.decode_channel(reader, false, *output_samples, readsamplesize, &hdr);
        } else {
            if self.sample_size_config <= 16 {
                for i in 0..*output_samples {
                    let v = reader.readbits(self.sample_size_config as u32);
                    self.outputsamples_buffer_a[i] = sign_extend_32(v as i32, self.sample_size_config as u32);
                }
            } else {
                for i in 0..*output_samples {
                    let mut v = reader.readbits(16) as i32;
                    v <<= self.sample_size_config as u32 - 16;
                    v |= reader.readbits(self.sample_size_config as u32 - 16) as i32;
                    self.outputsamples_buffer_a[i] = sign_extend_24(v);
                }
            }
        }

        // Output
        match self.sample_size_config {
            16 => {
                for i in 0..*output_samples {
                    let s = (self.outputsamples_buffer_a[i] as i16).to_le_bytes();
                    let off = i * self.num_channels as usize * 2;
                    output[off..off + 2].copy_from_slice(&s);
                }
            }
            24 => {
                for i in 0..*output_samples {
                    let mut sample = self.outputsamples_buffer_a[i];
                    if uncompressed_bytes > 0 && is_not_compressed == 0 {
                        let mask = !(0xFFFFFFFFu32 << (uncompressed_bytes * 8)) as i32;
                        sample = (sample << (uncompressed_bytes * 8)) | (self.uncompressed_bytes_buffer_a[i] & mask);
                    }
                    let off = i * self.num_channels as usize * 3;
                    output[off] = sample as u8;
                    output[off + 1] = (sample >> 8) as u8;
                    output[off + 2] = (sample >> 16) as u8;
                }
            }
            _ => {}
        }
    }

    fn decode_stereo(
        &mut self,
        reader: &mut BitReader,
        output: &mut [u8],
        output_samples: &mut usize,
        output_size: &mut usize,
    ) {
        let (uncompressed_bytes, is_not_compressed) =
            parse_subframe_header(reader, output_samples, output_size, self.bytes_per_sample as usize);
        if *output_samples == 0 {
            *output_size = 0;
            return;
        }

        let readsamplesize = self.sample_size_config as u32 - uncompressed_bytes * 8 + 1;
        let mut interlacing_shift = 0u8;
        let mut interlacing_leftweight = 0u8;

        if is_not_compressed == 0 {
            interlacing_shift = reader.readbits(8) as u8;
            interlacing_leftweight = reader.readbits(8) as u8;

            // Both predictor headers are read before either channel is decoded.
            let hdr_a = read_predictor_header(reader);
            let hdr_b = read_predictor_header(reader);

            if uncompressed_bytes > 0 {
                for i in 0..*output_samples {
                    self.uncompressed_bytes_buffer_a[i] = reader.readbits(uncompressed_bytes * 8) as i32;
                    self.uncompressed_bytes_buffer_b[i] = reader.readbits(uncompressed_bytes * 8) as i32;
                }
            }

            self.decode_channel(reader, false, *output_samples, readsamplesize, &hdr_a);
            self.decode_channel(reader, true, *output_samples, readsamplesize, &hdr_b);
        } else {
            if self.sample_size_config <= 16 {
                for i in 0..*output_samples {
                    let a = reader.readbits(self.sample_size_config as u32);
                    let b = reader.readbits(self.sample_size_config as u32);
                    self.outputsamples_buffer_a[i] = sign_extend_32(a as i32, self.sample_size_config as u32);
                    self.outputsamples_buffer_b[i] = sign_extend_32(b as i32, self.sample_size_config as u32);
                }
            } else {
                for i in 0..*output_samples {
                    let mut a = reader.readbits(16) as i32;
                    a <<= self.sample_size_config as u32 - 16;
                    a |= reader.readbits(self.sample_size_config as u32 - 16) as i32;
                    self.outputsamples_buffer_a[i] = sign_extend_24(a);

                    let mut b = reader.readbits(16) as i32;
                    b <<= self.sample_size_config as u32 - 16;
                    b |= reader.readbits(self.sample_size_config as u32 - 16) as i32;
                    self.outputsamples_buffer_b[i] = sign_extend_24(b);
                }
            }
        }

        // Deinterlace and output
        match self.sample_size_config {
            16 => deinterlace_16(
                &self.outputsamples_buffer_a,
                &self.outputsamples_buffer_b,
                output,
                self.num_channels as usize,
                *output_samples,
                interlacing_shift,
                interlacing_leftweight,
            ),
            24 => deinterlace_24(
                &Deinterlace24Params {
                    buf_a: &self.outputsamples_buffer_a,
                    buf_b: &self.outputsamples_buffer_b,
                    uncompressed_bytes,
                    uncomp_a: &self.uncompressed_bytes_buffer_a,
                    uncomp_b: &self.uncompressed_bytes_buffer_b,
                    num_channels: self.num_channels as usize,
                    num_samples: *output_samples,
                    shift: interlacing_shift,
                    leftweight: interlacing_leftweight,
                },
                output,
            ),
            _ => {}
        }
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    #[test]
    fn alac_init_and_set_info() {
        let mut alac = AlacDecoder::new(16, 2);
        let mut info = [0u8; 48];
        // frame_length = 352
        info[24..28].copy_from_slice(&352u32.to_be_bytes());
        info[29] = 16; // bit depth
        info[30] = 40; // pb
        info[31] = 10; // mb
        info[32] = 14; // kb
        info[33] = 2; // channels
        info[34..36].copy_from_slice(&255u16.to_be_bytes());
        info[44..48].copy_from_slice(&44100u32.to_be_bytes());
        alac.set_info(&info);
        // Should not panic — buffers allocated
    }

    /// Minimal MSB-first bit writer for building ALAC subframes in tests.
    struct BitWriter {
        bytes: Vec<u8>,
        nbits: usize,
    }
    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                nbits: 0,
            }
        }
        fn put(&mut self, val: u32, bits: u32) {
            for i in (0..bits).rev() {
                if self.nbits.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                if (val >> i) & 1 == 1 {
                    let last = self.bytes.len() - 1;
                    self.bytes[last] |= 1 << (7 - (self.nbits % 8));
                }
                self.nbits += 1;
            }
        }
    }

    /// ALACSpecificConfig with 16-bit samples and the given max frame length.
    fn config_16(max_frames: u32) -> [u8; 48] {
        let mut c = [0u8; 48];
        c[24..28].copy_from_slice(&max_frames.to_be_bytes());
        c[29] = 16; // sample_size_config
        c
    }

    fn config_24(max_frames: u32) -> [u8; 48] {
        let mut c = config_16(max_frames);
        c[29] = 24; // sample_size_config
        c
    }

    // An uncompressed ALAC subframe just sign-extends and packs the raw samples,
    // so the decoded PCM must equal the input samples — a true correctness check
    // of the shared subframe-header parse + dispatch + output paths.

    #[test]
    fn decode_uncompressed_mono_roundtrips_samples() {
        let mut dec = AlacDecoder::new(16, 1);
        dec.set_info(&config_16(4));

        let samples: [u16; 4] = [0x0102, 0x7FFF, 0x8000, 0xFFFF];
        let mut w = BitWriter::new();
        w.put(0, 3); // channels = 0 (mono)
        w.put(0, 4);
        w.put(0, 12);
        w.put(0, 1); // has_size = 0 → output_samples = max_frames
        w.put(0, 2); // uncompressed_bytes = 0
        w.put(1, 1); // is_not_compressed = 1
        for &s in &samples {
            w.put(s as u32, 16);
        }

        let mut out = [0u8; 64];
        let n = dec.decode_frame(&w.bytes, &mut out);
        assert_eq!(n, 8);
        let expected: Vec<u8> = samples.iter().flat_map(|&s| (s as i16).to_le_bytes()).collect();
        assert_eq!(&out[..8], &expected[..]);
    }

    #[test]
    fn decode_uncompressed_stereo_roundtrips_samples() {
        let mut dec = AlacDecoder::new(16, 2);
        dec.set_info(&config_16(4));

        let l: [u16; 4] = [0x0102, 0x7FFF, 0x8000, 0xFFFF];
        let r: [u16; 4] = [0x1111, 0x2222, 0x3333, 0x4444];
        let mut w = BitWriter::new();
        w.put(1, 3); // channels = 1 (stereo)
        w.put(0, 4);
        w.put(0, 12);
        w.put(0, 1); // has_size = 0
        w.put(0, 2); // uncompressed_bytes = 0
        w.put(1, 1); // is_not_compressed = 1
        for i in 0..4 {
            w.put(l[i] as u32, 16);
            w.put(r[i] as u32, 16);
        }

        let mut out = [0u8; 64];
        let n = dec.decode_frame(&w.bytes, &mut out);
        assert_eq!(n, 16);
        let mut expected = Vec::new();
        for i in 0..4 {
            expected.extend_from_slice(&(l[i] as i16).to_le_bytes());
            expected.extend_from_slice(&(r[i] as i16).to_le_bytes());
        }
        assert_eq!(&out[..16], &expected[..]);
    }

    #[test]
    fn decode_uncompressed_stereo_24bit_to_f32() {
        let mut dec = AlacDecoder::new(24, 2);
        dec.set_info(&config_24(2));

        let samples: [i32; 4] = [0, 0x7f_ffff, -0x80_0000, -1];
        let mut w = BitWriter::new();
        w.put(1, 3); // channels = 1 (stereo)
        w.put(0, 4);
        w.put(0, 12);
        w.put(0, 1); // has_size = 0
        w.put(0, 2); // uncompressed_bytes = 0
        w.put(1, 1); // is_not_compressed = 1
        for &sample in &samples {
            w.put((sample as u32) & 0x00ff_ffff, 24);
        }

        let decoded = dec.decode_frame_f32(&w.bytes).expect("24-bit ALAC frame should decode");
        assert_eq!(decoded.len(), samples.len());
        for (actual, expected) in decoded.iter().zip(samples) {
            assert!((*actual - expected as f32 / 8_388_608.0).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn decoder_without_info_returns_no_samples() {
        let mut dec = AlacDecoder::new(16, 2);
        let mut out = [0u8; 64];

        assert_eq!(dec.decode_frame(&[0u8; 8], &mut out), 0);
        assert!(dec.decode_frame_f32(&[0u8; 8]).is_none());
    }

    #[test]
    fn explicit_zero_sample_frame_returns_no_samples() {
        let mut dec = AlacDecoder::new(16, 2);
        dec.set_info(&config_16(4));

        let mut w = BitWriter::new();
        w.put(1, 3); // channels = 1 (stereo)
        w.put(0, 4);
        w.put(0, 12);
        w.put(1, 1); // has_size = 1
        w.put(0, 2); // uncompressed_bytes = 0
        w.put(1, 1); // is_not_compressed = 1
        w.put(0, 32); // explicit output_samples = 0

        let mut out = [0u8; 64];
        assert_eq!(dec.decode_frame(&w.bytes, &mut out), 0);
    }

    // --- Golden vectors: real Apple-encoded (afconvert) *compressed* ALAC ---
    //
    // The uncompressed tests above exercise the verbatim path. These vectors are
    // produced by macOS `afconvert` (Apple's reference ALAC encoder) and contain
    // genuinely compressed frames (rice + FIR prediction). ALAC is lossless, so
    // the decoder must reproduce the encoder's input PCM bit-for-bit — the
    // committed PCM *is* the oracle. Regenerate with tests/data/alac/gen_alac.py.
    //
    // afconvert pads the final packet to a full frame (mRemainderFrames), so the
    // decoded stream is >= the valid PCM; we trim to the valid length to compare.

    struct Golden {
        sample_rate: u32,
        channels: u8,
        cookie: Vec<u8>,
        frames: Vec<Vec<u8>>,
        pcm: Vec<u8>,
    }

    fn rd_u32(d: &[u8], p: &mut usize) -> u32 {
        let v = u32::from_le_bytes(d[*p..*p + 4].try_into().unwrap());
        *p += 4;
        v
    }

    fn parse_golden(d: &[u8]) -> Golden {
        assert_eq!(&d[..8], b"ALACGV01", "bad fixture magic");
        let mut p = 8;
        let sample_rate = rd_u32(d, &mut p);
        let channels = d[p];
        p += 4; // channels(1) + bit_depth(1) + reserved(2)
        let clen = rd_u32(d, &mut p) as usize;
        let cookie = d[p..p + clen].to_vec();
        p += clen;
        let nframes = rd_u32(d, &mut p) as usize;
        let mut frames = Vec::with_capacity(nframes);
        for _ in 0..nframes {
            let flen = rd_u32(d, &mut p) as usize;
            frames.push(d[p..p + flen].to_vec());
            p += flen;
        }
        let plen = rd_u32(d, &mut p) as usize;
        let pcm = d[p..p + plen].to_vec();
        p += plen;
        assert_eq!(p, d.len(), "trailing bytes in fixture");
        Golden {
            sample_rate,
            channels,
            cookie,
            frames,
            pcm,
        }
    }

    fn check_golden(raw: &[u8]) {
        let g = parse_golden(raw);
        assert_eq!(g.cookie.len(), 48, "cookie must be the 48-byte set_info block");

        let mut dec = AlacDecoder::new(16, g.channels as i32);
        dec.set_info(&g.cookie);
        assert_eq!(dec.sample_rate, g.sample_rate, "set_info parsed sample rate");
        assert!(dec.max_samples_per_frame > 0, "set_info parsed frame length");

        let frame_bytes = dec.max_samples_per_frame as usize * dec.bytes_per_sample as usize;
        let mut out = vec![0u8; frame_bytes];
        let mut got = Vec::with_capacity(g.pcm.len());
        let mut compressed = 0;
        for frame in &g.frames {
            let n = dec.decode_frame(frame, &mut out);
            assert!(n > 0, "frame decoded to zero bytes");
            got.extend_from_slice(&out[..n]);
            // A verbatim full frame would be ~frame_bytes; compressed frames are
            // materially smaller (the whole point of these vectors).
            if frame.len() < frame_bytes {
                compressed += 1;
            }
        }
        assert!(
            got.len() >= g.pcm.len(),
            "decoded {} bytes, fewer than the {} valid PCM bytes",
            got.len(),
            g.pcm.len()
        );
        got.truncate(g.pcm.len()); // drop encoder padding in the final packet
        assert!(
            got == g.pcm,
            "decoded PCM does not match the Apple-encoded golden vector"
        );
        assert!(
            compressed > 0,
            "no compressed frames present — vector would not exercise rice/FIR"
        );
    }

    #[test]
    fn golden_stereo_compressed_matches_apple_encoder() {
        check_golden(include_bytes!("../../tests/data/alac/stereo.alac"));
    }

    #[test]
    fn golden_mono_compressed_matches_apple_encoder() {
        check_golden(include_bytes!("../../tests/data/alac/mono.alac"));
    }
}
