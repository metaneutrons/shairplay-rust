//! Apple Lossless Audio Codec (ALAC) decoder.

/// ALAC decoder configuration, parsed from the fmtp SDP attribute.
#[derive(Debug, Clone)]
pub struct AlacConfig {
    /// Samples per frame.
    pub frame_length: u32,
    /// ALAC version.
    pub compatible_version: u8,
    /// Bits per sample (16 or 24).
    pub bit_depth: u8,
    /// Rice parameter history mult.
    pub pb: u8,
    /// Rice initial history.
    pub mb: u8,
    /// Rice limit.
    pub kb: u8,
    /// Number of audio channels.
    pub num_channels: u8,
    /// Maximum run length.
    pub max_run: u16,
    /// Maximum encoded frame size.
    pub max_frame_bytes: u32,
    /// Average bit rate.
    pub avg_bit_rate: u32,
    /// Sample rate in Hz.
    pub sample_rate: u32,
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
        let result = if self.pos < self.buf.len() { self.buf[self.pos] as u32 } else { 0 };
        let result = (result << self.bit) >> 7 & 1;
        let new_acc = self.bit + 1;
        self.pos += (new_acc / 8) as usize;
        self.bit = new_acc % 8;
        result
    }

    fn unreadbits(&mut self, bits: u32) {
        let total = (self.pos as i64 * 8) + self.bit as i64 - bits as i64;
        self.pos = (total / 8) as usize;
        self.bit = (total % 8).unsigned_abs() as u32;
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
    if v < 0 { -1 } else if v > 0 { 1 } else { 0 }
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
            if v < 0 { (v + rice.k_modifier as i32) as u32 } else { rice.k_modifier }
        };

        let decoded_value = entropy_decode_value(reader, read_sample_size, k, 0xFFFFFFFF) + sign_modifier;
        let final_value = {
            let v = (decoded_value + 1) / 2;
            if decoded_value & 1 != 0 { -v } else { v }
        };
        output[i] = final_value;
        sign_modifier = 0;

        history += decoded_value * rice.history_mult as i32 - ((history * rice.history_mult as i32) >> 9);
        if decoded_value > 0xFFFF { history = 0xFFFF; }

        if (history < 128) && (i + 1 < output_size) {
            sign_modifier = 1;
            let k = count_leading_zeros(history as u32) + ((history as u32 + 16) / 64) - 24;
            let block_size = entropy_decode_value(reader, 16, k, rice.k_modifier_mask);
            if block_size > 0 {
                let end = (i + 1 + block_size as usize).min(output_size);
                output[i + 1..end].fill(0);
                i = end - 1;
            }
            if block_size > 0xFFFF { sign_modifier = 0; }
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
    buffer_out[0] = error_buffer[0];

    if predictor_coef_num == 0 {
        if output_size <= 1 { return; }
        buffer_out[1..output_size].copy_from_slice(&error_buffer[1..output_size]);
        return;
    }

    if predictor_coef_num == 0x1f {
        if output_size <= 1 { return; }
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

fn deinterlace_16(buf_a: &[i32], buf_b: &[i32], out: &mut [u8], num_channels: usize, num_samples: usize, shift: u8, leftweight: u8) {
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
pub struct AlacDecoder {
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
    pub fn new(sample_size: i32, num_channels: i32) -> Self {
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
    pub fn set_info(&mut self, config: &[u8]) {
        let mut p = 24; // skip: size(4) + frma(4) + alac(4) + size(4) + alac(4) + 0(4)
        self.max_samples_per_frame = u32::from_be_bytes([config[p], config[p+1], config[p+2], config[p+3]]);
        p += 4;
        p += 1; // 7a
        self.sample_size_config = config[p]; p += 1;
        self.rice_history_mult = config[p]; p += 1;
        self.rice_initial_history = config[p]; p += 1;
        self.rice_k_modifier = config[p]; p += 1;
        p += 1; // 7f
        self.max_run = u16::from_be_bytes([config[p], config[p+1]]); p += 2;
        self.max_frame_bytes = u32::from_be_bytes([config[p], config[p+1], config[p+2], config[p+3]]); p += 4;
        self.avg_bit_rate = u32::from_be_bytes([config[p], config[p+1], config[p+2], config[p+3]]); p += 4;
        self.sample_rate = u32::from_be_bytes([config[p], config[p+1], config[p+2], config[p+3]]);
        self.allocate_buffers();
    }

    /// Allocate internal decode buffers. Called automatically by set_info.
    pub fn allocate_buffers(&mut self) {
        let n = self.max_samples_per_frame as usize;
        self.predicterror_buffer_a = vec![0i32; n];
        self.predicterror_buffer_b = vec![0i32; n];
        self.outputsamples_buffer_a = vec![0i32; n];
        self.outputsamples_buffer_b = vec![0i32; n];
        self.uncompressed_bytes_buffer_a = vec![0i32; n];
        self.uncompressed_bytes_buffer_b = vec![0i32; n];
    }

    /// Decode one ALAC frame. Returns the number of bytes written to output (S16LE).
    pub fn decode_frame(&mut self, input: &[u8], output: &mut [u8]) -> usize {
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
    pub fn decode_frame_f32(&mut self, input: &[u8]) -> Option<Vec<f32>> {
        let mut s16_buf = vec![0u8; 16384];
        let len = self.decode_frame(input, &mut s16_buf);
        if len == 0 { return None; }
        Some(s16_buf[..len].chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]) as f32 / 32768.0)
            .collect())
    }

    fn decode_mono(&mut self, reader: &mut BitReader, output: &mut [u8], output_samples: &mut usize, output_size: &mut usize) {
        reader.readbits(4);
        reader.readbits(12);
        let has_size = reader.readbits(1);
        let uncompressed_bytes = reader.readbits(2);
        let is_not_compressed = reader.readbits(1);

        if has_size != 0 {
            *output_samples = reader.readbits(32) as usize;
            *output_size = *output_samples * self.bytes_per_sample as usize;
        }

        let readsamplesize = self.sample_size_config as u32 - uncompressed_bytes * 8;

        if is_not_compressed == 0 {
            let mut predictor_coef_table = [0i16; 32];
            reader.readbits(8);
            reader.readbits(8);
            let _prediction_type = reader.readbits(4);
            let prediction_quantitization = reader.readbits(4);
            let ricemodifier = reader.readbits(3);
            let predictor_coef_num = reader.readbits(5) as usize;

            predictor_coef_table[..predictor_coef_num].iter_mut().for_each(|v| *v = reader.readbits(16) as i16);

            if uncompressed_bytes > 0 {
                self.uncompressed_bytes_buffer_a[..*output_samples].iter_mut().for_each(|v| *v = reader.readbits(uncompressed_bytes * 8) as i32);
            }

            entropy_rice_decode(
                reader, &mut self.predicterror_buffer_a, *output_samples,
                readsamplesize, &RiceParams {
                    initial_history: self.rice_initial_history as u32,
                    k_modifier: self.rice_k_modifier as u32,
                    history_mult: ricemodifier * self.rice_history_mult as u32 / 4,
                    k_modifier_mask: (1 << self.rice_k_modifier) - 1,
                },
            );

            predictor_decompress_fir_adapt(
                &self.predicterror_buffer_a.clone(), &mut self.outputsamples_buffer_a,
                *output_samples, readsamplesize, &mut predictor_coef_table,
                predictor_coef_num, prediction_quantitization as i32,
            );
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

    fn decode_stereo(&mut self, reader: &mut BitReader, output: &mut [u8], output_samples: &mut usize, output_size: &mut usize) {
        reader.readbits(4);
        reader.readbits(12);
        let has_size = reader.readbits(1);
        let uncompressed_bytes = reader.readbits(2);
        let is_not_compressed = reader.readbits(1);

        if has_size != 0 {
            *output_samples = reader.readbits(32) as usize;
            *output_size = *output_samples * self.bytes_per_sample as usize;
        }

        let readsamplesize = self.sample_size_config as u32 - uncompressed_bytes * 8 + 1;
        let mut interlacing_shift = 0u8;
        let mut interlacing_leftweight = 0u8;

        if is_not_compressed == 0 {
            interlacing_shift = reader.readbits(8) as u8;
            interlacing_leftweight = reader.readbits(8) as u8;

            // Channel A
            let _pred_type_a = reader.readbits(4);
            let pred_quant_a = reader.readbits(4);
            let ricemod_a = reader.readbits(3);
            let pred_num_a = reader.readbits(5) as usize;
            let mut pred_table_a = [0i16; 32];
            pred_table_a[..pred_num_a].iter_mut().for_each(|v| *v = reader.readbits(16) as i16);

            // Channel B
            let _pred_type_b = reader.readbits(4);
            let pred_quant_b = reader.readbits(4);
            let ricemod_b = reader.readbits(3);
            let pred_num_b = reader.readbits(5) as usize;
            let mut pred_table_b = [0i16; 32];
            pred_table_b[..pred_num_b].iter_mut().for_each(|v| *v = reader.readbits(16) as i16);

            if uncompressed_bytes > 0 {
                for i in 0..*output_samples {
                    self.uncompressed_bytes_buffer_a[i] = reader.readbits(uncompressed_bytes * 8) as i32;
                    self.uncompressed_bytes_buffer_b[i] = reader.readbits(uncompressed_bytes * 8) as i32;
                }
            }

            // Decode channel A
            entropy_rice_decode(
                reader, &mut self.predicterror_buffer_a, *output_samples,
                readsamplesize, &RiceParams {
                    initial_history: self.rice_initial_history as u32,
                    k_modifier: self.rice_k_modifier as u32,
                    history_mult: ricemod_a * self.rice_history_mult as u32 / 4,
                    k_modifier_mask: (1 << self.rice_k_modifier) - 1,
                },
            );
            predictor_decompress_fir_adapt(
                &self.predicterror_buffer_a.clone(), &mut self.outputsamples_buffer_a,
                *output_samples, readsamplesize, &mut pred_table_a, pred_num_a, pred_quant_a as i32,
            );

            // Decode channel B
            entropy_rice_decode(
                reader, &mut self.predicterror_buffer_b, *output_samples,
                readsamplesize, &RiceParams {
                    initial_history: self.rice_initial_history as u32,
                    k_modifier: self.rice_k_modifier as u32,
                    history_mult: ricemod_b * self.rice_history_mult as u32 / 4,
                    k_modifier_mask: (1 << self.rice_k_modifier) - 1,
                },
            );
            predictor_decompress_fir_adapt(
                &self.predicterror_buffer_b.clone(), &mut self.outputsamples_buffer_b,
                *output_samples, readsamplesize, &mut pred_table_b, pred_num_b, pred_quant_b as i32,
            );
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
                &self.outputsamples_buffer_a, &self.outputsamples_buffer_b,
                output, self.num_channels as usize, *output_samples,
                interlacing_shift, interlacing_leftweight,
            ),
            24 => deinterlace_24(&Deinterlace24Params {
                buf_a: &self.outputsamples_buffer_a,
                buf_b: &self.outputsamples_buffer_b,
                uncompressed_bytes,
                uncomp_a: &self.uncompressed_bytes_buffer_a,
                uncomp_b: &self.uncompressed_bytes_buffer_b,
                num_channels: self.num_channels as usize,
                num_samples: *output_samples,
                shift: interlacing_shift,
                leftweight: interlacing_leftweight,
            }, output),
            _ => {}
        }
    }
}
