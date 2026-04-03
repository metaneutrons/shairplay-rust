//! Sample rate conversion for AirPlay 2 audio (44100↔48000 Hz).

use rubato::{SincFixedIn, SincInterpolationParameters, SincInterpolationType, WindowFunction, Resampler};

/// Resample interleaved S16LE stereo audio from `from_rate` to `to_rate`.
/// Returns resampled S16LE stereo bytes.
pub fn resample_s16le_stereo(input: &[u8], from_rate: u32, to_rate: u32) -> Vec<u8> {
    if from_rate == to_rate || input.len() < 4 {
        return input.to_vec();
    }

    let num_samples = input.len() / 2;
    let num_frames = num_samples / 2; // stereo

    // Deinterleave to f64 channels
    let mut left = Vec::with_capacity(num_frames);
    let mut right = Vec::with_capacity(num_frames);
    for i in 0..num_frames {
        let l = i16::from_le_bytes([input[i * 4], input[i * 4 + 1]]) as f64 / 32768.0;
        let r = i16::from_le_bytes([input[i * 4 + 2], input[i * 4 + 3]]) as f64 / 32768.0;
        left.push(l);
        right.push(r);
    }

    let params = SincInterpolationParameters {
        sinc_len: 64,
        f_cutoff: 0.95,
        interpolation: SincInterpolationType::Linear,
        oversampling_factor: 128,
        window: WindowFunction::BlackmanHarris2,
    };

    let ratio = to_rate as f64 / from_rate as f64;
    let mut resampler = SincFixedIn::<f64>::new(ratio, 1.0, params, num_frames, 2)
        .expect("resampler creation failed");

    let waves_in = vec![left, right];
    let waves_out = resampler.process(&waves_in, None).expect("resample failed");

    // Interleave back to S16LE
    let out_frames = waves_out[0].len();
    let mut out = Vec::with_capacity(out_frames * 4);
    for i in 0..out_frames {
        let l = (waves_out[0][i] * 32768.0).clamp(-32768.0, 32767.0) as i16;
        let r = (waves_out[1][i] * 32768.0).clamp(-32768.0, 32767.0) as i16;
        out.extend_from_slice(&l.to_le_bytes());
        out.extend_from_slice(&r.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_same_rate() {
        let input = vec![0u8; 100];
        let output = resample_s16le_stereo(&input, 44100, 44100);
        assert_eq!(output, input);
    }

    #[test]
    fn resample_44100_to_48000_correct_length() {
        // 4410 frames of stereo S16LE = 4410 * 4 bytes
        let num_frames = 4410;
        let input = vec![0u8; num_frames * 4];
        let output = resample_s16le_stereo(&input, 44100, 48000);
        let out_frames = output.len() / 4;
        // Expected: 4410 * 48000/44100 ≈ 4800 (rubato may produce slightly fewer due to sinc filter)
        assert!((out_frames as i32 - 4800).abs() < 50, "got {out_frames} frames");
    }

    #[test]
    fn sine_wave_roundtrip() {
        // Generate 440Hz sine at 44100Hz, resample to 48000, back to 44100
        let num_frames = 4410; // 100ms
        let mut input = Vec::with_capacity(num_frames * 4);
        for i in 0..num_frames {
            let t = i as f64 / 44100.0;
            let sample = (2.0 * std::f64::consts::PI * 440.0 * t).sin();
            let s = (sample * 30000.0) as i16;
            input.extend_from_slice(&s.to_le_bytes());
            input.extend_from_slice(&s.to_le_bytes()); // mono→stereo
        }

        let up = resample_s16le_stereo(&input, 44100, 48000);
        let back = resample_s16le_stereo(&up, 48000, 44100);

        // Verify roundtrip preserves approximate frame count
        let back_frames = back.len() / 4;
        assert!((back_frames as i32 - num_frames as i32).abs() < 100,
            "roundtrip frames: {back_frames} vs {num_frames}");

        // Verify signal isn't destroyed: check some samples aren't all zero
        let nonzero = (0..back_frames.min(num_frames)).filter(|&i| {
            let s = i16::from_le_bytes([back[i*4], back[i*4+1]]);
            s.abs() > 100
        }).count();
        assert!(nonzero > num_frames / 4, "signal destroyed: only {nonzero} nonzero samples");
    }
}

/// Persistent F32 resampler for streaming audio.
pub struct StreamResampler {
    resampler: rubato::SincFixedIn<f32>,
    channels: usize,
    from_rate: u32,
    to_rate: u32,
}

impl StreamResampler {
    pub fn new(from_rate: u32, to_rate: u32, channels: usize) -> Option<Self> {
        if from_rate == to_rate { return None; }
        let params = rubato::SincInterpolationParameters {
            sinc_len: 64,
            f_cutoff: 0.95,
            interpolation: rubato::SincInterpolationType::Linear,
            oversampling_factor: 128,
            window: rubato::WindowFunction::BlackmanHarris2,
        };
        let ratio = to_rate as f64 / from_rate as f64;
        // Use a reasonable chunk size
        let resampler = rubato::SincFixedIn::<f32>::new(ratio, 1.0, params, 1024, channels).ok()?;
        Some(Self { resampler, channels, from_rate, to_rate })
    }

    /// Resample interleaved F32 audio. Returns resampled interleaved F32.
    pub fn process(&mut self, interleaved: &[f32]) -> Vec<f32> {
        use rubato::Resampler;
        let frames = interleaved.len() / self.channels;
        if frames == 0 { return Vec::new(); }

        // Deinterleave
        let mut channels: Vec<Vec<f32>> = (0..self.channels).map(|_| Vec::with_capacity(frames)).collect();
        for frame in interleaved.chunks_exact(self.channels) {
            for (ch, &sample) in frame.iter().enumerate() {
                channels[ch].push(sample);
            }
        }

        // Resample
        let out = match self.resampler.process(&channels, None) {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };

        // Reinterleave
        let out_frames = out[0].len();
        let mut result = Vec::with_capacity(out_frames * self.channels);
        for i in 0..out_frames {
            for ch in &out {
                result.push(ch[i]);
            }
        }
        result
    }
}

/// Mix down multi-channel F32 audio to fewer channels.
/// Standard ITU-R BS.775 downmix coefficients.
pub fn mixdown(input: &[f32], in_channels: usize, out_channels: usize) -> Vec<f32> {
    if in_channels == out_channels { return input.to_vec(); }
    if out_channels != 2 { return input.to_vec(); } // only stereo mixdown supported

    let frames = input.len() / in_channels;
    let mut output = Vec::with_capacity(frames * 2);
    let k: f32 = 0.707; // -3dB

    for frame in input.chunks_exact(in_channels) {
        let (l, r) = match in_channels {
            6 => {
                // 5.1: FL FR FC LFE RL RR
                let fl = frame[0]; let fr = frame[1]; let fc = frame[2];
                let _lfe = frame[3]; let rl = frame[4]; let rr = frame[5];
                (fl + k * fc + k * rl, fr + k * fc + k * rr)
            }
            8 => {
                // 7.1: FL FR FC LFE SL SR RL RR
                let fl = frame[0]; let fr = frame[1]; let fc = frame[2];
                let _lfe = frame[3]; let sl = frame[4]; let sr = frame[5];
                let rl = frame[6]; let rr = frame[7];
                (fl + k * fc + k * sl + k * rl, fr + k * fc + k * sr + k * rr)
            }
            _ => (frame[0], frame.get(1).copied().unwrap_or(frame[0])),
        };
        output.push(l.clamp(-1.0, 1.0));
        output.push(r.clamp(-1.0, 1.0));
    }
    output
}
