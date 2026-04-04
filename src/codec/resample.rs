//! Sample rate conversion and channel mixdown for AirPlay audio.

/// Persistent F32 resampler for streaming audio.
pub struct StreamResampler {
    resampler: rubato::SincFixedIn<f32>,
    channels: usize,
}

impl StreamResampler {
    /// Create a new resampler. Returns `None` if rates are equal.
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
        let resampler = rubato::SincFixedIn::<f32>::new(ratio, 1.0, params, 1024, channels).ok()?;
        Some(Self { resampler, channels })
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
/// Uses ITU-R BS.775 downmix coefficients for 5.1 and 7.1.
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
                let rl = frame[4]; let rr = frame[5];
                (fl + k * fc + k * rl, fr + k * fc + k * rr)
            }
            8 => {
                // 7.1: FL FR FC LFE SL SR RL RR
                let fl = frame[0]; let fr = frame[1]; let fc = frame[2];
                let sl = frame[4]; let sr = frame[5];
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
