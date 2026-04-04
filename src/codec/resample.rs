//! Sample rate conversion and channel mixdown for AirPlay audio.

use rubato::{Async, FixedAsync, Resampler, SincInterpolationParameters, SincInterpolationType, WindowFunction};
use rubato::audioadapter_buffers::direct::SequentialSliceOfVecs;

/// Persistent F32 resampler for streaming audio.
/// Buffers input internally and processes in fixed chunks.
pub struct StreamResampler {
    resampler: Async<f32>,
    channels: usize,
    chunk_size: usize,
    /// Accumulated input samples (interleaved).
    pending: Vec<f32>,
    /// Whether the initial delay has been flushed.
    warmed_up: bool,
}

impl StreamResampler {
    /// Create a new resampler. Returns `None` if rates are equal.
    pub fn new(from_rate: u32, to_rate: u32, channels: usize) -> Option<Self> {
        if from_rate == to_rate { return None; }
        let params = SincInterpolationParameters {
            sinc_len: 64,
            f_cutoff: 0.95,
            interpolation: SincInterpolationType::Linear,
            oversampling_factor: 128,
            window: WindowFunction::BlackmanHarris2,
        };
        let ratio = to_rate as f64 / from_rate as f64;
        let chunk_size = 128; // small for low latency
        let resampler = Async::<f32>::new_sinc(
            ratio, 1.0, &params, chunk_size, channels, FixedAsync::Input,
        ).ok()?;
        Some(Self { resampler, channels, chunk_size, pending: Vec::new(), warmed_up: false })
    }

    /// Resample interleaved F32 audio. Returns resampled interleaved F32.
    pub fn process(&mut self, interleaved: &[f32]) -> Vec<f32> {
        self.pending.extend_from_slice(interleaved);

        let samples_per_chunk = self.chunk_size * self.channels;
        let mut output = Vec::new();

        while self.pending.len() >= samples_per_chunk {
            let chunk: Vec<f32> = self.pending.drain(..samples_per_chunk).collect();

            // Deinterleave
            let mut ch_vecs: Vec<Vec<f32>> = (0..self.channels)
                .map(|_| Vec::with_capacity(self.chunk_size))
                .collect();
            for frame in chunk.chunks_exact(self.channels) {
                for (ch, &s) in frame.iter().enumerate() {
                    ch_vecs[ch].push(s);
                }
            }

            let input = match SequentialSliceOfVecs::new(&ch_vecs, self.channels, self.chunk_size) {
                Ok(i) => i,
                Err(_) => continue,
            };

            if let Ok(result) = self.resampler.process(&input, 0, None) {
                    let data = result.take_data();
                    if !data.is_empty() {
                        if !self.warmed_up {
                            // Skip initial silence from sinc filter warmup
                            self.warmed_up = true;
                        }
                        output.extend(data);
                    }
            }
        }

        output
    }
}

/// Mix down multi-channel F32 audio to fewer channels.
/// Uses ITU-R BS.775 downmix coefficients for 5.1 and 7.1.
pub fn mixdown(input: &[f32], in_channels: usize, out_channels: usize) -> Vec<f32> {
    if in_channels == out_channels { return input.to_vec(); }
    if out_channels != 2 { return input.to_vec(); }

    let frames = input.len() / in_channels;
    let mut output = Vec::with_capacity(frames * 2);
    let k: f32 = 0.707; // -3dB

    for frame in input.chunks_exact(in_channels) {
        let (l, r) = match in_channels {
            6 => {
                let fl = frame[0]; let fr = frame[1]; let fc = frame[2];
                let rl = frame[4]; let rr = frame[5];
                (fl + k * fc + k * rl, fr + k * fc + k * rr)
            }
            8 => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resample_small_chunks() {
        let mut rs = StreamResampler::new(44100, 96000, 2).unwrap();
        let mut total_out = 0;
        // Feed 10 chunks of 352 frames (typical ALAC)
        for _ in 0..10 {
            let mut input = Vec::new();
            for i in 0..352 {
                let t = i as f32 / 44100.0;
                let s = (2.0 * std::f32::consts::PI * 440.0 * t).sin() * 0.5;
                input.push(s);
                input.push(s);
            }
            let output = rs.process(&input);
            total_out += output.len();
        }
        eprintln!("Total output samples from 10x352 frames: {}", total_out);
        assert!(total_out > 0, "no output produced");
    }

    #[test]
    fn resample_passthrough_returns_none() {
        assert!(StreamResampler::new(44100, 44100, 2).is_none());
    }
}
