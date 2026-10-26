//! Sample rate conversion and channel mixdown for AirPlay audio.

use rubato::audioadapter_buffers::direct::SequentialSliceOfVecs;
use rubato::{
    Async, FixedAsync, Resampler, SincInterpolationParameters, SincInterpolationType,
    WindowFunction,
};

/// Persistent F32 resampler for streaming audio.
/// Buffers input internally and processes in fixed chunks.
pub(crate) struct StreamResampler {
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
    pub(crate) fn new(from_rate: u32, to_rate: u32, channels: usize) -> Option<Self> {
        if from_rate == to_rate {
            return None;
        }
        let params = SincInterpolationParameters {
            sinc_len: 64,
            f_cutoff: Some(0.95),
            interpolation: SincInterpolationType::Linear,
            oversampling_factor: 128,
            window: WindowFunction::BlackmanHarris2,
        };
        let ratio = to_rate as f64 / from_rate as f64;
        let chunk_size = 128; // small for low latency
        let resampler =
            Async::<f32>::new_sinc(ratio, 1.0, &params, chunk_size, channels, FixedAsync::Input)
                .ok()?;
        Some(Self {
            resampler,
            channels,
            chunk_size,
            pending: Vec::new(),
            warmed_up: false,
        })
    }

    /// Resample interleaved F32 audio. Returns resampled interleaved F32.
    pub(crate) fn process(&mut self, interleaved: &[f32]) -> Vec<f32> {
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

            if let Ok(result) = self.resampler.process(&input, None) {
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

/// ITU-R BS.775 downmix coefficient (−3 dB) applied to centre and surround
/// channels when folding 5.1/7.1 into stereo.
const DOWNMIX_3DB: f32 = 0.707;

/// Mix down multi-channel F32 audio to fewer channels.
/// Uses ITU-R BS.775 downmix coefficients for 5.1 and 7.1.
pub(crate) fn mixdown(input: &[f32], in_channels: usize, out_channels: usize) -> Vec<f32> {
    if in_channels == out_channels {
        return input.to_vec();
    }
    if out_channels != 2 {
        return input.to_vec();
    }

    let frames = input.len() / in_channels;
    let mut output = Vec::with_capacity(frames * 2);
    let k: f32 = DOWNMIX_3DB;

    for frame in input.chunks_exact(in_channels) {
        let (l, r) = match in_channels {
            6 => {
                let fl = frame[0];
                let fr = frame[1];
                let fc = frame[2];
                let rl = frame[4];
                let rr = frame[5];
                (fl + k * fc + k * rl, fr + k * fc + k * rr)
            }
            8 => {
                let fl = frame[0];
                let fr = frame[1];
                let fc = frame[2];
                let sl = frame[4];
                let sr = frame[5];
                let rl = frame[6];
                let rr = frame[7];
                (fl + k * fc + k * sl + k * rl, fr + k * fc + k * sr + k * rr)
            }
            _ => (frame[0], frame.get(1).copied().unwrap_or(frame[0])),
        };
        output.push(l.clamp(-1.0, 1.0));
        output.push(r.clamp(-1.0, 1.0));
    }
    output
}

/// Mix `samples` down to `out_channels` (if `src_channels` is larger) and then
/// resample through `resampler` (if present). This is the shared tail of the AP2
/// realtime and buffered receive pipelines.
pub(crate) fn mixdown_and_resample(
    mut samples: Vec<f32>,
    src_channels: u8,
    out_channels: u8,
    resampler: &mut Option<StreamResampler>,
) -> Vec<f32> {
    if src_channels > out_channels {
        samples = mixdown(&samples, src_channels as usize, out_channels as usize);
    }
    if let Some(rs) = resampler {
        samples = rs.process(&samples);
    }
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixdown_and_resample_passthrough_is_identity() {
        // No mixdown (src == out) and no resampler → samples returned unchanged.
        let samples = vec![0.1, 0.2, 0.3, 0.4];
        let mut none = None;
        assert_eq!(
            mixdown_and_resample(samples.clone(), 2, 2, &mut none),
            samples
        );
    }

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
        assert!(total_out > 0, "no output produced");
    }

    #[test]
    fn resample_passthrough_returns_none() {
        assert!(StreamResampler::new(44100, 44100, 2).is_none());
    }

    /// Feed `chunks` blocks of `frames` interleaved stereo frames of a sine
    /// (`freq` Hz, amplitude 0.5, phase 0 at the first input frame) and return
    /// `(interleaved output, frames fed)`.
    fn run_sine(from: u32, to: u32, freq: f64, chunks: usize, frames: usize) -> (Vec<f32>, usize) {
        let mut rs = StreamResampler::new(from, to, 2).unwrap();
        let mut out = Vec::new();
        let mut n = 0usize;
        for _ in 0..chunks {
            let mut input = Vec::with_capacity(frames * 2);
            for _ in 0..frames {
                let t = n as f64 / f64::from(from);
                let s = (0.5 * (2.0 * std::f64::consts::PI * freq * t).sin()) as f32;
                input.push(s);
                input.push(s);
                n += 1;
            }
            out.extend(rs.process(&input));
        }
        (out, n)
    }

    /// Least-squares fit of `A sin(wt) + B cos(wt)` to channel `ch` of `out`
    /// (skipping `skip` warm-up frames). Returns `(amplitude, rms_residual)`.
    /// A phase-free measure, so a changed filter delay between resampler
    /// versions does not influence it.
    fn fit_sine(out: &[f32], ch: usize, rate: u32, freq: f64, skip: usize) -> (f64, f64) {
        let w = 2.0 * std::f64::consts::PI * freq / f64::from(rate);
        let (mut ss, mut cc, mut sc, mut sy, mut cy) = (0.0, 0.0, 0.0, 0.0, 0.0);
        let frames = out.len() / 2;
        for i in skip..frames {
            let y = f64::from(out[i * 2 + ch]);
            let (s, c) = (w * i as f64).sin_cos();
            ss += s * s;
            cc += c * c;
            sc += s * c;
            sy += s * y;
            cy += c * y;
        }
        let det = ss * cc - sc.powi(2);
        let a = (sy * cc - cy * sc) / det;
        let b = (cy * ss - sy * sc) / det;
        let mut err = 0.0;
        for i in skip..frames {
            let (s, c) = (w * i as f64).sin_cos();
            let e = f64::from(out[i * 2 + ch]) - (a * s + b * c);
            err += e * e;
        }
        (a.hypot(b), (err / (frames - skip) as f64).sqrt())
    }

    /// Behaviour pin for the resampling path: output length stays within one
    /// resampler block of `frames_in * ratio`, both channels stay identical,
    /// and a 440 Hz sine keeps its frequency and amplitude with a residual far
    /// below audibility. Independent of the filter delay, so it must hold
    /// across resampler releases.
    #[test]
    fn resample_sine_fidelity() {
        for &(from, to) in &[(44_100u32, 48_000u32), (44_100, 96_000), (48_000, 44_100)] {
            let (out, fed) = run_sine(from, to, 440.0, 40, 352);
            let ratio = f64::from(to) / f64::from(from);
            let expected = fed as f64 * ratio;
            let got = (out.len() / 2) as f64;
            assert!(
                (expected - got).abs() <= 2.0 * 128.0 * ratio.max(1.0),
                "{from}->{to}: expected about {expected} frames, got {got}"
            );
            assert!(out.iter().all(|s| s.is_finite()));
            for f in out.as_chunks::<2>().0 {
                assert!((f[0] - f[1]).abs() < 1e-6, "channels diverged");
            }
            let (amp, rms) = fit_sine(&out, 0, to, 440.0, 512);
            assert!((amp - 0.5).abs() < 1e-3, "{from}->{to}: amplitude {amp}");
            assert!(rms < 1e-4, "{from}->{to}: residual rms {rms}");
        }
    }
}

// --- Channel mixdown tests ---

#[cfg(all(test, feature = "ap2"))]
mod mixdown_tests {
    use super::mixdown;

    #[test]
    fn stereo_passthrough() {
        let input = vec![0.5_f32, -0.5, 0.3, -0.3];
        let out = mixdown(&input, 2, 2);
        assert_eq!(out, input);
    }

    #[test]
    fn surround_51_to_stereo() {
        // 5.1: FL=1.0 FR=0.0 FC=0.5 LFE=0.0 RL=0.0 RR=0.0
        let input = vec![1.0, 0.0, 0.5, 0.0, 0.0, 0.0_f32];
        let out = mixdown(&input, 6, 2);
        // L = FL + 0.707*FC = 1.0 + 0.3535 = 1.3535 → clamped to 1.0
        // R = FR + 0.707*FC = 0.0 + 0.3535 = 0.3535
        assert!((out[0] - 1.0).abs() < 0.01); // clamped
        assert!((out[1] - 0.3535).abs() < 0.01);
    }

    #[test]
    fn surround_71_to_stereo() {
        // 7.1: FL=0.5 FR=0.5 FC=0.0 LFE=0.0 SL=0.3 SR=0.3 RL=0.2 RR=0.2
        let input = vec![0.5, 0.5, 0.0, 0.0, 0.3, 0.3, 0.2, 0.2_f32];
        let out = mixdown(&input, 8, 2);
        let k: f32 = 0.707;
        let expected_l = 0.5 + k * 0.3 + k * 0.2;
        let expected_r = 0.5 + k * 0.3 + k * 0.2;
        assert!((out[0] - expected_l).abs() < 0.01);
        assert!((out[1] - expected_r).abs() < 0.01);
    }

    #[test]
    fn mixdown_clamps_output() {
        // All channels at 1.0 — should clamp to [-1.0, 1.0]
        let input = vec![1.0_f32; 6];
        let out = mixdown(&input, 6, 2);
        assert!(out[0] <= 1.0);
        assert!(out[1] <= 1.0);
    }
}
