use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use shairplay::{AudioCodec, AudioFormat, AudioHandler, AudioSession};

// More than PipeWire's 4 MiB stereo S16 ring, to exercise wraparound.
const FRAMES: usize = 44100 * 25;
const PREROLL_FRAMES: usize = 44100;
const MAX_SAMPLES: usize = 44100 * 2 * 40;

pub(super) fn samples() -> Vec<i16> {
    let mut state = 0x1234_5678_u32;
    (0..FRAMES * 2)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            ((state >> 16) as i16 / 2) | 1
        })
        .collect()
}

pub(super) fn wav() -> Vec<u8> {
    let mut bytes = b"RIFF".to_vec();
    let data_bytes = (PREROLL_FRAMES * 2 + FRAMES) * 4;
    bytes.extend_from_slice(&u32::try_from(36 + data_bytes).unwrap().to_le_bytes());
    bytes.extend_from_slice(b"WAVEfmt ");
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    for value in [1_u16, 2] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in [44100_u32, 44100 * 4] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in [4_u16, 16] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&u32::try_from(data_bytes).unwrap().to_le_bytes());
    // Let the session-manager-free graph link both channels before non-silent data.
    bytes.resize(bytes.len() + PREROLL_FRAMES * 4, 0);
    for sample in samples() {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    // Drain the non-silent payload before suspending the sender.
    bytes.resize(bytes.len() + PREROLL_FRAMES * 4, 0);
    bytes
}

#[derive(Default)]
pub(super) struct Capture {
    pub(super) sessions: Arc<Mutex<Vec<SessionData>>>,
}

#[derive(Default)]
pub(super) struct SessionData {
    samples: Vec<f32>,
    stopped: bool,
}

struct Session {
    sessions: Arc<Mutex<Vec<SessionData>>>,
    index: usize,
}

impl AudioHandler for Capture {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        assert_eq!(
            (
                format.codec,
                format.sample_rate,
                format.channels,
                format.bits
            ),
            (AudioCodec::Pcm, 44100, 2, 32)
        );
        let mut sessions = self.sessions.lock().unwrap();
        let index = sessions.len();
        sessions.push(SessionData::default());
        Box::new(Session {
            sessions: self.sessions.clone(),
            index,
        })
    }
}

impl AudioSession for Session {
    fn audio_process(&mut self, samples: &[f32]) {
        let mut sessions = self.sessions.lock().unwrap();
        let data = &mut sessions[self.index].samples;
        assert!(data.len() + samples.len() <= MAX_SAMPLES);
        data.extend_from_slice(samples);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.sessions.lock().unwrap()[self.index].stopped = true;
    }
}

impl Capture {
    pub(super) async fn wait_stopped(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self
                    .sessions
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|s| s.stopped)
                    .count()
                    == count
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("audio session teardown");
    }

    pub(super) fn verify(&self, index: usize) -> serde_json::Value {
        let sessions = self.sessions.lock().unwrap();
        let actual = &sessions[index].samples;
        let result = verify_samples(actual);
        assert!(sessions[index].stopped);
        json!({"format": "PCM f32 stereo 44100 Hz", "received_frames": actual.len()/2,
            "expected_payload_frames": FRAMES, "exact_payload": result.is_ok(),
            "failure": result.err(), "stopped": true})
    }
}

fn verify_samples(actual: &[f32]) -> Result<(), String> {
    let (frames, remainder) = actual.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("incomplete stereo frame".into());
    }
    let start = frames
        .iter()
        .position(|f| *f != [0.0, 0.0])
        .ok_or("no non-silent audio")?
        * 2;
    let expected = samples();
    let payload = actual
        .get(start..start + expected.len())
        .ok_or("truncated payload")?;
    for (index, (received, sample)) in payload.iter().zip(&expected).enumerate() {
        let expected = f32::from(*sample) / 32768.0;
        if received.to_bits() != expected.to_bits() {
            let source = samples();
            let frame = &payload[index / 2 * 2..index / 2 * 2 + 2];
            let positions: Vec<_> = source
                .as_chunks::<2>()
                .0
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    frame[0] == f32::from(s[0]) / 32768.0 && frame[1] == f32::from(s[1]) / 32768.0
                })
                .map(|(i, _)| i)
                .take(10)
                .collect();
            return Err(format!(
                "sample {index}: received {received}, expected {expected}; source frame positions {positions:?}; received frames {}",
                actual.len() / 2
            ));
        }
    }
    if actual[start + expected.len()..].iter().any(|s| *s != 0.0) {
        return Err("unexpected audio after payload".into());
    }
    Ok(())
}

#[test]
fn exact_audio_with_silence_passes() {
    let mut actual = vec![0.0; 100];
    actual.extend(samples().iter().map(|s| f32::from(*s) / 32768.0));
    actual.extend([0.0; 200]);
    assert_eq!(verify_samples(&actual), Ok(()));
}

#[test]
fn corrupted_truncated_reordered_or_missing_audio_fails() {
    let reference: Vec<_> = samples().iter().map(|s| f32::from(*s) / 32768.0).collect();
    assert!(verify_samples(&[]).is_err());
    assert!(verify_samples(&vec![0.0; reference.len()]).is_err());
    assert!(verify_samples(&reference[..reference.len() - 2]).is_err());
    assert!(verify_samples(&reference[..reference.len() - 1]).is_err());
    for index in [0, 1, 2000, reference.len() - 1] {
        let mut corrupt = reference.clone();
        corrupt[index] = 0.0;
        assert!(verify_samples(&corrupt).is_err());
    }
    let mut swapped = reference.clone();
    swapped.swap(0, 1);
    assert!(verify_samples(&swapped).is_err());
    let mut dropped = reference.clone();
    dropped.drain(200..202);
    assert!(verify_samples(&dropped).is_err());
    let mut repeated = reference.clone();
    repeated.extend(&reference);
    assert!(verify_samples(&repeated).is_err());
}

#[test]
fn wav_contains_preroll_payload_and_postroll() {
    let bytes = wav();
    assert_eq!(&bytes[..4], b"RIFF");
    assert_eq!(
        u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize + 8,
        bytes.len()
    );
    assert_eq!(
        u32::from_le_bytes(bytes[40..44].try_into().unwrap()) as usize + 44,
        bytes.len()
    );
    let decoded: Vec<_> = bytes[44..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|s| f32::from(i16::from_le_bytes(*s)) / 32768.0)
        .collect();
    assert_eq!(verify_samples(&decoded), Ok(()));
}
