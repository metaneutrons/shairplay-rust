//! Public types and traits for the AirPlay server.

use std::sync::Arc;

/// Audio codec type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// Decoded PCM (f32 interleaved). Always delivered regardless of AP1/AP2.
    Pcm,
}

/// Audio format descriptor passed to [`AudioHandler::audio_init`].
#[derive(Debug, Clone, Copy)]
pub struct AudioFormat {
    /// Audio codec (always PCM for decoded output).
    pub codec: AudioCodec,
    /// Bits per sample (always 32 — samples are delivered as `&[f32]`).
    pub bits: u8,
    /// Number of channels.
    pub channels: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Trait for receiving decoded audio data from AirPlay clients.
///
/// Implement this trait to handle audio output. A new [`AudioSession`] is created
/// for each client connection via [`audio_init`](AudioHandler::audio_init).
pub trait AudioHandler: Send + Sync + 'static {
    /// Called when a new audio stream starts. Return a session to receive PCM data.
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession>;
    /// Called when a client connects.
    fn on_client_connected(&self, _addr: &str) {}
    /// Called when a client disconnects.
    fn on_client_disconnected(&self, _addr: &str) {}
    /// Called on runtime errors. Default: log at warn level.
    fn on_error(&self, error: &crate::error::ShairplayError) {
        tracing::warn!(%error, "AirPlay error");
    }
}

/// Storage for paired device keys. Implement this to persist pairing across restarts.
///
/// Without persistence, iPhones that previously paired will send encrypted data
/// on connect and fail because the server has no cached keys.
#[cfg(feature = "ap2")]
pub trait PairingStore: Send + Sync + 'static {
    /// Look up a paired device's Ed25519 public key by device ID.
    fn get(&self, device_id: &str) -> Option<[u8; 32]>;
    /// Save a paired device's Ed25519 public key.
    fn put(&self, device_id: &str, public_key: [u8; 32]);
    /// Remove a paired device.
    fn remove(&self, device_id: &str);
}

/// In-memory pairing store (lost on restart). Use for testing or wrap with file I/O.
#[cfg(feature = "ap2")]
#[derive(Default)]
pub struct MemoryPairingStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
}

#[cfg(feature = "ap2")]
impl PairingStore for MemoryPairingStore {
    fn get(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.lock().ok()?.get(device_id).copied()
    }
    fn put(&self, device_id: &str, public_key: [u8; 32]) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(device_id.to_string(), public_key);
        }
    }
    fn remove(&self, device_id: &str) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.remove(device_id);
        }
    }
}

/// Per-connection audio session receiving decoded PCM samples.
///
/// Created by [`AudioHandler::audio_init`]. Dropped when the client disconnects.
pub trait AudioSession: Send + Sync {
    /// Receive decoded f32 interleaved PCM audio samples.
    fn audio_process(&mut self, samples: &[f32]);
    /// Flush the audio buffer (e.g. on seek).
    fn audio_flush(&mut self) {}
    /// Volume change in dB (0.0 = max, -144.0 = mute).
    fn audio_set_volume(&mut self, _volume: f32) {}
    /// Track metadata (parsed from DMAP).
    fn audio_set_metadata(&mut self, _metadata: &crate::proto::dmap::TrackMetadata) {}
    /// Album artwork (JPEG or PNG).
    fn audio_set_coverart(&mut self, _coverart: &[u8]) {}
    /// DACP remote control identifiers (AP1 only).
    fn audio_remote_control_id(&mut self, _dacp_id: &str, _active_remote: &str, _remote_addr: &[u8]) {}
    /// Playback progress (start, current, end in RTP timestamps).
    fn audio_set_progress(&mut self, _start: u32, _current: u32, _end: u32) {}
    /// Called when a remote control interface becomes available (AP1 DACP).
    fn remote_control_available(&mut self, _remote: Arc<dyn RemoteControl>) {}
}

/// Playback command to send to the source device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCommand {
    /// Start playback.
    Play,
    /// Pause playback.
    Pause,
    /// Skip to next track.
    NextTrack,
    /// Skip to previous track.
    PreviousTrack,
    /// Set volume (0-100).
    SetVolume(u8),
    /// Toggle shuffle mode.
    ToggleShuffle,
    /// Toggle repeat mode.
    ToggleRepeat,
    /// Stop playback.
    Stop,
}

/// Unified remote control interface for AP1 (DACP) and AP2 (MediaRemote).
pub trait RemoteControl: Send + Sync {
    /// Send a playback command to the source device.
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError>;
    /// Commands the source device supports. AP1 returns all; AP2 returns advertised set.
    fn available_commands(&self) -> Vec<RemoteCommand>;
}
