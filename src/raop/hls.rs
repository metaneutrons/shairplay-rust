//! HLS (HTTP Live Streaming) handler traits and playback state.
//!
//! The iPhone sends an m3u8 URL via `/play`. The application is responsible
//! for fetching and playing the stream. The library relays playback state
//! (position, duration, rate) back to the iPhone via `/playback-info`.

use std::sync::{Arc, Mutex};

/// Factory for HLS playback sessions.
pub trait HlsHandler: Send + Sync {
    /// Called when the iPhone sends a `/play` request with an HLS URL.
    /// The application should start playing the stream and return a session
    /// handle for state queries.
    fn on_play(&self, url: &str, start_position: f32) -> Box<dyn HlsSession>;
}

/// A live HLS playback session. The library polls this to respond to
/// `/playback-info` requests from the iPhone.
pub trait HlsSession: Send {
    /// Total duration in seconds (0.0 if unknown/live).
    fn duration(&self) -> f32;
    /// Current playback position in seconds.
    fn position(&self) -> f32;
    /// Playback rate: 0.0 = paused, 1.0 = normal.
    fn rate(&self) -> f32;
    /// Whether the player is ready to play.
    fn ready(&self) -> bool {
        true
    }
    /// Seek to a position in seconds.
    fn seek(&mut self, position: f32);
    /// Set playback rate (0.0 = pause, 1.0 = play).
    fn set_rate(&mut self, rate: f32);
    /// Stop playback.
    fn stop(&mut self);
}

/// Shared HLS state accessible from RTSP handlers.
pub(crate) struct HlsState {
    pub session: Option<Box<dyn HlsSession>>,
    pub session_id: Option<String>,
}

impl HlsState {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            session: None,
            session_id: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSession {
        pos: f32,
        rate: f32,
        stopped: bool,
    }

    impl HlsSession for MockSession {
        fn duration(&self) -> f32 {
            120.0
        }
        fn position(&self) -> f32 {
            self.pos
        }
        fn rate(&self) -> f32 {
            self.rate
        }
        fn seek(&mut self, position: f32) {
            self.pos = position;
        }
        fn set_rate(&mut self, rate: f32) {
            self.rate = rate;
        }
        fn stop(&mut self) {
            self.stopped = true;
            self.rate = 0.0;
        }
    }

    #[test]
    fn hls_state_lifecycle() {
        let state = HlsState::new();
        {
            let s = state.lock().unwrap();
            assert!(s.session.is_none());
        }

        // Simulate /play
        {
            let mut s = state.lock().unwrap();
            s.session = Some(Box::new(MockSession {
                pos: 0.0,
                rate: 1.0,
                stopped: false,
            }));
            s.session_id = Some("test-123".into());
        }

        // Simulate /playback-info poll
        {
            let s = state.lock().unwrap();
            let session = s.session.as_ref().unwrap();
            assert_eq!(session.duration(), 120.0);
            assert_eq!(session.rate(), 1.0);
        }

        // Simulate /scrub
        {
            let mut s = state.lock().unwrap();
            s.session.as_mut().unwrap().seek(60.0);
            assert_eq!(s.session.as_ref().unwrap().position(), 60.0);
        }

        // Simulate /rate?value=0 (pause)
        {
            let mut s = state.lock().unwrap();
            s.session.as_mut().unwrap().set_rate(0.0);
            assert_eq!(s.session.as_ref().unwrap().rate(), 0.0);
        }

        // Simulate /stop
        {
            let mut s = state.lock().unwrap();
            s.session.as_mut().unwrap().stop();
            assert_eq!(s.session.as_ref().unwrap().rate(), 0.0);
            s.session = None;
        }

        let s = state.lock().unwrap();
        assert!(s.session.is_none());
    }
}
