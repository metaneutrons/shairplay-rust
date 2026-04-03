//! Minimal PTP timing client for AirPlay 2 (Apple aPTP profile).
//!
//! Listens on UDP ports 319 (event) and 320 (general) for PTP Sync/Follow_Up/Announce
//! messages. Tracks master clock ID and computes local-to-master time offset with smoothing.
//! Ports 319/320 require root or CAP_NET_BIND_SERVICE.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// PTP message types (IEEE 1588).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PtpMessageType {
    Sync = 0,
    FollowUp = 8,
    Announce = 11,
    Other = 0xFF,
}

impl From<u8> for PtpMessageType {
    fn from(v: u8) -> Self {
        match v & 0x0F {
            0 => Self::Sync,
            8 => Self::FollowUp,
            11 => Self::Announce,
            _ => Self::Other,
        }
    }
}

/// Clock info shared between PTP receiver and audio pipeline.
#[derive(Debug, Clone, Default)]
pub struct PtpClockInfo {
    pub master_clock_id: u64,
    pub local_time: u64,           // ns, when offset was last calculated
    pub offset: u64,               // add to local time to get master time
    pub mastership_start_time: u64, // ns
}

/// Thread-safe PTP clock state.
#[derive(Clone)]
pub struct PtpClock {
    info: Arc<RwLock<PtpClockInfo>>,
}

impl PtpClock {
    pub fn new() -> Self {
        Self { info: Arc::new(RwLock::new(PtpClockInfo::default())) }
    }

    pub fn get_info(&self) -> PtpClockInfo {
        self.info.read().unwrap().clone()
    }

    pub fn update(&self, clock_id: u64, local_time: u64, offset: u64, mastership_start: u64) {
        let mut info = self.info.write().unwrap();
        info.master_clock_id = clock_id;
        info.local_time = local_time;
        info.offset = offset;
        info.mastership_start_time = mastership_start;
    }

    /// Get current master time in nanoseconds.
    pub fn master_time_now(&self) -> Option<u64> {
        let info = self.info.read().unwrap();
        if info.master_clock_id == 0 { return None; }
        let now = now_ns();
        Some(now.wrapping_add(info.offset))
    }
}

/// Parse a PTP Follow_Up message and extract the preciseOriginTimestamp.
/// Returns (clock_id, precise_origin_timestamp_ns, correction_field_ns).
pub fn parse_follow_up(buf: &[u8]) -> Option<(u64, u64, i64)> {
    if buf.len() < 54 { return None; }
    let msg_type = PtpMessageType::from(buf[0]);
    if msg_type != PtpMessageType::FollowUp { return None; }

    // Clock identity: bytes 20..28
    let clock_id = u64::from_be_bytes(buf[20..28].try_into().ok()?);

    // Correction field: bytes 8..16 (signed, in units of 2^-16 ns)
    let correction_raw = i64::from_be_bytes(buf[8..16].try_into().ok()?);
    let correction_ns = correction_raw / 65536;

    // preciseOriginTimestamp: bytes 34..44 (6-byte seconds + 4-byte nanoseconds)
    let seconds_hi = u16::from_be_bytes([buf[34], buf[35]]) as u64;
    let seconds_lo = u32::from_be_bytes(buf[36..40].try_into().ok()?) as u64;
    let nanoseconds = u32::from_be_bytes(buf[40..44].try_into().ok()?) as u64;
    let seconds = (seconds_hi << 32) | seconds_lo;
    let timestamp_ns = seconds * 1_000_000_000 + nanoseconds;

    Some((clock_id, timestamp_ns.wrapping_add(correction_ns as u64), correction_ns))
}

/// Parse a PTP Announce message and extract the clock identity.
pub fn parse_announce(buf: &[u8]) -> Option<u64> {
    if buf.len() < 64 { return None; }
    let msg_type = PtpMessageType::from(buf[0]);
    if msg_type != PtpMessageType::Announce { return None; }
    let clock_id = u64::from_be_bytes(buf[20..28].try_into().ok()?);
    Some(clock_id)
}

/// Offset smoother matching NQPTP behavior.
pub struct OffsetSmoother {
    previous_offset: u64,
    previous_time: u64,
    mastership_start: u64,
    initialized: bool,
}

impl OffsetSmoother {
    pub fn new() -> Self {
        Self { previous_offset: 0, previous_time: 0, mastership_start: 0, initialized: false }
    }

    /// Process a new offset sample. Returns the smoothed offset.
    pub fn update(&mut self, raw_offset: u64, reception_time: u64) -> u64 {
        if !self.initialized {
            self.previous_offset = raw_offset;
            self.previous_time = reception_time;
            self.mastership_start = reception_time;
            self.initialized = true;
            return raw_offset;
        }

        let jitter = raw_offset as i64 - self.previous_offset as i64;
        let mastership_time = reception_time.saturating_sub(self.mastership_start) as i64;

        let smoothed = if jitter < 0 {
            // Negative jitter: clamp and apply slowly
            let clamped = jitter.max(-2_500_000);
            if mastership_time > 1_000_000_000 {
                (self.previous_offset as i64 + clamped / 256) as u64
            } else {
                self.previous_offset
            }
        } else if mastership_time < 1_000_000_000 {
            // Early: accept positive changes quickly
            (self.previous_offset as i64 + jitter) as u64
        } else {
            // Later: smooth positive changes
            (self.previous_offset as i64 + jitter / 16) as u64
        };

        self.previous_offset = smoothed;
        self.previous_time = reception_time;
        smoothed
    }

    pub fn reset(&mut self) {
        self.initialized = false;
    }
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_follow_up_valid() {
        // Construct a minimal Follow_Up message (54 bytes)
        let mut buf = vec![0u8; 54];
        buf[0] = 0x08; // Follow_Up type
        // Clock identity at bytes 20..28
        buf[20..28].copy_from_slice(&0xAABBCCDD11223344u64.to_be_bytes());
        // Correction field at bytes 8..16 (0 for simplicity)
        // preciseOriginTimestamp at bytes 34..44
        // seconds_hi = 0, seconds_lo = 1000, nanoseconds = 500000000
        buf[36..40].copy_from_slice(&1000u32.to_be_bytes());
        buf[40..44].copy_from_slice(&500_000_000u32.to_be_bytes());

        let (clock_id, ts, corr) = parse_follow_up(&buf).unwrap();
        assert_eq!(clock_id, 0xAABBCCDD11223344);
        assert_eq!(ts, 1000 * 1_000_000_000 + 500_000_000);
        assert_eq!(corr, 0);
    }

    #[test]
    fn parse_announce_valid() {
        let mut buf = vec![0u8; 64];
        buf[0] = 0x0B; // Announce type
        buf[20..28].copy_from_slice(&0x1234567890ABCDEFu64.to_be_bytes());
        let clock_id = parse_announce(&buf).unwrap();
        assert_eq!(clock_id, 0x1234567890ABCDEF);
    }

    #[test]
    fn smoother_first_sample_passthrough() {
        let mut s = OffsetSmoother::new();
        let result = s.update(1_000_000, 100_000_000);
        assert_eq!(result, 1_000_000);
    }

    #[test]
    fn smoother_positive_jitter_early() {
        let mut s = OffsetSmoother::new();
        s.update(1_000_000, 0);
        // Early phase (< 1s mastership): positive jitter accepted fully
        let result = s.update(1_100_000, 500_000_000);
        assert_eq!(result, 1_100_000);
    }

    #[test]
    fn smoother_negative_jitter_clamped() {
        let mut s = OffsetSmoother::new();
        s.update(1_000_000, 0);
        // Early phase: negative jitter ignored
        let result = s.update(900_000, 500_000_000);
        assert_eq!(result, 1_000_000); // unchanged
    }

    #[test]
    fn ptp_clock_master_time() {
        let clock = PtpClock::new();
        assert!(clock.master_time_now().is_none());
        clock.update(1, now_ns(), 42, now_ns());
        let mt = clock.master_time_now().unwrap();
        assert!(mt > 42); // should be now + 42
    }
}
