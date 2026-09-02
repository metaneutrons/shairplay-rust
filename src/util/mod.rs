//! Utility functions — hardware address formatting, hex encoding, monotonic-ish time.

use std::fmt::Write;

/// Current wall-clock time in nanoseconds since the UNIX epoch.
///
/// Saturates to 0 if the clock is before the epoch. Used by the AP2 audio
/// playout scheduler and PTP timing code.
#[cfg(feature = "ap2")]
pub fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Format a hardware address for RAOP service name: "AABBCCDDEEFF" (uppercase hex, no separators).
/// Equivalent to utils_hwaddr_raop.
pub fn hwaddr_raop(hwaddr: &[u8]) -> String {
    let mut s = String::with_capacity(hwaddr.len() * 2);
    for &b in hwaddr {
        write!(s, "{b:02X}").unwrap();
    }
    s
}

/// Format a hardware address for AirPlay device ID: "aa:bb:cc:dd:ee:ff" (lowercase hex, colon-separated).
/// Equivalent to utils_hwaddr_airplay.
pub fn hwaddr_airplay(hwaddr: &[u8]) -> String {
    let mut s = String::with_capacity(hwaddr.len() * 3);
    for (i, &b) in hwaddr.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hwaddr_raop_c_vector() {
        assert_eq!(
            hwaddr_raop(&[0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22]),
            "485D607CEE22"
        );
    }

    #[test]
    fn hwaddr_airplay_c_vector() {
        assert_eq!(
            hwaddr_airplay(&[0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22]),
            "48:5d:60:7c:ee:22"
        );
    }
}
