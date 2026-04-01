pub mod base64;

use std::fmt::Write;
use std::path::Path;

use crate::error::ShairplayError;

/// Read an entire file into a String. Equivalent to utils_read_file.
#[allow(dead_code)]
pub fn read_file(path: &Path) -> Result<String, ShairplayError> {
    std::fs::read_to_string(path).map_err(|e| {
        crate::error::NetworkError::Io(e).into()
    })
}

/// Format a hardware address for RAOP service name: "AABBCCDDEEFF" (uppercase hex, no separators).
/// Equivalent to utils_hwaddr_raop.
pub fn hwaddr_raop(hwaddr: &[u8]) -> String {
    let mut s = String::with_capacity(hwaddr.len() * 2);
    for &b in hwaddr {
        write!(s, "{:02X}", b).unwrap();
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
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hwaddr_raop_c_vector() {
        assert_eq!(hwaddr_raop(&[0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22]), "485D607CEE22");
    }

    #[test]
    fn hwaddr_airplay_c_vector() {
        assert_eq!(hwaddr_airplay(&[0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22]), "48:5d:60:7c:ee:22");
    }
}
