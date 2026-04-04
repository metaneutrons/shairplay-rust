//! Base64 encoding/decoding (custom implementation for RTSP compatibility).

const BASE64_PADDING: u8 = 0x40;
const BASE64_INVALID: u8 = 0x80;

/// Base64 encoder/decoder matching the behavior of base64.c.
/// Supports configurable character set, padding, and space-skipping.
pub struct Base64 {
    charlist: [u8; 64],
    charmap: [u8; 256],
    use_padding: bool,
    skip_spaces: bool,
}

impl Base64 {
    /// Create a new Base64 instance. Equivalent to base64_init.
    pub fn new(charlist: &[u8; 64], use_padding: bool, skip_spaces: bool) -> Self {
        for &c in charlist {
            assert!(c != b'\r' && c != b'\n' && c != b'=');
        }
        let mut b = Self {
            charlist: *charlist,
            charmap: [BASE64_INVALID; 256],
            use_padding,
            skip_spaces,
        };
        for (i, &c) in b.charlist.iter().enumerate() {
            b.charmap[c as usize] = i as u8;
        }
        b.charmap[b'=' as usize] = BASE64_PADDING;
        b
    }

    /// Standard base64 (RFC 4648) with padding and space-skipping.

    /// Compute the encoded length for a given source length.
    /// Equivalent to base64_encoded_length (minus the NUL terminator).
    pub fn encoded_length(&self, src_len: usize) -> usize {
        if self.use_padding {
            src_len.div_ceil(3) * 4
        } else {
            let mut len = src_len / 3 * 4;
            match src_len % 3 {
                2 => len += 3,
                1 => len += 2,
                _ => {}
            }
            len
        }
    }

    /// Encode bytes to a base64 string. Equivalent to base64_encode.
    pub fn encode(&self, src: &[u8]) -> String {
        let mut dst = Vec::with_capacity(self.encoded_length(src.len()));
        let mut residue: u32 = 0;

        for (src_idx, &byte) in src.iter().enumerate() {
            residue |= byte as u32;
            match src_idx % 3 {
                0 => {
                    dst.push(self.charlist[((residue >> 2) % 64) as usize]);
                    residue &= 0x03;
                }
                1 => {
                    dst.push(self.charlist[(residue >> 4) as usize]);
                    residue &= 0x0f;
                }
                2 => {
                    dst.push(self.charlist[(residue >> 6) as usize]);
                    dst.push(self.charlist[(residue & 0x3f) as usize]);
                    residue = 0;
                }
                _ => unreachable!(),
            }
            residue <<= 8;
        }

        // Add trailing characters and optional padding
        match src.len() % 3 {
            1 => {
                dst.push(self.charlist[(residue >> 4) as usize]);
                if self.use_padding {
                    dst.push(b'=');
                    dst.push(b'=');
                }
            }
            2 => {
                dst.push(self.charlist[(residue >> 6) as usize]);
                if self.use_padding {
                    dst.push(b'=');
                }
            }
            _ => {}
        }

        // Safety: charlist is ASCII, '=' is ASCII
        String::from_utf8(dst).expect("base64 output is always valid ASCII")
    }

    /// Decode a base64 string to bytes. Equivalent to base64_decode.
    pub fn decode(&self, src: &str) -> Option<Vec<u8>> {
        let mut inbuf: Vec<u8> = if self.skip_spaces {
            src.bytes().filter(|b| !b.is_ascii_whitespace()).collect()
        } else {
            src.bytes().collect()
        };

        // Add padding if not using padding mode
        if !self.use_padding {
            match inbuf.len() % 4 {
                1 => return None,
                2 => {
                    inbuf.push(b'=');
                    inbuf.push(b'=');
                }
                3 => inbuf.push(b'='),
                _ => {}
            }
        }

        if inbuf.len() % 4 != 0 {
            return None;
        }

        // Calculate output length
        let mut outbuflen = inbuf.len() / 4 * 3;
        if inbuf.len() >= 4
            && inbuf[inbuf.len() - 1] == b'=' {
                outbuflen -= 1;
                if inbuf[inbuf.len() - 2] == b'=' {
                    outbuflen -= 1;
                }
            }

        let mut outbuf = Vec::with_capacity(outbuflen);
        let mut i = 0;
        while i < inbuf.len() {
            let a = self.charmap[inbuf[i] as usize];
            let b = self.charmap[inbuf[i + 1] as usize];
            let c = self.charmap[inbuf[i + 2] as usize];
            let d = self.charmap[inbuf[i + 3] as usize];
            i += 4;

            if a == BASE64_INVALID || b == BASE64_INVALID
                || c == BASE64_INVALID || d == BASE64_INVALID
            {
                return None;
            }
            if a == BASE64_PADDING || b == BASE64_PADDING {
                return None;
            }

            outbuf.push((a << 2) | ((b & 0x30) >> 4));

            if c == BASE64_PADDING {
                break;
            }
            outbuf.push(((b & 0x0f) << 4) | ((c & 0x3c) >> 2));

            if d == BASE64_PADDING {
                break;
            }
            outbuf.push(((c & 0x03) << 6) | d);
        }

        if outbuf.len() != outbuflen {
            return None;
        }

        Some(outbuf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn std_b64() -> Base64 {
        Base64::new(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true, true)
    }

    #[test]
    fn encode_c_vector() { assert_eq!(std_b64().encode(b"Hello, AirPlay!"), "SGVsbG8sIEFpclBsYXkh"); }

    #[test]
    fn encode_empty() { assert_eq!(std_b64().encode(b""), ""); }

    #[test]
    fn encode_one_byte() { assert_eq!(std_b64().encode(&[0xff]), "/w=="); }

    #[test]
    fn decode_roundtrip() { assert_eq!(std_b64().decode("SGVsbG8sIEFpclBsYXkh").unwrap(), b"Hello, AirPlay!"); }

    #[test]
    fn decode_with_spaces() { assert_eq!(std_b64().decode("SGVs bG8s IEFp clBs YXkh").unwrap(), b"Hello, AirPlay!"); }

    #[test]
    fn nopad_encode_c_vector() {
        let b = Base64::new(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", false, false);
        assert_eq!(b.encode(b"AB"), "QUI");
        assert_eq!(b.encode(b"ABC"), "QUJD");
    }

    #[test]
    fn decode_invalid() { assert!(std_b64().decode("!!!").is_none()); }
}
