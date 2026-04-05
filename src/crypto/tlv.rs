//! TLV (Type-Length-Value) codec for HomeKit pairing messages.
//!
//! Binary format: `[type: u8] [length: u8] [value: [u8; length]]`
//! Values > 255 bytes are split into 255-byte chunks with the same type byte.

/// Well-known TLV types from the HomeKit pairing protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// HomeKit pairing TLV message types (from HAP specification).
pub enum TlvType {
    /// Pairing method.
    Method = 0,
    /// Device identifier.
    Identifier = 1,
    /// SRP salt.
    Salt = 2,
    /// SRP/Ed25519 public key.
    PublicKey = 3,
    /// SRP proof.
    Proof = 4,
    /// Encrypted payload.
    EncryptedData = 5,
    /// Pairing state (M1-M6).
    State = 6,
    /// Error code.
    Error = 7,
    /// Retry delay in seconds.
    RetryDelay = 8,
    /// MFi certificate.
    Certificate = 9,
    /// Ed25519 signature.
    Signature = 10,
    /// Pairing permissions.
    Permissions = 11,
    /// Fragment data.
    FragmentData = 13,
    /// Last fragment marker.
    FragmentLast = 14,
    /// Pairing flags (transient bit).
    Flags = 19,
    /// TLV separator.
    Separator = 0xff,
}

/// Ordered collection of TLV entries (preserves insertion order).
#[derive(Debug, Clone, Default)]
/// Collection of TLV entries, keyed by type. Supports encode/decode.
pub struct TlvValues {
    entries: Vec<(u8, Vec<u8>)>,
}

impl TlvValues {
    /// Create an empty TLV collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a TLV entry by raw tag number.
    pub fn add(&mut self, tag: u8, value: &[u8]) {
        self.entries.push((tag, value.to_vec()));
    }

    /// Add a TLV entry by typed tag.
    pub fn add_type(&mut self, tag: TlvType, value: &[u8]) {
        self.add(tag as u8, value);
    }

    /// Get a TLV value by raw tag number.
    pub fn get(&self, tag: u8) -> Option<&[u8]> {
        self.entries.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.as_slice())
    }

    /// Get a TLV value by typed tag.
    pub fn get_type(&self, tag: TlvType) -> Option<&[u8]> {
        self.get(tag as u8)
    }

    /// Serialize to binary TLV format. Values > 255 bytes are chunked.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for (tag, value) in &self.entries {
            if value.is_empty() {
                buf.push(*tag);
                buf.push(0);
            } else {
                for chunk in value.chunks(255) {
                    buf.push(*tag);
                    buf.push(chunk.len() as u8);
                    buf.extend_from_slice(chunk);
                }
            }
        }
        buf
    }

    /// Parse binary TLV data. Adjacent chunks with the same type are concatenated.
    pub fn decode(data: &[u8]) -> Result<Self, TlvError> {
        let mut values = Self::new();
        let mut i = 0;
        while i < data.len() {
            if i + 1 >= data.len() {
                return Err(TlvError::Truncated);
            }
            let tag = data[i];
            let len = data[i + 1] as usize;
            i += 2;
            if i + len > data.len() {
                return Err(TlvError::Truncated);
            }
            let chunk = &data[i..i + len];
            i += len;

            // If same type as last entry and previous chunk was exactly 255 bytes, concatenate
            if let Some((last_tag, last_val)) = values.entries.last_mut() {
                if *last_tag == tag && last_val.len() % 255 == 0 && !last_val.is_empty() {
                    last_val.extend_from_slice(chunk);
                    continue;
                }
            }
            values.entries.push((tag, chunk.to_vec()));
        }
        Ok(values)
    }
}

#[derive(Debug, thiserror::Error)]
/// TLV parsing errors.
pub enum TlvError {
    #[error("TLV data truncated")]
    /// TLV data was truncated (incomplete length field).
    Truncated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple() {
        let mut tlv = TlvValues::new();
        tlv.add(6, &[1]); // State = M1
        tlv.add(0, &[0]); // Method = 0
        let encoded = tlv.encode();
        assert_eq!(encoded, &[6, 1, 1, 0, 1, 0]);
        let decoded = TlvValues::decode(&encoded).unwrap();
        assert_eq!(decoded.get(6), Some(&[1u8][..]));
        assert_eq!(decoded.get(0), Some(&[0u8][..]));
    }

    #[test]
    fn roundtrip_chunked() {
        let mut tlv = TlvValues::new();
        let big = vec![0xAB; 300];
        tlv.add(3, &big);
        let encoded = tlv.encode();
        // Should be: [3, 255, <255 bytes>, 3, 45, <45 bytes>]
        assert_eq!(encoded.len(), 2 + 255 + 2 + 45);
        let decoded = TlvValues::decode(&encoded).unwrap();
        assert_eq!(decoded.get(3).unwrap().len(), 300);
        assert_eq!(decoded.get(3).unwrap(), &big[..]);
    }

    #[test]
    fn empty_value() {
        let mut tlv = TlvValues::new();
        tlv.add(0xff, &[]);
        let encoded = tlv.encode();
        assert_eq!(encoded, &[0xff, 0]);
        let decoded = TlvValues::decode(&encoded).unwrap();
        assert_eq!(decoded.get(0xff), Some(&[][..]));
    }

    #[test]
    fn truncated_input() {
        assert!(TlvValues::decode(&[6]).is_err());
        assert!(TlvValues::decode(&[6, 5, 1, 2]).is_err());
    }

    // --- C-verified test vectors (generated from pair-tlv.c) ---

    #[test]
    fn c_vector_simple_state_method() {
        // State=M1, Method=0
        let mut tlv = TlvValues::new();
        tlv.add(6, &[1]);
        tlv.add(0, &[0]);
        let encoded = tlv.encode();
        assert_eq!(hex_encode(&encoded), "060101000100");
        // Verify decode roundtrip
        let decoded = TlvValues::decode(&encoded).unwrap();
        assert_eq!(decoded.get(6), Some(&[1u8][..]));
        assert_eq!(decoded.get(0), Some(&[0u8][..]));
    }

    #[test]
    fn c_vector_chunked_300_bytes() {
        // 300-byte public key: bytes 0x00..0xFF, 0x00..0x2B
        let mut tlv = TlvValues::new();
        let pk: Vec<u8> = (0u16..300).map(|i| (i & 0xff) as u8).collect();
        tlv.add(3, &pk);
        let encoded = tlv.encode();
        assert_eq!(encoded.len(), 304); // 2+255 + 2+45
        // First chunk header
        assert_eq!(encoded[0], 3);
        assert_eq!(encoded[1], 255);
        // Second chunk header
        assert_eq!(encoded[257], 3);
        assert_eq!(encoded[258], 45);
        let decoded = TlvValues::decode(&encoded).unwrap();
        assert_eq!(decoded.get(3).unwrap(), &pk[..]);
    }

    #[test]
    fn c_vector_multi_field_m2() {
        // Simulated pair-setup M2: State=2, Salt(16 bytes), PublicKey(384 bytes chunked)
        let mut tlv = TlvValues::new();
        tlv.add(6, &[2]);
        let salt: Vec<u8> = (0x10u8..0x20).collect();
        tlv.add(2, &salt);
        let spk: Vec<u8> = (0u16..384).map(|i| ((i * 7) & 0xff) as u8).collect();
        tlv.add(3, &spk);
        let encoded = tlv.encode();
        assert_eq!(encoded.len(), 409); // 3 + 18 + (2+255)+(2+129) + (2+255) = 3+18+257+131 = 409
        let decoded = TlvValues::decode(&encoded).unwrap();
        assert_eq!(decoded.get(6), Some(&[2u8][..]));
        assert_eq!(decoded.get(2).unwrap(), &salt[..]);
        assert_eq!(decoded.get(3).unwrap(), &spk[..]);
    }

    // Note: C pair_tlv_format has a bug for empty values — it writes 2 bytes
    // ([type, 0]) but reports size=0. Our implementation correctly encodes
    // empty values as [type, 0] (2 bytes).
    #[test]
    fn empty_separator_c_bug_fixed() {
        let mut tlv = TlvValues::new();
        tlv.add(0xff, &[]);
        let encoded = tlv.encode();
        assert_eq!(encoded, &[0xff, 0]); // Correct: 2 bytes
        let decoded = TlvValues::decode(&encoded).unwrap();
        assert_eq!(decoded.get(0xff), Some(&[][..]));
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
