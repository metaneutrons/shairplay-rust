//! Binary plist helpers for AirPlay 2 protocol messages.

use std::collections::HashMap;

/// Plist value types matching the C library's PLIST_TYPE_* constants.
#[derive(Debug, Clone)]
/// Simplified plist value type for AirPlay protocol messages.
pub enum PlistValue {
    /// Boolean value.
    Boolean(bool),
    /// Integer value.
    Integer(i64),
    /// Floating-point value.
    Real(f64),
    /// Raw byte data.
    Data(Vec<u8>),
    /// String value.
    String(String),
    /// Ordered array.
    Array(Vec<PlistValue>),
    /// Key-value dictionary.
    Dict(HashMap<String, PlistValue>),
}

impl PlistValue {
    /// Extract as boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PlistValue::Boolean(v) => Some(*v),
            _ => None,
        }
    }
    /// Extract as integer.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            PlistValue::Integer(v) => Some(*v),
            _ => None,
        }
    }
    /// Extract as floating-point number.
    pub fn as_real(&self) -> Option<f64> {
        match self {
            PlistValue::Real(v) => Some(*v),
            _ => None,
        }
    }
    /// Extract as raw byte data.
    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            PlistValue::Data(v) => Some(v),
            _ => None,
        }
    }
    /// Extract as string.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            PlistValue::String(v) => Some(v),
            _ => None,
        }
    }
    /// Extract as array.
    pub fn as_array(&self) -> Option<&[PlistValue]> {
        match self {
            PlistValue::Array(v) => Some(v),
            _ => None,
        }
    }
    /// Extract as dictionary.
    pub fn as_dict(&self) -> Option<&HashMap<String, PlistValue>> {
        match self {
            PlistValue::Dict(v) => Some(v),
            _ => None,
        }
    }
    /// Look up a key in a dictionary value.
    pub fn dict_get(&self, key: &str) -> Option<&PlistValue> {
        self.as_dict()?.get(key)
    }
    /// Get an element from an array value by index.
    pub fn array_get(&self, idx: usize) -> Option<&PlistValue> {
        self.as_array()?.get(idx)
    }
}

/// Convert a plist::Value (from the plist crate) to our PlistValue.
fn from_plist_value(val: plist::Value) -> PlistValue {
    match val {
        plist::Value::Boolean(b) => PlistValue::Boolean(b),
        plist::Value::Integer(i) => PlistValue::Integer(i.as_signed().unwrap_or(0)),
        plist::Value::Real(r) => PlistValue::Real(r),
        plist::Value::Data(d) => PlistValue::Data(d),
        plist::Value::String(s) => PlistValue::String(s),
        plist::Value::Array(a) => PlistValue::Array(a.into_iter().map(from_plist_value).collect()),
        plist::Value::Dictionary(d) => {
            let map = d.into_iter().map(|(k, v)| (k, from_plist_value(v))).collect();
            PlistValue::Dict(map)
        }
        plist::Value::Date(_) => PlistValue::String("(date)".to_string()),
        plist::Value::Uid(u) => PlistValue::Integer(u.get() as i64),
        _ => PlistValue::Data(vec![]),
    }
}

/// Convert our PlistValue to a plist::Value for serialization.
fn to_plist_value(val: &PlistValue) -> plist::Value {
    match val {
        PlistValue::Boolean(b) => plist::Value::Boolean(*b),
        PlistValue::Integer(i) => plist::Value::Integer((*i).into()),
        PlistValue::Real(r) => plist::Value::Real(*r),
        PlistValue::Data(d) => plist::Value::Data(d.clone()),
        PlistValue::String(s) => plist::Value::String(s.clone()),
        PlistValue::Array(a) => plist::Value::Array(a.iter().map(to_plist_value).collect()),
        PlistValue::Dict(d) => {
            let dict: plist::Dictionary = d.iter().map(|(k, v)| (k.clone(), to_plist_value(v))).collect();
            plist::Value::Dictionary(dict)
        }
    }
}

/// Parse a binary plist (bplist00 format) from raw bytes.
/// Equivalent to plist_object_from_bplist.
pub fn from_bplist(data: &[u8]) -> Option<PlistValue> {
    let val = plist::Value::from_reader(std::io::Cursor::new(data)).ok()?;
    Some(from_plist_value(val))
}

/// Serialize a PlistValue to binary plist format.
/// Equivalent to plist_object_to_bplist.
pub fn to_bplist(value: &PlistValue) -> Option<Vec<u8>> {
    let pval = to_plist_value(value);
    let mut buf = Vec::new();
    pval.to_writer_binary(&mut buf).ok()?;
    Some(buf)
}
