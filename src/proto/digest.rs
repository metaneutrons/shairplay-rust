//! HTTP Digest authentication (RFC 2617) for optional password protection.

use md5::{Digest, Md5};
use rand::RngExt;
use subtle::ConstantTimeEq;

fn md5_to_hex(hash: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for &b in hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Compute the Digest auth response hash.
/// response = MD5(MD5(username:realm:password):nonce:MD5(method:uri))
fn get_response(
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    // HA1 = MD5(username:realm:password)
    let mut h = Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    let ha1: [u8; 16] = h.finalize().into();
    let ha1_hex = md5_to_hex(&ha1);

    // HA2 = MD5(method:uri)
    let mut h = Md5::new();
    h.update(method.as_bytes());
    h.update(b":");
    h.update(uri.as_bytes());
    let ha2: [u8; 16] = h.finalize().into();
    let ha2_hex = md5_to_hex(&ha2);

    // response = MD5(HA1:nonce:HA2)
    let mut h = Md5::new();
    h.update(ha1_hex.as_bytes());
    h.update(b":");
    h.update(nonce.as_bytes());
    h.update(b":");
    h.update(ha2_hex.as_bytes());
    let result: [u8; 16] = h.finalize().into();
    md5_to_hex(&result)
}

/// Generate a random hex nonce string. Equivalent to digest_generate_nonce.
pub fn generate_nonce(len: usize) -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.random()).collect();
    let mut h = Md5::new();
    h.update(&bytes);
    let hash: [u8; 16] = h.finalize().into();
    let hex = md5_to_hex(&hash);
    hex[..len.min(32)].to_string()
}

/// Validate an HTTP Digest Authorization header. Equivalent to digest_is_valid.
pub fn is_valid(
    realm: &str,
    password: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    authorization: Option<&str>,
) -> bool {
    let auth = match authorization {
        Some(a) => a,
        None => return false,
    };

    if !auth.starts_with("Digest") {
        return false;
    }
    let params = &auth[6..];

    let mut username = None;
    let mut auth_realm = None;
    let mut auth_nonce = None;
    let mut auth_uri = None;
    let mut response = None;

    for part in params.split(',') {
        let part = part.trim();
        if let Some(val) = extract_quoted(part, "username") {
            username = Some(val);
        } else if let Some(val) = extract_quoted(part, "realm") {
            auth_realm = Some(val);
        } else if let Some(val) = extract_quoted(part, "nonce") {
            auth_nonce = Some(val);
        } else if let Some(val) = extract_quoted(part, "uri") {
            auth_uri = Some(val);
        } else if let Some(val) = extract_quoted(part, "response") {
            response = Some(val);
        }
    }

    let (username, auth_realm, auth_nonce, auth_uri, response) =
        match (username, auth_realm, auth_nonce, auth_uri, response) {
            (Some(u), Some(r), Some(n), Some(i), Some(p)) => (u, r, n, i, p),
            _ => return false,
        };

    if auth_realm != realm || auth_nonce != nonce || auth_uri != uri {
        return false;
    }

    let our_response = get_response(username, realm, password, nonce, method, uri);
    // Constant-time comparison to avoid leaking the expected digest via timing.
    response.as_bytes().ct_eq(our_response.as_bytes()).into()
}

/// Extract a quoted value from a "key=\"value\"" pair.
fn extract_quoted<'a>(part: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=\"");
    if part.starts_with(&prefix) && part.ends_with('"') {
        Some(&part[prefix.len()..part.len() - 1])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MD5 per RFC 1321 appendix A.5 plus the `md5_to_hex` formatter.
    #[test]
    fn md5_rfc1321_vectors() {
        let cases = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expected) in cases {
            let mut h = Md5::new();
            h.update(input.as_bytes());
            let hash: [u8; 16] = h.finalize().into();
            assert_eq!(md5_to_hex(&hash), expected, "md5({input:?})");
        }
    }

    /// RFC 2617 section 3.5 example inputs under the RFC 2069 (no qop)
    /// response formula used here. The value was computed with Python hashlib;
    /// the same script reproduces the RFC's qop=auth response 6629fae4... for
    /// these inputs, which validates the computation.
    #[test]
    fn response_known_answer() {
        assert_eq!(
            get_response(
                "Mufasa",
                "testrealm@host.com",
                "Circle Of Life",
                "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                "GET",
                "/dir/index.html"
            ),
            "670fd8c2df070c60b045671b8b24ff02"
        );
    }

    #[test]
    fn is_valid_accepts_known_answer_and_rejects_variants() {
        let header = |resp: &str| {
            format!(
                "Digest username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", response=\"{resp}\""
            )
        };
        let check = |pw: &str, method: &str, resp: &str| {
            is_valid(
                "testrealm@host.com",
                pw,
                "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                method,
                "/dir/index.html",
                Some(&header(resp)),
            )
        };
        assert!(check(
            "Circle Of Life",
            "GET",
            "670fd8c2df070c60b045671b8b24ff02"
        ));
        assert!(!check(
            "Circle Of Life",
            "POST",
            "670fd8c2df070c60b045671b8b24ff02"
        ));
        assert!(!check(
            "CircleOfLife",
            "GET",
            "670fd8c2df070c60b045671b8b24ff02"
        ));
        assert!(!check(
            "Circle Of Life",
            "GET",
            "00000000000000000000000000000000"
        ));
        // One flipped hex digit and a truncated response both fail.
        assert!(!check(
            "Circle Of Life",
            "GET",
            "070fd8c2df070c60b045671b8b24ff02"
        ));
        assert!(!check(
            "Circle Of Life",
            "GET",
            "670fd8c2df070c60b045671b8b24ff0"
        ));
    }

    #[test]
    fn generate_nonce_is_hex_of_requested_length_and_random() {
        for len in [1, 8, 16, 32] {
            let n = generate_nonce(len);
            assert_eq!(n.len(), len);
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
        }
        // Lengths beyond the 32 hex digits of an MD5 are clamped.
        assert_eq!(generate_nonce(64).len(), 32);
        assert_ne!(generate_nonce(32), generate_nonce(32));
    }
}
