use md5::{Digest, Md5};
use rand::Rng;

fn md5_to_hex(hash: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for &b in hash {
        s.push_str(&format!("{:02x}", b));
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
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
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
    response == our_response
}

/// Extract a quoted value from a "key=\"value\"" pair.
fn extract_quoted<'a>(part: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{}=\"", key);
    if part.starts_with(&prefix) && part.ends_with('"') {
        Some(&part[prefix.len()..part.len() - 1])
    } else {
        None
    }
}
