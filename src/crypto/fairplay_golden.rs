//! Golden-vector test for the FairPlay key decryption.
//!
//! The vectors in `tests/data/fairplay_golden.txt` were produced by running the
//! C reference on pseudo-random inputs. The test only uses the public behaviour
//! (`handshake`, then `decrypt`), so it holds for any implementation behind it.

use crate::crypto::fairplay::FairPlay;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn decrypt_matches_reference_vectors() {
    let data = include_str!("../../tests/data/fairplay_golden.txt");
    let mut checked = 0;
    for line in data
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let mut cols = line.split(' ');
        let message: [u8; 164] = unhex(cols.next().unwrap()).try_into().unwrap();
        let cipher: [u8; 72] = unhex(cols.next().unwrap()).try_into().unwrap();
        let expected: [u8; 16] = unhex(cols.next().unwrap()).try_into().unwrap();

        let mut fp = FairPlay::new();
        fp.handshake(&message).expect("handshake");
        let key = fp.decrypt(&cipher).expect("decrypt");
        assert_eq!(key, expected, "vector {checked}, mode {}", message[12]);
        checked += 1;
    }
    assert_eq!(checked, 256);
}
