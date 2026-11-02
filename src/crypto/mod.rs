//! Cryptographic primitives for AirPlay authentication and encryption.

pub mod aes;
#[cfg(feature = "fairplay")]
pub mod fairplay;
#[cfg(feature = "fairplay")]
mod fairplay_data;
#[cfg(feature = "fairplay")]
mod fairplay_garble;
pub mod pairing;
pub mod rsa;

#[cfg(feature = "ap2")]
pub mod chacha_transport;
#[cfg(feature = "ap2")]
pub mod pairing_homekit;
#[cfg(feature = "ap2")]
pub mod tlv;
#[cfg(feature = "video")]
pub mod video_cipher;
#[cfg(feature = "video")]
pub mod video_key;
