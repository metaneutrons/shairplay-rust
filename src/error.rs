//! Error types for the shairplay library.

use thiserror::Error;

/// Top-level error type for the shairplay library.
#[derive(Debug, Error)]
pub enum ShairplayError {
    /// Server or session error.
    #[error("server error: {0}")]
    Server(#[from] ServerError),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Network I/O or mDNS error.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// Protocol parsing error.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Audio codec error.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
}

/// Errors from the AirPlay server and session handling.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Server has not been started yet.
    #[error("server not started")]
    NotStarted,

    /// Server is already running.
    #[error("server already running")]
    AlreadyRunning,

    /// Maximum number of concurrent clients reached.
    #[error("max clients reached ({0})")]
    MaxClients(usize),

    /// Hardware address has invalid length (expected 6 bytes).
    #[error("invalid hardware address length: {0}")]
    InvalidHwAddr(usize),

    /// Password has invalid length.
    #[error("invalid password length: {0}")]
    InvalidPassword(usize),

    /// Audio handler returned an error.
    #[error("audio handler error: {0}")]
    AudioHandler(String),
}

/// Errors from cryptographic operations (RSA, pairing, FairPlay, AES).
#[derive(Debug, Error)]
pub enum CryptoError {
    /// RSA key loading or parsing failed.
    #[error("RSA key error: {0}")]
    RsaKey(String),

    /// RSA decryption failed (wrong key or corrupted data).
    #[error("RSA decryption failed")]
    RsaDecrypt,

    /// Pairing handshake failed (Ed25519/Curve25519 or SRP-6a).
    #[error("pairing handshake failed: {0}")]
    PairingHandshake(String),

    /// Pair-verify signature check failed.
    #[error("pairing verification failed")]
    PairingVerify,

    /// FairPlay DRM handshake failed.
    #[error("FairPlay handshake failed: {0}")]
    FairPlay(String),

    /// AES encryption/decryption error.
    #[error("AES error: {0}")]
    Aes(String),
}

/// Errors from networking (TCP/UDP sockets, mDNS registration).
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// mDNS service registration failed.
    #[error("mDNS registration failed: {0}")]
    Mdns(String),

    /// Failed to bind to the specified port.
    #[error("bind failed on port {0}")]
    Bind(u16),
}

/// Errors from protocol parsing (RTSP, SDP, plist, HTTP Digest).
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Malformed or unsupported RTSP request.
    #[error("invalid RTSP request: {0}")]
    InvalidRtsp(String),

    /// SDP session description parsing failed.
    #[error("SDP parse error: {0}")]
    Sdp(String),

    /// Binary plist parsing failed.
    #[error("plist parse error: {0}")]
    Plist(String),

    /// HTTP Digest authentication error.
    #[error("HTTP digest auth error: {0}")]
    DigestAuth(String),

    /// Request data is incomplete (need more bytes).
    #[error("incomplete request")]
    Incomplete,
}

/// Errors from audio codec operations (ALAC, AAC decoding).
#[derive(Debug, Error)]
pub enum CodecError {
    /// ALAC frame decoding failed.
    #[error("ALAC decode error: {0}")]
    AlacDecode(String),

    /// AAC frame decoding failed.
    #[error("AAC decode error: {0}")]
    AacDecode(String),

    /// Audio format not supported.
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
}
