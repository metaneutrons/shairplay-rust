use thiserror::Error;

/// Top-level error type for the shairplay library.
#[derive(Debug, Error)]
/// Top-level error type for the shairplay library.
pub enum ShairplayError {
    #[error("RAOP error: {0}")]
    Raop(#[from] RaopError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
}

/// Errors from the RAOP server and session handling.
#[derive(Debug, Error)]
/// Errors from the RAOP server and session handling.
pub enum RaopError {
    #[error("server not started")]
    NotStarted,

    #[error("server already running")]
    AlreadyRunning,

    #[error("max clients reached ({0})")]
    MaxClients(usize),

    #[error("invalid hardware address length: {0}")]
    InvalidHwAddr(usize),

    #[error("invalid password length: {0}")]
    InvalidPassword(usize),

    #[error("audio handler error: {0}")]
    AudioHandler(String),
}

/// Errors from cryptographic operations.
#[derive(Debug, Error)]
/// Errors from cryptographic operations (RSA, pairing, FairPlay, AES).
pub enum CryptoError {
    #[error("RSA key error: {0}")]
    RsaKey(String),

    #[error("RSA decryption failed")]
    RsaDecrypt,

    #[error("pairing handshake failed: {0}")]
    PairingHandshake(String),

    #[error("pairing verification failed")]
    PairingVerify,

    #[error("FairPlay handshake failed: {0}")]
    FairPlay(String),

    #[error("AES error: {0}")]
    Aes(String),
}

/// Errors from networking (TCP/UDP, mDNS).
#[derive(Debug, Error)]
/// Errors from networking (TCP/UDP sockets, mDNS registration).
pub enum NetworkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("mDNS registration failed: {0}")]
    Mdns(String),

    #[error("bind failed on port {0}")]
    Bind(u16),
}

/// Errors from protocol parsing (RTSP, SDP, plist, HTTP digest).
#[derive(Debug, Error)]
/// Errors from protocol parsing (RTSP, SDP, plist, HTTP Digest).
pub enum ProtocolError {
    #[error("invalid RTSP request: {0}")]
    InvalidRtsp(String),

    #[error("SDP parse error: {0}")]
    Sdp(String),

    #[error("plist parse error: {0}")]
    Plist(String),

    #[error("HTTP digest auth error: {0}")]
    DigestAuth(String),

    #[error("incomplete request")]
    Incomplete,
}

/// Errors from audio codec operations.
#[derive(Debug, Error)]
/// Errors from audio codec operations (ALAC decoding).
pub enum CodecError {
    #[error("ALAC decode error: {0}")]
    AlacDecode(String),

    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
}
