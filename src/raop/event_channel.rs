//! AirPlay 2 encrypted event and remote control channels.
//!
//! After initial SETUP, the client connects to the event TCP port.
//! All traffic is encrypted with ChaCha20-Poly1305 using HKDF-derived keys.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::crypto::chacha_transport::EncryptedChannel;
use crate::error::NetworkError;

/// Handle for sending commands through the event channel.
#[derive(Clone)]
pub(crate) struct EventSender {
    // Load-bearing AND the outbound channel: holding this keeps the mpsc open for
    // the connection's lifetime (stored in `RaopConnection::event_sender`), and
    // `send()` pushes events through it. Currently unwired beyond the initial
    // `updateInfo` queued at SETUP — see AP2-STATUS.md.
    #[allow(dead_code)]
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl EventSender {
    /// Create from an existing channel sender.
    pub(crate) fn from_tx(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }

    /// Push an event to the controller over the encrypted AP2 event channel.
    ///
    /// Scaffolding for receiver-initiated outbound events (volume, now-playing,
    /// progress). Today only the initial `updateInfo` is sent at SETUP time via
    /// the raw channel sender; wiring this on receiver-side state changes would
    /// enable fuller AP2 event reporting. Unwired — see AP2-STATUS.md.
    #[allow(dead_code)] // unwired outbound-event API — see AP2-STATUS.md
    pub(crate) fn send(&self, data: Vec<u8>) -> Result<(), NetworkError> {
        self.tx
            .send(data)
            .map_err(|_| NetworkError::Mdns("event channel closed".into()))
    }
}

/// Async event channel that accepts one encrypted TCP connection.
pub(crate) struct EventChannel;

impl EventChannel {
    /// Handle a connected event channel stream (public for use from handlers).
    pub(crate) async fn handle_stream(
        stream: TcpStream,
        channel: EncryptedChannel,
        cmd_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        Self::handle(stream, channel, cmd_rx).await;
    }

    async fn handle(
        mut stream: TcpStream,
        mut channel: EncryptedChannel,
        mut cmd_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let mut buf = vec![0u8; 4096];
        let mut encrypted_buf = Vec::new();
        loop {
            tokio::select! {
                result = stream.read(&mut buf) => {
                    match result {
                        Ok(0) => { debug!("Event channel closed by client"); break; }
                        Ok(n) => {
                            encrypted_buf.extend_from_slice(&buf[..n]);
                            debug!(n, "Event channel data received");
                            match channel.decrypt_ctx.decrypt(&encrypted_buf) {
                                Ok((plain, consumed)) => {
                                    if consumed > 0 { encrypted_buf.drain(..consumed); }
                                    if !plain.is_empty() {
                                        debug!(len = plain.len(), "Event channel message received");
                                    }
                                }
                                Err(e) => { warn!("Event channel decrypt error: {e}"); }
                            }
                        }
                        Err(e) => { warn!("Event channel read error: {e}"); break; }
                    }
                }
                Some(data) = cmd_rx.recv() => {
                    debug!(len = data.len(), "Sending on event channel");
                    let encrypted = match channel.encrypt_ctx.encrypt(&data) {
                        Ok(e) => e,
                        Err(e) => { warn!("Event channel encrypt error: {e}"); break; }
                    };
                    if let Err(e) = stream.write_all(&encrypted).await {
                        warn!("Event channel write error: {e}"); break;
                    }
                }
            }
        }
    }
}
