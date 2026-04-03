//! AirPlay 2 encrypted event and remote control channels.
//!
//! After initial SETUP, the client connects to the event TCP port.
//! All traffic is encrypted with ChaCha20-Poly1305 using HKDF-derived keys.

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::crypto::chacha_transport::EncryptedChannel;
use crate::error::NetworkError;

/// Handle for sending commands through the event channel.
#[derive(Clone)]
pub struct EventSender {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl EventSender {
    /// Create from an existing channel sender.
    pub fn from_tx(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }

    /// Send a plaintext message (will be encrypted before transmission).
    pub fn send(&self, data: Vec<u8>) -> Result<(), NetworkError> {
        self.tx.send(data).map_err(|_| NetworkError::Mdns("event channel closed".into()))
    }
}

/// Async event channel that accepts one encrypted TCP connection.
pub struct EventChannel {
    listener: TcpListener,
    pub port: u16,
}

impl EventChannel {
    /// Bind a TCP listener on any available port.
    pub async fn bind() -> Result<Self, NetworkError> {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        debug!(port, "Event channel listening");
        Ok(Self { listener, port })
    }

    /// Run the event channel. Returns an EventSender for sending commands.
    pub async fn run(self, mut channel: EncryptedChannel) -> EventSender {
        let (tx, rx) = mpsc::unbounded_channel();
        let sender = EventSender { tx };

        let (stream, addr) = match self.listener.accept().await {
            Ok(s) => s,
            Err(e) => { warn!("Event channel accept failed: {e}"); return sender; }
        };
        info!(%addr, "Event channel client connected");

        tokio::spawn(Self::handle(stream, channel, rx));
        sender
    }

    /// Handle a connected event channel stream (public for use from handlers).
    pub async fn handle_stream(
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
                            info!(n, total=encrypted_buf.len(), "Event channel raw bytes received");
                            match channel.decrypt_ctx.decrypt(&encrypted_buf) {
                                Ok((plain, consumed)) => {
                                    if consumed > 0 { encrypted_buf.drain(..consumed); }
                                    if !plain.is_empty() {
                                        debug!(len = plain.len(), "Event channel received");
                                        if let Ok(s) = std::str::from_utf8(&plain) {
                                            info!("Event channel text: {}", s);
                                        } else if let Ok(val) = plist::from_bytes::<plist::Value>(&plain) {
                                            info!("Event channel plist: {:?}", val);
                                        } else {
                                            info!("Event channel binary: {:02x?}", &plain[..plain.len().min(100)]);
                                        }
                                    } else {
                                        info!(consumed, buf_remaining=encrypted_buf.len(), "Event channel: decrypted empty");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::chacha_transport::CipherContext;

    #[tokio::test]
    async fn event_channel_binds() {
        let ch = EventChannel::bind().await.unwrap();
        assert!(ch.port > 0);
    }

    #[tokio::test]
    async fn event_channel_roundtrip() {
        let ch = EventChannel::bind().await.unwrap();
        let port = ch.port;

        let key = [0x42u8; 32];
        let server_channel = EncryptedChannel {
            encrypt_ctx: CipherContext::new(key),
            decrypt_ctx: CipherContext::new(key),
        };

        // Spawn server
        let handle = tokio::spawn(async move { ch.run(server_channel).await });

        // Client connects and sends encrypted data
        let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let mut client_enc = CipherContext::new(key);
        let encrypted = client_enc.encrypt(b"test event").unwrap();
        client.write_all(&encrypted).await.unwrap();

        // Close triggers server exit
        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
}
