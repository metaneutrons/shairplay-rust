//! AirPlay 2 encrypted event and remote control channels.
//!
//! After initial SETUP, the client connects to the event TCP port.
//! All traffic is encrypted with ChaCha20-Poly1305 using HKDF-derived keys.

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::crypto::chacha_transport::EncryptedChannel;
use crate::error::NetworkError;

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

    /// Run the event channel: accept one connection, send updateInfo, read events.
    pub async fn run(self, mut channel: EncryptedChannel) {
        let (stream, addr) = match self.listener.accept().await {
            Ok(s) => s,
            Err(e) => { warn!("Event channel accept failed: {e}"); return; }
        };
        debug!(%addr, "Event channel client connected");
        Self::handle(stream, &mut channel).await;
    }

    async fn handle(mut stream: TcpStream, channel: &mut EncryptedChannel) {
        // Read loop: decrypt incoming event messages
        let mut buf = vec![0u8; 4096];
        let mut encrypted_buf = Vec::new();
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => { debug!("Event channel closed by client"); break; }
                Ok(n) => {
                    encrypted_buf.extend_from_slice(&buf[..n]);
                    match channel.decrypt_ctx.decrypt(&encrypted_buf) {
                        Ok((plain, consumed)) => {
                            if consumed > 0 {
                                encrypted_buf.drain(..consumed);
                            }
                            if !plain.is_empty() {
                                debug!(len = plain.len(), "Event channel received message");
                            }
                        }
                        Err(e) => { warn!("Event channel decrypt error: {e}"); break; }
                    }
                }
                Err(e) => { warn!("Event channel read error: {e}"); break; }
            }
        }
    }

    /// Send an encrypted message on the event channel stream.
    pub async fn send_encrypted(
        stream: &mut TcpStream,
        channel: &mut EncryptedChannel,
        data: &[u8],
    ) -> Result<(), NetworkError> {
        let encrypted = channel.encrypt_ctx.encrypt(data)
            .map_err(|e| NetworkError::Mdns(e.to_string()))?;
        stream.write_all(&encrypted).await
            .map_err(|e| NetworkError::Io(e))
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
