//! Async TCP server with TLS-like encrypt/decrypt hooks for RTSP connections.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};

use crate::error::NetworkError;
use crate::proto::http::{HttpRequest, HttpResponse};

/// Controls how the server binds to network addresses.
///
/// # Examples
/// ```
/// use shairplay::BindConfig;
/// use std::net::IpAddr;
///
/// // Bind to all interfaces (default)
/// let config = BindConfig::default();
///
/// // Bind to a specific IPv4 address
/// let config = BindConfig::new().addrs(["192.168.1.100".parse().unwrap()]);
///
/// // Bind to specific IPv4 + IPv6
/// let config = BindConfig::new()
///     .addrs(["192.168.1.100".parse().unwrap(), "fd00::1".parse().unwrap()]);
///
/// // Bind to a specific port
/// let config = BindConfig::new().port(7000);
/// ```
#[derive(Debug, Clone)]
pub struct BindConfig {
    /// IP addresses to bind to. Empty = bind to all interfaces (0.0.0.0 + \[::\]).
    pub bind_addrs: Vec<IpAddr>,
    /// Port number. Used as starting port for auto-sensing, or exact port if `auto_port` is false.
    pub port: u16,
    /// If true (default), try incrementing ports if the requested port is busy.
    pub auto_port: bool,
}

impl Default for BindConfig {
    fn default() -> Self {
        Self { bind_addrs: Vec::new(), port: 5000, auto_port: true }
    }
}

impl BindConfig {
    /// Create a new default bind configuration.
    pub fn new() -> Self { Self::default() }

    /// Set specific addresses to bind to. Replaces any previous addresses.
    pub fn addrs(mut self, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.bind_addrs = addrs.into_iter().collect();
        self
    }

    /// Set the port number.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Disable port auto-sensing (fail if exact port is unavailable).
    pub fn exact_port(mut self) -> Self {
        self.auto_port = false;
        self
    }
}

/// Callback trait for HTTP/RTSP connection lifecycle. Equivalent to httpd_callbacks_t.
pub trait HttpdCallbacks: Send + Sync + 'static {
    /// Called when a new TCP connection is accepted. Return a handler or None to reject.
    fn conn_init(&self, local: SocketAddr, remote: SocketAddr) -> Option<Box<dyn ConnectionHandler>>;
}

/// Per-connection request handler. Equivalent to conn_request + conn_destroy.
pub trait ConnectionHandler: Send {
    /// Handle an HTTP/RTSP request and return the response.
    fn conn_request(&mut self, request: &HttpRequest) -> HttpResponse;

    /// Decrypt incoming raw bytes. Returns decrypted data and bytes consumed.
    /// Default: passthrough (no encryption).
    fn decrypt_incoming(&mut self, data: &[u8]) -> Option<(Vec<u8>, usize)> {
        Some((data.to_vec(), data.len()))
    }

    /// Encrypt outgoing response bytes. Default: passthrough.
    fn encrypt_outgoing(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    /// Whether the connection is in encrypted mode.
    fn is_encrypted(&self) -> bool { false }

    /// Called after a response is written. Activates pending encryption.
    fn after_response(&mut self) {}
}

/// Async TCP server supporting IPv4 and IPv6. Equivalent to httpd_t.
pub struct HttpServer {
    callbacks: Arc<dyn HttpdCallbacks>,
    max_connections: usize,
    shutdown_tx: Option<watch::Sender<bool>>,
    port: u16,
    running: bool,
    bind_config: BindConfig,
}

impl HttpServer {
    /// Create a new HTTP server with the given callbacks and connection limit.
    pub fn new(callbacks: Arc<dyn HttpdCallbacks>, max_connections: usize) -> Self {
        Self {
            callbacks,
            max_connections,
            shutdown_tx: None,
            port: 0,
            running: false,
            bind_config: BindConfig::default(),
        }
    }

    /// Set the bind configuration (addresses, port, auto-sensing).
    pub fn set_bind_config(&mut self, config: BindConfig) {
        self.bind_config = config;
    }

    /// Start listening. Returns the actual port (may differ if auto-sensing).
    pub async fn start(&mut self, port: u16) -> Result<u16, NetworkError> {
        if self.running {
            return Ok(self.port);
        }

        let bind_port = if port > 0 { port } else { self.bind_config.port };
        let auto_port = self.bind_config.auto_port;

        // Determine bind addresses
        let addrs: Vec<IpAddr> = if self.bind_config.bind_addrs.is_empty() {
            // Default: all IPv4 + all IPv6
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::UNSPECIFIED)]
        } else {
            self.bind_config.bind_addrs.clone()
        };

        // Bind first listener (with optional port auto-sensing)
        let first = bind_listener(addrs[0], bind_port, auto_port).await?;
        let actual_port = first.local_addr()?.port();

        // Bind remaining listeners on the same port (no auto-sensing)
        let mut listeners = vec![first];
        for &addr in &addrs[1..] {
            match bind_listener(addr, actual_port, false).await {
                Ok(l) => listeners.push(l),
                Err(e) => tracing::warn!(%addr, "Failed to bind additional listener: {e}"),
            }
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        self.port = actual_port;
        self.running = true;

        let callbacks = self.callbacks.clone();
        let semaphore = Arc::new(Semaphore::new(self.max_connections));

        for listener in listeners {
            let addr = listener.local_addr().unwrap();
            tracing::debug!(%addr, "Listener bound");
            spawn_accept_loop(listener, callbacks.clone(), semaphore.clone(), shutdown_rx.clone());
        }

        Ok(actual_port)
    }

    /// Whether the server is currently accepting connections.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// The actual port the server is listening on (after auto-sensing).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Stop the server and close all listeners.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        self.running = false;
    }
}

/// Try to bind a TCP listener, optionally auto-incrementing the port.
async fn bind_listener(addr: IpAddr, start_port: u16, auto_port: bool) -> Result<TcpListener, NetworkError> {
    let mut port = start_port;
    loop {
        match TcpListener::bind(SocketAddr::new(addr, port)).await {
            Ok(listener) => return Ok(listener),
            Err(_e) if auto_port && port < start_port.saturating_add(100) => {
                port += 1;
            }
            Err(e) => return Err(NetworkError::Io(e)),
        }
    }
}
/// Spawn a tokio task that accepts connections on the given listener.
fn spawn_accept_loop(
    listener: TcpListener,
    callbacks: Arc<dyn HttpdCallbacks>,
    semaphore: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, remote) = match result {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    tracing::info!(%remote, "New connection");
                    let local = match stream.local_addr() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => { tracing::warn!("Max connections reached"); continue; }
                    };
                    let cb = callbacks.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let mut handler = match cb.conn_init(local, remote) {
                            Some(h) => h,
                            None => return,
                        };
                        let mut stream = stream;
                        let mut buf = [0u8; 4096];
                        let mut request = HttpRequest::new();
                        let mut raw_buf = Vec::new(); // accumulates encrypted data

                        loop {
                            // Handle complete requests
                            while request.is_complete() {
                                let method = request.method().unwrap_or("?").to_string();
                                let url = request.url().unwrap_or("?").to_string();
                                tracing::debug!(%method, %url, body_len = request.data().map(|d| d.len()).unwrap_or(0), "RTSP request");
                                let response = handler.conn_request(&request);
                                let status = response.status_code();
                                tracing::debug!(%method, %url, status, "RTSP response");
                                let disconnect = response.get_disconnect();
                                let raw_out = response.get_data();
                                let wire_out = if handler.is_encrypted() {
                                    handler.encrypt_outgoing(raw_out)
                                } else {
                                    raw_out.to_vec()
                                };
                                if stream.write_all(&wire_out).await.is_err() {
                                    return;
                                }
                                handler.after_response();
                                if disconnect {
                                    let _ = stream.shutdown().await;
                                    return;
                                }
                                let leftover = request.take_leftover();
                                request = HttpRequest::new();
                                if !leftover.is_empty() && request.add_data(&leftover).is_err() {
                                    return;
                                }
                            }

                            // Read from network
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };

                            // Decrypt if encrypted, otherwise feed directly
                            if handler.is_encrypted() {
                                raw_buf.extend_from_slice(&buf[..n]);
                                if raw_buf.len() > 1024 * 1024 {
                                    tracing::warn!("Encrypted buffer exceeded 1 MB, dropping connection");
                                    break;
                                }
                                tracing::trace!(encrypted = true, raw_len = raw_buf.len(), new_bytes = n, "Read");
                                match handler.decrypt_incoming(&raw_buf) {
                                    Some((plain, consumed)) => {
                                        tracing::trace!(plain_len = plain.len(), consumed, "Decrypt");
                                        if consumed > 0 {
                                            raw_buf.drain(..consumed);
                                        }
                                        if !plain.is_empty() {
                                            tracing::trace!("Decrypted: {:?}", String::from_utf8_lossy(&plain[..plain.len().min(120)]));
                                            if request.add_data(&plain).is_err() {
                                                tracing::warn!("HTTP parse error on decrypted data");
                                                break;
                                            }
                                            tracing::trace!(complete = request.is_complete(), headers_complete = request.headers_complete(), "After add_data");
                                        }
                                    }
                                    None => {
                                        tracing::warn!("Decryption failed, raw_buf first bytes: {:02x?}", &raw_buf[..raw_buf.len().min(16)]);
                                        break;
                                    }
                                }
                            } else {
                                tracing::trace!(encrypted = false, n, "Read (plaintext)");
                                if request.add_data(&buf[..n]).is_err() {
                                    tracing::warn!("HTTP parse error, first bytes: {:02x?}", &buf[..n.min(32)]);
                                    break;
                                }
                            }
                        }
                        tracing::info!(%remote, "Connection closed");
                    });
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    });
}
