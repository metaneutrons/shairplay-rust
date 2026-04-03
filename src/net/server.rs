use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};

use crate::error::NetworkError;
use crate::proto::http::{HttpRequest, HttpResponse};

/// Controls how the server binds to network addresses.
#[derive(Debug, Clone)]
pub struct BindConfig {
    /// IP address to bind to. `None` = bind to all interfaces (0.0.0.0 / [::]).
    pub addr: Option<IpAddr>,
    /// Port number. Used as starting port for auto-sensing, or exact port if `auto_port` is false.
    pub port: u16,
    /// If true (default), try incrementing ports if the requested port is busy.
    /// If false, fail immediately if the exact port is unavailable.
    pub auto_port: bool,
    /// Enable IPv6 listener (in addition to IPv4). Ignored if `addr` is set to a specific IP.
    pub ipv6: bool,
}

impl Default for BindConfig {
    fn default() -> Self {
        Self { addr: None, port: 5000, auto_port: true, ipv6: true }
    }
}

/// Callback trait for HTTP/RTSP connection lifecycle. Equivalent to httpd_callbacks_t.
pub trait HttpdCallbacks: Send + Sync + 'static {
    fn conn_init(&self, local: SocketAddr, remote: SocketAddr) -> Option<Box<dyn ConnectionHandler>>;
}

/// Per-connection request handler. Equivalent to conn_request + conn_destroy.
pub trait ConnectionHandler: Send {
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

    pub fn set_bind_config(&mut self, config: BindConfig) {
        self.bind_config = config;
    }

    pub async fn start(&mut self, port: u16) -> Result<u16, NetworkError> {
        if self.running {
            return Ok(self.port);
        }

        let bind_port = if port > 0 { port } else { self.bind_config.port };
        let bind_ip = self.bind_config.addr;
        let auto_port = self.bind_config.auto_port;
        let enable_ipv6 = self.bind_config.ipv6;

        // Determine bind addresses
        let is_specific_ip = bind_ip.is_some();
        let ipv4_addr = bind_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let is_ipv6_addr = matches!(ipv4_addr, IpAddr::V6(_));

        // Try binding, with optional port auto-sensing
        let listener4 = if !is_ipv6_addr {
            Some(bind_listener(ipv4_addr, bind_port, auto_port).await?)
        } else {
            None
        };

        let actual_port = if let Some(ref l) = listener4 {
            l.local_addr()?.port()
        } else {
            bind_port
        };

        // IPv6 listener: only if enabled and not binding to a specific IPv4 address
        let listener6 = if enable_ipv6 && !is_specific_ip && !is_ipv6_addr {
            bind_listener(IpAddr::V6(Ipv6Addr::UNSPECIFIED), actual_port, false).await.ok()
        } else if is_ipv6_addr {
            Some(bind_listener(ipv4_addr, bind_port, auto_port).await?)
        } else {
            None
        };

        let final_port = listener4.as_ref()
            .or(listener6.as_ref())
            .map(|l| l.local_addr().unwrap().port())
            .unwrap_or(bind_port);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        self.port = final_port;
        self.running = true;

        let callbacks = self.callbacks.clone();
        let semaphore = Arc::new(Semaphore::new(self.max_connections));

        if let Some(l4) = listener4 {
            spawn_accept_loop(l4, callbacks.clone(), semaphore.clone(), shutdown_rx.clone());
        }
        if let Some(l6) = listener6 {
            spawn_accept_loop(l6, callbacks, semaphore, shutdown_rx);
        }

        Ok(final_port)
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn port(&self) -> u16 {
        self.port
    }

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
                        let mut pending = Vec::new();
                        let mut raw_buf = Vec::new(); // accumulates encrypted data

                        loop {
                            // Try to parse pending decrypted data
                            if !pending.is_empty() {
                                if request.add_data(&pending).is_err() {
                                    tracing::warn!("HTTP parse error on pending data");
                                    break;
                                }
                                pending.clear();
                            }

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
                                if disconnect {
                                    let _ = stream.shutdown().await;
                                    return;
                                }
                                let leftover = request.take_leftover();
                                request = HttpRequest::new();
                                if !leftover.is_empty() {
                                    if request.add_data(&leftover).is_err() {
                                        return;
                                    }
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
                                match handler.decrypt_incoming(&raw_buf) {
                                    Some((plain, consumed)) => {
                                        if consumed > 0 {
                                            raw_buf.drain(..consumed);
                                        }
                                        if !plain.is_empty() {
                                            if request.add_data(&plain).is_err() {
                                                tracing::warn!("HTTP parse error on decrypted data");
                                                break;
                                            }
                                        }
                                    }
                                    None => {
                                        tracing::warn!("Decryption failed");
                                        break;
                                    }
                                }
                            } else {
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
