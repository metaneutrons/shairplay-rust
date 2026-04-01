use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};

use crate::error::NetworkError;
use crate::proto::http::{HttpRequest, HttpResponse};

/// Callback trait for HTTP/RTSP connection lifecycle. Equivalent to httpd_callbacks_t.
pub trait HttpdCallbacks: Send + Sync + 'static {
    fn conn_init(&self, local: SocketAddr, remote: SocketAddr) -> Option<Box<dyn ConnectionHandler>>;
}

/// Per-connection request handler. Equivalent to conn_request + conn_destroy.
pub trait ConnectionHandler: Send {
    fn conn_request(&mut self, request: &HttpRequest) -> HttpResponse;
}

/// Async TCP server supporting IPv4 and IPv6. Equivalent to httpd_t.
pub struct HttpServer {
    callbacks: Arc<dyn HttpdCallbacks>,
    max_connections: usize,
    shutdown_tx: Option<watch::Sender<bool>>,
    port: u16,
    running: bool,
}

impl HttpServer {
    pub fn new(callbacks: Arc<dyn HttpdCallbacks>, max_connections: usize) -> Self {
        Self {
            callbacks,
            max_connections,
            shutdown_tx: None,
            port: 0,
            running: false,
        }
    }

    pub async fn start(&mut self, port: u16) -> Result<u16, NetworkError> {
        if self.running {
            return Ok(self.port);
        }

        let addr4 = format!("0.0.0.0:{}", port);
        let listener4 = TcpListener::bind(&addr4).await?;
        let actual_port = listener4.local_addr()?.port();

        // Try IPv6 on same port, non-fatal if it fails
        let listener6 = TcpListener::bind(format!("[::]:{}",actual_port)).await.ok();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        self.port = actual_port;
        self.running = true;

        let callbacks = self.callbacks.clone();
        let semaphore = Arc::new(Semaphore::new(self.max_connections));

        // Spawn accept loop for IPv4
        spawn_accept_loop(listener4, callbacks.clone(), semaphore.clone(), shutdown_rx.clone());

        // Spawn accept loop for IPv6 if available
        if let Some(l6) = listener6 {
            spawn_accept_loop(l6, callbacks, semaphore, shutdown_rx);
        }

        Ok(actual_port)
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        self.running = false;
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
                    let local = match stream.local_addr() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => continue, // max connections reached
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

                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            if request.add_data(&buf[..n]).is_err() {
                                break;
                            }
                            if !request.is_complete() {
                                continue;
                            }
                            let response = handler.conn_request(&request);
                            let disconnect = response.get_disconnect();
                            let data = response.get_data();
                            if stream.write_all(data).await.is_err() {
                                break;
                            }
                            if disconnect {
                                let _ = stream.shutdown().await;
                                break;
                            }
                            request = HttpRequest::new();
                        }
                        // handler dropped here = conn_destroy
                    });
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    });
}
