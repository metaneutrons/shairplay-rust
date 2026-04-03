use std::collections::HashMap;
use std::fmt::Write;

use crate::error::ProtocolError;

/// Incremental RTSP/HTTP request parser. Equivalent to http_request.c.
/// Uses httparse internally instead of the joyent http_parser.
pub struct HttpRequest {
    buffer: Vec<u8>,
    method: Option<String>,
    url: Option<String>,
    headers: HashMap<String, String>,
    body: Option<Vec<u8>>,
    content_length: Option<usize>,
    headers_complete: bool,
    complete: bool,
    error: Option<String>,
}

impl HttpRequest {
    /// Create a new empty request parser. Equivalent to http_request_init.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            method: None,
            url: None,
            headers: HashMap::new(),
            body: None,
            content_length: None,
            headers_complete: false,
            complete: false,
            error: None,
        }
    }

    /// Feed data into the parser. Equivalent to http_request_add_data.
    pub fn add_data(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        if self.complete {
            return Ok(());
        }
        self.buffer.extend_from_slice(data);

        if !self.headers_complete {
            self.try_parse_headers()?;
        }

        if self.headers_complete {
            self.try_complete_body();
        }

        Ok(())
    }

    fn try_parse_headers(&mut self) -> Result<(), ProtocolError> {
        // httparse only accepts HTTP/1.x — Apple devices send RTSP/1.0.
        // Replace RTSP/1.0 with HTTP/1.0 in the buffer before parsing.
        let mut parse_buf = self.buffer.clone();
        if let Some(pos) = parse_buf.windows(8).position(|w| w == b"RTSP/1.0") {
            parse_buf[pos..pos + 4].copy_from_slice(b"HTTP");
        }

        let mut header_buf = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut header_buf);

        match req.parse(&parse_buf) {
            Ok(httparse::Status::Complete(body_offset)) => {
                self.method = req.method.map(|m| m.to_string());
                self.url = req.path.map(|p| p.to_string());

                for h in req.headers.iter() {
                    self.headers.insert(
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    );
                }

                // Extract Content-Length
                self.content_length = self
                    .headers
                    .get("Content-Length")
                    .and_then(|v| v.parse::<usize>().ok());

                self.headers_complete = true;

                // Keep only the body portion in the buffer
                let remaining = self.buffer[body_offset..].to_vec();
                self.buffer = remaining;

                Ok(())
            }
            Ok(httparse::Status::Partial) => Ok(()),
            Err(e) => {
                let msg = format!("{}", e);
                self.error = Some(msg.clone());
                Err(ProtocolError::InvalidRtsp(msg))
            }
        }
    }

    fn try_complete_body(&mut self) {
        let needed = self.content_length.unwrap_or(0);
        if self.buffer.len() >= needed {
            if needed > 0 {
                self.body = Some(self.buffer[..needed].to_vec());
            }
            self.complete = true;
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Get a header value by name (case-sensitive, matching C behavior).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }

    pub fn data(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }
}

/// RTSP/HTTP response builder. Equivalent to http_response.c.
pub struct HttpResponse {
    data: Vec<u8>,
    complete: bool,
    disconnect: bool,
    code: u16,
}

impl HttpResponse {
    /// Create a new response with status line. Equivalent to http_response_init.
    pub fn new(protocol: &str, code: u16, message: &str) -> Self {
        let mut data = Vec::with_capacity(1024);
        let status_line = format!("{} {} {}\r\n", protocol, code, message);
        data.extend_from_slice(status_line.as_bytes());
        Self {
            data,
            complete: false,
            disconnect: false,
            code,
        }
    }

    /// Add a header. Equivalent to http_response_add_header.
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.data.extend_from_slice(name.as_bytes());
        self.data.extend_from_slice(b": ");
        self.data.extend_from_slice(value.as_bytes());
        self.data.extend_from_slice(b"\r\n");
    }

    /// Finalize the response with optional body data.
    /// Equivalent to http_response_finish.
    pub fn finish(&mut self, body: Option<&[u8]>) {
        if let Some(body) = body.filter(|b| !b.is_empty()) {
            let mut len_str = String::new();
            write!(len_str, "{}", body.len()).unwrap();
            self.data.extend_from_slice(b"Content-Length: ");
            self.data.extend_from_slice(len_str.as_bytes());
            self.data.extend_from_slice(b"\r\n\r\n");
            self.data.extend_from_slice(body);
        } else {
            self.data.extend_from_slice(b"\r\n");
        }
        self.complete = true;
    }

    pub fn set_disconnect(&mut self, disconnect: bool) {
        self.disconnect = disconnect;
    }

    pub fn status_code(&self) -> u16 { self.code }

    pub fn get_disconnect(&self) -> bool {
        self.disconnect
    }

    /// Get the serialized response bytes. Equivalent to http_response_get_data.
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}

impl Default for HttpRequest {
    fn default() -> Self { Self::new() }
}
