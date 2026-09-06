//! HTTP/RTSP request and response parsing.

use std::collections::HashMap;

use crate::error::ProtocolError;

#[cfg(test)]
mod tests;

/// Maximum size accepted for RTSP/HTTP headers.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Maximum number of headers accepted or emitted by protocol diagnostics.
pub(crate) const MAX_HEADER_COUNT: usize = 64;
/// Maximum size accepted for a single request body.
pub(crate) const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Incremental RTSP/HTTP request parser. Equivalent to http_request.c.
/// Uses httparse internally instead of the joyent http_parser.
pub struct HttpRequest {
    buffer: Vec<u8>,
    request_line_start: Option<usize>,
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
            request_line_start: None,
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
        self.add_data_with_body_limit(data, |_| Ok(MAX_BODY_BYTES))
    }

    /// Consult the connection's policy exactly once, before retaining body bytes.
    pub(crate) fn add_data_with_body_limit(
        &mut self,
        data: &[u8],
        on_headers: impl FnOnce(&Self) -> Result<usize, ProtocolError>,
    ) -> Result<(), ProtocolError> {
        if let Some(error) = &self.error {
            return Err(ProtocolError::InvalidRtsp(error.clone()));
        }
        let result = self.ingest(data, on_headers);
        if let Err(error) = &result {
            self.error = Some(match error {
                ProtocolError::InvalidRtsp(message) => message.clone(),
                _ => error.to_string(),
            });
        }
        result
    }

    fn ingest(
        &mut self,
        mut data: &[u8],
        on_headers: impl FnOnce(&Self) -> Result<usize, ProtocolError>,
    ) -> Result<(), ProtocolError> {
        if self.complete {
            return Ok(());
        }
        if !self.headers_complete {
            // Keep coalesced bodies out of the header buffer and scan incrementally.
            while let Some((&byte, rest)) = data.split_first() {
                if self.buffer.len() == MAX_HEADER_BYTES {
                    return Err(ProtocolError::InvalidRtsp(
                        "request headers exceed 64 KiB".into(),
                    ));
                }
                if self.request_line_start.is_none() && !matches!(byte, b'\r' | b'\n') {
                    self.request_line_start = Some(self.buffer.len());
                }
                self.buffer.push(byte);
                data = rest;
                if self.request_line_start.is_some()
                    && (self.buffer.ends_with(b"\n\r\n") || self.buffer.ends_with(b"\n\n"))
                    && self.try_parse_headers()?
                {
                    let limit = on_headers(self)?.min(MAX_BODY_BYTES);
                    if self.content_length.unwrap_or(0) > limit {
                        return Err(ProtocolError::InvalidRtsp(
                            "request body exceeds connection policy".into(),
                        ));
                    }
                    break;
                }
            }
        }

        if self.headers_complete {
            let needed = self.content_length.unwrap_or(0);
            let accepted = data.len().min(needed - self.buffer.len());
            self.buffer.extend_from_slice(&data[..accepted]);
            if self.buffer.len() == needed {
                if needed != 0 {
                    self.body = Some(std::mem::take(&mut self.buffer));
                }
                self.complete = true;
                // Following bytes belong to the next pipelined request, not this body.
                self.buffer.extend_from_slice(&data[accepted..]);
            }
        }
        Ok(())
    }

    fn try_parse_headers(&mut self) -> Result<bool, ProtocolError> {
        // httparse accepts HTTP, so translate only the complete request-line version.
        // Leading empty lines are permitted by httparse; URI/header/body bytes stay intact.
        if let Some(start) = self.request_line_start {
            let line = self.buffer[start..]
                .split_mut(|byte| *byte == b'\n')
                .next()
                .unwrap();
            let end = line.len() - usize::from(line.ends_with(b"\r"));
            let line = &mut line[..end];
            if line.ends_with(b" RTSP/1.0") {
                let start = line.len() - 8;
                line[start..start + 4].copy_from_slice(b"HTTP");
            }
        }

        let mut header_buf = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
        let mut req = httparse::Request::new(&mut header_buf);

        match req.parse(&self.buffer) {
            Ok(httparse::Status::Complete(body_offset)) => {
                self.method = req.method.map(|m| m.to_string());
                self.url = req.path.map(|p| p.to_string());

                for h in req.headers.iter() {
                    let name = h.name.to_ascii_lowercase();
                    if name == "transfer-encoding" {
                        return Err(ProtocolError::InvalidRtsp(
                            "transfer framing is unsupported".into(),
                        ));
                    }
                    if matches!(name.as_str(), "content-length" | "content-type")
                        && self.headers.contains_key(&name)
                    {
                        return Err(ProtocolError::InvalidRtsp("duplicate body metadata".into()));
                    }
                    self.headers
                        .insert(name, String::from_utf8_lossy(h.value).to_string());
                }

                self.content_length = self
                    .headers
                    .get("content-length")
                    .map(|value| {
                        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                            return Err(ProtocolError::InvalidRtsp(
                                "invalid Content-Length".into(),
                            ));
                        }
                        value.parse::<usize>().map_err(|_| {
                            ProtocolError::InvalidRtsp("Content-Length overflow".into())
                        })
                    })
                    .transpose()?;
                if self.content_length.unwrap_or(0) > MAX_BODY_BYTES {
                    return Err(ProtocolError::InvalidRtsp(
                        "request body exceeds 32 MiB".into(),
                    ));
                }

                self.headers_complete = true;

                debug_assert_eq!(body_offset, self.buffer.len());
                self.buffer.clear();

                Ok(true)
            }
            Ok(httparse::Status::Partial) => Ok(false),
            Err(e) => Err(ProtocolError::InvalidRtsp(e.to_string())),
        }
    }

    /// Return any bytes in the buffer beyond the complete request.
    pub(crate) fn take_leftover(&mut self) -> Vec<u8> {
        if !self.complete {
            return Vec::new();
        }
        std::mem::take(&mut self.buffer)
    }

    /// Whether a complete HTTP request has been parsed.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Whether all headers have been parsed (body may still be pending).
    pub(crate) fn headers_complete(&self) -> bool {
        self.headers_complete
    }

    /// The HTTP method (GET, POST, SETUP, etc.).
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    /// The request URL/path.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Get a header value by name. Header lookup is ASCII case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    /// Iterate over parsed headers for the transport diagnostics layer.
    #[cfg(feature = "diagnostic-headers")]
    pub(crate) fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// The request body, if present.
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
        let status_line = format!("{protocol} {code} {message}\r\n");
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
            let len_str = body.len().to_string();
            self.data.extend_from_slice(b"Content-Length: ");
            self.data.extend_from_slice(len_str.as_bytes());
            self.data.extend_from_slice(b"\r\n\r\n");
            self.data.extend_from_slice(body);
        } else {
            self.data.extend_from_slice(b"\r\n");
        }
        self.complete = true;
    }

    /// Set a binary property list body, automatically adding the Content-Type header.
    #[cfg(feature = "ap2")]
    pub(crate) fn set_plist_body(&mut self, plist_dict: &plist::Dictionary) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, plist_dict).ok()?;
        self.add_header("Content-Type", "application/x-apple-binary-plist");
        Some(buf)
    }

    /// Mark this response as requiring connection close after sending.
    pub fn set_disconnect(&mut self, disconnect: bool) {
        self.disconnect = disconnect;
    }

    /// The HTTP status code.
    pub(crate) fn status_code(&self) -> u16 {
        self.code
    }

    /// Whether the connection should be closed after this response.
    pub fn get_disconnect(&self) -> bool {
        self.disconnect
    }

    /// Get the serialized response bytes. Equivalent to http_response_get_data.
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}

impl Default for HttpRequest {
    fn default() -> Self {
        Self::new()
    }
}
