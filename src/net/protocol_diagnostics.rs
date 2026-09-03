//! Opt-in, structured RTSP header diagnostics.

use std::borrow::Cow;

use tracing::Level;

use crate::error::ServerError;
use crate::proto::http::{HttpRequest, HttpResponse, MAX_HEADER_COUNT};

pub(crate) const TRACE_TARGET: &str = "shairplay::protocol_headers";
#[cfg(feature = "dangerous-raw-headers")]
pub(crate) const RAW_RELEASE_ERROR: &str =
    "raw header diagnostics require a build with debug assertions enabled";

const REDACTED_VALUE: &str = "<redacted>";
const TRUNCATED_SUFFIX: &str = "<truncated>";
const MAX_REDACTED_VALUE_CHARS: usize = 512;

const ALLOWLISTED_HEADER_NAMES: &[&str] = &[
    "apple-jack-status",
    "audio-latency",
    "connection",
    "content-length",
    "content-type",
    "cseq",
    "public",
    "server",
    "user-agent",
];

/// Controls opt-in RTSP request and response header diagnostics.
///
/// Diagnostics are emitted as structured `TRACE` events under the
/// `shairplay::protocol_headers` target. Request bodies, response bodies, and
/// media payloads are never logged. The default is [`Disabled`](Self::Disabled).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderDiagnostics {
    /// Do not emit RTSP header diagnostics.
    #[default]
    Disabled,
    /// Emit allowlisted metadata and redact every other header value.
    Redacted,
    /// Emit all parsed header values.
    ///
    /// This mode is available only with the `dangerous-raw-headers` feature and
    /// is rejected by [`RaopServerBuilder::build`](crate::RaopServerBuilder::build)
    /// unless debug assertions are enabled. Logs can contain credentials,
    /// pairing material, stable identifiers, and other sensitive information.
    #[cfg(feature = "dangerous-raw-headers")]
    Raw,
}

impl HeaderDiagnostics {
    pub(crate) fn validate(self) -> Result<(), ServerError> {
        #[cfg(feature = "dangerous-raw-headers")]
        return self.validate_for_build(cfg!(debug_assertions));

        #[cfg(not(feature = "dangerous-raw-headers"))]
        Ok(())
    }

    #[cfg(feature = "dangerous-raw-headers")]
    fn validate_for_build(self, debug_assertions: bool) -> Result<(), ServerError> {
        if self == Self::Raw && !debug_assertions {
            return Err(ServerError::InvalidConfiguration(RAW_RELEASE_ERROR));
        }
        Ok(())
    }

    pub(crate) fn warn_if_raw(self) {
        #[cfg(feature = "dangerous-raw-headers")]
        if self == Self::Raw {
            tracing::warn!(
                target: TRACE_TARGET,
                "raw RTSP header diagnostics are enabled; logs may contain credentials and identifiers"
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RenderedValue<'a> {
    value: Cow<'a, str>,
    redacted: bool,
    truncated: bool,
}

pub(crate) fn trace_request(policy: HeaderDiagnostics, request: &HttpRequest, encrypted: bool) {
    if policy == HeaderDiagnostics::Disabled
        || !tracing::enabled!(target: TRACE_TARGET, Level::TRACE)
    {
        return;
    }

    let mut headers: Vec<_> = request.headers().collect();
    headers.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let total = headers.len();
    for (header_index, (name, value)) in headers.into_iter().take(MAX_HEADER_COUNT).enumerate() {
        let name = escape_control_chars(name);
        let rendered = render_value(policy, name.as_ref(), value);
        tracing::trace!(
            target: TRACE_TARGET,
            direction = "request",
            method = request.method().unwrap_or("?"),
            encrypted,
            header_index,
            header_name = %name,
            header_value = %rendered.value,
            redacted = rendered.redacted,
            truncated = rendered.truncated,
            "RTSP header"
        );
    }
    trace_omitted_headers("request", total);
}

pub(crate) fn trace_response(policy: HeaderDiagnostics, response: &HttpResponse, encrypted: bool) {
    if policy == HeaderDiagnostics::Disabled
        || !tracing::enabled!(target: TRACE_TARGET, Level::TRACE)
    {
        return;
    }

    let Some(head) = response_head(response.get_data()) else {
        tracing::trace!(
            target: TRACE_TARGET,
            direction = "response",
            status = response.status_code(),
            encrypted,
            "RTSP response header block unavailable"
        );
        return;
    };
    let Ok(head) = std::str::from_utf8(head) else {
        tracing::trace!(
            target: TRACE_TARGET,
            direction = "response",
            status = response.status_code(),
            encrypted,
            "RTSP response header block is not UTF-8"
        );
        return;
    };

    let headers: Vec<_> = head
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .collect();
    let total = headers.len();
    for (header_index, (name, value)) in headers.into_iter().take(MAX_HEADER_COUNT).enumerate() {
        let name = escape_control_chars(name);
        let rendered = render_value(policy, name.as_ref(), value.trim_start());
        tracing::trace!(
            target: TRACE_TARGET,
            direction = "response",
            status = response.status_code(),
            encrypted,
            header_index,
            header_name = %name,
            header_value = %rendered.value,
            redacted = rendered.redacted,
            truncated = rendered.truncated,
            "RTSP header"
        );
    }
    trace_omitted_headers("response", total);
}

fn trace_omitted_headers(direction: &'static str, total: usize) {
    if total > MAX_HEADER_COUNT {
        tracing::trace!(
            target: TRACE_TARGET,
            direction,
            headers_omitted = total - MAX_HEADER_COUNT,
            "RTSP header diagnostics limit reached"
        );
    }
}

fn response_head(data: &[u8]) -> Option<&[u8]> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|end| &data[..end])
}

fn render_value<'a>(
    policy: HeaderDiagnostics,
    header_name: &str,
    value: &'a str,
) -> RenderedValue<'a> {
    match policy {
        HeaderDiagnostics::Disabled | HeaderDiagnostics::Redacted => {}
        #[cfg(feature = "dangerous-raw-headers")]
        HeaderDiagnostics::Raw => {
            return RenderedValue {
                value: escape_control_chars(value),
                redacted: false,
                truncated: false,
            };
        }
    }

    if ALLOWLISTED_HEADER_NAMES
        .iter()
        .any(|safe| header_name.eq_ignore_ascii_case(safe))
    {
        let (value, truncated) = truncate_chars(value, MAX_REDACTED_VALUE_CHARS);
        return RenderedValue {
            value: escape_control_chars_cow(value),
            redacted: false,
            truncated,
        };
    }

    RenderedValue {
        value: Cow::Borrowed(REDACTED_VALUE),
        redacted: true,
        truncated: false,
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> (Cow<'_, str>, bool) {
    let Some((byte_index, _)) = value.char_indices().nth(max_chars) else {
        return (Cow::Borrowed(value), false);
    };
    let mut truncated = String::with_capacity(byte_index + TRUNCATED_SUFFIX.len());
    truncated.push_str(&value[..byte_index]);
    truncated.push_str(TRUNCATED_SUFFIX);
    (Cow::Owned(truncated), true)
}

fn escape_control_chars(value: &str) -> Cow<'_, str> {
    if !value.chars().any(char::is_control) {
        return Cow::Borrowed(value);
    }

    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    Cow::Owned(escaped)
}

fn escape_control_chars_cow(value: Cow<'_, str>) -> Cow<'_, str> {
    if value.chars().any(char::is_control) {
        Cow::Owned(escape_control_chars(value.as_ref()).into_owned())
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedOutput {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedOutput {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture_events(run: impl FnOnce()) -> String {
        let output = CapturedOutput::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(Level::TRACE)
            .with_writer(output.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        String::from_utf8(output.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn redacted_policy_uses_a_conservative_case_insensitive_allowlist() {
        let allowed = render_value(HeaderDiagnostics::Redacted, "Content-Type", "image/jpeg");
        assert_eq!(
            allowed,
            RenderedValue {
                value: Cow::Borrowed("image/jpeg"),
                redacted: false,
                truncated: false,
            }
        );

        for name in [
            "Authorization",
            "Apple-Challenge",
            "DACP-ID",
            "Session",
            "Transport",
            "X-Unknown-Extension",
        ] {
            let rendered = render_value(HeaderDiagnostics::Redacted, name, "sentinel-secret");
            assert_eq!(rendered.value, REDACTED_VALUE, "header: {name}");
            assert!(rendered.redacted, "header: {name}");
        }
    }

    #[test]
    fn redacted_policy_bounds_allowlisted_values_on_character_boundaries() {
        let value = "x".repeat(MAX_REDACTED_VALUE_CHARS) + "é";
        let rendered = render_value(HeaderDiagnostics::Redacted, "User-Agent", &value);
        assert!(rendered.truncated);
        assert_eq!(
            rendered.value.chars().count(),
            MAX_REDACTED_VALUE_CHARS + TRUNCATED_SUFFIX.chars().count()
        );
        assert!(rendered.value.ends_with(TRUNCATED_SUFFIX));
    }

    #[test]
    fn control_characters_are_escaped() {
        let rendered = render_value(HeaderDiagnostics::Redacted, "CSeq", "1\r\nforged\tline");
        assert_eq!(rendered.value, r"1\r\nforged\tline");
        assert!(!rendered.value.contains('\n'));
    }

    #[test]
    fn response_head_excludes_the_body() {
        let data = b"RTSP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nsentinel-body";
        let head = response_head(data).unwrap();
        assert_eq!(
            head,
            b"RTSP/1.0 200 OK\r\nContent-Type: text/plain".as_slice()
        );
        assert!(!head.windows(13).any(|window| window == b"sentinel-body"));
    }

    #[test]
    fn emitted_redacted_events_hide_secrets_and_bodies() {
        let mut request = HttpRequest::new();
        request
            .add_data(
                b"POST /diagnostics RTSP/1.0\r\n\
                  Authorization: sentinel-request-secret\r\n\
                  User-Agent: diagnostic-client\r\n\
                  Content-Length: 21\r\n\r\n\
                  sentinel-request-body",
            )
            .unwrap();
        assert!(request.is_complete());

        let mut response = HttpResponse::new("RTSP/1.0", 200, "OK");
        response.add_header("Authorization", "sentinel-response-secret");
        response.add_header("Content-Type", "text/plain");
        response.finish(Some(b"sentinel-response-body"));

        let events = capture_events(|| {
            trace_request(HeaderDiagnostics::Redacted, &request, false);
            trace_response(HeaderDiagnostics::Redacted, &response, false);
        });

        assert!(events.contains("diagnostic-client"));
        assert!(events.contains("text/plain"));
        assert!(events.contains(REDACTED_VALUE));
        for secret in [
            "sentinel-request-secret",
            "sentinel-request-body",
            "sentinel-response-secret",
            "sentinel-response-body",
        ] {
            assert!(
                !events.contains(secret),
                "leaked diagnostic value: {secret}"
            );
        }

        let disabled = capture_events(|| {
            trace_request(HeaderDiagnostics::Disabled, &request, false);
            trace_response(HeaderDiagnostics::Disabled, &response, false);
        });
        assert!(disabled.is_empty());
    }

    #[cfg(feature = "dangerous-raw-headers")]
    #[test]
    fn raw_policy_matches_the_build_safety_gate() {
        assert!(HeaderDiagnostics::Raw.validate_for_build(true).is_ok());
        assert!(matches!(
            HeaderDiagnostics::Raw.validate_for_build(false),
            Err(ServerError::InvalidConfiguration(RAW_RELEASE_ERROR))
        ));

        let validation = HeaderDiagnostics::Raw.validate();
        assert_eq!(validation.is_ok(), cfg!(debug_assertions));

        let rendered = render_value(
            HeaderDiagnostics::Raw,
            "Authorization",
            "sentinel-secret\r\n",
        );
        assert_eq!(rendered.value, r"sentinel-secret\r\n");
        assert!(!rendered.redacted);
        assert!(!rendered.truncated);

        let mut request = HttpRequest::new();
        request
            .add_data(b"OPTIONS * RTSP/1.0\r\nAuthorization: sentinel-raw-secret\r\n\r\n")
            .unwrap();
        let events = capture_events(|| {
            trace_request(HeaderDiagnostics::Raw, &request, false);
        });
        assert!(events.contains("sentinel-raw-secret"));
    }
}
