//! HLS HTTP handlers — /play, /playback-info, /scrub, /rate, /stop, /server-info.

use super::handlers_ap1::RaopConnection;
use crate::proto::http::{HttpRequest, HttpResponse};

/// `GET /server-info` — server capabilities for HLS mode.
pub(crate) fn handle_server_info(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let mac = conn
        .hwaddr
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    let mut dict = plist::Dictionary::new();
    // Bits 0-6 + 9: video, photo, FairPlay DRM, volume, HLS, slideshow, unknown, audio
    dict.insert("features".into(), plist::Value::Integer(0x27F_i64.into()));
    dict.insert("macAddress".into(), plist::Value::String(mac.clone()));
    dict.insert(
        "model".into(),
        plist::Value::String(crate::net::mdns::GLOBAL_MODEL.into()),
    );
    dict.insert("osBuildVersion".into(), plist::Value::String("12B435".into()));
    dict.insert("protovers".into(), plist::Value::String("1.0".into()));
    dict.insert(
        "srcvers".into(),
        plist::Value::String(crate::net::mdns::AP2_SRCVERS.into()),
    );
    dict.insert("vv".into(), plist::Value::Integer(2_i64.into()));
    dict.insert("deviceid".into(), plist::Value::String(mac));

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &plist::Value::Dictionary(dict)).ok()?;
    response.add_header("Content-Type", "text/x-apple-plist+xml");
    Some(buf)
}

/// `POST /play` — iPhone sends m3u8 URL to start HLS playback.
pub(crate) fn handle_play(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    let plist_val: plist::Value = plist::from_bytes(data).ok()?;
    let dict = plist_val.as_dictionary()?;

    let url = dict.get("Content-Location").and_then(|v| v.as_string())?;
    let start_pos = dict.get("Start-Position").and_then(|v| v.as_real()).unwrap_or(0.0) as f32;

    let session_id = request.header("X-Apple-Session-ID").map(|s| s.to_string());

    tracing::info!(%url, start_pos, "HLS play request");

    let hls_handler = conn.hls_handler.as_ref()?;
    let session = hls_handler.on_play(url, start_pos);

    if let Ok(mut state) = conn.hls_state.lock() {
        state.session = Some(session);
        state.session_id = session_id;
    }
    None
}

/// `GET /playback-info` — iPhone polls for playback state.
pub(crate) fn handle_playback_info(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let state = conn.hls_state.lock().ok()?;
    let session = state.session.as_ref()?;

    let duration = session.duration() as f64;
    let position = session.position() as f64;
    let rate = session.rate() as f64;
    let ready = session.ready();

    let mut dict = plist::Dictionary::new();
    dict.insert("duration".into(), plist::Value::Real(duration));
    dict.insert("position".into(), plist::Value::Real(position));
    dict.insert("rate".into(), plist::Value::Real(rate));
    dict.insert("readyToPlay".into(), plist::Value::Integer((ready as i64).into()));
    dict.insert("playbackBufferEmpty".into(), plist::Value::Integer(0_i64.into()));
    dict.insert("playbackBufferFull".into(), plist::Value::Integer(1_i64.into()));
    dict.insert("playbackLikelyToKeepUp".into(), plist::Value::Integer(1_i64.into()));

    // loadedTimeRanges
    let mut loaded = plist::Dictionary::new();
    loaded.insert("start".into(), plist::Value::Real(position));
    loaded.insert("duration".into(), plist::Value::Real(duration - position));
    dict.insert(
        "loadedTimeRanges".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(loaded)]),
    );

    // seekableTimeRanges
    let mut seekable = plist::Dictionary::new();
    seekable.insert("start".into(), plist::Value::Real(0.0));
    seekable.insert("duration".into(), plist::Value::Real(duration));
    dict.insert(
        "seekableTimeRanges".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(seekable)]),
    );

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &plist::Value::Dictionary(dict)).ok()?;
    response.add_header("Content-Type", "text/x-apple-plist+xml");
    Some(buf)
}

/// `POST /scrub?position=X` — seek to position.
pub(crate) fn handle_scrub(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let url = request.url()?;
    let pos = parse_query_float(url, "position")?;
    tracing::debug!(pos, "HLS scrub");
    if let Ok(mut state) = conn.hls_state.lock() {
        if let Some(session) = state.session.as_mut() {
            session.seek(pos);
        }
    }
    None
}

/// `POST /rate?value=X` — set playback rate (0=pause, 1=play).
pub(crate) fn handle_rate(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let url = request.url()?;
    let rate = parse_query_float(url, "value")?;
    tracing::debug!(rate, "HLS rate");
    if let Ok(mut state) = conn.hls_state.lock() {
        if let Some(session) = state.session.as_mut() {
            session.set_rate(rate);
        }
    }
    None
}

/// `POST /stop` — stop HLS playback.
pub(crate) fn handle_stop(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    tracing::info!("HLS stop");
    if let Ok(mut state) = conn.hls_state.lock() {
        if let Some(session) = state.session.as_mut() {
            session.stop();
        }
        state.session = None;
        state.session_id = None;
    }
    None
}

/// Parse `?key=value` from a URL query string.
fn parse_query_float(url: &str, key: &str) -> Option<f32> {
    let query = url.split('?').nth(1)?;
    for param in query.split('&') {
        if let Some(val) = param.strip_prefix(key).and_then(|s| s.strip_prefix('=')) {
            return val.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_float_basic() {
        assert_eq!(parse_query_float("/scrub?position=12.5", "position"), Some(12.5));
        assert_eq!(parse_query_float("/rate?value=1.0", "value"), Some(1.0));
        assert_eq!(parse_query_float("/rate?value=0.0", "value"), Some(0.0));
    }

    #[test]
    fn parse_query_float_missing() {
        assert_eq!(parse_query_float("/scrub", "position"), None);
        assert_eq!(parse_query_float("/scrub?other=1", "position"), None);
    }

    #[test]
    fn parse_query_float_multiple_params() {
        assert_eq!(parse_query_float("/x?a=1&position=3.14&b=2", "position"), Some(3.14));
    }

    #[test]
    fn parse_query_float_invalid() {
        assert_eq!(parse_query_float("/scrub?position=abc", "position"), None);
        assert_eq!(parse_query_float("/scrub?position=", "position"), None);
    }
}
