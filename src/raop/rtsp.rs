//! RTSP request dispatch — routes incoming requests to handlers.
//!
//! Uses a compile-time route table for clean, extensible routing.
//! Auth, Apple-Challenge, and logging are handled as middleware
//! before dispatch.

use crate::proto::digest;
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::raop::handlers_ap1::{self as handlers, RaopConnection};
#[cfg(feature = "ap2")]
use crate::raop::handlers_ap2;
#[cfg(feature = "hls")]
use crate::raop::handlers_hls;

/// Handler function signature — all RTSP handlers share this type.
type Handler = fn(&mut RaopConnection, &HttpRequest, &mut HttpResponse) -> Option<Vec<u8>>;

/// A single route entry: HTTP method, URL path, handler function.
struct Route {
    method: &'static str,
    path: &'static str,
    handler: Handler,
}

/// Static route table — checked in order, first match wins.
/// Feature-gated routes are included/excluded at compile time.
const ROUTES: &[Route] = &[
    // --- Authentication & DRM ---
    #[cfg(feature = "ap2")]
    Route {
        method: "POST",
        path: "/pair-setup",
        handler: handlers_ap2::handle_pair_setup,
    },
    #[cfg(not(feature = "ap2"))]
    Route {
        method: "POST",
        path: "/pair-setup",
        handler: handlers::handle_pair_setup,
    },
    #[cfg(feature = "ap2")]
    Route {
        method: "POST",
        path: "/pair-verify",
        handler: handlers_ap2::handle_pair_verify,
    },
    #[cfg(not(feature = "ap2"))]
    Route {
        method: "POST",
        path: "/pair-verify",
        handler: handlers::handle_pair_verify,
    },
    Route {
        method: "POST",
        path: "/fp-setup",
        handler: handlers::handle_fp_setup,
    },
    // --- AP2 POST endpoints ---
    #[cfg(feature = "ap2")]
    Route {
        method: "POST",
        path: "/feedback",
        handler: handlers_ap2::handle_feedback,
    },
    #[cfg(feature = "ap2")]
    Route {
        method: "POST",
        path: "/command",
        handler: handlers_ap2::handle_command,
    },
    #[cfg(feature = "ap2")]
    Route {
        method: "POST",
        path: "/audioMode",
        handler: handlers_ap2::handle_audio_mode,
    },
    // --- Standard RTSP methods ---
    Route {
        method: "OPTIONS",
        path: "*",
        handler: handlers::handle_options,
    },
    Route {
        method: "ANNOUNCE",
        path: "*",
        handler: handlers::handle_announce,
    },
    Route {
        method: "GET_PARAMETER",
        path: "*",
        handler: handlers::handle_get_parameter,
    },
    Route {
        method: "SET_PARAMETER",
        path: "*",
        handler: handlers::handle_set_parameter,
    },
    // --- AP2 RTSP methods ---
    #[cfg(feature = "ap2")]
    Route {
        method: "SETRATEANCHORTIME",
        path: "*",
        handler: handlers_ap2::handle_set_rate_anchor_time,
    },
    #[cfg(feature = "ap2")]
    Route {
        method: "SETPEERS",
        path: "*",
        handler: handlers_ap2::handle_set_peers,
    },
    #[cfg(feature = "ap2")]
    Route {
        method: "SETPEERSX",
        path: "*",
        handler: handlers_ap2::handle_set_peers,
    },
    #[cfg(feature = "ap2")]
    Route {
        method: "FLUSHBUFFERED",
        path: "*",
        handler: handlers_ap2::handle_flush_buffered,
    },
    // --- Info ---
    #[cfg(feature = "ap2")]
    Route {
        method: "GET",
        path: "/info",
        handler: handlers_ap2::handle_info,
    },
    // --- HLS (HTTP Live Streaming) ---
    #[cfg(feature = "hls")]
    Route {
        method: "GET",
        path: "/server-info",
        handler: handlers_hls::handle_server_info,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "POST",
        path: "/play",
        handler: handlers_hls::handle_play,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "GET",
        path: "/playback-info",
        handler: handlers_hls::handle_playback_info,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "POST",
        path: "/stop",
        handler: handlers_hls::handle_stop,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "POST",
        path: "/scrub",
        handler: handlers_hls::handle_scrub,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "POST",
        path: "/rate",
        handler: handlers_hls::handle_rate,
    },
];

/// Dispatch an RTSP request: authenticate, resolve route, call handler, build response.
pub(crate) fn dispatch(conn: &mut RaopConnection, request: &HttpRequest) -> HttpResponse {
    let method = request.method().unwrap_or("");
    let url = request.url().unwrap_or("");
    let cseq = request.header("CSeq").unwrap_or("0");

    let mut response = HttpResponse::new("RTSP/1.0", 200, "OK");
    response.add_header("CSeq", cseq);
    response.add_header("Apple-Jack-Status", "connected; type=analog");

    // --- Middleware: authentication ---
    if method != "OPTIONS" && !conn.password.is_empty() {
        let authorization = request.header("Authorization");
        if !digest::is_valid("airplay", &conn.password, &conn.nonce, method, url, authorization) {
            let auth_str = format!("Digest realm=\"airplay\", nonce=\"{}\"", conn.nonce);
            response = HttpResponse::new("RTSP/1.0", 401, "Unauthorized");
            response.add_header("CSeq", cseq);
            response.add_header("WWW-Authenticate", &auth_str);
            response.finish(None);
            return response;
        }
    }

    // --- Middleware: Apple-Challenge ---
    if let Some(challenge) = request.header("Apple-Challenge") {
        if let Ok(sig) = conn.rsakey.sign_challenge(challenge, &conn.local_addr, &conn.hwaddr) {
            response.add_header("Apple-Response", &sig);
        }
    }

    // --- Route resolution ---
    let handler = resolve_handler(conn, request, method, url);
    let response_data = handler.and_then(|h| h(conn, request, &mut response));
    response.finish(response_data.as_deref());
    response
}

/// Resolve the handler for a request. Checks the route table first,
/// then falls back to special-case handlers for methods that need
/// custom routing logic (SETUP, RECORD, FLUSH, TEARDOWN).
fn resolve_handler(conn: &mut RaopConnection, request: &HttpRequest, method: &str, url: &str) -> Option<Handler> {
    // 1. Check static route table (exact path or prefix match for query-string routes)
    for route in ROUTES {
        if route.method == method {
            let path = url.split('?').next().unwrap_or(url);
            if route.path == "*" || route.path == path {
                return Some(route.handler);
            }
        }
    }

    // 2. Special-case methods with custom routing logic
    match method {
        "SETUP" => resolve_setup(conn, request),
        "RECORD" => resolve_record(conn),
        "FLUSH" => {
            handle_flush_inline(conn, request);
            None
        }
        "TEARDOWN" => Some(handle_teardown as Handler),
        _ => {
            tracing::debug!(method, url, "Unhandled RTSP method");
            None
        }
    }
}

/// SETUP routing: AP1 (Transport header) vs AP2 (binary plist body).
fn resolve_setup(conn: &RaopConnection, request: &HttpRequest) -> Option<Handler> {
    #[cfg(feature = "ap2")]
    {
        let is_plist = request.data().map(|d| d.starts_with(b"bplist")).unwrap_or(false);
        if conn.is_ap2 || is_plist {
            return Some(handlers_ap2::handle_setup);
        }
    }
    let _ = (conn, request); // suppress unused warnings without ap2
    Some(handlers::handle_setup)
}

/// RECORD routing: AP2 has its own handler.
fn resolve_record(conn: &RaopConnection) -> Option<Handler> {
    #[cfg(feature = "ap2")]
    if conn.is_ap2 {
        return Some(handlers_ap2::handle_record);
    }
    let _ = conn;
    None
}

/// FLUSH: parse RTP-Info header and flush the buffer inline.
fn handle_flush_inline(conn: &mut RaopConnection, request: &HttpRequest) {
    if let Some(rtp_info) = request.header("RTP-Info") {
        if let Some(seq_str) = rtp_info.strip_prefix("seq=") {
            if let Ok(next_seq) = seq_str.parse::<i32>() {
                if let Some(rtp) = &conn.raop_rtp {
                    rtp.flush(next_seq);
                }
            }
        }
    }
}

/// TEARDOWN: stop RTP, stop buffered audio, close connection.
fn handle_teardown(conn: &mut RaopConnection, _request: &HttpRequest, response: &mut HttpResponse) -> Option<Vec<u8>> {
    response.add_header("Connection", "close");
    response.set_disconnect(true);
    if let Some(mut rtp) = conn.raop_rtp.take() {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(rtp.stop());
        });
    }
    #[cfg(feature = "ap2")]
    if let Some(cmd) = &conn.playout_cmd {
        let _ = cmd.send(crate::raop::buffered_audio::PlayoutCommand::Stop);
    }
    None
}
