//! RTSP request dispatch — routes incoming requests to handlers.
//!
//! Uses a compile-time route table for clean, extensible routing.
//! Auth, Apple-Challenge, and logging are handled as middleware
//! before dispatch.

use crate::proto::digest;
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::raop::handlers_ap1::{self as handlers, RaopConnection};

/// HTTP Digest authentication realm advertised and validated for RTSP auth.
const DIGEST_REALM: &str = "airplay";
/// Server identity advertised on every routed RTSP response.
const RTSP_SERVER_HEADER_VALUE: &str = "AirTunes/105.1";
#[cfg(feature = "ap2")]
use crate::raop::handlers_ap2;
#[cfg(feature = "hls")]
use crate::raop::handlers_hls;

/// Handler function signature — all RTSP handlers share this type.
type Handler = fn(&mut RaopConnection, &HttpRequest, &mut HttpResponse) -> Option<Vec<u8>>;

/// Result of route resolution.
enum RouteResolution {
    /// Request is handled inline and has no body.
    NoBody,
    /// Request should be passed to a handler function.
    Handler(Handler),
}

/// A single route entry: HTTP method, URL path, handler function.
struct Route {
    method: &'static str,
    path: &'static str,
    handler: Handler,
}

// The compatibility route requires an exact origin-form target, unlike legacy
// routes that deliberately ignore a query string. Both ingress and dispatch use it.
#[cfg(feature = "pipewire-auth-setup-compat")]
const PIPEWIRE_AUTH_SETUP_ROUTE: Route = Route {
    method: "POST",
    path: "/auth-setup",
    handler: super::auth_setup::handle,
};

#[cfg(feature = "pipewire-auth-setup-compat")]
fn pipewire_auth_setup_route(
    conn: &RaopConnection,
    request: &HttpRequest,
) -> Option<&'static Route> {
    if !conn.shared.pipewire_auth_setup_compat {
        return None;
    }
    #[cfg(feature = "ap2")]
    if conn.is_ap2 {
        return None;
    }
    (request.method() == Some(PIPEWIRE_AUTH_SETUP_ROUTE.method)
        && request.url() == Some(PIPEWIRE_AUTH_SETUP_ROUTE.path))
    .then_some(&PIPEWIRE_AUTH_SETUP_ROUTE)
}

#[cfg(feature = "pipewire-auth-setup-compat")]
pub(super) fn request_body_policy(
    conn: &RaopConnection,
    request: &HttpRequest,
) -> Result<crate::net::server::RequestBodyPolicy, crate::error::ProtocolError> {
    if pipewire_auth_setup_route(conn, request).is_some() {
        super::auth_setup::body_policy(request)
    } else {
        Ok(crate::net::server::RequestBodyPolicy::default())
    }
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
    #[cfg(feature = "ap2")]
    Route {
        method: "POST",
        path: "/pair-pin-start",
        handler: handlers_ap2::handle_pair_pin_start,
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

    let mut response = new_response(200, "OK", cseq);
    response.add_header("Apple-Jack-Status", "connected; type=analog");

    // --- Middleware: authentication ---
    if method != "OPTIONS" && !conn.shared.password.is_empty() {
        let authorization = request.header("Authorization");
        if !digest::is_valid(
            DIGEST_REALM,
            &conn.shared.password,
            &conn.nonce,
            method,
            url,
            authorization,
        ) {
            let auth_str = format!(
                "Digest realm=\"{}\", nonce=\"{}\"",
                DIGEST_REALM, conn.nonce
            );
            response = new_response(401, "Unauthorized", cseq);
            response.add_header("WWW-Authenticate", &auth_str);
            response.finish(None);
            return response;
        }
    }

    // --- Middleware: Apple-Challenge ---
    if let Some(challenge) = request.header("Apple-Challenge")
        && let Ok(sig) =
            conn.shared
                .rsakey
                .sign_challenge(challenge, &conn.local_addr, &conn.shared.hwaddr)
    {
        response.add_header("Apple-Response", &sig);
    }

    // --- Route resolution ---
    let response_data = match resolve_handler(conn, request, method, url) {
        Some(RouteResolution::Handler(handler)) => handler(conn, request, &mut response),
        Some(RouteResolution::NoBody) => None,
        None => {
            tracing::debug!(method, url, "Unhandled RTSP request");
            response = new_response(404, "Not Found", cseq);
            response.finish(None);
            return response;
        }
    };
    response.finish(response_data.as_deref());
    response
}

pub(super) fn new_response(status: u16, message: &str, cseq: &str) -> HttpResponse {
    let mut response = HttpResponse::new("RTSP/1.0", status, message);
    response.add_header("CSeq", cseq);
    response.add_header("Server", RTSP_SERVER_HEADER_VALUE);
    response
}

/// Resolve the handler for a request. Checks the route table first,
/// then falls back to special-case handlers for methods that need
/// custom routing logic (SETUP, RECORD, FLUSH, TEARDOWN).
fn resolve_handler(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    method: &str,
    url: &str,
) -> Option<RouteResolution> {
    #[cfg(feature = "pipewire-auth-setup-compat")]
    if let Some(route) = pipewire_auth_setup_route(conn, request) {
        return Some(RouteResolution::Handler(route.handler));
    }

    // 1. Check static route table (exact path or prefix match for query-string routes)
    for route in ROUTES {
        if route.method == method {
            let path = url.split('?').next().unwrap_or(url);
            if route.path == "*" || route.path == path {
                return Some(RouteResolution::Handler(route.handler));
            }
        }
    }

    // 2. Special-case methods with custom routing logic
    match method {
        "SETUP" => resolve_setup(conn, request).map(RouteResolution::Handler),
        "RECORD" => resolve_record(conn).map(RouteResolution::Handler),
        "FLUSH" => {
            handle_flush_inline(conn, request);
            Some(RouteResolution::NoBody)
        }
        "TEARDOWN" => Some(RouteResolution::Handler(handle_teardown as Handler)),
        _ => None,
    }
}

/// SETUP routing: AP1 (Transport header) vs AP2 (binary plist body).
fn resolve_setup(conn: &RaopConnection, request: &HttpRequest) -> Option<Handler> {
    #[cfg(feature = "ap2")]
    {
        let is_plist = request
            .data()
            .map(|d| d.starts_with(b"bplist"))
            .unwrap_or(false);
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
    Some(handlers::handle_record)
}

/// FLUSH: parse RTP-Info header and flush the buffer inline.
fn handle_flush_inline(conn: &mut RaopConnection, request: &HttpRequest) {
    if let Some(rtp_info) = request.header("RTP-Info")
        && let Some(seq_str) = rtp_info.strip_prefix("seq=")
        && let Ok(next_seq) = seq_str.parse::<i32>()
        && let Some(rtp) = &conn.raop_rtp
    {
        rtp.flush(next_seq);
    }
}

/// TEARDOWN: stop RTP, stop buffered audio, close connection.
fn handle_teardown(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    response.add_header("Connection", "close");
    response.set_disconnect(true);
    if let Some(mut rtp) = conn.raop_rtp.take() {
        rtp.stop();
    }
    #[cfg(feature = "ap2")]
    if let Some(cmd) = &conn.playout_cmd {
        let _ = cmd.send(crate::raop::buffered_audio::PlayoutCommand::Stop);
    }
    None
}
