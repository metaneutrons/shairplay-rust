use crate::proto::digest;
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::raop::handlers::{self, RaopConnection};

/// Route an RTSP request to the appropriate handler.
/// Equivalent to conn_request dispatch logic in raop.c.
pub(crate) fn dispatch(conn: &mut RaopConnection, request: &HttpRequest) -> HttpResponse {
    let method = request.method().unwrap_or("");
    let url = request.url().unwrap_or("");
    let cseq = request.header("CSeq").unwrap_or("0");

    let mut response = HttpResponse::new("RTSP/1.0", 200, "OK");
    let mut require_auth = false;

    // Auth check for everything except OPTIONS
    if method != "OPTIONS" && !conn.password.is_empty() {
        let authorization = request.header("Authorization");
        if !digest::is_valid("airplay", &conn.password, &conn.nonce, method, url, authorization) {
            let auth_str = format!("Digest realm=\"airplay\", nonce=\"{}\"", conn.nonce);
            response = HttpResponse::new("RTSP/1.0", 401, "Unauthorized");
            response.add_header("WWW-Authenticate", &auth_str);
            require_auth = true;
        }
    }

    response.add_header("CSeq", cseq);
    response.add_header("Apple-Jack-Status", "connected; type=analog");

    // Apple-Challenge response
    if !require_auth {
        if let Some(challenge) = request.header("Apple-Challenge") {
            if let Ok(sig) = conn.rsakey.sign_challenge(challenge, &conn.local_addr, &conn.hwaddr) {
                response.add_header("Apple-Response", &sig);
            }
        }
    }

    // Route to handler
    type Handler = fn(&mut RaopConnection, &HttpRequest, &mut HttpResponse) -> Option<Vec<u8>>;
    let handler: Option<Handler> = if require_auth {
        Some(handlers::handle_none)
    } else if method == "POST" && url == "/pair-setup" {
        #[cfg(feature = "airplay2")]
        { Some(handlers::handle_pair_setup_ap2) }
        #[cfg(not(feature = "airplay2"))]
        { Some(handlers::handle_pair_setup) }
    } else if method == "POST" && url == "/pair-verify" {
        #[cfg(feature = "airplay2")]
        { Some(handlers::handle_pair_verify_ap2) }
        #[cfg(not(feature = "airplay2"))]
        { Some(handlers::handle_pair_verify) }
    } else if method == "POST" && url == "/fp-setup" {
        Some(handlers::handle_fp_setup)
    } else if method == "OPTIONS" {
        Some(handlers::handle_options)
    } else if method == "ANNOUNCE" {
        Some(handlers::handle_announce)
    } else if method == "SETUP" {
        #[cfg(feature = "airplay2")]
        {
            if conn.is_ap2 {
                Some(handlers::handle_setup_2 as Handler)
            } else {
                Some(handlers::handle_setup as Handler)
            }
        }
        #[cfg(not(feature = "airplay2"))]
        { Some(handlers::handle_setup) }
    } else if method == "GET_PARAMETER" {
        Some(handlers::handle_get_parameter)
    } else if method == "SET_PARAMETER" {
        Some(handlers::handle_set_parameter)
    } else if method == "GET" {
        #[cfg(feature = "airplay2")]
        { Some(handlers::handle_get_info as Handler) }
        #[cfg(not(feature = "airplay2"))]
        { None }
    } else if method == "FLUSH" {
        if let Some(rtp_info) = request.header("RTP-Info") {
            if let Some(seq_str) = rtp_info.strip_prefix("seq=") {
                if let Ok(next_seq) = seq_str.parse::<i32>() {
                    if let Some(rtp) = &conn.raop_rtp {
                        rtp.flush(next_seq);
                    }
                }
            }
        }
        None
    } else if method == "TEARDOWN" {
        response.add_header("Connection", "close");
        response.set_disconnect(true);
        if let Some(mut rtp) = conn.raop_rtp.take() {
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(rtp.stop()));
        }
        None
    } else {
        #[cfg(feature = "airplay2")]
        {
            if method == "RECORD" && conn.is_ap2 {
                Some(handlers::handle_record_2 as Handler)
            } else if method == "SETRATEANCHORTI" {
                Some(handlers::handle_setrateanchorti as Handler)
            } else if method == "SETPEERS" || method == "SETPEERSX" {
                Some(handlers::handle_setpeers as Handler)
            } else if method == "FLUSHBUFFERED" {
                Some(handlers::handle_flushbuffered as Handler)
            } else {
                None
            }
        }
        #[cfg(not(feature = "airplay2"))]
        { None }
    };

    let response_data = handler.and_then(|h| h(conn, request, &mut response));
    response.finish(response_data.as_deref());
    response
}
