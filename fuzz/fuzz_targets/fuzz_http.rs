#![no_main]
use libfuzzer_sys::fuzz_target;
use shairplay::proto::http::HttpRequest;

fuzz_target!(|data: &[u8]| {
    let mut req = HttpRequest::new();
    let _ = req.add_data(data);
});
