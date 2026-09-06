#![no_main]
use libfuzzer_sys::fuzz_target;
use shairplay::proto::http::HttpRequest;

fuzz_target!(|data: &[u8]| {
    let mut whole = HttpRequest::new();
    let whole_result = whole.add_data(data);
    for chunk_size in [1, 7, 1 + usize::from(data.first().copied().unwrap_or(0))] {
        let mut fragmented = HttpRequest::new();
        let mut fragmented_result = Ok(());
        for chunk in data.chunks(chunk_size) {
            fragmented_result = fragmented.add_data(chunk);
            if fragmented_result.is_err() || fragmented.is_complete() {
                break;
            }
        }
        assert_eq!(whole_result.is_err(), fragmented_result.is_err());
        if whole_result.is_ok() {
            assert_eq!(whole.is_complete(), fragmented.is_complete());
            assert_eq!(whole.method(), fragmented.method());
            assert_eq!(whole.url(), fragmented.url());
            assert_eq!(whole.data(), fragmented.data());
            for name in ["content-length", "content-type", "cseq"] {
                assert_eq!(whole.header(name), fragmented.header(name));
            }
        }
    }
});
