#![no_main]
use libfuzzer_sys::fuzz_target;
use shairplay::proto::plist;

fuzz_target!(|data: &[u8]| {
    if let Some(val) = plist::from_bplist(data) {
        let _ = plist::to_bplist(&val);
    }
});
