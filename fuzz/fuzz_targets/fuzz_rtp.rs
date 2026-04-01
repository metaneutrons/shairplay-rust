#![no_main]
use libfuzzer_sys::fuzz_target;
use shairplay::raop::buffer::RaopBuffer;

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 { return; }
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let mut buf = RaopBuffer::new("96 352", "96 352 0 16 40 10 14 2 255 0 0 44100", &key, &iv);
    let _ = buf.queue(data, true);
    let _ = buf.dequeue(true);
});
