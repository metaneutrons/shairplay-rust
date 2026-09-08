# raop: write TCP packet length into the interleaved header

With `raop.transport=tcp`, `stream_send_packet()` leaves the interleaved packet length at zero and ORs the intended length into the first word of the encoded ALAC payload. A receiver therefore cannot frame the packet correctly, and the audio bytes are also modified.

Write the RTP header plus encoded-audio length into `tcp_pkt[0]`, alongside the `$` marker and channel zero. The RTP header and encoded payload remain byte-identical to the UDP packet.

Extend the existing native sender callback regression to check the four-byte TCP prefix and the full RTP/ALAC bytes for all 353 frame-aligned two-segment splits, including empty head/tail. The socketpair captures each callback output as one datagram, so this test checks packet construction; actual TCP streaming is covered by the live receiver qualification.

Validation so far:
- Based on upstream master `c73df14f03e30c41f6430acd82c6250dcdb168d8`.
- Unmodified sender plus regression: 707 cases, 353 failures (every TCP case).
- Fixed sender: 707 cases, zero failures; existing RTSP client regression passes.
- Both native tests pass with ASan/UBSan and `b_ndebug=true` on Linux aarch64.
- Strict live TCP qualification with shairplay-rust on Linux aarch64: all five feature/profile configurations pass; six 25-second non-silent audio sessions are bit-exact, with TEARDOWN and reconnect, including release. Runtime-off/feature-absent 404 and protected 401 rejection checks still pass.
- The unmodified sender fails all three audio configurations: compatibility and combined receive zero decoded frames in both sessions; release receives zero in the first session and then fails reconnect.

The live test covers passwordless, unencrypted classic RAOP with uncompressed ALAC. It does not qualify encrypted audio, TCP backpressure/short-write handling or arbitrary desktop setups.

Local preparation only. No branch has been pushed and no MR has been submitted.
