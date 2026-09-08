# raop: write TCP packet length into the interleaved header

With `raop.transport=tcp`, `stream_send_packet()` leaves the interleaved packet length at zero and ORs the intended length into the first word of the encoded ALAC payload. Receivers cannot frame the packet correctly, and the audio bytes are modified.

Write the RTP header plus encoded-audio length into `tcp_pkt[0]`, alongside the `$` marker and channel zero. The RTP header and encoded payload remain byte-identical to the UDP packet.

Extend the native sender callback regression to check the four-byte TCP prefix and the complete RTP/ALAC bytes for all 353 frame-aligned two-segment splits, including empty head/tail. Its datagram socketpair checks packet construction; actual TCP streaming is covered by the live receiver qualification.

Validation against upstream master `c73df14f03e30c41f6430acd82c6250dcdb168d8`:

- Unmodified sender plus regression: 707 cases, 353 failures, covering every TCP case. Fixed sender: 707 cases, zero failures.
- The earlier standalone fix passes all five shairplay-rust TCP feature/profile configurations on Linux aarch64, including six bit-exact 25-second audio sessions and reconnect. Unmodified master produces no decoded payload and fails the live oracle.
- Final combined TCP/auth candidate: all five strict shairplay-rust feature/profile builds pass over both UDP and TCP on native Linux aarch64 and x86_64. The 20 reports contain 48 bit-exact 25-second non-silent audio sessions: 24 protected and 24 passwordless, including release, TEARDOWN and reconnect. Missing and incorrect passwords are rejected with bounded 401 sequences and no audio; feature/runtime gates remain 404.
- Native packet, RTSP-client and authentication tests pass with ASan/UBSan and `b_ndebug=true` on both architectures. The combined packet regression has 707 cases and zero failures. Receiver production code, waveform duration and strict audio oracle are unchanged.

Native reproduction, after applying this patch to the base above:

```sh
meson setup build -Dauto_features=disabled '-Dsession-managers=[]' \
  -Draop=enabled -Dtests=enabled -Dspa-plugins=enabled -Dsupport=enabled \
  -Ddbus=disabled -Dflatpak=disabled -Dpipewire-jack=disabled -Dpipewire-v4l2=disabled \
  -Db_sanitize=address,undefined -Db_ndebug=true
meson test -C build --print-errorlogs pw-test-raop-iovec pw-test-raop-rtsp-client
```

The reproduction package `pipewire-raop-pre-submission-20260908.tar.gz` contains the independent patches, combined test patch, raw reports, sanitizer logs, checksum manifest and a self-contained Git bundle with the exact receiver/test checkout. Its README gives the live Docker commands; no unpublished GitHub branch is needed.

The TCP patch is independent of the auth-setup change. Live coverage uses classic RAOP, uncompressed ALAC and unencrypted audio on IPv4 loopback. Encrypted audio, TCP backpressure/short writes and the original desktop environment are outside this qualification.
