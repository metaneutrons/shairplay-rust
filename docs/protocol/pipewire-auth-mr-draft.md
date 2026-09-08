# raop: authenticate auth-setup after a password challenge

A receiver may accept OPTIONS without authentication and challenge the following POST /auth-setup. With `raop.password` configured, the RAOP sink currently aborts at that 401 instead of authenticating, so playback never reaches ANNOUNCE.

Reuse the OPTIONS challenge parser and send one authenticated retry of the same 33-byte POST. Compute Digest using the actual method and target, `POST:/auth-setup`; subsequent RTSP requests use their own method and session URI. Replace previous challenge state safely and reset the retry guard on connection cleanup. Missing credentials, malformed or unsupported challenges, a second 401, and failures to construct or send the authenticated request terminate the attempt.

The shared authentication path also needs a one-line Basic correction: the payload formatter and common header formatter both added the scheme, producing `Basic Basic ...`. Only the common formatter now adds it. OPTIONS authentication errors explicitly schedule module destruction, because the RTSP dispatcher only logs callback errors and would otherwise leave the sink connected without progressing. These corrections are separate commits within this authentication change.

The native regression uses real loopback RTSP I/O and independent EVP-based Digest and Basic calculations. It checks the exact binary POST, Digest challenges at OPTIONS and at auth-setup, Basic OPTIONS/POST/ANNOUNCE, fresh per-request authorization, bounded repeated-401 rejection, and invalid or missing challenges/credentials at both entry points. A small test seam observes destruction scheduling; the live negative cases exercise actual module teardown.

Validation against upstream master `c73df14f03e30c41f6430acd82c6250dcdb168d8`:

- Unmodified master fails the original native auth-setup regression on the first 401 and fails the live password oracle because no authenticated POST follows. The earlier standalone Digest fix passes all five UDP feature/profile configurations on Linux aarch64, including six protected and six passwordless exact audio sessions.
- The added OPTIONS negative regression fails before the error-path correction and passes afterward. The Basic regression exposed the duplicate scheme and passes with the single-scheme correction.
- Final combined TCP/auth candidate: all five strict shairplay-rust feature/profile builds pass over both UDP and TCP on native Linux aarch64 and x86_64. The 20 reports contain 48 bit-exact 25-second non-silent audio sessions: 24 protected and 24 passwordless, including release, TEARDOWN and reconnect. Missing and incorrect passwords are rejected with bounded 401 sequences and no audio; feature/runtime gates remain 404.
- Native packet, RTSP-client and authentication tests pass with ASan/UBSan and `b_ndebug=true` on both architectures. The combined packet regression has 707 cases and zero failures. Receiver production code, waveform duration and strict audio oracle are unchanged.

Native reproduction, after applying this patch to the base above:

```sh
meson setup build -Dauto_features=disabled '-Dsession-managers=[]' \
  -Draop=enabled -Dtests=enabled -Dspa-plugins=enabled -Dsupport=enabled \
  -Ddbus=disabled -Dflatpak=disabled -Dpipewire-jack=disabled -Dpipewire-v4l2=disabled \
  -Db_sanitize=address,undefined -Db_ndebug=true
meson test -C build --print-errorlogs \
  pw-test-raop-iovec pw-test-raop-rtsp-client pw-test-raop-auth
```

The reproduction package `pipewire-raop-pre-submission-20260908.tar.gz` contains the independent patches, combined test patch, raw reports, sanitizer logs, checksum manifest and a self-contained Git bundle with the exact receiver/test checkout. Its README gives the live Docker commands; no unpublished GitHub branch is needed.

This patch is independent of the TCP framing change. Live coverage uses password Digest, classic RAOP, uncompressed ALAC and unencrypted audio on IPv4 loopback. Basic is covered by the native protocol regression, not live shairplay playback. This does not establish MFi/encrypted playback, a supported released baseline or behavior on the original desktop.
