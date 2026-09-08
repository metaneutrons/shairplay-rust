# raop: authenticate auth-setup after a password challenge

A receiver may accept OPTIONS without authentication and challenge the following
POST /auth-setup. With `raop.password` configured, the RAOP sink currently
aborts at that 401 instead of authenticating, so playback never reaches ANNOUNCE.

Reuse the OPTIONS challenge parser and send one authenticated retry of the same
33-byte POST. Compute Digest using the actual method and target,
`POST:/auth-setup`; subsequent RTSP requests continue to use their own method and
session URI. Replace previous challenge state safely and reset the retry guard
on connection cleanup. Missing credentials, malformed challenges, a second 401
or failure to construct/send the authenticated POST abort the module.

The native loopback regression checks the binary POST and independent Digest,
successful ANNOUNCE with a freshly computed Digest, bounded rejection and invalid
challenges. It uses real RTSP I/O and observes module destruction through a small
test seam. The unchanged master fails on the first 401; the candidate and the
existing iovec/RTSP tests pass, including ASan/UBSan with `b_ndebug=true`.

Strict shairplay-rust live qualification on Linux aarch64 passes all five
feature/profile configurations: six protected and six passwordless 25-second
non-silent sessions are bit-exact, including release and reconnect. Missing and
incorrect passwords produce no audio and terminate with the expected bounded
401 sequence. Receiver production code and the audio oracle are unchanged.

Local candidate: `a64092b4589e202403331c2d312dfc30044ba142`, based on master
`c73df14f03e30c41f6430acd82c6250dcdb168d8`. The live run covers password Digest,
classic RAOP and unencrypted UDP audio; it does not establish MFi or encrypted
playback, a released baseline, or behavior on arbitrary desktop setups.

The native test was strengthened after the live run; the production callback
hash is identical. [Evidence and exact provenance](evidence/pipewire-auth-c73df14f-aarch64/README.md)
record both test versions.

Local preparation only. No branch has been pushed and no MR has been submitted.
