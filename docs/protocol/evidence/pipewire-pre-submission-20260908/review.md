# Independent pre-submission review — 2026-09-08

An independent Codex reviewer (Luna/max), separate from the implementation author, reviewed the TCP and authentication candidates without modifying them. The review found one material issue: a negative result from OPTIONS challenge parsing or request construction was only logged by the RTSP dispatcher, leaving the sender connected without advancing or terminating.

Commit `61446aa7c72341fec9b64dbea666395c9c4438e1` fixes this by scheduling destruction when `rtsp_do_options_auth()` returns a parse or send error. The new negative regression failed before the correction and passed afterward. It covers absent, malformed and unsupported challenges and missing credentials for both OPTIONS and auth-setup, using a real RTSP client and observing exactly one destruction request. The reviewer checked the resolution and reported no further material findings in the final TCP/auth candidates.

Extending the native OPTIONS coverage also exposed a pre-existing duplicate Basic scheme (`Basic Basic ...`). Commit `73f10aaff` removes the duplicate. The native test independently calculates the expected Basic value and checks OPTIONS, POST and ANNOUNCE; Digest checks use independently calculated hashes and the actual request method/URI.

The logs in `review/` record these failures and the corrected native result. All credentials in the native fixture are synthetic test values. Final combined native sanitizer logs are recorded separately for each architecture.

Patch reconstruction was checked independently: applying the TCP and auth patch files to clean `c73df14f` reproduces the exact Git tree of combined commit `bc1550df93fc87e43959c3248872e3898c7cd624`. The auth patch also applies independently. An offline clone of the supplied receiver bundle is clean at `ced748a8fbd9d5b3a8ff2c9513139d5a4d508f40` and contains the identical combined patch.

No branch, MR, comment or attachment was published during preparation.
