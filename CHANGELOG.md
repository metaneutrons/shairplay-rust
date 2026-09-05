# Changelog

## [0.8.0](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.7.0...shairplay-v0.8.0) (2026-09-02)

### Minimum Supported Rust Version

* **MSRV:** Rust 1.94 or newer is required ([#47](https://github.com/metaneutrons/shairplay-rust/pull/47)) ([484bf4c](https://github.com/metaneutrons/shairplay-rust/commit/484bf4c13d3bff3f85424e940e5b77c9426d43b9))


### Features

* **raop:** configurable AP1 capability advertisement ([#42](https://github.com/metaneutrons/shairplay-rust/issues/42)) ([cd6dc73](https://github.com/metaneutrons/shairplay-rust/commit/cd6dc73699695c5f20e222203bf8ca1b3f211276))
* **raop:** decode raw-PCM (L16) streams and accept unencrypted audio ([#41](https://github.com/metaneutrons/shairplay-rust/issues/41)) ([249560b](https://github.com/metaneutrons/shairplay-rust/commit/249560b231e99129ad9593aa7a4dd5afc84f5175))


### Bug Fixes

* **meta:** point repository at this fork ([#48](https://github.com/metaneutrons/shairplay-rust/issues/48)) ([86e129a](https://github.com/metaneutrons/shairplay-rust/commit/86e129a56297c15b951b995947b817d4d5d85968))
* **raop:** send Server header on RTSP replies ([#40](https://github.com/metaneutrons/shairplay-rust/issues/40)) ([763795b](https://github.com/metaneutrons/shairplay-rust/commit/763795b8cf1571d1d09150202b6292695a00d393))

## [0.7.0](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.6.2...shairplay-v0.7.0) (2026-07-03)


### ⚠ BREAKING CHANGES

* **codec:** the codec module (shairplay::codec::* via #[doc(hidden)]) is now crate-private.
* **api:** items previously reachable via the #[doc(hidden)] module paths (crypto/proto/net internals, codec, raop plumbing) and the async DacpClient API are now crate-private. The documented public API is unchanged.

### Features

* **raop:** advertise PIN-required pairing mode ([1c2c205](https://github.com/metaneutrons/shairplay-rust/commit/1c2c205f0109b517daeac2a44c6adebb56b48f86))
* **raop:** fast AP2 connect + clean session handoff ([#30](https://github.com/metaneutrons/shairplay-rust/issues/30)) ([229c1be](https://github.com/metaneutrons/shairplay-rust/commit/229c1beac8be1c990dae94960bae5ca465faf05b))


### Bug Fixes

* **example:** avoid panic on --name/--persist without a value ([#29](https://github.com/metaneutrons/shairplay-rust/issues/29)) ([f05e7c4](https://github.com/metaneutrons/shairplay-rust/commit/f05e7c405bf000b362f9c70d6dfbdc91678c66ff))
* **raop:** acknowledge AP2 pair-pin-start ([53316c0](https://github.com/metaneutrons/shairplay-rust/commit/53316c0593912b62d4dee881b16b839407a244cc))


### Code Refactoring

* **api:** minimize public API surface to the curated set ([da08b47](https://github.com/metaneutrons/shairplay-rust/commit/da08b4748132fdf415cc1e5f844830ff2679b447))
* **codec:** make the codec module crate-private ([49f8308](https://github.com/metaneutrons/shairplay-rust/commit/49f8308e1bb604018131fcb22be4e29473638fbd))

## [0.6.2](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.6.1...shairplay-v0.6.2) (2026-06-30)


### Bug Fixes

* **raop:** initialize AP2 realtime ALAC decoder ([4275710](https://github.com/metaneutrons/shairplay-rust/commit/4275710dbed01e3d4ad535a2ccf26f45423ce246)), closes [#20](https://github.com/metaneutrons/shairplay-rust/issues/20)

## [0.6.1](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.6.0...shairplay-v0.6.1) (2026-06-29)


### Bug Fixes

* **crypto:** use precomputed MD5 constant table for deterministic FairPlay key ([d341561](https://github.com/metaneutrons/shairplay-rust/commit/d341561be6f864cd10800c1a762c2bc49935f999))
* **raop:** handle AP1 RECORD and advertise reachable mDNS addresses ([8a5a24c](https://github.com/metaneutrons/shairplay-rust/commit/8a5a24c4ab51ee8cd1083cac30b27f7e7d3340b3)), closes [#14](https://github.com/metaneutrons/shairplay-rust/issues/14)
* **raop:** send Audio-Latency on AP1 RECORD for parity with AP2 ([d2a4828](https://github.com/metaneutrons/shairplay-rust/commit/d2a4828b71c4137f7354b23ba80b3cf5e3085b8f))


### Performance Improvements

* **http:** rewrite RTSP→HTTP in place instead of cloning the buffer ([203bd6b](https://github.com/metaneutrons/shairplay-rust/commit/203bd6b624f35c061ffc653d1d93fff75c08fe24))

## [0.6.0](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.5.0...shairplay-v0.6.0) (2026-06-28)


### ⚠ BREAKING CHANGES

* **error:** ProtocolError::DigestAuth, CodecError::AlacDecode, and CodecError::AacDecode are removed (never constructed by the library). The `dacp` module is hidden from documentation; it remains accessible but unsupported.
* **error:** ServerError::{NotStarted, AlreadyRunning, AudioHandler} are removed. They were never constructed by the library, so only a downstream `match` that explicitly named these arms is affected.
* **crypto:** the advertised accessory public key (pk) is now a real secret instead of being derived from the public device id, so already-paired Apple devices must pair once more after upgrade. Wire a persistent PairingStore to keep the identity stable across restarts.

### Features

* **raop:** surface AAC decoder-init failure via on_error ([c5363a8](https://github.com/metaneutrons/shairplay-rust/commit/c5363a8af5cf2a961d8a33f40fd2c9d1b2bdcb97))
* **raop:** wire AudioHandler::on_error to surface failures to apps ([3d3055d](https://github.com/metaneutrons/shairplay-rust/commit/3d3055d7bc3abdd65efc614862278e27e6f55647))


### Bug Fixes

* **crypto:** secure AP2 identity key, close remote-panic and timing holes ([5f16e95](https://github.com/metaneutrons/shairplay-rust/commit/5f16e951e03c7f2b2fbddc47e0cd0639c0172ba7))


### Code Refactoring

* **error:** prune dead error variants, hide internal dacp module ([865f854](https://github.com/metaneutrons/shairplay-rust/commit/865f8549470329d500b616917e86e22596a52220))
* **error:** remove never-constructed ServerError variants ([6ca097a](https://github.com/metaneutrons/shairplay-rust/commit/6ca097a13a1ced066001302f258bcc7d989f23a1))

## [0.5.0](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.4.0...shairplay-v0.5.0) (2026-05-23)


### Features

* **ap2:** add runtime AirPlayMode selection ([be2cc15](https://github.com/metaneutrons/shairplay-rust/commit/be2cc15cfe163c89f0440210827e0e27db10f6b6))

## [0.4.0](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.3.1...shairplay-v0.4.0) (2026-05-23)


### Features

* **ap2:** complete GET /info plist payload and correct eventPort handling on remote control only connections ([8d89127](https://github.com/metaneutrons/shairplay-rust/commit/8d8912794ae6ce9a0b6f53290b7d3f20ecd8abd8))
* **ap2:** implement stable, deterministic Pairing Identifier (pi) derived from MAC address ([bb996d6](https://github.com/metaneutrons/shairplay-rust/commit/bb996d65afd2c33df57875e97b8f8a3525ab38fa))

## [0.3.1](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.3.0...shairplay-v0.3.1) (2026-05-22)


### Bug Fixes

* **deps:** update crates to latest stable versions ([eb13f6d](https://github.com/metaneutrons/shairplay-rust/commit/eb13f6dfc9018e8cfa40775fbfccd508c078b70c))

## [0.3.0](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.2.0...shairplay-v0.3.0) (2026-05-19)


### Features

* **lib:** export video types, mark internal modules doc(hidden) ([32b041e](https://github.com/metaneutrons/shairplay-rust/commit/32b041e144fc4b3cae9b80d327f6ccaf5141b6bf))


### Bug Fixes

* **security:** harden protocol handling and input validation ([8288c7b](https://github.com/metaneutrons/shairplay-rust/commit/8288c7b61a3cc9171b64edd4839769b2c9e54289))

## [0.2.0](https://github.com/metaneutrons/shairplay-rust/compare/shairplay-v0.1.0...shairplay-v0.2.0) (2026-04-05)


### ⚠ BREAKING CHANGES

* move metadata/volume/coverart/progress off audio path

### Features

* --bind option in player example ([f253075](https://github.com/metaneutrons/shairplay-rust/commit/f25307548d64efe10e48da3b6684dcf17ca580a5))
* --persist flag for device identity and pairing key storage ([0edf6bc](https://github.com/metaneutrons/shairplay-rust/commit/0edf6bcd89046e2bfc300c907096107888ae9a63))
* add airplay2 feature gate with conditional dependencies ([e20ca5e](https://github.com/metaneutrons/shairplay-rust/commit/e20ca5e6d34293acad8fb15b30400b8c5606de90))
* add autotools build scripts and new shairplay program ([784848c](https://github.com/metaneutrons/shairplay-rust/commit/784848c78a47ae5d972aebdcb4db0a5d3f33b1bf))
* add BindConfig for address/port/IPv6 control ([3e40b83](https://github.com/metaneutrons/shairplay-rust/commit/3e40b83cc24be4625b7b7eac022c0bd9f50a590b))
* add connection + RTSP request/response logging with status codes ([a643849](https://github.com/metaneutrons/shairplay-rust/commit/a643849ff0082828c4f33e81f96656fa29630b2e))
* add DACP client for remote-controlling Apple devices ([20cd1ad](https://github.com/metaneutrons/shairplay-rust/commit/20cd1ada401a664f646b860744bf3c544d88eef3))
* add debug logging for metadata, volume, coverart, progress ([3f55b31](https://github.com/metaneutrons/shairplay-rust/commit/3f55b310e62f789efffac093a57d309d1ee214db))
* add error and lifecycle callbacks, rename RaopError to ServerError ([53e55a6](https://github.com/metaneutrons/shairplay-rust/commit/53e55a6f8a648bbe9571f676daafcdafd4bd8612))
* **airplay2:** AAC ADTS framing with C-verified test vectors ([d93c457](https://github.com/metaneutrons/shairplay-rust/commit/d93c457103650570666e8ee7357d25f5a199b642))
* **airplay2:** AAC decode via symphonia → PCM → AudioHandler ([72464f9](https://github.com/metaneutrons/shairplay-rust/commit/72464f9d533169ab91ee8ec29ac326021b9bf5a9))
* **airplay2:** activate encrypted RTSP transport after pair-setup ([703f87e](https://github.com/metaneutrons/shairplay-rust/commit/703f87e36c27462650d5818f4845cad8dd8a4c6b))
* **airplay2:** AP2 mDNS registration with full feature flags ([0f194c8](https://github.com/metaneutrons/shairplay-rust/commit/0f194c8f67ef6322a76400bc74cb2bed2ed7dc53))
* **airplay2:** AP2 RTSP handlers — pair-setup, pair-verify, GET /info, SETUP ([f53ca78](https://github.com/metaneutrons/shairplay-rust/commit/f53ca78d64b173d3b5830714aac155b686c92212))
* **airplay2:** buffered audio processor (type 103 streams) ([55c54a1](https://github.com/metaneutrons/shairplay-rust/commit/55c54a1f35d3ba88c1f2dd2c09b2b8541c71a101))
* **airplay2:** ChaCha20-Poly1305 encrypted RTSP transport ([5aaca77](https://github.com/metaneutrons/shairplay-rust/commit/5aaca778a3e05b14f593a1ec2b22d35eb37873ca))
* **airplay2:** complete RTSP handler coverage ([81df6d6](https://github.com/metaneutrons/shairplay-rust/commit/81df6d6ad765b39718b7edc590daf5a25b228a96))
* **airplay2:** decode AAC inside library, always deliver PCM ([a82d187](https://github.com/metaneutrons/shairplay-rust/commit/a82d18745619c42d1a2618c5ec7125a82c48d7fc))
* **airplay2:** decrypt buffered audio with shk (ChaCha20-Poly1305) ([1f276f2](https://github.com/metaneutrons/shairplay-rust/commit/1f276f2967e97bfbd56a44987b202b34f24dbffd))
* **airplay2:** encrypted event + RC channels ([1cead9d](https://github.com/metaneutrons/shairplay-rust/commit/1cead9db652781366696dab1c80481c6b1914ace))
* **airplay2:** handle stream type 130 (Remote Control data channel) ([3a3afc1](https://github.com/metaneutrons/shairplay-rust/commit/3a3afc1ccf8c521b236d6fa94b5d2ea4ddaa324e))
* **airplay2:** HomeKit normal pairing (M5/M6) + pair-verify ([f1528f2](https://github.com/metaneutrons/shairplay-rust/commit/f1528f26307c2f320cb97071bef9112aab2e0bcd))
* **airplay2:** HomeKit transient pairing — SRP-6a server ([0802b25](https://github.com/metaneutrons/shairplay-rust/commit/0802b256c56fc3f437abe6ad998e018b58b14414))
* **airplay2:** PairingStore trait for persistent device keys ([1e74823](https://github.com/metaneutrons/shairplay-rust/commit/1e748238afdc96896a4b154a4663fcadfc623430))
* **airplay2:** PTP timing client with message parsing and offset smoothing ([8630cb0](https://github.com/metaneutrons/shairplay-rust/commit/8630cb0828be6d4eec266f9e735705fba76f80d2))
* **airplay2:** PTP-anchored audio playout timing ([c12db00](https://github.com/metaneutrons/shairplay-rust/commit/c12db00a167b8c5ba5051c2f8e5e75f386c102ba))
* **airplay2:** resampling, channel mixdown, session reinit on format change ([333d733](https://github.com/metaneutrons/shairplay-rust/commit/333d733ecb7f22a4ee2d81528627c23861e1550a))
* **airplay2:** sample rate conversion via rubato (44100↔48000) ([62e2353](https://github.com/metaneutrons/shairplay-rust/commit/62e2353f3fb1f70d316202c22acc6569daf0bc31))
* **airplay2:** server advertises as AP2 when feature enabled ([78a36e3](https://github.com/metaneutrons/shairplay-rust/commit/78a36e321864a0610156f92c3ed04d6047470534))
* **airplay2:** SSRC-based format detection + output config ([62b4b99](https://github.com/metaneutrons/shairplay-rust/commit/62b4b99525c8f0c9b5d81c7e721e1220653eb70f))
* **airplay2:** stream SETUP (type 96/103) + RECORD_2, SETRATEANCHORTI, SETPEERS, FLUSHBUFFERED ([025a65a](https://github.com/metaneutrons/shairplay-rust/commit/025a65a5cffaca890577fe1a4de26910bdf0852b))
* **airplay2:** timed playout buffer with PTP anchor and pause/flush ([2adabbe](https://github.com/metaneutrons/shairplay-rust/commit/2adabbe9b5b0515ea6f0f3815632e9efe9c54ce6))
* **airplay2:** TLV codec with C-verified test vectors ([cf65166](https://github.com/metaneutrons/shairplay-rust/commit/cf65166aea39ec6d4344e79b9fc683c3767b9c95))
* **airplay2:** wire buffered audio processor to SETUP type 103 ([c5f7fa7](https://github.com/metaneutrons/shairplay-rust/commit/c5f7fa751a7f6bcf781301c9e4492fe7838c636a))
* AirPlayFeature enum + AP2-REMOTE.md documentation ([48f2bc0](https://github.com/metaneutrons/shairplay-rust/commit/48f2bc04e2257c565bb273a94cb244e5c68fd777))
* AP2 metadata forwarding (volume, artwork, progress, DMAP) ([0b6fc85](https://github.com/metaneutrons/shairplay-rust/commit/0b6fc8558cce9065aebfd2213e9e5d635317f8c3))
* AudioCodec enum so apps know PCM vs AAC format ([363fab9](https://github.com/metaneutrons/shairplay-rust/commit/363fab9e877be1f144ae45e87709660cdfc96e84))
* buffered audio packets are ChaCha20-Poly1305 encrypted with shk ([7ebfd8a](https://github.com/metaneutrons/shairplay-rust/commit/7ebfd8a3dc0666dbd8f554c5418102b2fffdb2a8))
* cross-platform mDNS — astro-dnssd (macOS) + mdns-sd (Linux) ([828cfa8](https://github.com/metaneutrons/shairplay-rust/commit/828cfa8b9f0c41c9a669b76a3711cb9e06a8063b))
* DACP port discovery via mDNS ([61d9ae6](https://github.com/metaneutrons/shairplay-rust/commit/61d9ae6087e7d59ee422287b3fe795d326c25b06))
* decode MR supported commands from iPhone ([0424094](https://github.com/metaneutrons/shairplay-rust/commit/0424094bbd44fe2061ec459dbe703a3614f696ed))
* deliver F32LE interleaved PCM for full 24-bit precision ([58bd297](https://github.com/metaneutrons/shairplay-rust/commit/58bd2975364aaa526ca4ef8c5c0aa794234271c0))
* example player shows AP1/AP2 mode + tracing subscriber ([a0859a8](https://github.com/metaneutrons/shairplay-rust/commit/a0859a845e6e2c167e0bc751401e44fdb8079119))
* **example:** AAC decoding in player app via symphonia ([224ae81](https://github.com/metaneutrons/shairplay-rust/commit/224ae81868cdeda4e8e81b35d9c29cfc59bc8219))
* full AP2 protocol trace working ([1162184](https://github.com/metaneutrons/shairplay-rust/commit/11621840aeea6d75accfd33c92e8b52f1831da5f))
* HLS (HTTP Live Streaming) support behind 'hls' feature gate ([72312b2](https://github.com/metaneutrons/shairplay-rust/commit/72312b20c10b80a8956a74bc6741f1777dd135b1))
* improve SETUP logging — stream types, keys, mirroring state ([4de5ea6](https://github.com/metaneutrons/shairplay-rust/commit/4de5ea609c8a3523a5179249305e149133468b35))
* legacy ALAC audio for video feature — NTP timing, plist SETUP routing ([29e57bf](https://github.com/metaneutrons/shairplay-rust/commit/29e57bf623056c42f553455ef21b0e84c5cc4cb9))
* make resampling optional via 'resample' feature flag ([f2369dd](https://github.com/metaneutrons/shairplay-rust/commit/f2369dd46ff9c837b331914d7705d2045841255e))
* move metadata/volume/coverart/progress off audio path ([2a53225](https://github.com/metaneutrons/shairplay-rust/commit/2a532252ccd38d390cc99087f7b4bf78961d3d9b))
* multi-interface binding support ([d67b5e0](https://github.com/metaneutrons/shairplay-rust/commit/d67b5e073b483eb30682593fd1aca2be26f30633))
* normal HomeKit pairing with persistent key storage ([56a689e](https://github.com/metaneutrons/shairplay-rust/commit/56a689e512b8c31373698e9f837bdcbb7d3eb2fe))
* output_sample_rate and resampling available for AP1 and AP2 ([f92252b](https://github.com/metaneutrons/shairplay-rust/commit/f92252b18a7cfe7c7c6cc9bda3b0936fb700d255))
* parse DMAP metadata — deliver TrackMetadata struct instead of raw bytes ([8dc0ad8](https://github.com/metaneutrons/shairplay-rust/commit/8dc0ad8777b97eb29342d4bcd37f5b7abedd3ea4))
* pure Rust AirPlay server library ([844af58](https://github.com/metaneutrons/shairplay-rust/commit/844af584382ecb3de111ae63ac2e4460e3265bc8))
* realtime ALAC receiver (stream type 96) ([36b424f](https://github.com/metaneutrons/shairplay-rust/commit/36b424ff3debd53bb34c73d50898f7ddb6fe94ed))
* unified RemoteControl trait for AP1 (DACP) and AP2 ([d148e27](https://github.com/metaneutrons/shairplay-rust/commit/d148e270e7c9dbf59a36ea261fa603afd72c8040))
* video (screen mirroring) support behind `video` feature gate ([2920ae3](https://github.com/metaneutrons/shairplay-rust/commit/2920ae3e5e1b385a8b87a4e5d13a01a70bb54f4f))
* video screen mirroring — working on iOS 18 ([7a34cbb](https://github.com/metaneutrons/shairplay-rust/commit/7a34cbba5a093438e811d716527cd7f8b4811bb1))


### Bug Fixes

* advertise et=0,3,5 (none, FairPlay, and FairPlay SAP 2.5) ([2b3c9ef](https://github.com/metaneutrons/shairplay-rust/commit/2b3c9ef363b0ca4de606f81afb877e0890e26cd5))
* **airplay2:** activate encryption via after_response() callback ([bdc15dd](https://github.com/metaneutrons/shairplay-rust/commit/bdc15ddc865fea3c8a99ef95c80348b8c4a8f190))
* **airplay2:** bind event port on IPv6 when client connects via IPv6 ([f1e475a](https://github.com/metaneutrons/shairplay-rust/commit/f1e475ac2bf2d3402e2c36e360e06a1bda330e94))
* **airplay2:** bind real event port in initial SETUP ([e3fde32](https://github.com/metaneutrons/shairplay-rust/commit/e3fde3226f88e5b67ef11c1d65139dd48f813e44))
* **airplay2:** buffered audio uses simple length-prefixed TCP framing ([55c987d](https://github.com/metaneutrons/shairplay-rust/commit/55c987d46bfdc01a5bb849dc32c906939d08e805))
* **airplay2:** delay encryption until after pair-setup response is sent ([45f35ea](https://github.com/metaneutrons/shairplay-rust/commit/45f35ea49c9f6547075d77d20a0b22a0bf60092f))
* **airplay2:** discard stale frames on resume/track change ([27d7296](https://github.com/metaneutrons/shairplay-rust/commit/27d72966e9fe2d1eb1735eaefa0c9ab2fc5f37dc))
* **airplay2:** don't clear buffer on pause, only stop delivery ([5c66ede](https://github.com/metaneutrons/shairplay-rust/commit/5c66eded6c3caccb9ea5198e61fc00f8008db145))
* **airplay2:** enable AP1 fallback in mDNS advertisement ([9b2479d](https://github.com/metaneutrons/shairplay-rust/commit/9b2479d6abdf3c12ab2173b0bded2da6adc48c95))
* **airplay2:** persistent AAC decoder with streaming pipe ([a31e40a](https://github.com/metaneutrons/shairplay-rust/commit/a31e40a75c8921bd3916117e659889d7683c85dd))
* **airplay2:** proper timingPeerInfo addresses + RC connection handling ([405ab80](https://github.com/metaneutrons/shairplay-rust/commit/405ab803a88a1c2e91a83702a980b08b98c60442))
* **airplay2:** route SETRATEANCHORTIME (correct method name) ([c6aa1a1](https://github.com/metaneutrons/shairplay-rust/commit/c6aa1a1076ec8fc2da75e3baf1868e4af689f6d4))
* **airplay2:** use local wall clock for playout timing ([f7e09ce](https://github.com/metaneutrons/shairplay-rust/commit/f7e09ce0a135329f9cb21128ab218a660fe6e165))
* **airplay2:** use wrapping RTP timestamp comparison for frame delivery ([76e0ae9](https://github.com/metaneutrons/shairplay-rust/commit/76e0ae9d3366bdd12bd336dec417d8cb6f1b5022))
* ALAC BitReader bounds check — prevent panic on short packets ([baf90ef](https://github.com/metaneutrons/shairplay-rust/commit/baf90ef197cba6aac25eacad79367c64a4d492be))
* always return dataPort for type 130 stream setup ([f0bb2ea](https://github.com/metaneutrons/shairplay-rust/commit/f0bb2ea479e93bd8feef6e0057ed34247d29107f))
* AP1 audio silent when resample feature enabled without library resampler ([c403a8f](https://github.com/metaneutrons/shairplay-rust/commit/c403a8f8f689f8c021f7109c10fe4dc14f83e60e))
* check request completeness after adding decrypted data ([85d9909](https://github.com/metaneutrons/shairplay-rust/commit/85d99090f41a8cc53d6eaf66cb17cf48cfe6afb7))
* DACP use remote IP + port 3689 instead of mDNS resolve ([0452f02](https://github.com/metaneutrons/shairplay-rust/commit/0452f02c18ef3a375664b71e7877899d8d0295dc))
* empty feedback response when not playing (matches shairport-sync) ([6616129](https://github.com/metaneutrons/shairplay-rust/commit/661612939f3d7cc80ab12d20d33e055f15d922d9))
* ensure txtvers is first in TXT records (iPhone compatibility) ([ac26fd9](https://github.com/metaneutrons/shairplay-rust/commit/ac26fd94f5f25fcdec9131e191010584e4d45277))
* example discovery, suppress warnings ([41990a0](https://github.com/metaneutrons/shairplay-rust/commit/41990a07802e0d62d4b41ec5abe79b816a1691d0))
* **example:** probe ADTS frame for correct AAC codec parameters ([97082a8](https://github.com/metaneutrons/shairplay-rust/commit/97082a89ede22c7c30dcfd2704ffcf7fc1735063))
* force 44100 Hz output to match AirPlay sample rate ([38bcfbd](https://github.com/metaneutrons/shairplay-rust/commit/38bcfbd9f4f4eecbc0d1e4820d5159b84876f8c8))
* graceful fallback when no audio output device available ([4400531](https://github.com/metaneutrons/shairplay-rust/commit/44005310798c790d4f650d598a00699d32a02b78))
* handle pipelined RTSP requests with leftover body data ([30b823c](https://github.com/metaneutrons/shairplay-rust/commit/30b823ce8d9d297fc846368066db2dcf7dfb2024))
* harden ALAC decoder — catch_unwind for malformed input ([1a48786](https://github.com/metaneutrons/shairplay-rust/commit/1a487861842a4b6d6fc9d5913e25c3fc2378c16e))
* only register _airplay._tcp for AP2 ([5a2a3ff](https://github.com/metaneutrons/shairplay-rust/commit/5a2a3ff672ce38febf11056ac78780fa24d46428))
* preserve TXT record insertion order for iOS compatibility ([f990292](https://github.com/metaneutrons/shairplay-rust/commit/f99029258492f376d7ee8065aa51183b623e7d07))
* reduce AP2 feature bitmask to match shairport-sync (0x1C340405D4A00) ([0232eb0](https://github.com/metaneutrons/shairplay-rust/commit/0232eb0d600d3f8391d6f5ac8f9747aea5e56ff7))
* reduce playout delay from ~6s to ~100ms ([a08c724](https://github.com/metaneutrons/shairplay-rust/commit/a08c724ce9094ac9f83da95949f69e3214226f99))
* resampler was never initialized (duplicate SSRC block bug) ([754f24d](https://github.com/metaneutrons/shairplay-rust/commit/754f24dfe35c7ad4aff3c16f19d6d7d54fa2c931))
* revert to astro-dnssd (upstream crates.io) for mDNS ([a5add9f](https://github.com/metaneutrons/shairplay-rust/commit/a5add9fa3be6a18f043dc3f07ff58914687b9cce))
* RTP and AP2 sub-listeners bind to unspecified for link-local IPv6 ([1c20abb](https://github.com/metaneutrons/shairplay-rust/commit/1c20abb813b03a7bc18ebc455b258de66cebba29))
* RTSP/1.0 parsing — Apple devices don't send HTTP/1.0 ([9fd7a92](https://github.com/metaneutrons/shairplay-rust/commit/9fd7a92bed8cb1d88c65ecddf7fb70b10ec9c5df))
* send full device info in updateInfo for faster startup ([9d44c38](https://github.com/metaneutrons/shairplay-rust/commit/9d44c38bf035e6d50ac8db734eaffacd69830176))
* send updateInfo on event channel to eliminate 6s startup delay ([c6af2bd](https://github.com/metaneutrons/shairplay-rust/commit/c6af2bda40993c68d0f10ce6d9727eb6fa1b7133))
* StreamResampler buffers input for variable-size chunks ([8decf49](https://github.com/metaneutrons/shairplay-rust/commit/8decf494318ae1386f16fd019a4e543e312f7140))


### Performance Improvements

* move DMAP parsing off audio delivery path ([a17bda0](https://github.com/metaneutrons/shairplay-rust/commit/a17bda002d7213ca2796eec4ad496186bacb3dff))


### Reverts

* "fix: always return dataPort for type 130 stream setup" ([f31addb](https://github.com/metaneutrons/shairplay-rust/commit/f31addb875e98e4d7a117b8b7b0995370d93dd22))
* "research: add eventPort + updateInfo to RC connection (untested)" ([8bcd514](https://github.com/metaneutrons/shairplay-rust/commit/8bcd51415be6019349e7e46109dae0e4ade23687))
* RC eventPort and dataPort changes (no effect on delay) ([15d2be4](https://github.com/metaneutrons/shairplay-rust/commit/15d2be4605fbd716870162ab4defb58a9542318f))

## 0.1.0 (2026-04-05)


### Features

* --bind option in player example ([f253075](https://github.com/metaneutrons/shairplay-rust/commit/f25307548d64efe10e48da3b6684dcf17ca580a5))
* --persist flag for device identity and pairing key storage ([0edf6bc](https://github.com/metaneutrons/shairplay-rust/commit/0edf6bcd89046e2bfc300c907096107888ae9a63))
* add airplay2 feature gate with conditional dependencies ([e20ca5e](https://github.com/metaneutrons/shairplay-rust/commit/e20ca5e6d34293acad8fb15b30400b8c5606de90))
* add autotools build scripts and new shairplay program ([784848c](https://github.com/metaneutrons/shairplay-rust/commit/784848c78a47ae5d972aebdcb4db0a5d3f33b1bf))
* add BindConfig for address/port/IPv6 control ([3e40b83](https://github.com/metaneutrons/shairplay-rust/commit/3e40b83cc24be4625b7b7eac022c0bd9f50a590b))
* add connection + RTSP request/response logging with status codes ([a643849](https://github.com/metaneutrons/shairplay-rust/commit/a643849ff0082828c4f33e81f96656fa29630b2e))
* add DACP client for remote-controlling Apple devices ([20cd1ad](https://github.com/metaneutrons/shairplay-rust/commit/20cd1ada401a664f646b860744bf3c544d88eef3))
* add debug logging for metadata, volume, coverart, progress ([3f55b31](https://github.com/metaneutrons/shairplay-rust/commit/3f55b310e62f789efffac093a57d309d1ee214db))
* **airplay2:** AAC ADTS framing with C-verified test vectors ([d93c457](https://github.com/metaneutrons/shairplay-rust/commit/d93c457103650570666e8ee7357d25f5a199b642))
* **airplay2:** AAC decode via symphonia → PCM → AudioHandler ([72464f9](https://github.com/metaneutrons/shairplay-rust/commit/72464f9d533169ab91ee8ec29ac326021b9bf5a9))
* **airplay2:** activate encrypted RTSP transport after pair-setup ([703f87e](https://github.com/metaneutrons/shairplay-rust/commit/703f87e36c27462650d5818f4845cad8dd8a4c6b))
* **airplay2:** AP2 mDNS registration with full feature flags ([0f194c8](https://github.com/metaneutrons/shairplay-rust/commit/0f194c8f67ef6322a76400bc74cb2bed2ed7dc53))
* **airplay2:** AP2 RTSP handlers — pair-setup, pair-verify, GET /info, SETUP ([f53ca78](https://github.com/metaneutrons/shairplay-rust/commit/f53ca78d64b173d3b5830714aac155b686c92212))
* **airplay2:** buffered audio processor (type 103 streams) ([55c54a1](https://github.com/metaneutrons/shairplay-rust/commit/55c54a1f35d3ba88c1f2dd2c09b2b8541c71a101))
* **airplay2:** ChaCha20-Poly1305 encrypted RTSP transport ([5aaca77](https://github.com/metaneutrons/shairplay-rust/commit/5aaca778a3e05b14f593a1ec2b22d35eb37873ca))
* **airplay2:** complete RTSP handler coverage ([81df6d6](https://github.com/metaneutrons/shairplay-rust/commit/81df6d6ad765b39718b7edc590daf5a25b228a96))
* **airplay2:** decode AAC inside library, always deliver PCM ([a82d187](https://github.com/metaneutrons/shairplay-rust/commit/a82d18745619c42d1a2618c5ec7125a82c48d7fc))
* **airplay2:** decrypt buffered audio with shk (ChaCha20-Poly1305) ([1f276f2](https://github.com/metaneutrons/shairplay-rust/commit/1f276f2967e97bfbd56a44987b202b34f24dbffd))
* **airplay2:** encrypted event + RC channels ([1cead9d](https://github.com/metaneutrons/shairplay-rust/commit/1cead9db652781366696dab1c80481c6b1914ace))
* **airplay2:** handle stream type 130 (Remote Control data channel) ([3a3afc1](https://github.com/metaneutrons/shairplay-rust/commit/3a3afc1ccf8c521b236d6fa94b5d2ea4ddaa324e))
* **airplay2:** HomeKit normal pairing (M5/M6) + pair-verify ([f1528f2](https://github.com/metaneutrons/shairplay-rust/commit/f1528f26307c2f320cb97071bef9112aab2e0bcd))
* **airplay2:** HomeKit transient pairing — SRP-6a server ([0802b25](https://github.com/metaneutrons/shairplay-rust/commit/0802b256c56fc3f437abe6ad998e018b58b14414))
* **airplay2:** PairingStore trait for persistent device keys ([1e74823](https://github.com/metaneutrons/shairplay-rust/commit/1e748238afdc96896a4b154a4663fcadfc623430))
* **airplay2:** PTP timing client with message parsing and offset smoothing ([8630cb0](https://github.com/metaneutrons/shairplay-rust/commit/8630cb0828be6d4eec266f9e735705fba76f80d2))
* **airplay2:** PTP-anchored audio playout timing ([c12db00](https://github.com/metaneutrons/shairplay-rust/commit/c12db00a167b8c5ba5051c2f8e5e75f386c102ba))
* **airplay2:** resampling, channel mixdown, session reinit on format change ([333d733](https://github.com/metaneutrons/shairplay-rust/commit/333d733ecb7f22a4ee2d81528627c23861e1550a))
* **airplay2:** sample rate conversion via rubato (44100↔48000) ([62e2353](https://github.com/metaneutrons/shairplay-rust/commit/62e2353f3fb1f70d316202c22acc6569daf0bc31))
* **airplay2:** server advertises as AP2 when feature enabled ([78a36e3](https://github.com/metaneutrons/shairplay-rust/commit/78a36e321864a0610156f92c3ed04d6047470534))
* **airplay2:** SSRC-based format detection + output config ([62b4b99](https://github.com/metaneutrons/shairplay-rust/commit/62b4b99525c8f0c9b5d81c7e721e1220653eb70f))
* **airplay2:** stream SETUP (type 96/103) + RECORD_2, SETRATEANCHORTI, SETPEERS, FLUSHBUFFERED ([025a65a](https://github.com/metaneutrons/shairplay-rust/commit/025a65a5cffaca890577fe1a4de26910bdf0852b))
* **airplay2:** timed playout buffer with PTP anchor and pause/flush ([2adabbe](https://github.com/metaneutrons/shairplay-rust/commit/2adabbe9b5b0515ea6f0f3815632e9efe9c54ce6))
* **airplay2:** TLV codec with C-verified test vectors ([cf65166](https://github.com/metaneutrons/shairplay-rust/commit/cf65166aea39ec6d4344e79b9fc683c3767b9c95))
* **airplay2:** wire buffered audio processor to SETUP type 103 ([c5f7fa7](https://github.com/metaneutrons/shairplay-rust/commit/c5f7fa751a7f6bcf781301c9e4492fe7838c636a))
* AirPlayFeature enum + AP2-REMOTE.md documentation ([48f2bc0](https://github.com/metaneutrons/shairplay-rust/commit/48f2bc04e2257c565bb273a94cb244e5c68fd777))
* AP2 metadata forwarding (volume, artwork, progress, DMAP) ([0b6fc85](https://github.com/metaneutrons/shairplay-rust/commit/0b6fc8558cce9065aebfd2213e9e5d635317f8c3))
* AudioCodec enum so apps know PCM vs AAC format ([363fab9](https://github.com/metaneutrons/shairplay-rust/commit/363fab9e877be1f144ae45e87709660cdfc96e84))
* buffered audio packets are ChaCha20-Poly1305 encrypted with shk ([7ebfd8a](https://github.com/metaneutrons/shairplay-rust/commit/7ebfd8a3dc0666dbd8f554c5418102b2fffdb2a8))
* cross-platform mDNS — astro-dnssd (macOS) + mdns-sd (Linux) ([828cfa8](https://github.com/metaneutrons/shairplay-rust/commit/828cfa8b9f0c41c9a669b76a3711cb9e06a8063b))
* DACP port discovery via mDNS ([61d9ae6](https://github.com/metaneutrons/shairplay-rust/commit/61d9ae6087e7d59ee422287b3fe795d326c25b06))
* decode MR supported commands from iPhone ([0424094](https://github.com/metaneutrons/shairplay-rust/commit/0424094bbd44fe2061ec459dbe703a3614f696ed))
* deliver F32LE interleaved PCM for full 24-bit precision ([58bd297](https://github.com/metaneutrons/shairplay-rust/commit/58bd2975364aaa526ca4ef8c5c0aa794234271c0))
* example player shows AP1/AP2 mode + tracing subscriber ([a0859a8](https://github.com/metaneutrons/shairplay-rust/commit/a0859a845e6e2c167e0bc751401e44fdb8079119))
* **example:** AAC decoding in player app via symphonia ([224ae81](https://github.com/metaneutrons/shairplay-rust/commit/224ae81868cdeda4e8e81b35d9c29cfc59bc8219))
* full AP2 protocol trace working ([1162184](https://github.com/metaneutrons/shairplay-rust/commit/11621840aeea6d75accfd33c92e8b52f1831da5f))
* HLS (HTTP Live Streaming) support behind 'hls' feature gate ([72312b2](https://github.com/metaneutrons/shairplay-rust/commit/72312b20c10b80a8956a74bc6741f1777dd135b1))
* improve SETUP logging — stream types, keys, mirroring state ([4de5ea6](https://github.com/metaneutrons/shairplay-rust/commit/4de5ea609c8a3523a5179249305e149133468b35))
* legacy ALAC audio for video feature — NTP timing, plist SETUP routing ([29e57bf](https://github.com/metaneutrons/shairplay-rust/commit/29e57bf623056c42f553455ef21b0e84c5cc4cb9))
* make resampling optional via 'resample' feature flag ([f2369dd](https://github.com/metaneutrons/shairplay-rust/commit/f2369dd46ff9c837b331914d7705d2045841255e))
* multi-interface binding support ([d67b5e0](https://github.com/metaneutrons/shairplay-rust/commit/d67b5e073b483eb30682593fd1aca2be26f30633))
* normal HomeKit pairing with persistent key storage ([56a689e](https://github.com/metaneutrons/shairplay-rust/commit/56a689e512b8c31373698e9f837bdcbb7d3eb2fe))
* output_sample_rate and resampling available for AP1 and AP2 ([f92252b](https://github.com/metaneutrons/shairplay-rust/commit/f92252b18a7cfe7c7c6cc9bda3b0936fb700d255))
* pure Rust AirPlay server library ([844af58](https://github.com/metaneutrons/shairplay-rust/commit/844af584382ecb3de111ae63ac2e4460e3265bc8))
* realtime ALAC receiver (stream type 96) ([36b424f](https://github.com/metaneutrons/shairplay-rust/commit/36b424ff3debd53bb34c73d50898f7ddb6fe94ed))
* unified RemoteControl trait for AP1 (DACP) and AP2 ([d148e27](https://github.com/metaneutrons/shairplay-rust/commit/d148e270e7c9dbf59a36ea261fa603afd72c8040))
* video (screen mirroring) support behind `video` feature gate ([2920ae3](https://github.com/metaneutrons/shairplay-rust/commit/2920ae3e5e1b385a8b87a4e5d13a01a70bb54f4f))
* video screen mirroring — working on iOS 18 ([7a34cbb](https://github.com/metaneutrons/shairplay-rust/commit/7a34cbba5a093438e811d716527cd7f8b4811bb1))


### Bug Fixes

* advertise et=0,3,5 (none, FairPlay, and FairPlay SAP 2.5) ([2b3c9ef](https://github.com/metaneutrons/shairplay-rust/commit/2b3c9ef363b0ca4de606f81afb877e0890e26cd5))
* **airplay2:** activate encryption via after_response() callback ([bdc15dd](https://github.com/metaneutrons/shairplay-rust/commit/bdc15ddc865fea3c8a99ef95c80348b8c4a8f190))
* **airplay2:** bind event port on IPv6 when client connects via IPv6 ([f1e475a](https://github.com/metaneutrons/shairplay-rust/commit/f1e475ac2bf2d3402e2c36e360e06a1bda330e94))
* **airplay2:** bind real event port in initial SETUP ([e3fde32](https://github.com/metaneutrons/shairplay-rust/commit/e3fde3226f88e5b67ef11c1d65139dd48f813e44))
* **airplay2:** buffered audio uses simple length-prefixed TCP framing ([55c987d](https://github.com/metaneutrons/shairplay-rust/commit/55c987d46bfdc01a5bb849dc32c906939d08e805))
* **airplay2:** delay encryption until after pair-setup response is sent ([45f35ea](https://github.com/metaneutrons/shairplay-rust/commit/45f35ea49c9f6547075d77d20a0b22a0bf60092f))
* **airplay2:** discard stale frames on resume/track change ([27d7296](https://github.com/metaneutrons/shairplay-rust/commit/27d72966e9fe2d1eb1735eaefa0c9ab2fc5f37dc))
* **airplay2:** don't clear buffer on pause, only stop delivery ([5c66ede](https://github.com/metaneutrons/shairplay-rust/commit/5c66eded6c3caccb9ea5198e61fc00f8008db145))
* **airplay2:** enable AP1 fallback in mDNS advertisement ([9b2479d](https://github.com/metaneutrons/shairplay-rust/commit/9b2479d6abdf3c12ab2173b0bded2da6adc48c95))
* **airplay2:** persistent AAC decoder with streaming pipe ([a31e40a](https://github.com/metaneutrons/shairplay-rust/commit/a31e40a75c8921bd3916117e659889d7683c85dd))
* **airplay2:** proper timingPeerInfo addresses + RC connection handling ([405ab80](https://github.com/metaneutrons/shairplay-rust/commit/405ab803a88a1c2e91a83702a980b08b98c60442))
* **airplay2:** route SETRATEANCHORTIME (correct method name) ([c6aa1a1](https://github.com/metaneutrons/shairplay-rust/commit/c6aa1a1076ec8fc2da75e3baf1868e4af689f6d4))
* **airplay2:** use local wall clock for playout timing ([f7e09ce](https://github.com/metaneutrons/shairplay-rust/commit/f7e09ce0a135329f9cb21128ab218a660fe6e165))
* **airplay2:** use wrapping RTP timestamp comparison for frame delivery ([76e0ae9](https://github.com/metaneutrons/shairplay-rust/commit/76e0ae9d3366bdd12bd336dec417d8cb6f1b5022))
* ALAC BitReader bounds check — prevent panic on short packets ([baf90ef](https://github.com/metaneutrons/shairplay-rust/commit/baf90ef197cba6aac25eacad79367c64a4d492be))
* always return dataPort for type 130 stream setup ([f0bb2ea](https://github.com/metaneutrons/shairplay-rust/commit/f0bb2ea479e93bd8feef6e0057ed34247d29107f))
* AP1 audio silent when resample feature enabled without library resampler ([c403a8f](https://github.com/metaneutrons/shairplay-rust/commit/c403a8f8f689f8c021f7109c10fe4dc14f83e60e))
* check request completeness after adding decrypted data ([85d9909](https://github.com/metaneutrons/shairplay-rust/commit/85d99090f41a8cc53d6eaf66cb17cf48cfe6afb7))
* DACP use remote IP + port 3689 instead of mDNS resolve ([0452f02](https://github.com/metaneutrons/shairplay-rust/commit/0452f02c18ef3a375664b71e7877899d8d0295dc))
* empty feedback response when not playing (matches shairport-sync) ([6616129](https://github.com/metaneutrons/shairplay-rust/commit/661612939f3d7cc80ab12d20d33e055f15d922d9))
* ensure txtvers is first in TXT records (iPhone compatibility) ([ac26fd9](https://github.com/metaneutrons/shairplay-rust/commit/ac26fd94f5f25fcdec9131e191010584e4d45277))
* example discovery, suppress warnings ([41990a0](https://github.com/metaneutrons/shairplay-rust/commit/41990a07802e0d62d4b41ec5abe79b816a1691d0))
* **example:** probe ADTS frame for correct AAC codec parameters ([97082a8](https://github.com/metaneutrons/shairplay-rust/commit/97082a89ede22c7c30dcfd2704ffcf7fc1735063))
* force 44100 Hz output to match AirPlay sample rate ([38bcfbd](https://github.com/metaneutrons/shairplay-rust/commit/38bcfbd9f4f4eecbc0d1e4820d5159b84876f8c8))
* graceful fallback when no audio output device available ([4400531](https://github.com/metaneutrons/shairplay-rust/commit/44005310798c790d4f650d598a00699d32a02b78))
* handle pipelined RTSP requests with leftover body data ([30b823c](https://github.com/metaneutrons/shairplay-rust/commit/30b823ce8d9d297fc846368066db2dcf7dfb2024))
* harden ALAC decoder — catch_unwind for malformed input ([1a48786](https://github.com/metaneutrons/shairplay-rust/commit/1a487861842a4b6d6fc9d5913e25c3fc2378c16e))
* only register _airplay._tcp for AP2 ([5a2a3ff](https://github.com/metaneutrons/shairplay-rust/commit/5a2a3ff672ce38febf11056ac78780fa24d46428))
* preserve TXT record insertion order for iOS compatibility ([f990292](https://github.com/metaneutrons/shairplay-rust/commit/f99029258492f376d7ee8065aa51183b623e7d07))
* reduce AP2 feature bitmask to match shairport-sync (0x1C340405D4A00) ([0232eb0](https://github.com/metaneutrons/shairplay-rust/commit/0232eb0d600d3f8391d6f5ac8f9747aea5e56ff7))
* reduce playout delay from ~6s to ~100ms ([a08c724](https://github.com/metaneutrons/shairplay-rust/commit/a08c724ce9094ac9f83da95949f69e3214226f99))
* resampler was never initialized (duplicate SSRC block bug) ([754f24d](https://github.com/metaneutrons/shairplay-rust/commit/754f24dfe35c7ad4aff3c16f19d6d7d54fa2c931))
* revert to astro-dnssd (upstream crates.io) for mDNS ([a5add9f](https://github.com/metaneutrons/shairplay-rust/commit/a5add9fa3be6a18f043dc3f07ff58914687b9cce))
* RTP and AP2 sub-listeners bind to unspecified for link-local IPv6 ([1c20abb](https://github.com/metaneutrons/shairplay-rust/commit/1c20abb813b03a7bc18ebc455b258de66cebba29))
* RTSP/1.0 parsing — Apple devices don't send HTTP/1.0 ([9fd7a92](https://github.com/metaneutrons/shairplay-rust/commit/9fd7a92bed8cb1d88c65ecddf7fb70b10ec9c5df))
* send full device info in updateInfo for faster startup ([9d44c38](https://github.com/metaneutrons/shairplay-rust/commit/9d44c38bf035e6d50ac8db734eaffacd69830176))
* send updateInfo on event channel to eliminate 6s startup delay ([c6af2bd](https://github.com/metaneutrons/shairplay-rust/commit/c6af2bda40993c68d0f10ce6d9727eb6fa1b7133))
* StreamResampler buffers input for variable-size chunks ([8decf49](https://github.com/metaneutrons/shairplay-rust/commit/8decf494318ae1386f16fd019a4e543e312f7140))


### Reverts

* "fix: always return dataPort for type 130 stream setup" ([f31addb](https://github.com/metaneutrons/shairplay-rust/commit/f31addb875e98e4d7a117b8b7b0995370d93dd22))
* "research: add eventPort + updateInfo to RC connection (untested)" ([8bcd514](https://github.com/metaneutrons/shairplay-rust/commit/8bcd51415be6019349e7e46109dae0e4ade23687))
* RC eventPort and dataPort changes (no effect on delay) ([15d2be4](https://github.com/metaneutrons/shairplay-rust/commit/15d2be4605fbd716870162ab4defb58a9542318f))

## Changelog
