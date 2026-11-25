# AAC-ELD buffer fixtures

`stereo-44100-512.aaceld` contains five raw stereo AAC-ELD access units encoded
at 44.1 kHz with 512 samples per channel. The file is a small test container,
not an AAC or ADTS stream: it has the ASCII magic `RAOP-AAC-ELD`, a version byte
`01`, a big-endian `u16` access-unit count, then repeated big-endian `u16`
lengths and unmodified raw access-unit bytes. The generator extracts the
variable packet lengths from CAF's `pakt` table.

The source is a deterministic synthetic stereo waveform: 440 Hz plus an 880 Hz
harmonic on the left, and 659.25 Hz plus a 1318.5 Hz harmonic on the right.
There is no external or copyrighted audio in this fixture. The waveform is
encoded with Apple's `afconvert` AAC-ELD encoder (`aace`, 96 kbit/s). It was
generated with `afconvert` 2.0 on macOS 27.2.1. The AAC encoder can produce
different bytes across macOS versions; the committed file hash records this
specific output and does not promise cross-version byte reproducibility.

Regenerate or check the committed vector on macOS with:

```sh
python3 tests/data/aac-eld/generate.py
python3 tests/data/aac-eld/generate.py --check
```

The committed fixture is 706 bytes with SHA-256
`a4c539d3ec5e108bff56e182cfc7611a8a91b51c797d7d2098eaca43c1c3d084`.
The Rust tests do not invoke `afconvert`; they use the checked-in access units
and compare `RaopBuffer` output with a separately initialized raw
`rusty_aac::decode::Decoder` using the same stream configuration. This checks
RTP ordering and AES-CBC transport against the raw decoder input path; it is
not an independent AAC decoder conformance comparison. The Rust tests use fixed,
nonzero AES key and IV values reserved for these synthetic fixtures.
