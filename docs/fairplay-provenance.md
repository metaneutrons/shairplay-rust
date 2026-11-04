# FairPlay: provenance and licensing

This page describes where the FairPlay code in this crate comes from, what I
believe about its legal status, and what remains uncertain. It is not legal
advice. I would rather state the uncertainty than hide it.

## What the code does

The FairPlay key exchange (`POST /fp-setup`, `a=fpaeskey`, and the AirPlay 2 video
keys) lets a receiver unwrap the AES session key that an Apple sender wraps for it.
The code lives in `src/crypto/fairplay*.rs` and in the binary data files under
`src/crypto/fairplay_data/`. It is compiled with the `fairplay` feature, which is
**enabled by default**.

## History

- **Releases up to and including 0.10.0** contained a Rust port of the `playfair`
  library. The structure, the function boundaries, the names and the constant
  tables followed the C source, which was available to the author.
- **Since the change that introduced this page** the code is rewritten. The
  structure is different: table-driven ciphers with a shared byte shuffle, a
  round-key type, separate digest and cipher modules, new names throughout, and the
  constants stored as binary data files. It is tested against 256 golden vectors
  produced by running the C reference on pseudo-random inputs
  (`tests/data/fairplay_golden.txt`) and against the intermediate vectors of the
  individual steps.
- **This is not a clean-room implementation.** The author had read the reference
  before writing the new code. I do not claim independent creation.

## Where the original comes from

The C code originates from the `playfair` library by EstebanKubata (2015), which the
upstream [shairplay](https://github.com/juhovh/shairplay) project ships under the
GPL-3.0 and builds only on request (`--with-playfair`). What I could establish:

- The repository contains the GPL-3.0 text, without a named copyright holder, and
  the source files carry no per-file notice.
- Nothing states which Apple binary or document the knowledge came from or how it
  was obtained. Projects that bundle it, for example RPiPlay, describe its legal
  status as unclear.
- I found no permissively licensed alternative implementation of the same
  handshake.

## My position

1. **The constants are not protectable.** The tables, keys and reply messages are
   plain data. They have no creative design, their values are fixed by what the
   protocol requires, and so I see no copyright in them. They are kept as binary
   files and loaded at build time.
2. **The algorithm is a mathematically and functionally forced sequence.** To
   interoperate, a receiver must compute exactly what the sender expects. Ideas,
   principles and algorithms are not protected by software copyright. In
   particular, the routine I call the blender is a fixed sequence of operations
   whose steps and order are dictated by compatibility. It is reproduced because
   there is no other way to compute the same result, not because it was copied for
   its expression.
3. **Therefore I publish the crate under the LGPL-3.0-or-later,** including this
   code.

Residual uncertainty remains, as it does in most legal questions:

- Whether the original code is protected at all, and by whom, is unclear.
- Whether a rewrite made with knowledge of the original counts as an adaptation of
  it depends on how a court weighs the expressive and the forced parts.
- This page does not assess other regimes, for example rules on circumventing
  technical protection measures in some jurisdictions, or contractual terms of the
  platform vendor.

## If you cannot accept this

Disable the feature:

```toml
shairplay = { version = "0.10", default-features = false }
```

Without `fairplay` the crate contains none of this code. `Ap1Encryption::FairPlay`
and the `/fp-setup` route are then absent, a sender that negotiates a FairPlay key is
refused. The `video` and `hls` features need FairPlay and switch it back on.
The AirPlay 2 discovery records still advertise the capabilities they always did.
That configuration has not been tested against an iPhone.

## Contributing

Do not copy code from `playfair`, `shairplay`, `RPiPlay`, `UxPlay` or other
implementations into the FairPlay files. Changes there should be derived from the
behaviour verified by the golden vectors. Tell me if you have information about the
provenance of the original.
