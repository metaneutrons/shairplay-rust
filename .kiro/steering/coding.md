# Coding Standards

## Rust

- `#![forbid(unsafe_code)]` in the library crate
- `#![warn(missing_docs)]` — all public items must have `///` doc comments
- Edition 2021, `max_width = 120` (rustfmt.toml)
- Zero clippy warnings with `--features hls` (superset of all features)
- Zero `cargo fmt` diffs — pre-commit hook enforces this

## Code Style

- Enterprise patterns only — no shortcuts, no hacks, no test code in commits
- Files should be under 300 lines. Split when exceeding this
- Module name provides namespace — don't prefix function names with module name
  - ✅ `handlers_ap2::handle_setup`
  - ❌ `handlers_ap2::handle_ap2_setup`
- Use `str_replace` for code edits, not Python scripts
- Feature-gated code uses `#[cfg(feature = "...")]` on individual items
- Errors: use `thiserror` derive, structured error enums
- Logging: `tracing` crate
  - `info` — connection events, stream setup, server lifecycle
  - `debug` — metadata, volume, protocol details
  - `trace` — packet-level, unknown DMAP tags

## Error Handling

- Public API returns `Result<_, ShairplayError>`
- Handlers return `Option<Vec<u8>>` — None = empty 200 OK response
- Runtime errors delivered via `AudioHandler::on_error()` callback
- Never panic in library code — use `Result` or log + continue
- Mutex locks: `.ok()?` or `.unwrap()` only for non-poisonable locks

## Testing

- All feature combos must pass: `default`, `ap2`, `video`, `hls`
- C-verified test vectors for crypto (pair_ap, shairplay C source)
- DMAP parser has fuzz-style tests (empty, truncated, corrupt length)
- Integration tests skip mDNS when `CI` env var is set
- Run before commit: `cargo test --features hls && cargo clippy --features hls`
