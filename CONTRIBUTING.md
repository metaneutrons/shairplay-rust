# Contributing to shairplay-rust

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/metaneutrons/shairplay-rust.git
cd shairplay-rust
cargo build --features video
cargo test --features video
```

## Guidelines

- **Conventional commits** — all commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/)
- **No unsafe code** — `#![forbid(unsafe_code)]` is enforced
- **Documentation** — all public items must have `///` doc comments
- **Tests** — add tests for new functionality
- **Clippy** — `cargo clippy --features video` must pass with zero warnings
- **Formatting** — run `cargo fmt` before committing

## Feature Flags

| Flag | Description |
|------|-------------|
| (default) | AP1 only |
| `resample` | Adds rubato for sample rate conversion |
| `ap2` | AirPlay 2 (implies `resample`) |
| `video` | Screen mirroring (implies `ap2`) |

## Release Process

Releases are fully automated via [release-please](https://github.com/googleapis/release-please):

1. Develop on a feature branch, open a PR to `main`
2. CI runs on the PR (build, test, clippy, fmt on macOS + Ubuntu)
3. Merge the PR — commits must follow [conventional commits](https://www.conventionalcommits.org/)
4. Release-please automatically opens/updates a "Release PR" with:
   - Version bump in `Cargo.toml`
   - Generated `CHANGELOG.md` from commit messages
5. When ready to release: **merge the Release PR**
6. Release-please creates a `v*` tag, which triggers:
   - Full CI on macOS + Ubuntu (build, test, clippy, fmt)
   - CHANGELOG version guard
   - Publish to [crates.io](https://crates.io/crates/shairplay)
   - GitHub Release with changelog notes

Commit prefixes and their effect on versioning:

| Prefix | Example | Version bump |
|--------|---------|-------------|
| `feat:` | `feat: add volume control` | Minor (0.1.0 → 0.2.0) |
| `fix:` | `fix: buffer overflow on flush` | Patch (0.1.0 → 0.1.1) |
| `feat!:` | `feat!: rename ap2 feature` | Major (0.1.0 → 1.0.0) |
| `docs:`, `chore:`, `ci:` | `docs: update README` | No release |

## License

By contributing, you agree that your contributions will be licensed under LGPL-3.0-or-later.
