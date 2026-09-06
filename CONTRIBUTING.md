# Contributing to shairplay-rust

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/metaneutrons/shairplay-rust.git
cd shairplay-rust
brew install lefthook gitleaks
lefthook install
cargo nextest run --workspace --all-features --locked
```

Rust is selected from `rust-toolchain.toml`. The crate's tested minimum Rust
version remains the `rust-version` declared in `Cargo.toml`.

## Branches and Commits

Create a short-lived branch from `main`. Use `feat/`, `fix/`, `docs/`,
`refactor/`, or `chore/` followed by a concise kebab-case description.

All commit messages and pull-request titles follow
[Conventional Commits](https://www.conventionalcommits.org/). Keep the subject
at or below 100 characters. A squash merge uses the pull-request title as the
commit subject and its body as the commit body.

## Engineering Guidelines

- No unsafe code: `unsafe_code = "forbid"` is enforced workspace-wide.
- Document every public item and every observable compatibility change.
- Add regression tests for corrected behavior.
- Preserve the MSRV unless a deliberate, documented breaking change raises it.
- Avoid platform assumptions outside explicitly gated modules.

Run the same principal checks used by CI before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --all-features --locked
cargo deny check
```

`lefthook run pre-push` runs the bounded local subset. Full platform and
coverage matrices remain CI responsibilities. If a hook is unavailable, run
its documented command directly; do not bypass a failing check.

## Feature Flags

| Flag | Description |
|------|-------------|
| (default) | AP1 only |
| `resample` | Adds rubato for sample rate conversion |
| `ap2` | AirPlay 2 (implies `resample`) |
| `video` | Screen mirroring (implies `ap2`) |

## Release Process

Releases are fully automated via [release-please](https://github.com/googleapis/release-please):

1. Develop on a feature branch and open a pull request to `main`.
2. Wait for the aggregate `CI Success` check and resolve review threads.
3. Squash-merge the pull request.
4. Release Please updates its release pull request, including the version,
   changelog, and lockfile.
5. Merge the release pull request when the next version is ready.
6. Release Please creates an immutable `v*` tag and a draft GitHub Release.
7. The release workflow packages and verifies the crate, publishes through
   crates.io Trusted Publishing, verifies the registry result, and only then
   promotes the GitHub Release to latest.

Historical `shairplay-v*` tags remain immutable compatibility references. New
releases use `vX.Y.Z`; release titles can be normalized without renaming tags.
Own `.crate` assets and checksums accompany stable releases starting at `0.9.0`.
See [release qualification and recovery](docs/release-process.md) before
changing the release pipeline or handling a partially published release.

Commit prefixes and their effect on versioning:

| Prefix | Example | Version bump |
|--------|---------|-------------|
| `feat:` | `feat: add volume control` | Minor (0.1.0 → 0.2.0) |
| `fix:` | `fix: buffer overflow on flush` | Patch (0.1.0 → 0.1.1) |
| `feat!:` | `feat!: rename ap2 feature` | Major (0.1.0 → 1.0.0) |
| `docs:`, `chore:`, `ci:` | `docs: update README` | No release |

## License

By contributing, you agree that your contributions will be licensed under LGPL-3.0-or-later.
