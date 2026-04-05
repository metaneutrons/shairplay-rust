# Git & Release Workflow

## Branching

- `main` is protected — no direct pushes
- Feature branches: `feat/description`, `fix/description`, `refactor/description`
- PRs required — CI must pass before merge
- Squash merge preferred for clean history

## Commits

Conventional commits enforced:
- `feat:` — new feature
- `fix:` — bug fix
- `refactor:` — code restructuring, no behavior change
- `docs:` — documentation only
- `ci:` — CI/CD changes
- `chore:` — dependencies, tooling
- `style:` — formatting (cargo fmt)
- `test:` — adding tests

Split commits into functional groups — never amend unrelated changes together.

## Pre-commit Hook

Located at `.githooks/pre-commit`. Activate with:
```bash
git config core.hooksPath .githooks
```
Runs `cargo fmt --check` — auto-formats and aborts if needed.

## Release Process

1. Merge feature PRs into `main`
2. Release-please auto-creates a release PR with CHANGELOG + version bump
3. Review and merge the release PR
4. Release-please creates git tag + GitHub Release
5. Publish job runs automatically → pushes to crates.io

Manual publish (if needed):
```bash
cargo publish --registry crates-io
```

## CI Checks (all must pass)

- Build + test on macOS and Ubuntu (all feature combos)
- Clippy with `--features hls` (superset)
- `cargo fmt --check`
- `cargo audit` (security advisory check)

## Important Files

- `.cargo/audit.toml` — ignored security advisories (rsa Marvin attack, instant unmaintained)
- `.github/workflows/ci.yml` — CI on push + PR
- `.github/workflows/release-please.yml` — release automation + crates.io publish
- `CHANGELOG.md` — managed by release-please, do not edit manually
