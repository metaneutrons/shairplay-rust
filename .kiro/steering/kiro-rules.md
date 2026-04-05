# Kiro Rules

## CRITICAL: Never Do Without Explicit User Consent

- **Never `git push`** — always ask first
- **Never create PRs** — always ask first
- **Never merge PRs** — always ask first
- **Never delete branches/tags/releases** — always ask first
- **Never run `cargo publish`** — always ask first

## Commit Rules

- Commit locally without asking — this is safe and expected
- Always use conventional commits
- Amend only the most recent commit, and only when it's the same topic
- Split unrelated changes into separate commits

## Code Changes

- Use `str_replace` for edits, not Python scripts
- Run `cargo build` and `cargo test` after changes before reporting success
- Run `cargo fmt --all` before committing
- Test all affected feature combos (default, ap2, video, hls)

## Communication

- Don't run interactive commands (cargo login, git rebase -i) — they freeze the terminal
- When a command fails, show the error and propose a fix — don't retry silently
- When context is getting long, summarize progress and suggest saving
