# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-09-03

### Changed

- Rewrote the comparison section. It now covers OpenAI's `codex-plugin-cc` and `secondmate`, which
  were missing, and describes what each project actually enforces rather than what it resembles.

### Fixed

- The comparison said `shiplog` leans on GitHub branch protection. It doesn't: it records signed
  `Reviewed-by:` lines on pull requests, and needs an authenticated `gh` and a GitHub remote.
- `quorum` is credited with absorbing the earlier `consensus-loop`.

## [0.1.0] - 2026-09-03

First public release.

### Added

- Review packets with a strict, allow-listed schema: size cap, repo-relative path checks, a
  credential scan that reports field paths and never values, and a rendering that fences packet
  text as untrusted data.
- The four refusals that make up the gate: a verdict must answer a packet that exists in the
  inbox; an approval must name that packet's own commit; a packet can't report a push, deploy or
  restart without a `review_ref`; and that `review_ref` must resolve to an existing approving
  verdict for the same commit (`verify` runs the same checks as `publish` and writes nothing).
- One inbox per repository, shared across `git worktree`s, resolved without spawning `git`.
- `install-hook`: a Claude Code `Stop` hook that drops a completion signal so a reviewer can be
  woken by the event instead of polling. `install-watch`: a launchd agent for macOS.
- A consult lane (`consult-*`) that is explicitly non-gating.
- `tier`: a deterministic difficulty score for a packet, handed to the reviewer command as
  `TWOPERSON_TIER` / `TWOPERSON_TIER_SCORE` / `TWOPERSON_PACKET_ID`, plus the `ESCALATE:`
  convention for asking for a stronger reviewer.

[Unreleased]: https://github.com/ahm3dwasim/twoperson/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ahm3dwasim/twoperson/releases/tag/v0.1.1
[0.1.0]: https://pypi.org/project/twoperson/0.1.0/
