# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The ship gate now also refuses a packet whose `changed_files` changes a test file
  (`twoperson.testset`) unless the cited verdict's `acknowledged_tests` names those exact paths
  (`twoperson verdict --ack-test-changes`, which derives the paths from the packet under review —
  never a hand-typed list). Detection fails closed: only `added`/`copied` statuses are safe, so
  `modified`, `deleted`, `renamed`, the `unknown` sentinel, or any status added to the schema later
  all require the ack; `TWOPERSON_TEST_GLOBS` only *extends* the built-in test-path rule and can
  never switch it off; and an optional `old_path` (rename source) is honored on any entry that
  carries it — a test source flags the change whatever its status, and an absent, empty, or
  `unknown` source is flagged conservatively — closing bypasses where a test moved to a non-test
  path evaded detection because only the destination path was ever checked.
- `publish_verdict` now refuses to write a verdict whose `acknowledged_tests` names a test path the
  reviewed packet doesn't actually alter, so a verdict can only ever acknowledge the test changes
  present in the packet it reviews. This makes the content-binding structural rather than a CLI
  convention: without it, a caller writing verdicts directly (bypassing `--ack-test-changes`) could
  mint an acknowledgment for arbitrary paths and have it replayed onto an unrelated ship report.

### Changed

- `acknowledged_tests` (a list of the specific test paths the reviewer acknowledges) replaces the
  earlier boolean `acknowledges_test_changes`. The gate now requires the ship report's altered
  tests to be a subset of what the cited verdict acknowledged, rather than accepting any truthy
  flag — a verdict acknowledging one packet's test changes can no longer be cited to unlock a
  different ship report's different test changes at the same head, since `changed_files` is
  self-reported per packet. The feature was unreleased, so there is no compatibility path for the
  old boolean field.

## [0.1.1] - 2026-09-03

### Security

- The publish workflow verifies what it was handed before anything reaches the trusted-publishing
  step: the tag must name a commit on `main` and match the version declared in `pyproject.toml`.
  Pushing a tag is enough to reach the upload, so the checks that matter live where they gate it
  rather than in whatever a maintainer happened to run first.
- The entire build toolchain is pinned by version and hash in `requirements-build.txt` and used
  with `--no-isolation`, so nothing resolves freely into the environment that produces the artifact.
  Pinning the actions, or even the two top-level tools, while their dependencies float would leave
  the same door open.
- Both distributions that will be uploaded, the wheel and the sdist, are installed and tested on
  every Python version this package claims to support before the upload runs, and the sdist is
  installed under the same frozen toolchain rather than letting pip resolve a build environment of
  its own. The supported versions are now listed explicitly as classifiers, 3.10 through 3.14, and a
  test fails if that list and the release matrix ever disagree in either direction. Testing the source tree on one interpreter
  and publishing artifacts nobody ran proves the wrong thing.
- Values that come from outside, such as the tag name, reach the workflow's shell steps through the
  environment rather than being substituted into the script text, where a tag named with shell
  metacharacters would become code.
- The workflow is read-only by default, checkouts do not persist credentials, and only the
  publishing job holds anything more.
- Every GitHub Action in every workflow is pinned to a commit rather than a moving tag or branch.
  The upload job is the one that holds `id-token: write`, so a mutable reference in it could mint a
  token for this project; the jobs before it are pinned too, because they decide what that token is
  used to upload. A test fails the suite if any workflow reintroduces a mutable reference.

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
