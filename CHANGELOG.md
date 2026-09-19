# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-09-19

### Added

- The ship gate refuses a packet whose `changed_files` modifies a test file (`twoperson.testset`)
  unless the cited verdict's `acknowledged_tests` names those exact paths
  (`twoperson verdict --ack-test-changes`, which derives the paths from the packet itself, never a
  hand-typed list). Detection fails closed: only `added`/`copied` statuses are exempt, and a rename
  is checked against its `old_path` too, so a test moved to a non-test path is still caught.
- `publish_verdict` refuses to write a verdict whose `acknowledged_tests` names a path the reviewed
  packet doesn't actually alter, so an acknowledgment can never be minted for, or replayed onto, an
  unrelated packet.

### Changed

- `acknowledged_tests` (the specific test paths a reviewer acknowledges) replaces the earlier
  boolean `acknowledges_test_changes`; the gate now requires the ship report's altered tests to be a
  subset of what the cited verdict acknowledged.
- A lane operation that loses a race now absorbs only `FileNotFoundError` ("the source is already
  gone"); a lane that cannot be *opened* is reported as a refusal instead.

### Fixed

- Every lane and root operation (open, read, list, claim, publish, quarantine, archive, rename) now
  reports a refusal (`LaneUnreadable`, exit `2`) instead of a raw traceback, an empty result, or a
  false "nothing waiting" when a lane, its root, or an entry is a symlink, a dangling link, a hard
  link, a FIFO, an existing non-directory file, or sits under an unwritable parent.
- A publish interrupted mid-write (a short `os.write`, a failed fsync or rename) can no longer leave
  a truncated packet behind, and a failed publish no longer strands its staging entry and blocks
  every retry of that packet id.
- `watch` reads its four lanes (packets, verdicts, consults, advice) independently, so an unreadable
  advice/consult lane no longer suppresses notification for a real packet elsewhere; `watch --once`
  reports a refused lane on stderr and exits `2` instead of printing "nothing new" and exiting `0`.
- The master mute switch (`watch --on` / `--off` / `--status`, and every dispatch pass) now reports
  ON, OFF, or UNKNOWN honestly: a state is only ever reported as ON or OFF once it has been both
  written (or already true) and confirmed by reading it back. A write that fails, a read-back that
  cannot be confirmed, or a transient fault that clears between two checks moments apart is reported
  as UNKNOWN with a non-zero exit — never a guessed or fail-closed boolean — so `watch --off` can
  never claim a mute it never actually established, and no pass notifies, launches, or advances the
  cursor while the pause state is unconfirmed.
- The docs-only score cap (`tier`) is now decided by a file's own name — an allow-list of prose
  extensions (`.md`, `.rst`, `.adoc`) and conventional document stems (`README`, `LICENSE`,
  `CHANGELOG`, ...) for `.txt` — rather than the directory it sits in or a blanket `.txt` rule, so a
  program named `docs/deploy.py` or a build file like `CMakeLists.txt` is no longer capped to the
  prose ceiling.

### Security

- All filesystem access under the inbox root goes through one module (`twoperson._safefs`) with a
  single syscall-conversion point, enforced structurally by a test that fails the suite if any other
  module performs file I/O directly — including through an import alias — or if a syscall is ever
  added outside that conversion point.
- A hard link or FIFO planted at any writable name (a lane entry, the publish or watch lock, the
  cursor, or the mute switch) can no longer truncate a file outside the inbox, write through a link,
  or block the process forever: every content write goes to a fresh temp file revealed by
  `os.replace`, so no content is ever written or truncated through an existing name (lock files are
  opened without truncation and must be a regular file with a single link), and a non-regular file is
  refused before use in either read or write direction.
- The publish lock no longer leaks a file descriptor on every acquisition, and a failed lock release
  can no longer crash an already-successful publish or dispatch pass.
- The watcher's cursor is read with a bounded size; malformed, non-UTF-8, deeply nested, or
  numerically oversized content recovers as "no cursor" (logged) instead of crashing the watcher.
- A permission error or an I/O fault reading a lane entry or the mute switch is now reported as a
  refusal, never silently read as "that name is free" or "not muted". One bad entry makes its own
  lane report as unreadable (and hold its notifications) but can no longer suppress any other lane,
  and a transient fault can no longer let a launch through with the pause state unknown.

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

[Unreleased]: https://github.com/ahm3dwasim/twoperson/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/ahm3dwasim/twoperson/releases/tag/v0.1.2
[0.1.1]: https://github.com/ahm3dwasim/twoperson/releases/tag/v0.1.1
[0.1.0]: https://pypi.org/project/twoperson/0.1.0/
