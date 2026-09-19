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
  carries it — a test source flags the change whatever its status, and an absent or `unknown` source
  is flagged conservatively — closing bypasses where a test moved to a non-test path evaded
  detection because only the destination path was ever checked.
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
- A lane operation that loses a race now absorbs only `FileNotFoundError` — "the source is already
  gone" — instead of any `OSError`. A lane that cannot be *opened* is a refusal, not a lost race, and
  reporting it as "nothing to claim" was the same refusal-read-as-absence mistake the lane listing
  already fails closed to avoid.

### Fixed

- **An inbox lane that cannot be listed is refused, not answered as an empty one.** Listing a lane
  returned `[]` identically for a lane that was empty and for a lane that could not be read, so a
  permission wall or a hand-dropped symlink made `has_pending()` report "no work waiting" and
  `pending()` report a clean zero — a false negative on exactly the tampering the refusal exists to
  catch. Readers now raise `LaneUnreadable` (a `PacketError`) on an incomplete listing. This is a
  behaviour change for callers: `check` exits `2` instead of `1`, `list` reports the refusal instead
  of printing nothing, and any command that reads a lane reports the refusal rather than a traceback
  (one net in `main`, so the covered set is not a hand-kept list of remembered commands).
  `verdicted_packet_ids` and `answered_consult_ids` raise for the same reason — the sweep that
  consumes them treats a missing id as *unresolved*, so a short set would requeue work whose durable
  verdict already exists. The `signals/` lane is the one deliberate exception: a signal gates
  nothing, so that lane stays live and skips a refused entry rather than going dark.
- **Publishing no longer rewrites the permissions of a directory outside the inbox.**
  `_ensure_tree` used `mkdir(exist_ok=True)`, which *succeeds* on a symlink to a directory — an
  "already exists" case, not an error — and `os.chmod` then followed it, so a lane replaced by a link
  had its target chmodded to `0700` by an ordinary `publish`. Directories are now created, checked
  and permission-set through a descriptor opened `O_NOFOLLOW`, so what is created, what is checked
  and what is modified are provably the same object.
- **A lane file can no longer be swapped for a symlink between the listing and the read, and a
  publish can no longer be redirected out of the inbox mid-write.** Every lane read opens with
  `O_NOFOLLOW`, so the refusal happens in the open rather than after a `stat` that a second path
  resolution could invalidate; and a publish holds both `staging/` and the destination lane open with
  `O_NOFOLLOW | O_DIRECTORY` for the whole operation, creating the staging file `O_EXCL` and
  addressing the rename relative to those descriptors instead of to paths that could mean something
  else by then. The containment assertions stay — they reject a hostile *name*, which is a different
  attack from a hostile *directory*. The descriptor-relative code uses the same POSIX surface this
  module already required for its `fcntl.flock` publish lock, so it narrows nothing further.
- **`watch` no longer swallows a refusal.** The four lane listings were a single expression, so an
  unreadable `advice/` or `consult/` lane — neither of which gates anything — suppressed notification
  and launch for a real audit packet sitting readable in `pending/`. Each lane is now read on its
  own; a refused lane carries its cursor slice forward untouched, so nothing in it is announced and
  nothing in it is marked seen; and `watch --once` exits `2` with the refusal on stderr instead of
  printing "nothing new" and exiting `0`.
- **`O_NOFOLLOW` was guarding only the last component, so a symlinked inbox ROOT or a lane swapped
  for a symlink after the listing was still followed.** Opening `<root>/<lane>` with `O_NOFOLLOW`
  refuses a symlinked *lane* and says nothing about the root above it, which the kernel re-resolved
  on every call — a scan through a symlinked root returned `complete=True` for a listing taken
  outside the inbox, and a lane swapped after the scan redirected the read, the claim and the rename
  that followed it, because the scanner closes its descriptor and hands back plain paths. Every
  read, claim, rename and publish is now addressed through a **descriptor chain**: the root is opened
  once with `O_NOFOLLOW | O_DIRECTORY`, each lane is opened by `dir_fd` from that root, and each
  entry by `dir_fd` from its lane — `os.rename`/`os.replace` take `src_dir_fd`/`dst_dir_fd` and name
  no path at all, and the size read, the free-name choice and the `.reason.txt` write go through the
  same chain. The root itself is validated by that open rather than by an `lstat` that a second
  resolution could invalidate; directories *above* the inbox root are the operator's own layout and
  stay out of scope, which the module now says in a comment. A symlinked root is refused by scan,
  read, claim, publish and `_ensure_tree`, and a lane swapped for a symlink between the listing and
  the read or the claim is refused in the syscall that would have followed it.
- **A publish could report success after writing only part of the packet.** `os.write` may write
  fewer bytes than it was given and report how many; the return value was ignored, so a short write
  left a truncated packet in the lane with no error anywhere. The buffer is now drained in a loop,
  and a write that makes no progress raises rather than spinning.
- **A failed publish left its staging file behind and blocked every retry of that packet.** The
  staging entry was unlinked only when `os.replace` failed, so a failure in the write, the fsync or
  the destination lookup — or the short write above — stranded it, and since the staging create is
  `O_EXCL` the next attempt at the same packet refused forever. Every step after the create is now
  inside one cleanup block: any failure removes the staging entry and re-raises, so a retry of the
  same packet succeeds.
- **The docs-only score cap was decided by the directory a file sits in, not by the file.** The
  predicate was `path.startswith("docs/") or path.endswith(".md") or path.endswith(".txt")`, so
  `docs/deploy.py` — a program on the deploy path — was capped to the prose ceiling while
  `src/deploy.py` scored as the deploy change it is, and any `.txt` anywhere was treated as prose.
  The cap now asks the file's own extension: `.md` and `.rst` are prose, `.txt` is prose unless its
  basename is a dependency manifest (`requirements*.txt`, `constraints*.txt` — input that gets
  installed, so changing a pin changes what runs), and no executable or source extension is ever
  prose wherever it lives. A path with no extension is not assumed to be one.

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
