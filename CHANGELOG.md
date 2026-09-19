# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-09-19

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

- **The refusal for a lane that cannot be *opened* is raised where it happens, so no command turns
  it into a stack trace.** The entry above made a lane that cannot be *listed* fail closed, but a
  lane the descriptor chain cannot *open* — a symlinked `claimed/`, a symlinked root — was answered
  by `os.open` with a raw `OSError`, which is neither a `PacketError` nor what the boundary net
  catches. `twoperson next` therefore died with `NotADirectoryError` and exit `1`, the code that
  means "nothing to do": the refusal delivered as the empty answer it exists to be told apart from.
  The chain now raises `LaneUnreadable` itself, at the root hop, the lane hop, and the entry hop
  (read and create), so every command — including ones not yet written — gets the refusal with exit
  `2`. `FileNotFoundError` is deliberately left unconverted: it is the documented answer for the two
  non-hostile cases, a tree `_ensure_tree` has not created yet (provably empty) and an entry another
  process already moved (a lost race). This is also a behaviour change for callers that caught
  `OSError` around a lane operation: they now see `LaneUnreadable`, which several readers had to
  distinguish from a *bad file* — `_next`, `read_signals`, `read_verdicts`, `read_advice` and
  `_next_consult` would otherwise have quarantined a good packet because the lane it sat in could not
  be opened, and `find_packet`, `_all_verdicts`, `verdicted_packet_ids` and `answered_consult_ids`
  would have silently under-reported, which for the latter two means re-auditing resolved work.
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
- **The watcher's own writes bypassed the descriptor chain the rest of the package had just moved
  onto.** Inbox operations were addressed by descriptor, but the files the *watcher* writes in the
  root were still opened by path: `.watch.lock` with mode `"w"`, which resolves the root again and
  *truncates* whatever it lands on, so a `.watch.lock` pre-created as a symlink had the file it
  pointed at emptied by an ordinary dispatch tick — no hostile command, no unusual flag. The cursor's
  temp file and the mute switch reopened the same door through `write_text` and `touch`: the first
  writes *through* a pre-created symlink, the second re-stamps the target's mtime. All three now go
  through a root descriptor held `O_NOFOLLOW` (the same `_open_root_dir` the inbox uses), the names
  are created `O_NOFOLLOW` — `O_EXCL` for the temp, so a leftover is cleared and retried rather than
  followed or deadlocked on — and the rename is `os.replace` between two `dir_fd`s. A root that is a
  symlink is refused: the pass degrades to un-serialized as it already documented, the cursor logs and
  skips the save, and the switch reports what it did. Nothing the watcher writes can reach a file
  outside the inbox root.
- **Every lane move derived its destination from the *source* path and discarded the root it was
  given.** `_move_lane_entry` built the destination as `src.parent.parent / dst_lane`, so
  `archive_claimed('/outside/claimed/x.json', root='/intended')` wrote under `/outside`: the explicit
  `root` argument was accepted and ignored, and the operation followed the caller's path out of the
  inbox. Each operation now names both lanes, `_lane_member` refuses a source that is not an entry of
  the expected lane *of that root* with a `PacketError` rather than following it, and both endpoints
  are opened from the root's own descriptor — so claim, requeue, quarantine, archive and the three
  consult equivalents all resolve inside the root they were handed.
- **A lane entry swapped for a FIFO could block a reader forever.** `O_NOFOLLOW` refuses a symlink
  and says nothing about the file type, so a listed entry replaced by a FIFO was opened — and
  `O_RDONLY` on a FIFO with no writer *blocks in the open itself*, before any read or size check,
  with no timeout and no error: a wedged watcher and a wedged CLI, neither of which reports anything.
  Lane entries are now opened `O_NONBLOCK`, `fstat`ed, and refused unless `S_ISREG` before any read or
  size check, then returned to blocking mode for the read. Covered both for the entry that already is
  a FIFO and the one swapped in after the listing, under a timeout guard so a regression fails the
  suite instead of hanging it.
- **Root and lane creation raised its own errors past the refusal net.** `_ensure_tree` called
  `mkdir` *before* the refusal-converting open, so a root that was an existing regular file, a
  dangling symlink, or a root under an unwritable parent raised `FileExistsError` or
  `PermissionError` from the create — neither a `PacketError` nor anything the command boundary
  catches — and the command died with a traceback instead of exit `2`. Every `OSError` in root and
  lane creation or opening is now converted to `LaneUnreadable`, the refusal the boundary answers
  with exit `2`, and the unwritable parent is refused explicitly rather than discovered by a failing
  `mkdir`. A missing root whose parent exists and is writable keeps its documented "provably empty"
  answer. The CLI refusal matrix now covers every lane command against a regular-file root, a
  dangling root symlink and an unwritable parent — 51 cases, each exiting `2` with no traceback — and
  pins the `signals` lane's documented opt-out, which exits `1`.
- **The docs-only score cap was decided by the directory a file sits in, not by the file.** The
  predicate was `path.startswith("docs/") or path.endswith(".md") or path.endswith(".txt")`, so
  `docs/deploy.py` — a program on the deploy path — was capped to the prose ceiling while
  `src/deploy.py` scored as the deploy change it is, and any `.txt` anywhere was treated as prose.
  The cap now asks the file's own name and answers `.txt` by ALLOWLIST: `.md`, `.rst` and `.adoc` are
  prose anywhere in the tree, `.txt` is prose only for the conventional document stems (`README`,
  `LICENSE`/`LICENCE`, `NOTICE`, `AUTHORS`, `CHANGELOG`, `CONTRIBUTING`, `COPYING`, case-insensitive),
  and nothing else is prose — no executable or source extension wherever it lives, and no path
  without an extension. The dependency-manifest deny-list this replaces was the same mistake one step
  in: it caught the machine-read names someone thought of and handed the ceiling to `CMakeLists.txt`
  — a build program that runs the compiler — for the crime of being a name nobody had enumerated. A
  ceiling on how cheaply a change may be audited has to fail the other way, so naming the prose is
  now the only way to get it.

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
