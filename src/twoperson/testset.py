"""Test-file detection for the packet review gate.

A builder under pressure to get a green packet past review has an easy lever nobody is watching:
quietly weaken or delete a test rather than fix the code it covers. This module answers one
narrow, stdlib-only question — "did this packet's `changed_files` touch something that looks like
a test, in a way that could be a weakening?" — so `twoperson.inbox.assert_review_ref_resolves` can
require the approving verdict to say it noticed.

The detection is deliberately built to fail *closed*: every place where the packet could carry an
ambiguous or builder-chosen value, the ambiguous case is treated as "might be a weakened test" and
flagged, never waved through. Three such places, each of which a builder could otherwise use to
slip a change past the gate:

* **Status.** Only `"added"` and `"copied"` are treated as safe (both introduce a file rather than
  weaken an existing one). *Every other* status — `"modified"`, `"deleted"`, `"renamed"`, the
  `"unknown"` sentinel, and any status added to the schema later — is a possible weakening. The
  rule is a safe-list, not a weakening-list, so a new or unknown status can never silently bypass.
* **Change source.** `changed_files` records only the *destination* path, so a test moved to a
  non-test path (`tests/test_auth.py` -> `src/auth.py`) reads as "not a test file" if only `path`
  is checked. Entries may carry an OPTIONAL `old_path` (the pre-rename path); it is honored
  whatever status carries it, so a test source is not ignored just because the status is
  `"unknown"` or `"modified"` rather than `"renamed"`. A present `old_path` equal to the `"unknown"`
  sentinel cannot be ruled out as a test and is flagged (in a valid packet `old_path` is otherwise a
  concrete non-empty path — the schema's `_repo_path` rejects an empty one before it could reach
  here); and a `"renamed"` status with no recorded source is flagged unconditionally, since the move
  could be exactly that.
* **Test-path globs.** `TWOPERSON_TEST_GLOBS` can only *add* patterns to the built-in rule; it can
  never replace or narrow it. A builder who controls the environment at publish time therefore
  cannot set a nonmatching glob to switch detection off — the defaults always still apply.

Two limitations, stated here because they matter more than the feature:

* It acts on the builder-declared `changed_files` list (`path` and, for renames, `old_path`),
  nothing else. A builder who edits or deletes a test and omits that entry from the list altogether
  is not caught — nothing here reads the real diff. (A rename that omits `old_path` *is* caught: a
  bare `"renamed"` entry is flagged conservatively.) That is a separate integrity gap: the packet's
  `changed_files` is self-reported, same as `diff_summary`.
* It flags any qualifying test change for acknowledgment; it does not attempt to judge whether the
  change is a legitimate strengthening or an actual weakening. That judgment stays with the
  reviewer — this only makes sure the change was seen and acknowledged, not silently approved.

See `docs/PROTOCOL.md` for how the gate uses this.
"""
from __future__ import annotations

import fnmatch
import os
from typing import Any, Iterable, Mapping

from .packet import UNKNOWN

#: Path segments that mark a directory (or a bare filename) as belonging to a test tree, matched
#: case-insensitively against every segment of the path, not only the last one.
TEST_PATH_SEGMENTS: frozenset[str] = frozenset({"tests", "test", "__tests__", "spec"})

#: Basename globs (case-insensitive, matched with `fnmatch`) that mark a file as a test file
#: regardless of which directory it lives in.
DEFAULT_TEST_BASENAME_GLOBS: tuple[str, ...] = (
    "test_*", "*_test.*", "*.test.*", "*.spec.*", "*_spec.*", "conftest.py",
)

#: Set to a comma-separated list of `fnmatch` globs (matched case-insensitively against the whole
#: repo-relative path) to ADD extra test-path patterns. It EXTENDS the built-in segment/basename
#: rule; it can never replace or narrow it, so it cannot be used to switch detection off.
TEST_GLOBS_ENV = "TWOPERSON_TEST_GLOBS"

#: `changed_files[].status` values that are NEVER a weakening of an existing test: `"added"`
#: introduces a new test, `"copied"` duplicates one — neither removes coverage. This is a
#: safe-list on purpose: any status not in it (including `"modified"`, `"deleted"`, `"renamed"`,
#: the `"unknown"` sentinel, or a status added to the schema later) is treated as a possible
#: weakening, so nothing slips through by carrying an unrecognised or ambiguous status.
SAFE_STATUSES: frozenset[str] = frozenset({"added", "copied"})


def _extra_globs() -> list[str]:
    """Extra whole-path globs from `TWOPERSON_TEST_GLOBS`, or `[]` when it is unset/empty. These are
    ADDED to the built-in rule (see `is_test_path`); they never replace it."""
    raw = os.environ.get(TEST_GLOBS_ENV)
    if raw is None:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def is_test_path(path: str) -> bool:
    """Whether ``path`` (a repo-relative POSIX path) counts as a test file.

    A path is a test file if ANY of these hold: a `/`-separated segment (including the basename)
    case-insensitively equals one of `TEST_PATH_SEGMENTS`; the basename case-insensitively matches
    one of `DEFAULT_TEST_BASENAME_GLOBS`; or the whole path case-insensitively matches one of the
    extra globs from `TWOPERSON_TEST_GLOBS`. The environment variable only ever ADDS matches — the
    two built-in rules are always applied, so detection cannot be switched off by setting it.
    """
    lowered = path.lower()
    segments = lowered.split("/")
    if any(segment in TEST_PATH_SEGMENTS for segment in segments):
        return True
    if any(fnmatch.fnmatch(segments[-1], glob.lower()) for glob in DEFAULT_TEST_BASENAME_GLOBS):
        return True
    return any(fnmatch.fnmatch(lowered, glob.lower()) for glob in _extra_globs())


def _declared_source_is_testish(entry: Mapping[str, Any]) -> bool:
    """Whether the entry declares a rename source (`old_path`) that is — or cannot be ruled out as —
    a test.

    `old_path` is the pre-rename path, but the schema permits it on ANY entry, so it is honored
    whatever status carries it, `"added"`/`"copied"` included: an `old_path` on an "added" file is
    itself inconsistent and must not be usable to hide a test that was moved out. A present
    `old_path` equal to the `"unknown"` sentinel cannot be ruled out as a test, so it counts. In a
    valid packet a present `old_path` is a concrete non-empty path — `_repo_path` rejects an empty
    one — so the falsy branch below never fires for schema-validated input; it stays as defence in
    depth for a caller that hands `altered_test_files` an unvalidated `changed_files`. Returns
    `False` when `old_path` is absent (that case is left to the status/destination rules) or names a
    concrete non-test path (a genuine non-test rename, which must not be over-flagged).
    """
    if "old_path" not in entry:
        return False
    old_path = entry.get("old_path")
    if not old_path or old_path == UNKNOWN:  # `not old_path`: defensive; a valid packet can't reach it
        return True
    return is_test_path(str(old_path))


def altered_test_files(changed_files: Iterable[Mapping[str, Any]]) -> list[str]:
    """Paths, in packet order, of changed files that touch a test in a possibly-weakening way.

    An entry is flagged when ANY of these hold, checked in order:

    * its declared source (`old_path`) is, or cannot be ruled out as, a test
      (`_declared_source_is_testish`) — honored on any status, so a moved-out test cannot be hidden
      behind an `"added"`/`"copied"`/`"unknown"` status;
    * otherwise, its `status` is NOT in `SAFE_STATUSES` (`"added"`/`"copied"`) and its destination
      `path` is a test file;
    * otherwise, its `status` is `"renamed"` with NO recorded `old_path` — a bare rename whose
      source is unknown could be a test moved out of the tree.

    A packet that only *adds* or *copies* non-test-sourced files returns an empty list.
    """
    flagged: list[str] = []
    for entry in changed_files:
        path = str(entry.get("path", ""))
        status = entry.get("status")
        if _declared_source_is_testish(entry):
            flagged.append(path)
            continue
        if status in SAFE_STATUSES:
            continue
        if is_test_path(path):
            flagged.append(path)
            continue
        if status == "renamed" and "old_path" not in entry:
            flagged.append(path)
    return flagged


def any_test_change_needs_ack(changed_files: Iterable[Mapping[str, Any]]) -> bool:
    """True if `changed_files` contains at least one possibly-weakened test file."""
    return bool(altered_test_files(changed_files))
