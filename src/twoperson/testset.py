"""Test-file detection for the packet review gate.

A builder under pressure to get a green packet past review has an easy lever nobody is watching:
quietly weaken or delete a test rather than fix the code it covers. This module answers one
narrow, stdlib-only question — "did this packet's `changed_files` touch something that looks like
a test, in a way that could be a weakening?" — so `twoperson.inbox.assert_review_ref_resolves` can
require the approving verdict to say it noticed.

A rename is the one status where the changed path alone is not enough: `changed_files` records
only the *destination* path, so a test moved to a non-test path (`tests/test_auth.py` ->
`src/auth.py`) would read as "not a test file" if only `path` were checked, silently dropping the
coverage with nobody asked to acknowledge it. `changed_files` entries may carry an OPTIONAL
`old_path` (the pre-rename path) precisely so a rename can be judged from both ends: a rename is
flagged if either `path` or `old_path` looks like a test file. When `old_path` is absent, the
rename is flagged unconditionally — a rename with no recorded source could be exactly that
undetectable move, so the conservative default is to require acknowledgment rather than assume it
was not a test.

Two limitations, stated here because they matter more than the feature:

* It acts on the builder-declared `changed_files` list (`path` and, for renames, `old_path`),
  nothing else. A builder who edits a test and simply omits it from that list — or renames one and
  omits `old_path` while also renaming it in a way that dodges every default pattern — is not
  caught. That is a separate integrity gap: the packet's `changed_files` is self-reported, same as
  `diff_summary`.
* It flags any qualifying test change for acknowledgment; it does not attempt to judge whether the
  change is a legitimate strengthening or an actual weakening. That judgment stays with the
  reviewer — this only makes sure the change was seen and acknowledged, not silently approved.

See `docs/PROTOCOL.md` for how the gate uses this.
"""
from __future__ import annotations

import fnmatch
import os
from typing import Any, Iterable, Mapping

#: Path segments that mark a directory (or a bare filename) as belonging to a test tree, matched
#: case-insensitively against every segment of the path, not only the last one.
TEST_PATH_SEGMENTS: frozenset[str] = frozenset({"tests", "test", "__tests__", "spec"})

#: Basename globs (case-insensitive, matched with `fnmatch`) that mark a file as a test file
#: regardless of which directory it lives in.
DEFAULT_TEST_BASENAME_GLOBS: tuple[str, ...] = (
    "test_*", "*_test.*", "*.test.*", "*.spec.*", "*_spec.*", "conftest.py",
)

#: Set to a comma-separated list of `fnmatch` globs, matched case-insensitively against the whole
#: repo-relative path, to REPLACE (not extend) the default segment/basename rule above.
TEST_GLOBS_ENV = "TWOPERSON_TEST_GLOBS"

#: `changed_files[].status` values that count as a possible weakening of an existing test. Adding
#: a new test file (`"added"`) is the opposite of weakening, and a straight `"copied"` duplicate
#: introduces nothing new either — both are deliberately excluded.
WEAKENING_STATUSES: frozenset[str] = frozenset({"modified", "deleted", "renamed"})


def _env_globs() -> list[str] | None:
    raw = os.environ.get(TEST_GLOBS_ENV)
    if raw is None:
        return None
    globs = [item.strip() for item in raw.split(",") if item.strip()]
    return globs or None


def is_test_path(path: str) -> bool:
    """Whether ``path`` (a repo-relative POSIX path) counts as a test file.

    Default rule: any `/`-separated segment (including the basename) case-insensitively equals one
    of `TEST_PATH_SEGMENTS`, OR the basename case-insensitively matches one of
    `DEFAULT_TEST_BASENAME_GLOBS`. If `TWOPERSON_TEST_GLOBS` is set, it replaces that default rule
    outright: the path counts as a test file iff it case-insensitively matches one of the
    comma-separated globs, matched against the full path.
    """
    overrides = _env_globs()
    if overrides is not None:
        lowered = path.lower()
        return any(fnmatch.fnmatch(lowered, glob.lower()) for glob in overrides)

    segments = path.split("/")
    if any(segment.lower() in TEST_PATH_SEGMENTS for segment in segments):
        return True
    basename = segments[-1].lower()
    return any(fnmatch.fnmatch(basename, glob.lower()) for glob in DEFAULT_TEST_BASENAME_GLOBS)


def _renamed_from_a_test(entry: Mapping[str, Any]) -> bool:
    """Whether a `"renamed"` entry's *source* looks like it was a test file.

    `old_path` is optional. When it is present, its own test-ness is what matters — a rename can
    move a file INTO `tests/` (not a weakening; the destination already covers that case via
    `is_test_path(path)`) or OUT of it (a weakening this function exists to catch). When it is
    absent, there is no way to tell the two apart, so this returns `True`: a rename with an
    unrecorded source is treated as though it *might* have come from a test, rather than assumed
    innocent.
    """
    old_path = entry.get("old_path")
    if not old_path:
        return True
    return is_test_path(str(old_path))


def altered_test_files(changed_files: Iterable[Mapping[str, Any]]) -> list[str]:
    """Paths, in packet order, of changed test files whose status is a possible weakening.

    Only entries whose `status` is in `WEAKENING_STATUSES` are considered at all — `"added"` and
    `"copied"` never appear here. For `"modified"`/`"deleted"`, an entry is flagged when `path` is a
    test file. For `"renamed"`, an entry is flagged when `path` is a test file (moved test-to-test),
    OR `old_path` is present and is a test file (moved test-to-non-test — the bypass this exists to
    close), OR `old_path` is absent entirely (conservative: an unrecorded source might have been a
    test). A packet that only *adds* test files returns an empty list.
    """
    flagged: list[str] = []
    for entry in changed_files:
        if entry.get("status") not in WEAKENING_STATUSES:
            continue
        path = str(entry.get("path", ""))
        if is_test_path(path):
            flagged.append(path)
        elif entry.get("status") == "renamed" and _renamed_from_a_test(entry):
            flagged.append(path)
    return flagged


def any_test_change_needs_ack(changed_files: Iterable[Mapping[str, Any]]) -> bool:
    """True if `changed_files` contains at least one possibly-weakened test file."""
    return bool(altered_test_files(changed_files))
