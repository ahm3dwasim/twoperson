"""Test-file detection for the packet review gate.

A builder under pressure to get a green packet past review has an easy lever nobody is watching:
quietly weaken or delete a test rather than fix the code it covers. This module answers one
narrow, stdlib-only question — "did this packet's `changed_files` touch something that looks like
a test, in a way that could be a weakening?" — so `twoperson.inbox.assert_review_ref_resolves` can
require the approving verdict to say it noticed.

Two limitations, stated here because they matter more than the feature:

* It acts on the builder-declared `changed_files` list, nothing else. A builder who edits a test
  and simply omits it from that list is not caught — that is a separate integrity gap (the
  packet's `changed_files` is self-reported, same as `diff_summary`).
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


def altered_test_files(changed_files: Iterable[Mapping[str, Any]]) -> list[str]:
    """Paths, in packet order, of changed test files whose status is a possible weakening.

    Only entries whose `status` is in `WEAKENING_STATUSES` and whose `path` is a test file
    (`is_test_path`) are returned. A packet that only *adds* test files returns an empty list.
    """
    return [
        str(entry["path"])
        for entry in changed_files
        if entry.get("status") in WEAKENING_STATUSES and is_test_path(str(entry.get("path", "")))
    ]


def any_test_change_needs_ack(changed_files: Iterable[Mapping[str, Any]]) -> bool:
    """True if `changed_files` contains at least one possibly-weakened test file."""
    return bool(altered_test_files(changed_files))
