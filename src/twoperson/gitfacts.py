"""Derive a packet's diff evidence from git instead of trusting what the builder typed.

`changed_files` and `diff_summary` are hand-entered by the builder, same as everything else in a
packet — and the same as everything else, that means they can be stale by a commit, or simply
wrong, without anyone lying. A reviewer reading a diffstat cannot tell "stale" from "fabricated":
the evidence-to-head binding is broken either way, and re-establishing it costs a round.

The data is fully derivable from the two shas the packet already names, so it never needed to be
typed by hand. This module derives it, and `verify`/`publish` refuse a packet whose stated diff
disagrees with the head it names — printing every disagreement rather than picking one.

**Fail closed, but only on a real disagreement.** If the shas do not resolve in this repository the
packet is refused rather than waved through: an unverifiable diff claim is exactly the failure mode
this closes. ``--no-derive`` is the deliberate escape hatch for a checkout that does not hold the
objects (a draft, a dry run, a CI job without the branch fetched) — it publishes the builder's claim
unchecked, and says so out loud rather than quietly.

Renames are derived with git's own rename detection (`-M`), so a moved test is reported as
`status="renamed"` with `old_path` set, not as an unrelated delete-plus-add — which is exactly the
shape `twoperson.testset` needs to keep the test-change acknowledgment gate honest about a file that
changed identity as well as location.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

from . import _gitrun
from .packet import UNKNOWN, PacketError

#: `git diff --name-status` first-letter code -> the packet's `status` enum. `T` (a type change —
#: e.g. a file becoming a symlink) has no dedicated slot in the packet schema; `modified` is the
#: honest nearest reading, not a new status the schema was never asked to accept.
_STATUS = {"A": "added", "M": "modified", "D": "deleted", "R": "renamed", "C": "copied",
          "T": "modified"}

#: Refuse to derive against an absurd tree rather than emitting a huge changed_files list that no
#: reviewer could audit as one unit.
MAX_DERIVED_FILES = 200

#: A bound on subprocess WORK and memory, never a statement about what was verified: a git call that
#: would return more than this is refused before it is parsed, the same way an oversized inbox entry
#: is refused before it is read (see `twoperson._safefs`).
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024

_GIT_TIMEOUT_S = 30

#: Hex, 7-40 chars: the same shape `packet._sha` accepts, minus the `unknown` sentinel.
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


class GitFactsError(PacketError):
    """The named head could not be described from this repository."""


def _git(repo: Path, *args: str) -> str:
    """Run one git subcommand against an EXPLICIT repository path, with fixed argv and no shell.

    A git failure — missing binary, not a repository, a bad ref, a timeout, a runaway stream over
    `MAX_GIT_OUTPUT_BYTES` — is a refusal here, never "no changes": the two answers mean opposite
    things to a reviewer, and only one of them is true when git simply could not be asked. All of
    that bounding is `_gitrun.run_git`'s job, not this function's — see that module for why stdout
    and stderr are each streamed and capped rather than buffered in full before either is checked.
    """
    try:
        result = _gitrun.run_git(repo, *args, timeout=_GIT_TIMEOUT_S, max_bytes=MAX_GIT_OUTPUT_BYTES)
    except _gitrun.GitRunError as exc:
        raise GitFactsError(str(exc)) from exc
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise GitFactsError(f"git {' '.join(args)} failed: {stderr or 'no output'}")
    return result.stdout.decode("utf-8", "replace")


def concrete(sha: Any) -> bool:
    """True when the value is an actual sha rather than the schema's ``unknown`` placeholder.

    `_sha` deliberately accepts ``unknown`` — a draft, or a round that does not name a head yet —
    so "is this checkable at all?" has to be a separate question from "does it check out?". A packet
    with no concrete head is not refused; deriving against it is simply not attempted.
    """
    return isinstance(sha, str) and sha != UNKNOWN and bool(_SHA_RE.match(sha))


def _rev_parse(repo: Path, ref: str) -> str | None:
    """The commit sha ``ref`` names in ``repo``, or ``None`` if it does not resolve locally.

    Never raises — this is a probe, used both by `resolvable` (does a claimed sha exist at all) and
    by `derive` (does a claimed `base_ref` resolve in THIS checkout, so it is worth checking against
    at all — a ref this checkout never fetched is simply not a check `derive` can make).
    """
    try:
        out = _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except GitFactsError:
        return None
    return out.strip() or None


def resolvable(repo: Path | str, *shas: str) -> bool:
    """True when every sha names a commit in ``repo``. Never raises — this is a probe."""
    repo = Path(repo)
    for sha in shas:
        if not concrete(sha):
            return False
        if _rev_parse(repo, sha) is None:
            return False
    return True


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    """True when ``ancestor`` is reachable from ``descendant`` in ``repo``'s commit graph.

    `git merge-base --is-ancestor` answers exactly this: exit 0 is yes, exit 1 is no — a real
    answer, not a failure, and the one case where a non-zero exit from this module is NOT a
    refusal. Any other exit code (git itself missing, a ref that does not resolve) is the same
    refusal every other call in this module gives, never silently read as "not an ancestor".
    A commit is its own ancestor here, same as git's own definition — callers that need a
    *proper* ancestor (this module's own `derive`) check ``ancestor != descendant`` themselves.
    """
    try:
        result = _gitrun.run_git(repo, "merge-base", "--is-ancestor", ancestor, descendant,
                                 timeout=_GIT_TIMEOUT_S, max_bytes=MAX_GIT_OUTPUT_BYTES)
    except _gitrun.GitRunError as exc:
        raise GitFactsError(str(exc)) from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    stderr = result.stderr.decode("utf-8", "replace").strip()
    raise GitFactsError(
        f"git merge-base --is-ancestor {ancestor} {descendant} failed: {stderr or 'no output'}")


def _split_z(output: str) -> list[str]:
    """A NUL-terminated git output, split into its fields with the trailing empty one dropped."""
    parts = output.split("\0")
    if parts and parts[-1] == "":
        parts.pop()
    return parts


def _parse_name_status(output: str) -> list[dict[str, Any]]:
    """``git diff --name-status -M -z`` output, in order, as ``{"code", "old_path", "new_path"}``.

    ``-z`` is what makes this parseable at all: without it, git abbreviates a rename's path as
    ``dir/{old => new}/file.py`` or ``old.py => new.py`` for the sake of a human terminal, and that
    abbreviation is ambiguous to parse back apart. With ``-z``, a rename or copy is TWO separate
    NUL-terminated fields (old path, then new path) and everything else is one.
    """
    tokens = _split_z(output)
    rows: list[dict[str, Any]] = []
    i = 0
    while i < len(tokens):
        code = tokens[i]
        i += 1
        letter = code[0] if code else ""
        if letter in ("R", "C"):
            if i + 1 >= len(tokens):
                raise GitFactsError("git name-status output ended in the middle of a rename/copy")
            old_path, new_path = tokens[i], tokens[i + 1]
            i += 2
            rows.append({"code": letter, "old_path": old_path, "new_path": new_path})
        else:
            if i >= len(tokens):
                raise GitFactsError("git name-status output ended in the middle of an entry")
            path = tokens[i]
            i += 1
            rows.append({"code": letter, "old_path": None, "new_path": path})
    return rows


def _parse_numstat(output: str) -> dict[str, tuple[int, int]]:
    """``git diff --numstat -M -z`` line counts, keyed by the file's DESTINATION path.

    Each NUL-delimited chunk is itself ``<added>\\t<removed>\\t<rest>`` — the two counts stay
    TAB-separated even under ``-z``. For an ordinary entry ``rest`` is the path outright. For a
    rename or copy, git leaves ``rest`` EMPTY: that is the signal that the traditional single
    "old => new" column has been replaced by two more NUL-terminated fields (old path, then new
    path) that follow as their own chunks, which is what makes this self-describing rather than
    dependent on `--name-status` agreeing on record order.
    """
    tokens = _split_z(output)
    counts: dict[str, tuple[int, int]] = {}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        i += 1
        parts = token.split("\t", 2)
        if len(parts) != 3:
            raise GitFactsError(f"git numstat produced an unparseable record: {token!r}")
        added_s, removed_s, rest = parts
        try:
            added = 0 if added_s == "-" else int(added_s)
            removed = 0 if removed_s == "-" else int(removed_s)
        except ValueError as exc:
            raise GitFactsError(f"git numstat produced a non-numeric line count: {exc}") from exc
        if rest == "":
            if i + 1 >= len(tokens):
                raise GitFactsError("git numstat output ended in the middle of a rename/copy")
            new_path = tokens[i + 1]
            i += 2
        else:
            new_path = rest
        counts[new_path] = (added, removed)
    return counts


def derive(repo: Path | str, base_sha: str, head_sha: str, base_ref: str | None = None) -> dict[str, Any]:
    """``changed_files`` + ``diff_summary`` for ``base_sha...head_sha``, computed from the repo.

    The three-dot form is deliberate: it describes what the branch ADDS relative to the merge base,
    which is what a reviewer reads, and does not report unrelated commits that landed on the base
    since the branch started. ``-M`` turns a delete-plus-add pair the tool would otherwise report as
    two unrelated entries into one ``"renamed"`` entry with `old_path` set.

    **A derived diff must be the diff of the head against its declared base, not against anything
    that merely resolves.** Both shas resolving is necessary but not sufficient: `base_sha ==
    head_sha` resolves and "derives" an empty diff for any packet, and a `base_sha` that resolves to
    some unrelated commit (a different branch, a stale fork point, a typo) resolves too — either way
    the three-dot diff is well-formed and *wrong*. This refuses unless `base_sha` is a PROPER
    ancestor of `head_sha` (`git merge-base --is-ancestor`, and not equal to it): that is the one
    relationship every real "here is my branch's diff" claim has, and it is what makes the derived
    numbers actually describe the change the packet is reporting rather than a diff against whatever
    the builder happened to name.

    **The equality check is on the FULL, resolved commit id, never on the sha strings the packet
    spelled.** `base_sha` and `head_sha` are independently abbreviated — a packet may spell one
    short and the other long — and an abbreviated sha that names the same commit as a full one is
    equal as a commit while unequal as a string. Comparing the strings directly would let
    `base_sha="89cc0fa"` and `head_sha="89cc0fad7c33e6e9fada858c0e67c1c6801bbb7e"` sail past the
    equality check, reach `_is_ancestor` (which is correct, per git's own definition, that a commit
    is its own ancestor), and "derive" an empty diff stamped as checked. Both shas are resolved to
    their full form with `git rev-parse --verify <sha>^{commit}` first, and every comparison below —
    equality, ancestry, reachability from `base_ref` — is done on those resolved ids.

    When `base_ref` is also given and resolves in THIS checkout, `base_sha` must additionally be
    reachable from it. **What that does and does not prove**: it proves the diff is consistent with
    the commits this checkout actually holds under that ref name right now — it does NOT prove
    `base_ref` is the project's current upstream default branch, and it proves nothing when the ref
    does not resolve here at all (an unfetched remote-tracking ref), in which case this half of the
    check is simply not attempted, the same way derivation itself is not attempted against a
    non-concrete head.
    """
    repo = Path(repo)
    if not concrete(base_sha) or not concrete(head_sha):
        raise GitFactsError(
            f"cannot describe {base_sha[:12]}...{head_sha[:12]} from {repo} — one or both commits "
            "are not in this repository. Publish from a checkout that holds them, or pass "
            "--no-derive to state explicitly that the diff evidence is unverified."
        )
    full_base, full_head = _rev_parse(repo, base_sha), _rev_parse(repo, head_sha)
    if full_base is None or full_head is None:
        raise GitFactsError(
            f"cannot describe {base_sha[:12]}...{head_sha[:12]} from {repo} — one or both commits "
            "are not in this repository. Publish from a checkout that holds them, or pass "
            "--no-derive to state explicitly that the diff evidence is unverified."
        )
    if full_base == full_head:
        raise GitFactsError(
            f"base_sha and head_sha both resolve to the same commit ({full_head[:12]}) — there is "
            "no diff to derive. A derived diff must be of the head against a PROPER ancestor of it, "
            "never against itself; state a real base, or pass --no-derive to publish the claim "
            "unverified."
        )
    if not _is_ancestor(repo, full_base, full_head):
        raise GitFactsError(
            f"base_sha {full_base[:12]} is not an ancestor of head_sha {full_head[:12]} in {repo} — "
            "a derived diff must be of the head against a commit actually in its history, not an "
            "unrelated one. Correct git.base_sha, or pass --no-derive to publish the claim "
            "unverified."
        )
    if base_ref is not None:
        base_ref_sha = _rev_parse(repo, base_ref)
        if base_ref_sha is not None and not _is_ancestor(repo, full_base, base_ref_sha):
            raise GitFactsError(
                f"base_sha {full_base[:12]} is not reachable from base_ref {base_ref!r} "
                f"({base_ref_sha[:12]}) in {repo} — the packet's declared base is not on the "
                "branch it claims to be based on. Correct git.base_sha or git.base_ref, or pass "
                "--no-derive to publish the claim unverified."
            )
    status_rows = _parse_name_status(
        _git(repo, "diff", "--name-status", "-M", "-z", f"{full_base}...{full_head}"))
    if len(status_rows) > MAX_DERIVED_FILES:
        raise GitFactsError(
            f"{len(status_rows)} changed files exceeds the {MAX_DERIVED_FILES}-file derivation "
            "cap — a packet this wide is not reviewable as one unit; split it"
        )
    numstat_counts = _parse_numstat(
        _git(repo, "diff", "--numstat", "-M", "-z", f"{full_base}...{full_head}"))
    if numstat_counts.keys() != {row["new_path"] for row in status_rows}:
        raise GitFactsError("git numstat and name-status disagree on which files changed")

    changed_files: list[dict[str, Any]] = []
    for row in status_rows:
        added, removed = numstat_counts[row["new_path"]]
        entry: dict[str, Any] = {
            "path": row["new_path"],
            "status": _STATUS.get(row["code"], UNKNOWN),
            "insertions": added,
            "deletions": removed,
        }
        if row["old_path"] is not None:
            entry["old_path"] = row["old_path"]
        changed_files.append(entry)
    changed_files.sort(key=lambda e: e["path"])

    return {
        "changed_files": changed_files,
        "diff_summary": {
            "files_changed": len(changed_files),
            "insertions": sum(e["insertions"] for e in changed_files),
            "deletions": sum(e["deletions"] for e in changed_files),
        },
    }


def disagreement(packet: Mapping[str, Any], derived: Mapping[str, Any]) -> list[str]:
    """Human-readable differences between a packet's stated diff evidence and the derived truth.

    Totals, the file set, and — per file — `status` and `old_path` are compared; per-file line
    counts are not, because they are already checked through the totals and a formatting difference
    there is not the failure this exists to catch. `status`/`old_path` ARE compared individually:
    a builder who lists an altered test as ``"added"`` (exempt from the test-change acknowledgment
    gate) when git says ``"modified"``, or who omits `old_path` on a rename, is describing a
    different change from the one at the head, which is exactly the self-report gap this closes.
    """
    problems: list[str] = []
    stated_summary, truth_summary = packet.get("diff_summary") or {}, derived["diff_summary"]
    for key in ("files_changed", "insertions", "deletions"):
        if stated_summary.get(key) != truth_summary[key]:
            problems.append(
                f"diff_summary.{key}: packet says {stated_summary.get(key)!r}, head is "
                f"{truth_summary[key]!r}")

    stated_by_path = {e.get("path"): e for e in (packet.get("changed_files") or [])}
    truth_by_path = {e["path"]: e for e in derived["changed_files"]}

    for path in sorted(truth_by_path.keys() - stated_by_path.keys()):
        problems.append(f"changed_files: {path} is in the diff but not in the packet")
    for path in sorted(stated_by_path.keys() - truth_by_path.keys()):
        problems.append(f"changed_files: {path} is in the packet but not in the diff")
    for path in sorted(truth_by_path.keys() & stated_by_path.keys()):
        stated_entry, truth_entry = stated_by_path[path], truth_by_path[path]
        if stated_entry.get("status") != truth_entry["status"]:
            problems.append(
                f"changed_files[{path!r}].status: packet says {stated_entry.get('status')!r}, "
                f"head is {truth_entry['status']!r}")
        stated_old, truth_old = stated_entry.get("old_path"), truth_entry.get("old_path")
        if stated_old != truth_old:
            problems.append(
                f"changed_files[{path!r}].old_path: packet says {stated_old!r}, head is "
                f"{truth_old!r}")
    return problems
