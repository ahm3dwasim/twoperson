"""Does a `tests[]` row cite a run that can still be repeated at the head being published?

A `tests[]` row is a claim that a run can be repeated. The schema in `packet.py` checks that the
row is a well-formed object with the right field types and lengths — it has never checked whether
the run the row describes could actually be performed against the code the packet is publishing.
A row citing a symbol the head does not contain is not weak evidence. It is none, wearing the
costume of a reproduction step.

The failure mode this closes is copy-forward: a row is written once, is true when written, and is
then carried unchanged into every later packet of a lane while the code underneath it moves.
Nothing ages a stale citation out on its own — a stale `command` reads exactly like a fresh one
until something re-checks it against the head being shipped.

WHAT THIS ESTABLISHES, AND WHAT IT DOES NOT
-------------------------------------------
This is a **necessary condition, never a sufficient one.** It refuses rows that are provably
unrepeatable; it certifies nothing about the rows it passes. A symbol that resolves somewhere in
the head's Python may still not be the symbol the run used, and a command may fail for a hundred
reasons this never looks at. The honest statement is: *a citation that does not resolve at the head
cannot be re-run there.* That is the whole claim.

The gaps are deliberate and are listed here rather than hidden, because a check whose boundary is
undocumented gets read as covering everything inside it:

* **A row citing nothing extractable passes untouched.** Prose without identifiers ("312 passed in
  40s") yields no citation and is not evidence of anything either way. `CitationCheck.checked`
  reports how many citations were actually resolved, so a caller can see when that number is zero
  rather than reading silence as approval.
* **Expression-shaped citations are not covered.** ``os.path.exists(target) and registered`` is a
  backticked *expression*, not a name; pulling identifiers out of it yields `os`, `path`, `target`,
  `and`, `registered` — noise that would refuse good packets on a false positive. Only a backticked
  span that is ENTIRELY a dotted name (optionally called) is treated as a citation.
* **A path is judged only when its top-level directory exists at the head**, so a scratch harness
  in `tmp/` or `scratchpad/` is passed over rather than refused. A file deleted along with its whole
  top-level directory is therefore missed.
* **Only the `command` field is read.** An `evidence` field asserting a symbol is gone is correct
  and is left alone; the cost is that a stale citation appearing only in `evidence` is not caught.
  This split is structural, not a phrase match: `command` is what you would run, and a name in it is
  part of the reproduction step; `evidence` is what was observed, and a name there is frequently an
  assertion that something is **absent** ("`_old_helper` is deleted, not orphaned, 0 references") —
  which resolving would refuse for being true.
* **A bare name in prose is not a citation, however much it looks like one.** Only a pytest node id
  (`file.py::name`) and a backticked whole name count. A bare `test_*` token or a bare path in free
  text is not extracted, because no sound rule separates a bare test-function name from a bare
  test-module name (which routinely does not exist as its own file) in prose — a length heuristic
  would separate them today at the cost of being exactly the kind of arbitrary threshold this module
  exists to avoid.
* **A pytest node id is checked only for its FILE, and a dotted name is not a citation at all.**
  A node id's later `::` segments (a class, a parametrized case) are questions only pytest
  collection can answer — `::test_case[old-id]` loses its parameter to a text match, and a nested
  segment matched anywhere in the file would let an unrelated class beside an unrelated function
  satisfy `file.py::Class::method`. Rather than approximate collection with text search, the claim
  is narrowed to what a text search can actually prove: the file must exist for the run to happen at
  all, so that much is kept and the rest is not claimed. A dotted symbol (`module.symbol`) is
  likewise not reduced to its leaf name — `wrong.module.symbol` must not pass on the strength of
  `symbol` existing somewhere unrelated, and resolving the qualified name needs an import graph a
  text search does not have.
* **A head this repository does not hold is undeterminable, and the GATE refuses it.** Three states
  exist because "a citation is gone" and "I could not look" are different facts a caller deserves to
  tell apart. But only `resolves` is treated as passing: a gate that published whatever it could not
  check would have made "name a head this tree does not hold" into a way through, which defeats the
  point of checking at all.

The check runs at **publish** and not at `verify`. `verify` is allowed to run anywhere and writes
nothing; `publish` runs in the builder's own worktree, which is checked out at the head being
published, and is the moment the claim is actually being made.
"""
from __future__ import annotations

import keyword
import re
from pathlib import Path
from typing import Any, Mapping, NamedTuple

from . import _gitrun
from .gitfacts import MAX_GIT_OUTPUT_BYTES

# A bound on SUBPROCESS WORK, never a statement about what was verified. Exceeding it yields
# UNDETERMINABLE, so the cap can never be used to smuggle an unchecked citation past the gate.
MAX_CITATIONS = 200

_GIT_TIMEOUT_S = 30

RESOLVES = "resolves"
MISSING = "missing"
UNDETERMINABLE = "undeterminable"

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")

# A backticked span that is ENTIRELY a dotted name, optionally called. The anchors are the whole
# point: `_reload_tree(parent)` matches, `os.path.exists(target) and registered` does not.
_BACKTICKED = re.compile(r"`([^`\n]{1,200})`")
# ONE identifier, optionally called. A DOTTED name is deliberately not a citation: reducing
# `wrong.module.symbol` to `symbol` would let a citation naming the wrong module pass on the
# strength of the leaf existing in some unrelated file. Resolving the module half needs the
# qualified name, which a text search cannot supply.
_WHOLE_NAME = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(.*\))?$")

# A path to a Python file in a command — `pytest tests/handoff/test_citations.py -q`. Checked for
# existence, and ONLY when its top-level directory exists at the head (see `_resolves`).
_PY_PATH = re.compile(r"(?<![\w:.-])((?:[\w.-]+/)+[\w.-]+\.py)(?!::)")

# `path/to/file.py::test_name`, and `file.py::Class::test_name` — a pytest node id. EVERY `::`
# segment is captured, not just the first, but only the FILE half is ever used as a citation: the
# `::` segments name a pytest-collection question this module does not attempt to answer (see the
# module docstring).
_NODE_ID = re.compile(r"(?<![\w./-])([\w][\w./-]*\.py)((?:::[A-Za-z_][A-Za-z0-9_]*)+)")

# Names that are identifiers but carry no evidence: keywords, and a handful of single words that
# appear backticked in prose meaning something other than a symbol.
_NOT_A_SYMBOL = frozenset(keyword.kwlist) | {
    "self", "None", "True", "False", "unknown", "pass", "passed", "failed", "main", "HEAD",
}


class Citation(NamedTuple):
    """One thing a `tests[]` row says a re-run would need."""

    kind: str          # "path" or "symbol"
    token: str         # what gets resolved at the head
    raw: str           # what the row actually wrote, for the refusal message
    row: str           # the row's `name`, so a refusal points at one row


class CitationCheck(NamedTuple):
    state: str                    # RESOLVES if every citation did, MISSING if any did not, else UNDETERMINABLE
    checked: int                  # how many citations were actually resolved — 0 means this proved nothing
    missing: tuple[Citation, ...]
    note: str


def _dedupe(items: list[Citation]) -> list[Citation]:
    seen: set[tuple[str, str]] = set()
    out: list[Citation] = []
    for item in items:
        key = (item.kind, item.token)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def cited_symbols(packet: Mapping[str, Any]) -> list[Citation]:
    """Every citation the packet's `tests[]` rows make, deduped and capped.

    Reads `command` ONLY, never `evidence` — see the module docstring for why the split is
    structural rather than a phrase match.
    """
    found: list[Citation] = []
    for entry in packet.get("tests") or []:
        if not isinstance(entry, Mapping):
            continue
        row = str(entry.get("name", "") or "")[:120]
        blob = str(entry.get("command", "") or "")

        for match in _NODE_ID.finditer(blob):
            found.append(Citation("path", match.group(1), match.group(1), row))
        for match in _PY_PATH.finditer(blob):
            found.append(Citation("path", match.group(1), match.group(1), row))
        for span in _BACKTICKED.findall(blob):
            whole = _WHOLE_NAME.match(span.strip())
            if not whole:
                continue
            dotted = whole.group(1)
            leaf = dotted.rsplit(".", 1)[-1]
            if leaf in _NOT_A_SYMBOL or len(leaf) < 3 or _SHA_RE.match(leaf):
                continue
            found.append(Citation("symbol", leaf, span.strip(), row))

    return _dedupe(found)


def _git(repo: Path, *args: str) -> _gitrun.GitResult:
    """Run one git subcommand against an EXPLICIT repository path, through the shared bounded runner.

    Every caller here reads only the return code, plus — since the fix for the top-level-probe
    conflation below — occasionally `stderr` for a refusal message. Bounding (time, and stdout/stderr
    bytes each) is entirely `_gitrun.run_git`'s job now, not this function's: a git stdout this
    module never parses can still exhaust memory just by being buffered, which is why it is bounded
    the same as `gitfacts._git`'s is, through the same runner. A failure to even RUN git (missing
    binary, a timeout, either stream over `MAX_GIT_OUTPUT_BYTES`) raises `_gitrun.GitRunError`;
    `check_citations` is what catches that, at the two call sites below, and turns it into
    `UNDETERMINABLE` rather than a crash or a silent pass.
    """
    return _gitrun.run_git(repo, *args, timeout=_GIT_TIMEOUT_S, max_bytes=MAX_GIT_OUTPUT_BYTES)


def _head_is_present(repo: Path, head_sha: str) -> bool:
    """Does this repository hold the commit — and its tree — the packet names?"""
    if not _SHA_RE.match(head_sha or ""):
        return False
    return _git(repo, "rev-parse", "--verify", "--quiet", f"{head_sha}^{{tree}}").returncode == 0


def _resolves(repo: Path, head_sha: str, cite: Citation) -> bool:
    """Would a run at this head find what the row cites?

    `git ls-tree`/`git grep` against the COMMIT, never the working tree: an uncommitted or stale
    file on disk is exactly the thing that would let a deleted symbol look present, which is the
    failure this exists to catch wearing a different hat.

    A PATH citation is checked with `git ls-tree`, never `git cat-file -e`. `ls-tree <sha> --
    <path>` exits 0, with EMPTY output, when `<sha>` resolves but `<path>` is simply not an entry of
    that tree — a clean, unambiguous "not here" that costs nothing to tell apart from a git failure.
    `cat-file -e <sha>:<path>` cannot make that distinction: it returns the SAME exit status (128,
    "fatal: ... does not exist") for a genuinely absent path as it does for other ways the compound
    `<sha>:<path>` expression fails to resolve. Reading "nonzero" as "absent, exempt" — the previous
    shape of the top-level-directory probe below — silently turned any such failure into a pass. Any
    OTHER exit status from `ls-tree` here (the treeish itself failing to resolve, which cannot
    happen — `_head_is_present` already proved `head_sha` resolves — but is not assumed) is raised
    rather than swallowed, so an unexpected status is a refusal, never a resolve.
    """
    if cite.kind == "path":
        # Only judge a path whose TOP-LEVEL directory exists at the head. A command's counterfactual
        # harness is routinely a scratch file — `tmp/mut_v1.py`, `scratchpad/probe.py` — which is
        # never committed and whose absence says nothing about the run. Gating on the directory is a
        # property of the tree rather than a list of blessed names, so it does not go stale the way
        # a hardcoded `{"tmp", "scratchpad", ...}` would.
        top = cite.token.split("/", 1)[0]
        top_probe = _git(repo, "ls-tree", "--name-only", "-z", head_sha, "--", top)
        if top_probe.returncode != 0:
            raise _gitrun.GitRunError(
                f"git ls-tree {head_sha}:{top} exited {top_probe.returncode} unexpectedly — "
                f"{top_probe.stderr.decode('utf-8', 'replace').strip() or 'no output'}"
            )
        if not top_probe.stdout:
            return True  # the top-level directory is provably absent at this head: exempt
        full_probe = _git(repo, "ls-tree", "--name-only", "-z", head_sha, "--", cite.token)
        if full_probe.returncode != 0:
            raise _gitrun.GitRunError(
                f"git ls-tree {head_sha}:{cite.token} exited {full_probe.returncode} "
                f"unexpectedly — {full_probe.stderr.decode('utf-8', 'replace').strip() or 'no output'}"
            )
        return bool(full_probe.stdout)
    grep = _git(repo, "grep", "-w", "-F", "-l", "-e", cite.token, head_sha, "--", "*.py")
    if grep.returncode not in (0, 1):
        raise _gitrun.GitRunError(
            f"git grep -e {cite.token} {head_sha} exited {grep.returncode} unexpectedly — "
            f"{grep.stderr.decode('utf-8', 'replace').strip() or 'no output'}"
        )
    return grep.returncode == 0


def check_citations(repo: Path | str, packet: Mapping[str, Any]) -> CitationCheck:
    """Resolve every citation in `tests[]` against the head the packet names.

    Three states, never two: a boolean answer forces "could not determine" onto whichever side the
    caller treats as permissive, and the permissive side is the one that has to be earned.
    """
    repo = Path(repo)
    head_sha = str((packet.get("git") or {}).get("head_sha", "") or "")
    # THE HEAD IS ESTABLISHED FIRST, before anything can return success. A packet whose rows cite
    # nothing extractable is common and must not skip this: an early "nothing to check" return
    # reaching the permissive answer before the head is even looked at would publish a packet naming
    # a head this repository does not hold, for exactly the population least able to afford it —
    # the same mistake as trusting an absent head, in a new place.
    try:
        present = _head_is_present(repo, head_sha)
    except _gitrun.GitRunError as exc:
        return CitationCheck(UNDETERMINABLE, 0, (), f"git could not be run here — {exc}")
    if not present:
        return CitationCheck(UNDETERMINABLE, 0, (),
                             f"this repository does not hold head {head_sha or 'unknown'}, "
                             "so nothing could be resolved against it")

    every = cited_symbols(packet)
    cites, dropped = every[:MAX_CITATIONS], max(0, len(every) - MAX_CITATIONS)
    if not cites:
        return CitationCheck(RESOLVES, 0, (), "no citation in tests[] was extractable")

    missing: list[Citation] = []
    try:
        for cite in cites:
            if not _resolves(repo, head_sha, cite):
                missing.append(cite)
    except _gitrun.GitRunError as exc:
        return CitationCheck(UNDETERMINABLE, 0, (), f"git stopped answering — {exc}")

    if missing:
        return CitationCheck(MISSING, len(cites), tuple(missing),
                             f"{len(missing)} of {len(cites)} citations do not resolve at "
                             f"{head_sha[:8]}")
    if dropped:
        # A cap that sliced the list and then reported "all N resolve" would make ordering an
        # unresolvable citation past the cap a deterministic bypass. A bound on work must never
        # become a claim about what was checked, so a truncated set can only ever say
        # "undeterminable".
        return CitationCheck(UNDETERMINABLE, len(cites), (),
                             f"{len(cites)} citations resolve at {head_sha[:8]}, but {dropped} more "
                             f"were not checked — over the {MAX_CITATIONS} cap")
    return CitationCheck(RESOLVES, len(cites), (),
                         f"all {len(cites)} citations resolve at {head_sha[:8]}")


def citation_findings(check: CitationCheck) -> list[str]:
    """One human line per unrepeatable citation, naming the row it came from."""
    return [f"tests[] row {cite.row!r} cites {cite.raw!r}, which does not exist at the head being "
            f"published — that run cannot be repeated here" for cite in check.missing]
