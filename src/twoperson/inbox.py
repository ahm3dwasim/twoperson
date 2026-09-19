"""The durable Builder->Reviewer inbox — a plain directory tree, not a chat channel.

    state/twoperson/
      staging/   <- packet bytes are written here first; never visible to a reader
      pending/   <- atomically published packets awaiting audit
      claimed/   <- packets an auditor has taken (exclusive; a packet is claimed at most once)
      audited/   <- claimed packets whose verdict was durably published (terminal, for the record)
      rejected/  <- quarantined packets + a .reason.txt saying why
      signals/   <- completion signals: "a session stopped", NOT audit packets
      signals_seen/ <- signals an auditor has acknowledged
      consult/   <- advisory questions awaiting Reviewer's counsel (NOT audit packets)
      consult_claimed/ <- consults an auditor has taken to answer
      consult_answered/ <- claimed consults whose advice was durably published (terminal)
      advice/    <- Reviewer's advisory answers, awaiting the manager
      advice_seen/ <- advice the manager has acknowledged

Signals live in their own lane on purpose. They are wake-ups, not work: `pending()` and therefore
`check`/`next` never see them, so a finished session that produced nothing auditable can never be
mistaken for a packet awaiting audit.

`claimed/`/`consult_claimed/` are meant to hold ONLY unresolved work — either genuinely mid-review or
orphaned by a crashed auditor (see `twoperson.reviewer.recovery`'s stale-claim sweep, which requeues
anything sitting there past a lease timeout). A successfully reviewed packet/consult is therefore
moved OUT to `audited/`/`consult_answered/` once its verdict/advice is durably published
(`archive_claimed`/`archive_claimed_consult`) — never left behind in `claimed/`, where an
age-based sweep would eventually mistake it for an orphan and requeue an already-decided packet for
a pointless repeat review. The verdict/advice itself (in `verdicts/`/`advice/`, surviving into
`verdicts_seen/`/`advice_seen/`) remains the actual audit record; `audited/`/`consult_answered/` is a
secondary trail of which claim it resolved.

Why a directory: the handoff must survive a crashed or disconnected session, needs no live
agent-to-agent link, costs nothing to poll (`has_pending()` is a `listdir`), and is auditable with
`ls`. `state/` is gitignored and host-local, so packets are never committed or deployed.

**One inbox per repository, not per worktree.** Sessions work in their own `git worktree`, so
"this checkout's `state/`" would give each session a private inbox and a packet published in a
worktree would be invisible to an auditor polling the main checkout — a silent gate failure, since
an unreachable packet and an empty inbox both read as "nothing waiting". The default therefore
resolves to the **main working tree's** `state/twoperson` for every worktree of the repository
(see `shared_repo_root`); `$TWOPERSON_INBOX` still overrides it outright.

Safety properties this module owns:

* **Atomic publish.** Bytes land in `staging/` and become visible only via a single `os.replace`
  into `pending/`, so a concurrent reader sees a whole packet or nothing at all.
* **Exclusive claim.** Claiming is `os.rename` out of `pending/`; the loser of a race gets an
  `OSError`, never a duplicate. A packet is therefore audited at most once.
* **No path authority.** Target names are built only from a validated slug and a normalised
  timestamp, and every read, claim, rename and publish is addressed through a descriptor chain
  opened `O_NOFOLLOW | O_DIRECTORY` from the inbox root down: the root descriptor, then the lane by
  `dir_fd`, then the entry by `dir_fd`. A symlinked root, or a lane swapped for a symlink after it
  was listed, is refused in the syscall that would have followed it rather than re-resolved.
* **Hostile input is quarantined, not returned.** Anything in `pending/` that is oversize,
  unparseable, symlinked, a directory, or schema-invalid is moved to `rejected/` with a reason.
* **A refusal is not an empty lane.** If a lane cannot be listed in full, its readers raise
  :class:`~twoperson.packet.LaneUnreadable` rather than answering "nothing here" — a poller that
  cannot tell those apart goes quiet on exactly the tampering the refusal exists to catch. The one
  lane that opts out is `signals/`, which gates nothing; it says so in its own docstring.
* **A refusal is raised where it happens, not where it is remembered.** The file-access primitive
  itself raises ``LaneUnreadable`` for any hop it cannot make, so a command reaches the refusal
  through the operations it already calls rather than through a per-command `except` clause somebody
  has to remember to add. The single exception is `FileNotFoundError`, which is the documented "not
  created yet" / "already moved" answer and stays the caller's to interpret.

**Every file this module touches goes through :mod:`twoperson._safefs`**, which states the threat
model (which names are adversarial and which belong to the operator) and enforces it in one place —
see its module docstring. This module holds no `open` of its own: the descriptor chain below is a
sequence of calls into that primitive, and `tests/test_safefs_guard.py` fails the build if a raw
file operation reappears here.

See `docs/PROTOCOL.md` for the runbook.
"""
from __future__ import annotations

import os
import stat as _stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import structlog

from . import _safefs
from .packet import (
    MAX_PACKET_BYTES,
    LaneUnreadable,
    PacketError,
    dumps_packet,
    loads_packet,
    validate_packet,
)
from .signal import MAX_SIGNAL_BYTES, dumps_signal, loads_signal, validate_signal
from .testset import altered_test_files
from .verdict import (
    MAX_VERDICT_BYTES,
    SHIP_DECISIONS,
    dumps_verdict,
    loads_verdict,
    unlocks_ship,
    validate_verdict,
)
from .consult import MAX_CONSULT_BYTES, dumps_consult, loads_consult, validate_consult
from .advice import MAX_ADVICE_BYTES, dumps_advice, loads_advice, validate_advice

log = structlog.get_logger(__name__)

__all__ = [
    "MAX_PACKET_BYTES", "Claimed", "LaneScan", "LaneUnreadable", "ack_advice", "ack_signals",
    "ack_verdicts", "answered_consult_ids",
    "archive_claimed", "archive_claimed_consult", "archived", "archived_consults", "claim_consult",
    "claim_next", "claimed", "claimed_consults", "has_pending", "has_pending_advice",
    "has_pending_consults", "has_pending_signals", "has_pending_verdicts", "inbox_root",
    "peek_consult", "peek_next", "pending", "pending_advice", "pending_consults",
    "pending_signals", "pending_verdicts", "publish", "publish_advice", "publish_consult",
    "publish_signal", "publish_verdict", "quarantine", "read_advice", "read_signals",
    "read_verdicts", "requeue_claimed", "find_packet", "assert_review_ref_resolves", "requeue_claimed_consult", "shared_repo_root",
    "verdicted_packet_ids",
]

INBOX_ENV = "TWOPERSON_INBOX"
INBOX_DIRNAME = ".twoperson"
_SUBDIRS = ("staging", "pending", "claimed", "audited", "rejected", "signals", "signals_seen",
            "verdicts", "verdicts_seen", "consult", "consult_claimed", "consult_answered",
            "advice", "advice_seen")
#: The hard ceiling on one lane entry the chain will read. Each lane's own cap (``MAX_*_BYTES``) is
#: the authority for that lane and is checked by its own reader; this is the outer bound the
#: primitive needs so that "read this entry" can never mean "read however many bytes are there".
_MAX_ENTRY_BYTES = max(MAX_PACKET_BYTES, MAX_VERDICT_BYTES, MAX_SIGNAL_BYTES,
                       MAX_CONSULT_BYTES, MAX_ADVICE_BYTES)
#: Where the repository search starts. ``None`` means "the process's current working directory",
#: resolved at call time: a CLI must address the repository it is *run in*, never the one it was
#: *installed from*. Pinning it to the package location works only for an editable checkout and
#: silently points every pip-installed user at their site-packages tree. Tests pin it to a fixture.
_SEARCH_START: Path | None = None


def _start_dir() -> Path:
    """The directory `shared_repo_root` walks up from when the caller named none."""
    return _SEARCH_START if _SEARCH_START is not None else Path.cwd()
# `.git` pointer files and `commondir` hold one short path; anything longer is not one of ours.
_GITFILE_MAX_CHARS = 4096


@dataclass(frozen=True)
class Claimed:
    """A packet taken out of `pending/` — ``path`` is where it now lives, ``packet`` is validated."""

    path: Path
    packet: dict


#: A refused entry's name is chosen by whoever dropped it and lands in a terminal and a log line.
#: Anything that is not printable ASCII becomes an escape, so it can never move the cursor, start a
#: colour run, or open a second line inside a message whose whole job is to be one legible line.
_SAFE_NAME_CHARS = 96


def _safe_name(name: str) -> str:
    """One filesystem name, rendered so it cannot forge output. Bounded, printable, single-line."""
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else "\\x%02x" % min(ord(ch), 255) for ch in name)
    if len(cleaned) > _SAFE_NAME_CHARS:
        cleaned = cleaned[:_SAFE_NAME_CHARS] + "…"
    return cleaned


@dataclass(frozen=True)
class LaneScan:
    """One lane's listing, with the refusals kept instead of thrown away.

    ``complete`` is the field that matters: when it is False, ``files`` is a LOWER BOUND and an empty
    ``files`` proves nothing. A caller that treats absence as evidence must consult ``complete``
    before it does — or call `_lane_files`, which fails closed on its behalf.
    """

    files: tuple[Path, ...]
    refused: tuple[str, ...]
    complete: bool

    def reason(self, lane: str) -> str:
        """A one-line, bounded description of why the listing is incomplete. Never echoes content.

        The names come straight from the filesystem into a string that reaches a terminal and a log.
        A filename may hold newlines, control characters and ANSI escapes, so a hand-dropped entry
        could forge CLI output and audit-log lines — the one place a refusal is supposed to be
        legible. Names are sanitised to printable ASCII, bounded per name, and the whole line is
        single-line by construction.
        """
        shown = ", ".join(_safe_name(name) for name in sorted(self.refused)[:5])
        more = f" (+{len(self.refused) - 5} more)" if len(self.refused) > 5 else ""
        return f"inbox lane {lane!r} could not be listed completely; refused: {shown}{more}"


# --------------------------------------------------------------------------------------------
# Layout
# --------------------------------------------------------------------------------------------

def shared_repo_root(start: Path | str | None = None) -> Path | None:
    """The **main** working tree of the repository containing ``start`` — one path for all worktrees.

    Sessions often run in their own `git worktree`, and each worktree is a separate checkout
    with its own `state/`. Defaulting the inbox to "this checkout's state dir" therefore gives every
    session a *private* inbox: Builder publishes in a worktree, Reviewer polls from the main checkout,
    and neither can see the other. That is a silent failure — `check` exits 1, which reads exactly
    like "no work waiting".

    Resolution is filesystem-only (no `git` subprocess, so a poll stays a few `stat` calls):

    * `<dir>/.git` is a directory -> ``dir`` is the main working tree.
    * `<dir>/.git` is a file -> a linked worktree. It holds ``gitdir: <path>``; that directory holds
      a ``commondir`` pointing at the shared `.git`, whose parent is the main working tree.

    Returns ``None`` when ``start`` is not inside a git checkout at all (e.g. an installed package),
    so the caller can fall back rather than guess.
    """
    base = Path(start) if start is not None else _start_dir()
    try:
        base = base.resolve()
    except OSError:
        return None
    for directory in (base, *base.parents):
        marker = directory / ".git"
        try:
            if marker.is_dir():
                return directory
            if marker.is_file():
                return _main_worktree_from_gitfile(marker) or directory
        except OSError:
            return None
    return None


def _main_worktree_from_gitfile(marker: Path) -> Path | None:
    """Follow a linked worktree's ``.git`` file to the main working tree, or ``None`` if it is odd.

    Every read is bounded and every failure returns ``None``: a malformed or hostile `.git` file
    must degrade to "use this checkout", never to an arbitrary path or an exception in a poll.
    """
    try:
        # safefs: out-of-model — a checkout's own `.git` marker, found by walking UP from the working
        # directory; it is the operator's layout, outside every inbox root, and this module does not
        # own it. The read is bounded, tolerant of bad bytes and any failure returns None.
        text = marker.read_text(encoding="utf-8", errors="replace")[:_GITFILE_MAX_CHARS]
        prefix, _, raw = text.partition(":")
        if prefix.strip() != "gitdir" or not raw.strip():
            return None
        gitdir = Path(raw.strip())
        if not gitdir.is_absolute():
            gitdir = marker.parent / gitdir
        # safefs: out-of-model — the same operator-owned `.git` tree, one hop further in; the path
        # comes from the marker above, never from an inbox name, and the read is bounded.
        common_raw = (gitdir / "commondir").read_text(encoding="utf-8")[:_GITFILE_MAX_CHARS].strip()
        if not common_raw:
            return None
        common = Path(common_raw)
        if not common.is_absolute():
            common = gitdir / common
        common = common.resolve()
    except (OSError, ValueError):
        return None
    # Only a real `.git` directory has a working tree above it; a bare repo's parent does not.
    if common.name != ".git" or not common.is_dir() or not common.parent.is_dir():
        return None
    return common.parent


def _default_parent() -> Path:
    """The directory the inbox defaults *inside* — **shared by every worktree of this repository**.

    Order: a live ``TWOPERSON_HOME`` (an operator's explicit, absolute choice) -> the main working
    tree found by `shared_repo_root` -> the user's home directory.

    The home fallback only fires outside a git checkout. It is deliberately a real, writable,
    per-user path rather than the process CWD: an inbox that moves whenever you `cd` is an inbox
    two agents silently disagree about, which is the exact failure this module exists to prevent.
    """
    home = os.environ.get("TWOPERSON_HOME", "").strip()
    if home:
        return Path(home)
    shared = shared_repo_root()
    if shared is not None:
        return shared
    return Path.home()


def inbox_root(root: Path | str | None = None) -> Path:
    """The inbox root: explicit argument, else ``$TWOPERSON_INBOX``, else the shared default.

    The default is deterministic across worktrees (see `_default_parent`), so Builder in
    `.builder/worktrees/<x>` and Reviewer in the main checkout address the *same* inbox without either
    side configuring anything. An explicit argument or ``$TWOPERSON_INBOX`` still wins outright —
    that is what tests and any deliberately isolated inbox rely on.
    """
    if root is not None:
        return Path(root)
    override = os.environ.get(INBOX_ENV, "").strip()
    return Path(override) if override else _default_parent() / INBOX_DIRNAME


def _ensure_tree(root: Path) -> Path:
    """Create the inbox tree owner-only, one level below a held descriptor at a time.

    Every step — the root's ``mkdir``, its ``fchmod``, each lane's ``mkdir`` and ``fchmod`` — is a
    creation that can fail (a full disk, a permission wall) and each is performed by
    :func:`twoperson._safefs.open_dir`, which wraps all four into the same `LaneUnreadable` the read
    path raises. A root that is an existing regular file, a root that is a dangling symlink, and a
    parent this process may not write to used to leave here as raw `FileExistsError` /
    `PermissionError` / `OSError` — a traceback out of `next`, which is the one thing a refusal
    exists to prevent.

    Each level is created RELATIVE to the descriptor of the level above it and permission-set
    through the level's own descriptor, so the directory that was checked and the directory that was
    modified are provably the same object. Creating ``root / name`` by path instead would re-resolve
    the root once per lane, so a root swapped for a symlink part-way through the loop would have had
    the remaining lanes created somewhere else. ``mkdir``'s "already exists" answer is NOT the
    check: a lane replaced by a symlink gives that answer too, and it is the open that refuses.
    """
    root_fd = _open_root_dir(root, create=True)
    try:
        for name in _SUBDIRS:
            _safefs.close_quietly(_safefs.open_dir(root_fd, name, create=True, what=f"the lane {name!r}"))
    finally:
        _safefs.close_quietly(root_fd)
    return root


@contextmanager
def _publish_lock(root: Path):
    """Serialise name-selection + rename across processes (the repo's budget-ledger idiom).

    The lock lives on its own file, never on a packet, so an atomic replace can never disturb a
    concurrent locker's open file description. It is created relative to the root's descriptor with
    `O_NOFOLLOW`, so a `.lock` swapped for a symlink cannot aim the lock — or the file it opens —
    at something outside the inbox.
    """
    root_fd = _open_root_dir(root)
    try:
        handle = _safefs.open_lockfile(root_fd, ".lock", what="the publish lock")
    finally:
        _safefs.close_quietly(root_fd)
    try:
        yield
    finally:
        _safefs.unlock_quietly(handle)
        _safefs.close_handle_quietly(handle)


def _assert_inside(root: Path, target: Path) -> Path:
    """Refuse any target that does not resolve inside the inbox root."""
    root_resolved = root.resolve()
    resolved = target.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise PacketError(f"refusing to write outside the inbox root: {target}")
    return target


# --------------------------------------------------------------------------------------------
# The descriptor chain
#
# Every path an inbox operation touches has the shape `<root>/<lane>/<entry>`, and each hop is
# opened with `O_NOFOLLOW` RELATIVE TO THE DESCRIPTOR ABOVE IT. `O_NOFOLLOW` on a bare path guards
# only its LAST component: the components above it are resolved by the kernel on every call, so a
# root or a lane swapped for a symlink is followed even though each individual open "checked" a
# symlink. Holding the chain and addressing each hop by `dir_fd` removes the question entirely — an
# operation can no longer be redirected by a swap of a path it does not name.
#
# The root is validated by that same open. `lstat`-then-open would be two resolutions with a window
# between them, which is not a check; `O_NOFOLLOW | O_DIRECTORY` refuses a symlinked or
# non-directory root in the single syscall that would have followed it. Directories ABOVE the inbox
# root are the operator's own layout and are deliberately out of scope: the inbox does not own
# them, cannot know what they are for, and refusing a checkout reached through a symlinked parent
# would refuse ordinary setups.
#
# ONE EXCEPTION TYPE ESCAPES, and it escapes as a refusal. A hop this chain cannot make is a
# refusal, not a lost race and not a crash, so it surfaces as `LaneUnreadable` — the type the CLI
# boundary net and every lane reader already handle. Guarding each command separately would be a
# hand-kept list, and the commands that had guards would be the ones somebody remembered; raising
# the refusal HERE is what covers the commands not yet written. `FileNotFoundError` is deliberately
# NOT converted: it is the documented answer for the two ordinary, non-hostile cases — a tree
# `_ensure_tree` has not created yet (provably empty), and an entry another process already moved
# (a lost race) — and both are the caller's to interpret. Everything else the kernel can answer
# here (a symlinked lane, a lane that is a regular file, a permission wall) is a refusal.
# --------------------------------------------------------------------------------------------

def _refuse_a_root_that_cannot_be_created(root: Path) -> None:
    """A missing root is "provably empty" only where it COULD have existed.

    `_lane_scan` reads a root that is not there as an empty inbox, which is right for a fresh
    checkout whose `state/` has not been made yet, and wrong for an inbox whose parent refuses this
    process: there, "nothing is waiting" is a refusal reported as the empty answer it exists to be
    told apart from, and a poller goes quiet on exactly the misconfiguration it should surface. So
    the question is asked of the PARENT — and only when the parent is itself there: a path whose
    whole tree is absent is the documented "never created" case and stays one, because `_ensure_tree`
    would create every level of it on the next write.

    :raises LaneUnreadable: the root does not exist and cannot be made to.
    """
    parent = root.parent
    if parent.is_dir() and not os.access(parent, os.W_OK | os.X_OK):
        raise LaneUnreadable(
            f"the inbox root {root} could not be created: {parent} is not writable"
        )


def _open_root_dir(root: Path, *, create: bool = False) -> int:
    """The inbox root's own descriptor, or `LaneUnreadable` when the root is not a real directory.

    ``create`` is the writing path: the primitive makes the root (and reports a failure to make it
    as a refusal) before opening it. Without it the absent root is the caller's own answer, and the
    only question this adds is whether it *could* have existed — see
    `_refuse_a_root_that_cannot_be_created`.
    """
    try:
        return _safefs.open_dir(None, str(root), create=create, what=f"the inbox root {root}")
    except FileNotFoundError:
        if create:
            raise           # the primitive already tried to make it; this is unreachable by rule
        _refuse_a_root_that_cannot_be_created(root)
        raise               # nothing has ever been published here — a provably empty inbox


def _lane_dir_fd(root: Path, lane: str) -> int:
    """An open descriptor for one lane, reached THROUGH the root's, or `OSError`.

    `O_NOFOLLOW | O_DIRECTORY` refuses a symlinked or non-directory lane in the same syscall that
    opens it, and opening it relative to the root's descriptor means the root is held for that hop
    too. Every read, rename and write below is addressed RELATIVE to the descriptor this returns,
    so no operation depends on a path meaning the same thing twice.

    :raises LaneUnreadable: the root or the lane is not a real, openable directory.
    :raises FileNotFoundError: the root or the lane does not exist — the caller's own "not created
        yet" / "already gone" answer, which this layer deliberately does not reinterpret.
    """
    root_fd = _open_root_dir(root)
    try:
        return _safefs.open_dir(root_fd, lane, what=f"the lane {lane!r}")
    finally:
        _safefs.close_quietly(root_fd)


def _split_lane_path(path: Path) -> tuple[Path, str, str]:
    """``<root>/<lane>/<entry>`` -> ``(root, lane, entry)``.

    Exactly two components are stripped, so a root that is itself a deep or a relative path comes
    back the way `_lane_scan` built it. The shape is the module's own invariant: every path handed
    out by a lane listing, and every path handed back to a lane operation, is ``root / lane / name``
    and nothing else is a lane entry.
    """
    lane_dir = path.parent
    return lane_dir.parent, lane_dir.name, path.name


def _entry_what(lane: str, name: str) -> str:
    """The refusal's own wording for one lane entry, built from our names and never from the file's.

    A dropped entry's name is chosen by whoever dropped it and reaches a terminal, so it goes through
    `_safe_name` — bounded, printable, single-line — before it can be part of a message.
    """
    return f"the entry {_safe_name(name)!r} in lane {lane!r}"


def _open_lane_entry_fd(path: Path) -> tuple[int, str, str]:
    """The chain's last hop: ``(lane_fd, entry_name, lane)`` for one entry PATH.

    Handing a bare path to `open()` guards only its last component, so an entry could be listed
    safely and then read from outside the inbox once the *lane* above it was swapped for a symlink
    in the window between the listing and the read. The chain is root -> lane -> entry, and every
    hop is made by :mod:`twoperson._safefs`, which refuses in the syscall that would have followed
    it. The caller owns the returned descriptor and must close it.

    :raises LaneUnreadable: the root or the lane is not a real, openable directory.
    :raises FileNotFoundError: some hop is already gone; the caller decides what that means.
    """
    root, lane, name = _split_lane_path(path)
    return _lane_dir_fd(root, lane), name, lane


def _read_lane_file(path: Path) -> bytes:
    """Read one lane file through the descriptor chain, refusing a symlink AT OPEN.

    The check and the open are one operation, so a swap between them is not a race to lose: the
    refusal happens in the syscall that would otherwise have consumed the wrong file. A swap to a
    different REGULAR file is still possible and is not claimed otherwise; that attacker already
    holds write access to a 0700 directory, and what they would gain is writing a packet, which they
    could do directly. A FIFO swapped in cannot hang the read, and a special file cannot be read at
    all — both are refused by the primitive before a byte moves.
    """
    lane_fd, name, lane = _open_lane_entry_fd(path)
    try:
        return _safefs.read_regular(lane_fd, name, _MAX_ENTRY_BYTES, what=_entry_what(lane, name))
    finally:
        _safefs.close_quietly(lane_fd)


def _lane_entry_size(path: Path) -> int:
    """One lane entry's size, read through the same chain as its content.

    A size cap is a read of the entry too: `path.stat()` re-resolves the lane by path and follows a
    symlink, so the number a caller used to decide whether to open the file could come from a file
    the read itself would then refuse.
    """
    lane_fd, name, lane = _open_lane_entry_fd(path)
    try:
        return _safefs.entry_size(lane_fd, name, what=_entry_what(lane, name))
    finally:
        _safefs.close_quietly(lane_fd)


def _write_lane_file(root: Path, lane: str, name: str, body: bytes) -> None:
    """Make one file IN a lane of ``root`` mean exactly ``body``, through the descriptor chain.

    Used for the `.reason.txt` recorded beside a quarantined packet. `Path.write_text` resolves the
    lane again, so a lane swapped for a symlink would have had the reason — and only the reason —
    written outside the inbox.

    The lane is named, not derived from the target path, for the same reason a move's is (see
    `_lane_member`): a write's inbox is the caller's to name, and reading it back out of the path
    would discard the one the caller gave. The entry NAME is checked as one component here, so this
    hop carries its own authority rather than inheriting it from the move that produced the path.

    The write REPLACES the directory entry rather than opening the file it names — see
    `_safefs.replace_regular`. Opening it with `O_TRUNC | O_NOFOLLOW` refused a symlink but not a
    HARD LINK, so a `rejected/<stem>.reason.txt` pre-created as a hard link to a writable file
    outside the inbox had that outside file truncated by an ordinary quarantine. A refusal —
    a `.reason.txt` name pre-created as a symlink, a lane that is not a directory — is raised as
    `LaneUnreadable` and not as a raw `ELOOP`/`ENOTDIR`: this hop is reachable from an ordinary
    `next`, because a malformed packet is quarantined on the way past.
    """
    lane_fd = _lane_dir_fd(root, lane)
    try:
        _safefs.replace_regular(lane_fd, name, body, what=_entry_what(lane, name))
    finally:
        _safefs.close_quietly(lane_fd)


def _lane_member(root: Path, lane: str, path: Path) -> str:
    """The entry NAME ``path`` must have inside ``root/lane`` — or a refusal.

    A move names its source as a PATH and its inbox as an explicit ``root``, and those are two
    claims that can disagree. Deriving the root back out of the source threw the explicit one away:
    ``archive_claimed('/outside/claimed/x.json', root='/intended')`` resolved both lanes under
    ``/outside`` and moved the file THERE, so a caller that named an inbox did not get the move it
    asked for and had no way to know — the return value is a path, and it looked like a success. The
    root the caller names is the only authority for where an entry may be, so the source is required
    to BE an entry of ``root/lane`` and is refused, not followed, when it is not.

    The comparison is on the path as given, deliberately: resolving it first would ask a question
    about where the path POINTS, which is the answer an attacker supplies. A caller that built the
    path the way this module hands paths out — ``root / lane / name``, exactly what `_lane_scan`
    returns — always matches, and a caller holding a path to some other inbox is told so.
    """
    if path.parent != root / lane:
        raise PacketError(
            f"refusing to move {_safe_name(path.name)!r}: it is not an entry in the {lane!r} lane "
            f"of the inbox root {root}"
        )
    return _safefs.plain_name(path.name)


def _move_lane_entry(src: Path, *, root: Path, src_lane: str, dst_lane: str) -> Path:
    """Move one lane entry into another lane of the inbox named by ``root``, both ends by descriptor.

    `os.rename(src, dst)` resolves both paths again, so a lane swapped for a symlink after the
    listing redirected the move — and the file it moved — outside the inbox. `os.rename` with
    `src_dir_fd`/`dst_dir_fd` names no path at all: both lanes are held open with
    `O_NOFOLLOW | O_DIRECTORY`, and a rename never follows a symlink at either end (it replaces
    one), so neither end can be redirected. The free-name choice is made against the destination
    lane's descriptor for the same reason.

    BOTH lanes are resolved from ``root`` — the source lane by the name the caller gives (never by
    reading it back out of ``src``), after `_lane_member` has confirmed the source is an entry of
    that very lane. So the source that is validated and the source that is renamed are the same
    claim, and the destination is derived from the inbox the caller named rather than from wherever
    the source happened to sit.

    `FileNotFoundError` is left to the caller: it is what "the source is already gone" looks like,
    which every caller here treats as a lost race and not as a failure. A lane that cannot be
    opened, and a source outside the inbox the caller named, are different answers and are allowed
    to propagate.
    """
    name = _lane_member(root, src_lane, src)
    src_fd = _lane_dir_fd(root, src_lane)
    try:
        dst_fd = _lane_dir_fd(root, dst_lane)
        try:
            final = _safefs.free_name(dst_fd, name)
            _safefs.rename(src_fd, name, dst_fd, final)
        finally:
            _safefs.close_quietly(dst_fd)
    finally:
        _safefs.close_quietly(src_fd)
    return root / dst_lane / final


def _stamp(created_at: str) -> str:
    """``2026-08-19T09:30:00Z`` -> ``20260819T093000Z`` (UTC), so filenames sort chronologically."""
    parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# --------------------------------------------------------------------------------------------
# Publish
# --------------------------------------------------------------------------------------------

def _atomic_publish(directory: Path, lane: str, name: str, body: str) -> Path:
    """Write ``body`` into ``staging/`` and reveal it in ``lane/`` with a single `os.replace`.

    Shared by packets and signals so both lanes get the same durability guarantee from the same
    code — a reader of either lane sees a whole file or no file, never a partial one.

    Containment is checked and THEN the write and the rename happen, so performing both by path
    would let a lane swapped for a symlink in that window send them outside the inbox. Both
    directories are held open with `O_NOFOLLOW | O_DIRECTORY` for the whole operation instead, and
    the create and the rename are addressed relative to those descriptors — a later swap of either
    path cannot redirect an operation that no longer names a path. The containment assertion stays:
    it rejects a hostile NAME, which is a different attack from a hostile directory. The free-name
    choice is made against the destination's descriptor too, so the name that is picked is the name
    the rename actually uses.

    The whole write — the exclusive create of the staging name, the drained write, the ``fsync``, the
    reveal, AND the removal of the staging entry on any failure in between — is one call into
    :func:`twoperson._safefs.replace_regular`, given the destination lane's descriptor instead of its
    own. That is deliberate rather than tidy: every one of those steps can fail, a short write and a
    failed replace leave the staging name behind if they do, and `O_EXCL` makes a leftover fatal to
    every retry of the same packet. A caller that had to remember the cleanup would get it right
    until the first step nobody thought of; the primitive cannot forget it.

    The create is ``O_EXCL | O_NOFOLLOW``, so an attacker can neither pre-create the staging name as
    a symlink nor write through a name already there — and a stale one (a publish killed between the
    create and the reveal) is cleared by the primitive rather than blocking this packet forever.
    """
    _assert_inside(directory, directory / "staging" / name)
    with _publish_lock(directory):
        staging_fd = _lane_dir_fd(directory, "staging")
        try:
            lane_fd = _lane_dir_fd(directory, lane)
            try:
                # The name is chosen against the DESTINATION's descriptor, then the write is told to
                # reveal at exactly that name — so the name that was picked is the name that is used.
                final = _safefs.free_name(lane_fd, name)
                _safefs.stage_and_reveal(staging_fd, name, body.encode("utf-8"),
                                         dst_dir_fd=lane_fd, dst_name=final,
                                         what=f"the staging entry {_safe_name(name)!r}")
            finally:
                _safefs.close_quietly(lane_fd)
        finally:
            _safefs.close_quietly(staging_fd)
    return directory / lane / final


def publish(packet: Mapping[str, Any], *, root: Path | str | None = None) -> Path:
    """Validate ``packet`` and atomically publish it to ``pending/``. Returns the published path.

    Validation happens BEFORE the tree is touched, so a rejected packet leaves no trace on disk.
    """
    validated = validate_packet(packet)
    assert_review_ref_resolves(validated, root=root)
    directory = _ensure_tree(inbox_root(root))
    name = f"{_stamp(validated['created_at'])}-{validated['packet_id']}.json"
    target = _atomic_publish(directory, "pending", name, dumps_packet(validated))
    log.info("twoperson.published", packet_id=validated["packet_id"], path=str(target))
    return target


#: Lanes a verdict may bind to. `pending/` covers a reviewer who reads the file directly instead of
#: claiming it; `audited/` covers a second opinion on an already-reviewed packet. `rejected/` is
#: deliberately absent: a quarantined packet was never a valid review target.
_PACKET_LANES = ("claimed", "pending", "audited")


def find_packet(packet_id: str, root: Path | str | None = None) -> tuple[str, Path, dict] | None:
    """Locate the packet with ``packet_id`` in this inbox: ``(lane, path, packet)`` or ``None``.

    This is what makes a verdict *about something*. Without it, `verdict --packet anything` would
    happily record an approval for a packet that was never published, and `verdicts --ack` would
    print "ship gate OPEN" for it. Files that fail to load are skipped, never raised on — a corrupt
    neighbour must not stop a real packet from being found.
    """
    for lane in _PACKET_LANES:
        for path in _lane_files(root, lane):
            try:
                packet = _load(path)
            except LaneUnreadable:
                # Per-FILE tolerance must not become per-LANE tolerance. "Skip a file I cannot
                # parse" is safe; "answer None because a lane refused me" makes this function state
                # that a packet nobody can see does not exist — and its answer is what makes a
                # verdict *about something*, so a silent None here is a verdict bound to nothing.
                raise
            except (PacketError, FileNotFoundError):
                continue
            if packet["packet_id"] == packet_id:
                return lane, path, packet
    return None


def _all_verdicts(root: Path | str | None) -> list[dict]:
    """Every loadable verdict in ``verdicts/`` and ``verdicts_seen/``. Best-effort, oldest first."""
    out: list[dict] = []
    for lane in ("verdicts", "verdicts_seen"):
        for path in _lane_files(root, lane):
            try:
                if _lane_entry_size(path) > MAX_VERDICT_BYTES:
                    continue
                out.append(loads_verdict(_read_lane_file(path)))
            except LaneUnreadable:
                # Same line as `find_packet`: the consumer here is `assert_review_ref_resolves`,
                # which answers "no verdict by that id exists" — under-reporting a SHIP GATE. A lane
                # that refused must decline to answer, never answer short.
                raise
            except (PacketError, FileNotFoundError):
                continue
    return out


def assert_review_ref_resolves(packet: Mapping[str, Any], *, root: Path | str | None = None) -> None:
    """A packet reporting a shipped side effect must cite a real, approving verdict for the SAME head.

    "Shipped" is any of ``pushed``, ``deployed`` or ``restarted`` — a deploy without a push is still
    a change that reached the world. The schema alone can only insist the field is not ``unknown``;
    any string would pass. Here the reference is resolved against the inbox: it must be the
    ``verdict_id`` of a verdict that exists, whose decision unlocks a ship, and whose ``head_sha``
    equals this packet's ``git.head_sha``. Raises :class:`PacketError` otherwise. A packet that
    shipped nothing is not checked at all.

    On top of that binding, a packet whose ``changed_files`` modifies, deletes, or renames anything
    `twoperson.testset` considers a test file must cite a verdict whose `acknowledged_tests` is a
    SUPERSET of those altered paths (see `build_verdict`/``--ack-test-changes``) — otherwise a
    builder under deadline pressure could get a weakened test quietly approved by a reviewer who
    never looked at the test diff at all. The check is content-bound on purpose: `acknowledged_tests`
    names the exact paths the reviewer acknowledged, so a verdict written for one packet's test
    changes cannot silently unlock a DIFFERENT ship report's different test changes at the same
    head — `changed_files` is self-reported per packet, and a bare boolean acknowledgment could be
    replayed across reports.

    This function reasons over whatever `changed_files` the packet ARRIVES with, self-reported or
    derived — it has no way to tell the two apart, and that is deliberate: it is also the function
    every synthetic-sha test in this suite calls directly, with a `changed_files` that was never put
    through `twoperson.gitfacts` at all. The property that a CLAIMED (underived) diff can never be
    the basis for a ship is enforced one layer up, at the CLI (`twoperson.__main__._dispatch`),
    which is the one caller that knows whether `--no-derive` was used and can refuse before this
    function — and `inbox.publish` — are ever reached. See docs/PROTOCOL.md §2a.
    """
    push = packet["push_status"]
    if not (push["pushed"] or push["deployed"] or push["restarted"]):
        return
    ref = push["review_ref"]
    head = packet["git"]["head_sha"]
    match = next((v for v in _all_verdicts(root) if v["verdict_id"] == ref), None)
    if match is None:
        raise PacketError(
            f"push_status.review_ref: {ref!r} is not the id of any verdict in this inbox — a push "
            "may only cite a verdict the reviewer actually recorded"
        )
    if not unlocks_ship(match):
        raise PacketError(
            f"push_status.review_ref: verdict {ref!r} is {match['decision']!r}, which does not "
            "unlock a ship"
        )
    if match["head_sha"] != head:
        raise PacketError(
            f"push_status.review_ref: verdict {ref!r} approved head {match['head_sha']!r}, but this "
            f"packet shipped {head!r} — an approval does not carry over to a different commit"
        )
    altered = altered_test_files(packet["changed_files"])
    if altered:
        acked = set(match.get("acknowledged_tests", ()))
        missing = [p for p in altered if p not in acked]
        if missing:
            raise PacketError(
                "push_status.review_ref: packet altered tests (" + ", ".join(missing) + ") that the "
                "approving verdict did not acknowledge — the reviewer must acknowledge these exact test "
                "paths (twoperson verdict --ack-test-changes)"
            )


def publish_signal(signal: Mapping[str, Any], *, root: Path | str | None = None) -> Path:
    """Validate ``signal`` and atomically publish it to ``signals/``. Returns the published path.

    A signal is **not** a packet and never lands in `pending/`: it announces that a session
    finished, and the audit gate stays the packet. See `src/twoperson/signal.py`.
    """
    validated = validate_signal(signal)
    directory = _ensure_tree(inbox_root(root))
    # `signal_id` already opens with its own UTC stamp, so it sorts chronologically on its own and
    # needs no prefix. It is slug-validated, so it is safe as a filename.
    name = f"{validated['signal_id']}.json"
    target = _atomic_publish(directory, "signals", name, dumps_signal(validated))
    log.info("twoperson.signalled", signal_id=validated["signal_id"], path=str(target),
             packet_pending=validated["packet_pending"])
    return target


def publish_verdict(verdict: Mapping[str, Any], *, root: Path | str | None = None) -> Path:
    """Validate ``verdict`` and atomically publish it to ``verdicts/``. Returns the published path.

    This is the **return leg** of the bridge: Reviewer writes an audited decision back into the same
    inbox, so Builder's manager reads it with `read_verdicts` instead of out of a chat window. A
    verdict never enters `pending/` and is never returned by `check`/`next` — it does not become
    work; it reports the outcome of work. The ship gate is unchanged: only an `Approve` /
    `Approve with nits` decision for a still-current head unlocks a push, and the manager checks
    that head itself.

    A verdict's `acknowledged_tests` is also bound at write time: every path it names must be one
    `twoperson.testset.altered_test_files` derives from the REVIEWED packet's own `changed_files`
    (`--ack-test-changes` already does this; this is what makes it structural rather than a CLI
    convention). Without this, an API caller could mint a verdict acknowledging arbitrary test
    paths that were never in the reviewed packet, and a later ship report could cite that verdict
    to unlock tests nobody actually reviewed — the content-binding in `assert_review_ref_resolves`
    only checks that the acknowledgment is a superset of what the *ship report* altered, not that
    it was honestly derived from what the *reviewed packet* altered.
    """
    validated = validate_verdict(verdict)
    # Bind the verdict to a packet that exists in THIS inbox. A verdict is a statement about a
    # specific review request; one that names a packet nobody published is not a review, and an
    # approving one would still read as "ship gate OPEN" to the builder.
    found = find_packet(validated["packet_id"], root)
    if found is None:
        raise PacketError(
            f"packet_id: no packet {validated['packet_id']!r} in this inbox (pending, claimed or "
            "audited) — a verdict must answer a published packet; run `next` to claim one"
        )
    _, _, packet = found
    if validated["decision"] in SHIP_DECISIONS and validated["head_sha"] != packet["git"]["head_sha"]:
        raise PacketError(
            f"head_sha: {validated['decision']!r} names {validated['head_sha']!r} but packet "
            f"{validated['packet_id']!r} is at {packet['git']['head_sha']!r} — an approval binds to "
            "the packet's own head"
        )
    acked = validated.get("acknowledged_tests")
    if acked:
        altered = set(altered_test_files(packet["changed_files"]))
        stray = [p for p in acked if p not in altered]
        if stray:
            raise PacketError(
                "acknowledged_tests: verdict acknowledges tests (" + ", ".join(stray) + ") that packet "
                f"{validated['packet_id']!r} does not alter — a verdict may only acknowledge the test "
                "changes in the packet it reviews (`--ack-test-changes` derives them), so an "
                "acknowledgment cannot be minted for arbitrary paths and replayed onto another report"
            )
    body = dumps_verdict(validated)
    # Guard the serialized size at WRITE time, not only on read. A verdict whose fields each pass but
    # whose JSON total exceeds the cap (e.g. 64 findings at the length limit) would otherwise land in
    # the lane and be quarantined only when someone reads it — reject it here so the return lane never
    # holds a file its own reader will refuse.
    if len(body.encode("utf-8")) > MAX_VERDICT_BYTES:
        raise PacketError(
            f"verdict: serialized size {len(body.encode('utf-8'))} exceeds the "
            f"{MAX_VERDICT_BYTES}-byte limit"
        )
    directory = _ensure_tree(inbox_root(root))
    name = f"{validated['verdict_id']}.json"
    target = _atomic_publish(directory, "verdicts", name, body)
    log.info("twoperson.verdict", verdict_id=validated["verdict_id"], path=str(target),
             packet_id=validated["packet_id"], decision=validated["decision"])
    return target


def publish_consult(consult: Mapping[str, Any], *, root: Path | str | None = None) -> Path:
    """Validate ``consult`` and atomically publish it to ``consult/``. Returns the published path.

    A consult is **not** a packet and never lands in `pending/`: it asks Reviewer to *advise*, not to
    *audit*, so `check`/`next` never surface it and answering it unlocks nothing. The audit gate is
    the packet, unchanged. See `src/twoperson/consult.py`.
    """
    validated = validate_consult(consult)
    directory = _ensure_tree(inbox_root(root))
    # `consult_id` opens with its own UTC stamp, so it sorts chronologically on its own; it is
    # short-validated, so it is safe as a filename component.
    name = f"{validated['consult_id']}.json"
    target = _atomic_publish(directory, "consult", name, dumps_consult(validated))
    log.info("twoperson.consult", consult_id=validated["consult_id"], path=str(target),
             area=validated["area"])
    return target


def publish_advice(advice: Mapping[str, Any], *, root: Path | str | None = None) -> Path:
    """Validate ``advice`` and atomically publish it to ``advice/``. Returns the published path.

    This is the **return leg** of the advisory bridge: Reviewer writes counsel back into the same inbox,
    so the manager reads it with `read_advice` instead of out of a chat window. Advice never enters
    `pending/` and is never returned by `check`/`next` — and, unlike a verdict, it can never unlock a
    ship, because advice gates nothing.
    """
    validated = validate_advice(advice)
    body = dumps_advice(validated)
    # Guard the serialized size at WRITE time, not only on read: an advice whose fields each pass but
    # whose JSON total exceeds the cap must be refused here, so the return lane never holds a file its
    # own reader will quarantine.
    if len(body.encode("utf-8")) > MAX_ADVICE_BYTES:
        raise PacketError(
            f"advice: serialized size {len(body.encode('utf-8'))} exceeds the "
            f"{MAX_ADVICE_BYTES}-byte limit"
        )
    directory = _ensure_tree(inbox_root(root))
    name = f"{validated['advice_id']}.json"
    target = _atomic_publish(directory, "advice", name, body)
    log.info("twoperson.advice", advice_id=validated["advice_id"], path=str(target),
             consult_id=validated["consult_id"], confidence=validated["confidence"])
    return target


# --------------------------------------------------------------------------------------------
# Detect / claim
# --------------------------------------------------------------------------------------------

def _lane_scan(root: Path | str | None, lane: str) -> LaneScan:
    """List one lane, oldest first, and REPORT what was refused instead of discarding it.

    Only regular, non-hidden `.json` files count. Symlinks and directories are never followed — a
    hand-dropped symlink must not let a reader walk the inbox out to another file. But a refusal is
    recorded, not silently absorbed: a `.json` entry that is a symlink or is not a regular file, and
    any listing error other than "the lane does not exist yet", clears ``complete``.

    A lane directory that has simply never been created is genuinely, provably empty — `_ensure_tree`
    has not run — so `FileNotFoundError` alone returns a COMPLETE empty scan. Every other `OSError`
    (a permission wall, an I/O error) is a refusal: we do not know what is in there.

    Checking the lane with `lstat` and then RE-OPENING IT BY PATH to list it would be two path
    resolutions with a window between them, which is not a check: swap the lane for a symlink in
    that window and the listing walks outside the inbox while reporting a complete scan, after which
    `claim_next` moves an outside file into `claimed/`. The lane is opened ONCE and every entry is
    stated relative to that open descriptor, so nothing here depends on the path resolving the same
    way twice.

    `O_NOFOLLOW | O_DIRECTORY` also makes the refusal atomic and total in one syscall: a symlinked
    lane cannot be opened at all (ELOOP on Linux, ENOTDIR on macOS), and neither can a lane that is a
    regular file, a FIFO, or anything else that is not a directory. No enumeration of the ways a lane
    can fail to be a directory has to be complete for that to hold.

    The lane is opened relative to the ROOT's descriptor, not by the path `root / lane`. Opening the
    path guards only the lane component: the root above it was still resolved by the kernel, so a
    symlinked root was followed and a listing from outside the inbox came back as a COMPLETE scan of
    this lane — the same "checked something other than what was opened" mistake, one level up.
    """
    directory = inbox_root(root)
    try:
        fd = _lane_dir_fd(directory, lane)
    except FileNotFoundError:
        return LaneScan(files=(), refused=(), complete=True)   # never created: provably empty
    except PacketError as exc:
        # This function is the layer whose JOB is to report a refusal rather than raise one, so it
        # catches the refusal `_lane_dir_fd` now raises and turns it back into an incomplete scan.
        # Catching only `OSError` here would let `LaneUnreadable` — which is a `PacketError`, not an
        # `OSError` — sail past this handler and out of every caller that reads a scan instead of a
        # lane, turning the one lane that must stay tolerant (`signals/`) into a raising one.
        return LaneScan(files=(), refused=(f"<{exc}>",), complete=False)

    files: list[Path] = []
    refused: list[str] = []
    try:
        try:
            names = _safefs.list_names(fd, what=f"the lane {lane!r}")
        except PacketError as exc:
            return LaneScan(files=(), refused=(f"<{exc}>",), complete=False)
        for name in names:
            if not name.endswith(".json") or name.startswith("."):
                continue
            # Stated against the open lane, not against a path that could now mean something else.
            # `follow_symlinks=False` reports the LINK, so `S_ISREG` is false for a symlink, a
            # directory, a FIFO or a device in a single answer.
            try:
                entry_stat = _safefs.stat_nolink(fd, name, what=_entry_what(lane, name))
            except PacketError as exc:
                # One entry we cannot interrogate costs the WHOLE lane, and says so. The tempting
                # alternative — skip the entry and report the rest as a complete scan — is "we do not
                # know" spelled as a clean list, which is the one answer `complete` exists to keep
                # out of this function. `stat_nolink` used to answer `None` (i.e. "free") for a
                # `PermissionError` and to let an `EIO` out raw, so this call had no refusal to
                # catch and a single bad entry took down the caller's whole pass instead.
                return LaneScan(files=(), refused=(f"<{exc}>",), complete=False)
            if entry_stat is None or not _stat.S_ISREG(entry_stat.st_mode):
                refused.append(name)
                continue
            files.append(directory / lane / name)
    finally:
        _safefs.close_quietly(fd)
    return LaneScan(files=tuple(sorted(files)), refused=tuple(refused), complete=not refused)


def _lane_files(root: Path | str | None, lane: str) -> list[Path]:
    """Readable `.json` files in one lane, oldest first — FAILING CLOSED on an incomplete listing.

    This is the safe default and what nearly every caller wants: if the lane could not be read in
    full, you are told, rather than handed an empty list you cannot distinguish from an empty lane.
    A caller that must stay live in the presence of a hostile drop calls `_lane_scan` directly and
    decides for itself — and, because it is opting out of the guard, must say in its own docstring
    which direction it is choosing to be wrong in.

    :raises LaneUnreadable: the lane exists but could not be listed completely.
    """
    scan = _lane_scan(root, lane)
    if not scan.complete:
        log.warning("twoperson.lane_unreadable", lane=lane, refused=list(scan.refused))
        raise LaneUnreadable(scan.reason(lane))
    return list(scan.files)


def pending(root: Path | str | None = None) -> list[Path]:
    """Publishable packet files awaiting audit, oldest first."""
    return _lane_files(root, "pending")


def has_pending(root: Path | str | None = None) -> bool:
    """Cheap event probe: is there work waiting? No parsing, no model call, no tokens."""
    return bool(pending(root))


def _load(path: Path) -> dict:
    """Read + validate one pending file, size-guarded before any parse."""
    size = _lane_entry_size(path)
    if size > MAX_PACKET_BYTES:
        raise PacketError(f"packet: size {size} exceeds the {MAX_PACKET_BYTES}-byte limit")
    return loads_packet(_read_lane_file(path))


def quarantine(path: Path, reason: str, *, root: Path | str | None = None,
               lane: str = "pending") -> Path:
    """Move a bad entry out of ``lane`` into ``rejected/`` and record why beside it.

    Returns the new path. ``lane`` is the lane the caller listed the entry from and defaults to the
    packet lane, which is the only one that quarantines on its own; the consult lane passes its own
    name rather than having it read back out of ``path`` (see `_lane_member` for why a caller's
    inbox is never inferred from a path). The reason file is written to ``rejected/`` of that same
    explicit root, by name, so both halves of the quarantine are anchored to one inbox.
    """
    directory = _ensure_tree(inbox_root(root))
    target = _move_lane_entry(path, root=directory, src_lane=lane, dst_lane="rejected")
    _write_lane_file(
        directory, "rejected", f"{target.stem}.reason.txt",
        f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}\n{reason}\n".encode("utf-8"),
    )
    log.warning("twoperson.quarantined", path=str(target), reason=reason)
    return target


def _next(root: Path | str | None, *, claim: bool) -> Claimed | None:
    """Shared walk for `peek_next`/`claim_next`: skip and quarantine bad files, return the first
    good one. Returns None when the inbox holds nothing auditable."""
    directory = inbox_root(root)
    for path in pending(directory):
        try:
            packet = _load(path)
        except LaneUnreadable:
            # `_load` reads through the descriptor chain, so a lane refused mid-read arrives as a
            # `LaneUnreadable` — which IS a `PacketError`. Without this branch the handler below
            # would catch it and QUARANTINE a good packet because the lane it sat in could not be
            # opened: a refusal turned into a verdict on the packet. Re-raised, the packet stays
            # where it is and the operator gets the refusal.
            raise
        except PacketError as exc:
            quarantine(path, str(exc), root=directory)
            continue
        except FileNotFoundError:  # vanished between listing and load — nothing to audit
            continue
        if not claim:
            return Claimed(path=path, packet=packet)
        _ensure_tree(directory)
        try:
            target = _move_lane_entry(path, root=directory, src_lane="pending", dst_lane="claimed")
        except FileNotFoundError:
            continue  # another auditor claimed it first; there is no duplicate to hand back
        # Only "the source is already gone" is absorbed above. A lane that cannot be OPENED is a
        # different answer entirely, and letting it through as "nothing to claim" is the same
        # refusal-read-as-absence mistake the lane listing fails closed to avoid.
        log.info("twoperson.claimed", packet_id=packet["packet_id"], path=str(target))
        return Claimed(path=target, packet=packet)
    return None


def peek_next(root: Path | str | None = None) -> Claimed | None:
    """The oldest auditable packet, left in ``pending/``."""
    return _next(root, claim=False)


def claim_next(root: Path | str | None = None) -> Claimed | None:
    """Take the oldest auditable packet, moving it to ``claimed/``. Exclusive across processes."""
    return _next(root, claim=True)


def claimed(root: Path | str | None = None) -> list[Path]:
    """Packets currently in ``claimed/`` — mid-review, or orphaned by an auditor that crashed after
    `claim_next` but before it produced a verdict — oldest first. This is the read side of the
    claim/writeback durability gap `twoperson.reviewer` closes: pair with `requeue_claimed`."""
    return _lane_files(root, "claimed")


def requeue_claimed(path: Path, *, root: Path | str | None = None) -> Path:
    """Move a claimed packet back to ``pending/`` — the self-heal for a crash between claim and
    writeback. Symmetric to `quarantine` (which moves a BAD packet pending->rejected): this moves a
    GOOD packet claimed->pending, so a packet an auditor claimed and then failed to review (a `reviewer
    exec` error, a process crash, a malformed reply it could not parse) becomes auditable again on
    the next tick INSTEAD of sitting lost in `claimed/` forever with no verdict ever written.

    Exclusive via `os.rename`: if another process already requeued or re-claimed this exact path, the
    rename raises `FileNotFoundError` — the caller should treat that as "someone else already
    recovered it", not as a failure to surface, exactly like a lost `claim_next` race is not an
    error. A lane that cannot be opened raises instead: that is a refusal, not a lost race. A source
    that is not an entry of ``root/claimed`` is refused too, and nothing is moved: the inbox named
    here is the only one whose lanes this call may touch."""
    directory = _ensure_tree(inbox_root(root))
    target = _move_lane_entry(path, root=directory, src_lane="claimed", dst_lane="pending")
    log.warning("twoperson.requeued", path=str(target))
    return target


def archived(root: Path | str | None = None) -> list[Path]:
    """Packets in ``audited/`` — successfully reviewed, verdict already published — oldest first.
    Pair with `archive_claimed`."""
    return _lane_files(root, "audited")


def archive_claimed(path: Path, *, root: Path | str | None = None) -> Path:
    """Move a claimed packet to ``audited/`` — the terminal move for a SUCCESSFUL review, once its
    verdict is already durably published. This is what keeps `claimed/` meaning "unresolved": the
    stale-claim sweep (`twoperson.reviewer.recovery`) requeues anything left in `claimed/` past a lease
    timeout, so a completed review that stayed behind would eventually be mistaken for an orphan and
    audited again for no reason. Best-effort by design — call this AFTER `publish_verdict` succeeds;
    if archiving itself fails, the verdict (the actual audit record) is already safe, so a caller
    should log and move on rather than treat it as a review failure.

    The archive lands in the inbox the caller names, not in whatever inbox the claimed path happens
    to sit in: a source that is not an entry of ``root/claimed`` is refused (`PacketError`) and
    nothing is moved."""
    directory = _ensure_tree(inbox_root(root))
    target = _move_lane_entry(path, root=directory, src_lane="claimed", dst_lane="audited")
    log.info("twoperson.archived", path=str(target))
    return target


# --------------------------------------------------------------------------------------------
# Signals — the wake-up lane
# --------------------------------------------------------------------------------------------

def pending_signals(root: Path | str | None = None) -> list[Path]:
    """Unacknowledged completion-signal files, oldest first — TOLERANT of a refused entry.

    This lane deliberately opts out of `_lane_files`' fail-closed listing, and the reason is the
    line between the two behaviours: **a packet gates a ship; a signal gates nothing.** A signal only
    reports that a session stopped — it satisfies no audit, unlocks no push, and the protocol is
    explicit that it is not the packet. Refusing to serve the lane because someone dropped a symlink
    in it would convert a nuisance into an outage of the whole event-driven wake-up, and would do so
    to protect a decision that is not being made here.

    The direction this chooses to be wrong in: **under-report**. A refused entry is skipped and
    logged, so at worst Reviewer is not woken by *this* signal and is woken by the next one or by its
    poll. Nothing is admitted, and no absence here is ever read as evidence.
    """
    scan = _lane_scan(root, "signals")
    if not scan.complete:
        log.warning("twoperson.signal_scan_incomplete", lane="signals", refused=list(scan.refused))
    return list(scan.files)


def has_pending_signals(root: Path | str | None = None) -> bool:
    """Cheap event probe for the signal lane: did a session finish since we last looked?"""
    return bool(pending_signals(root))


def read_signals(root: Path | str | None = None) -> list[tuple[Path, dict]]:
    """Validated signals awaiting acknowledgement, oldest first.

    A signal that is oversize, unparseable, or schema-invalid is quarantined exactly like a bad
    packet — the wake-up lane is written by a hook and read by an auditor, so it gets the same
    "quarantine, don't return" rule and never hands hostile bytes to the reader.
    """
    directory = inbox_root(root)
    out: list[tuple[Path, dict]] = []
    for path in pending_signals(directory):
        try:
            size = _lane_entry_size(path)
            if size > MAX_SIGNAL_BYTES:
                raise PacketError(f"signal: size {size} exceeds the {MAX_SIGNAL_BYTES}-byte limit")
            out.append((path, loads_signal(_read_lane_file(path))))
        except LaneUnreadable:
            raise       # a refused lane is not a bad file: never quarantine over it (see `_next`)
        except PacketError as exc:
            quarantine(path, str(exc), root=directory, lane="signals")
        except FileNotFoundError:  # vanished between listing and load — nothing to report
            continue
    return out


def ack_signals(paths: Iterable[Path] | None = None, *, root: Path | str | None = None) -> list[Path]:
    """Move signals to ``signals_seen/``. Returns the paths acknowledged.

    Pass the exact ``paths`` that were read (`read_signals`) and only those are acked — a signal that
    arrives between the read and the ack is then never swept out of the waiting lane **unseen**. With
    ``paths=None`` it falls back to acking everything currently pending, which is only safe when no
    unread signal can be arriving concurrently.

    Acknowledging is `os.rename`, so two auditors acking at once each move a disjoint set and a
    signal is never delivered twice. It is bookkeeping only — it grants nothing and audits nothing;
    the packet remains the unit of review. Paths outside this inbox's ``signals/`` lane are ignored.

    Backward compatibility: the legacy signature was ``ack_signals(root=None)``, so a caller passing
    a root **positionally** — ``ack_signals(some_root)`` — must keep meaning "ack everything in that
    root", not be misread as an iterable of paths (a ``Path`` is not iterable → TypeError; a ``str``
    would iterate character-by-character). A ``str``/``Path`` first positional is therefore treated
    as ``root``.
    """
    if isinstance(paths, (str, Path)):
        if root is not None:
            raise TypeError("ack_signals: give the root positionally or as root=, not both")
        root, paths = paths, None
    directory = _ensure_tree(inbox_root(root))
    candidates = pending_signals(directory) if paths is None else [Path(p) for p in paths]
    acked: list[Path] = []
    for path in candidates:
        try:
            # The same rule the move itself enforces (`_lane_member`), so what this skips and what
            # the move would refuse are one answer rather than two. It replaced a `.resolve()`
            # comparison, which asked where the path POINTS — resolving the lane and following a
            # symlink out of the inbox to decide whether to touch it, the exact re-resolution the
            # descriptor chain exists to remove.
            _lane_member(directory, "signals", path)
        except PacketError:
            continue  # only ack a file that is actually a signal in THIS inbox's signals/ lane
        try:
            target = _move_lane_entry(path, root=directory, src_lane="signals",
                                      dst_lane="signals_seen")
        except FileNotFoundError:
            continue  # another auditor took it first, or it vanished — nothing to hand back
        acked.append(target)
    if acked:
        log.info("twoperson.signals_acked", count=len(acked))
    return acked


# --------------------------------------------------------------------------------------------
# Verdicts — the return lane (Reviewer -> Builder)
# --------------------------------------------------------------------------------------------

def pending_verdicts(root: Path | str | None = None) -> list[Path]:
    """Unacknowledged audit-verdict files, oldest first."""
    return _lane_files(root, "verdicts")


def has_pending_verdicts(root: Path | str | None = None) -> bool:
    """Cheap event probe for the return lane: has Reviewer answered since we last looked?"""
    return bool(pending_verdicts(root))


def read_verdicts(root: Path | str | None = None) -> list[tuple[Path, dict]]:
    """Validated verdicts awaiting acknowledgement, oldest first.

    A verdict that is oversize, unparseable, or schema-invalid is quarantined exactly like a bad
    packet — the return lane is written by the *other* agent, so it gets the same "quarantine,
    don't return" rule and never hands hostile bytes to the reader.
    """
    directory = inbox_root(root)
    out: list[tuple[Path, dict]] = []
    for path in pending_verdicts(directory):
        try:
            size = _lane_entry_size(path)
            if size > MAX_VERDICT_BYTES:
                raise PacketError(f"verdict: size {size} exceeds the {MAX_VERDICT_BYTES}-byte limit")
            out.append((path, loads_verdict(_read_lane_file(path))))
        except LaneUnreadable:
            raise       # a refused lane is not a bad file: never quarantine over it (see `_next`)
        except PacketError as exc:
            quarantine(path, str(exc), root=directory, lane="verdicts")
        except FileNotFoundError:  # vanished between listing and load — nothing to report
            continue
    return out


def ack_verdicts(paths: Iterable[Path], *, root: Path | str | None = None) -> list[Path]:
    """Move exactly the given verdict ``paths`` to ``verdicts_seen/``. Returns the paths acknowledged.

    Acknowledging **only what was read** is the whole contract: a caller reads with `read_verdicts`,
    acts on that set, then acks *that* set. Re-scanning the lane here would sweep any verdict that
    arrived between the read and the ack out of sight **unseen** — a returned audit result silently
    lost. So this takes the paths explicitly; it never re-lists `pending_verdicts`.

    Acknowledging is `os.rename`, so two readers acking at once each move a disjoint set and a
    verdict is never delivered twice. It is bookkeeping only — it grants nothing; the manager still
    checks the head and the decision before it ships. Paths outside the inbox, or already gone, are
    skipped rather than raised on.

    ``paths`` is a required iterable of verdict paths — there is no legacy root-positional form on
    this (new) lane. A ``str``/``Path`` passed here is a caller mistake (a ``str`` would silently
    iterate character-by-character, a ``Path`` would raise deep in the loop), so it is rejected
    loudly up front — the sibling-bug-class guard to ``ack_signals``'s legacy shim.
    """
    if isinstance(paths, (str, Path)):
        raise TypeError("ack_verdicts: paths must be an iterable of verdict paths, not a single path/str")
    directory = _ensure_tree(inbox_root(root))
    acked: list[Path] = []
    for path in paths:
        path = Path(path)
        try:
            # One containment rule for the skip and the move: see `ack_signals` for why the
            # `.resolve()` comparison this replaced was the wrong question (it follows the link).
            _lane_member(directory, "verdicts", path)
        except PacketError:
            continue  # only ack a file that is actually a verdict in THIS inbox's verdicts/ lane
        try:
            target = _move_lane_entry(path, root=directory, src_lane="verdicts",
                                      dst_lane="verdicts_seen")
        except FileNotFoundError:
            continue  # another reader took it first, or it vanished — nothing to hand back
        acked.append(target)
    if acked:
        log.info("twoperson.verdicts_acked", count=len(acked))
    return acked


def verdicted_packet_ids(root: Path | str | None = None) -> frozenset[str]:
    """Every ``packet_id`` that already has a durable verdict recorded — scanning BOTH ``verdicts/``
    (not yet acknowledged by the manager) and ``verdicts_seen/`` (already acknowledged), because a
    packet is RESOLVED the moment its own verdict exists, independent of whether the manager has
    gotten around to reading/acking it. This is the reconciliation primitive
    `twoperson.reviewer.recovery.sweep_stale_claims` needs: a packet sitting in `claimed/` past the stale
    threshold might be genuinely orphaned (no verdict anywhere — a crash victim) OR might already be
    fully resolved but never archived (a pre-existing backlog, or a verdict written by the legacy
    Mac-side watcher's `handoff verdict` CLI call, which predates `archive_claimed` and does not call
    it) — those two cases must never be treated the same way; blindly requeuing the second case would
    silently duplicate an already-shipped review.

    Best-effort at the FILE level: a verdict file that is oversize, unparseable, or otherwise corrupt
    is skipped rather than raised — one bad file must never abort the scan.

    That per-FILE tolerance does NOT extend to the LANE, because under-reporting is not the safe
    direction here. The consumer is a stale-claim sweep that treats an id missing from this set as
    UNRESOLVED and requeues the claim, so a short set does not fail harmlessly toward requeuing — it
    re-audits a packet whose durable verdict already exists, breaking at-most-once. "Skip a file we
    cannot parse" and "cannot see the lane at all" are different sizes of doubt, and only the first
    one is safe to absorb.

    So the lane listing goes through `_lane_files` and fails closed like every other gating reader.
    A caller that cannot get an answer must decline to act, not act on a set it knows is short.

    :raises LaneUnreadable: a verdict lane could not be listed completely.
    """
    directory = inbox_root(root)
    ids: set[str] = set()
    for path in _lane_files(directory, "verdicts") + _lane_files(directory, "verdicts_seen"):
        try:
            size = _lane_entry_size(path)
            if size > MAX_VERDICT_BYTES:
                continue
            verdict = loads_verdict(_read_lane_file(path))
        except LaneUnreadable:
            raise       # a refused lane must not shrink this set: short reads back as "unresolved"
        except (PacketError, FileNotFoundError):
            continue
        packet_id = verdict.get("packet_id")
        if isinstance(packet_id, str) and packet_id:
            ids.add(packet_id)
    return frozenset(ids)


# --------------------------------------------------------------------------------------------
# Consults — the advisory request lane (Builder -> Reviewer), claimed like a packet
# --------------------------------------------------------------------------------------------

def pending_consults(root: Path | str | None = None) -> list[Path]:
    """Advisory-question files awaiting Reviewer's counsel, oldest first."""
    return _lane_files(root, "consult")


def has_pending_consults(root: Path | str | None = None) -> bool:
    """Cheap event probe for the advisory lane: is there a question waiting? No parse, no tokens."""
    return bool(pending_consults(root))


def _load_consult(path: Path) -> dict:
    """Read + validate one pending consult, size-guarded before any parse."""
    size = _lane_entry_size(path)
    if size > MAX_CONSULT_BYTES:
        raise PacketError(f"consult: size {size} exceeds the {MAX_CONSULT_BYTES}-byte limit")
    return loads_consult(_read_lane_file(path))


def _next_consult(root: Path | str | None, *, claim: bool) -> Claimed | None:
    """Shared walk for `peek_consult`/`claim_consult`: skip and quarantine bad files, return the
    first good one. Claiming is exclusive (`os.rename` out of `consult/`), so a consult is answered
    at most once — the same guarantee a packet gets, for the same reason."""
    directory = inbox_root(root)
    for path in pending_consults(directory):
        try:
            consult = _load_consult(path)
        except LaneUnreadable:
            raise       # a refused lane is not a bad file: never quarantine over it (see `_next`)
        except PacketError as exc:
            quarantine(path, str(exc), root=directory, lane="consult")
            continue
        except FileNotFoundError:  # vanished between listing and load — nothing to answer
            continue
        if not claim:
            return Claimed(path=path, packet=consult)
        _ensure_tree(directory)
        try:
            target = _move_lane_entry(path, root=directory, src_lane="consult",
                                      dst_lane="consult_claimed")
        except FileNotFoundError:
            continue  # another auditor claimed it first; there is no duplicate to hand back
        log.info("twoperson.consult_claimed", consult_id=consult["consult_id"], path=str(target))
        return Claimed(path=target, packet=consult)
    return None


def peek_consult(root: Path | str | None = None) -> Claimed | None:
    """The oldest answerable consult, left in ``consult/``. ``.packet`` holds the validated consult."""
    return _next_consult(root, claim=False)


def claim_consult(root: Path | str | None = None) -> Claimed | None:
    """Take the oldest answerable consult, moving it to ``consult_claimed/``. Exclusive across
    processes. ``.packet`` holds the validated consult (the field is reused; a consult is not a
    packet and never gains a packet's ship-gate powers by riding the same envelope)."""
    return _next_consult(root, claim=True)


def claimed_consults(root: Path | str | None = None) -> list[Path]:
    """Consults currently in ``consult_claimed/`` — mid-answer, or orphaned by an advisor that
    crashed after `claim_consult` but before it produced advice — oldest first. The consult-lane
    sibling of `claimed`; pair with `requeue_claimed_consult`."""
    return _lane_files(root, "consult_claimed")


def requeue_claimed_consult(path: Path, *, root: Path | str | None = None) -> Path:
    """Move a claimed consult back to ``consult/`` — the consult-lane sibling of `requeue_claimed`,
    for the same reason: a crash between `claim_consult` and `publish_advice` must not lose the
    question forever. Exclusive via `os.rename`, same race handling as `requeue_claimed` — including
    its refusal of a source that is not an entry of ``root/consult_claimed``."""
    directory = _ensure_tree(inbox_root(root))
    target = _move_lane_entry(path, root=directory, src_lane="consult_claimed", dst_lane="consult")
    log.warning("twoperson.consult_requeued", path=str(target))
    return target


def archived_consults(root: Path | str | None = None) -> list[Path]:
    """Consults in ``consult_answered/`` — successfully answered, advice already published — oldest
    first. The consult-lane sibling of `archived`; pair with `archive_claimed_consult`."""
    return _lane_files(root, "consult_answered")


def archive_claimed_consult(path: Path, *, root: Path | str | None = None) -> Path:
    """Move a claimed consult to ``consult_answered/`` — the consult-lane sibling of
    `archive_claimed`, for the same reason: keeps `consult_claimed/` meaning "unresolved" so the
    stale-claim sweep never mistakes a completed answer for an orphan. Like `archive_claimed`, the
    archive lands in the inbox the caller names; a source outside ``root/consult_claimed`` is
    refused rather than followed."""
    directory = _ensure_tree(inbox_root(root))
    target = _move_lane_entry(path, root=directory, src_lane="consult_claimed",
                              dst_lane="consult_answered")
    log.info("twoperson.consult_archived", path=str(target))
    return target


# --------------------------------------------------------------------------------------------
# Advice — the advisory return lane (Reviewer -> Builder)
# --------------------------------------------------------------------------------------------

def pending_advice(root: Path | str | None = None) -> list[Path]:
    """Unacknowledged advisory-answer files, oldest first."""
    return _lane_files(root, "advice")


def has_pending_advice(root: Path | str | None = None) -> bool:
    """Cheap event probe for the advisory return lane: has Reviewer answered since we last looked?"""
    return bool(pending_advice(root))


def read_advice(root: Path | str | None = None) -> list[tuple[Path, dict]]:
    """Validated advice awaiting acknowledgement, oldest first.

    Advice that is oversize, unparseable, or schema-invalid is quarantined exactly like a bad packet
    — the return lane is written by the *other* agent, so it gets the same "quarantine, don't return"
    rule and never hands hostile bytes to the reader.
    """
    directory = inbox_root(root)
    out: list[tuple[Path, dict]] = []
    for path in pending_advice(directory):
        try:
            size = _lane_entry_size(path)
            if size > MAX_ADVICE_BYTES:
                raise PacketError(f"advice: size {size} exceeds the {MAX_ADVICE_BYTES}-byte limit")
            out.append((path, loads_advice(_read_lane_file(path))))
        except LaneUnreadable:
            raise       # a refused lane is not a bad file: never quarantine over it (see `_next`)
        except PacketError as exc:
            quarantine(path, str(exc), root=directory, lane="advice")
        except FileNotFoundError:  # vanished between listing and load — nothing to report
            continue
    return out


def ack_advice(paths: Iterable[Path], *, root: Path | str | None = None) -> list[Path]:
    """Move exactly the given advice ``paths`` to ``advice_seen/``. Returns the paths acknowledged.

    Acknowledging **only what was read** is the whole contract: a caller reads with `read_advice`,
    acts on that set, then acks *that* set. Re-scanning the lane here would sweep any advice that
    arrived between the read and the ack out of sight **unseen**. So this takes the paths explicitly;
    it never re-lists `pending_advice`. It is bookkeeping only — advice grants nothing to begin with.

    ``paths`` is a required iterable — a ``str``/``Path`` passed here is a caller mistake (a ``str``
    would silently iterate character-by-character, a ``Path`` would raise deep in the loop), so it is
    rejected loudly up front, the sibling guard to `ack_verdicts`.
    """
    if isinstance(paths, (str, Path)):
        raise TypeError("ack_advice: paths must be an iterable of advice paths, not a single path/str")
    directory = _ensure_tree(inbox_root(root))
    acked: list[Path] = []
    for path in paths:
        path = Path(path)
        try:
            # One containment rule for the skip and the move: see `ack_signals`.
            _lane_member(directory, "advice", path)
        except PacketError:
            continue  # only ack a file that is actually an advice in THIS inbox's advice/ lane
        try:
            target = _move_lane_entry(path, root=directory, src_lane="advice",
                                      dst_lane="advice_seen")
        except FileNotFoundError:
            continue  # another reader took it first, or it vanished — nothing to hand back
        acked.append(target)
    if acked:
        log.info("twoperson.advice_acked", count=len(acked))
    return acked


def answered_consult_ids(root: Path | str | None = None) -> frozenset[str]:
    """Every ``consult_id`` that already has durable advice recorded — scanning BOTH ``advice/`` and
    ``advice_seen/``. The consult-lane sibling of `verdicted_packet_ids`, and it fails closed for the
    same reason: its consumer treats a missing id as unresolved, so a lane it could not read in full
    must decline the sweep rather than requeue an already-answered consult.

    :raises LaneUnreadable: an advice lane could not be listed completely."""
    directory = inbox_root(root)
    ids: set[str] = set()
    for path in _lane_files(directory, "advice") + _lane_files(directory, "advice_seen"):
        try:
            size = _lane_entry_size(path)
            if size > MAX_ADVICE_BYTES:
                continue
            advice = loads_advice(_read_lane_file(path))
        except LaneUnreadable:
            raise       # a refused lane must not shrink this set: short reads back as "unanswered"
        except (PacketError, FileNotFoundError):
            continue
        consult_id = advice.get("consult_id")
        if isinstance(consult_id, str) and consult_id:
            ids.add(consult_id)
    return frozenset(ids)
