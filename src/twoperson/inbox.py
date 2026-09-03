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
  timestamp, and every write is asserted to resolve inside the inbox root.
* **Hostile input is quarantined, not returned.** Anything in `pending/` that is oversize,
  unparseable, symlinked, a directory, or schema-invalid is moved to `rejected/` with a reason.

See `docs/PROTOCOL.md` for the runbook.
"""
from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import structlog

from .packet import (
    MAX_PACKET_BYTES,
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
    "MAX_PACKET_BYTES", "Claimed", "ack_advice", "ack_signals", "ack_verdicts", "answered_consult_ids",
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
_DIR_MODE = 0o700
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
        text = marker.read_text(encoding="utf-8", errors="replace")[:_GITFILE_MAX_CHARS]
        prefix, _, raw = text.partition(":")
        if prefix.strip() != "gitdir" or not raw.strip():
            return None
        gitdir = Path(raw.strip())
        if not gitdir.is_absolute():
            gitdir = marker.parent / gitdir
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
    """Create the inbox tree owner-only. `mkdir(mode=...)` is umask-masked, so chmod explicitly."""
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, _DIR_MODE)
    for name in _SUBDIRS:
        directory = root / name
        directory.mkdir(exist_ok=True)
        os.chmod(directory, _DIR_MODE)
    return root


@contextmanager
def _publish_lock(root: Path):
    """Serialise name-selection + rename across processes (the repo's budget-ledger idiom).

    The lock lives on its own file, never on a packet, so an atomic replace can never disturb a
    concurrent locker's open file description.
    """
    handle = open(root / ".lock", "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()


def _assert_inside(root: Path, target: Path) -> Path:
    """Refuse any target that does not resolve inside the inbox root."""
    root_resolved = root.resolve()
    resolved = target.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise PacketError(f"refusing to write outside the inbox root: {target}")
    return target


def _free_name(path: Path) -> Path:
    """``path`` if it is free, else ``<stem>-2``, ``<stem>-3``… — publishing never clobbers."""
    if not path.exists():
        return path
    for suffix in range(2, 1000):
        candidate = path.with_name(f"{path.stem}-{suffix}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise PacketError(f"cannot find a free filename for {path.name}")


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
    """
    staging = _assert_inside(directory, directory / "staging" / name)
    with _publish_lock(directory):
        staging.write_text(body, encoding="utf-8")
        os.chmod(staging, 0o600)
        target = _assert_inside(directory, _free_name(directory / lane / name))
        try:
            os.replace(staging, target)
        except OSError:
            staging.unlink(missing_ok=True)
            raise
    return target


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
            except (PacketError, OSError):
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
                if path.stat().st_size > MAX_VERDICT_BYTES:
                    continue
                out.append(loads_verdict(path.read_bytes()))
            except (PacketError, OSError):
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
    `twoperson.testset` considers a test file must cite a verdict that acknowledged noticing (see
    `build_verdict`/``--ack-test-changes``) — otherwise a builder under deadline pressure could get
    a weakened test quietly approved by a reviewer who never looked at the test diff at all.
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
    if altered and not match.get("acknowledges_test_changes"):
        raise PacketError(
            "push_status.review_ref: packet altered tests (" + ", ".join(altered) + ") but the "
            "approving verdict did not acknowledge the test change (needs "
            "acknowledges_test_changes / --ack-test-changes)"
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

def _lane_files(root: Path | str | None, lane: str) -> list[Path]:
    """Readable `.json` files in one lane, oldest first (names are timestamp-prefixed).

    Only regular, non-hidden `.json` files count. Symlinks and directories are ignored outright —
    a hand-dropped symlink must never let a reader follow the inbox out to another file.
    """
    directory = inbox_root(root) / lane
    try:
        entries = list(directory.iterdir())
    except OSError:
        return []
    return sorted(
        entry for entry in entries
        if entry.suffix == ".json"
        and not entry.name.startswith(".")
        and not entry.is_symlink()
        and entry.is_file()
    )


def pending(root: Path | str | None = None) -> list[Path]:
    """Publishable packet files awaiting audit, oldest first."""
    return _lane_files(root, "pending")


def has_pending(root: Path | str | None = None) -> bool:
    """Cheap event probe: is there work waiting? No parsing, no model call, no tokens."""
    return bool(pending(root))


def _load(path: Path) -> dict:
    """Read + validate one pending file, size-guarded before any parse."""
    size = path.stat().st_size
    if size > MAX_PACKET_BYTES:
        raise PacketError(f"packet: size {size} exceeds the {MAX_PACKET_BYTES}-byte limit")
    return loads_packet(path.read_bytes())


def quarantine(path: Path, reason: str, *, root: Path | str | None = None) -> Path:
    """Move a bad packet to ``rejected/`` and record why beside it. Returns the new path."""
    directory = _ensure_tree(inbox_root(root))
    target = _assert_inside(directory, _free_name(directory / "rejected" / path.name))
    os.rename(path, target)
    target.with_name(f"{target.stem}.reason.txt").write_text(
        f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}\n{reason}\n", encoding="utf-8"
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
        except PacketError as exc:
            quarantine(path, str(exc), root=directory)
            continue
        except OSError:  # vanished or unreadable between listing and load — nothing to audit
            continue
        if not claim:
            return Claimed(path=path, packet=packet)
        _ensure_tree(directory)
        target = _assert_inside(directory, _free_name(directory / "claimed" / path.name))
        try:
            os.rename(path, target)
        except OSError:
            continue  # another auditor claimed it first; there is no duplicate to hand back
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
    rename raises `OSError` — the caller should treat that as "someone else already recovered it",
    not as a failure to surface, exactly like a lost `claim_next` race is not an error."""
    directory = _ensure_tree(inbox_root(root))
    target = _assert_inside(directory, _free_name(directory / "pending" / path.name))
    os.rename(path, target)
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
    should log and move on rather than treat it as a review failure."""
    directory = _ensure_tree(inbox_root(root))
    target = _assert_inside(directory, _free_name(directory / "audited" / path.name))
    os.rename(path, target)
    log.info("twoperson.archived", path=str(target))
    return target


# --------------------------------------------------------------------------------------------
# Signals — the wake-up lane
# --------------------------------------------------------------------------------------------

def pending_signals(root: Path | str | None = None) -> list[Path]:
    """Unacknowledged completion-signal files, oldest first."""
    return _lane_files(root, "signals")


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
            size = path.stat().st_size
            if size > MAX_SIGNAL_BYTES:
                raise PacketError(f"signal: size {size} exceeds the {MAX_SIGNAL_BYTES}-byte limit")
            out.append((path, loads_signal(path.read_bytes())))
        except PacketError as exc:
            quarantine(path, str(exc), root=directory)
        except OSError:  # vanished or unreadable between listing and load — nothing to report
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
    signals_dir = (directory / "signals").resolve()
    candidates = pending_signals(directory) if paths is None else [Path(p) for p in paths]
    acked: list[Path] = []
    for path in candidates:
        if path.resolve().parent != signals_dir:
            continue  # only ack a file that is actually a signal in THIS inbox's signals/ lane
        target = _assert_inside(directory, _free_name(directory / "signals_seen" / path.name))
        try:
            os.rename(path, target)
        except OSError:
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
            size = path.stat().st_size
            if size > MAX_VERDICT_BYTES:
                raise PacketError(f"verdict: size {size} exceeds the {MAX_VERDICT_BYTES}-byte limit")
            out.append((path, loads_verdict(path.read_bytes())))
        except PacketError as exc:
            quarantine(path, str(exc), root=directory)
        except OSError:  # vanished or unreadable between listing and load — nothing to report
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
    verdicts_dir = (directory / "verdicts").resolve()
    acked: list[Path] = []
    for path in paths:
        path = Path(path)
        # Only ack a file that is actually a verdict in THIS inbox's verdicts/ lane.
        if path.resolve().parent != verdicts_dir:
            continue
        target = _assert_inside(directory, _free_name(directory / "verdicts_seen" / path.name))
        try:
            os.rename(path, target)
        except OSError:
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

    Best-effort: a verdict file that is oversize, unparseable, or otherwise corrupt is skipped rather
    than raised — one bad file must never abort the scan, and skipping it only ever makes this
    function UNDER-report (a real packet_id treated as "no verdict found yet"), which biases the
    caller toward requeuing rather than toward silently archiving something never actually verified —
    the safe direction to be wrong in.
    """
    directory = inbox_root(root)
    ids: set[str] = set()
    for path in _lane_files(directory, "verdicts") + _lane_files(directory, "verdicts_seen"):
        try:
            size = path.stat().st_size
            if size > MAX_VERDICT_BYTES:
                continue
            verdict = loads_verdict(path.read_bytes())
        except (PacketError, OSError):
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
    size = path.stat().st_size
    if size > MAX_CONSULT_BYTES:
        raise PacketError(f"consult: size {size} exceeds the {MAX_CONSULT_BYTES}-byte limit")
    return loads_consult(path.read_bytes())


def _next_consult(root: Path | str | None, *, claim: bool) -> Claimed | None:
    """Shared walk for `peek_consult`/`claim_consult`: skip and quarantine bad files, return the
    first good one. Claiming is exclusive (`os.rename` out of `consult/`), so a consult is answered
    at most once — the same guarantee a packet gets, for the same reason."""
    directory = inbox_root(root)
    for path in pending_consults(directory):
        try:
            consult = _load_consult(path)
        except PacketError as exc:
            quarantine(path, str(exc), root=directory)
            continue
        except OSError:  # vanished or unreadable between listing and load — nothing to answer
            continue
        if not claim:
            return Claimed(path=path, packet=consult)
        _ensure_tree(directory)
        target = _assert_inside(directory, _free_name(directory / "consult_claimed" / path.name))
        try:
            os.rename(path, target)
        except OSError:
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
    question forever. Exclusive via `os.rename`, same race handling as `requeue_claimed`."""
    directory = _ensure_tree(inbox_root(root))
    target = _assert_inside(directory, _free_name(directory / "consult" / path.name))
    os.rename(path, target)
    log.warning("twoperson.consult_requeued", path=str(target))
    return target


def archived_consults(root: Path | str | None = None) -> list[Path]:
    """Consults in ``consult_answered/`` — successfully answered, advice already published — oldest
    first. The consult-lane sibling of `archived`; pair with `archive_claimed_consult`."""
    return _lane_files(root, "consult_answered")


def archive_claimed_consult(path: Path, *, root: Path | str | None = None) -> Path:
    """Move a claimed consult to ``consult_answered/`` — the consult-lane sibling of
    `archive_claimed`, for the same reason: keeps `consult_claimed/` meaning "unresolved" so the
    stale-claim sweep never mistakes a completed answer for an orphan."""
    directory = _ensure_tree(inbox_root(root))
    target = _assert_inside(directory, _free_name(directory / "consult_answered" / path.name))
    os.rename(path, target)
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
            size = path.stat().st_size
            if size > MAX_ADVICE_BYTES:
                raise PacketError(f"advice: size {size} exceeds the {MAX_ADVICE_BYTES}-byte limit")
            out.append((path, loads_advice(path.read_bytes())))
        except PacketError as exc:
            quarantine(path, str(exc), root=directory)
        except OSError:  # vanished or unreadable between listing and load — nothing to report
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
    advice_dir = (directory / "advice").resolve()
    acked: list[Path] = []
    for path in paths:
        path = Path(path)
        # Only ack a file that is actually an advice in THIS inbox's advice/ lane.
        if path.resolve().parent != advice_dir:
            continue
        target = _assert_inside(directory, _free_name(directory / "advice_seen" / path.name))
        try:
            os.rename(path, target)
        except OSError:
            continue  # another reader took it first, or it vanished — nothing to hand back
        acked.append(target)
    if acked:
        log.info("twoperson.advice_acked", count=len(acked))
    return acked


def answered_consult_ids(root: Path | str | None = None) -> frozenset[str]:
    """Every ``consult_id`` that already has durable advice recorded — scanning BOTH ``advice/`` and
    ``advice_seen/``. The consult-lane sibling of `verdicted_packet_ids`; see its docstring for why
    this specific under-report-is-safe direction matters for the stale-claim sweep."""
    directory = inbox_root(root)
    ids: set[str] = set()
    for path in _lane_files(directory, "advice") + _lane_files(directory, "advice_seen"):
        try:
            size = path.stat().st_size
            if size > MAX_ADVICE_BYTES:
                continue
            advice = loads_advice(path.read_bytes())
        except (PacketError, OSError):
            continue
        consult_id = advice.get("consult_id")
        if isinstance(consult_id, str) and consult_id:
            ids.add(consult_id)
    return frozenset(ids)
