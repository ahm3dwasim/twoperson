"""The one file-access primitive — every name under a protected root goes through here.

**Threat model, stated once.** Two directories in this package are *shared* directories: the inbox
root (``~/.twoperson/``, ``TWOPERSON_INBOX``, or a checkout's ``.twoperson/``) and the watcher's
state directory, which is that same root. Anything with write access to one of them — a second local
account, a process the operator ran, a synced folder that mirrored someone else's file into it — can
create ANY NAME there. So every name inside those roots is treated as adversarial, in all of these
shapes and without needing to enumerate them:

* a **symlink**, to a file or a directory, inside or outside the root (``O_NOFOLLOW`` at every hop);
* a **hard link** to a writable file outside the root (defeated by never writing *through* a name:
  see `replace_regular`);
* a **FIFO, device or socket**, which makes a blocking open hang forever (``O_NONBLOCK`` plus an
  ``fstat`` on the resulting descriptor);
* a **directory** where a file is expected, or a **file** where a directory is expected
  (``O_DIRECTORY`` on every directory hop);
* an **oversized** file, which costs memory before any schema check (every read is bounded);
* **invalid UTF-8**, which is a decode failure and must never be a crash (decoding is the caller's,
  and the caller catches `UnicodeDecodeError` explicitly — this module deals in bytes only);
* a name that is **already gone**, which is the one non-hostile answer and stays `FileNotFoundError`.

**Out of scope, deliberately.** The PARENT directories of a root, and every path the operator types
or configures — the packet path on a command line, the hook script, the launchd plist, a checkout's
own ``.git`` marker — belong to the operator's own layout. This package does not own them, cannot
know what they are for, and refusing a checkout reached through a symlinked parent would refuse
ordinary setups. No guarantee here is stated against them.

**The guarantees, against that model.** Each is enforced by construction rather than by a check
somebody has to remember to pair with the right call:

1. *No operation is redirected by a name it does not hold.* Directories are opened
   ``O_RDONLY | O_NOFOLLOW | O_DIRECTORY`` and every hop below them is addressed by ``dir_fd``, so
   the component that was validated and the component that is used are the same object. A path is
   resolved once, at the root, and never again.
2. *No write is ever aimed through a name.* `replace_regular` creates a fresh
   ``O_CREAT | O_EXCL | O_NOFOLLOW`` temporary in the destination directory and reveals it with
   ``os.replace`` addressed by two descriptors. Nothing in this module opens an existing file for
   writing — no ``O_TRUNC``, anywhere — so a hard link at the destination is *replaced as a
   directory entry* and the file it pointed at is untouched, and a symlink is refused rather than
   followed.
3. *No read blocks and no read is unbounded.* ``O_NONBLOCK`` on the open, ``fstat`` on the
   descriptor that was actually opened, ``S_ISREG`` required before a byte is read, and a byte
   ceiling on the read itself.
4. *No hostile name becomes a traceback.* Every `OSError` that is not the documented
   "provably empty / lost race" `FileNotFoundError` is raised as the module's refusal type, which is
   a :class:`~twoperson.packet.PacketError` — so the CLI's boundary net answers exit 2 with a
   one-line refusal instead of a stack trace, for commands not yet written as much as for these.

**One deliberate exception to rule 4.** `FileNotFoundError` is *not* converted. It is the ordinary
answer for a tree that has not been created yet (provably empty) and for an entry another process
already moved (a lost race), and both are the caller's to interpret — see `open_dir`/`read_regular`.
Turning it into a refusal would make an empty inbox indistinguishable from a hostile one, which is
the exact confusion :class:`LaneUnreadable` exists to prevent.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import stat as _stat
from pathlib import Path
from typing import IO

from .packet import LaneUnreadable, PacketError

#: Directories this package creates are owner-only. `mkdir(mode=...)` is umask-masked, so the mode
#: is applied with `fchmod` through the descriptor of the directory that was just opened — see
#: `open_dir` for why naming a directory twice is not the same as holding it once.
DIR_MODE = 0o700

#: Files this package creates. Never world-readable: a packet body is the operator's own text.
FILE_MODE = 0o600

#: The suffix this module reserves for the temporary half of `replace_regular`. It is derived from
#: the destination name, so `X` and `.X.tmp` are always in the same directory and on the same
#: filesystem — which is what makes the reveal a rename rather than a copy.
TMP_PREFIX = "."
TMP_SUFFIX = ".tmp"


class SafeFsRefusal(PacketError):
    """A file inside a protected root could not be used, and it was not a lane that refused.

    The same refusal `LaneUnreadable` spells for a lane, for the names that live *in* the root rather
    than in a lane of it: the publish lock, the watcher's lock, the mute switch, the cursor. The
    caller that degrades — the watcher — catches this type explicitly; the CLI's boundary net
    catches it because it is a `PacketError`.
    """


def refusal(what: str, exc: OSError, *, verb: str = "opened",
            kind: type[PacketError] = LaneUnreadable) -> PacketError:
    """One refusal, spelled the same way at every hop.

    ``what`` is built by the caller from this package's own names and the root the operator gave —
    never from a dropped entry's name — so the message cannot be forged by whoever dropped it. It
    reaches a terminal through `LaneScan.reason` and the CLI, so the errno's own ``strerror`` is
    carried rather than the exception's ``repr``, which would drag a path and a traceback into one
    line.

    ``verb`` is a statement of fact rather than decoration: a root this package had to CREATE cannot
    be said to have failed to open. The type — which is what every caller and the CLI boundary net
    switch on — is identical either way.
    """
    return kind(f"{what} could not be {verb}: {exc.strerror or type(exc).__name__}")


@contextlib.contextmanager
def _converting(label: str, verb: str, kind: type[PacketError],
                passthrough: tuple[type[BaseException], ...] = ()):
    """THE one place a syscall's ``OSError`` becomes this module's refusal.

    Every ``os.*`` / ``fcntl.*`` call in this module sits lexically inside one of these blocks, and
    a structural guard in ``tests/test_safefs_guard.py`` reads this file's AST and fails the build
    when one does not. That is what makes the module's error contract PROVABLE rather than a list of
    sites somebody remembered to wrap: the set of exceptions this module can raise is decided at
    this one function — the refusal ``kind``, plus whatever ``passthrough`` names for this block.

    ``passthrough`` is the deliberate exception, and there are exactly two reasons to name one:

    * ``FileNotFoundError`` — the documented "provably empty / already gone" answer. It is the
      caller's to read (see the module docstring), and turning it into a refusal would make an inbox
      nobody has created yet indistinguishable from a hostile one.
    * ``FileExistsError`` — an ANSWER a caller acts on rather than a failure: a stale temporary to
      clear, a packet already published, a mute switch already thrown.

    Both are named per block, so which syscall is allowed to say what is visible at the call and not
    only in a docstring three functions away. Everything else — ``EIO``, ``EACCES``, ``ENOSPC``,
    ``ELOOP``, ``ENOTDIR``, and a bare ``PermissionError`` — leaves as ``kind``.
    """
    try:
        yield
    except passthrough:
        raise
    except OSError as exc:
        raise refusal(label, exc, verb=verb, kind=kind) from exc


def _release(close) -> None:
    """Run a close exactly ONCE, dropping any error. See `close_quietly`.

    ``close`` must never be retried, ``EINTR`` included: on Linux (and POSIX generally) the
    descriptor is released by the kernel the instant ``close`` is called, whatever it then reports.
    A retry after ``EINTR`` does not close "the same" descriptor again — there is no descriptor left
    to close — it closes whatever NUMBER the kernel has since handed to an unrelated ``open`` on
    another thread, silently closing that operation's file (or lock) instead of this one. What used
    to look like the safe choice — retrying the one errno that claims nothing happened — is the one
    retry that is never safe here.
    """
    try:
        close()
    except OSError:
        pass


def close_quietly(fd: int) -> None:
    """Release a descriptor from a ``finally`` block, and never raise.

    ``close`` is the one syscall whose failure cannot be reported from where it is called: every
    call site here is finishing — the work is done, or a failure is already on its way out — so
    raising would REPLACE that outcome. On the cleanup half of a refusal it would replace a refusal
    with a raw ``OSError``, which is the exact contract this module exists to keep, and on a
    success path it would turn a published packet into a traceback after the bytes were already
    ``fsync``ed and revealed.

    ``close`` is attempted exactly once, and every error it can report — ``EINTR`` included — is
    dropped without a retry. See `_release` for why: the descriptor is already gone by the time
    ``close`` answers, so retrying can only land on a DIFFERENT descriptor that has since been
    reused.
    """
    _release(lambda: os.close(fd))


def unlock_quietly(handle: IO[bytes]) -> None:
    """Release an ``flock`` from a ``finally`` block, and never raise. See `close_quietly`.

    Every caller takes this lock only to serialize a section of work that is already finished by the
    time this runs — the packet is revealed, or a refusal is already on its way out — so a failed
    ``LOCK_UN`` must not replace that outcome any more than a failed ``close`` may. Unlike ``close``,
    there is nothing to get wrong by not retrying: the descriptor itself is untouched either way, and
    the ``close_quietly``/``close_handle_quietly`` call that follows this one releases every ``flock``
    the process holds on it regardless — so a dropped unlock error here is never the last word on the
    lock.
    """
    try:
        fcntl.flock(handle, fcntl.LOCK_UN)
    except OSError:
        pass


def close_handle_quietly(handle: IO[bytes]) -> None:
    """The same for a file object that OWNS its descriptor (``closefd=True``) — see `close_quietly`."""
    _release(handle.close)


def plain_name(name: str) -> str:
    """Refuse a name that is not exactly ONE filesystem component.

    Names this package operates on come from a directory listing, so they are one component by
    construction. The check exists so a caller passing a constructed name cannot turn an operation
    into a traversal, and so the refusal is deliberate rather than whatever the kernel happened to
    answer. Separators are POSIX ones, which is the surface this package already requires.
    """
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise PacketError(f"refusing a name that is not one component: {name!r}")
    return name


def _args(dir_fd: int | None) -> dict:
    """``dir_fd`` for a held directory; nothing at all when the caller named a path instead."""
    return {} if dir_fd is None else {"dir_fd": dir_fd}


def _create(dir_fd: int | None, name: str, flags: int, *, label: str, kind: type[PacketError],
            passthrough: tuple[type[BaseException], ...] = (), mode: int = FILE_MODE) -> int:
    """``os.open`` a name, retrying a concurrent create once.

    macOS intermittently answers a create that another thread is performing at the same instant with
    ``ENOENT`` — neither creating the file nor reporting ``EEXIST``. Measured on this platform: 62
    failures in 320 concurrent ``openat(dir_fd, name, O_CREAT…)`` attempts, and 0 in 320 with the
    single retry below. The answer cannot mean what it says, because the directory is open and the
    create is unconditional, so it is not a refusal; treating it as one made a lock, a switch, a
    cursor and a staging file all fail for no reason at all.

    ONE retry, deliberately not a loop: by the time the loser asks again the winner's create has
    landed, so the second call finds the name — ``O_CREAT`` opens it, and ``O_EXCL`` reports
    ``EEXIST``, which IS the answer that caller asked for. This is only for CREATING opens: a read
    that says ``ENOENT`` means the entry is gone, and it keeps meaning that.

    Both attempts sit inside a `_converting` block, so the errno chaos above never reaches a caller
    as raw text: the FIRST attempt lets ``ENOENT`` through (it is the retry's trigger, not an
    answer), and the SECOND is authoritative — a create whose directory is genuinely gone converts
    it, because with ``O_CREAT`` there is no other reading of that errno. ``passthrough`` carries
    ``FileExistsError`` for the ``O_EXCL`` callers, which act on it rather than refuse it.
    """
    with _converting(label, "created", kind, passthrough=passthrough):
        try:
            return os.open(name, flags, mode, **_args(dir_fd))
        except FileNotFoundError:
            pass            # the macOS create race; the second attempt below is authoritative
    with _converting(label, "created", kind, passthrough=passthrough):
        return os.open(name, flags, mode, **_args(dir_fd))


def open_dir(parent_fd: int | None, name: str, *, create: bool = False,
             what: str | None = None) -> int:
    """Open one directory, or refuse. ``parent_fd`` is a HELD descriptor; ``None`` means a path.

    ``O_RDONLY | O_NOFOLLOW | O_DIRECTORY`` rejects a symlink (``ELOOP`` on Linux, ``ENOTDIR`` on
    macOS), a regular file, a FIFO and a device in the one syscall that would otherwise have
    followed it, so no enumeration of the ways a directory can fail to be a directory has to be
    complete. Taking the parent descriptor rather than a path is what lets a whole tree be created
    from ONE root resolution: handing this ``root / name`` would re-resolve the root per level, and
    a root swapped part-way through such a loop would have had the remaining levels created
    somewhere else. A FIFO cannot block this open either — ``O_DIRECTORY`` answers ``ENOTDIR``
    before any blocking open would be attempted.

    ``create=True`` makes the directory if it is absent and ``fchmod``s it through the descriptor
    that was just opened. BOTH of those steps are wrapped: ``mkdir`` and ``fchmod`` are creation
    failures (a full disk, a permission wall), and a raw ``OSError`` out of either is a traceback
    where the operator needs a refusal. ``FileExistsError`` from ``mkdir`` is deliberately passed
    through to the open rather than converted — it means something already occupies the name, which
    is exactly the question the open asks and answers in one syscall.

    :raises LaneUnreadable: this hop is not a real, openable directory.
    :raises FileNotFoundError: it is not there and ``create`` is false — the caller's own
        "provably empty" / "already gone" answer, which this layer does not reinterpret.
    """
    label = what or f"the directory {name!r}"
    if create:
        try:
            with _converting(label, "created", LaneUnreadable, passthrough=(FileExistsError,)):
                if parent_fd is None:
                    Path(name).mkdir(parents=True, exist_ok=True)
                else:
                    os.mkdir(name, dir_fd=parent_fd)
        except FileExistsError:
            pass            # occupied; the open below decides whether what occupies it is usable
    # `ENOENT` is the one errno this hop does NOT own: it is the caller's "provably empty" answer
    # and passes through untouched. Everything else the open can say is a refusal.
    with _converting(label, "opened", LaneUnreadable, passthrough=(FileNotFoundError,)):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, **_args(parent_fd))
    if not create:
        return fd
    try:
        with _converting(label, "created", LaneUnreadable):
            os.fchmod(fd, DIR_MODE)
    except BaseException:
        close_quietly(fd)
        raise
    return fd


def _open_regular(dir_fd: int, name: str, what: str,
                  kind: type[PacketError]) -> tuple[int, os.stat_result]:
    """Open one entry for reading and prove it is a regular file, or refuse.

    ``O_NOFOLLOW`` is not enough on its own: it refuses a symlink and permits everything else, and
    "everything else" includes a FIFO. ``O_RDONLY`` on a FIFO with no writer BLOCKS until one
    appears, so a name listed and then swapped for a FIFO between the listing and the open hangs the
    reader forever — with whatever check the caller intended behind the block. Three things close
    it, in this order: ``O_NONBLOCK`` makes the open return immediately whatever the entry is,
    ``fstat`` on the DESCRIPTOR asks what was actually opened, and anything that is not ``S_ISREG``
    is refused before a byte is read or a size is trusted. The descriptor is what is checked, so the
    check and the read cannot be answered by two different objects.
    """
    plain_name(name)
    with _converting(what, "opened", kind, passthrough=(FileNotFoundError,)):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        with _converting(what, "opened", kind):
            info = os.fstat(fd)
        if not _stat.S_ISREG(info.st_mode):
            raise kind(f"{what} could not be opened: not a regular file")
    except BaseException:
        close_quietly(fd)
        raise
    return fd, info


def read_regular(dir_fd: int, name: str, max_bytes: int, *, what: str | None = None,
                 kind: type[PacketError] = LaneUnreadable) -> bytes:
    """Read one entry's bytes, bounded, or refuse. Decoding is the CALLER's and is not done here.

    This module deals in bytes only, on purpose: the decode is where a hostile file becomes a
    ``UnicodeDecodeError``, and a caller that has already decided what a bad decode MEANS (recover,
    or refuse) is the only one that can catch it in the right place. Swallowing it here would hide
    the choice; raising it here would make it a crash in callers that meant to recover.

    ``max_bytes`` is a ceiling, not a suggestion: a file larger than it is refused *before* it is
    read, so an oversized name costs a refusal rather than the memory to hold it.
    """
    label = what or f"the entry {name!r}"
    fd, info = _open_regular(dir_fd, name, label, kind)
    try:
        if info.st_size > max_bytes:
            raise kind(f"{label} could not be read: larger than {max_bytes} bytes")
        # The READ is a syscall too, and the file object's own `read` is where an EIO on a failing
        # disk arrives. It used to leave here raw, past every `except LaneUnreadable` on the way up,
        # which is how an unreadable packet came back to `inbox._next` as "no packet waiting".
        with _converting(label, "read", kind):
            with os.fdopen(fd, "rb", closefd=False) as handle:
                return handle.read(max_bytes)
    finally:
        close_quietly(fd)


def entry_size(dir_fd: int, name: str, *, what: str | None = None,
               kind: type[PacketError] = LaneUnreadable) -> int:
    """One entry's size, read through the same open as its content.

    A size cap is a read of the entry too: a path-based ``stat`` re-resolves the directory and
    follows a symlink, so the number a caller used to decide whether to open the file could come
    from a file the open itself would then refuse.
    """
    fd, info = _open_regular(dir_fd, name, what or f"the entry {name!r}", kind)
    close_quietly(fd)
    return info.st_size


def create_exclusive(dir_fd: int, name: str, *, what: str | None = None,
                     kind: type[PacketError] = LaneUnreadable) -> int:
    """Create a name that must NOT exist yet, or refuse. Returns the descriptor to write to.

    ``O_CREAT | O_EXCL | O_NOFOLLOW``: ``O_EXCL`` is what makes a pre-created name — a symlink, a
    FIFO, a hard link to someone else's file — a refusal rather than something we write through, and
    ``O_NOFOLLOW`` refuses an existing symlink on its own terms instead of leaving ``O_EXCL`` to
    report it as a plain ``EEXIST``. ``EEXIST`` is deliberately NOT converted — and it now really is
    not: it passes through `_create` by name, so the docstring and the code say the same thing.
    "That name is already taken" is an answer the caller acts on (a stale temporary to clear, a
    packet already published, a mute switch already thrown), not a refusal.
    """
    label = what or f"the entry {name!r}"
    plain_name(name)
    return _create(dir_fd, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                   label=label, kind=kind, passthrough=(FileExistsError,))


def write_all(fd: int, body: bytes, *, what: str = "the body",
              kind: type[PacketError] = LaneUnreadable) -> None:
    """Write the WHOLE buffer, in as many calls as the kernel needs.

    ``os.write`` may write fewer bytes than it was given and report how many. Ignoring that return
    value publishes a TRUNCATED file and reports success — the tail of the body is silently dropped
    — so the buffer is drained in a loop. A zero-byte write has made no progress and is raised
    rather than spun on.
    """
    view = memoryview(body)
    while view:
        with _converting(what, "written", kind):
            written = os.write(fd, view)
        if written <= 0:
            raise kind(f"{what} could not be written: {len(view)} byte(s) were not written")
        view = view[written:]


def _write_and_sync(fd: int, data: bytes, label: str, kind: type[PacketError]) -> None:
    """Drain the buffer to a held descriptor and ``fsync`` it, or refuse.

    A short write is a truncated file published as a success, so it is drained in a loop; an ENOSPC
    is the same failure one syscall earlier. Both leave as the caller's refusal rather than as a raw
    ``OSError``, because both are reachable from an ordinary command on a full disk.
    """
    write_all(fd, data, what=label, kind=kind)
    with _converting(label, "written", kind):
        os.fsync(fd)


def replace_regular(dir_fd: int, name: str, data: bytes, *, what: str | None = None,
                    kind: type[PacketError] = LaneUnreadable) -> None:
    """Make ``name`` mean exactly ``data``, by replacing the directory entry — never by writing
    through it.

    **This is the whole reason the module exists.** Opening an existing file for writing with
    ``O_TRUNC`` — even with ``O_NOFOLLOW``, which only refuses a *symlink* — writes through a HARD
    LINK. A ``rejected/<stem>.reason.txt`` pre-created as a hard link to a writable file outside the
    inbox had that outside file truncated by an ordinary quarantine. ``O_NOFOLLOW`` cannot help:
    there is no link to refuse, the name simply *is* the other file.

    A fresh ``O_CREAT | O_EXCL | O_NOFOLLOW`` temporary is written in the same directory, drained,
    ``fsync``ed, and revealed with ``os.replace`` addressed by ``src_dir_fd``/``dst_dir_fd``. The
    reveal is a rename of a DIRECTORY ENTRY: whatever ``name`` used to point at — hard link, symlink
    target, a longer or shorter previous file — keeps its own existence and its own contents, and
    the only thing that changes is which inode the name in *this* directory refers to. ``O_EXCL``
    additionally means a pre-created temporary name cannot be written through, and ``O_NOFOLLOW``
    refuses one that already exists as a symlink.

    A temporary left by a save that did not finish is cleared and the create retried once. Every
    production caller runs this inside a lock, so a ``.X.tmp`` sitting there is never a live writer —
    and ``O_EXCL`` without this would let one leftover block every future save of that name forever.
    Failing after the create removes the temporary for the same reason: a retry has to be able to
    succeed. The same reasoning covers the DESTINATION, which is why nothing here reads it first: a
    name already there is replaced, so neither a leftover nor a hostile name can wedge the write.

    :raises PacketError: ``kind``, for any failure that is not the caller's own lost race. The
        temporary is removed first, so a refusal leaves the directory as it found it.
    """
    label = what or f"the entry {name!r}"
    plain_name(name)
    tmp = f"{TMP_PREFIX}{name}{TMP_SUFFIX}"
    tmp_what = f"{label} (temporary {tmp!r})"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = _create(dir_fd, tmp, flags, label=tmp_what, kind=kind,
                     passthrough=(FileExistsError,))
    except FileExistsError:
        unlink(dir_fd, tmp, missing_ok=True)        # a save that did not finish; see the docstring
        fd = _create(dir_fd, tmp, flags, label=tmp_what, kind=kind)
    try:
        _write_and_sync(fd, data, label, kind)
        reveal(dir_fd, tmp, dir_fd, name, what=label, kind=kind)
    except BaseException:
        try:
            unlink(dir_fd, tmp, missing_ok=True)
        except PacketError:
            pass                    # the caller's own failure is the one worth reporting
        raise
    finally:
        close_quietly(fd)


def stage_and_reveal(src_dir_fd: int, src_name: str, data: bytes, *, dst_dir_fd: int,
                     dst_name: str, what: str | None = None,
                     kind: type[PacketError] = LaneUnreadable) -> None:
    """Write ``data`` at ``src_name``, then reveal it as ``dst_name`` in ANOTHER directory we hold.

    The cross-directory half of `replace_regular`, and its own function because the operation really
    is different: there the name being replaced is the name being written, and here the bytes land
    under one name in one directory and become visible under another name in another. Folding them
    together would mean the temporary's name had to differ from the destination's, and then a
    pre-created STAGING name would survive the publish that was supposed to consume it.

    Same rules, for the same reasons. The create is ``O_CREAT | O_EXCL | O_NOFOLLOW``, so the name
    cannot be a symlink and cannot be a file something else already put there; a name that IS already
    there is cleared and the create retried once, because `O_EXCL` without that lets one leftover —
    or one hostile name — wedge this packet id forever, and clearing it removes a NAME (one link)
    rather than touching whatever that name referred to. The write is drained and ``fsync``ed before
    the reveal, and BOTH the source name and any failure after the create is cleaned up, so a refusal
    leaves the source directory as it found it.
    """
    label = what or f"the entry {src_name!r}"
    plain_name(src_name)
    plain_name(dst_name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = _create(src_dir_fd, src_name, flags, label=label, kind=kind,
                     passthrough=(FileExistsError,))
    except FileExistsError:
        unlink(src_dir_fd, src_name, missing_ok=True)
        fd = _create(src_dir_fd, src_name, flags, label=label, kind=kind)
    try:
        _write_and_sync(fd, data, label, kind)
        reveal(src_dir_fd, src_name, dst_dir_fd, dst_name, what=label, kind=kind)
    except BaseException:
        try:
            unlink(src_dir_fd, src_name, missing_ok=True)
        except PacketError:
            pass                    # the caller's own failure is the one worth reporting
        raise
    finally:
        close_quietly(fd)


def open_lockfile(dir_fd: int, name: str, *, what: str | None = None,
                  kind: type[PacketError] = SafeFsRefusal) -> IO[bytes]:
    """Open ``name`` as a lock file and take an exclusive ``flock`` on it.

    ``O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK`` and deliberately **no ``O_TRUNC``**: a lock
    file's content is nothing, so nothing here needs truncating, and truncating is how a lock name
    pre-created as a hard link destroyed a file outside the root. ``O_NONBLOCK`` is what keeps a
    FIFO at the lock's name from blocking the open forever; the ``fstat`` then refuses it.

    A lock is only a lock if two processes take it on the SAME file, so the descriptor is checked as
    well as opened: it must be a regular file with ``st_nlink == 1``. A hard link at the lock's name
    is a second name for a file someone else controls, which is not a lock this process can trust.

    **The returned handle OWNS the descriptor.** ``os.fdopen`` is asked for ``closefd=True`` (the
    default), so the caller's one ``handle.close()`` releases the lock file's descriptor. It used to
    be ``closefd=False``, which made ``handle.close()`` close the *buffer* and leave the descriptor
    open forever: every watcher tick and every publish leaked one fd, and a long-running ``--loop``
    ran the process out of them. The error paths below close through the handle for the same reason
    — closing both would be a double close on an integer the kernel may already have handed out.

    The caller is responsible for releasing: ``flock(handle, LOCK_UN)`` then ``handle.close()``.
    """
    label = what or f"the lock file {name!r}"
    plain_name(name)
    fd = _create(dir_fd, name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                 label=label, kind=kind)
    handle: IO[bytes] | None = None
    try:
        with _converting(label, "opened", kind):
            info = os.fstat(fd)
        if not _stat.S_ISREG(info.st_mode):
            raise kind(f"{label} could not be opened: not a regular file")
        if info.st_nlink != 1:
            raise kind(f"{label} could not be opened: it is a hard link to another file")
        with _converting(label, "opened", kind):
            handle = os.fdopen(fd, "r+b", closefd=True)
    except BaseException:
        # `handle` is assigned only by the LAST statement above, so a failure anywhere before it
        # leaves the raw descriptor unowned and it is this branch that must release it.
        if handle is None:
            close_quietly(fd)
        else:
            close_handle_quietly(handle)
        raise
    try:
        with _converting(label, "locked", kind):
            fcntl.flock(handle, fcntl.LOCK_EX)
    except BaseException:
        close_handle_quietly(handle)
        raise
    return handle


def unlink(dir_fd: int, name: str, *, missing_ok: bool = False,
           what: str | None = None, kind: type[PacketError] = LaneUnreadable) -> None:
    """Remove one NAME from a directory we hold. ``unlink`` never follows a link, so it removes the
    name and not what a symlink at that name points at."""
    plain_name(name)
    try:
        with _converting(what or f"the entry {name!r}", "removed", kind,
                         passthrough=(FileNotFoundError,)):
            os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        if missing_ok:
            return
        raise           # the name is already gone: a lost race, and the caller's to read


def rename(src_fd: int, src_name: str, dst_fd: int, dst_name: str, *,
           what: str | None = None, kind: type[PacketError] = LaneUnreadable) -> None:
    """Move one name between two directories we hold, naming no path at all.

    ``os.rename(src, dst)`` resolves both paths again, so a directory swapped for a symlink after a
    listing redirected the move — and the file it moved — outside the root. With both descriptors
    held, neither end can be redirected, and a rename never FOLLOWS a symlink at either end (it
    replaces one).
    """
    plain_name(src_name)
    plain_name(dst_name)
    with _converting(what or f"the entry {src_name!r}", "moved", kind,
                     passthrough=(FileNotFoundError,)):
        os.rename(src_name, dst_name, src_dir_fd=src_fd, dst_dir_fd=dst_fd)


def reveal(src_fd: int, src_name: str, dst_fd: int, dst_name: str, *,
           what: str | None = None, kind: type[PacketError] = LaneUnreadable) -> None:
    """Move one name between two directories we hold, REPLACING whatever the destination was.

    The cross-directory half of `replace_regular`, for the case where the bytes were already written
    somewhere else (a ``staging/`` entry) and only the reveal is left. ``os.replace`` is the
    destination-replacing spelling of the same POSIX ``rename(2)`` `rename` wraps: the difference is
    the contract, not the syscall — `rename` is used where the destination has been proven free, and
    this where replacing it is the point. Both ends are held descriptors, so neither is resolved
    again and neither can be redirected; a rename never follows a symlink at either end.
    """
    plain_name(src_name)
    plain_name(dst_name)
    with _converting(what or f"the entry {src_name!r}", "moved", kind,
                     passthrough=(FileNotFoundError,)):
        os.replace(src_name, dst_name, src_dir_fd=src_fd, dst_dir_fd=dst_fd)


def stat_nolink(dir_fd: int, name: str, *, what: str | None = None,
                kind: type[PacketError] = LaneUnreadable) -> os.stat_result | None:
    """Is this NAME taken in this directory? ``None`` when it is not, a refusal when we cannot tell.

    ``follow_symlinks=False`` reports the LINK, so a symlink, a directory, a FIFO and a device all
    count as occupying their own name — which is what "taken" has to mean, or a publish picks a name
    that is already there.

    Exactly ONE errno means "free": ``ENOENT``, the name is not there. Everything else the
    interrogation can say — ``EIO`` on a failing disk, ``EACCES``, ``ENOTDIR`` because the thing
    above us was swapped — means *we do not know*, and "we do not know" must never be spelled
    ``None``. ``None`` is the answer that lets a caller choose a name and write to it, so a
    transient ``EIO`` read as "free" is how a write lands on top of something.

    ``PermissionError`` used to be mapped to ``None`` here, on the argument that a directory's own
    read permission already answered the question. It does not: `os.stat` by ``dir_fd`` needs
    *search* permission on the directory, so a ``PermissionError`` says the lookup could not be
    performed at all, which is exactly the case this function must not answer "free" to. It is now a
    refusal like every other errno.

    :raises kind: the name's occupancy could not be determined.
    """
    label = what or f"the entry {name!r}"
    plain_name(name)
    try:
        with _converting(label, "examined", kind, passthrough=(FileNotFoundError,)):
            return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None         # the one errno that answers the question: that name is free


def list_names(dir_fd: int, *, what: str = "the directory",
               kind: type[PacketError] = LaneUnreadable) -> list[str]:
    """Every name in a directory we hold, or a refusal. ``os.scandir`` never follows entries."""
    with _converting(what, "listed", kind):
        with os.scandir(dir_fd) as entries:
            return [entry.name for entry in entries]


def free_name(dir_fd: int, name: str) -> str:
    """``name`` if it is free IN THIS DIRECTORY, else ``<stem>-2``, ``<stem>-3``… — never clobbers.

    The question is asked, and the answer is used, against ONE descriptor, so the name that was
    chosen and the name that is then used cannot be answered by two different directories.
    """
    what = f"the candidate name {name!r}"
    if stat_nolink(dir_fd, name, what=what) is None:
        return name
    stem, suffix = os.path.splitext(name)
    for index in range(2, 1000):
        candidate = f"{stem}-{index}{suffix}"
        if stat_nolink(dir_fd, candidate, what=f"the candidate name {candidate!r}") is None:
            return candidate
    raise PacketError(f"cannot find a free filename for {name}")
