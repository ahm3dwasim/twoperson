"""The r3 findings, behaviourally — at EVERY write and read site, not just the one that was named.

Three audit rounds each named the next file operation the previous fix had not reached. The last
round named four:
:mod:`tests.test_safefs_guard` closes the CLASS structurally (nothing outside the primitive may name
a file operation at all); this module pins the CONSEQUENCES, one row per site, so a primitive that
stopped enforcing one of them fails a behavioural test and not only a structural one.

The three shapes a name inside an inbox root can take that used to reach through the package:

* a **hard link** to a writable file outside the root — ``O_NOFOLLOW`` cannot refuse it, because
  there is no link at the name, the name simply IS the other file. Only "never write through a name"
  answers it, which is what `_safefs.replace_regular` does.
* a **FIFO** — ``O_RDONLY`` with no writer blocks forever, on a READER; ``O_WRONLY`` with no reader
  blocks forever, on a WRITER. Both directions are covered, and a hang is turned into a failure by
  `tests.fixtures.guarded`.
* a **creation failure** — a full disk is an ``OSError`` at a `mkdir`, an `fchmod`, a write or a
  replace, and each of those used to escape as a raw traceback instead of a refusal.
"""
from __future__ import annotations

import errno
import json
import os
import pathlib

import pytest

from twoperson import _safefs, inbox, watch
from twoperson.packet import PacketError
from twoperson.watch import Cursor
from tests.fixtures import guarded as _guarded, inject as _inject, valid_packet


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    monkeypatch.delenv(watch.AUDIT_CMD_ENV, raising=False)
    return target


#: The bytes that must survive every attack below. Distinctive enough that a partial write, a
#: truncation to zero and a successful overwrite are all visible as "not this".
OUTSIDE = b"OPERATOR DATA THAT MUST SURVIVE ANY INBOX OPERATION\n"


def _outside(tmp_path, name: str) -> pathlib.Path:
    """A writable file OUTSIDE the inbox, and the thing every "untouched" assertion is about."""
    path = tmp_path / f"{name}-outside.txt"
    path.write_bytes(OUTSIDE)
    return path


def _hardlink(tmp_path, root, name: str, relative: str) -> pathlib.Path:
    """Hard-link ``relative`` inside the inbox to a file outside it. Returns the outside file."""
    outside = _outside(tmp_path, name)
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    os.link(outside, target)
    return outside


# --------------------------------------------------------------------------------------------
# r3 finding 1 — a hard link at every writable name, and the file outside is untouched
#
# `O_TRUNC | O_NOFOLLOW` was the whole write path: `O_NOFOLLOW` refuses a SYMLINK and permits
# everything else, and "everything else" includes a hard link. A `rejected/<stem>.reason.txt`
# pre-created as a hard link to a writable file outside the inbox had that outside file TRUNCATED by
# an ordinary quarantine. The fix is not a flag — no flag can answer it — it is never opening an
# existing file for writing at all: a fresh O_EXCL temporary is revealed with os.replace, which
# changes which inode the NAME refers to and leaves the other link's file exactly as it was.
# --------------------------------------------------------------------------------------------

def _write_reason(root):
    return inbox._write_lane_file(root, "rejected", "p.reason.txt", b"quarantined: bad schema\n")


def _take_publish_lock(root):
    with inbox._publish_lock(root):
        return "locked"


def _take_watch_lock(root):
    with watch._dispatch_lock(root):
        return "locked"


def _mute(root):
    return watch.set_muted(True, root=root)


def _save_cursor(root):
    return watch.save_cursor(Cursor(packets=frozenset({"a.json"})), root=root)


def _publish(root):
    return inbox.publish(valid_packet(), root=root)


#: Every name this package WRITES, the relative path it lives at, and what the operation does when
#: the name is a hard link. There are two correct answers and the difference is deliberate:
#:
#: * **refuse** — this name is a lock, and a lock that is a second name for a file someone else
#:   controls is not a lock at all. `inbox._publish_lock` lets that refusal out.
#: * **degrade** — the watcher's own names. The watcher must never raise into a `--loop` tick, so it
#:   logs and carries on; the guarantee is that the outside file is untouched and nothing is written
#:   through it, not that the caller hears about it.
#: * **rewrite** — a reason file or a cursor is REPLACED as a directory entry, which is a success
#:   with the outside file intact.
WRITE_SITES = [
    pytest.param("reason", "rejected/p.reason.txt", _write_reason, "rewrite", id="reason-file"),
    pytest.param("lock", ".lock", _take_publish_lock, "refuse", id="publish-lock"),
    pytest.param("watch-lock", ".watch.lock", _take_watch_lock, "degrade", id="watch-lock"),
    pytest.param("mute", ".watch_muted", _mute, "degrade", id="mute-switch"),
    pytest.param("cursor", ".watch_seen.json", _save_cursor, "rewrite", id="cursor"),
]


@pytest.mark.parametrize("name,relative,operation,outcome", WRITE_SITES)
def test_a_hard_link_at_a_writable_name_never_touches_the_file_outside(root, tmp_path, name,
                                                                     relative, operation, outcome):
    """The r3 finding, at every writable name rather than only the reason file the reviewer named."""
    outside = _hardlink(tmp_path, root, name, relative)
    inbox._ensure_tree(root)

    if outcome == "refuse":
        # A lock that is a hard link is a name someone else controls; a lock held on it is not a lock.
        with pytest.raises((PacketError, OSError)):
            operation(root)
    else:
        operation(root)     # "degrade" and "rewrite" both return: the guarantee is about the file

    assert outside.read_bytes() == OUTSIDE, (
        f"the write at {relative!r} went THROUGH the hard link and destroyed a file outside the "
        f"inbox — the exact defect `O_NOFOLLOW` cannot catch"
    )
    assert outside.stat().st_size == len(OUTSIDE), "the outside file was truncated to a new size"


def test_a_hard_link_at_the_staging_name_is_cleared_and_the_publish_still_succeeds(root, tmp_path):
    """Staging is the one site whose answer is "clear it and carry on", and the reason matters.

    `O_EXCL` makes a pre-created staging name a refusal rather than something written through — but a
    refusal here is a DoS: anyone who can create a name in `staging/` would block every future
    publish of that packet id, including the publish that would have moved it out of the way. The
    name is removed and the create retried, which costs the attacker a name and costs the operator
    nothing. Removing the name deletes ONE LINK: the file it was a second name for is untouched.
    """
    packet = valid_packet()
    name = f"{inbox._stamp(packet['created_at'])}-{packet['packet_id']}.json"
    outside = _hardlink(tmp_path, root, "staging", f"staging/{name}")
    inbox._ensure_tree(root)

    published = inbox.publish(packet, root=root)

    assert published.parent == root / "pending", "the publish did not land"
    assert outside.read_bytes() == OUTSIDE, "the staging create wrote through a hard link"
    assert list((root / "staging").iterdir()) == [], (
        "the publish left a staging entry behind, which blocks every retry of this packet"
    )


def test_a_quarantine_does_not_truncate_a_hard_link_at_its_reason_file(root, tmp_path):
    """The end-to-end shape of finding 1, through the command that actually reaches it.

    A malformed packet in `pending/` is quarantined on the way past an ordinary `next`, and the
    quarantine writes `rejected/<stem>.reason.txt`. That is the path the reviewer walked.
    """
    inbox._ensure_tree(root)
    published = inbox.publish(valid_packet(), root=root)
    stem = published.stem

    outside = _hardlink(tmp_path, root, "quarantine", f"rejected/{stem}.reason.txt")
    published.write_text("{ not a packet", encoding="utf-8")

    target = inbox.quarantine(published, "the packet is not valid JSON")

    assert target.parent == root / "rejected"
    assert outside.read_bytes() == OUTSIDE, (
        "quarantining a packet truncated a file outside the inbox through a hard link"
    )
    reason = (root / "rejected" / f"{target.stem}.reason.txt").read_text(encoding="utf-8")
    assert "not valid JSON" in reason, "the reason was refused rather than written"
    assert os.stat(root / "rejected" / f"{target.stem}.reason.txt").st_nlink == 1, (
        "the reason file is still a second name for the operator's file"
    )


# --------------------------------------------------------------------------------------------
# r3 finding 2 — a FIFO at every name, in BOTH directions
#
# The r2 work covered the READERS: an `O_RDONLY` open of a writer-less FIFO waits for a writer that
# never comes. The other half is the WRITERS, which r3 did not reach: `O_WRONLY` on a reader-less
# FIFO waits for a reader that never comes, so a FIFO at a reason filename, a lock, or the mute
# switch blocked the opening process forever. `O_NONBLOCK` is what makes the open return whatever
# the entry is; the `fstat` on the resulting descriptor is what refuses it.
# --------------------------------------------------------------------------------------------

def _fifo(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(path)


#: Every name this package opens, and what the operation must do when the name is a FIFO. "refuse"
#: is `PacketError`/`OSError`; "degrade" is the watcher's documented no-op, which must still return
#: rather than raise into a `--loop` tick; "recover" is the tolerant loader answering "no cursor".
FIFO_SITES = [
    # The reason file is a "rewrite": the write never opens the destination, so a FIFO there is not
    # refused, it is REPLACED — which is a stronger answer than a refusal and the same property that
    # defeats the hard link above.
    pytest.param("reason", "rejected/p.reason.txt", _write_reason, "rewrite", id="reason-file"),
    pytest.param("lock", ".lock", _take_publish_lock, "refuse", id="publish-lock"),
    pytest.param("watch-lock", ".watch.lock", _take_watch_lock, "degrade", id="watch-lock"),
    pytest.param("mute", ".watch_muted", _mute, "degrade", id="mute-switch"),
    pytest.param("cursor-read", ".watch_seen.json",
                 lambda r: watch.load_cursor(root=r), "recover", id="cursor-read"),
    pytest.param("cursor-write", ".watch_seen.json", _save_cursor, "degrade", id="cursor-write"),
]


@pytest.mark.parametrize("name,relative,operation,outcome", FIFO_SITES)
def test_a_fifo_at_a_name_never_blocks_the_open(root, tmp_path, name, relative, operation,
                                                outcome):
    """The r3 finding, in both directions: a writer blocked on a reader-less FIFO, and a reader on a
    writer-less one. Both must come back — a refusal is an answer, a hang is not."""
    inbox._ensure_tree(root)
    _fifo(root / relative)

    if outcome == "refuse":
        with pytest.raises((PacketError, OSError)):
            _guarded(operation, root)
    elif outcome == "recover":
        assert _guarded(operation, root) == Cursor(), (
            "a cursor that cannot be read must recover as 'no cursor', never as a crash"
        )
    else:
        # "rewrite" (the name is replaced by a regular file) and "degrade" (the watcher logs and
        # carries on) both have to RETURN — a refusal is an answer, a hang is not.
        _guarded(operation, root)

    assert (root / relative).exists(), "the name was removed rather than replaced"


def test_a_fifo_at_a_lane_entry_is_refused_without_blocking_on_the_read(root):
    """The reader half, re-pinned here so the whole class sits in one file.

    `tests/test_inbox.py` carries the original r2 tests for this; this is the same property stated
    against the primitive, and it is what a regression in `_safefs` would break first.
    """
    inbox._ensure_tree(root)
    published = inbox.publish(valid_packet(), root=root)
    published.unlink()
    os.mkfifo(published)

    with pytest.raises(inbox.LaneUnreadable) as caught:
        _guarded(inbox._read_lane_file, published)
    assert "could not be opened" in str(caught.value), caught.value


# --------------------------------------------------------------------------------------------
# r3 finding 3 — the cursor: a symlinked root, a FIFO, and bytes that are not UTF-8
#
# The old `load_cursor` was `path.read_text(encoding="utf-8")` on a PATH. Three separate ways to
# take the watcher down on a `--loop` tick, all reachable by anyone who can write a name into the
# inbox root — and the third was the quiet one: `UnicodeDecodeError` is not an `OSError` and not a
# `JSONDecodeError`, so it sailed past the `except` and killed the pass.
# --------------------------------------------------------------------------------------------

def test_a_cursor_that_is_not_utf8_is_recovered_as_no_cursor_with_a_log_line(root, tmp_path,
                                                                             monkeypatch):
    """The finding, exactly: a bad decode must be a recovery, and it must say so.

    The log line is asserted, not just the recovery: "no cursor" and "a cursor I could not read" are
    the same answer to the caller and a different fact to the operator, and the watcher's whole
    design is that it degrades VISIBLY.
    """
    from structlog.testing import capture_logs

    inbox._ensure_tree(root)
    (root / watch.CURSOR_NAME).write_bytes(b"\xff\xfe\x00 not utf-8 at all \xc3\x28")
    monkeypatch.setattr(watch, "_cursor_path", lambda *_a, **_k: None, raising=False)

    with capture_logs() as logs:
        cursor = watch.load_cursor(root=root)

    assert cursor == Cursor(), "invalid UTF-8 must recover as an empty cursor"
    assert any(entry.get("event") == "twoperson.watch_cursor_unreadable" for entry in logs), (
        f"the recovery was silent: {logs}"
    )


def test_an_oversized_cursor_is_refused_rather_than_read_into_memory(root):
    """The read is bounded, so a hostile name costs a refusal rather than the memory to hold it."""
    inbox._ensure_tree(root)
    (root / watch.CURSOR_NAME).write_bytes(b"x" * (watch.MAX_CURSOR_BYTES + 1))

    assert watch.load_cursor(root=root) == Cursor()


def test_a_cursor_behind_a_symlinked_root_is_not_followed(root, tmp_path):
    """The root is opened `O_NOFOLLOW`, so a root swapped for a symlink is refused, not followed."""
    real = tmp_path / "a-real-inbox"
    real.mkdir()
    inbox._ensure_tree(real)
    (real / watch.CURSOR_NAME).write_text(json.dumps({"packets": ["smuggled.json"]}),
                                          encoding="utf-8")
    root.symlink_to(real)

    assert watch.load_cursor(root=root) == Cursor(), (
        "the cursor was read through a symlinked root — the watcher followed the link out of the "
        "inbox it was pointed at"
    )


def test_a_cursor_swapped_for_a_fifo_cannot_hang_a_dispatch_pass(root, monkeypatch):
    """The end-to-end shape: the loader is called by the dispatch path, so a hang there is a hang in
    `watch --loop`, with no timeout and nothing to report."""
    inbox._ensure_tree(root)
    inbox.publish(valid_packet(), root=root)
    _fifo(root / watch.CURSOR_NAME)

    class Rec:
        def notify(self, *_a, **_k):
            return True

        def run(self, *_a, **_k):
            return 0

    rec = Rec()
    report = _guarded(watch.dispatch_once, audit_cmd="audit", notify_fn=rec.notify,
                      run_fn=rec.run)
    assert report is not None, "a read that could not happen must still produce a pass"


# --------------------------------------------------------------------------------------------
# r3 finding 4 — a creation failure is a refusal, at EVERY creating step
#
# `_ensure_tree` wrapped the root's `mkdir` and then left the lane `mkdir` and the directory `fchmod`
# unwrapped. An injected ENOSPC there was a raw `OSError` traceback out of `next`, which is the one
# thing `LaneUnreadable` exists to prevent — and exit 1 instead of exit 2.
# --------------------------------------------------------------------------------------------

def _enospc(*_args, **_kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


def _enospc_root_mkdir(monkeypatch):
    # The root (no held `dir_fd` yet) goes through `_safefs._mkdir_parents`'s bare `os.mkdir(name)`,
    # not `Path.mkdir` — see that function for why a plain `os.mkdir` replaced the pathlib call. The
    # lane mkdir below is `dir_fd`-addressed, so the two are told apart the same way
    # `_enospc_lane_mkdir` already tells them apart, and by the same signature.
    real = os.mkdir

    def only_the_root(name, *args, **kwargs):
        if "dir_fd" not in kwargs:
            _enospc()
        return real(name, *args, **kwargs)

    monkeypatch.setattr(inbox.os, "mkdir", only_the_root)


def _enospc_lane_mkdir(monkeypatch):
    real = os.mkdir

    def only_the_lane(name, *args, **kwargs):
        if "dir_fd" in kwargs:
            _enospc()
        return real(name, *args, **kwargs)

    monkeypatch.setattr(inbox.os, "mkdir", only_the_lane)


def _enospc_fchmod(monkeypatch):
    monkeypatch.setattr(inbox.os, "fchmod", _enospc)


def _enospc_temp_write(monkeypatch):
    # At the SYSCALL the body is drained with, not at `write_all`: `write_all` is the module's own
    # conversion point for that call, so patching the wrapper would replace the thing under test
    # with a raiser and prove nothing about the site. `_safefs.os` IS the `os` module, so the
    # instrumented raiser confines the failure to this package's frames — an unconfined `os.write`
    # patch also disarms pytest's capture and every logging handler in the process.
    _inject(monkeypatch, "write", errno.ENOSPC)


def _enospc_replace(monkeypatch):
    monkeypatch.setattr(inbox.os, "replace", _enospc)


#: Each creating step of the write path, and the injector that makes it fail the way a full disk
#: does. Every one of them is a step a real ENOSPC can land on, and every one of them used to be a
#: different answer to the operator.
ENOSPC_STEPS = [
    pytest.param("the root mkdir", _enospc_root_mkdir, id="root-mkdir"),
    pytest.param("a lane mkdir", _enospc_lane_mkdir, id="lane-mkdir"),
    pytest.param("a directory fchmod", _enospc_fchmod, id="fchmod"),
    pytest.param("the staging write", _enospc_temp_write, id="temp-write"),
    pytest.param("the reveal", _enospc_replace, id="replace"),
]


@pytest.mark.parametrize("step,inject", ENOSPC_STEPS)
def test_a_full_disk_at_every_creating_step_is_a_refusal_not_a_traceback(root, monkeypatch, step,
                                                                        inject):
    """`_ensure_tree` and the publish path raise the SAME type for all five, so the CLI has one net.

    The assertion is the type and the wording — `could not be created` for a step that was creating,
    `could not be written` / `could not be opened` for the rest — never the errno's repr, which is
    what used to reach the terminal.
    """
    inject(monkeypatch)

    with pytest.raises(PacketError) as caught:
        inbox.publish(valid_packet(), root=root)

    message = str(caught.value)
    assert "could not be" in message, f"{step}: the refusal does not say what failed: {message}"
    assert "No space left on device" in message, (
        f"{step}: the errno's own wording was dropped from the refusal: {message}"
    )
    assert "Traceback" not in message, f"{step}: a traceback reached the refusal: {message}"


@pytest.mark.parametrize("step,inject", ENOSPC_STEPS)
def test_a_full_disk_at_every_creating_step_exits_two_through_the_cli(root, tmp_path, monkeypatch,
                                                                     capsys, step, inject):
    """The property the operator actually sees: exit 2, a one-line refusal, no stack trace.

    Driven through `main()` in-process, which is the same entry point `python -m twoperson` calls —
    the net that converts a `PacketError` into exit 2 is the thing under test, not the shell.
    """
    from twoperson.__main__ import main

    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(valid_packet()), encoding="utf-8")
    inject(monkeypatch)

    rc = main(["publish", "--from", str(packet_path)])
    err = capsys.readouterr().err

    assert rc == 2, f"{step}: exit {rc}, and the refusal is supposed to be exit 2"
    assert "Traceback" not in err, f"{step}: a stack trace reached the terminal:\n{err}"
    assert "could not be" in err, f"{step}: the refusal is not on stderr: {err}"


@pytest.mark.parametrize("step,inject", ENOSPC_STEPS)
def test_a_full_disk_leaves_no_staging_leftover(root, monkeypatch, step, inject):
    """A create that fails after the staging name was taken must still give the name back.

    `O_EXCL` is what makes the staging name safe and what makes a leftover fatal: the NEXT attempt
    at the same packet is refused by a file the FAILED attempt left behind.
    """
    inbox._ensure_tree(root)
    inject(monkeypatch)

    with pytest.raises((PacketError, OSError)):
        inbox.publish(valid_packet(), root=root)

    monkeypatch.undo()
    assert list((root / "staging").iterdir()) == [], (
        f"{step}: the failed publish left a staging entry behind, blocking every retry"
    )
