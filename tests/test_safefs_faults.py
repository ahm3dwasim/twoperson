"""Every syscall, at every errno, through every entry point — the PROOF of the error contract.

`tests/test_safefs_guard.py` proves structurally that nothing outside the primitive names a file
operation, and that inside it every syscall sits in the one conversion block. Both are claims about
the SOURCE. This module is the claim about BEHAVIOUR, and it is the one an auditor can falsify
without reading the code: take every ``os.*``/``fcntl.*`` function the primitive calls — collected
from its AST, so a syscall added tomorrow is in the sweep without anyone remembering to add it —
break it with each of the errnos a real filesystem raises, drive every public entry point, and
assert that what comes back is a refusal or an exit code.

What this replaces, and why the replacement is stronger than a longer list: three audit rounds each
found the next un-wrapped site, and each round's fix was verified by a test naming THAT site. A test
per site is a test per mistake already made. The sweep does not know which sites exist; it reads
them out of the module and breaks all of them, so the next un-wrapped site fails here on the commit
that introduces it rather than in the next review.

Three things are asserted, in this order of importance:

1. **Nothing raw escapes.** No driver may raise anything that is not a ``PacketError``, and no CLI
   driver may print a traceback. A raw ``OSError`` reaching a caller is the whole defect class.
2. **A refusal is never silently turned into an answer.** Where a driver is told a fault it actually
   reached, "no packet waiting" / "an empty lane" / "nothing to report" are failures, not passes —
   that is the shape both of the two high findings had.
3. **A tolerant driver says so.** The watcher's lanes, the cursor and the locks DEGRADE by design;
   each has to report the degradation rather than return the same value it returns on a good day.

The injector is in `tests.fixtures`: it fails a call only when a frame of this package is on the
stack. An unconfined ``os.write`` patch would also disarm pytest's capture and every logging handler
in the process, which turns the row into a harness error and proves nothing about the package.
"""
from __future__ import annotations

import ast
import errno
import fcntl
import json
import os
import pathlib
import tempfile

import pytest

from twoperson import _safefs, inbox, watch
from twoperson import __main__ as cli
from twoperson.__main__ import main
from twoperson.packet import LaneUnreadable, PacketError
from twoperson.watch import Cursor
from tests.fixtures import _called_from_package, _called_from_safefs, inject as _inject, valid_packet


# --------------------------------------------------------------------------------------------
# Which syscalls exist — read out of the primitive, not remembered here.
# --------------------------------------------------------------------------------------------

#: The modules whose calls are syscalls, and the names on them that are. A name in this table that
#: the module calls but is not a syscall would make the sweep lie about what it covers, so it is kept
#: to the calls that touch a file descriptor or a directory entry.
_SYSCALL_NAMES = {
    "os": frozenset({
        "open", "read", "write", "close", "fstat", "stat", "lstat", "fchmod", "chmod",
        "mkdir", "makedirs", "rmdir", "remove", "unlink", "rename", "replace", "link", "symlink",
        "scandir", "fdopen", "fsync", "fdatasync", "lseek", "truncate", "ftruncate", "dup", "utime",
    }),
    "fcntl": frozenset({"flock", "lockf", "fcntl"}),
}


def _safefs_syscalls() -> set[tuple[str, str]]:
    """Every ``module.name`` the primitive calls, as ``(module, name)`` pairs."""
    tree = ast.parse(pathlib.Path(_safefs.__file__).read_text(encoding="utf-8"))
    found: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        func = node.func if isinstance(node, ast.Call) else None
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.attr in _SYSCALL_NAMES.get(func.value.id, ())):
            found.add((func.value.id, func.attr))
    return found


SYSCALLS = sorted(_safefs_syscalls())

#: The errnos a real filesystem answers with, and the reason each is worth a row: EIO is a failing
#: disk (the read the reviewer found escaping), EACCES is a permission wall (the stat the reviewer
#: found reading as "free"), ENOSPC is a full disk (the write path).
ERRNOS = [errno.EIO, errno.EACCES, errno.ENOSPC]

#: A syscall whose failure is DROPPED rather than refused, and why. `close` runs in `finally`
#: blocks: raising there would replace the outcome that brought us there — including a refusal —
#: so `_safefs.close_quietly` retries EINTR and drops the rest. A driver that still succeeds while
#: this fires is the documented behaviour, not a swallowed refusal.
_TOLERATED = {"close"}


def test_the_sweep_actually_collected_the_syscalls_it_claims_to():
    """A collection that returned nothing would make every row below vacuously green."""
    names = {name for _module, name in SYSCALLS}
    assert {"open", "write", "fstat", "stat", "mkdir", "fchmod", "replace", "unlink", "close",
            "fsync", "scandir", "fdopen", "flock"} <= names, (
        f"the AST collector missed syscalls the primitive calls: {sorted(names)}"
    )
    assert ("fcntl", "flock") in SYSCALLS, "the flock call is not being swept"


# --------------------------------------------------------------------------------------------
# The drivers — each one PERFORMS an operation and returns what it answered. What that answer is
# allowed to be is the sweep's decision, not the driver's: a driver that judged itself could not be
# driven by a fault it never reached.
# --------------------------------------------------------------------------------------------



def _build_inbox(target) -> pathlib.Path:
    """A real inbox, published through the real write path: a pending packet and a readable
    neighbour in a lane that gates nothing. Built with the injector DISARMED — see `Fault.armed`."""
    inbox.publish(valid_packet(), root=target)
    (target / "advice").mkdir(parents=True, exist_ok=True)
    (target / "advice" / "note.json").write_text(json.dumps({
        "advice_id": "advice-sweep", "consult_id": "consult-sweep",
        "created_at": "2026-08-19T09:00:00Z", "counsel": "unknown", "confidence": "unknown",
        "head_sha": "0900128",
        "rationale": "a readable neighbour in a lane that gates nothing"}))
    return target


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    """One inbox for the tests below that are about a single fault rather than a whole row."""
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    monkeypatch.delenv(watch.AUDIT_CMD_ENV, raising=False)
    return _build_inbox(target)


def _drive_publish(root):
    return inbox.publish(valid_packet(), root=root)


def _drive_claim(root):
    return inbox.claim_next(root)


def _drive_peek(root):
    return inbox.peek_next(root)


def _drive_quarantine(root):
    # The path is looked up through the REAL listing rather than spelled here: a fault that breaks
    # the listing is itself the refusal, and a hard-coded name would make this row's failure a
    # `FileNotFoundError` about the test's own constant instead of about the contract.
    return inbox.quarantine(inbox.pending(root)[0], "sweep", root=root)


def _drive_list_cli(root):
    return main(["list"])


def _drive_check_cli(root):
    return main(["check"])


def _drive_publish_cli(root, tmp_path):
    packet_file = tmp_path / "sweep-packet.json"
    packet_file.write_text(json.dumps(valid_packet()), encoding="utf-8")
    # --no-derive: the fixture's head is synthetic, so this reaches the syscall the sweep is
    # driving instead of the (unrelated) diff-derivation refusal.
    return main(["publish", "--no-derive", "--from", str(packet_file)])


def _drive_watch_scan(root):
    delta = watch.scan_new(root, Cursor())
    assert delta.new_packets or delta.unreadable, (
        "a lane holding a readable packet must be either announced or reported unreadable — "
        f"scan_new did neither: {delta!r}"
    )
    return delta


def _drive_cursor_load(root):
    """Only "nothing raw escaped" is asserted here: an absent cursor and an unreadable one are the
    same answer to this caller by design, which is why the read path gets its own row in the
    finding-2 test below."""
    return watch.load_cursor(root)


def _drive_cursor_save(root):
    return watch.save_cursor(Cursor(packets=frozenset({"seen.json"})), root)


def _drive_dispatch_lock(root):
    ran = False
    with watch._dispatch_lock(root):
        ran = True
    assert ran, "the dispatch lock refused AND skipped its body — it must degrade to a no-op"


def _drive_publish_lock(root):
    with inbox._publish_lock(inbox.inbox_root(root)):
        pass


def _drive_dispatch_once(root):
    # The loop-level entry point, not just its pure core (`scan_new`, already a row above): a
    # refusal reaching HERE unconverted is what finding 3 (the mute switch's `stat`) actually looked
    # like — a `PacketError` out of `is_muted`, past every driver `scan_new` alone could exercise.
    return watch.dispatch_once(root, audit_cmd="", notify_fn=lambda *_a: True, run_fn=lambda *_a: 0)


def _drive_watch_loop_once(root):
    # One bounded `watch_loop` iteration: the contract is that a fault costs the TICK, not the loop,
    # so this drives the actual `while` body a real `--loop` run executes rather than only the
    # function it calls each time around.
    return watch.watch_loop(root, max_passes=1, audit_cmd="", notify_fn=lambda *_a: True,
                            run_fn=lambda *_a: 0)


def _exit_two(value) -> bool:
    """A CLI driver's refusal IS an exit code, so it has no exception to hand back."""
    return value == 2


#: ``(name, driver, strict, refusal_value)``.
#:
#: ``strict`` is the row's promise: when the fault this row is about was actually REACHED, the driver
#: must have refused rather than returned an answer. A driver that never reaches the broken syscall
#: is free to answer, which is what `Fault.fired` decides — the alternative is a row that either
#: asserts nothing (a sweep that cannot fail) or demands a refusal from an entry point that never
#: touched the syscall (a sweep that fails on the truth).
#:
#: The drivers themselves assert nothing about refusal: they perform the operation and return what
#: it answered. That split is deliberate — a driver that decided for itself whether it had refused
#: could not be driven by a fault it never reached.
DRIVERS = [
    ("publish", _drive_publish, True, None),
    ("claim/next", _drive_claim, True, None),
    ("peek", _drive_peek, True, None),
    ("quarantine", _drive_quarantine, True, None),
    ("cli:list", _drive_list_cli, True, _exit_two),
    ("cli:check", _drive_check_cli, True, _exit_two),
    ("cli:publish", _drive_publish_cli, True, _exit_two),
    ("watch:scan", _drive_watch_scan, False, None),
    ("cursor:load", _drive_cursor_load, False, None),
    ("cursor:save", _drive_cursor_save, False, None),
    ("lock:dispatch", _drive_dispatch_lock, False, None),
    ("lock:publish", _drive_publish_lock, False, None),
    ("watch:dispatch_once", _drive_dispatch_once, False, None),
    ("watch:loop_once", _drive_watch_loop_once, False, None),
]


def _call(driver, root, tmp_path):
    """Run one driver, returning ``("refusal", exc)``, ``("value", value)`` or ``("crash", exc)``."""
    try:
        result = driver(root, tmp_path) if driver is _drive_publish_cli else driver(root)
    except PacketError as exc:
        return "refusal", exc
    except BaseException as exc:            # noqa: BLE001 - the classification IS the assertion
        return "crash", exc
    return "value", result


# --------------------------------------------------------------------------------------------
# Which OCCURRENCE of a syscall each driver can reach — read from a clean run, not guessed.
#
# `Fault` used to fire on every matching call, which means a row could only ever prove something
# about the FIRST occurrence of a syscall in a driver: the driver raises (or is told a refusal) on
# that first call and never runs far enough to make a second one. `fcntl.flock` is called twice by
# every locking driver — `LOCK_EX` to acquire, `LOCK_UN` to release — and a sweep that only ever
# breaks the first occurrence can never reach the second at all. That is how the release being
# unconverted (finding 4) went three audit rounds unswept, and how a `stat` reached only on a SECOND
# pass through `is_muted` (finding 3) did too.
#
# So the count is measured, not assumed: every driver is run once per syscall with a COUNTING hook
# in place of the real call — it never raises, only tallies how many times a package frame reached
# it — and the highest count any driver produces is how many occurrences that syscall's row sweeps.
# --------------------------------------------------------------------------------------------

def _reachable_calls(module_name: str, syscall_name: str, base: pathlib.Path) -> int:
    """The most times any driver reaches ``module.syscall_name`` from a `_safefs.py` frame, clean.

    Scoped to `_called_from_safefs`, not the wider `_called_from_package`: the count measured here
    is the index space `Fault(at=...)` is later asked to fault, so the two must agree exactly on
    what "reached" means, or occurrence #3 counted here and occurrence #3 actually faulted later
    would not be the same call.
    """
    holder = os if module_name == "os" else __import__(module_name)
    real = getattr(holder, syscall_name)
    counter = {"n": 0}

    def counting(*args, **kwargs):
        if _called_from_safefs():
            counter["n"] += 1
        return real(*args, **kwargs)

    saved_inbox_env = os.environ.get("TWOPERSON_INBOX")
    saved_audit_env = os.environ.get(watch.AUDIT_CMD_ENV)
    setattr(holder, syscall_name, counting)
    best = 0
    try:
        for index, (_label, driver, _strict, _refusal) in enumerate(DRIVERS):
            root = _build_inbox(base / f"count-{module_name}-{syscall_name}-{index:02d}")
            os.environ["TWOPERSON_INBOX"] = str(root)
            os.environ.pop(watch.AUDIT_CMD_ENV, None)
            counter["n"] = 0
            try:
                driver(root, base) if driver is _drive_publish_cli else driver(root)
            except BaseException:          # noqa: BLE001 - only the reachable COUNT matters here
                pass
            best = max(best, counter["n"])
    finally:
        setattr(holder, syscall_name, real)
        if saved_inbox_env is None:
            os.environ.pop("TWOPERSON_INBOX", None)
        else:
            os.environ["TWOPERSON_INBOX"] = saved_inbox_env
        if saved_audit_env is None:
            os.environ.pop(watch.AUDIT_CMD_ENV, None)
        else:
            os.environ[watch.AUDIT_CMD_ENV] = saved_audit_env
    return best


with tempfile.TemporaryDirectory(prefix="twoperson-sweep-count-") as _count_base:
    #: ``(module, name) -> how many occurrences to sweep``, measured once at collection time. Never
    #: zero: a syscall no driver reaches still gets one row, which simply never sets `fault.fired`
    #: and so asserts nothing — the same "free to answer" rule a single-occurrence row always had.
    CALL_COUNTS: dict[tuple[str, str], int] = {
        (module, name): max(1, _reachable_calls(module, name, pathlib.Path(_count_base)))
        for module, name in SYSCALLS
    }

#: Every ``(module, name, index)`` the sweep drives — the Cartesian product of `SYSCALLS` and each
#: syscall's own measured occurrence count, not a single flat count for all of them.
INDEX_CASES = [
    (module, name, index)
    for module, name in SYSCALLS
    for index in range(1, CALL_COUNTS[(module, name)] + 1)
]

#: ``(name, index)`` pairs whose failure is DROPPED rather than refused, on top of `_TOLERATED`
#: (which drops a name at every index). Two entries, both explained below.
_TOLERATED_AT = {
    # `flock`'s SECOND occurrence in every locking driver is the `LOCK_UN` release
    # (`_safefs.unlock_quietly`): it runs from a `finally` after the locked work is already done, so
    # — like `close` — a failure there must not replace a completed outcome. Its FIRST occurrence
    # (`LOCK_EX`, the acquire) stays strict: a lock that could not be TAKEN must still refuse or
    # degrade, never silently proceed as if it had been.
    ("flock", 2),
    # `mkdir`'s FIRST occurrence in every driver is `_ensure_tree`'s `Path(root).mkdir(exist_ok=True)`
    # — and every driver here runs against a root `_build_inbox` already created, so this call is
    # always "recreate a directory that is already there", which `Path.mkdir(exist_ok=True)` is
    # DOCUMENTED to swallow whatever the errno (it checks `self.is_dir()`, not the errno, precisely
    # because "the OS could give priority to another error like EACCES" over EEXIST). That is a
    # stdlib contract this package does not own — the genuinely-missing-root case (where the same
    # call SHOULD refuse) has no `Path.mkdir(exist_ok=True)` escape hatch and is proved directly by
    # `test_a_genuinely_missing_root_that_cannot_be_created_is_a_refusal` below instead.
    ("mkdir", 1),
}


@pytest.mark.parametrize("module,name,index", INDEX_CASES,
                         ids=[f"{m}.{n}#{i}" for m, n, i in INDEX_CASES])
@pytest.mark.parametrize("errno_value", ERRNOS, ids=lambda v: errno.errorcode[v])
def test_no_syscall_failure_escapes_as_a_raw_oserror(tmp_path, monkeypatch,
                                                     module, name, index, errno_value):
    """Break the ``index``-th reachable call to ONE syscall, drive EVERY entry point, and require a
    refusal (or a documented, tolerated degrade) at each that reaches it.

    The same fault, at the same occurrence index, is held for all drivers in the row: an entry point
    that reaches that occurrence must refuse (unless the occurrence is `_TOLERATED`/`_TOLERATED_AT`),
    and one that never reaches it is free to answer — `Fault.fired` decides which. Faulting only ONE
    occurrence, rather than every one, is what lets a driver run PAST an earlier call to a syscall to
    reach a later one — see the section comment above for why that is load-bearing.
    """
    holder = os if module == "os" else __import__(module)
    fault = _inject(monkeypatch, name, errno_value, holder=holder, at=index,
                    reached=_called_from_safefs)
    fault.armed = False

    tolerated = name in _TOLERATED or (name, index) in _TOLERATED_AT
    failures: list[str] = []
    for driver_index, (label, driver, strict, refusal_value) in enumerate(DRIVERS):
        # A FRESH tree per driver, because the drivers are not read-only: `claim/next` MOVES the
        # packet out of `pending/`, so a shared tree would leave every later driver running against
        # an inbox the earlier one had emptied — and "there was nothing there" would read as "the
        # operation refused". Built disarmed; the fault is armed only for the drive itself.
        root = _build_inbox(tmp_path / f"driver-{driver_index:02d}")
        monkeypatch.setenv("TWOPERSON_INBOX", str(root))
        fault.reset()
        fault.armed = True
        outcome, payload = _call(driver, root, tmp_path)
        fault.armed = False
        if outcome == "value" and refusal_value is not None and refusal_value(payload):
            outcome = "refusal"
        if outcome == "crash":
            failures.append(
                f"{label}: a raw {type(payload).__name__} escaped — {payload!r} "
                f"(the contract is a refusal, or exit 2 at the CLI)"
            )
            continue
        if fault.fired and strict and not tolerated and outcome != "refusal":
            failures.append(
                f"{label}: {module}.{name} call #{index} failed with "
                f"{errno.errorcode[errno_value]} and the driver still answered {payload!r} — a "
                f"refusal turned into an answer"
            )
    assert not failures, "\n".join(failures)


def test_a_genuinely_missing_root_that_cannot_be_created_is_a_refusal(tmp_path, monkeypatch):
    """`_TOLERATED_AT` drops `mkdir` call #1 only because every sweep driver runs against a root
    `_build_inbox` already created: `Path.mkdir(exist_ok=True)` swallows a failure there because the
    directory already exists (it checks `self.is_dir()`, not the errno), not because anything was
    refused. This is the same call on a root that does NOT exist yet, where that escape hatch cannot
    apply and the failure must reach the caller as a refusal.
    """
    root = tmp_path / "twoperson"
    fault = _inject(monkeypatch, "mkdir", errno.ENOSPC, at=1, reached=_called_from_safefs)

    with pytest.raises(PacketError):
        inbox.publish(valid_packet(), root=root)

    assert fault.fired, "the fault was never reached — this row proves nothing"


# --------------------------------------------------------------------------------------------
# Finding 2 — an UNREADABLE read is not an empty lane. The row that had no proof before.
# --------------------------------------------------------------------------------------------

def _fail_the_file_object_read(monkeypatch, errno_value):
    """Break the file object's ``read`` — the syscall ``os.read`` does NOT cover.

    ``read_regular`` reads through ``os.fdopen(...).read``, and ``os.read`` is not on that path at
    all, so a sweep over ``os.*`` alone would have walked straight past the one un-wrapped syscall
    the audit found. ``io.BufferedReader`` is an immutable C type that cannot be patched, so the
    break goes in one level out: ``os.fdopen`` returns a handle of ours that fails on ``read`` and is
    otherwise the real one — ``__getattr__`` hands ``open_lockfile`` the real ``fileno``, so the lock
    path keeps working and this stays a test about ONE call.
    """
    real_fdopen = os.fdopen
    detail = os.strerror(errno_value)

    class Unreadable:
        def __init__(self, handle):
            self._handle = handle

        def read(self, *_args, **_kwargs):
            raise OSError(errno_value, detail)

        def __getattr__(self, name):
            return getattr(self._handle, name)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return self._handle.__exit__(*exc)

    def breaking_fdopen(*args, **kwargs):
        handle = real_fdopen(*args, **kwargs)
        return Unreadable(handle) if _called_from_package() else handle

    monkeypatch.setattr(os, "fdopen", breaking_fdopen)


def test_a_read_that_fails_is_a_refusal_not_no_packet_waiting(prepared, monkeypatch):
    """`read_regular`'s file-object read was the ONE syscall in the module outside a converting
    block: an EIO there left as a raw `OSError`, sailed past `except LaneUnreadable` (a `PacketError`
    is not an `OSError`), and landed on `except OSError: continue` — which is how a packet nobody
    could read came back to the caller as "nothing waiting"."""
    _fail_the_file_object_read(monkeypatch, errno.EIO)

    with pytest.raises(LaneUnreadable) as caught:
        inbox.claim_next(prepared)

    assert "could not be read" in str(caught.value), (
        f"the refusal does not say what failed: {caught.value}"
    )


def test_an_unreadable_packet_is_not_reported_as_an_empty_inbox_by_the_cli(prepared, monkeypatch):
    """The same fault, one layer up: the operator's probe must exit 2, not "nothing to do"."""
    _fail_the_file_object_read(monkeypatch, errno.EIO)

    assert main(["next"]) == 2, "`next` read an unreadable packet as an empty inbox"


def test_an_unlistable_lane_is_not_reported_as_nothing_waiting_at_the_cli(prepared, monkeypatch):
    """The other half of the same property, on the probe an operator's tooling branches on: `check`
    exits 0 for "work waiting" and 1 for "nothing waiting", so an unlistable lane that answered 1
    would be indistinguishable from an empty inbox — the expensive direction to be wrong in."""
    _inject(monkeypatch, "scandir", errno.EIO)

    assert main(["check"]) == 2, "an unlistable lane answered `check` with \"nothing waiting\""


@pytest.mark.parametrize("refusal", [LaneUnreadable, _safefs.SafeFsRefusal])
def test_the_cli_net_answers_every_refusal_type_with_exit_2(monkeypatch, capsys, refusal):
    """The one net in `main` catches the BASE type, and both refusals are checked, not just the one.

    `_safefs` raises exactly two refusals: `LaneUnreadable` for anything inside a lane, and
    `SafeFsRefusal` for the root-level files the watcher owns — the lock, the cursor, the mute
    switch. A net naming one of those subclasses is the same hand-kept list the net exists to
    replace, and the failure it produces is the one this whole lane is about: the refusal arriving
    as a stack trace with exit `1`, which reads as "nothing to do".

    The net is driven at the seam it actually wraps (`_dispatch`) rather than through a command,
    because no command can reach it with a `SafeFsRefusal` today: `inbox` normalizes every refusal
    from the chain into `LaneUnreadable`, and every site that can raise the other kind — the lock,
    the cursor, the mute switch — catches `PacketError` locally and degrades. That makes this a
    guard on the net's contract, not a description of a reachable bug: the next command added is the
    one it protects, which is exactly why it is checked here instead of left to that reviewer.
    """
    def refuse(_args):
        raise refusal(f"refused by the test: {refusal.__name__}")

    monkeypatch.setattr(cli, "_dispatch", refuse)

    assert main(["next"]) == 2, f"{refusal.__name__} left `main` without exit 2"
    assert refusal.__name__ in capsys.readouterr().err, "the refusal was not reported to the operator"


def test_the_cli_net_is_a_net_and_not_a_catch_all(monkeypatch):
    """...and it must not be widened into `except OSError`: that is the shape every finding had.

    A raw `OSError` out of the chain is a bug in the primitive, not an answer for the operator. If
    the net ever absorbs one, this test fails — so the net can be widened to `PacketError` without
    quietly becoming the `except OSError` the whole round was spent removing.
    """
    def break_the_chain(_args):
        raise OSError(errno.EIO, "a raw, unconverted failure")

    monkeypatch.setattr(cli, "_dispatch", break_the_chain)

    with pytest.raises(OSError):
        main(["next"])


# --------------------------------------------------------------------------------------------
# Finding 3 — one entry that cannot be interrogated costs one lane, not the whole pass.
# --------------------------------------------------------------------------------------------

def test_an_unstatable_entry_does_not_suppress_a_readable_packet_elsewhere(prepared, monkeypatch):
    """`stat_nolink` left `EIO` unwrapped and read `PermissionError` as "the name is free". Neither
    reached `_lane_scan` as a refusal, so one bad entry in `advice/` — a lane that gates nothing —
    aborted the watcher's whole pass and suppressed a real audit packet sitting in `pending/`."""
    bad = prepared / "advice" / "note.json"
    real_stat = os.stat

    def only_that_entry(path, *args, **kwargs):
        if kwargs.get("dir_fd") is not None and path == bad.name:
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(_safefs.os, "stat", only_that_entry)

    delta = watch.scan_new(prepared, Cursor())

    assert delta.new_packets, (
        f"a readable packet in pending/ was suppressed by an unreadable entry in advice/: {delta!r}"
    )
    assert delta.unreadable, "the lane that could not be read reported nothing at all"


def test_a_permission_error_is_never_read_as_a_free_name(prepared, monkeypatch):
    """The same defect one layer down, stated as the property: "I could not look" is not "it is not
    there". `None` is the answer that lets a caller pick a name and write to it."""
    _inject(monkeypatch, "stat", errno.EACCES)

    with pytest.raises(PacketError):
        _safefs.stat_nolink(0, "anything", what="the entry 'anything'")


# --------------------------------------------------------------------------------------------
# Finding 1 — the lock handle owns its descriptor.
# --------------------------------------------------------------------------------------------

def _open_descriptors() -> int:
    """How many descriptors this process holds. `/dev/fd` on macOS, `/proc/self/fd` on Linux."""
    for path in ("/dev/fd", "/proc/self/fd"):
        if os.path.isdir(path):
            return len(os.listdir(path))
    pytest.skip("no descriptor table to census on this platform")


def test_the_lock_leaks_no_descriptor_across_ticks(prepared):
    """`open_lockfile` returned a handle with `closefd=False`, so the caller's `close()` released
    the buffer and left the descriptor open — one per watcher tick and one per publish, forever.

    The census is taken after a warm-up pass, because the first pass legitimately opens things that
    stay open (a log handler, an import). What is asserted is that TWO HUNDRED more passes cost
    nothing, which is the leak's signature: a constant, and therefore invisible to any test that
    runs a pass or two.
    """
    def one_tick(_iterations=0):
        watch.dispatch_once(audit_cmd="", notify_fn=lambda *_a: True, run_fn=lambda *_a: 0)

    one_tick()                       # warm-up: imports, logging, caches
    before = _open_descriptors()
    for _ in range(200):
        one_tick()
    after = _open_descriptors()

    assert after == before, (
        f"200 watcher ticks leaked {after - before} descriptor(s) ({before} -> {after}): "
        f"the lock handle is not closing the descriptor it opened"
    )


def test_the_lock_leaks_no_descriptor_across_publishes(prepared):
    """The same leak on the publish path, which takes the lock once per packet."""
    inbox.publish(valid_packet(), root=prepared)
    before = _open_descriptors()
    for index in range(200):
        inbox.publish(valid_packet(packet_id=f"sweep-{index:03d}"), root=prepared)
    after = _open_descriptors()

    assert after == before, (
        f"200 publishes leaked {after - before} descriptor(s) ({before} -> {after}): "
        f"the publish lock is not closing the descriptor it opened"
    )


# --------------------------------------------------------------------------------------------
# Finding 4 — the cursor's byte cap bounds size, and size is not depth.
# --------------------------------------------------------------------------------------------

def test_a_deeply_nested_cursor_recovers_instead_of_killing_the_tick(prepared):
    """400KB of `[` is valid UTF-8, well under `MAX_CURSOR_BYTES`, and deeper than the interpreter
    will parse — so `json.loads` answers with a `RecursionError`. That is neither an `OSError` nor a
    `JSONDecodeError`, so it used to leave `load_cursor` past every handler and end the loop."""
    body = b"[" * 200_000
    assert len(body) < watch.MAX_CURSOR_BYTES, "the row must stay under the cap it is about"
    inbox._ensure_tree(prepared)
    (prepared / watch.CURSOR_NAME).write_bytes(body)

    cursor = watch.load_cursor(root=prepared)

    assert cursor == Cursor(), "a cursor too deep to parse must recover as no cursor"
    assert watch.dispatch_once(audit_cmd="", notify_fn=lambda *_a: True,
                               run_fn=lambda *_a: 0) is not None, (
        "the watcher pass after a nested cursor must still happen"
    )


@pytest.mark.parametrize("body,why", [
    (b'{"packets": "not-a-list"}', "a lane value that is not a list"),
    (b'{"packets": [1, 2, 3]}', "a lane list holding something that is not a filename"),
    (b'[1, 2, 3]', "a cursor that is not an object at all"),
    (b'{"packets": {"a": 1}}', "a cursor whose lane is an object"),
], ids=["string-lane", "non-string-items", "array-root", "object-lane"])
def test_a_wrong_shaped_cursor_recovers_and_says_why(prepared, body, why):
    """Tolerant must not mean SILENT: `Cursor.from_json` degrades quietly by design, so the reason
    has to be derived before the tolerance or a wrong-shaped cursor and an absent one look the
    same in the log."""
    from structlog.testing import capture_logs

    inbox._ensure_tree(prepared)
    (prepared / watch.CURSOR_NAME).write_bytes(body)

    with capture_logs() as logs:
        cursor = watch.load_cursor(root=prepared)

    assert cursor == Cursor(), f"{why}: must recover as no cursor"
    assert any(entry.get("event") == "twoperson.watch_cursor_unreadable" for entry in logs), (
        f"{why}: the recovery was silent — {logs}"
    )


# --------------------------------------------------------------------------------------------
# The errnos the sweep's rows are about, named once so a typo cannot silently narrow it.
# --------------------------------------------------------------------------------------------

def test_the_sweep_covers_the_errnos_the_findings_were_about():
    assert {errno.EIO, errno.EACCES, errno.ENOSPC} == set(ERRNOS)
    assert sorted(_TOLERATED) == ["close"], (
        "every tolerated syscall needs a written reason in the sweep's table"
    )


def test_every_syscall_the_primitive_calls_is_in_the_sweep():
    """The sweep's own coverage claim, asserted rather than described."""
    called = _safefs_syscalls()
    swept = set(SYSCALLS)
    assert called == swept, f"the sweep is not covering what the primitive calls: {called ^ swept}"
    assert len(swept) >= 13, f"the sweep collapsed to {len(swept)} rows: {sorted(swept)}"


# --------------------------------------------------------------------------------------------
# tpsync-r6 — four findings the widened sweep above would have caught on its own (all four are
# also swept: the release at `flock#2`/`_TOLERATED_AT`, the missing-root `mkdir#1`/the dedicated
# test above, and the cursor/mute-switch rows are driven by `watch:dispatch_once`/`watch:loop_once`
# through the same `index`-parametrized rows). These are kept as their own tests anyway because a
# dedicated test names the MECHANISM directly — which occurrence of which syscall, on which entry
# point — rather than leaving a reader to work it out from a `#3` in a parametrize id.
# --------------------------------------------------------------------------------------------

def test_close_is_attempted_exactly_once_and_never_retried_after_eintr(monkeypatch):
    """`close_quietly` used to retry `EINTR` once, on the theory that `EINTR` is the one errno that
    means the descriptor was NOT released. On Linux (and POSIX generally) that theory is wrong: the
    descriptor IS released the instant `close` is called, whatever it then reports, so a retry does
    not close "the same" fd again — there is none left — it closes whatever NUMBER the kernel has
    since handed to an unrelated `open` on another thread, silently closing THAT operation's file
    instead of this one.

    Proved here as a call count rather than an outcome, because the defect this guards against is
    silent by construction: a retried close never raises, it just closes the wrong descriptor.
    """
    calls = []
    real_close = os.close

    def once_then_fail(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise InterruptedError()
        return real_close(fd)

    monkeypatch.setattr(os, "close", once_then_fail)

    fd = os.open(os.devnull, os.O_RDONLY)
    _safefs.close_quietly(fd)

    assert calls == [fd], (
        f"close was attempted {len(calls)} time(s) — it must be attempted exactly once, or a retry "
        f"can close a DIFFERENT descriptor the kernel has since reused: {calls!r}"
    )
    os.close(fd)          # `once_then_fail` raised on the first attempt, so the real close never ran


def test_a_cursor_with_an_oversized_integer_recovers_instead_of_killing_the_tick(prepared):
    """A JSON integer of a few thousand digits is syntactically valid and well under
    `MAX_CURSOR_BYTES`, but Python 3.11+ refuses to convert a string that long to an `int` at all —
    `sys.set_int_max_str_digits`'s default 4300-digit limit — which is a plain `ValueError`, not a
    `json.JSONDecodeError` (a subclass, but not the one actually raised here). `load_cursor` used to
    catch `JSONDecodeError` and `RecursionError` but not the bare `ValueError`, so this sailed past
    every handler and would have killed the tick the same way the two already-tested shapes did.
    """
    body = (b'{"packets": [], "verdicts": [], "consults": [], "advice": ' + b"9" * 5000 + b"}")
    inbox._ensure_tree(prepared)
    (prepared / watch.CURSOR_NAME).write_bytes(body)

    cursor = watch.load_cursor(root=prepared)

    assert cursor == Cursor(), "a cursor with an oversized integer must recover as no cursor"
    assert watch.dispatch_once(audit_cmd="", notify_fn=lambda *_a: True,
                               run_fn=lambda *_a: 0) is not None, (
        "the watcher pass after an oversized-integer cursor must still happen"
    )


def test_an_unstatable_mute_switch_does_not_crash_dispatch_or_the_loop(prepared, monkeypatch):
    """`is_muted`'s `stat_nolink` call REFUSES (rather than answers) when the switch's occupancy
    cannot be determined at all — `EIO`, `EACCES`, an unsupported filesystem — and that refusal used
    to be left uncaught, so it propagated out of `is_muted`, through `dispatch_once` (which never
    catches a bare `PacketError` around its own `is_muted` calls), and killed `watch_loop`'s `while`
    on the first bad tick instead of costing that one tick.
    """
    fault = _inject(monkeypatch, "stat", errno.EIO, reached=_called_from_safefs)

    report = watch.dispatch_once(root=prepared, audit_cmd="", notify_fn=lambda *_a: True,
                                 run_fn=lambda *_a: 0)
    assert fault.fired, "the fault was never reached — this row proves nothing"
    assert report is not None, "a stat failure on the mute switch must degrade, not raise"

    fault.reset()
    acted = watch.watch_loop(prepared, max_passes=3, interval=0, audit_cmd="",
                             notify_fn=lambda *_a: True, run_fn=lambda *_a: 0)
    assert fault.fired, "the fault was never reached by the loop either"
    assert acted >= 0, "watch_loop must survive every pass rather than raising out of the while"


def test_a_failed_lock_release_does_not_crash_a_successful_publish(prepared, monkeypatch):
    """`fcntl.flock(handle, LOCK_UN)` used to sit outside `_safefs`'s one conversion point, called
    directly from `inbox._publish_lock`'s `finally` block: an `EIO` there — reachable on a filesystem
    where the lock file itself has gone bad after the publish already succeeded — became a raw
    `OSError` traceback replacing a SUCCESSFUL publish. `_safefs.unlock_quietly` now owns the release
    and drops the error the same way `close_quietly` already had to.
    """
    fault = _inject(monkeypatch, "flock", errno.EIO, holder=fcntl, at=2, reached=_called_from_safefs)

    path = inbox.publish(valid_packet(), root=prepared)

    assert fault.fired, "the fault was never reached — this row proves nothing"
    assert path.exists(), "a failed lock release must not undo an already-completed publish"
