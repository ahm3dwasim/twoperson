"""A minimal VALID review packet, plus helpers to break exactly one field at a time.

Every handoff test starts from ``valid_packet()`` and mutates one thing, so a failure names the
rule that broke rather than "the schema".
"""
from __future__ import annotations

import copy
import os
import pathlib
import subprocess
import sys
from typing import Any

from twoperson import _safefs

#: `-c` overrides, not global config: a test repo must never depend on — or pollute — the
#: developer's own `~/.gitconfig` (name, email, default branch, signing).
_GIT_ENV = ("-c", "user.name=test", "-c", "user.email=test@example.com",
           "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main")


class GitRepo:
    """A throwaway git repository for `gitfacts`/`citations` tests, addressed by real commits.

    Both modules read the repository at a named head through git plumbing, never the working tree
    (see docs/PROTOCOL.md §3a), so a test that exercises them has to commit real content rather than
    only writing files to disk.
    """

    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self._run("init", "-q")

    def _run(self, *args: str) -> str:
        result = subprocess.run(("git", *_GIT_ENV, *args), cwd=self.path,
                                capture_output=True, text=True, check=False)
        assert result.returncode == 0, f"git {args} failed: {result.stderr}"
        return result.stdout

    def write(self, relpath: str, content: str) -> None:
        target = self.path / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def rm(self, relpath: str) -> None:
        (self.path / relpath).unlink()

    def mv(self, src: str, dst: str) -> None:
        self._run("mv", src, dst)

    def commit(self, message: str = "commit") -> str:
        self._run("add", "-A")
        self._run("commit", "-q", "-m", message, "--allow-empty")
        return self._run("rev-parse", "HEAD").strip()

    def head(self) -> str:
        return self._run("rev-parse", "HEAD").strip()


def git_repo(tmp_path: pathlib.Path) -> GitRepo:
    """A fresh `GitRepo` under ``tmp_path``. Not a pytest fixture itself — call it from one, so
    each test picks its own subdirectory name rather than sharing a fixture-scoped repo."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(exist_ok=True)
    return GitRepo(repo_dir)


def valid_packet(**overrides: Any) -> dict:
    packet: dict[str, Any] = {
        "schema_version": "1",
        "packet_id": "reviewer-handoff-bridge-001",
        "created_at": "2026-08-19T09:30:00Z",
        "task_id": "task-reviewer-bridge",
        "session_id": "sess-abc123",
        "run_id": "run-000042",
        "goal": "Durable Builder->Reviewer handoff bridge.",
        "acceptance_criteria": ["A valid packet lands atomically in the inbox."],
        "git": {
            "branch": "worktree-reviewer-handoff-bridge",
            "base_ref": "origin/main",
            "base_sha": "a50fad98d5e189e549b2fa3af6299d66c29fb4c2",
            "head_sha": "0" * 40,
        },
        "diff_summary": {"files_changed": 2, "insertions": 120, "deletions": 3},
        "changed_files": [
            {"path": "src/twoperson/packet.py", "status": "added", "insertions": 100, "deletions": 0},
            {"path": "tests/test_packet.py", "status": "added", "insertions": 20, "deletions": 3},
        ],
        "tests": [
            {"name": "handoff suite", "command": "pytest tests", "result": "passed",
             "evidence": "12 passed"},
        ],
        "evidence": [{"kind": "test-log", "ref": "tests", "note": "focused suite"}],
        "model_class": {
            "account_class": "high-capacity",
            "primary_model": "builder-opus-5",
            "reviewer_model": "reviewer",
            "session_kind": "fresh-bounded",
        },
        "impact": {
            "cost_usd": 0.42,
            "cache_read_tokens": 100000,
            "cache_creation_tokens": 8000,
            "input_tokens": 110000,
            "output_tokens": 9000,
            "latency_s": 61.5,
            "model_calls": 7,
        },
        "review_areas": ["policy/security", "operator law"],
        "tradeoffs": ["Fail-closed on suspected secrets can reject a legitimate packet."],
        "open_questions": ["Should retries be capped per host or globally?"],
        "push_status": {
            "pushed": False,
            "deployed": False,
            "restarted": False,
            "remotes_touched": [],
            "review_ref": "unknown",
            "statement": "No push, no deploy, no restart, no remote changes.",
        },
    }
    packet.update(overrides)
    return copy.deepcopy(packet)


def without(field: str) -> dict:
    """A packet with one required top-level field removed."""
    packet = valid_packet()
    packet.pop(field, None)
    return packet


def packet_for(packet_id: str, head_sha: str = "0900128", **overrides: Any) -> dict:
    """Publish a valid packet with ``packet_id`` at ``head_sha`` and return it.

    Verdicts bind to a real packet in the inbox, so a test that records a verdict publishes the
    packet it answers first. ``head_sha`` defaults to the short sha the verdict tests approve.
    """
    from twoperson import inbox
    packet = valid_packet(packet_id=packet_id, **overrides)
    packet["git"]["head_sha"] = head_sha
    inbox.publish(packet)
    return packet


# --------------------------------------------------------------------------------------------
# A hang cannot pass as a pass.
#
# A hostile filesystem entry that blocks an open does not return an error and does not raise — it
# does not finish at all. So a test for it cannot be written as "call this and assert"; without a
# guard, a regression HANGS the suite instead of failing it, which reads as an infrastructure
# problem rather than a defect and gets re-run rather than fixed. Every blocking-entry test in this
# suite runs its call through `guarded`, which turns "never came back" into a named failure.
# --------------------------------------------------------------------------------------------

#: Long enough that a slow machine is never a failure, short enough that a regression cannot hold
#: the suite: a blocked open does not finish at all, so the timeout is not a duration to tune.
FIFO_GUARD_SECONDS = 20


def guarded(fn, *args, **kwargs):
    """Run ``fn`` in a daemon thread and fail if it has not finished — a hang cannot pass as a pass.

    The blocked open cannot be cancelled from here (that is the point: a thread stuck in `openat` is
    not interruptible), so the thread is a daemon and the SUITE still finishes. What it buys is the
    assertion: a regression reports "blocked on a FIFO entry" instead of hanging CI.
    """
    import threading

    box: dict = {}

    def run():
        try:
            box["value"] = fn(*args, **kwargs)
        except BaseException as exc:      # noqa: BLE001 - re-raised in the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(FIFO_GUARD_SECONDS)
    assert not thread.is_alive(), (
        f"{getattr(fn, '__name__', fn)} blocked on a FIFO entry — the reader is uninterruptible, "
        f"which is the defect: {FIFO_GUARD_SECONDS}s with no answer"
    )
    if "error" in box:
        raise box["error"]
    return box.get("value")


# --------------------------------------------------------------------------------------------
# Fault injection at the SYSCALL, confined to this package's own frames.
#
# A suite that patches ``os.write`` outright also disarms pytest's capture and its logging handlers,
# because those write with the same function: the injected failure lands in the test harness instead
# of in the code under test, and the row either errors for the wrong reason or passes for one. The
# raiser below looks at the CALLER instead — it fails a call only when a frame of ``twoperson`` is on
# the stack — so the fault is injected precisely where the contract is being tested and nowhere else.
# --------------------------------------------------------------------------------------------

#: The package whose frames the injector is allowed to break.
PACKAGE_DIR = pathlib.Path(_safefs.__file__).resolve().parent

#: The primitive itself — narrower than `PACKAGE_DIR`. See `_called_from_safefs`.
PRIMITIVE_FILE = pathlib.Path(_safefs.__file__).resolve()


def _called_from_package() -> bool:
    """Is a frame of this package on the stack above the injected call?"""
    frame = sys._getframe(2)            # 0 = here, 1 = the raiser, 2 = the raiser's caller
    while frame is not None:
        filename = frame.f_code.co_filename
        if filename.startswith(str(PACKAGE_DIR) + os.sep):
            return True
        frame = frame.f_back
    return False


def _called_from_safefs() -> bool:
    """Is a `_safefs.py` frame on the stack above the injected call? Narrower than
    `_called_from_package`, and what the syscall SWEEP wants: `SYSCALLS` is parsed out of
    `_safefs.py`'s own source, and the structural guard in `test_safefs_guard.py` proves no other
    module may make one of these calls — so every occurrence the sweep needs to fault already has
    `_safefs.py` on the stack. `_called_from_package` is wider on purpose for the single-fault tests
    elsewhere in this file, but that width is a liability for an INDEXED sweep: a caller like
    `inbox._assert_inside` reaches `os.stat` too, by way of `pathlib.Path.resolve(strict=False)`,
    which is documented to swallow any `OSError` its internal `stat` raises and never propagate it —
    so faulting THAT occurrence proves nothing and would misnumber every real occurrence after it.
    """
    frame = sys._getframe(2)
    while frame is not None:
        if frame.f_code.co_filename == str(PRIMITIVE_FILE):
            return True
        frame = frame.f_back
    return False


class Fault:
    """A monkeypatch target that fails with one errno — inside this package, and only there.

    ``fired`` is what makes a sweep assertion honest: a driver can only be required to REFUSE when
    the syscall it was told about was actually reached. Without the flag, a row for a syscall a given
    entry point never calls would have to choose between asserting nothing and asserting something
    false, and a sweep full of the first is a sweep that cannot fail.

    ``at`` decides WHICH matching call fails: ``None`` (the default) fails every one, which is what
    every single-fault test in this file wants — the syscall named is broken for the whole driver run.
    An integer fails only the Nth call reached from a package frame and lets every other one through
    to the real function. That is what the driver-independent sweep needs: `fcntl.flock` is called
    twice by every locking driver (`LOCK_EX` to acquire, `LOCK_UN` to release), and a `Fault` that
    always fires never lets a driver past the acquire to reach the release at all — which is exactly
    how the release being unconverted escaped three prior audit rounds.
    """

    def __init__(self, errno_value: int, real, detail: str = "", at: int | None = None,
                reached=_called_from_package):
        self.errno_value = errno_value
        self.real = real
        self.detail = detail or os.strerror(errno_value)
        self.fired = False
        self.calls = 0
        self.at = at
        #: Which stack-scope counts as "reached" — `_called_from_package` by default (every
        #: single-fault test in this file wants that width); the indexed sweep passes
        #: `_called_from_safefs` instead. See that function's docstring for why the two must not be
        #: mixed within one count-then-fault pass.
        self._reached = reached
        #: Disarmed while a test BUILDS the tree a driver is about to be run against: a fault that
        #: is armed during setup breaks the setup, and then the row reports "there was nothing
        #: there" as if it were "the operation refused".
        self.armed = True

    def __call__(self, *args, **kwargs):
        if self.armed and self._reached():
            self.calls += 1
            if self.at is None or self.calls == self.at:
                self.fired = True
                raise OSError(self.errno_value, self.detail)
        return self.real(*args, **kwargs)

    def reset(self) -> None:
        self.fired = False
        self.calls = 0


def inject(monkeypatch, name: str, errno_value: int, *, holder=None, attr: str | None = None,
          at: int | None = None, reached=_called_from_package) -> Fault:
    """Make ``holder.name`` (default: ``os.name``) fail with ``errno_value`` inside this package.

    ``attr`` names the real callable when it is not the attribute being replaced — for a patch on a
    METHOD, where the attribute and the callable are the same object read off a different holder.
    ``at`` and ``reached`` are passed straight through to `Fault` — see its docstring.
    """
    holder = os if holder is None else holder
    fault = Fault(errno_value, getattr(holder, attr or name), at=at, reached=reached)
    monkeypatch.setattr(holder, name, fault)
    return fault
