"""A minimal VALID review packet, plus helpers to break exactly one field at a time.

Every handoff test starts from ``valid_packet()`` and mutates one thing, so a failure names the
rule that broke rather than "the schema".
"""
from __future__ import annotations

import copy
import os
import pathlib
import sys
from typing import Any

from twoperson import _safefs


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


def _called_from_package() -> bool:
    """Is a frame of this package on the stack above the injected call?"""
    frame = sys._getframe(2)            # 0 = here, 1 = the raiser, 2 = the raiser's caller
    while frame is not None:
        filename = frame.f_code.co_filename
        if filename.startswith(str(PACKAGE_DIR) + os.sep):
            return True
        frame = frame.f_back
    return False


def fault(errno_value: int, real, detail: str = ""):
    """A replacement for ``real`` that raises ``OSError(errno_value)`` — from this package only."""
    def raiser(*args, **kwargs):
        if _called_from_package():
            raise OSError(errno_value, detail or os.strerror(errno_value))
        return real(*args, **kwargs)
    return raiser


def inject(monkeypatch, name: str, errno_value: int, *, holder=None, attr: str | None = None):
    """Make ``holder.name`` (default: ``os.name``) fail with ``errno_value`` inside this package.

    ``attr`` names the real callable when it is not the attribute being replaced — for a patch that
    installs a PROXY (an ``os.fdopen`` that returns a handle whose ``read`` fails, say).
    """
    holder = os if holder is None else holder
    real = getattr(holder, attr or name)
    monkeypatch.setattr(holder, name, fault(errno_value, real))
    return real
