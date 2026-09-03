"""A minimal VALID review packet, plus helpers to break exactly one field at a time.

Every handoff test starts from ``valid_packet()`` and mutates one thing, so a failure names the
rule that broke rather than "the schema".
"""
from __future__ import annotations

import copy
from typing import Any


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
