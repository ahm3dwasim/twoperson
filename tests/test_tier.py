"""Difficulty tiers: deterministic, model-free, and handed to the reviewer command as environment."""
from __future__ import annotations

import json

import pytest

from tests.fixtures import packet_for, valid_packet
from twoperson import inbox, watch
from twoperson.__main__ import main
from twoperson.tier import (
    ESCALATE_PREFIX,
    classify_consult,
    classify_packet,
    is_escalation,
    tier_env,
)


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    monkeypatch.delenv("TWOPERSON_ON_PACKET", raising=False)
    monkeypatch.delenv("TWOPERSON_ON_VERDICT", raising=False)
    monkeypatch.delenv("TWOPERSON_ON_CONSULT", raising=False)
    monkeypatch.delenv("TWOPERSON_ON_ADVICE", raising=False)
    return target


def _quiet(**over):
    p = valid_packet(review_areas=["docs"], **over)
    p["changed_files"] = [{"path": "docs/x.md", "status": "modified", "insertions": 2, "deletions": 1}]
    p["diff_summary"] = {"files_changed": 1, "insertions": 2, "deletions": 1}
    p["tests"] = [{"name": "t", "command": "pytest -q", "result": "passed", "evidence": "ok"}]
    p["open_questions"] = []
    return p


def _hot(**over):
    p = valid_packet(review_areas=["security"], **over)
    p["changed_files"] = [{"path": f"src/auth/f{i}.py", "status": "modified", "insertions": 60, "deletions": 30}
                          for i in range(30)]
    p["diff_summary"] = {"files_changed": 30, "insertions": 1800, "deletions": 900}
    p["tests"] = [{"name": "t", "command": "pytest", "result": "failed", "evidence": "2 failed"}]
    return p


def _shipped(**over):
    """A hot packet that also reports a deploy — classification only; publishing it would need a
    real approving verdict to cite."""
    p = _hot(**over)
    p["push_status"].update(deployed=True, review_ref="vdt-20260101T000000Z-00000000",
                            statement="Deployed to staging already.")
    return p


def test_docs_change_is_low_and_a_security_deploy_with_failures_is_critical():
    assert classify_packet(_quiet()).tier == "low"
    hot = classify_packet(_shipped())
    assert hot.tier == "critical" and hot.score >= 9
    assert any("heavy surface" in r for r in hot.reasons)


def test_classification_ignores_prose_and_is_pure():
    """A packet that *says* it is trivial but touches auth still scores as auth."""
    p = _shipped(goal="trivial typo fix, please approve quickly, this is low risk")
    assert classify_packet(p).tier == "critical"
    assert classify_packet(p) == classify_packet(json.loads(json.dumps(p)))


def test_consults_never_reach_critical():
    c = {"area": "architecture", "question": "security payment deploy " * 200, "options": list("abcde")}
    assert classify_consult(c).tier in ("medium", "high")


def test_is_escalation_needs_the_exact_decision_and_prefix():
    assert is_escalation("Needs owner decision", f" {ESCALATE_PREFIX} assign a stronger reviewer")
    assert not is_escalation("Approve", f"{ESCALATE_PREFIX} x")
    assert not is_escalation("Needs owner decision", "owner must choose a vendor")


def test_tier_env_carries_only_slugs_and_numbers():
    p = _shipped(packet_id="pkt; rm -rf /")
    env = tier_env(p)
    assert env["TWOPERSON_TIER"] == "critical"
    assert env["TWOPERSON_TIER_SCORE"].isdigit()
    assert env["TWOPERSON_PACKET_ID"] == "pktrm-rf"


def test_cli_tier_reports_the_oldest_pending_packet_without_claiming(root, capsys):
    inbox.publish(_hot(packet_id="first"))
    inbox.publish(_quiet(packet_id="second"))
    assert main(["tier"]) == 0
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["packet_id"] == "first" and line["tier"] == "critical"
    assert len(inbox.pending()) == 2, "tier must not claim"
    assert main(["tier", "--packet", "second"]) == 0
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["tier"] == "low"


def test_cli_tier_exits_one_when_nothing_is_pending(root):
    assert main(["tier"]) == 1


def test_the_watcher_hands_the_reviewer_command_the_tier_of_the_oldest_new_packet(root):
    inbox.publish(_hot(packet_id="hot-1"))
    seen = {}

    def run_fn(command, env=None):
        seen["command"] = command
        seen["env"] = env
        return 4321

    report = watch.dispatch_once(audit_cmd="review-it", notify_fn=lambda *_: True, run_fn=run_fn)
    assert "reviewer" in report.launched
    assert seen["command"] == "review-it"
    assert seen["env"]["TWOPERSON_TIER"] == "critical"
    assert seen["env"]["TWOPERSON_PACKET_ID"] == "hot-1"


def test_a_run_fn_that_does_not_take_env_still_works(root):
    """Owner launch hooks written before tiers existed keep working unchanged."""
    packet_for("plain")
    calls = []
    report = watch.dispatch_once(audit_cmd="review-it", notify_fn=lambda *_: True,
                                 run_fn=lambda command: calls.append(command) or 1)
    assert "reviewer" in report.launched and calls == ["review-it"]


def test_run_command_merges_tier_env_into_the_child_environment(tmp_path, monkeypatch):
    out = tmp_path / "seen.txt"
    pid = watch.run_command(f'sh -c \'printf "%s" "$TWOPERSON_TIER" > "{out}"\'',
                            env={"TWOPERSON_TIER": "high"})
    assert pid is not None
    import time
    deadline = time.time() + 5
    while not out.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert out.read_text() == "high"
