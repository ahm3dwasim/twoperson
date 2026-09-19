"""Difficulty tiers: deterministic, model-free, and handed to the reviewer command as environment."""
from __future__ import annotations

import json

import pytest

from tests.fixtures import packet_for, valid_packet
from twoperson import inbox, watch
from twoperson.__main__ import main
from twoperson.tier import (
    DOCS_ONLY_CEILING,
    ESCALATE_PREFIX,
    _tier_for,
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


# --- Calibration -------------------------------------------------------------------------------
#
# The first bands were chosen by feel and were wrong in a way only a corpus shows. Replayed over 562
# real audited packets they gave low 9 / medium 92 / high 250 / critical 210: 82% of audits began at
# or above the second-most-expensive rung and 75% never touched the cheapest, while the top rung
# alone drew 78% of all audit input tokens against the cheapest rung's 3%. These guards pin the
# three fixes, and each fails on the behaviour that shipped before them.


def _heavy_change(paths):
    """A packet scoring well above the cap on every axis except which files it touches.

    Same heavy areas, same wide-and-large diff, same failing test in both calls below, so the only
    variable is the file list. Without that control these tests compare scoring noise, not the cap.
    """
    return valid_packet(
        review_areas=["security", "routing", "policy"],
        changed_files=[{"path": p, "status": "modified", "insertions": 40, "deletions": 10}
                       for p in paths],
        diff_summary={"files_changed": len(paths), "insertions": 900, "deletions": 400},
        tests=[{"name": "suite", "command": "pytest", "result": "failed", "evidence": "red"}],
    )


def test_disclosure_is_not_charged_as_risk():
    """`open_questions` and `tradeoffs` each used to add +1 — the packet paid for candour.

    Those two points were routinely the ones that carried an ordinary change over the `critical`
    line, so a packet that hid its uncertainty was given the cheaper reviewer.
    """
    bare = classify_packet(valid_packet(review_areas=["deploy"]))
    candid = classify_packet(valid_packet(
        review_areas=["deploy"],
        open_questions=["is this the right seam?", "should this be gated?"],
        tradeoffs=["a", "b", "c", "d"]))
    assert candid.score == bare.score


def test_a_docs_only_change_is_capped_below_high():
    """Prose about `security` and `routing` is not a change to security or routing."""
    docs = classify_packet(_heavy_change([f"docs/DOC_{i}.md" for i in range(29)] + ["README.md"]))
    assert docs.score == DOCS_ONLY_CEILING
    assert docs.tier == "medium"
    assert any("docs-only" in r for r in docs.reasons), docs.reasons


def test_one_executable_file_lifts_the_docs_cap():
    """The cap keys on the file list, never on how the packet describes itself."""
    mixed = classify_packet(_heavy_change([f"docs/DOC_{i}.md" for i in range(29)]
                                          + ["src/twoperson/inbox.py"]))
    assert mixed.score > DOCS_ONLY_CEILING
    assert not any("docs-only" in r for r in mixed.reasons)


@pytest.mark.parametrize("score,tier", [
    (0, "low"), (3, "low"), (4, "medium"), (6, "medium"), (7, "high"), (8, "high"),
    (9, "critical"), (99, "critical"),
])
def test_the_bands(score, tier):
    """Pinned individually. The old bands made 3 medium and 6 high, and those two off-by-one steps
    are what put ordinary work on expensive rungs."""
    assert _tier_for(score) == tier

# --- the prose ceiling is asked of the FILE, not of its directory --------------------------------
#
# `startswith("docs/")` stood in for "is this a document" and so answered a question about the
# DIRECTORY. It handed the prose ceiling to `docs/deploy.py` — a program on the deploy path — while
# scoring `src/deploy.py` as the deploy change it is, and it gave that same ceiling to every `.txt`,
# including the dependency manifests, which are input that gets installed.
#
# The cap only bites above `DOCS_ONLY_CEILING`, so every case below is scored well past it. Nine
# files carry the file-count bump; the control differs from the case ONLY in the basename shape.

def _nine(path):
    """Nine files of the same shape as ``path`` — enough to score past the ceiling either way."""
    head, dot, tail = path.rpartition(".")
    if not dot or "/" in tail:
        return [f"{path}-{i}" for i in range(9)]
    return [f"{head}-{i}.{tail}" for i in range(9)]


def test_a_file_under_docs_is_scored_by_its_own_extension_not_its_directory():
    """The probe: the same file, under a different directory, scored differently — the only thing
    that changed was the directory name."""
    in_docs = classify_packet(_heavy_change(_nine("docs/deploy.py")))
    in_src = classify_packet(_heavy_change(_nine("src/deploy.py")))

    assert in_docs.score == in_src.score, (
        f"docs/deploy.py scored {in_docs.score} against src/deploy.py's {in_src.score}: the cap is "
        "reading the directory, not the file"
    )
    assert in_docs.score > DOCS_ONLY_CEILING
    assert not any("docs-only" in r for r in in_docs.reasons), in_docs.reasons


@pytest.mark.parametrize("path", ["requirements.txt", "requirements-dev.txt", "constraints.txt"])
def test_a_dependency_manifest_is_not_prose(path):
    """`.txt` is the prose extension; a manifest is what gets INSTALLED, so a changed pin is a
    change to what runs. Read against a control that differs only in the basename."""
    manifest = classify_packet(_heavy_change(_nine(path)))
    prose = classify_packet(_heavy_change(_nine("notes.txt")))

    assert prose.score == DOCS_ONLY_CEILING, "plain .txt stopped being prose"
    assert manifest.score > DOCS_ONLY_CEILING, f"{path} was given the prose ceiling"
    assert not any("docs-only" in r for r in manifest.reasons), manifest.reasons


@pytest.mark.parametrize("path", ["docs/guide.md", "guide.rst", "notes/TODO.txt", "README.md"])
def test_prose_is_capped_wherever_it_lives(path):
    """The other direction, kept: a document is a document outside `docs/` too."""
    capped = classify_packet(_heavy_change(_nine(path)))
    assert capped.score == DOCS_ONLY_CEILING
    assert any("docs-only" in r for r in capped.reasons), capped.reasons


@pytest.mark.parametrize("path", ["docs/config.yaml", "docs/Makefile", "src/app.py", "docs/note"])
def test_a_path_that_is_not_prose_keeps_its_score(path):
    """Never prose by assumption: anything an interpreter or an installer can act on, and anything
    with no extension at all, keeps whatever it scored."""
    uncapped = classify_packet(_heavy_change(_nine(path)))
    assert uncapped.score > DOCS_ONLY_CEILING
    assert not any("docs-only" in r for r in uncapped.reasons), uncapped.reasons
