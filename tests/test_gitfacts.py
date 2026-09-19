"""`twoperson.gitfacts`: deriving `changed_files`/`diff_summary` from git instead of trusting them.

Every scenario here is built on a REAL commit graph (`tests.fixtures.git_repo`), because the whole
point of this module is that it reads the repository, not the working tree or a packet's claims.
"""
from __future__ import annotations

import pytest

from tests.fixtures import git_repo
from twoperson.gitfacts import GitFactsError, concrete, derive, disagreement, resolvable
from twoperson.packet import UNKNOWN


def test_concrete_distinguishes_unknown_from_a_real_looking_sha():
    assert concrete("a" * 40) is True
    assert concrete("a" * 7) is True
    assert concrete(UNKNOWN) is False
    assert concrete("not-hex") is False
    assert concrete(None) is False


def test_resolvable_is_false_for_a_sha_this_repository_does_not_hold(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    repo.commit()
    assert resolvable(repo.path, "0" * 40) is False
    assert resolvable(repo.path, UNKNOWN) is False


def test_resolvable_is_true_for_real_commits(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    base = repo.commit("base")
    repo.write("a.txt", "one\ntwo\n")
    head = repo.commit("head")
    assert resolvable(repo.path, base, head) is True


def test_derive_reports_added_modified_deleted(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("keep.txt", "unchanged\n")
    repo.write("edit.txt", "line1\nline2\n")
    repo.write("gone.txt", "bye\n")
    base = repo.commit("base")
    repo.write("edit.txt", "line1\nline2\nline3\n")
    repo.rm("gone.txt")
    repo.write("new.txt", "hello\n")
    head = repo.commit("head")

    facts = derive(repo.path, base, head)
    by_path = {e["path"]: e for e in facts["changed_files"]}
    assert by_path["edit.txt"]["status"] == "modified"
    assert by_path["edit.txt"]["insertions"] == 1
    assert by_path["edit.txt"]["deletions"] == 0
    assert by_path["gone.txt"]["status"] == "deleted"
    assert by_path["new.txt"]["status"] == "added"
    assert "keep.txt" not in by_path
    assert facts["diff_summary"]["files_changed"] == 3
    assert facts["diff_summary"]["insertions"] == 2   # edit.txt +1, new.txt +1
    assert facts["diff_summary"]["deletions"] == 1    # gone.txt's one line


def test_derive_detects_a_rename_and_records_old_path(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("src/big.py", "\n".join(f"line {i}" for i in range(50)) + "\n")
    base = repo.commit("base")
    repo.mv("src/big.py", "src/renamed.py")
    repo.write("src/renamed.py", "\n".join(f"line {i}" for i in range(50)) + "\nextra\n")
    head = repo.commit("rename")

    facts = derive(repo.path, base, head)
    assert len(facts["changed_files"]) == 1
    entry = facts["changed_files"][0]
    assert entry["path"] == "src/renamed.py"
    assert entry["old_path"] == "src/big.py"
    assert entry["status"] == "renamed"
    assert entry["insertions"] == 1


def test_derive_refuses_a_sha_this_repository_does_not_hold(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    head = repo.commit()
    with pytest.raises(GitFactsError, match="not in this repository"):
        derive(repo.path, "0" * 40, head)


def test_derive_refuses_when_git_itself_fails(tmp_path, monkeypatch):
    """Git missing or erroring must be a refusal, never silently read as 'no changes'."""
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    base = repo.commit("base")
    repo.write("a.txt", "y\n")
    head = repo.commit("head")

    import twoperson.gitfacts as gitfacts_mod

    def _broken_run(*args, **kwargs):
        raise FileNotFoundError("git: command not found")

    monkeypatch.setattr(gitfacts_mod.subprocess, "run", _broken_run)
    with pytest.raises(GitFactsError):
        derive(repo.path, base, head)


def test_derive_caps_an_unreviewably_wide_change(tmp_path):
    import twoperson.gitfacts as gitfacts_mod
    repo = git_repo(tmp_path)
    base = repo.commit("base")
    for i in range(gitfacts_mod.MAX_DERIVED_FILES + 1):
        repo.write(f"file{i}.txt", "x\n")
    head = repo.commit("flood")
    with pytest.raises(GitFactsError, match="derivation cap"):
        derive(repo.path, base, head)


def test_disagreement_is_empty_when_the_packet_matches_the_head(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    base = repo.commit("base")
    repo.write("a.txt", "x\ny\n")
    head = repo.commit("head")
    facts = derive(repo.path, base, head)
    packet = {"diff_summary": facts["diff_summary"], "changed_files": facts["changed_files"]}
    assert disagreement(packet, facts) == []


def test_disagreement_catches_an_omitted_file():
    """The self-report gap this module closes: a file the head changed but the packet never listed."""
    facts = {
        "diff_summary": {"files_changed": 2, "insertions": 3, "deletions": 0},
        "changed_files": [
            {"path": "a.txt", "status": "modified", "insertions": 1, "deletions": 0},
            {"path": "tests/test_a.py", "status": "modified", "insertions": 2, "deletions": 0},
        ],
    }
    packet = {
        "diff_summary": {"files_changed": 1, "insertions": 1, "deletions": 0},
        "changed_files": [{"path": "a.txt", "status": "modified", "insertions": 1, "deletions": 0}],
    }
    problems = disagreement(packet, facts)
    assert any("tests/test_a.py" in p and "not in the packet" in p for p in problems)


def test_disagreement_catches_a_misreported_status():
    facts = {
        "diff_summary": {"files_changed": 1, "insertions": 1, "deletions": 1},
        "changed_files": [{"path": "a.txt", "status": "modified", "insertions": 1, "deletions": 1}],
    }
    packet = {
        "diff_summary": {"files_changed": 1, "insertions": 1, "deletions": 1},
        "changed_files": [{"path": "a.txt", "status": "added", "insertions": 1, "deletions": 1}],
    }
    problems = disagreement(packet, facts)
    assert any("status" in p and "'added'" in p and "'modified'" in p for p in problems)


def test_disagreement_catches_a_missing_old_path_on_a_rename():
    facts = {
        "diff_summary": {"files_changed": 1, "insertions": 0, "deletions": 0},
        "changed_files": [{"path": "new.py", "old_path": "old.py", "status": "renamed",
                          "insertions": 0, "deletions": 0}],
    }
    packet = {
        "diff_summary": {"files_changed": 1, "insertions": 0, "deletions": 0},
        "changed_files": [{"path": "new.py", "status": "renamed", "insertions": 0, "deletions": 0}],
    }
    problems = disagreement(packet, facts)
    assert any("old_path" in p and "'old.py'" in p for p in problems)


def test_disagreement_catches_a_stale_diffstat():
    facts = {
        "diff_summary": {"files_changed": 1, "insertions": 5, "deletions": 0},
        "changed_files": [{"path": "a.txt", "status": "modified", "insertions": 5, "deletions": 0}],
    }
    packet = {
        "diff_summary": {"files_changed": 1, "insertions": 2, "deletions": 0},
        "changed_files": [{"path": "a.txt", "status": "modified", "insertions": 2, "deletions": 0}],
    }
    problems = disagreement(packet, facts)
    assert any("diff_summary.insertions" in p for p in problems)
