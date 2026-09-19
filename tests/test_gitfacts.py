"""`twoperson.gitfacts`: deriving `changed_files`/`diff_summary` from git instead of trusting them.

Every scenario here is built on a REAL commit graph (`tests.fixtures.git_repo`), because the whole
point of this module is that it reads the repository, not the working tree or a packet's claims.
"""
from __future__ import annotations

import pytest

from tests.fixtures import git_repo
from twoperson.gitfacts import GitFactsError, concrete, derive, disagreement, resolvable
from twoperson.packet import UNKNOWN

# --------------------------------------------------------------------------------------------
# derive() must refuse a base that only RESOLVES, when it does not actually describe the head's
# history — a base equal to the head, an unrelated commit, or one not reachable from base_ref.
# --------------------------------------------------------------------------------------------


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

    import twoperson._gitrun as gitrun_mod

    def _broken_popen(*args, **kwargs):
        raise FileNotFoundError("git: command not found")

    monkeypatch.setattr(gitrun_mod.subprocess, "Popen", _broken_popen)
    with pytest.raises(GitFactsError):
        derive(repo.path, base, head)


def test_derive_refuses_base_equal_to_head(tmp_path):
    """`base_sha == head_sha` resolves fine and "derives" an empty diff for ANY packet — exactly the
    bypass this closes: a shipped report could name any commit as both its base and its head and
    walk away with a clean, empty, "derived" diffstat regardless of what actually changed."""
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    head = repo.commit("only commit")
    with pytest.raises(GitFactsError, match="same commit"):
        derive(repo.path, head, head)


def test_derive_refuses_an_abbreviated_base_equal_to_the_full_head(tmp_path):
    """`base_sha` and `head_sha` are abbreviated independently by whoever wrote the packet — an
    abbreviated base naming the SAME commit as a full head must be caught by resolving both to
    their full commit id first, not by comparing the strings the packet happened to spell. Before
    this fix, `base_sha == head_sha` compared the strings, missed this pair, and let `_is_ancestor`
    (correctly, per git's own definition that a commit is its own ancestor) wave it through to
    "derive" an empty diff stamped `diff_provenance: "derived"`."""
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    head = repo.commit("only commit")
    abbreviated_base = head[:12]
    assert abbreviated_base != head  # unequal as strings — the exact shape of the bypass
    with pytest.raises(GitFactsError, match="same commit"):
        derive(repo.path, abbreviated_base, head)


def test_derive_accepts_an_empty_diff_between_genuinely_distinct_commits(tmp_path):
    """An empty diff between two DIFFERENT commits (an empty follow-up commit, same tree as its
    parent) is not a git failure — it is simply true, and `gitfacts.derive` has no notion of
    "shipped" to refuse it on. The refusal for THIS shape belongs to
    `inbox._refuse_empty_shipped_diff`, layered on top of this general-purpose deriver — see
    `tests/test_inbox_diff_evidence.py`."""
    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    base = repo.commit("base")
    head = repo.commit("empty follow-up")  # GitRepo.commit always passes --allow-empty
    assert base != head
    facts = derive(repo.path, base, head)
    assert facts["diff_summary"]["files_changed"] == 0
    assert facts["changed_files"] == []


def test_derive_refuses_a_base_unrelated_to_the_head(tmp_path):
    """A `base_sha` that resolves but is not in the head's history at all — a different branch, a
    stale fork point, a typo — must not be silently treated as "the" base to diff against."""
    repo = git_repo(tmp_path)
    repo.write("common.txt", "shared\n")
    root = repo.commit("root")
    repo._run("checkout", "-q", "-b", "side", root)
    repo.write("side.txt", "side\n")
    unrelated = repo.commit("side branch")
    repo._run("checkout", "-q", "main")
    repo.write("main.txt", "main\n")
    head = repo.commit("main branch")
    with pytest.raises(GitFactsError, match="not an ancestor"):
        derive(repo.path, unrelated, head)


def test_derive_accepts_a_real_ancestor(tmp_path):
    """The positive case for the ancestry check: a genuine parent commit is accepted exactly as
    before this closed the base==head / unrelated-base gaps."""
    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    base = repo.commit("base")
    repo.write("a.txt", "one\ntwo\n")
    head = repo.commit("head")
    facts = derive(repo.path, base, head)
    assert facts["diff_summary"]["files_changed"] == 1


def test_derive_refuses_a_base_not_reachable_from_base_ref(tmp_path):
    """`base_ref` names a real, resolvable branch in this checkout, but `base_sha` is not on it —
    the packet's declared base is not on the branch it claims to be based on."""
    repo = git_repo(tmp_path)
    repo.write("common.txt", "shared\n")
    root = repo.commit("root")
    repo._run("branch", "-q", "release", root)
    repo.write("main.txt", "main\n")
    on_main_only = repo.commit("main-only")
    repo.write("more.txt", "more\n")
    head = repo.commit("head")
    with pytest.raises(GitFactsError, match="not reachable from base_ref"):
        derive(repo.path, on_main_only, head, base_ref="release")


def test_derive_accepts_a_base_reachable_from_base_ref(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    base = repo.commit("base")
    repo._run("branch", "-q", "release", base)
    repo.write("a.txt", "one\ntwo\n")
    head = repo.commit("head")
    facts = derive(repo.path, base, head, base_ref="release")
    assert facts["diff_summary"]["files_changed"] == 1


def test_derive_skips_the_base_ref_check_when_the_ref_does_not_resolve_locally(tmp_path):
    """`base_ref` naming an unfetched remote-tracking ref (or the schema's own `unknown` default)
    must not be treated as a refusal — the check simply is not attempted, same as derivation itself
    against a non-concrete head."""
    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    base = repo.commit("base")
    repo.write("a.txt", "one\ntwo\n")
    head = repo.commit("head")
    facts = derive(repo.path, base, head, base_ref="origin/main")
    assert facts["diff_summary"]["files_changed"] == 1


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
