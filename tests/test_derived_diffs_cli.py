"""End-to-end: `verify`/`publish` deriving diff evidence and checking `tests[]` citations against
a REAL repository, driven through the CLI exactly as a builder session would call it.
"""
from __future__ import annotations

import json

import pytest

from tests.fixtures import git_repo, valid_packet
from twoperson import inbox
from twoperson.__main__ import main


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    return target


def _write(tmp_path, packet, name="packet.json"):
    path = tmp_path / name
    path.write_text(json.dumps(packet), encoding="utf-8")
    return str(path)


def test_publish_derives_and_stores_the_real_diff(root, tmp_path, monkeypatch, capsys):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    base = repo.commit("base")
    repo.write("a.txt", "one\ntwo\n")
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    packet = valid_packet(
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[{"path": "a.txt", "status": "modified", "insertions": 1, "deletions": 0}],
        diff_summary={"files_changed": 1, "insertions": 1, "deletions": 0},
    )
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 0, err
    assert "diff evidence derived" in err

    (_path, published), = [(p, inbox._load(p)) for p in inbox.pending()]
    assert published["diff_provenance"] == "derived"
    assert published["changed_files"] == [
        {"path": "a.txt", "status": "modified", "insertions": 1, "deletions": 0}]


def test_publish_refuses_a_stated_diff_that_does_not_match_the_head(root, tmp_path, monkeypatch, capsys):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    base = repo.commit("base")
    repo.write("a.txt", "one\ntwo\n")
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    packet = valid_packet(git={"branch": "b", "base_ref": "origin/main",
                              "base_sha": base, "head_sha": head})
    # The shared fixture's changed_files names files this diff never touched.
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "does not describe the head" in err
    assert inbox.pending() == []


def test_publish_refuses_an_omitted_test_file(root, tmp_path, monkeypatch, capsys):
    """The self-report gap: a test the head shows as changed, left off `changed_files`."""
    repo = git_repo(tmp_path)
    repo.write("src/thing.py", "x = 1\n")
    repo.write("tests/test_thing.py", "def test_x(): assert True\n")
    base = repo.commit("base")
    repo.write("src/thing.py", "x = 2\n")
    repo.write("tests/test_thing.py", "def test_x(): assert False\n")
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    packet = valid_packet(
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[{"path": "src/thing.py", "status": "modified", "insertions": 1,
                        "deletions": 1}],
        diff_summary={"files_changed": 1, "insertions": 1, "deletions": 1},
    )
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "tests/test_thing.py" in err
    assert "not in the packet" in err
    assert inbox.pending() == []


def test_publish_stores_the_derived_per_file_counts_even_when_only_totals_were_checked(
    root, tmp_path, monkeypatch, capsys,
):
    """`disagreement()` checks totals and path/status/old_path, not per-file line counts — so a
    builder who swaps the insertions/deletions between two files with matching totals is not
    refused by it. The published packet must still carry the CORRECT per-file numbers, because the
    whole `changed_files` list is replaced by the derived one, not patched around the checks."""
    repo = git_repo(tmp_path)
    repo.write("a.txt", "1\n")
    repo.write("b.txt", "1\n2\n3\n")
    base = repo.commit("base")
    repo.write("a.txt", "1\n2\n3\n4\n")   # +3
    repo.write("b.txt", "1\n2\n3\n4\n5\n")  # +2
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    # Swapped: a.txt claims +2, b.txt claims +3 — same total (+5), wrong per file.
    packet = valid_packet(
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[
            {"path": "a.txt", "status": "modified", "insertions": 2, "deletions": 0},
            {"path": "b.txt", "status": "modified", "insertions": 3, "deletions": 0},
        ],
        diff_summary={"files_changed": 2, "insertions": 5, "deletions": 0},
    )
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    assert rc == 0, capsys.readouterr().err

    published = inbox._load(inbox.pending()[0])
    by_path = {e["path"]: e for e in published["changed_files"]}
    assert by_path["a.txt"]["insertions"] == 3
    assert by_path["b.txt"]["insertions"] == 2


def test_a_draft_with_no_concrete_head_is_not_refused(root, tmp_path, capsys):
    packet = valid_packet(git={"branch": "b", "base_ref": "origin/main",
                              "base_sha": "unknown", "head_sha": "unknown"})
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 0, err
    assert "does not name a concrete" in err
    published = inbox._load(inbox.pending()[0])
    assert published["diff_provenance"] == "claimed"


def test_git_failing_is_a_refusal_never_a_silent_pass(root, tmp_path, monkeypatch, capsys):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "1\n")
    base = repo.commit("base")
    repo.write("a.txt", "1\n2\n")
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    import twoperson.gitfacts as gitfacts_mod

    def _broken(*args, **kwargs):
        raise FileNotFoundError("git: command not found")

    monkeypatch.setattr(gitfacts_mod.subprocess, "run", _broken)

    packet = valid_packet(git={"branch": "b", "base_ref": "origin/main",
                              "base_sha": base, "head_sha": head})
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    assert rc == 2
    assert inbox.pending() == []


# --------------------------------------------------------------------------------------------
# tests[] citations
# --------------------------------------------------------------------------------------------

def test_publish_refuses_a_tests_row_citing_a_symbol_the_head_does_not_contain(
    root, tmp_path, monkeypatch, capsys,
):
    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "def _helper():\n    pass\n")
    base = repo.commit("still true")
    repo.write("pkg/mod.py", "def _other():\n    pass\n")
    head = repo.commit("went stale")  # a real, proper ancestor relationship — see gitfacts.derive
    monkeypatch.chdir(repo.path)

    packet = valid_packet(
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[{"path": "pkg/mod.py", "status": "modified", "insertions": 1,
                        "deletions": 1}],
        diff_summary={"files_changed": 1, "insertions": 1, "deletions": 1},
        tests=[{"name": "probe", "command": "call `_helper()` directly", "result": "passed",
               "evidence": "n/a"}],
    )
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "_helper" in err
    assert "cannot be repeated" in err
    assert inbox.pending() == []


def test_publish_accepts_a_tests_row_whose_citation_resolves(root, tmp_path, monkeypatch, capsys):
    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "def _helper():\n    pass\n")
    base = repo.commit("base")
    head = repo.commit("head")  # an empty commit: a real ancestor, with nothing left to diff
    monkeypatch.chdir(repo.path)

    packet = valid_packet(
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[], diff_summary={"files_changed": 0, "insertions": 0, "deletions": 0},
        tests=[{"name": "probe", "command": "call `_helper()` directly", "result": "passed",
               "evidence": "n/a"}],
    )
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 0, err
    assert "test citations" in err


def test_no_derive_skips_citations_too(root, tmp_path, monkeypatch, capsys):
    """`--no-derive` is the checkout-does-not-hold-the-commits escape hatch for BOTH checks: a
    stale citation is exactly as unverifiable there as a stale diffstat."""
    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "def _other():\n    pass\n")
    head = repo.commit()
    monkeypatch.chdir(repo.path)

    packet = valid_packet(
        git={"branch": "b", "base_ref": "origin/main", "base_sha": head, "head_sha": head},
        tests=[{"name": "probe", "command": "call `_never_existed_anywhere()` directly",
               "result": "passed", "evidence": "n/a"}],
    )
    rc = main(["publish", "--no-derive", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 0, err
    assert "citations NOT verified" in err
    assert inbox.pending() != []


def test_a_renamed_test_needs_acknowledgment_at_the_derived_path(root, tmp_path, monkeypatch, capsys):
    """End to end: a renamed test is derived with `old_path` set, the ack gate reads the PUBLISHED
    (derived) `changed_files` back off the reviewed packet, and a ship report is blocked until the
    verdict names that exact path."""
    from twoperson.testset import altered_test_files
    from twoperson.verdict import build_verdict

    repo = git_repo(tmp_path)
    repo.write("tests/test_old.py", "def test_x():\n    assert True\n" * 5)
    base = repo.commit("base")
    repo.mv("tests/test_old.py", "tests/test_new.py")
    head = repo.commit("rename")
    monkeypatch.chdir(repo.path)

    rename_entry = {"path": "tests/test_new.py", "old_path": "tests/test_old.py",
                    "status": "renamed", "insertions": 0, "deletions": 0}
    assert altered_test_files([rename_entry]) == ["tests/test_new.py"]

    def _ship(packet_id: str, review_ref: str) -> dict:
        packet = valid_packet(
            packet_id=packet_id,
            git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
            changed_files=[rename_entry],
            diff_summary={"files_changed": 1, "insertions": 0, "deletions": 0},
        )
        packet["push_status"].update(pushed=True, review_ref=review_ref,
                                     statement="Shipped after the recorded approval.")
        return packet

    # A prior packet for the reviewer to have actually looked at — published `derive=True` so its
    # own diff evidence is library-verified, which the ship gate now requires of the packet a cited
    # approval reviewed (not only of the ship report itself).
    inbox.publish(valid_packet(
        packet_id="reviewed-1",
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[rename_entry],
        diff_summary={"files_changed": 1, "insertions": 0, "deletions": 0},
    ), derive=True)

    unacked = inbox.publish_verdict(
        build_verdict(packet_id="reviewed-1", decision="Approve", head_sha=head)).stem
    rc = main(["publish", "--from", _write(tmp_path, _ship("ship-1", unacked), name="ship1.json")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "altered tests" in err
    assert "tests/test_new.py" in err

    acked = inbox.publish_verdict(
        build_verdict(packet_id="reviewed-1", decision="Approve", head_sha=head,
                      acknowledged_tests=["tests/test_new.py"])).stem
    rc = main(["publish", "--from", _write(tmp_path, _ship("ship-2", acked), name="ship2.json")])
    assert rc == 0, capsys.readouterr().err


# --------------------------------------------------------------------------------------------
# A derived diff must be of the head against a real base — not merely two shas that both resolve.
# --------------------------------------------------------------------------------------------

def test_publish_refuses_when_base_equals_head(root, tmp_path, monkeypatch, capsys):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    head = repo.commit("only commit")
    monkeypatch.chdir(repo.path)

    packet = valid_packet(git={"branch": "b", "base_ref": "origin/main",
                              "base_sha": head, "head_sha": head})
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "same commit" in err
    assert inbox.pending() == []


def test_publish_refuses_a_base_unrelated_to_head(root, tmp_path, monkeypatch, capsys):
    repo = git_repo(tmp_path)
    repo.write("common.txt", "shared\n")
    root_commit = repo.commit("root")
    repo._run("checkout", "-q", "-b", "side", root_commit)
    repo.write("side.txt", "side\n")
    unrelated = repo.commit("side branch")
    repo._run("checkout", "-q", "main")
    repo.write("main.txt", "main\n")
    head = repo.commit("main branch")
    monkeypatch.chdir(repo.path)

    packet = valid_packet(git={"branch": "b", "base_ref": "origin/main",
                              "base_sha": unrelated, "head_sha": head})
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not an ancestor" in err
    assert inbox.pending() == []


def test_publish_refuses_a_base_not_reachable_from_base_ref(root, tmp_path, monkeypatch, capsys):
    repo = git_repo(tmp_path)
    repo.write("common.txt", "shared\n")
    release_point = repo.commit("root")
    repo._run("branch", "-q", "release", release_point)
    repo.write("main.txt", "main\n")
    on_main_only = repo.commit("main-only")
    repo.write("more.txt", "more\n")
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    packet = valid_packet(
        git={"branch": "b", "base_ref": "release", "base_sha": on_main_only, "head_sha": head},
        changed_files=[{"path": "more.txt", "status": "added", "insertions": 1, "deletions": 0}],
        diff_summary={"files_changed": 1, "insertions": 1, "deletions": 0},
    )
    rc = main(["publish", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not reachable from base_ref" in err
    assert inbox.pending() == []


# --------------------------------------------------------------------------------------------
# `--no-derive` for a concrete, shipped head can never unlock a ship — the omitted-test bypass.
# --------------------------------------------------------------------------------------------

def test_no_derive_ship_report_with_an_omitted_test_is_refused(root, tmp_path, monkeypatch, capsys):
    """The exact bypass this closes: a ship report published with --no-derive can self-report a
    `changed_files` that omits an altered test, get an approval that never saw it, and ship the
    same head with `diff_provenance: "claimed"` — unless a claimed diff for a concrete head is
    refused outright, before its `changed_files` is ever trusted for the test-change ack check."""
    from twoperson.verdict import build_verdict

    repo = git_repo(tmp_path)
    repo.write("src/thing.py", "x = 1\n")
    repo.write("tests/test_thing.py", "def test_x(): assert True\n")
    base = repo.commit("base")
    repo.write("src/thing.py", "x = 2\n")
    repo.write("tests/test_thing.py", "def test_x(): assert False\n")
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    # A prior reviewed packet whose OWN self-report omits the test change too (published `claimed`,
    # the default when `derive` is not requested) — the reviewer never acknowledged the test change
    # because nothing (yet, self-reported OR derived) told it a test changed. The ship report below
    # is still refused even before its own `--no-derive` claim is reached, because the packet its
    # citation approved was itself never verified — see the assertions below.
    inbox.publish(valid_packet(
        packet_id="reviewed-1",
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[{"path": "src/thing.py", "status": "modified", "insertions": 1,
                        "deletions": 1}],
        diff_summary={"files_changed": 1, "insertions": 1, "deletions": 1},
    ))
    verdict_id = inbox.publish_verdict(
        build_verdict(packet_id="reviewed-1", decision="Approve", head_sha=head)).stem

    ship = valid_packet(
        packet_id="ship-1",
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        # Self-reported, and OMITS tests/test_thing.py — the head actually modifies it.
        changed_files=[{"path": "src/thing.py", "status": "modified", "insertions": 1,
                        "deletions": 1}],
        diff_summary={"files_changed": 1, "insertions": 1, "deletions": 1},
    )
    ship["push_status"].update(pushed=True, review_ref=verdict_id,
                               statement="Shipped after the recorded approval.")
    rc = main(["publish", "--no-derive", "--from", _write(tmp_path, ship, name="ship.json")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "diff_provenance" in err
    assert "'claimed'" in err
    assert not any("ship-1" in str(p) for p in inbox.pending())


def test_a_verdict_for_a_properly_derived_packet_cannot_be_reused_by_a_claimed_ship_report(
    root, tmp_path, monkeypatch, capsys,
):
    """The mirror question the finding asks: even when the REVIEWED packet went through real
    derivation (git-verified `changed_files`, a verdict that honestly acknowledges the actual test
    change), a SEPARATE ship report citing that same approval is still refused if IT is claimed for
    a concrete head — the ship packet's own provenance is what gates it, not the packet the cited
    verdict was originally written against."""
    from twoperson.testset import altered_test_files
    from twoperson.verdict import build_verdict

    repo = git_repo(tmp_path)
    repo.write("src/thing.py", "x = 1\n")
    repo.write("tests/test_thing.py", "def test_x(): assert True\n")
    base = repo.commit("base")
    repo.write("src/thing.py", "x = 2\n")
    repo.write("tests/test_thing.py", "def test_x(): assert False\n")
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    reviewed = valid_packet(
        packet_id="reviewed-honest",
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[
            {"path": "src/thing.py", "status": "modified", "insertions": 1, "deletions": 1},
            {"path": "tests/test_thing.py", "status": "modified", "insertions": 1, "deletions": 1},
        ],
        diff_summary={"files_changed": 2, "insertions": 2, "deletions": 2},
    )
    rc = main(["publish", "--from", _write(tmp_path, reviewed, name="reviewed.json")])
    assert rc == 0, capsys.readouterr().err
    published = inbox._load(inbox.pending()[0])
    assert published["diff_provenance"] == "derived"

    acked = altered_test_files(published["changed_files"])
    assert acked == ["tests/test_thing.py"]
    verdict_id = inbox.publish_verdict(
        build_verdict(packet_id="reviewed-honest", decision="Approve", head_sha=head,
                      acknowledged_tests=acked)).stem

    # A separate ship report, same head, citing that honest approval — but published claimed and
    # omitting the test file from its own self-report.
    ship = valid_packet(
        packet_id="ship-reuse",
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[{"path": "src/thing.py", "status": "modified", "insertions": 1,
                        "deletions": 1}],
        diff_summary={"files_changed": 1, "insertions": 1, "deletions": 1},
    )
    ship["push_status"].update(pushed=True, review_ref=verdict_id,
                               statement="Shipped after the recorded approval.")
    rc = main(["publish", "--no-derive", "--from", _write(tmp_path, ship, name="ship-reuse.json")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "diff_provenance" in err
    assert not any("ship-reuse" in str(p) for p in inbox.pending())


def test_verify_also_refuses_a_no_derive_ship_for_a_concrete_head(root, tmp_path, monkeypatch, capsys):
    """`verify` mirrors `publish`'s refusal here too — it must fail for every reason publish would,
    including one that only exists because a flag was passed, not because of a git-shaped defect.
    The REVIEWED packet is published `derive=True` against a real repo, so the only reason left for
    the refusal is the ship report's own `--no-derive` claim, not the (also-checked) provenance of
    the packet the cited approval reviewed."""
    from twoperson.verdict import build_verdict

    repo = git_repo(tmp_path)
    repo.write("a.txt", "one\n")
    base = repo.commit("base")
    repo.write("a.txt", "one\ntwo\n")
    head = repo.commit("head")
    monkeypatch.chdir(repo.path)

    inbox.publish(valid_packet(
        packet_id="reviewed-x",
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[{"path": "a.txt", "status": "modified", "insertions": 1, "deletions": 0}],
        diff_summary={"files_changed": 1, "insertions": 1, "deletions": 0},
    ), derive=True)
    verdict_id = inbox.publish_verdict(
        build_verdict(packet_id="reviewed-x", decision="Approve", head_sha=head)).stem

    packet = valid_packet(
        packet_id="ship-x",
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
    )
    packet["push_status"].update(pushed=True, review_ref=verdict_id,
                                 statement="Shipped after the recorded approval.")
    rc = main(["verify", "--no-derive", "--from", _write(tmp_path, packet)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "diff_provenance" in err


def test_a_draft_that_never_ships_is_unaffected_by_the_unverified_ship_check(root, tmp_path, capsys):
    """The new check is scoped to a packet that actually reports shipping — a claimed draft with no
    push at all must still publish exactly as before."""
    packet = valid_packet(git={"branch": "b", "base_ref": "origin/main",
                              "base_sha": "unknown", "head_sha": "unknown"})
    rc = main(["publish", "--no-derive", "--from", _write(tmp_path, packet)])
    assert rc == 0, capsys.readouterr().err
    assert inbox.pending() != []


def test_verify_never_checks_citations(root, tmp_path, monkeypatch, capsys):
    """The check reads the repository at the head being published; `verify` may run anywhere and
    must not depend on it."""
    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "def _other():\n    pass\n")
    base = repo.commit("base")
    head = repo.commit("head")  # an empty commit: a real ancestor, with nothing left to diff
    monkeypatch.chdir(repo.path)

    packet = valid_packet(
        git={"branch": "b", "base_ref": "origin/main", "base_sha": base, "head_sha": head},
        changed_files=[], diff_summary={"files_changed": 0, "insertions": 0, "deletions": 0},
        tests=[{"name": "probe", "command": "call `_never_existed_anywhere()` directly",
               "result": "passed", "evidence": "n/a"}],
    )
    assert main(["verify", "--from", _write(tmp_path, packet)]) == 0
    assert inbox.pending() == []
