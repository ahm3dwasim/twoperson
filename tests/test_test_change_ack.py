"""The ship gate must not let a builder quietly weaken a test past a reviewer who never noticed.

`twoperson.testset.altered_test_files` picks out `changed_files` entries that look like a test
being modified, deleted, or renamed (never merely added). `assert_review_ref_resolves` — the same
function that binds a ship report to an approving verdict for the right head — refuses that report
unless the cited verdict also has `acknowledges_test_changes: true`. This mirrors
`tests/test_gate_binding.py`'s style: a fixture packet, a verdict built with `build_verdict`, and
an assertion that `inbox.publish`/`main(["verify", ...])` raises or does not.
"""
from __future__ import annotations

import json

import pytest

from tests.fixtures import packet_for, valid_packet
from twoperson import inbox
from twoperson.__main__ import main
from twoperson.packet import PacketError
from twoperson.testset import altered_test_files, is_test_path
from twoperson.verdict import build_verdict


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    return target


def _pushed_with_files(packet_id: str, changed_files: list[dict], head: str = "0900128") -> dict:
    """A ship report (pushed=True) whose `changed_files` is exactly ``changed_files``."""
    packet = valid_packet(packet_id=packet_id)
    packet["git"]["head_sha"] = head
    packet["changed_files"] = changed_files
    packet["push_status"].update(
        pushed=True, review_ref="unknown", statement="Shipped after the recorded approval.",
    )
    return packet


# ---- the gate --------------------------------------------------------------------------------

def test_a_modified_test_file_without_ack_is_refused(root):
    packet_for("pkt-tc-1", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-1", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-1",
        [{"path": "tests/test_gate.py", "status": "modified", "insertions": 1, "deletions": 3}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(packet)
    msg = str(excinfo.value)
    assert "altered tests" in msg
    assert "tests/test_gate.py" in msg
    assert "acknowledges_test_changes" in msg and "--ack-test-changes" in msg
    assert inbox.find_packet("ship-tc-1") is None  # the refused ship report never landed


def test_a_modified_test_file_with_ack_is_accepted(root):
    packet_for("pkt-tc-2", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-2", decision="Approve", head_sha="0900128",
                      acknowledges_test_changes=True)
    ).stem
    packet = _pushed_with_files(
        "ship-tc-2",
        [{"path": "tests/test_gate.py", "status": "modified", "insertions": 1, "deletions": 3}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    assert inbox.publish(packet).exists()


def test_adding_a_new_test_file_does_not_require_ack(root):
    """Reviewer intent: writing MORE tests must never trip the same gate as weakening one."""
    packet_for("pkt-tc-3", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-3", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-3",
        [{"path": "tests/test_new_thing.py", "status": "added", "insertions": 40, "deletions": 0}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    assert inbox.publish(packet).exists()


def test_a_packet_with_no_test_changes_does_not_require_ack(root):
    """The default fixture packet's own test file is status "added" — unrelated ship reports with
    no test edits at all must keep working exactly as before this feature existed."""
    packet_for("pkt-tc-4", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-4", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-4",
        [{"path": "src/twoperson/packet.py", "status": "modified", "insertions": 5, "deletions": 1}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    assert inbox.publish(packet).exists()


@pytest.mark.parametrize("status", ["deleted", "renamed"])
def test_deleted_or_renamed_test_files_also_require_ack(root, status):
    packet_for(f"pkt-tc-status-{status}", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id=f"pkt-tc-status-{status}", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        f"ship-tc-status-{status}",
        [{"path": "tests/test_gate.py", "status": status, "insertions": 0, "deletions": 12}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(packet)
    assert "altered tests" in str(excinfo.value)


def test_a_copied_test_file_does_not_require_ack(root):
    """"copied" introduces nothing new either — excluded alongside "added"."""
    packet_for("pkt-tc-copied", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-copied", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-copied",
        [{"path": "tests/test_copy.py", "status": "copied", "insertions": 20, "deletions": 0}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    assert inbox.publish(packet).exists()


def test_verify_also_refuses_an_unacknowledged_test_change(root, tmp_path, capsys):
    packet_for("pkt-tc-verify", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-verify", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-verify",
        [{"path": "tests/test_gate.py", "status": "modified", "insertions": 1, "deletions": 1}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    f = tmp_path / "p.json"
    f.write_text(json.dumps(packet), encoding="utf-8")
    assert main(["verify", "--from", str(f)]) == 2
    assert "altered tests" in capsys.readouterr().err
    assert inbox.find_packet("ship-tc-verify") is None  # verify writes nothing


def test_cli_ack_test_changes_flag_sets_the_verdict_field(root, capsys):
    packet_for("pkt-tc-cli", head_sha="0900128")
    rc = main(["verdict", "--packet", "pkt-tc-cli", "--decision", "Approve",
               "--head", "0900128", "--ack-test-changes"])
    assert rc == 0
    (_, verdict), = inbox.read_verdicts()
    assert verdict["acknowledges_test_changes"] is True


def test_verdict_without_the_flag_never_carries_the_field(root):
    """`build_verdict` only writes the key when True, so an ordinary verdict round-trips unchanged."""
    v = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128")
    assert "acknowledges_test_changes" not in v


# ---- verdict schema: an old verdict on disk without the field still validates ----------------

def test_a_verdict_missing_the_field_entirely_still_validates(root):
    """Compat: a verdict recorded before this field existed has no `acknowledges_test_changes` key
    at all — `validate_verdict` (and therefore `loads_verdict`) must accept it unchanged."""
    from twoperson.verdict import validate_verdict
    v = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128")
    assert "acknowledges_test_changes" not in v
    assert validate_verdict(v) == v


def test_the_field_is_a_real_boolean_not_a_string(root):
    from twoperson.packet import SchemaError
    from twoperson.verdict import validate_verdict
    v = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128")
    v["acknowledges_test_changes"] = "true"
    with pytest.raises(SchemaError):
        validate_verdict(v)


# ---- twoperson.testset: the detection helper on its own -------------------------------------

@pytest.mark.parametrize("path", [
    "tests/foo.py",
    "src/test_x.py",
    "pkg/x_test.go",
    "web/x.spec.ts",
    "web/x_spec.rb",
    "src/x.test.js",
    "conftest.py",
    "a/b/conftest.py",
    "a/__tests__/thing.js",
    "a/spec/thing_spec.rb",
])
def test_is_test_path_recognises_every_default_pattern(path):
    assert is_test_path(path) is True


@pytest.mark.parametrize("path", [
    "src/main.py",
    "docs/contest.py",  # must not fuzzy-match "conftest.py"
    "README.md",
    "src/twoperson/testset.py",
])
def test_is_test_path_rejects_non_test_paths(path):
    assert is_test_path(path) is False


def test_altered_test_files_only_counts_weakening_statuses():
    changed = [
        {"path": "tests/a.py", "status": "added"},
        {"path": "tests/b.py", "status": "modified"},
        {"path": "tests/c.py", "status": "deleted"},
        {"path": "tests/d.py", "status": "renamed"},
        {"path": "tests/e.py", "status": "copied"},
        {"path": "src/f.py", "status": "modified"},
    ]
    assert altered_test_files(changed) == ["tests/b.py", "tests/c.py", "tests/d.py"]


def test_altered_test_files_preserves_changed_files_order():
    changed = [
        {"path": "tests/z.py", "status": "modified"},
        {"path": "tests/a.py", "status": "deleted"},
    ]
    assert altered_test_files(changed) == ["tests/z.py", "tests/a.py"]


# ---- TWOPERSON_TEST_GLOBS override ------------------------------------------------------------

def test_env_override_replaces_the_default_rule_entirely(monkeypatch):
    # "tests/foo.py" matches the DEFAULT rule but not this override's glob -> no longer a test path
    monkeypatch.setenv("TWOPERSON_TEST_GLOBS", "qa/**,*.e2e.py")
    assert is_test_path("tests/foo.py") is False
    assert is_test_path("qa/anything/here.py") is True
    assert is_test_path("thing.e2e.py") is True


def test_env_override_is_comma_separated_and_trims_whitespace(monkeypatch):
    monkeypatch.setenv("TWOPERSON_TEST_GLOBS", " qa/** , *.e2e.py ")
    assert is_test_path("qa/x.py") is True
    assert is_test_path("x.e2e.py") is True


def test_env_override_flows_through_to_the_gate(root, monkeypatch):
    """The override is not just a helper detail — the gate itself must honor it."""
    monkeypatch.setenv("TWOPERSON_TEST_GLOBS", "qa/**")
    packet_for("pkt-tc-env", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-env", decision="Approve", head_sha="0900128")
    ).stem
    # Under the override, tests/test_gate.py is no longer considered a test path at all.
    packet = _pushed_with_files(
        "ship-tc-env-1",
        [{"path": "tests/test_gate.py", "status": "modified", "insertions": 1, "deletions": 1}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    assert inbox.publish(packet).exists()

    ref2 = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-env", decision="Approve", head_sha="0900128")
    ).stem
    # ...but a path matching the override glob now needs the ack.
    packet2 = _pushed_with_files(
        "ship-tc-env-2",
        [{"path": "qa/checks.py", "status": "modified", "insertions": 1, "deletions": 1}],
        head="0900128",
    )
    packet2["push_status"]["review_ref"] = ref2
    with pytest.raises(PacketError):
        inbox.publish(packet2)
