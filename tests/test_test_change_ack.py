"""The ship gate must not let a builder quietly weaken a test past a reviewer who never noticed.

`twoperson.testset.altered_test_files` picks out `changed_files` entries that look like a test
being modified, deleted, or renamed (never merely added). `assert_review_ref_resolves` — the same
function that binds a ship report to an approving verdict for the right head — refuses that report
unless the cited verdict's `acknowledged_tests` is a SUPERSET of those altered paths. The check is
content-bound, not a bare flag: a verdict written for one packet's test changes must not be able to
unlock a DIFFERENT ship report's different test changes at the same head, since `changed_files` is
self-reported per packet. This mirrors `tests/test_gate_binding.py`'s style: a fixture packet, a
verdict built with `build_verdict`, and an assertion that `inbox.publish`/`main(["verify", ...])`
raises or does not.
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
    assert "--ack-test-changes" in msg
    assert inbox.find_packet("ship-tc-1") is None  # the refused ship report never landed


def test_a_modified_test_file_with_ack_is_accepted(root):
    packet_for("pkt-tc-2", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-2", decision="Approve", head_sha="0900128",
                      acknowledged_tests=["tests/test_gate.py"])
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


# ---- renames: old_path closes the renamed-away-test bypass -----------------------------------

def test_a_test_renamed_to_a_nontest_path_with_old_path_is_refused(root):
    """The bypass: `path` alone (tests/test_auth.py -> src/auth.py) would read as "not a test"."""
    packet_for("pkt-tc-rename-1", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-rename-1", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-rename-1",
        [{"path": "src/auth.py", "status": "renamed", "old_path": "tests/test_auth.py",
          "insertions": 2, "deletions": 40}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(packet)
    msg = str(excinfo.value)
    assert "altered tests" in msg and "src/auth.py" in msg
    assert inbox.find_packet("ship-tc-rename-1") is None


def test_a_test_renamed_to_a_nontest_path_with_old_path_is_accepted_when_acked(root):
    packet_for("pkt-tc-rename-1b", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-rename-1b", decision="Approve", head_sha="0900128",
                      acknowledged_tests=["src/auth.py"])
    ).stem
    packet = _pushed_with_files(
        "ship-tc-rename-1b",
        [{"path": "src/auth.py", "status": "renamed", "old_path": "tests/test_auth.py",
          "insertions": 2, "deletions": 40}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    assert inbox.publish(packet).exists()


def test_a_rename_without_old_path_is_conservatively_refused(root):
    """No recorded source: could have been a test moved out of the tree, so it is not waved through."""
    packet_for("pkt-tc-rename-2", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-rename-2", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-rename-2",
        [{"path": "src/auth.py", "status": "renamed", "insertions": 2, "deletions": 40}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(packet)
    assert "altered tests" in str(excinfo.value)


def test_a_nontest_renamed_to_a_nontest_with_old_path_does_not_require_ack(root):
    """No over-flagging: both ends declared and neither is a test file."""
    packet_for("pkt-tc-rename-3", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-rename-3", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-rename-3",
        [{"path": "src/new_name.py", "status": "renamed", "old_path": "src/old_name.py",
          "insertions": 0, "deletions": 0}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    assert inbox.publish(packet).exists()


def test_a_test_renamed_to_a_test_is_refused_without_ack(root):
    """Both ends under tests/ — the destination alone already trips it, unchanged from before."""
    packet_for("pkt-tc-rename-4", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-rename-4", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-rename-4",
        [{"path": "tests/test_auth_new.py", "status": "renamed", "old_path": "tests/test_auth.py",
          "insertions": 0, "deletions": 0}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError):
        inbox.publish(packet)


def test_a_nontest_renamed_to_a_test_is_also_refused(root):
    """The destination alone already covers this direction, old_path or not."""
    packet_for("pkt-tc-rename-5", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-rename-5", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-rename-5",
        [{"path": "tests/test_new.py", "status": "renamed", "old_path": "src/new.py",
          "insertions": 40, "deletions": 0}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError):
        inbox.publish(packet)


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


def test_ack_test_changes_flag_derives_paths_from_the_reviewed_packet(root, capsys):
    """The flag never takes a hand-typed list — it reads the REVIEWED packet's own `changed_files`,
    so a verdict can only ever acknowledge tests this reviewer actually had in front of them."""
    packet_for("pkt-cli", head_sha="0900128", changed_files=[
        {"path": "tests/test_thing.py", "status": "modified", "insertions": 1, "deletions": 2},
    ])
    rc = main(["verdict", "--packet", "pkt-cli", "--decision", "Approve",
               "--head", "0900128", "--ack-test-changes"])
    assert rc == 0
    (_, verdict), = inbox.read_verdicts()
    assert verdict["acknowledged_tests"] == ["tests/test_thing.py"]


def test_ack_test_changes_flag_on_a_packet_with_no_test_changes_writes_nothing(root):
    """The default fixture packet's own test file is status "added" — the flag derives an empty
    list from it, and `build_verdict` never writes the key for an empty list."""
    packet_for("pkt-cli-noop", head_sha="0900128")
    rc = main(["verdict", "--packet", "pkt-cli-noop", "--decision", "Approve",
               "--head", "0900128", "--ack-test-changes"])
    assert rc == 0
    (_, verdict), = inbox.read_verdicts()
    assert "acknowledged_tests" not in verdict


def test_verdict_without_the_flag_never_carries_the_field(root):
    """`build_verdict` only writes the key for a non-empty list, so an ordinary verdict round-trips
    unchanged."""
    v = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128")
    assert "acknowledged_tests" not in v


# ---- verdict schema: an old verdict on disk without the field still validates ----------------

def test_a_verdict_missing_the_field_entirely_still_validates(root):
    """Compat: a verdict recorded before this field existed has no `acknowledged_tests` key at
    all — `validate_verdict` (and therefore `loads_verdict`) must accept it unchanged."""
    from twoperson.verdict import validate_verdict
    v = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128")
    assert "acknowledged_tests" not in v
    assert validate_verdict(v) == v


def test_build_verdict_rejects_a_nonlist_acknowledgment():
    """A bare string like "false" must be rejected outright, not spread into one-character "paths"
    by `list("false")`. `build_verdict` guards this before the value ever reaches `_string_list`."""
    from twoperson.packet import SchemaError
    with pytest.raises(SchemaError):
        build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128",
                      acknowledged_tests="false")
    with pytest.raises(SchemaError):
        build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128",
                      acknowledged_tests=5)
    v = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128",
                      acknowledged_tests=["tests/test_x.py"])
    assert v["acknowledged_tests"] == ["tests/test_x.py"]
    v_empty = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128",
                            acknowledged_tests=[])
    assert "acknowledged_tests" not in v_empty
    v_none = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128",
                           acknowledged_tests=None)
    assert "acknowledged_tests" not in v_none


def test_the_field_is_a_list_of_strings_not_a_bare_string(root):
    from twoperson.packet import SchemaError
    from twoperson.verdict import validate_verdict
    v = build_verdict(packet_id="pkt-x", decision="Approve", head_sha="0900128")
    v["acknowledged_tests"] = "tests/test_x.py"
    with pytest.raises(SchemaError):
        validate_verdict(v)


# ---- content-bound: an acknowledgment for one packet's tests must not unlock another's --------

def test_a_verdict_acknowledging_other_tests_does_not_unlock_this_ship_report(root):
    """The exact r4 finding, now closed: a verdict acknowledging test changes for ONE packet must
    not silently unlock a DIFFERENT ship report at the same head whose altered tests differ."""
    packet_for("pkt-tc-other", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-other", decision="Approve", head_sha="0900128",
                      acknowledged_tests=["tests/test_other.py"])
    ).stem
    packet = _pushed_with_files(
        "ship-tc-other",
        [{"path": "tests/test_gate.py", "status": "modified", "insertions": 1, "deletions": 3}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(packet)
    msg = str(excinfo.value)
    assert "altered tests" in msg
    assert "tests/test_gate.py" in msg
    assert inbox.find_packet("ship-tc-other") is None


def test_a_subset_of_acknowledged_tests_is_accepted(root):
    """A verdict that acknowledges a SUPERSET of the ship report's altered tests still unlocks it —
    only the exact-match replay is what the gate closes."""
    packet_for("pkt-tc-superset", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-superset", decision="Approve", head_sha="0900128",
                      acknowledged_tests=["tests/test_gate.py", "tests/test_extra.py"])
    ).stem
    packet = _pushed_with_files(
        "ship-tc-superset",
        [{"path": "tests/test_gate.py", "status": "modified", "insertions": 1, "deletions": 3}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    assert inbox.publish(packet).exists()


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


# ---- altered_test_files: rename handling via old_path -----------------------------------------

def test_rename_to_nontest_path_is_flagged_via_old_path():
    changed = [{"path": "src/auth.py", "status": "renamed", "old_path": "tests/test_auth.py"}]
    assert altered_test_files(changed) == ["src/auth.py"]


def test_rename_to_nontest_path_without_old_path_is_flagged_conservatively():
    changed = [{"path": "src/auth.py", "status": "renamed"}]
    assert altered_test_files(changed) == ["src/auth.py"]


def test_rename_to_nontest_path_with_empty_old_path_is_flagged_conservatively():
    changed = [{"path": "src/auth.py", "status": "renamed", "old_path": ""}]
    assert altered_test_files(changed) == ["src/auth.py"]


def test_rename_between_two_nontest_paths_with_old_path_is_not_flagged():
    changed = [{"path": "src/new_name.py", "status": "renamed", "old_path": "src/old_name.py"}]
    assert altered_test_files(changed) == []


def test_rename_test_to_test_is_flagged():
    changed = [{"path": "tests/test_b.py", "status": "renamed", "old_path": "tests/test_a.py"}]
    assert altered_test_files(changed) == ["tests/test_b.py"]


def test_rename_nontest_to_test_is_flagged_regardless_of_old_path():
    changed = [{"path": "tests/test_new.py", "status": "renamed", "old_path": "src/new.py"}]
    assert altered_test_files(changed) == ["tests/test_new.py"]


# ---- TWOPERSON_TEST_GLOBS override ------------------------------------------------------------

def test_env_globs_extend_the_default_rule_and_never_replace_it(monkeypatch):
    # Extra globs ADD patterns; the built-in rule still applies, so a default test path stays one.
    monkeypatch.setenv("TWOPERSON_TEST_GLOBS", "qa/**,*.e2e.py")
    assert is_test_path("tests/foo.py") is True        # default rule still in force
    assert is_test_path("qa/anything/here.py") is True  # added by the env glob
    assert is_test_path("thing.e2e.py") is True         # added by the env glob


def test_env_globs_cannot_switch_off_default_detection(root, monkeypatch):
    """A builder controls the environment at publish time. A nonmatching glob must NOT disable the
    built-in detection, or `TWOPERSON_TEST_GLOBS=nomatch` would be a one-line bypass (r2 finding)."""
    monkeypatch.setenv("TWOPERSON_TEST_GLOBS", "does/not/match/anything/**")
    assert is_test_path("tests/test_gate.py") is True
    packet_for("pkt-tc-envoff", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-envoff", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-envoff",
        [{"path": "tests/test_gate.py", "status": "modified", "insertions": 1, "deletions": 3}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError):
        inbox.publish(packet)


def test_env_globs_are_comma_separated_and_trim_whitespace(monkeypatch):
    monkeypatch.setenv("TWOPERSON_TEST_GLOBS", " qa/** , *.e2e.py ")
    assert is_test_path("qa/x.py") is True
    assert is_test_path("x.e2e.py") is True


def test_env_globs_add_paths_to_the_gate_while_defaults_still_bite(root, monkeypatch):
    """Both the added glob AND the built-in rule must flow through to the gate."""
    monkeypatch.setenv("TWOPERSON_TEST_GLOBS", "qa/**")
    packet_for("pkt-tc-env", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-env", decision="Approve", head_sha="0900128")
    ).stem
    # A default test path still needs the ack even with the env set.
    packet = _pushed_with_files(
        "ship-tc-env-1",
        [{"path": "tests/test_gate.py", "status": "modified", "insertions": 1, "deletions": 1}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError):
        inbox.publish(packet)

    ref2 = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-env", decision="Approve", head_sha="0900128")
    ).stem
    # ...and so does a path matching the added glob.
    packet2 = _pushed_with_files(
        "ship-tc-env-2",
        [{"path": "qa/checks.py", "status": "modified", "insertions": 1, "deletions": 1}],
        head="0900128",
    )
    packet2["push_status"]["review_ref"] = ref2
    with pytest.raises(PacketError):
        inbox.publish(packet2)


# ---- fail-closed on ambiguous / builder-chosen inputs (r2 audit findings) ---------------------

def test_old_path_unknown_sentinel_on_rename_is_flagged_conservatively():
    # A rename to a non-test path whose source is the "unknown" sentinel must not be waved through:
    # "unknown" means the source cannot be ruled out as a test.
    changed = [{"path": "src/auth.py", "status": "renamed", "old_path": "unknown"}]
    assert altered_test_files(changed) == ["src/auth.py"]


def test_unknown_status_on_a_test_file_is_flagged():
    # status "unknown" is not in the safe-list, so a test file carrying it is still flagged.
    changed = [{"path": "tests/test_auth.py", "status": "unknown"}]
    assert altered_test_files(changed) == ["tests/test_auth.py"]


def test_only_added_and_copied_are_safe_statuses():
    for safe in ("added", "copied"):
        assert altered_test_files([{"path": "tests/test_x.py", "status": safe}]) == []
    for unsafe in ("modified", "deleted", "renamed", "unknown"):
        assert altered_test_files(
            [{"path": "tests/test_x.py", "status": unsafe}]
        ) == ["tests/test_x.py"]


def test_unknown_status_test_file_needs_ack_at_the_gate(root):
    packet_for("pkt-tc-unk", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-unk", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-unk",
        [{"path": "tests/test_auth.py", "status": "unknown", "insertions": 0, "deletions": 0}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError):
        inbox.publish(packet)


# ---- old_path is honored regardless of status (r3 audit finding) ------------------------------

def test_old_path_test_source_is_honored_regardless_of_status():
    # r3 finding: a declared test source must not be ignored because the status isn't "renamed".
    for status in ("unknown", "modified", "deleted", "renamed"):
        changed = [{"path": "src/auth.py", "status": status, "old_path": "tests/test_auth.py"}]
        assert altered_test_files(changed) == ["src/auth.py"], status


def test_old_path_present_but_unknown_is_flagged_for_any_status():
    for status in ("unknown", "modified", "renamed"):
        changed = [{"path": "src/auth.py", "status": status, "old_path": "unknown"}]
        assert altered_test_files(changed) == ["src/auth.py"], status


def test_non_test_change_with_no_old_path_is_not_flagged():
    # A normal modify/delete/unknown of a non-test file with no source recorded is left alone.
    for status in ("modified", "deleted", "unknown"):
        assert altered_test_files([{"path": "src/auth.py", "status": status}]) == [], status


def test_non_test_to_non_test_rename_with_old_path_is_not_over_flagged():
    changed = [{"path": "src/b.py", "status": "renamed", "old_path": "src/a.py"}]
    assert altered_test_files(changed) == []


def test_inconsistent_status_old_path_test_source_needs_ack_at_the_gate(root):
    # The exact r3 bypass, exercised through the real gate.
    packet_for("pkt-tc-src", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-src", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-src",
        [{"path": "src/auth.py", "status": "unknown", "old_path": "tests/test_auth.py",
          "insertions": 2, "deletions": 40}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError):
        inbox.publish(packet)


# ---- a declared test source is honored even under a "safe" status (r3 fix, completed) ---------

def test_a_test_source_is_flagged_even_under_a_safe_status():
    # "added"/"copied" normally skip, but an old_path naming a test must not let a moved-out test
    # hide behind an inconsistent status.
    for status in ("added", "copied"):
        changed = [{"path": "src/auth.py", "status": status, "old_path": "tests/test_auth.py"}]
        assert altered_test_files(changed) == ["src/auth.py"], status


def test_added_or_copied_test_with_no_source_still_does_not_require_ack():
    # The normal case — writing or duplicating a test — must stay unflagged.
    assert altered_test_files([{"path": "tests/test_new.py", "status": "added"}]) == []
    assert altered_test_files([{"path": "tests/test_new.py", "status": "copied"}]) == []


def test_added_with_test_old_path_needs_ack_at_the_gate(root):
    packet_for("pkt-tc-addsrc", head_sha="0900128")
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-tc-addsrc", decision="Approve", head_sha="0900128")
    ).stem
    packet = _pushed_with_files(
        "ship-tc-addsrc",
        [{"path": "src/auth.py", "status": "added", "old_path": "tests/test_auth.py",
          "insertions": 2, "deletions": 0}],
        head="0900128",
    )
    packet["push_status"]["review_ref"] = ref
    with pytest.raises(PacketError):
        inbox.publish(packet)


# ---- acknowledged_tests cap matches the packet's changed_files cap (r5 audit finding) ---------

def test_acknowledged_tests_cap_matches_changed_files_not_max_list():
    from twoperson.packet import MAX_CHANGED_FILES
    # 150 > the old MAX_LIST(100) but <= MAX_CHANGED_FILES(500): a report altering that many test
    # files derives that many paths and must remain acknowledgeable.
    paths = [f"tests/test_{i}.py" for i in range(150)]
    v = build_verdict(packet_id="p", decision="Approve", head_sha="0900128", acknowledged_tests=paths)
    assert len(v["acknowledged_tests"]) == 150
    # Over the packet's own cap is still rejected, so the two limits stay in lockstep.
    with pytest.raises(PacketError):
        build_verdict(packet_id="p", decision="Approve", head_sha="0900128",
                      acknowledged_tests=[f"tests/test_{i}.py" for i in range(MAX_CHANGED_FILES + 1)])


# ---- a verdict acknowledging many paths fits the byte cap too (r6 audit finding) --------------

def test_a_verdict_acknowledging_max_changed_files_paths_still_publishes():
    from twoperson.verdict import dumps_verdict, loads_verdict, MAX_VERDICT_BYTES
    from twoperson.packet import MAX_PACKET_BYTES
    # The count cap alone was not enough: publish_verdict also size-guards the serialized verdict,
    # so acknowledging MAX_CHANGED_FILES moderately-long test paths must fit that cap. The verdict
    # cap is now the packet cap, and a JSON array of paths is smaller than the changed_files array
    # of objects those paths came from, so any acknowledgment a valid packet can produce publishes.
    assert MAX_VERDICT_BYTES == MAX_PACKET_BYTES
    paths = [f"tests/{'sub/' * 15}test_module_{i:04d}.py" for i in range(500)]
    v = build_verdict(packet_id="p", decision="Approve", head_sha="0900128", acknowledged_tests=paths)
    raw = dumps_verdict(v)
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    assert len(data) > 32_768               # would have been rejected under the old 32 KB cap
    assert loads_verdict(raw)["acknowledged_tests"] == paths   # accepted, and round-trips
