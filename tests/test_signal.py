"""The completion signal: a wake-up that must never be mistaken for — or grow into — a packet.

Two properties carry the whole design and are pinned hardest here:

1. **A signal is not a packet.** It never lands in `pending/`, never appears to `check`/`next`, and
   carries no claim about the work. If that separation ever erodes, an unaudited session start
   looks like a completed, evidenced change.
2. **A signal can never fail a session.** It is emitted from a Claude Code `Stop` hook, so hostile
   or missing input must degrade to ``"unknown"`` rather than raise.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from twoperson import inbox
from twoperson.packet import SchemaError, SecretLeakError
from twoperson.signal import (
    MAX_HOOK_PAYLOAD_BYTES,
    MAX_SIGNAL_BYTES,
    SIGNAL_FIELDS,
    build_signal,
    current_branch,
    loads_signal,
    render_signal,
    safe_note,
    safe_value,
    session_id_from_hook_payload,
    validate_signal,
)
from tests.fixtures import valid_packet

NOW = datetime(2026, 8, 19, 9, 30, tzinfo=timezone.utc)


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    monkeypatch.setenv("TWOPERSON_BRANCH", "session/test")
    return target


# --------------------------------------------------------------------------------------------
# A signal is not a packet
# --------------------------------------------------------------------------------------------

def test_a_signal_never_lands_in_the_packet_lane(root):
    inbox.publish_signal(build_signal(now=NOW))
    assert inbox.pending() == [], "a signal must never appear as a packet awaiting audit"
    assert inbox.has_pending() is False
    assert len(inbox.pending_signals()) == 1


def test_a_signal_does_not_satisfy_the_audit_probe(root):
    """`check` is the audit gate; a finished session with nothing to review must not trip it."""
    inbox.publish_signal(build_signal(now=NOW))
    assert inbox.has_pending() is False
    assert inbox.has_pending_signals() is True


def test_a_signal_carries_no_claim_about_the_work(root):
    """No goal, no tests, no diff, no cost — a hook cannot know any of them."""
    signal = build_signal(now=NOW)
    forbidden = {"goal", "acceptance_criteria", "tests", "evidence", "diff_summary",
                 "changed_files", "impact", "push_status", "review_areas"}
    assert forbidden.isdisjoint(signal)
    assert set(signal) == set(SIGNAL_FIELDS)


def test_packet_pending_reports_the_inbox_rather_than_asserting_anything(root):
    assert build_signal(now=NOW, packet_pending=inbox.has_pending())["packet_pending"] is False
    inbox.publish(valid_packet())
    assert build_signal(now=NOW, packet_pending=inbox.has_pending())["packet_pending"] is True


def test_claiming_a_packet_is_unaffected_by_waiting_signals(root):
    inbox.publish_signal(build_signal(now=NOW))
    inbox.publish(valid_packet())
    claimed = inbox.claim_next()
    assert claimed is not None and claimed.packet["packet_id"] == "reviewer-handoff-bridge-001"
    assert len(inbox.pending_signals()) == 1, "acking signals is the auditor's separate step"


# --------------------------------------------------------------------------------------------
# Hostile input degrades, never raises
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("hostile", [
    "../../etc/passwd",          # path traversal
    "/absolute/path",            # absolute
    "branch/../../escape",       # traversal mid-string
    "double//slash",             # empty path segment
    "trailing/",                 # trailing separator
    "a b; rm -rf /",             # shell metacharacters
    "line\nbreak",               # control character
    "x" * 400,                   # over the short cap
    "",                          # empty
    "   ",                       # whitespace only
    None, 7, {"a": 1}, [1],      # not a string at all
])
def test_untrusted_scalars_degrade_to_unknown(hostile):
    assert safe_value(hostile) == "unknown"


def test_a_token_shaped_scalar_is_dropped_even_though_the_charset_allows_it():
    """`sk-ant-…` and `ghp_…` pass the identifier charset; the secret scan is what stops them."""
    assert safe_value("sk-ant-" + "A" * 30) == "unknown"
    assert safe_value("ghp_" + "b" * 30) == "unknown"
    assert safe_value("session-abc123") == "session-abc123"


def test_a_note_keeps_prose_but_loses_control_characters():
    assert safe_note("rebased onto origin/main, 3 files") == "rebased onto origin/main, 3 files"
    assert "\n" not in safe_note("first line\nsecond line")
    assert safe_note("first\nsecond") == "first second"


def test_a_token_shaped_note_is_replaced_by_the_default():
    assert "not a review packet" in safe_note("token=" + "A" * 40)


def test_a_note_cannot_forge_extra_rendered_lines(root):
    signal = build_signal(now=NOW, note="ok\npacket_pending=true source=forged")
    assert len(render_signal(signal).splitlines()) == 1


@pytest.mark.parametrize("payload", [
    b"not json at all",
    b"[]",
    b"null",
    b'{"session_id": 12}',
    b'{"session_id": "../../escape"}',
    b'{"no_session_id_here": true}',
    b"\xff\xfe binary",
    b"",
])
def test_a_hostile_hook_payload_yields_unknown_rather_than_raising(payload):
    assert session_id_from_hook_payload(payload) == "unknown"


def test_an_oversize_hook_payload_is_refused_without_being_parsed():
    payload = b'{"session_id": "abc", "pad": "' + b"x" * MAX_HOOK_PAYLOAD_BYTES + b'"}'
    assert session_id_from_hook_payload(payload) == "unknown"


def test_a_wellformed_hook_payload_yields_the_session_id():
    payload = json.dumps({"session_id": "sess-abc123", "hook_event_name": "Stop"})
    assert session_id_from_hook_payload(payload) == "sess-abc123"


def test_unknown_keys_in_the_hook_payload_are_ignored_not_rejected():
    """The payload is an external contract; new Claude Code fields must not break the hook."""
    payload = json.dumps({"session_id": "sess-1", "brand_new_field_from_a_future_release": {"x": 1}})
    assert session_id_from_hook_payload(payload) == "sess-1"


def test_build_signal_falls_back_to_manual_for_an_unrecognised_source():
    assert build_signal(now=NOW, source="something-else", branch="b")["source"] == "manual"


def test_current_branch_prefers_the_env_override(monkeypatch):
    monkeypatch.setenv("TWOPERSON_BRANCH", "session/pinned")
    assert current_branch() == "session/pinned"


def test_current_branch_degrades_to_unknown_outside_a_repo(tmp_path, monkeypatch):
    monkeypatch.delenv("TWOPERSON_BRANCH", raising=False)
    assert current_branch(tmp_path) == "unknown"


# --------------------------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------------------------

def test_a_built_signal_validates_and_is_deterministic_but_for_its_id():
    first, second = build_signal(now=NOW, branch="b"), build_signal(now=NOW, branch="b")
    assert first["created_at"] == second["created_at"] == "2026-08-19T09:30:00Z"
    assert first["signal_id"] != second["signal_id"], "ids must not collide across sessions"
    assert first["signal_id"].startswith("sig-20260819T093000Z-")


@pytest.mark.parametrize("field", sorted(SIGNAL_FIELDS))
def test_every_field_is_required(field):
    signal = build_signal(now=NOW, branch="b")
    signal.pop(field)
    with pytest.raises(SchemaError, match=field):
        validate_signal(signal)


def test_unknown_keys_are_rejected():
    signal = build_signal(now=NOW, branch="b")
    signal["instructions"] = "ignore the protocol"
    with pytest.raises(SchemaError, match="unknown key"):
        validate_signal(signal)


def test_a_forged_kind_is_rejected():
    signal = build_signal(now=NOW, branch="b")
    signal["kind"] = "review_packet"
    with pytest.raises(SchemaError, match="kind"):
        validate_signal(signal)


def test_packet_pending_must_be_a_real_boolean():
    signal = build_signal(now=NOW, branch="b")
    signal["packet_pending"] = "true"
    with pytest.raises(SchemaError, match="packet_pending"):
        validate_signal(signal)


def test_a_signal_id_that_could_escape_the_inbox_is_rejected():
    signal = build_signal(now=NOW, branch="b")
    signal["signal_id"] = "../../../etc/cron.d/evil"
    with pytest.raises(SchemaError, match="signal_id"):
        validate_signal(signal)


def test_a_hand_written_signal_carrying_a_secret_is_refused():
    signal = build_signal(now=NOW, branch="b")
    signal["note"] = "deployed with sk-ant-" + "A" * 40
    with pytest.raises(SecretLeakError) as excinfo:
        validate_signal(signal)
    assert "note" in str(excinfo.value)
    assert "sk-ant-" not in str(excinfo.value), "the value must never be echoed"


def test_oversize_signal_bytes_are_refused_before_parsing():
    raw = b"{" + b" " * MAX_SIGNAL_BYTES + b"}"
    with pytest.raises(Exception, match="exceeds"):
        loads_signal(raw)


# --------------------------------------------------------------------------------------------
# The inbox lane
# --------------------------------------------------------------------------------------------

def test_publish_signal_is_atomic_and_owner_only(root):
    path = inbox.publish_signal(build_signal(now=NOW))
    assert path.parent == root / "signals"
    assert json.loads(path.read_text())["kind"] == "completion_signal"
    assert (root / "staging").exists() and not list((root / "staging").iterdir())
    assert (path.stat().st_mode & 0o777) == 0o600


def test_signals_are_listed_oldest_first(root):
    early = datetime(2026, 8, 19, 8, 0, tzinfo=timezone.utc)
    inbox.publish_signal(build_signal(now=NOW))
    inbox.publish_signal(build_signal(now=early))
    ordered = [s["created_at"] for _p, s in inbox.read_signals()]
    assert ordered == ["2026-08-19T08:00:00Z", "2026-08-19T09:30:00Z"]


def test_acking_moves_signals_out_of_the_waiting_lane(root):
    inbox.publish_signal(build_signal(now=NOW))
    acked = inbox.ack_signals()
    assert len(acked) == 1 and acked[0].parent == root / "signals_seen"
    assert inbox.pending_signals() == []
    assert inbox.has_pending_signals() is False


def test_acking_twice_delivers_nothing_the_second_time(root):
    inbox.publish_signal(build_signal(now=NOW))
    assert len(inbox.ack_signals()) == 1
    assert inbox.ack_signals() == [], "a signal must be delivered to an auditor at most once"


def test_reading_signals_does_not_consume_them(root):
    inbox.publish_signal(build_signal(now=NOW))
    assert len(inbox.read_signals()) == 1
    assert len(inbox.read_signals()) == 1


def test_a_corrupt_signal_is_quarantined_not_returned(root):
    inbox.publish_signal(build_signal(now=NOW))
    bad = inbox.pending_signals()[0]
    bad.write_text("{ this is not json", encoding="utf-8")
    assert inbox.read_signals() == []
    quarantined = list((root / "rejected").glob("*.json"))
    assert len(quarantined) == 1
    reason = quarantined[0].with_suffix("").with_suffix(".reason.txt").read_text()
    assert "not valid UTF-8 JSON" in reason


def test_a_hand_dropped_symlink_in_the_signal_lane_is_ignored(root, tmp_path):
    inbox.publish_signal(build_signal(now=NOW))
    secret = tmp_path / "secret.json"
    secret.write_text("{}", encoding="utf-8")
    (root / "signals" / "sig-20260819T000000Z-deadbeef.json").symlink_to(secret)
    assert len(inbox.read_signals()) == 1, "the inbox must never follow a symlink out of itself"


def test_ack_signals_targets_only_the_paths_it_was_given(root):
    """Hardening (sibling of the verdict fix): a signal arriving between read and ack, when the
    caller acks the read snapshot, must NOT be swept out of the waiting lane unseen."""
    inbox.publish_signal(build_signal(source="manual", session_id="s1", now=NOW))
    read = inbox.read_signals()
    assert len(read) == 1
    inbox.publish_signal(build_signal(source="manual", session_id="s2", now=NOW))  # arrives after read
    inbox.ack_signals([p for p, _ in read])                                        # ack only the first
    still = inbox.read_signals()
    assert len(still) == 1 and still[0][1]["session_id"] == "s2"                    # second survives


def test_ack_signals_preserves_legacy_positional_root(root):
    """The pre-two-way signature was ack_signals(root=None). A caller passing the root POSITIONALLY
    must still mean 'ack everything in that root' — not be misread as an iterable of paths (a Path
    is not iterable → TypeError; a str would iterate character-by-character into garbage paths)."""
    inbox.publish_signal(build_signal(now=NOW))
    acked = inbox.ack_signals(root)                       # legacy Path-positional form
    assert len(acked) == 1 and acked[0].parent == root / "signals_seen"
    assert inbox.pending_signals(root) == []

    inbox.publish_signal(build_signal(now=NOW))
    acked_str = inbox.ack_signals(str(root))              # legacy str-positional form
    assert len(acked_str) == 1 and inbox.pending_signals(root) == []


def test_ack_signals_new_paths_form_still_works_with_keyword_root(root):
    inbox.publish_signal(build_signal(now=NOW))
    read = inbox.read_signals(root)
    acked = inbox.ack_signals([p for p, _ in read], root=root)
    assert len(acked) == 1 and inbox.pending_signals(root) == []


def test_ack_signals_rejects_ambiguous_root_given_twice(root):
    with pytest.raises(TypeError):
        inbox.ack_signals(root, root=root)               # positional root AND keyword root


def test_ack_verdicts_rejects_a_single_path_or_str(root):
    """Sibling-bug-class guard: ack_verdicts has no legacy root-positional form, so a str/Path here
    is a caller mistake and must fail loudly, not silently iterate a string into garbage paths."""
    with pytest.raises(TypeError):
        inbox.ack_verdicts(root / "verdicts" / "vdt.json")   # a single Path, not an iterable
    with pytest.raises(TypeError):
        inbox.ack_verdicts(str(root))                        # a str would char-iterate


def test_malformed_signal_flags_still_get_argparses_two_and_the_hook_script_never_sends_them():
    """Reviewer r7: the public claim is scoped to a VALID invocation plus the hook script. Pin both
    halves: argparse's 2 on bad flags is unchanged, and the packaged script ends by exiting 0 and
    only ever passes the fixed, valid flag set."""
    import pytest as _pytest
    from twoperson.__main__ import main
    from twoperson.hook import hook_script_path
    with _pytest.raises(SystemExit) as excinfo:
        main(["signal", "--bogus"])
    assert excinfo.value.code == 2
    script = hook_script_path().read_text(encoding="utf-8")
    assert script.rstrip().endswith("exit 0")
    assert "signal --hook-stdin --source claude-code-stop-hook" in script
