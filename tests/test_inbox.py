"""The durable inbox: atomic publish, detection, exclusive claim, quarantine.

The inbox is a plain directory tree on disk on purpose — it survives a crashed session, needs no
agent-chat channel, and is auditable with `ls`. These tests pin the properties that make that
substitution safe: a reader never sees a half-written packet, a packet is claimed at most once,
and a hand-dropped hostile file can never escape the inbox root.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

from twoperson import inbox
from twoperson.advice import build_advice
from twoperson.consult import build_consult
from twoperson.packet import PacketError, SecretLeakError
from twoperson.verdict import build_verdict
from tests.fixtures import valid_packet, packet_for


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    return target


def test_inbox_root_follows_the_env_override(root):
    assert inbox.inbox_root() == root


def test_inbox_root_defaults_to_a_dot_twoperson_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("TWOPERSON_INBOX", raising=False)
    monkeypatch.setenv("TWOPERSON_HOME", str(tmp_path))
    assert inbox.inbox_root().parts[-1:] == (".twoperson",)


def test_publish_creates_the_tree_and_lands_a_pending_packet(root):
    path = inbox.publish(valid_packet())
    assert path.parent == root / "pending"
    assert path.suffix == ".json"
    assert json.loads(path.read_text(encoding="utf-8"))["packet_id"] == "reviewer-handoff-bridge-001"
    assert [p.name for p in inbox.pending()] == [path.name]


def test_published_filename_sorts_chronologically_and_is_slug_safe(root):
    first = inbox.publish(valid_packet(packet_id="aaa", created_at="2026-08-19T09:00:00Z"))
    second = inbox.publish(valid_packet(packet_id="bbb", created_at="2026-08-19T10:00:00Z"))
    assert first.name < second.name
    assert first.name.startswith("20260819T090000Z-")
    assert [p.name for p in inbox.pending()] == [first.name, second.name]


def test_publish_is_atomic_no_partial_file_is_ever_visible(root, monkeypatch):
    """The bytes are written to a staging file; only os.replace makes them visible."""
    seen: list[list[str]] = []
    real_replace = os.replace

    def spy(src, dst):
        # Before the rename the pending dir must still be empty — nothing half-written is exposed.
        seen.append(sorted(p.name for p in (root / "pending").iterdir()))
        return real_replace(src, dst)

    monkeypatch.setattr(inbox.os, "replace", spy)
    inbox.publish(valid_packet())
    assert seen == [[]]


def test_publish_leaves_no_staging_files_behind(root):
    inbox.publish(valid_packet())
    assert [p.name for p in (root / "pending").iterdir() if p.suffix != ".json"] == []
    assert list((root / "staging").iterdir()) == []


def test_publish_validates_before_writing_anything(root):
    with pytest.raises(SecretLeakError):
        inbox.publish(valid_packet(goal="key " + "ghp_" + "A" * 36))
    assert not (root / "pending").exists() or list((root / "pending").iterdir()) == []


def test_publishing_the_same_packet_id_twice_does_not_clobber(root):
    first = inbox.publish(valid_packet())
    second = inbox.publish(valid_packet())
    assert first != second
    assert len(inbox.pending()) == 2


# --- detection + exclusive claim --------------------------------------------------------------

def test_claim_next_returns_the_oldest_pending_packet_and_moves_it(root):
    inbox.publish(valid_packet(packet_id="older", created_at="2026-08-19T08:00:00Z"))
    inbox.publish(valid_packet(packet_id="newer", created_at="2026-08-19T09:00:00Z"))

    claimed = inbox.claim_next()
    assert claimed is not None
    assert claimed.packet["packet_id"] == "older"
    assert claimed.path.parent == root / "claimed"
    still_pending = inbox.pending()
    assert len(still_pending) == 1 and still_pending[0].name.endswith("-newer.json")


def test_claim_next_on_an_empty_inbox_returns_none(root):
    assert inbox.claim_next() is None


def test_a_packet_is_claimed_at_most_once(root):
    inbox.publish(valid_packet())
    assert inbox.claim_next() is not None
    assert inbox.claim_next() is None


def test_claim_race_only_one_winner(root, monkeypatch):
    """Two claimers hitting the same file: the loser must get nothing, not a duplicate."""
    inbox.publish(valid_packet())
    target = inbox.pending()[0]
    real_rename = os.rename
    stolen = {"done": False}

    def steal_then_rename(src, dst):
        if not stolen["done"] and str(src) == str(target):
            stolen["done"] = True
            real_rename(src, root / "claimed" / target.name)  # the "other" claimer wins first
        return real_rename(src, dst)

    (root / "claimed").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(inbox.os, "rename", steal_then_rename)
    assert inbox.claim_next() is None


def test_peek_does_not_claim(root):
    inbox.publish(valid_packet())
    peeked = inbox.peek_next()
    assert peeked is not None
    assert peeked.path.parent == root / "pending"
    assert len(inbox.pending()) == 1


def test_has_pending_is_the_cheap_event_check(root):
    assert inbox.has_pending() is False
    inbox.publish(valid_packet())
    assert inbox.has_pending() is True


# --- claimed/ recovery (self-heal for a crash between claim and writeback) --------------------

def test_claimed_lists_claimed_packets_oldest_first(root):
    inbox.publish(valid_packet(packet_id="older", created_at="2026-08-19T08:00:00Z"))
    inbox.publish(valid_packet(packet_id="newer", created_at="2026-08-19T09:00:00Z"))
    first = inbox.claim_next()
    second = inbox.claim_next()
    assert [p.name for p in inbox.claimed()] == [first.path.name, second.path.name]


def test_claimed_is_empty_when_nothing_is_claimed(root):
    inbox.publish(valid_packet())
    assert inbox.claimed() == []


def test_requeue_claimed_moves_the_packet_back_to_pending(root):
    inbox.publish(valid_packet())
    claim = inbox.claim_next()
    assert inbox.claimed() == [claim.path]

    target = inbox.requeue_claimed(claim.path)

    assert target.parent == root / "pending"
    assert target.name == claim.path.name
    assert inbox.claimed() == []
    assert [p.name for p in inbox.pending()] == [target.name]


def test_requeued_packet_is_claimable_again_and_still_the_same_packet(root):
    inbox.publish(valid_packet(packet_id="crash-recovery"))
    first_claim = inbox.claim_next()
    inbox.requeue_claimed(first_claim.path)

    second_claim = inbox.claim_next()
    assert second_claim is not None
    assert second_claim.packet["packet_id"] == "crash-recovery"


def test_requeue_claimed_preserves_chronological_order_among_pending(root):
    inbox.publish(valid_packet(packet_id="older", created_at="2026-08-19T08:00:00Z"))
    newer_path = inbox.publish(valid_packet(packet_id="newer", created_at="2026-08-19T09:00:00Z"))
    older_claim = inbox.claim_next()  # takes "older" (oldest first)
    assert older_claim.packet["packet_id"] == "older"

    inbox.requeue_claimed(older_claim.path)

    # "older" sorts back to the front of pending/ — its filename still carries the original stamp.
    assert [p.name for p in inbox.pending()] == [older_claim.path.name, newer_path.name]


def test_requeue_claimed_raises_if_the_packet_was_already_recovered(root):
    inbox.publish(valid_packet())
    claim = inbox.claim_next()
    inbox.requeue_claimed(claim.path)
    with pytest.raises(OSError):
        inbox.requeue_claimed(claim.path)  # already moved out of claimed/ — nothing left to rename


def test_claimed_consults_lists_claimed_consults_oldest_first(root):
    inbox.publish_consult(build_consult(
        question="older?", now=datetime(2026, 8, 19, 8, 0, 0, tzinfo=timezone.utc)))
    inbox.publish_consult(build_consult(
        question="newer?", now=datetime(2026, 8, 19, 9, 0, 0, tzinfo=timezone.utc)))
    first = inbox.claim_consult()
    second = inbox.claim_consult()
    assert [p.name for p in inbox.claimed_consults()] == [first.path.name, second.path.name]


def test_requeue_claimed_consult_moves_it_back_to_consult_lane_and_is_claimable_again(root):
    inbox.publish_consult(build_consult(question="will this crash-recover?"))
    claim = inbox.claim_consult()
    assert inbox.claimed_consults() == [claim.path]

    target = inbox.requeue_claimed_consult(claim.path)
    assert target.parent == root / "consult"
    assert inbox.claimed_consults() == []

    second_claim = inbox.claim_consult()
    assert second_claim is not None
    assert second_claim.packet["consult_id"] == claim.packet["consult_id"]


# --- verdicted_packet_ids / answered_consult_ids (resolved-state reconciliation) ---------------

def test_verdicted_packet_ids_finds_a_verdict_in_the_unacknowledged_lane(root):
    packet_for("pkt-a")
    inbox.publish_verdict(build_verdict(packet_id="pkt-a", decision="Request changes"))
    assert inbox.verdicted_packet_ids() == frozenset({"pkt-a"})


def test_verdicted_packet_ids_finds_a_verdict_in_the_acknowledged_lane(root):
    packet_for("pkt-b")
    inbox.publish_verdict(build_verdict(packet_id="pkt-b", decision="Request changes"))
    verdict_path = inbox.pending_verdicts()[0]
    inbox.ack_verdicts([verdict_path])
    assert inbox.pending_verdicts() == []  # sanity: really moved out to verdicts_seen/
    assert inbox.verdicted_packet_ids() == frozenset({"pkt-b"})


def test_verdicted_packet_ids_combines_both_lanes(root):
    packet_for("pkt-c")
    inbox.publish_verdict(build_verdict(packet_id="pkt-c", decision="Request changes"))
    packet_for("pkt-d")
    inbox.publish_verdict(build_verdict(packet_id="pkt-d", decision="Request changes"))
    inbox.ack_verdicts([inbox.pending_verdicts()[0]])
    assert inbox.verdicted_packet_ids() == frozenset({"pkt-c", "pkt-d"})


def test_verdicted_packet_ids_is_empty_with_no_verdicts(root):
    assert inbox.verdicted_packet_ids() == frozenset()


def test_verdicted_packet_ids_skips_a_corrupt_verdict_file_without_raising(root):
    packet_for("pkt-e")
    inbox.publish_verdict(build_verdict(packet_id="pkt-e", decision="Request changes"))
    inbox.pending_verdicts()[0].write_text("{ not json", encoding="utf-8")
    assert inbox.verdicted_packet_ids() == frozenset()  # corrupt file skipped, never raised


def test_answered_consult_ids_combines_both_lanes(root):
    inbox.publish_advice(build_advice(consult_id="c-a", recommendation="Do X."))
    inbox.publish_advice(build_advice(consult_id="c-b", recommendation="Do Y."))
    inbox.ack_advice([inbox.pending_advice()[0]])
    assert inbox.answered_consult_ids() == frozenset({"c-a", "c-b"})


def test_answered_consult_ids_is_empty_with_no_advice(root):
    assert inbox.answered_consult_ids() == frozenset()


def test_answered_consult_ids_skips_a_corrupt_advice_file_without_raising(root):
    inbox.publish_advice(build_advice(consult_id="c-z", recommendation="Do X."))
    inbox.pending_advice()[0].write_text("{ not json", encoding="utf-8")
    assert inbox.answered_consult_ids() == frozenset()


# --- hostile / corrupt files ------------------------------------------------------------------

def test_a_corrupt_pending_file_is_quarantined_not_returned(root):
    inbox.publish(valid_packet())
    inbox.pending()[0].write_text("{ not json", encoding="utf-8")

    assert inbox.claim_next() is None
    rejected = list((root / "rejected").glob("*.json"))
    assert len(rejected) == 1
    reason = rejected[0].with_suffix(".reason.txt")
    assert reason.exists() and reason.read_text(encoding="utf-8").strip()


def test_a_hand_dropped_invalid_packet_is_quarantined(root):
    (root / "pending").mkdir(parents=True, exist_ok=True)
    (root / "pending" / "20260819T090000Z-forged.json").write_text(
        json.dumps({"schema_version": "1", "packet_id": "forged"}), encoding="utf-8"
    )
    assert inbox.claim_next() is None
    assert len(list((root / "rejected").iterdir())) == 2  # packet + reason


def test_quarantine_survives_a_name_collision(root):
    (root / "pending").mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        bad = root / "pending" / "20260819T090000Z-dupe.json"
        bad.write_text("{ nope", encoding="utf-8")
        assert inbox.claim_next() is None
    assert len(list((root / "rejected").glob("*.json"))) == 2


def test_pending_ignores_non_json_and_dotfiles(root):
    (root / "pending").mkdir(parents=True, exist_ok=True)
    (root / "pending" / "notes.txt").write_text("hi", encoding="utf-8")
    (root / "pending" / ".hidden.json").write_text("{}", encoding="utf-8")
    assert inbox.pending() == []


def test_an_oversize_pending_file_is_quarantined_without_being_parsed(root):
    (root / "pending").mkdir(parents=True, exist_ok=True)
    huge = root / "pending" / "20260819T090000Z-huge.json"
    huge.write_bytes(b"x" * (inbox.MAX_PACKET_BYTES + 1))
    assert inbox.claim_next() is None
    assert list((root / "rejected").glob("*.json"))


def test_a_pending_entry_that_is_a_directory_is_skipped(root):
    (root / "pending" / "20260819T090000Z-dir.json").mkdir(parents=True)
    assert inbox.pending() == []
    assert inbox.claim_next() is None


# --- path traversal ---------------------------------------------------------------------------

def test_publish_never_escapes_the_inbox_root(root, tmp_path):
    """packet_id is untrusted; it must not be able to steer the write out of the inbox."""
    escape = tmp_path / "escaped.json"
    with pytest.raises(PacketError):
        inbox.publish(valid_packet(packet_id="../../escaped"))
    assert not escape.exists()
    assert not (tmp_path / "escaped").exists()


def test_symlinked_pending_entry_is_not_followed_out_of_the_inbox(root, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(valid_packet()), encoding="utf-8")
    (root / "pending").mkdir(parents=True, exist_ok=True)
    link = root / "pending" / "20260819T090000Z-link.json"
    link.symlink_to(outside)

    assert inbox.pending() == []
    assert inbox.claim_next() is None
    assert outside.exists()  # untouched


def test_inbox_permissions_are_owner_only(root):
    inbox.publish(valid_packet())
    assert oct(root.stat().st_mode)[-3:] == "700"
