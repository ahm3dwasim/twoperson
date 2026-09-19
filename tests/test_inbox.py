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

    def spy(src, dst, **kwargs):
        # Before the rename the pending dir must still be empty — nothing half-written is exposed.
        # `**kwargs` carries src_dir_fd/dst_dir_fd: the publish addresses the rename through held
        # descriptors now, so the spy has to accept them and pass them through. The invariant is
        # about VISIBILITY and is unchanged; only the call signature moved with the implementation.
        seen.append(sorted(p.name for p in (root / "pending").iterdir()))
        return real_replace(src, dst, **kwargs)

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


def test_a_pending_entry_that_is_a_directory_is_refused_not_silently_skipped(root):
    """It is still never opened as a packet — but it no longer looks like an EMPTY lane.

    This test formerly asserted `pending() == []`, which is the defect: it agreed that a refusal and
    an empty lane give the same answer.
    """
    (root / "pending" / "20260819T090000Z-dir.json").mkdir(parents=True)
    scan = inbox._lane_scan(root, "pending")
    assert scan.files == ()
    assert scan.complete is False
    with pytest.raises(inbox.LaneUnreadable):
        inbox.pending()
    with pytest.raises(inbox.LaneUnreadable):
        inbox.claim_next()


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

    # Still never followed — and no longer indistinguishable from an empty lane.
    scan = inbox._lane_scan(root, "pending")
    assert scan.files == ()
    assert scan.complete is False
    with pytest.raises(inbox.LaneUnreadable):
        inbox.pending()
    with pytest.raises(inbox.LaneUnreadable):
        inbox.claim_next()
    assert outside.exists()  # untouched
    assert outside.read_text(encoding="utf-8") == json.dumps(valid_packet())


def test_inbox_permissions_are_owner_only(root):
    inbox.publish(valid_packet())
    assert oct(root.stat().st_mode)[-3:] == "700"


# --------------------------------------------------------------------------------------------
# A refusal is not an empty lane
#
# The defect this pins bit twice in one session, in two files: a reader that answers "nothing here"
# identically for an empty lane and for a lane it refused to read, and a caller that read that as
# evidence of absence. `_lane_files` is the single source the callers used to re-derive; it is now
# the single source that tells them apart.
# --------------------------------------------------------------------------------------------

def _drop_symlink(root, lane: str, name: str = "9999-hostile.json"):
    """Hand-drop a `.json` SYMLINK into a lane, the way an attacker or a stray `ln -s` would."""
    directory = root / lane
    directory.mkdir(parents=True, exist_ok=True)
    outside = root.parent / "elsewhere.json"
    outside.write_text("{}")
    link = directory / name
    link.symlink_to(outside)
    return link


def test_a_lane_that_was_never_created_is_provably_empty(root):
    """The one case where "no files" really is evidence: `_ensure_tree` has not run."""
    scan = inbox._lane_scan(root, "pending")
    assert scan.files == ()
    assert scan.refused == ()
    assert scan.complete is True
    assert inbox._lane_files(root, "pending") == []


def test_a_refused_entry_makes_the_scan_incomplete_rather_than_empty(root):
    """A hostile symlink is still not followed — but the refusal is now REPORTED, not absorbed."""
    _drop_symlink(root, "pending")
    scan = inbox._lane_scan(root, "pending")
    assert scan.files == (), "the symlink must still never be followed"
    assert scan.refused == ("9999-hostile.json",)
    assert scan.complete is False, (
        "a refused listing that reports complete=True is exactly the disarming this guard exists "
        "to prevent"
    )


def test_a_lane_it_refused_to_read_raises_instead_of_answering_empty(root):
    """`_lane_files` fails CLOSED: callers stop re-deriving refusal-vs-empty for themselves."""
    _drop_symlink(root, "pending")
    with pytest.raises(inbox.LaneUnreadable) as caught:
        inbox._lane_files(root, "pending")
    assert "pending" in str(caught.value)
    assert "9999-hostile.json" in str(caught.value)


def test_a_refused_pending_lane_never_reports_that_no_work_is_waiting(root):
    """The consumer property. `has_pending()` returning False here is the false negative itself."""
    _drop_symlink(root, "pending")
    with pytest.raises(inbox.LaneUnreadable):
        inbox.has_pending()


def test_a_refused_archive_lane_never_reports_that_no_archives_exist(root):
    """`archived()` answering `[]` is how a caller concludes no archive exists and falls back."""
    _drop_symlink(root, "audited")
    with pytest.raises(inbox.LaneUnreadable):
        inbox.archived(root)


def test_a_real_packet_beside_a_refused_entry_does_not_silently_become_the_whole_lane(root):
    """The dangerous shape: a partial listing that LOOKS total. It must refuse, not truncate."""
    inbox.publish(valid_packet(), root=root)
    _drop_symlink(root, "pending")
    scan = inbox._lane_scan(root, "pending")
    assert len(scan.files) == 1
    assert scan.complete is False, "one readable file does not make an incomplete listing complete"
    with pytest.raises(inbox.LaneUnreadable):
        inbox.pending(root)


def test_the_refusal_reason_is_bounded_and_never_echoes_file_content(root):
    """The message reaches logs and a CLI; it names entries, never what is inside them."""
    for index in range(9):
        _drop_symlink(root, "pending", name=f"999{index}-hostile.json")
    scan = inbox._lane_scan(root, "pending")
    reason = scan.reason("pending")
    assert reason.count(",") == 4, "at most five names are shown"
    assert "+4 more" in reason
    assert "{}" not in reason


def test_a_verdict_lane_it_could_not_list_never_reports_an_id_as_unverdicted(root):
    """"Under-report is the safe direction" was wrong HERE, and the consumer says why.

    The consumer of this set treats an id missing from it as UNRESOLVED and requeues the claim. So a
    short set does not fail harmlessly toward requeuing — it re-audits a packet whose durable verdict
    already exists, breaking at-most-once. The lane listing fails closed.

    A version of this test that placed a refused symlink BESIDE a readable verdict and asserted the
    readable one still came back would never exercise a lane that cannot be listed at all — the case
    that actually causes the duplicate audit. It would agree with the defect.
    """
    packet_for("pkt-refused-lane")
    inbox.publish_verdict(build_verdict(
        packet_id="pkt-refused-lane", decision="Approve", head_sha="0900128",
    ))
    assert inbox.verdicted_packet_ids(root) == frozenset({"pkt-refused-lane"})

    # A single refused entry is enough: it could BE the verdict for the packet being considered.
    _drop_symlink(root, "verdicts")
    with pytest.raises(inbox.LaneUnreadable):
        inbox.verdicted_packet_ids(root)


def test_a_corrupt_verdict_FILE_is_still_absorbed_rather_than_raising(root):
    """The per-file tolerance is unchanged and still right: one bad file must not abort the scan.

    "Skip a file we cannot parse" and "cannot see the lane at all" are different sizes of doubt.
    Only the first is safe to absorb; this pins that fixing the second did not harden the first.
    """
    packet_for("pkt-corrupt-neighbour")
    inbox.publish_verdict(build_verdict(
        packet_id="pkt-corrupt-neighbour", decision="Approve", head_sha="0900128",
    ))
    (root / "verdicts" / "9999-corrupt.json").write_text("{ not json", encoding="utf-8")
    assert inbox.verdicted_packet_ids(root) == frozenset({"pkt-corrupt-neighbour"})


def test_an_answered_consult_lane_it_could_not_list_fails_closed_too(root):
    """The consult-lane sibling, for the same reason: its consumer also treats a missing id as
    unresolved, so a lane it could not read must decline the sweep rather than requeue answered work."""
    _drop_symlink(root, "advice")
    with pytest.raises(inbox.LaneUnreadable):
        inbox.answered_consult_ids(root)


def test_the_signal_lane_deliberately_opts_out_and_under_reports(root):
    """`pending_signals` is the ONE lane that must stay live, and it says which way it is wrong.

    A packet gates a ship; a signal gates nothing. It only reports that a session stopped, so
    refusing to serve the lane over a hostile drop would convert a nuisance into an outage of the
    whole event-driven wake-up. The direction chosen is UNDER-REPORT: the refused entry is skipped
    and logged, nothing is admitted, and no absence here is ever read as evidence.
    """
    _drop_symlink(root, "signals")
    assert inbox.pending_signals(root) == []      # live, not an exception
    assert inbox.has_pending_signals(root) is False
    scan = inbox._lane_scan(root, "signals")
    assert scan.complete is False, "the refusal must still be visible to the caller that asks"


# --- the lane is held, not named twice ---------------------------------------------------------

def test_the_lane_is_opened_once_and_every_entry_is_stated_against_that_descriptor():
    """Checking the lane with `lstat` and then RE-OPENING IT BY PATH to list it would be two path
    resolutions with a window between them, which is not a check.

    This pins the structural property instead of trying to lose a race in a test: the listing goes
    through ONE descriptor opened with `O_NOFOLLOW | O_DIRECTORY`, so nothing it returns depends on
    the path resolving the same way twice.
    """
    import inspect

    source = inspect.getsource(inbox._lane_scan)
    assert "O_NOFOLLOW" in source and "O_DIRECTORY" in source, (
        "the lane is not opened with the flags that refuse a symlink atomically"
    )
    assert "dir_fd=fd" in source, "entries are stated by path, not against the open lane"
    assert source.count("os.open(") == 1, "the lane is resolved more than once"


def test_ensure_tree_never_chmods_through_a_symlink(root, tmp_path):
    """`mkdir(exist_ok=True)` SUCCEEDS on a symlink to a directory, and `os.chmod` then followed it —
    an ordinary `publish` rewrote the permissions of a directory outside the inbox."""
    outside = tmp_path / "someone-elses-directory"
    outside.mkdir(mode=0o755)
    before = oct(outside.stat().st_mode)[-3:]
    root.mkdir(parents=True, exist_ok=True)
    (root / "pending").symlink_to(outside)

    with pytest.raises(OSError):
        inbox._ensure_tree(root)
    assert oct(outside.stat().st_mode)[-3:] == before, (
        f"an outside directory's permissions were rewritten to {oct(outside.stat().st_mode)[-3:]}"
    )


# --- the lane itself, not only its entries ------------------------------------------------------

def test_a_lane_replaced_by_a_symlink_is_refused_before_anything_is_listed(root):
    """Checking only ENTRIES would let `audited/` -> `outside/` be followed, admitting regular
    `.json` files from outside the inbox to every reader, `claim_next` included."""
    import shutil
    inbox.publish(valid_packet(), root=root)          # build the tree, then replace one lane
    outside = root.parent / "outside"
    outside.mkdir()
    (outside / "20260819T090000Z-smuggled.json").write_text(
        json.dumps(valid_packet(packet_id="smuggled")), encoding="utf-8")
    shutil.rmtree(root / "audited")
    (root / "audited").symlink_to(outside)

    scan = inbox._lane_scan(root, "audited")
    assert scan.files == (), "a symlinked lane was followed out of the inbox"
    assert scan.complete is False
    with pytest.raises(inbox.LaneUnreadable):
        inbox.archived(root)


def test_a_dangling_lane_symlink_is_a_refusal_and_not_a_complete_empty_lane(root):
    """This scanner's own thesis, one level up: a broken lane symlink raises FileNotFoundError, and
    answering that as a provably-empty lane would reintroduce refusal-equals-empty inside the fix."""
    import shutil
    inbox.publish(valid_packet(), root=root)
    shutil.rmtree(root / "pending")
    (root / "pending").symlink_to(root / "nowhere-at-all")

    scan = inbox._lane_scan(root, "pending")
    assert scan.complete is False, "a dangling lane symlink reported as a provably empty lane"
    with pytest.raises(inbox.LaneUnreadable):
        inbox.pending(root)


def test_a_lane_that_is_a_regular_file_is_refused(root):
    """Neither a symlink nor a directory. Asking the positive question — IS it a directory — covers
    all three without anyone having to enumerate the ways a lane can fail to be one."""
    import shutil
    inbox.publish(valid_packet(), root=root)
    shutil.rmtree(root / "claimed")
    (root / "claimed").write_text("not a lane", encoding="utf-8")

    scan = inbox._lane_scan(root, "claimed")
    assert scan.complete is False
    with pytest.raises(inbox.LaneUnreadable):
        inbox.claimed(root)


def test_a_refusal_message_cannot_forge_a_log_line_or_move_a_terminal_cursor(root):
    """The names go from the filesystem straight into a line an operator reads."""
    directory = root / "pending"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "9999-\x1b[31mred\n\nFAKE LOG LINE\x07.json").mkdir()

    reason = inbox._lane_scan(root, "pending").reason("pending")
    assert "\n" not in reason and "\r" not in reason, "a refusal message opened a second line"
    assert "\x1b" not in reason and "\x07" not in reason, "escape sequences reached the terminal"
    assert all(32 <= ord(ch) < 127 or ch == "…" for ch in reason), reason


# --- the race is closed at the syscall, not checked and then re-opened --------------------------

def test_a_lane_file_swapped_for_a_symlink_after_the_scan_is_refused_at_the_read(root, tmp_path):
    """Entries are stat'ed against the lane descriptor, then handed back as PATHS.

    Every reader would re-resolve that path with `read_bytes()`, so swapping the entry for a symlink
    between the scan and the read made the reader consume content from outside the inbox. The check
    was sound; the thing it checked was not the thing that got opened.
    """
    secret = tmp_path / "not-for-the-reviewer.json"
    secret.write_text(json.dumps(valid_packet(packet_id="smuggled")), encoding="utf-8")
    published = inbox.publish(valid_packet(), root=root)

    published.unlink()                      # the exact swap the scan cannot prevent
    published.symlink_to(secret)

    with pytest.raises(OSError):
        inbox._read_lane_file(published)
    assert secret.exists(), "the outside file must be untouched"


def test_the_publish_rename_is_addressed_by_descriptor_not_by_path():
    """Containment is checked and THEN the write and rename happen, so performing both by path would
    let a lane swapped for a symlink in that window send them outside the inbox.

    Structural, and declared as such: it pins that both directories are held open with
    `O_NOFOLLOW | O_DIRECTORY` and that the rename is relative to them. A test that wins a filesystem
    race would be flaky and prove less.
    """
    import inspect

    source = inspect.getsource(inbox._atomic_publish)
    assert "src_dir_fd=" in source and "dst_dir_fd=" in source, "the rename still names paths"
    assert "O_EXCL" in source, (
        "without O_EXCL an attacker pre-creates the staging name and we write through it"
    )
    assert "_lane_dir_fd" in source, "the directories are not held open across the operation"


def test_the_staging_write_refuses_a_pre_created_symlink(root, tmp_path):
    """The other half of the write path, and the layering is worth being exact about.

    A symlink pre-created BEFORE the containment check is caught by `_assert_inside`, which resolves
    the target and sees it leave the root — that is the first line and it raises `PacketError`.
    `O_EXCL | O_NOFOLLOW` is the backstop for the symlink that appears AFTER that check. This test
    exercises the first line and asserts only what it can observe deterministically: the publish
    refuses, and the outside file is untouched either way.
    """
    outside = tmp_path / "target.json"
    outside.write_text("{}", encoding="utf-8")
    inbox._ensure_tree(root)
    packet = valid_packet()
    # Pre-create the staging name this publish will use, as a symlink pointing outside.
    from twoperson.inbox import _stamp
    name = f"{_stamp(packet['created_at'])}-{packet['packet_id']}.json"
    (root / "staging" / name).symlink_to(outside)

    with pytest.raises((OSError, PacketError)):
        inbox.publish(packet, root=root)
    assert outside.read_text(encoding="utf-8") == "{}", "we wrote through a pre-created symlink"
