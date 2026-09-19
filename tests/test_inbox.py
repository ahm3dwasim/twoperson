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
    """Two claimers hitting the same file: the loser must get nothing, not a duplicate.

    The claim rename is addressed through lane descriptors now, so this spy sees a bare NAME and a
    pair of `dir_fd`s instead of two paths. The "other" claimer is simulated through the same
    descriptors, which is exactly what a real concurrent claimer would use — the race, and the
    loser's answer to it, are unchanged.
    """
    inbox.publish(valid_packet())
    target = inbox.pending()[0]
    real_rename = os.rename
    stolen = {"done": False}

    def steal_then_rename(src, dst, **kwargs):
        if not stolen["done"] and str(src) == target.name:
            stolen["done"] = True
            real_rename(src, dst, **kwargs)  # the "other" claimer wins first
        return real_rename(src, dst, **kwargs)

    (root / "claimed").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(inbox.os, "rename", steal_then_rename)
    assert inbox.claim_next() is None
    assert [p.name for p in inbox.claimed()] == [target.name], (
        "the packet the other claimer took is still exactly where they put it"
    )


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
    the path resolving the same way twice. The descriptor now comes from the chain — root first,
    then the lane relative to it — so the root cannot be re-resolved behind the listing's back
    either. `_lane_dir_fd` is the chain (both hops, in order); the lane hop's own flags live in
    `_open_lane_at`, which is the one place a lane is opened, so `_ensure_tree` gets the same
    refusal for the same syscall instead of a second, hand-copied `os.open`.
    """
    import inspect

    chain = inspect.getsource(inbox._lane_dir_fd)
    assert chain.count("_open_root_dir(") == 1, "the root is resolved more than once, or not at all"
    assert "_open_lane_at(" in chain, (
        "the lane is opened by path, so the root above it is resolved by the kernel again"
    )
    assert chain.index("_open_root_dir(") < chain.index("_open_lane_at("), (
        "the lane hop must be relative to a root descriptor that was opened FIRST"
    )

    lane_hop = inspect.getsource(inbox._open_lane_at)
    assert "O_NOFOLLOW" in lane_hop and "O_DIRECTORY" in lane_hop, (
        "the lane is not opened with the flags that refuse a symlink atomically"
    )
    assert "dir_fd=root_fd" in lane_hop, (
        "the lane is named by path rather than addressed through the held root descriptor"
    )
    assert lane_hop.count("os.open(") == 1, "the lane is resolved more than once"

    source = inspect.getsource(inbox._lane_scan)
    assert source.count("_lane_dir_fd(") == 1, "the lane is resolved more than once"
    assert "dir_fd=fd" in source, "entries are stated by path, not against the open lane"


def test_ensure_tree_never_chmods_through_a_symlink(root, tmp_path):
    """`mkdir(exist_ok=True)` SUCCEEDS on a symlink to a directory, and `os.chmod` then followed it —
    an ordinary `publish` rewrote the permissions of a directory outside the inbox.

    The refusal is `LaneUnreadable` — a lane the chain cannot open — rather than a raw `OSError`: a
    per-command `except OSError` is a hand-kept list, and `LaneUnreadable` is the type the CLI
    boundary already turns into exit 2 for every command including ones not yet written.
    """
    outside = tmp_path / "someone-elses-directory"
    outside.mkdir(mode=0o755)
    before = oct(outside.stat().st_mode)[-3:]
    root.mkdir(parents=True, exist_ok=True)
    (root / "pending").symlink_to(outside)

    with pytest.raises(inbox.LaneUnreadable):
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

    with pytest.raises(inbox.LaneUnreadable):
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


# --------------------------------------------------------------------------------------------
# The chain is rooted at the ROOT, not at the lane
#
# `O_NOFOLLOW` on a bare path guards only its last component. Every path this module handles is
# `<root>/<lane>/<entry>`, so the two components above the entry were still resolved by the kernel
# on every call: a symlinked ROOT was followed by the listing (which then reported a COMPLETE scan
# of a directory outside the inbox), and a lane swapped for a symlink after the listing was
# followed by every read, claim and rename that re-opened it by path.
# --------------------------------------------------------------------------------------------

def _symlinked_root(root, tmp_path):
    """A real inbox tree, reached only through a symlink standing where the root should be.

    The tree is built for real so the probes have something to find: a followed symlink would
    return these files, and the assertions below would be satisfied by the wrong answer.
    """
    real = tmp_path / "real-inbox"
    real.mkdir()
    inbox._ensure_tree(real)
    inbox.publish(valid_packet(), root=real)
    root.symlink_to(real)
    return real


def test_a_symlinked_root_is_refused_by_the_lane_listing(root, tmp_path):
    """The probe r1 shipped: `_lane_scan` followed the root and answered `complete=True`."""
    real = _symlinked_root(root, tmp_path)
    assert len(inbox._lane_scan(real, "pending").files) == 1, "the fixture inbox is not readable"

    scan = inbox._lane_scan(root, "pending")
    assert scan.files == (), "the listing walked through a symlinked root"
    assert scan.complete is False, (
        "a listing taken outside the inbox was reported as a complete scan of this lane"
    )
    with pytest.raises(inbox.LaneUnreadable):
        inbox.pending(root)


def test_a_symlinked_root_is_refused_by_the_read(root, tmp_path):
    """The path resolves — through the symlink — to a real packet. It must still not be read."""
    real = _symlinked_root(root, tmp_path)
    through_the_link = root / "pending" / inbox._lane_scan(real, "pending").files[0].name
    assert through_the_link.exists(), "the probe path does not resolve; it would prove nothing"

    with pytest.raises(inbox.LaneUnreadable):
        inbox._read_lane_file(through_the_link)


def test_a_symlinked_root_is_refused_by_the_claim(root, tmp_path):
    """`claim_next` is a listing plus a move; neither may be answered by an outside directory."""
    _symlinked_root(root, tmp_path)
    with pytest.raises(inbox.LaneUnreadable):
        inbox.claim_next(root)


def test_a_symlinked_root_is_refused_by_the_publish(root, tmp_path):
    """`mkdir(exist_ok=True)` SUCCEEDS through a symlink to a directory — the write must not."""
    real = _symlinked_root(root, tmp_path)
    before = sorted(p.name for p in (real / "pending").iterdir())

    with pytest.raises(inbox.LaneUnreadable):
        inbox.publish(valid_packet(packet_id="through-the-link"), root=root)

    assert sorted(p.name for p in (real / "pending").iterdir()) == before, (
        "a packet was published through a symlinked root"
    )
    assert list((real / "staging").iterdir()) == [], "staging was written through a symlinked root"


def test_ensure_tree_refuses_a_symlinked_root(root, tmp_path):
    """The tree is created; the refusal is about WHICH directory the tree is created in."""
    real = tmp_path / "elsewhere"
    real.mkdir(mode=0o755)
    before = oct(real.stat().st_mode)[-3:]
    root.symlink_to(real)

    with pytest.raises(inbox.LaneUnreadable):
        inbox._ensure_tree(root)
    assert oct(real.stat().st_mode)[-3:] == before, "an outside directory's mode was rewritten"
    assert list(real.iterdir()) == [], "the inbox tree was created outside the inbox root"


def test_a_lane_swapped_for_a_symlink_after_the_listing_is_refused_at_the_read(root, tmp_path):
    """The r1 finding, exactly as probed: the scan legitimately returns the entry, then the LANE —
    not the entry — is swapped. `O_NOFOLLOW` on the entry's own path says nothing about that."""
    import shutil
    published = inbox.publish(valid_packet(), root=root)
    scan = inbox._lane_scan(root, "pending")
    assert [p.name for p in scan.files] == [published.name] and scan.complete is True

    outside = tmp_path / "outside"
    outside.mkdir()
    smuggled = outside / published.name
    smuggled.write_text(json.dumps(valid_packet(packet_id="smuggled")), encoding="utf-8")
    shutil.rmtree(root / "pending")
    (root / "pending").symlink_to(outside)

    with pytest.raises(inbox.LaneUnreadable):
        inbox._read_lane_file(published)
    assert json.loads(smuggled.read_text(encoding="utf-8"))["packet_id"] == "smuggled", (
        "content from outside the inbox reached the reader"
    )


def test_a_lane_swapped_for_a_symlink_after_the_listing_is_refused_at_the_move(root, tmp_path):
    """A claim is a rename; the rename addressed BOTH lanes by path, so this swap moved a file from
    outside the inbox into `claimed/` and handed it to a reviewer as an audited packet.

    The call shape follows the helper: both lanes come from the inbox the caller names, and the
    source lane is named rather than read back out of the path (`_lane_member`).
    """
    import shutil
    published = inbox.publish(valid_packet(), root=root)
    outside = tmp_path / "outside"
    outside.mkdir()
    smuggled = outside / published.name
    smuggled.write_text(json.dumps(valid_packet(packet_id="smuggled")), encoding="utf-8")
    shutil.rmtree(root / "pending")
    (root / "pending").symlink_to(outside)

    with pytest.raises(inbox.LaneUnreadable):
        inbox._move_lane_entry(published, root=root, src_lane="pending", dst_lane="claimed")

    assert smuggled.exists(), "a file from outside the inbox was moved into the claimed lane"
    assert list((root / "claimed").iterdir()) == [], "the claimed lane received an outside file"


def test_a_lane_swapped_for_a_symlink_between_the_scan_and_the_claim_is_refused(root, tmp_path,
                                                                                 monkeypatch):
    """The same swap, driven through the public `claim_next` rather than the helper.

    The listing is genuinely complete when it runs — the swap happens after it — so this is the
    window the scan cannot close. What the caller must never get is the OTHER answer, "nothing to
    claim": that is a refusal reported as an empty inbox, which is the failure this whole section of
    the module exists to prevent.
    """
    import shutil
    published = inbox.publish(valid_packet(), root=root)
    outside = tmp_path / "outside"
    outside.mkdir()
    smuggled = outside / published.name
    smuggled.write_text(json.dumps(valid_packet(packet_id="smuggled")), encoding="utf-8")

    real_load = inbox._load

    def swap_the_lane_then_load(path):
        packet = real_load(path)        # the listing has already happened by the time we are here
        shutil.rmtree(root / "pending")
        (root / "pending").symlink_to(outside)
        return packet

    monkeypatch.setattr(inbox, "_load", swap_the_lane_then_load)
    with pytest.raises(inbox.LaneUnreadable):
        inbox.claim_next(root)

    assert smuggled.exists(), "a file from outside the inbox was claimed"
    assert inbox.claimed(root) == [], "the claimed lane received an outside file"


# --- a short write is not a small packet --------------------------------------------------------

def test_a_short_write_is_looped_until_the_whole_body_is_written(tmp_path, monkeypatch):
    """`os.write` may write fewer bytes than it was given and report how many. Ignoring that return
    value publishes a TRUNCATED file and reports success — the tail of the packet silently gone."""
    body = b"x" * 4096
    real_write = os.write
    calls = {"count": 0}

    def one_byte_at_a_time(fd, data):
        calls["count"] += 1
        return real_write(fd, bytes(data[:1]))

    target = tmp_path / "body.bin"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        monkeypatch.setattr(inbox.os, "write", one_byte_at_a_time)
        inbox._write_all(fd, body)
        monkeypatch.undo()
    finally:
        os.close(fd)

    assert calls["count"] > 1, "the body went out in one write; a short write was never exercised"
    assert target.read_bytes() == body, "a short write truncated the body"


def test_a_publish_survives_a_short_write_whole(root, monkeypatch):
    """The same property where it matters: the bytes a reader ends up with are all of them."""
    from twoperson.packet import dumps_packet, validate_packet
    packet = valid_packet()
    expected = dumps_packet(validate_packet(packet)).encode("utf-8")
    assert len(expected) > 1, "a one-byte body cannot demonstrate a short write"

    real_write = os.write

    def one_byte_at_a_time(fd, data):
        return real_write(fd, bytes(data[:1]))

    monkeypatch.setattr(inbox.os, "write", one_byte_at_a_time)
    path = inbox.publish(packet, root=root)
    monkeypatch.undo()

    assert path.read_bytes() == expected, "the published packet was truncated by a short write"


def test_a_write_that_makes_no_progress_raises_rather_than_spinning(tmp_path, monkeypatch):
    """A zero-byte write cannot finish the buffer, and retrying it forever is not an answer."""
    target = tmp_path / "body.bin"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        monkeypatch.setattr(inbox.os, "write", lambda fd, data: 0)
        with pytest.raises(OSError):
            inbox._write_all(fd, b"anything")
    finally:
        os.close(fd)


# --- a failed publish leaves nothing behind ------------------------------------------------------

def _boom(*_args, **_kwargs):
    raise OSError("injected failure")


@pytest.mark.parametrize("fail_at", ["the write", "the destination lookup", "the replace"])
def test_a_publish_that_fails_after_the_create_leaves_no_staging_leftover(root, monkeypatch, fail_at):
    """`O_EXCL` is what makes the staging name safe and what makes a leftover fatal: the NEXT
    attempt at the same packet is refused by a file the FAILED attempt left behind. Cleaning up only
    on a failed `os.replace` covers one of the four steps that run between the create and the end.
    """
    from twoperson.inbox import _stamp
    packet = valid_packet()
    name = f"{_stamp(packet['created_at'])}-{packet['packet_id']}.json"

    if fail_at == "the write":
        monkeypatch.setattr(inbox, "_write_all", _boom)
    elif fail_at == "the destination lookup":
        monkeypatch.setattr(inbox, "_free_name_in", _boom)
    else:
        monkeypatch.setattr(inbox.os, "replace", _boom)

    with pytest.raises(OSError):
        inbox.publish(packet, root=root)

    assert list((root / "staging").iterdir()) == [], (
        f"a failure at {fail_at} left {name!r} in staging, which blocks every retry of this packet"
    )
    monkeypatch.undo()
    path = inbox.publish(packet, root=root)
    assert path.name == name and path.parent == root / "pending"


# --- the root is held ONCE, and every lane below it is created from that descriptor ---------------

def test_ensure_tree_creates_every_lane_relative_to_one_root_descriptor():
    """`root / name` resolves the root again for every lane, so a root swapped part-way through the
    loop has the remaining lanes created somewhere else. Structural, like the publish-rename guard
    below: it pins the shape, because a test that wins the swap would be flaky and prove less.

    Behaviourally this is already covered from above — `_chmod_own_directory` refused a symlinked
    root before this change too, so no run of the suite distinguishes the two by outcome. The
    property the finding names is that the root is resolved ONCE, and that is what is asserted.
    """
    import inspect

    source = inspect.getsource(inbox._ensure_tree)
    assert source.count("_open_root_dir(") == 1, "the root is resolved more than once"
    assert "dir_fd=root_fd" in source, "a lane is created by path, so the root is resolved per lane"
    assert "_fchmod_dir(lane_fd)" in source, (
        "a lane's mode is set by name, which follows a symlink the open above just refused"
    )


def test_the_move_rename_is_addressed_by_descriptor_not_by_path():
    """The claim/quarantine/requeue/archive move, pinned the same way.

    Both lanes are opened with `O_NOFOLLOW | O_DIRECTORY` and the rename is relative to those
    descriptors. A rename that named the paths instead would re-resolve both lanes — the same
    check-then-reopen window the scan closes, one layer down — so the open alone is not the guard;
    the addressing is. A behavioural probe cannot separate the two here, because the open refuses
    the swap before the rename is reached.
    """
    import inspect

    source = inspect.getsource(inbox._move_lane_entry)
    assert "src_dir_fd=" in source and "dst_dir_fd=" in source, "the rename still names paths"
    assert "_lane_dir_fd" in source, "the lanes are not held open across the move"
    assert "_free_name_in" in source, (
        "the destination name is chosen by path, so it can be answered by a different lane"
    )


# --------------------------------------------------------------------------------------------
# r3: the inbox a caller NAMES is the only one a move may touch
#
# Every move used to read its root back out of the source path, so the explicit `root` argument was
# discarded the moment the move started: `archive_claimed('/outside/claimed/x.json', root='/intended')`
# resolved BOTH lanes under `/outside` and moved the file there, returning a path that looked exactly
# like the success the caller asked for. The source is now required to BE an entry of `root/<lane>`.
# --------------------------------------------------------------------------------------------

#: Every public operation that moves an entry OUT of a lane, with the lane it reads it from. The
#: `ack_*` family is here too: it documents a SKIP rather than a raise for a foreign path, and a skip
#: is still a decision that has to be made against the root the caller named.
_FOREIGN_SOURCE_CASES = (
    pytest.param("quarantine", "pending", id="quarantine"),
    pytest.param("requeue_claimed", "claimed", id="requeue_claimed"),
    pytest.param("archive_claimed", "claimed", id="archive_claimed"),
    pytest.param("requeue_claimed_consult", "consult_claimed", id="requeue_claimed_consult"),
    pytest.param("archive_claimed_consult", "consult_claimed", id="archive_claimed_consult"),
    pytest.param("ack_signals", "signals", id="ack_signals"),
    pytest.param("ack_verdicts", "verdicts", id="ack_verdicts"),
    pytest.param("ack_advice", "advice", id="ack_advice"),
)


@pytest.mark.parametrize("name,lane", _FOREIGN_SOURCE_CASES)
def test_a_move_never_follows_a_source_outside_the_root_it_was_given(name, lane, root, tmp_path):
    """The demonstrated case, generalized to every move: nothing is moved and nothing is written.

    The foreign inbox is REAL and populated — its lane holds an entry with a plausible name — so a
    call that followed the source would succeed and look like a success, which is precisely the
    failure the explicit root has to prevent.
    """
    intended = root
    inbox._ensure_tree(intended)
    outside = tmp_path / "outside"
    (outside / lane).mkdir(parents=True)
    smuggled = outside / lane / "entry.json"
    smuggled.write_text(json.dumps(valid_packet()), encoding="utf-8")

    call = getattr(inbox, name)
    if name.startswith("ack_"):
        assert call([smuggled], root=intended) == [], (
            f"{name} acknowledged an entry from another inbox"
        )
    elif name == "quarantine":
        with pytest.raises(PacketError):
            call(smuggled, "malformed", root=intended)
    else:
        with pytest.raises(PacketError):
            call(smuggled, root=intended)

    assert smuggled.exists(), f"{name} moved an entry out of an inbox the caller never named"
    moved = [p for p in (outside / lane).iterdir() if p != smuggled]
    assert moved == [], f"{name} left something behind in the foreign lane: {moved}"
    for target_lane in inbox._SUBDIRS:
        assert list((intended / target_lane).iterdir()) == [], (
            f"{name} wrote into {target_lane}/ of the inbox it WAS given"
        )


def test_the_move_destination_comes_from_the_root_not_from_the_source(root, tmp_path):
    """The other half of the same property: the DESTINATION lane is the named root's, always.

    `root/claimed/x.json` is a perfectly good source for a caller whose root is `tmp_path`'s sibling
    inbox — and the archive must land in THAT inbox's `audited/`. Read against the foreign lane, so a
    fix that simply refused every path outside the module's own default would fail here.
    """
    inbox._ensure_tree(root)
    packet = valid_packet()
    inbox.publish(packet)
    claimed = inbox.claim_next().path
    assert claimed.parent == root / "claimed"

    target = inbox.archive_claimed(claimed, root=root)
    assert target.parent == root / "audited"
    assert target.exists() and not claimed.exists()


def test_a_claim_refuses_a_pending_entry_that_is_not_in_this_inboxs_pending(root, tmp_path):
    """`next` lists from the named root, so its sources are always genuine.

    Pinned anyway, because the refusal is what keeps that true if a caller ever hands one over: a
    claim that resolved the root from the source would move a foreign file INTO this inbox's
    `claimed/` and hand it to a reviewer as work from this repository.
    """
    inbox._ensure_tree(root)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "pending").mkdir(parents=True)
    stranger = elsewhere / "pending" / "packet.json"
    stranger.write_text(json.dumps(valid_packet()), encoding="utf-8")

    with pytest.raises(PacketError):
        inbox._move_lane_entry(stranger, root=root, src_lane="pending", dst_lane="claimed")

    assert stranger.exists()
    assert list((root / "claimed").iterdir()) == []


# --------------------------------------------------------------------------------------------
# r3: `O_NOFOLLOW` permits a FIFO — and a FIFO open blocks forever
#
# The chain refused the entry that IS a symlink and had no answer for the entry that is a FIFO: an
# `O_RDONLY` open of a writer-less FIFO waits for a writer that never comes, and the size check that
# would have refused it is an `fstat` behind that open. Every reader is opened `O_NONBLOCK`, fstat'ed
# on the DESCRIPTOR, and refused unless it is a regular file.
# --------------------------------------------------------------------------------------------

#: Long enough that a slow machine is never a failure, short enough that a regression cannot hold the
#: suite: a blocked open does not finish at all, so the timeout is not a duration to tune.
_FIFO_GUARD_SECONDS = 20


def _guarded(fn, *args, **kwargs):
    """Run ``fn`` in a daemon thread and fail if it has not finished — a hang cannot pass as a pass.

    The blocked open cannot be cancelled from here (that is the point: a thread stuck in `openat` is
    not interruptible), so the thread is a daemon and the SUITE still finishes. What it buys is the
    assertion: a regression reports "the reader blocked on a FIFO" instead of hanging CI.
    """
    import threading

    box: dict = {}

    def run():
        try:
            box["value"] = fn(*args, **kwargs)
        except BaseException as exc:      # noqa: BLE001 - re-raised in the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(_FIFO_GUARD_SECONDS)
    assert not thread.is_alive(), (
        f"{getattr(fn, '__name__', fn)} blocked on a FIFO entry — the reader is uninterruptible, "
        f"which is the defect: {_FIFO_GUARD_SECONDS}s with no answer"
    )
    if "error" in box:
        raise box["error"]
    return box.get("value")


@pytest.mark.parametrize("reader", ["_read_lane_file", "_lane_entry_size"], ids=["read", "size"])
def test_a_lane_entry_that_is_a_fifo_is_refused_without_blocking(reader, root):
    """A listed entry swapped for a FIFO, read through the same chain a reader uses."""
    inbox._ensure_tree(root)
    published = inbox.publish(valid_packet(), root=root)
    published.unlink()
    os.mkfifo(published)

    with pytest.raises(inbox.LaneUnreadable) as caught:
        _guarded(getattr(inbox, reader), published)

    assert "could not be opened" in str(caught.value), (
        f"refused for something other than the entry: {caught.value}"
    )
    assert published.exists(), "the FIFO was moved or removed rather than refused"


def test_a_fifo_swapped_in_after_the_listing_cannot_hang_the_reader(root):
    """The end-to-end shape: `next` lists a real packet, the swap happens, the read is refused.

    This is the window the listing cannot close — the FIFO is not there when the lane is scanned —
    so it is the reader that has to survive it. `next` must report a refusal, not wait forever and
    not answer "nothing to audit".
    """
    inbox._ensure_tree(root)
    published = inbox.publish(valid_packet(), root=root)

    real_scan = inbox._lane_scan

    def scan_with_swap(*args, **kwargs):
        scan = real_scan(*args, **kwargs)
        if str(args[1] if len(args) > 1 else kwargs.get("lane")) == "pending":
            published.unlink()
            os.mkfifo(published)
        return scan

    inbox._lane_scan = scan_with_swap
    try:
        with pytest.raises(inbox.LaneUnreadable):
            _guarded(inbox.peek_next)
    finally:
        inbox._lane_scan = real_scan


# --------------------------------------------------------------------------------------------
# r3: creating the root is a refusal surface too
#
# `_ensure_tree` created the root with `Path.mkdir` BEFORE the open that converts failures into
# `LaneUnreadable`, so a root that is an existing regular file, a root that is a dangling symlink and
# a parent this process may not write to each left as a raw `FileExistsError` / `PermissionError` —
# a traceback out of `next`, one hop above the open that would have reported it as a refusal.
# --------------------------------------------------------------------------------------------

def _unwritable_parent(tmp_path):
    """A directory that exists and cannot be written to, and can be (a test runs as root in some CI).

    Returns ``None`` when the process can write anyway — the same guard `test_cli`'s unwritable case
    uses — so the parametrization can skip a placement it cannot construct meaningfully rather than
    assert something the filesystem does not enforce.
    """
    parent = tmp_path / "readonly"
    parent.mkdir()
    parent.chmod(0o500)
    return parent


def test_a_root_that_is_a_regular_file_is_refused_as_a_lane(tmp_path):
    """`mkdir(exist_ok=True)` answers `FileExistsError`; the OPEN is what says why it is unusable."""
    blocked = tmp_path / "a-file"
    blocked.write_text("not an inbox", encoding="utf-8")

    with pytest.raises(inbox.LaneUnreadable) as caught:
        inbox._ensure_tree(blocked)

    assert "could not be opened" in str(caught.value), caught.value
    assert blocked.read_text(encoding="utf-8") == "not an inbox", "the root file was modified"


def test_a_root_that_is_a_dangling_symlink_is_refused_as_a_lane(tmp_path):
    """A dangling link is the case `mkdir` cannot create THROUGH and `mkdir(exist_ok=True)` cannot
    create EITHER — it raises `FileExistsError` for a name that does not resolve to anything."""
    dangling = tmp_path / "gone"
    dangling.symlink_to(tmp_path / "nowhere")

    with pytest.raises(inbox.LaneUnreadable) as caught:
        inbox._ensure_tree(dangling)

    assert "could not be opened" in str(caught.value), caught.value
    assert dangling.is_symlink(), "the dangling link was replaced rather than refused"


def test_a_root_under_an_unwritable_parent_is_refused_as_a_lane(tmp_path):
    """A permission wall is a refusal, not a `PermissionError` escaping the CLI net."""
    parent = _unwritable_parent(tmp_path)
    blocked = parent / "inbox"
    try:
        try:
            blocked.mkdir()
        except OSError:
            pass                      # writable after all (root, or a filesystem without modes)
        else:
            blocked.rmdir()
            pytest.skip("this process can write to a 0500 directory; the placement is unavailable")

        with pytest.raises(inbox.LaneUnreadable) as caught:
            inbox._ensure_tree(blocked)
        assert "could not be created" in str(caught.value), caught.value
    finally:
        parent.chmod(0o700)
