"""Direct-library bypass attempts for the ship gate (2026-09 audit, lane tpgaps-r2b).

`test_gate_binding.py`/`test_test_change_ack.py` exercise the gate through packets that are
already `"derived"` (via `publish_derived`); everything here is instead a caller trying to get
AROUND the gate — `inbox.publish`/`inbox.assert_review_ref_resolves`/`inbox.publish_verdict` called
directly, never through `twoperson.__main__`, which is where these two properties used to be
enforced (and ONLY there):

  A. `diff_provenance` is stamped by the library, at the one place a packet enters the inbox, and
     is never accepted from the packet's own input — and a shipped report can never unlock a ship
     on an unverified ("claimed") diff, whether that is the report itself or the packet a cited
     approval reviewed.
  B. A packet reporting pushed/deployed/restarted=true must name a concrete head — enforced by the
     schema itself, not only by the coincidence that a real approving verdict's head can never
     equal "unknown".

See docs/PROTOCOL.md §2a.
"""
from __future__ import annotations

import pytest

from tests.fixtures import git_repo, packet_for, publish_derived, valid_packet
from twoperson import inbox
from twoperson.packet import PacketError, SchemaError, validate_packet
from twoperson.verdict import build_verdict


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    return target


# --------------------------------------------------------------------------------------------
# Gap A — a caller of the LIBRARY, bypassing the CLI entirely, cannot mint "derived".
# --------------------------------------------------------------------------------------------

def test_a_packet_that_claims_derived_in_its_own_json_is_restamped(root):
    """`inbox.publish` never trusts the packet's own `diff_provenance` — it recomputes it, every
    time. A packet that arrives already claiming `"derived"` is republished as whatever the
    library actually established (here: `"claimed"`, since `derive` is left at the library's own
    default of `False` and nothing was asked to check it against a head)."""
    packet = valid_packet(diff_provenance="derived")
    path = inbox.publish(packet)
    assert inbox._load(path)["diff_provenance"] == "claimed"


def test_a_forged_derived_claim_cannot_unlock_a_ship_via_inbox_publish_directly(root):
    """The exact vector the audit named: calling `inbox.publish` directly (never through
    `__main__`) with a self-reported `"derived"` claim for a concrete, shipped head. The REVIEWED
    packet is genuinely `derived` here, isolating this from the separate reviewed-packet check
    below: the only remaining reason to refuse is the ship report's OWN forged claim."""
    packet_for("pkt-forge", head_sha="0900128", derived=True)
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-forge", decision="Approve", head_sha="0900128")).stem
    ship = valid_packet(packet_id="ship-forge", diff_provenance="derived")
    ship["git"]["head_sha"] = "0900128"
    ship["push_status"].update(pushed=True, review_ref=ref,
                               statement="Shipped after the recorded approval.")
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(ship)
    msg = str(excinfo.value)
    assert "diff_provenance" in msg and "'claimed'" in msg
    assert inbox.find_packet("ship-forge") is None


def test_assert_review_ref_resolves_called_directly_refuses_a_claimed_reviewed_packet(root):
    """The gate function itself, called directly with no `inbox.publish`/`prepare_packet` in the
    call at all — proving the check lives in the shared gate, not only in `publish`'s wrapper."""
    packet_for("pkt-direct", head_sha="0900128")  # "claimed"
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-direct", decision="Approve", head_sha="0900128")).stem
    ship = valid_packet(packet_id="ship-direct", diff_provenance="derived")
    ship["git"]["head_sha"] = "0900128"
    ship["push_status"].update(pushed=True, review_ref=ref,
                               statement="Shipped after the recorded approval.")
    with pytest.raises(PacketError) as excinfo:
        inbox.assert_review_ref_resolves(ship)
    assert "diff_provenance" in str(excinfo.value)
    assert "pkt-direct" in str(excinfo.value)


def test_a_verdict_for_a_claimed_packet_is_still_recorded_but_unlocks_no_ship(root):
    """`publish_verdict` itself is unaffected by this check — recording a review is not what gates
    a ship — but ANY later report citing it is refused, proving `publish_verdict` is not itself a
    way around the rule (the third vector the audit named)."""
    packet_for("pkt-reuse", head_sha="0900128")
    written = inbox.publish_verdict(
        build_verdict(packet_id="pkt-reuse", decision="Approve", head_sha="0900128"))
    assert written.exists()
    ship = valid_packet(packet_id="ship-reuse")
    ship["git"]["head_sha"] = "0900128"
    ship["push_status"].update(pushed=True, review_ref=written.stem,
                               statement="Shipped after the recorded approval.")
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(ship)
    assert "diff_provenance" in str(excinfo.value)


def test_a_properly_derived_ship_report_of_a_properly_derived_review_still_works(root):
    """The positive control: once BOTH the reviewed packet and the ship report are genuinely
    library-verified (`publish_derived`), the same shape of call the tests above refuse succeeds —
    proving the gate refuses on PROVENANCE, not merely on any packet shaped like these."""
    packet_for("pkt-honest", head_sha="0900128", derived=True)
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-honest", decision="Approve", head_sha="0900128")).stem
    ship = valid_packet(packet_id="ship-honest")
    ship["git"]["head_sha"] = "0900128"
    ship["push_status"].update(pushed=True, review_ref=ref,
                               statement="Shipped after the recorded approval.")
    assert publish_derived(ship).exists()


def test_derive_true_against_a_real_repo_that_lacks_the_commits_is_a_hard_refusal(root, tmp_path):
    """Asking for real verification (`derive=True`) against a real repository that simply does not
    hold the named commits must fail CLOSED — never silently downgrade to `"claimed"` — exactly as
    `--no-derive` documents as the deliberate, explicit way to get an unverified claim through."""
    ship = valid_packet(packet_id="ship-unresolvable")
    ship["git"]["head_sha"] = "0900128"
    empty_repo = git_repo(tmp_path)
    with pytest.raises(PacketError):
        inbox.publish(ship, repo=empty_repo.path, derive=True)
    assert inbox.find_packet("ship-unresolvable") is None


# --------------------------------------------------------------------------------------------
# Gap B — a shipped report must name a concrete head. Schema-level: true for EVERY caller that
# validates a packet, not only one that also happens to check it against the inbox.
# --------------------------------------------------------------------------------------------

def test_schema_refuses_a_pushed_packet_with_head_sha_unknown(root):
    """Independent of any verdict existing at all — `validate_packet` alone must refuse this."""
    packet = valid_packet(packet_id="ship-unknown-head")
    packet["git"]["head_sha"] = "unknown"
    packet["push_status"].update(pushed=True, review_ref="vdt-forged-id",
                                 statement="Shipped after the recorded approval.")
    with pytest.raises(SchemaError) as excinfo:
        validate_packet(packet)
    assert "head_sha" in str(excinfo.value)


@pytest.mark.parametrize("effect", ["pushed", "deployed", "restarted"])
def test_schema_refuses_every_shipped_effect_with_head_sha_unknown(root, effect):
    """"Shipped" is any of pushed/deployed/restarted — the schema check must not be scoped to
    `pushed` alone."""
    packet = valid_packet(packet_id=f"ship-{effect}-unknown")
    packet["git"]["head_sha"] = "unknown"
    packet["push_status"].update(review_ref="vdt-forged-id",
                                 statement="Shipped after the recorded approval.", **{effect: True})
    with pytest.raises(SchemaError):
        validate_packet(packet)


def test_a_pushed_unknown_head_citing_a_real_approval_is_still_refused_end_to_end(root):
    """Even when `review_ref` names a REAL, ship-unlocking verdict for a REAL concrete head, a ship
    packet whose OWN head is "unknown" is refused — closing the gap structurally rather than
    relying on the coincidence that a real approval's head can never literally equal "unknown"."""
    packet_for("pkt-realhead", head_sha="0900128", derived=True)
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-realhead", decision="Approve", head_sha="0900128")).stem
    ship = valid_packet(packet_id="ship-realhead-unknown")
    ship["git"]["head_sha"] = "unknown"
    ship["push_status"].update(pushed=True, review_ref=ref,
                               statement="Shipped after the recorded approval.")
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(ship)
    assert "head_sha" in str(excinfo.value)
    assert inbox.find_packet("ship-realhead-unknown") is None


def test_a_non_concrete_but_non_unknown_head_is_rejected_by_the_sha_shape_itself(root):
    """The schema's `_sha` validator only ever accepts "unknown" or a real sha shape — there is no
    OTHER "non-concrete" value a packet can carry, so this is the only case Gap B's fix needs to
    cover; a garbage value is refused on shape alone, unrelated to shipping."""
    packet = valid_packet(packet_id="ship-bad-head")
    packet["git"]["head_sha"] = "not-a-sha-at-all"
    packet["push_status"].update(pushed=True, review_ref="vdt-forged-id",
                                 statement="Shipped after the recorded approval.")
    with pytest.raises(SchemaError):
        validate_packet(packet)


def test_a_draft_with_unknown_head_and_no_push_is_unaffected(root):
    """Scoped correctly: a non-shipped packet may still legitimately not name a head yet."""
    packet = valid_packet(packet_id="draft-unknown")
    packet["git"]["base_sha"] = "unknown"
    packet["git"]["head_sha"] = "unknown"
    assert inbox.publish(packet).exists()


# --------------------------------------------------------------------------------------------
# Gap C — a shipped report's derived diff must not be EMPTY, either. `base_sha == head_sha` (the
# string-comparison bug closed in `gitfacts.derive`) is one way to reach an empty "derived" diff;
# two genuinely DIFFERENT, properly-ancestored commits that just happen to diff to nothing (an
# empty commit) is another, and `gitfacts` has no notion of "shipped" to refuse that one on — so
# the refusal lives here, at the ship-gate layer, same as Gap A's.
# --------------------------------------------------------------------------------------------

def test_an_honestly_derived_but_empty_diff_cannot_unlock_a_ship(root):
    """The diff is not CLAIMED (Gap A already refuses that) — it is genuinely `"derived"`, and it
    is genuinely empty. A reviewer who approved a packet reporting zero changed files reviewed
    nothing, and a ship report resting on that has nothing to cite as evidence of a real change."""
    packet_for("pkt-empty", head_sha="0900128", derived=True)
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-empty", decision="Approve", head_sha="0900128")).stem
    ship = valid_packet(
        packet_id="ship-empty", diff_provenance="derived", changed_files=[],
        diff_summary={"files_changed": 0, "insertions": 0, "deletions": 0},
    )
    ship["git"]["head_sha"] = "0900128"
    ship["push_status"].update(pushed=True, review_ref=ref,
                               statement="Shipped after the recorded approval.")
    with pytest.raises(PacketError, match="zero files"):
        publish_derived(ship)
    assert inbox.find_packet("ship-empty") is None


def test_an_empty_derived_diff_is_unaffected_for_a_draft_that_reports_no_push(root):
    """Scoped correctly: a packet may legitimately derive to an empty diff — a round that verified
    something changed nothing — as long as it is not the basis for a ship."""
    ship = valid_packet(
        packet_id="draft-empty", diff_provenance="derived", changed_files=[],
        diff_summary={"files_changed": 0, "insertions": 0, "deletions": 0},
    )
    ship["git"]["head_sha"] = "0900128"
    assert publish_derived(ship).exists()


def test_a_nonempty_honestly_derived_ship_report_is_still_unaffected(root):
    """The positive control, named for this gap specifically: a real, non-empty derived diff behind
    a shipped report is not touched by this check — it refuses on EMPTINESS, not on shipping."""
    packet_for("pkt-honest-c", head_sha="0900128", derived=True)
    ref = inbox.publish_verdict(
        build_verdict(packet_id="pkt-honest-c", decision="Approve", head_sha="0900128")).stem
    ship = valid_packet(packet_id="ship-honest-c")
    ship["git"]["head_sha"] = "0900128"
    ship["push_status"].update(pushed=True, review_ref=ref,
                               statement="Shipped after the recorded approval.")
    assert publish_derived(ship).exists()
