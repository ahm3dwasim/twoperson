"""The two claims the README makes, tested as claims.

1. A verdict is about a packet that exists; an approval names that packet's own head.
2. A packet that says it pushed cites a verdict that exists, approves, and approves THAT head.

Both were previously true only by convention (the reviewer runs `next` first, the builder copies the
verdict id). A public tool that says "the schema enforces it" has to mean it.
"""
from __future__ import annotations

import pytest

from tests.fixtures import packet_for, valid_packet
from twoperson import inbox
from twoperson.__main__ import main
from twoperson.packet import PacketError
from twoperson.verdict import build_verdict


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    return target


# ---- verdict -> packet ----------------------------------------------------------------------

def test_a_verdict_for_a_packet_nobody_published_is_refused(root):
    with pytest.raises(PacketError) as excinfo:
        inbox.publish_verdict(build_verdict(packet_id="never-published", decision="Approve", head_sha="0900128"))
    assert "no packet" in str(excinfo.value)
    assert not (root / "verdicts").exists() or not list((root / "verdicts").iterdir())


def test_the_cli_refuses_an_approval_for_a_nonexistent_packet(root, capsys):
    rc = main(["verdict", "--packet", "never-published", "--decision", "Approve", "--head", "0900128"])
    assert rc == 2
    assert "no packet" in capsys.readouterr().err


def test_an_approval_must_name_the_packets_own_head(root):
    packet_for("pkt-1", head_sha="0900128")
    with pytest.raises(PacketError) as excinfo:
        inbox.publish_verdict(build_verdict(packet_id="pkt-1", decision="Approve", head_sha="abcdef0"))
    assert "binds to the packet's own head" in str(excinfo.value)


def test_a_request_changes_verdict_does_not_need_a_matching_head(root):
    """Only a ship-unlocking decision binds to a sha; a rejection may be recorded against `unknown`."""
    packet_for("pkt-2", head_sha="0900128")
    path = inbox.publish_verdict(build_verdict(packet_id="pkt-2", decision="Request changes"))
    assert path.exists()


def test_the_cli_defaults_head_to_the_packets_head(root, capsys):
    packet_for("pkt-3", head_sha="0900128")
    assert main(["verdict", "--packet", "pkt-3", "--decision", "Approve"]) == 0
    (_, verdict), = inbox.read_verdicts()
    assert verdict["head_sha"] == "0900128"


def test_a_verdict_may_answer_a_claimed_or_audited_packet(root):
    packet_for("pkt-4", head_sha="0900128")
    claimed = inbox.claim_next()
    assert inbox.publish_verdict(build_verdict(packet_id="pkt-4", decision="Approve", head_sha="0900128"))
    inbox.archive_claimed(claimed.path)
    assert inbox.publish_verdict(build_verdict(packet_id="pkt-4", decision="Approve with nits", head_sha="0900128"))


# ---- packet(pushed) -> verdict --------------------------------------------------------------

def _pushed(review_ref: str, head: str = "0900128", **flags) -> dict:
    """A ship report. ``flags`` picks WHICH side effect happened; default is a push."""
    packet = valid_packet(packet_id="ship-report")
    packet["git"]["head_sha"] = head
    effects = flags or {"pushed": True}
    packet["push_status"].update(review_ref=review_ref, statement="Shipped after the recorded approval.",
                                 **effects)
    return packet


def test_a_push_citing_a_verdict_that_does_not_exist_is_refused(root):
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(_pushed("vdt-20260101T000000Z-00000000"))
    assert "not the id of any verdict" in str(excinfo.value)
    assert not inbox.pending()


def test_a_push_citing_a_request_changes_verdict_is_refused(root):
    packet_for("pkt-5", head_sha="0900128")
    path = inbox.publish_verdict(build_verdict(packet_id="pkt-5", decision="Request changes"))
    ref = path.stem
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(_pushed(ref))
    assert "does not unlock a ship" in str(excinfo.value)


def test_a_push_citing_an_approval_for_a_different_head_is_refused(root):
    packet_for("pkt-6", head_sha="0900128")
    ref = inbox.publish_verdict(build_verdict(packet_id="pkt-6", decision="Approve", head_sha="0900128")).stem
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(_pushed(ref, head="abcdef0"))
    assert "different commit" in str(excinfo.value)


def test_a_push_citing_a_real_approval_for_the_same_head_is_accepted(root):
    packet_for("pkt-7", head_sha="0900128")
    ref = inbox.publish_verdict(build_verdict(packet_id="pkt-7", decision="Approve", head_sha="0900128")).stem
    assert inbox.publish(_pushed(ref)).exists()


def test_an_acknowledged_verdict_still_resolves(root):
    """Acking moves a verdict to verdicts_seen/; a later ship report must still be able to cite it."""
    packet_for("pkt-8", head_sha="0900128")
    ref = inbox.publish_verdict(build_verdict(packet_id="pkt-8", decision="Approve", head_sha="0900128")).stem
    inbox.ack_verdicts([p for p, _ in inbox.read_verdicts()])
    assert inbox.publish(_pushed(ref)).exists()


def test_verify_also_resolves_the_reference_without_writing(root, tmp_path, capsys):
    packet = _pushed("vdt-20260101T000000Z-00000000")
    f = tmp_path / "p.json"
    f.write_text(__import__("json").dumps(packet))
    assert main(["verify", "--from", str(f)]) == 2
    assert "not the id of any verdict" in capsys.readouterr().err
    assert not inbox.pending()


# ---- deploy / restart are "shipped" too ---------------------------------------------------------

@pytest.mark.parametrize("effect", ["deployed", "restarted"])
def test_a_deploy_or_restart_citing_no_real_verdict_is_refused(root, effect):
    """Reviewer r2 P0: gating only `pushed` let `deployed=true` through with review_ref=unknown."""
    with pytest.raises(PacketError):
        inbox.publish(_pushed("vdt-20260101T000000Z-00000000", **{effect: True}))
    assert not inbox.pending()


@pytest.mark.parametrize("effect", ["deployed", "restarted"])
def test_a_deploy_or_restart_citing_an_approval_for_a_different_head_is_refused(root, effect):
    packet_for("pkt-9", head_sha="0900128")
    ref = inbox.publish_verdict(build_verdict(packet_id="pkt-9", decision="Approve", head_sha="0900128")).stem
    with pytest.raises(PacketError) as excinfo:
        inbox.publish(_pushed(ref, head="abcdef0", **{effect: True}))
    assert "different commit" in str(excinfo.value)


@pytest.mark.parametrize("effect", ["deployed", "restarted"])
def test_a_deploy_or_restart_citing_a_real_approval_is_accepted(root, effect):
    packet_for("pkt-10", head_sha="0900128")
    ref = inbox.publish_verdict(build_verdict(packet_id="pkt-10", decision="Approve", head_sha="0900128")).stem
    assert inbox.publish(_pushed(ref, **{effect: True})).exists()
