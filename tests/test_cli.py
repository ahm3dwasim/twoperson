"""The explicit launcher: `python -m twoperson`.

The explicit command is the contract a Builder session calls at completion and a Reviewer session calls
to audit — so its exit codes and stdout are pinned here. The `Stop` hook added alongside it
(`tests/test_hook_install.py`) only ever calls `signal`; `publish` remains the one way a
change becomes auditable, and `check`/`next` remain the audit gate.
"""
from __future__ import annotations

import json

import pytest

from twoperson.__main__ import main
from twoperson import inbox
from twoperson.hook import HOOK_COMMAND, HOOK_EVENT
from tests.fixtures import valid_packet


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    return target


def _write(tmp_path, packet, name="packet.json"):
    path = tmp_path / name
    path.write_text(json.dumps(packet), encoding="utf-8")
    return str(path)


def test_publish_from_a_file_exits_zero_and_prints_the_path(root, tmp_path, capsys):
    rc = main(["publish", "--from", _write(tmp_path, valid_packet())])
    out = capsys.readouterr().out
    assert rc == 0
    assert str(root / "pending") in out
    assert len(inbox.pending()) == 1


def test_publish_from_stdin(root, monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(valid_packet())))
    assert main(["publish", "--from", "-"]) == 0
    assert len(inbox.pending()) == 1


def test_publish_of_an_invalid_packet_exits_nonzero_and_writes_nothing(root, tmp_path, capsys):
    bad = valid_packet()
    bad.pop("push_status")
    rc = main(["publish", "--from", _write(tmp_path, bad)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "push_status" in err
    assert inbox.pending() == []


def test_publish_of_a_missing_file_exits_nonzero(root, tmp_path, capsys):
    assert main(["publish", "--from", str(tmp_path / "nope.json")]) == 2
    assert "nope.json" in capsys.readouterr().err


def test_verify_does_not_publish(root, tmp_path, capsys):
    assert main(["verify", "--from", _write(tmp_path, valid_packet())]) == 0
    assert inbox.pending() == []
    assert "ok" in capsys.readouterr().out.lower()


def test_verify_reports_the_failing_rule(root, tmp_path, capsys):
    bad = valid_packet()
    bad["push_status"]["pushed"] = True
    assert main(["verify", "--from", _write(tmp_path, bad)]) == 2
    assert "review_ref" in capsys.readouterr().err


def test_list_prints_pending_packets_one_per_line(root, capsys):
    inbox.publish(valid_packet(packet_id="one", created_at="2026-08-19T08:00:00Z"))
    inbox.publish(valid_packet(packet_id="two", created_at="2026-08-19T09:00:00Z"))
    assert main(["list"]) == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert "one" in lines[0] and "two" in lines[1]


def test_list_on_an_empty_inbox_is_quiet_and_exits_zero(root, capsys):
    assert main(["list"]) == 0
    assert capsys.readouterr().out.strip() == ""


def test_check_is_the_cheap_event_probe(root, capsys):
    """Exit 0 = work waiting, 1 = nothing. Cheap enough to poll without spending tokens."""
    assert main(["check"]) == 1
    inbox.publish(valid_packet())
    assert main(["check"]) == 0


def test_next_claims_and_renders_the_packet_as_untrusted_data(root, capsys):
    inbox.publish(valid_packet())
    assert main(["next"]) == 0
    out = capsys.readouterr().out
    assert "UNTRUSTED" in out
    assert "reviewer-handoff-bridge-001" in out
    assert inbox.pending() == []
    assert list((root / "claimed").glob("*.json"))


def test_next_on_an_empty_inbox_exits_one(root, capsys):
    assert main(["next"]) == 1


def test_next_peek_renders_without_claiming(root, capsys):
    inbox.publish(valid_packet())
    assert main(["next", "--peek"]) == 0
    assert "UNTRUSTED" in capsys.readouterr().out
    assert len(inbox.pending()) == 1


def test_next_json_emits_the_raw_packet_for_machine_consumers(root, capsys):
    inbox.publish(valid_packet())
    assert main(["next", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["run_id"] == "run-000042"


def test_template_emits_a_packet_skeleton_that_validates_after_filling(root, capsys):
    assert main(["template"]) == 0
    skeleton = json.loads(capsys.readouterr().out)
    assert skeleton["schema_version"] == "1"
    assert skeleton["push_status"]["pushed"] is False
    assert skeleton["task_id"] == "unknown"


def test_stdout_stays_machine_readable_and_logs_go_to_stderr(root, capsys):
    """`next --json` and `list` are piped into other tools; structured logs must not land there."""
    inbox.publish(valid_packet())
    capsys.readouterr()
    assert main(["next", "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["packet_id"] == "reviewer-handoff-bridge-001"
    assert "twoperson.claimed" in captured.err


def test_unknown_subcommand_exits_nonzero(root):
    with pytest.raises(SystemExit) as excinfo:
        main(["frobnicate"])
    assert excinfo.value.code != 0


# --------------------------------------------------------------------------------------------
# `signal` — the Stop-hook path. It may report nothing, but it may never reject.
# --------------------------------------------------------------------------------------------

def test_signal_emits_a_signal_and_never_a_packet(root, capsys):
    assert main(["signal", "--note", "done"]) == 0
    assert str(root / "signals") in capsys.readouterr().out
    assert inbox.pending() == [], "a completion signal must never enter the packet lane"
    assert len(inbox.pending_signals()) == 1


def test_signal_reads_the_session_id_from_the_hook_payload(root, monkeypatch, capsys):
    import io
    payload = json.dumps({"session_id": "sess-from-hook", "hook_event_name": "Stop"})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert main(["signal", "--hook-stdin", "--source", "claude-code-stop-hook"]) == 0
    capsys.readouterr()
    (_path, signal), = inbox.read_signals()
    assert signal["session_id"] == "sess-from-hook"
    assert signal["source"] == "claude-code-stop-hook"


def test_signal_never_returns_the_rejection_code(tmp_path, monkeypatch, capsys):
    """Claude Code reads a 2 from a Stop hook as "block stopping" — this path must not do that."""
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("i am a file", encoding="utf-8")
    monkeypatch.setenv("TWOPERSON_INBOX", str(blocked / "twoperson"))
    rc = main(["signal"])
    assert rc == 1, "soft failure, never the rejection code"
    assert "signal not emitted" in capsys.readouterr().err


def test_a_waiting_signal_does_not_make_check_claim_a_packet_is_ready(root, capsys):
    assert main(["signal"]) == 0
    capsys.readouterr()
    assert main(["check"]) == 1, "only a packet may satisfy the audit probe"
    assert main(["next"]) == 1


def test_signals_lists_one_line_each_and_exits_one_when_empty(root, capsys):
    assert main(["signals"]) == 1
    assert capsys.readouterr().out.strip() == ""
    assert main(["signal"]) == 0
    capsys.readouterr()
    assert main(["signals"]) == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 1 and "source=" in lines[0] and "packet_pending=" in lines[0]


def test_signals_json_is_machine_readable(root, capsys):
    assert main(["signal"]) == 0
    capsys.readouterr()
    assert main(["signals", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "completion_signal"


def test_signals_without_ack_leaves_them_waiting(root, capsys):
    assert main(["signal"]) == 0
    capsys.readouterr()
    assert main(["signals"]) == 0 and main(["signals"]) == 0


def test_signals_ack_consumes_them(root, capsys):
    assert main(["signal"]) == 0
    capsys.readouterr()
    assert main(["signals", "--ack"]) == 0
    assert main(["signals"]) == 1, "an acknowledged signal must not wake an auditor twice"


# --------------------------------------------------------------------------------------------
# `install-hook`
# --------------------------------------------------------------------------------------------

def test_install_hook_check_then_install_then_check(root, tmp_path, capsys):
    target = tmp_path / ".claude" / "settings.json"
    assert main(["install-hook", "--settings", str(target), "--check"]) == 1
    assert "missing" in capsys.readouterr().out
    assert main(["install-hook", "--settings", str(target)]) == 0
    assert "installed" in capsys.readouterr().out
    assert main(["install-hook", "--settings", str(target), "--check"]) == 0
    assert "current" in capsys.readouterr().out
    installed = json.loads(target.read_text(encoding="utf-8"))
    assert installed["hooks"][HOOK_EVENT][0]["hooks"][0]["command"] == HOOK_COMMAND


def test_install_hook_rejects_an_implausible_target(root, tmp_path, capsys):
    target = tmp_path / "crontab"
    assert main(["install-hook", "--settings", str(target)]) == 2
    assert "must be named" in capsys.readouterr().err
    assert not target.exists()


# --------------------------------------------------------------------------------------------
# Fail-closed must ARRIVE as a refusal, not as a stack trace
#
# Making the lane listing raise is only half a fix. The other half is that every edge which reads a
# lane — the CLI, the watcher — turns that raise into an outcome an operator can act on, without
# dying.
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


def test_no_cli_command_tracebacks_on_a_lane_it_was_refused(root, capsys):
    """One boundary net, so the covered set is not a hand-kept list of remembered commands.

    Four commands read a lane through the raising helper with nothing between them and the operator
    that caught it.
    """
    for lane, argv in (("verdicts", ["verdicts"]),
                       ("advice", ["consult-advice"]),
                       ("consult", ["consult-list"]),
                       ("pending", ["next"])):
        _drop_symlink(root, lane, name=f"9999-hostile-{lane}.json")
        code = main(argv)
        captured = capsys.readouterr()
        assert code != 0, f"{argv[0]}: a refused lane must not report success"
        assert "refused" in (captured.err + captured.out).lower(), (
            f"{argv[0]}: the refusal must reach the operator, got {captured.err!r}"
        )


def test_the_check_probe_never_answers_nothing_waiting_for_a_lane_it_could_not_read(root, capsys):
    """`check`'s exit code IS its answer, so EXIT_NOTHING here would be the false negative itself."""
    from twoperson.__main__ import EXIT_NOTHING

    _drop_symlink(root, "pending")
    code = main(["check"])
    assert code != EXIT_NOTHING, "a refused lane reported as 'no work waiting'"
    assert code != 0


def test_the_list_command_reports_a_refused_lane_instead_of_listing_nothing(root, capsys):
    _drop_symlink(root, "pending")
    code = main(["list"])
    captured = capsys.readouterr()
    assert code != 0
    assert "refused" in captured.err.lower()


def test_watch_once_reports_a_refused_lane_and_exits_nonzero(root, capsys):
    """A refused lane printed "nothing new" and exited 0 — refusal-equals-empty rebuilt at the CLI
    boundary, one level above the reader that was fixed for it. "I could not read this lane" is not
    "there is nothing in it", and the exit code has to say so.
    """
    _drop_symlink(root, "pending")
    code = main(["watch", "--once"])
    captured = capsys.readouterr()
    assert code != 0, "watch --once reported success on a lane it was refused"
    assert "lane refused" in captured.err
    assert "nothing new" not in captured.out or "COULD READ" in captured.out
