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
    # --no-derive: the shared fixture names a synthetic head, which the diff derivation correctly
    # refuses (pinned by test_a_fabricated_head_is_refused_by_default). This test is about publish
    # writing the packet, so it opts out of the git checks rather than inventing a real commit.
    rc = main(["publish", "--no-derive", "--from", _write(tmp_path, valid_packet())])
    out = capsys.readouterr().out
    assert rc == 0
    assert str(root / "pending") in out
    assert len(inbox.pending()) == 1


def test_publish_from_stdin(root, monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(valid_packet())))
    assert main(["publish", "--no-derive", "--from", "-"]) == 0
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
    assert main(["verify", "--no-derive", "--from", _write(tmp_path, valid_packet())]) == 0
    assert inbox.pending() == []
    assert "ok" in capsys.readouterr().out.lower()


def test_a_fabricated_head_is_refused_by_default(root, tmp_path, capsys):
    """A packet whose head is not a real commit must not publish.

    Before this check, a packet naming a head that does not exist — or one that exists but whose
    diff is nothing like the stated numbers — published cleanly, and the reviewer had to notice.
    """
    assert main(["publish", "--from", _write(tmp_path, valid_packet())]) == 2
    assert inbox.pending() == []
    err = capsys.readouterr().err
    assert "not in this repository" in err
    assert "--no-derive" in err, "the refusal must name the deliberate escape hatch"


def test_no_derive_says_out_loud_that_nothing_was_checked(root, tmp_path, capsys):
    """An unverified claim may publish, but it must never look like a verified one."""
    assert main(["publish", "--no-derive", "--from", _write(tmp_path, valid_packet())]) == 0
    err = capsys.readouterr().err
    assert "NOT derived" in err
    assert "NOT verified" in err
    packet = inbox.peek_next().packet
    assert packet["diff_provenance"] == "claimed"


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


# --------------------------------------------------------------------------------------------
# ...and the refusal is RAISED at the source, so it is not a hand-kept list either
#
# The net above only helps the commands that reach a reader which fails closed. A lane the chain
# cannot OPEN is a different hop: `os.open` answers with a raw `OSError`, which no per-command
# `except OSError` covers and the boundary net does not catch. So a symlinked lane — or a symlinked
# ROOT — arrived as a stack trace with exit 1, the code that means "nothing to do": the refusal
# reported as the empty answer it exists to be told apart from, one level below where the readers
# were fixed for it. The fix is that the chain raises `LaneUnreadable` itself, which is what makes
# this list exhaustive rather than remembered.
# --------------------------------------------------------------------------------------------

# Every subcommand that reaches a lane, with the lane it reaches FIRST. `verify` (for a packet that
# shipped nothing), `template`, `consult-template`, `consult-verify` and `install-hook` read no lane
# at all and are deliberately absent — parametrizing them would assert a refusal that is not due.
# `install-watch` is absent for a different reason: its writing path does call `_ensure_tree`, but it
# then installs a launchd agent on the machine running the test.
_LANE_COMMANDS = (
    pytest.param(["check"], "pending", id="check"),
    pytest.param(["list"], "pending", id="list"),
    pytest.param(["next"], "pending", id="next"),
    pytest.param(["next", "--peek"], "pending", id="next-peek"),
    pytest.param(["tier"], "pending", id="tier"),
    pytest.param(["watch", "--once"], "pending", id="watch-once"),
    pytest.param(["publish", "--from", "@packet", "--no-derive"], "pending", id="publish"),
    pytest.param(["verdict", "--packet", "any-id", "--decision", "Approve"], "pending",
                 id="verdict"),
    pytest.param(["verdicts"], "verdicts", id="verdicts"),
    pytest.param(["consult-check"], "consult", id="consult-check"),
    pytest.param(["consult-list"], "consult", id="consult-list"),
    pytest.param(["consult-next"], "consult", id="consult-next"),
    pytest.param(["consult-publish", "--from", "@consult"], "consult", id="consult-publish"),
    pytest.param(["consult-advice"], "advice", id="consult-advice"),
    pytest.param(["consult-advise", "--consult", "any-id", "--recommendation", "advise me"],
                 "advice", id="consult-advise"),
)

#: The chain's own wording for a hop it could not make (`inbox._refusal`). Asserted rather than the
#: per-command wrapper text, which differs: `check` prints "cannot determine whether work is
#: waiting", `publish` prints "publish failed", `verdict` prints "verdict rejected". A command that
#: refused for an unrelated reason (a schema failure, a bad argument) would satisfy "exit 2" on its
#: own and the test would pass while proving nothing about the lane.
_CHAIN_REFUSAL = "could not be opened"


def _materialize(argv, tmp_path):
    """Replace the ``@packet`` / ``@consult`` placeholders with files holding valid documents.

    They must be VALID: a packet the schema rejects would exit 2 for the wrong reason.
    """
    from twoperson.consult import build_consult, dumps_consult

    out = []
    for token in argv:
        if token == "@packet":
            out.append(str(_write(tmp_path, valid_packet())))
        elif token == "@consult":
            path = tmp_path / "consult.json"
            path.write_text(dumps_consult(build_consult(question="is this reachable?")),
                            encoding="utf-8")
            out.append(str(path))
        else:
            out.append(token)
    return out


def _real_inbox(root):
    """A REAL, populated inbox for ``root`` to be a symlink TO.

    It must hold real work: an inbox with nothing in it also answers 0 or 1, so a command that
    silently followed the link would be indistinguishable from one that refused.
    """
    real = root.parent / "a-real-inbox"
    real.mkdir()
    inbox._ensure_tree(real)
    inbox.publish(valid_packet(), root=real)
    return real


@pytest.mark.parametrize("placement", ["a symlinked root", "a symlinked lane"])
@pytest.mark.parametrize("argv,lane", _LANE_COMMANDS)
def test_every_lane_command_refuses_a_symlinked_root_or_lane(root, tmp_path, capsys, argv, lane,
                                                             placement):
    """The property, over every command that reaches a lane: exit 2 and no stack trace.

    Both placements are the same defect at two heights. A symlinked ROOT is refused by the chain's
    first hop; a symlinked LANE by the second. The second is also the case a per-command guard
    misses in the other direction: for the writing commands the lane is not one they came to READ —
    `_ensure_tree` holds every lane it walks past — so `publish` refuses a broken `claimed/` that no
    reader of its own ever asked for.
    """
    if placement == "a symlinked root":
        root.symlink_to(_real_inbox(root))
    else:
        inbox._ensure_tree(root)
        inbox.publish(valid_packet(), root=root)
        outside = root.parent / "outside"       # must EXIST: a dangling link is not a refusal
        outside.mkdir()
        (outside / "smuggled.json").write_text(json.dumps(valid_packet(packet_id="smuggled")),
                                               encoding="utf-8")
        (root / lane).rename(root / f"{lane}-real")
        (root / lane).symlink_to(outside)

    code = main(_materialize(argv, tmp_path))
    captured = capsys.readouterr()
    assert code == 2, (
        f"{' '.join(argv)}: {placement} must be a rejection (2), got {code} with "
        f"stderr={captured.err!r}"
    )
    assert "Traceback" not in captured.err, f"{' '.join(argv)}: a refusal arrived as a stack trace"
    assert _CHAIN_REFUSAL in captured.err, (
        f"{' '.join(argv)}: refused for something other than the lane, or said nothing about it; "
        f"got {captured.err!r}"
    )


# The commands that WRITE. Each one ends in `_ensure_tree`, which opens and holds EVERY lane in
# `_SUBDIRS` — so these are the commands that reach a lane they never came to read at all.
#
# This is the reported defect, and the two placements above do NOT cover it: a symlinked `pending/`
# is refused by the reader these commands call FIRST, so they exit 2 for a reason that has nothing
# to do with the hop that was broken. Symlinking a lane further down the list is what isolates it —
# `next` finds a perfectly good packet in `pending/`, claims it, and only then walks into `claimed/`.
_WRITING_COMMANDS = (
    pytest.param(["publish", "--from", "@packet", "--no-derive"], id="publish"),
    pytest.param(["next"], id="next"),
    pytest.param(["verdict", "--packet", "@packet_id", "--decision", "Approve"], id="verdict"),
    pytest.param(["consult-publish", "--from", "@consult"], id="consult-publish"),
    pytest.param(["consult-next"], id="consult-next"),
    pytest.param(["consult-advise", "--consult", "@consult_id", "--recommendation", "advise me"],
                 id="consult-advise"),
    pytest.param(["signals", "--ack"], id="signals-ack"),
    pytest.param(["verdicts", "--ack"], id="verdicts-ack"),
    pytest.param(["consult-advice", "--ack"], id="consult-advice-ack"),
)


def _populate(root):
    """One of everything, published BEFORE any lane is tampered with.

    The `--ack` commands read their lane and return early when it is empty, so an empty inbox would
    exit 1 and prove nothing: they have to have something to acknowledge before they reach the
    `_ensure_tree` that holds `claimed/`. Returns the ids the argv placeholders need.
    """
    from twoperson.advice import build_advice
    from twoperson.consult import build_consult
    from twoperson.signal import build_signal
    from twoperson.verdict import build_verdict

    inbox._ensure_tree(root)
    packet = valid_packet()
    inbox.publish(packet, root=root)
    inbox.publish_signal(build_signal(session_id="sess-populated"), root=root)
    consult = build_consult(question="is this reachable?")
    inbox.publish_consult(consult, root=root)
    inbox.publish_advice(build_advice(consult_id=consult["consult_id"],
                                      recommendation="advise me"), root=root)
    inbox.publish_verdict(build_verdict(packet_id=packet["packet_id"], decision="Approve",
                                        head_sha=packet["git"]["head_sha"]), root=root)
    return packet["packet_id"], consult["consult_id"]


@pytest.mark.parametrize("argv", _WRITING_COMMANDS)
def test_a_writing_command_refuses_a_lane_it_only_walks_past(root, tmp_path, capsys, argv):
    """`claimed/` is a lane none of these commands came to READ.

    `publish` writes to `staging/` then `pending/`; `next` reads `pending/` and moves to `claimed/`;
    the `--ack` commands move out of `signals/`, `verdicts/` and `advice/`. None of them opens
    `claimed/` on purpose — `_ensure_tree` holds it only because a lane that cannot be opened is a
    lane whose emptiness nobody can vouch for, and the lane it is about to be handed has to be one
    of a set that is wholly readable. Before the chain raised at the source, this hop answered with
    a raw `NotADirectoryError` and `next` reported the refusal as a stack trace with exit 1.
    """
    packet_id, consult_id = _populate(root)
    outside = root.parent / "outside"           # must EXIST: a dangling link is not a refusal
    outside.mkdir()
    (root / "claimed").rmdir()
    (root / "claimed").symlink_to(outside)

    resolved = [t.replace("@packet_id", packet_id).replace("@consult_id", consult_id)
                for t in _materialize(argv, tmp_path)]
    code = main(resolved)
    captured = capsys.readouterr()
    assert code == 2, (
        f"{' '.join(argv)}: a broken lane it only walks past must be a rejection (2), got {code} "
        f"with stderr={captured.err!r}"
    )
    assert "Traceback" not in captured.err, f"{' '.join(argv)}: a refusal arrived as a stack trace"
    assert _CHAIN_REFUSAL in captured.err and "'claimed'" in captured.err, (
        f"{' '.join(argv)}: expected a refusal naming the 'claimed' lane, got {captured.err!r}"
    )
    assert list(outside.iterdir()) == [], "work was moved into a lane that pointed outside the inbox"


@pytest.mark.parametrize("placement", ["a symlinked root", "a symlinked lane"])
def test_the_signal_lane_opts_out_of_the_refusal_without_tracebacking(root, tmp_path, capsys,
                                                                      placement):
    """The two commands the property deliberately does NOT give exit 2 to, pinned so that is a
    decision and not an oversight.

    `signal` runs from the Stop hook, where a 2 means "block stopping" — it degrades to 1 by design.
    `signals` reads the one lane that opts out of fail-closed (a signal gates nothing), so it
    under-reports rather than refusing. Neither may traceback, and both were exit 1 before this
    change too: what changed is that the exit is now reached by an answer rather than by a crash.
    """
    if placement == "a symlinked root":
        root.symlink_to(_real_inbox(root))
    else:
        inbox._ensure_tree(root)
        outside = root.parent / "outside"       # must EXIST: a dangling link is not a refusal
        outside.mkdir()
        (root / "pending").rmdir()
        (root / "pending").symlink_to(outside)

    for argv in (["signal"], ["signals"]):
        code = main(argv)
        captured = capsys.readouterr()
        assert code == 1, f"{' '.join(argv)}: expected the documented 1, got {code}"
        assert "Traceback" not in captured.err, f"{' '.join(argv)}: arrived as a stack trace"


# --------------------------------------------------------------------------------------------
# r3: the ROOT itself is a refusal surface, at every subcommand
#
# `_ensure_tree` created the root with `Path.mkdir` BEFORE the open that turns failures into
# `LaneUnreadable`, so a root that is an existing regular file, a root that is a dangling symlink and
# a parent this process may not write to each escaped as a raw `FileExistsError` / `PermissionError`.
# These are the three placements, over the same command list the lane placements use — each one is a
# DIFFERENT syscall answering (an open that refuses, an open that refuses, a mkdir that refuses), so
# one fix per placement would be a hand-kept list again.
# --------------------------------------------------------------------------------------------

#: The same commands `_LANE_COMMANDS` covers, plus the writing set, minus `signals --ack`. The signal
#: lane's documented opt-out covers it: `signals` reads the one lane that under-reports by design, so
#: a refused root reaches it as "no signals" and exits 1 — pinned in its own test below rather than
#: asserted here as a 2 that would have to be wrong. Spelled out with the lane each command reaches
#: first, because the writing set carries one placeholder shape and this list needs the lane too.
_ROOT_REFUSAL_COMMANDS = (
    pytest.param(["check"], "pending", id="check"),
    pytest.param(["list"], "pending", id="list"),
    pytest.param(["next"], "pending", id="next"),
    pytest.param(["next", "--peek"], "pending", id="next-peek"),
    pytest.param(["tier"], "pending", id="tier"),
    pytest.param(["watch", "--once"], "pending", id="watch-once"),
    pytest.param(["publish", "--from", "@packet", "--no-derive"], "pending", id="publish"),
    pytest.param(["verdict", "--packet", "any-id", "--decision", "Approve"], "pending", id="verdict"),
    pytest.param(["verdicts"], "verdicts", id="verdicts"),
    pytest.param(["verdicts", "--ack"], "verdicts", id="verdicts-ack"),
    pytest.param(["consult-check"], "consult", id="consult-check"),
    pytest.param(["consult-list"], "consult", id="consult-list"),
    pytest.param(["consult-next"], "consult", id="consult-next"),
    pytest.param(["consult-publish", "--from", "@consult"], "consult", id="consult-publish"),
    pytest.param(["consult-advice"], "advice", id="consult-advice"),
    pytest.param(["consult-advice", "--ack"], "advice", id="consult-advice-ack"),
    pytest.param(["consult-advise", "--consult", "any-id", "--recommendation", "advise me"],
                 "advice", id="consult-advise"),
)

#: The two verbs a root refusal is spelled with (`inbox._refusal`, and `_refuse_a_root_that_cannot_be
#: _created` for the wall): a root that IS something is one that could not be OPENED, a root that
#: cannot be MADE is one that could not be CREATED. Asserted so a command that exited 2 for an
#: unrelated reason (a schema failure, a bad argument) cannot satisfy this test while proving nothing.
_ROOT_REFUSAL = ("could not be opened", "could not be created")

_PLACEMENTS = ("a regular-file root", "a dangling root symlink", "an unwritable parent")


def _place_root(placement, root, tmp_path, monkeypatch):
    """Build one of the three root placements, and return a callable that undoes it."""
    if placement == "a regular-file root":
        root.write_text("not an inbox", encoding="utf-8")
        return lambda: None
    if placement == "a dangling root symlink":
        root.symlink_to(tmp_path / "nowhere")
        return lambda: None
    # An unwritable parent: the root cannot exist AND cannot be made. The parent is a directory of
    # its own so no other path in this test depends on it, and it is restored for cleanup.
    parent = tmp_path / "ro"
    parent.mkdir()
    parent.chmod(0o500)
    monkeypatch.setenv("TWOPERSON_INBOX", str(parent / "twoperson"))
    return lambda: parent.chmod(0o700)


@pytest.mark.parametrize("placement", _PLACEMENTS)
@pytest.mark.parametrize("argv,lane", _ROOT_REFUSAL_COMMANDS)
def test_every_lane_command_refuses_a_root_it_cannot_use(root, tmp_path, monkeypatch, capsys, argv,
                                                         lane, placement):
    """Exit 2, no stack trace, and a refusal that names the root — for all three placements.

    `publish` reaches this through `_ensure_tree`'s `mkdir`, the readers through the chain's first
    open, and the `--ack` commands through a lane read; the exit code and the wording are the same
    because the refusal is raised where the hop failed, not remembered per command.
    """
    undo = _place_root(placement, root, tmp_path, monkeypatch)
    try:
        # A process that can write to a 0500 directory (root, or a filesystem without modes) cannot
        # construct this placement at all; assert only what the filesystem actually enforces.
        if placement == "an unwritable parent":
            probe = tmp_path / "ro" / "probe"      # inside the 0500 parent, not its parent
            try:
                probe.mkdir()
            except OSError:
                pass
            else:
                probe.rmdir()
                pytest.skip("this process can write to a 0500 directory; the placement is unavailable")

        code = main(_materialize(argv, tmp_path))
        captured = capsys.readouterr()
        assert code == 2, (
            f"{' '.join(argv)}: {placement} must be a rejection (2), got {code} with "
            f"stderr={captured.err!r}"
        )
        assert "Traceback" not in captured.err, (
            f"{' '.join(argv)}: a refusal arrived as a stack trace: {captured.err!r}"
        )
        assert any(w in captured.err for w in _ROOT_REFUSAL), (
            f"{' '.join(argv)}: refused for something other than the root, or said nothing about "
            f"it; got {captured.err!r}"
        )
    finally:
        undo()


@pytest.mark.parametrize("placement", _PLACEMENTS)
def test_the_signal_lane_opts_out_of_a_root_refusal_without_tracebacking(root, tmp_path, monkeypatch,
                                                                        capsys, placement):
    """`signal` and `signals` keep the exit 1 they document, for a root as much as for a lane.

    `signal` runs from the Stop hook, where 2 means "block stopping", and `signals` reads the one lane
    that under-reports on purpose (a signal gates nothing). What may not happen is a traceback: these
    are the two commands whose documented answer is not 2, and an uncaught root failure would have
    given them both a crash instead.
    """
    undo = _place_root(placement, root, tmp_path, monkeypatch)
    try:
        for argv in (["signal"], ["signals"], ["signals", "--ack"]):
            code = main(argv)
            captured = capsys.readouterr()
            assert code == 1, f"{' '.join(argv)}: expected the documented 1, got {code}"
            assert "Traceback" not in captured.err, (
                f"{' '.join(argv)}: arrived as a stack trace: {captured.err!r}"
            )
    finally:
        undo()
