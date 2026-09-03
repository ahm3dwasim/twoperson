"""The inbox watcher: it must wake BOTH sides on a change, exactly once each, and never crash.

Three properties carry the design and are pinned hardest here:

1. **Both directions.** A new packet wakes the Reviewer/audit side; a new verdict wakes the Builder side.
2. **Idempotent under a coalescing watcher.** launchd fires once for a burst and says nothing about
   what changed, so a second pass over the same inbox does nothing — no double notification, no
   double launch.
3. **The launch command is owner config, never packet content**, and a missing backend / failing
   command degrades to a logged no-op rather than raising into the watcher.
"""
from __future__ import annotations

import os
import plistlib
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

from twoperson import inbox
from twoperson.verdict import build_verdict
from twoperson import watch
from twoperson.watch import (
    Cursor,
    dispatch_once,
    is_muted,
    load_cursor,
    save_cursor,
    scan_new,
    set_muted,
)
from twoperson import watchagent
from tests.fixtures import valid_packet, packet_for


@pytest.fixture
def root(tmp_path, monkeypatch):
    target = tmp_path / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    # Never let a test touch the real launch commands.
    monkeypatch.delenv(watch.AUDIT_CMD_ENV, raising=False)
    monkeypatch.delenv(watch.WAKE_CMD_ENV, raising=False)
    return target


class Recorder:
    """A stand-in for notify/run so a test asserts on calls without a desktop or a subprocess."""

    def __init__(self):
        self.notes: list[tuple[str, str]] = []
        self.commands: list[str] = []

    def notify(self, title, message):
        self.notes.append((title, message))
        return True

    def run(self, command, *, timeout=None):
        self.commands.append(command)
        return 0


# --------------------------------------------------------------------------------------------
# Pure core: scan_new
# --------------------------------------------------------------------------------------------

def test_scan_new_sees_a_fresh_packet_and_verdict(root):
    packet_for("PKT-x")
    inbox.publish_verdict(build_verdict(packet_id="PKT-x", decision="Approve", head_sha="0900128"))
    delta = scan_new(None, Cursor())
    assert len(delta.new_packets) == 1
    assert len(delta.new_verdicts) == 1
    assert not delta.is_empty


def test_scan_new_is_empty_when_cursor_already_covers_the_lanes(root):
    inbox.publish(valid_packet())
    first = scan_new(None, Cursor())
    second = scan_new(None, first.cursor)  # nothing changed since `first`
    assert second.is_empty


def test_scan_new_cursor_prunes_a_claimed_packet(root):
    inbox.publish(valid_packet())
    first = scan_new(None, Cursor())
    inbox.claim_next()  # packet leaves pending/
    nxt = scan_new(None, first.cursor)
    assert nxt.cursor.packets == frozenset(), "a claimed packet drops out of the cursor"


# --------------------------------------------------------------------------------------------
# dispatch_once: both directions, idempotence, launch gating
# --------------------------------------------------------------------------------------------

def test_dispatch_notifies_codex_on_a_new_packet(root):
    inbox.publish(valid_packet())
    rec = Recorder()
    report = dispatch_once(notify_fn=rec.notify, run_fn=rec.run)
    assert "reviewer" in report.notified
    assert rec.commands == [], "no launch command configured ⇒ notify only"


def test_dispatch_notifies_claude_on_a_new_verdict(root):
    packet_for("PKT-y")
    inbox.publish_verdict(build_verdict(packet_id="PKT-y", decision="Request changes"))
    rec = Recorder()
    report = dispatch_once(notify_fn=rec.notify, run_fn=rec.run)
    assert "builder" in report.notified


def test_dispatch_launches_the_configured_audit_command_on_a_packet(root):
    inbox.publish(valid_packet())
    rec = Recorder()
    report = dispatch_once(audit_cmd="run-reviewer-audit", notify_fn=rec.notify, run_fn=rec.run)
    assert rec.commands == ["run-reviewer-audit"]
    assert "reviewer" in report.launched


def test_dispatch_launches_the_configured_wake_command_on_a_verdict(root):
    packet_for("PKT-z")
    inbox.publish_verdict(build_verdict(packet_id="PKT-z", decision="Approve", head_sha="0900128"))
    rec = Recorder()
    dispatch_once(wake_cmd="wake-builder", notify_fn=rec.notify, run_fn=rec.run)
    assert rec.commands == ["wake-builder"]


def test_dispatch_is_idempotent_across_two_passes(root):
    inbox.publish(valid_packet())
    rec = Recorder()
    dispatch_once(audit_cmd="x", notify_fn=rec.notify, run_fn=rec.run)
    second = dispatch_once(audit_cmd="x", notify_fn=rec.notify, run_fn=rec.run)
    assert not second.acted, "a coalesced re-fire over the same inbox must do nothing twice"
    assert rec.commands == ["x"], "the audit command runs once, not once per watcher wake"


def test_dispatch_reads_launch_commands_from_the_environment(root, monkeypatch):
    monkeypatch.setenv(watch.AUDIT_CMD_ENV, "env-audit")
    inbox.publish(valid_packet())
    rec = Recorder()
    dispatch_once(notify_fn=rec.notify, run_fn=rec.run)
    assert rec.commands == ["env-audit"]


def test_empty_inbox_dispatch_does_nothing(root):
    rec = Recorder()
    report = dispatch_once(notify_fn=rec.notify, run_fn=rec.run)
    assert not report.acted
    assert rec.notes == [] and rec.commands == []


# --------------------------------------------------------------------------------------------
# Cursor persistence
# --------------------------------------------------------------------------------------------

def test_cursor_round_trips(root):
    save_cursor(Cursor(packets=frozenset({"a.json"}), verdicts=frozenset({"v.json"})))
    loaded = load_cursor()
    assert loaded.packets == {"a.json"} and loaded.verdicts == {"v.json"}


def test_a_corrupt_cursor_degrades_to_empty(root):
    inbox._ensure_tree(root)  # make the inbox dir so the file can be written
    (root / watch.CURSOR_NAME).write_text("{ not json", encoding="utf-8")
    assert load_cursor() == Cursor(), "a corrupt cursor must not raise; it starts clean"


# --------------------------------------------------------------------------------------------
# Effects never raise
# --------------------------------------------------------------------------------------------

def test_notify_never_raises_without_a_backend(monkeypatch):
    monkeypatch.setattr(watch.shutil, "which", lambda _name: None)
    assert watch.notify("t", "m") is False  # no backend ⇒ False, but no exception


def test_run_command_is_detached_fire_and_forget(tmp_path):
    # An empty command launches nothing and returns None.
    assert watch.run_command("   ") is None
    # A real command is launched DETACHED: run_command returns a pid immediately (does not wait) and
    # the command runs to completion on its own. We prove it ran by a side effect, polled briefly.
    marker = tmp_path / "ran.txt"
    pid = watch.run_command(f"sleep 0.1; echo ok > {marker}")
    assert isinstance(pid, int) and pid > 0
    deadline = time.time() + 5
    while not marker.exists() and time.time() < deadline:
        time.sleep(0.02)
    assert marker.read_text().strip() == "ok", "the detached command must actually run"


# --------------------------------------------------------------------------------------------
# launchd agent rendering + install
# --------------------------------------------------------------------------------------------

def test_render_plist_watches_the_actual_inbox_lanes(root):
    pl = watchagent.render_plist()
    assert pl["Label"] == watchagent.AGENT_LABEL
    assert pl["RunAtLoad"] is True
    watched = pl["WatchPaths"]
    assert str(root / "pending") in watched
    assert str(root / "verdicts") in watched
    assert str(root / "claimed") not in watched, "we only watch actionable lanes"


def test_install_watch_agent_writes_and_is_idempotent(root, tmp_path):
    home = tmp_path / "home"
    first = watchagent.install_watch_agent(home=home, reload=False)
    assert first.status == "installed" and first.path.exists()
    # A valid plist landed on disk.
    with first.path.open("rb") as fh:
        assert plistlib.load(fh)["Label"] == watchagent.AGENT_LABEL
    again = watchagent.install_watch_agent(home=home, reload=False)
    assert again.status == "current" and again.changed is False


def test_install_watch_check_reports_without_writing(root, tmp_path):
    home = tmp_path / "home"
    res = watchagent.install_watch_agent(home=home, check=True, reload=False)
    assert res.status == "missing" and not res.path.exists()


def test_check_mode_creates_no_directories(root, tmp_path):
    """`--check` is documented read-only: it must create neither the inbox tree nor the log dir."""
    home = tmp_path / "home"
    logs = tmp_path / "logs"
    assert not root.exists(), "precondition: the inbox does not exist yet"
    watchagent.install_watch_agent(home=home, log_dir=logs, check=True, reload=False)
    assert not root.exists(), "check mode must not create the inbox tree"
    assert not logs.exists(), "check mode must not create the log dir"


def test_render_plist_pins_the_inbox_env(root):
    """launchd does not inherit the installing shell's env, so the resolved inbox must be embedded —
    otherwise WatchPaths and the handler's runtime scan could target different inboxes."""
    pl = watchagent.render_plist()
    assert pl["EnvironmentVariables"]["TWOPERSON_INBOX"] == str(root)


def test_dispatch_retries_a_packet_when_the_audit_launch_fails(root):
    """A configured audit command that fails to START must NOT mark the packet seen — else the packet
    stays pending but is permanently suppressed from future wakeups and never gets audited."""
    inbox.publish(valid_packet())

    def failing_run(_command):
        return None  # Popen failure / command not found

    first = dispatch_once(audit_cmd="broken-cmd", notify_fn=lambda *_: True, run_fn=failing_run)
    assert "reviewer" in first.launch_failed and "reviewer" not in first.launched
    # The packet was NOT marked seen, so the very next pass sees it as new again and retries.
    second = dispatch_once(audit_cmd="broken-cmd", notify_fn=lambda *_: True, run_fn=failing_run)
    assert second.new_packets == first.new_packets, "a failed launch must be retried, not suppressed"


def test_dispatch_marks_seen_when_the_audit_launch_succeeds(root):
    inbox.publish(valid_packet())
    ok_run = lambda _command: 4321  # a pid
    first = dispatch_once(audit_cmd="good-cmd", notify_fn=lambda *_: True, run_fn=ok_run)
    assert "reviewer" in first.launched and not first.launch_failed
    second = dispatch_once(audit_cmd="good-cmd", notify_fn=lambda *_: True, run_fn=ok_run)
    assert not second.acted, "a successful launch marks the packet seen; no re-fire"


def _run_wrapper(tmp_path, *, env_file_text: str, extra_env: dict) -> str:
    """Run the packaged watch wrapper from an UNRELATED cwd with a launchd-like (near-empty) env.

    Returns what the stub interpreter observed. The wrapper redirects stdout to /dev/null, so the
    stub writes its observation to a file.
    """
    real = watchagent.watch_script_path()
    if not real.exists():  # pragma: no cover - the packaged script is expected to exist
        pytest.skip("wrapper script missing")
    project = tmp_path / "project"
    (project / ".twoperson").mkdir(parents=True)
    (project / ".twoperson" / "watch.env").write_text(env_file_text, encoding="utf-8")
    out = tmp_path / "seen.txt"
    stub = tmp_path / "stub.sh"
    stub.write_text(
        f'#!/bin/sh\nprintf "%s|%s|%s" "$TWOPERSON_INBOX" "$TWOPERSON_ON_PACKET" "$PWD" > "{out}"\n',
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "TWOPERSON_PYTHON": str(stub), **extra_env}
    subprocess.run(["/bin/sh", str(real)], env=env, cwd=elsewhere, timeout=20, check=False)
    return out.read_text() if out.exists() else ""


def test_wrapper_preserves_the_plist_pinned_inbox_over_the_env_file(tmp_path):
    """launchd pins TWOPERSON_INBOX in the plist, but the wrapper sources watch.env afterwards. A
    stray inbox in that file must NOT repoint the scan away from the watched lanes."""
    project = tmp_path / "project"
    pinned = str(tmp_path / "pinned-inbox")
    seen = _run_wrapper(
        tmp_path,
        env_file_text='export TWOPERSON_INBOX="/tmp/evil-inbox"\nexport TWOPERSON_ON_PACKET="true"\n',
        extra_env={"TWOPERSON_INBOX": pinned, "TWOPERSON_ROOT": str(project)},
    )
    inbox_seen, launch_seen, _ = seen.split("|")
    assert inbox_seen == pinned, "the env file must not override the plist-pinned inbox"
    assert launch_seen == "true", "the env file's legitimate job (launch commands) must still load"


def test_wrapper_loads_the_project_env_file_from_a_launchd_like_environment(tmp_path):
    """Reviewer P1: launchd gives the handler no cwd and no shell env. The plist pins TWOPERSON_ROOT,
    and that alone must be enough for `<root>/.twoperson/watch.env` to be found and sourced."""
    project = tmp_path / "project"
    seen = _run_wrapper(
        tmp_path,
        env_file_text='export TWOPERSON_ON_PACKET="run-the-reviewer"\n',
        extra_env={"TWOPERSON_INBOX": str(tmp_path / "inbox"), "TWOPERSON_ROOT": str(project)},
    )
    _, launch_seen, cwd_seen = seen.split("|")
    assert launch_seen == "run-the-reviewer"
    assert cwd_seen == str(project.resolve()), "the wrapper must run in the project, not launchd's cwd"


def test_render_plist_pins_the_project_root_and_working_directory(root, tmp_path):
    """The wrapper reads TWOPERSON_ROOT; a plist that only pins the inbox leaves it unset under launchd."""
    pl = watchagent.render_plist(repo_root=tmp_path)
    assert pl["EnvironmentVariables"]["TWOPERSON_ROOT"] == str(tmp_path.resolve())
    assert pl["WorkingDirectory"] == str(tmp_path.resolve())


# --------------------------------------------------------------------------------------------
# The master mute switch
# --------------------------------------------------------------------------------------------

def test_switch_defaults_to_on_and_toggles(root):
    assert is_muted() is False, "a fresh watcher is ON (not muted)"
    assert set_muted(True) is True and is_muted() is True
    assert set_muted(False) is False and is_muted() is False


def test_muted_dispatch_notifies_and_launches_nothing(root):
    inbox.publish(valid_packet())
    set_muted(True)
    rec = Recorder()
    report = dispatch_once(audit_cmd="x", notify_fn=rec.notify, run_fn=rec.run)
    assert report.muted is True
    assert rec.notes == [] and rec.commands == [], "a muted watcher fires nothing, either side"


def test_mute_is_a_pause_not_a_skip(root):
    """A packet that arrives while muted must be announced the moment the switch is turned back on —
    the cursor must not advance during mute, so nothing is silently missed."""
    inbox.publish(valid_packet())
    set_muted(True)
    dispatch_once(audit_cmd="x", notify_fn=lambda *_: True, run_fn=lambda *_a, **_k: 1)
    # Un-mute: the previously-published packet is still 'new' and now gets reacted to.
    set_muted(False)
    rec = Recorder()
    report = dispatch_once(notify_fn=rec.notify, run_fn=rec.run)
    assert report.acted and "reviewer" in report.notified, "muted arrivals resume on un-mute"


def test_switch_survives_a_missing_inbox(tmp_path, monkeypatch):
    # Pointed at an inbox that does not exist yet: is_muted must not raise, set_muted creates it.
    target = tmp_path / "nope"
    monkeypatch.setenv("TWOPERSON_INBOX", str(target))
    assert is_muted() is False
    assert set_muted(True) is True and (target / watch.SWITCH_NAME).exists()


def test_unmute_runs_a_catchup_pass_in_cli_mode(root):
    """Reviewer P1: un-mute must actually resume. `watch --on` runs a dispatch pass immediately, so a
    packet that arrived while muted is reacted to on un-mute — not left waiting for an unrelated later
    lane change (which is the only thing the launchd agent would otherwise wake on)."""
    from twoperson.__main__ import main

    set_muted(True)
    inbox.publish(valid_packet())               # arrives while muted
    assert load_cursor().packets == frozenset(), "muted: nothing reacted to yet"

    rc = main(["watch", "--on"])                # un-mute via the CLI
    assert rc == 0
    assert is_muted() is False
    # The catch-up dispatch advanced the cursor over the packet that arrived while muted.
    names = {p.name for p in inbox.pending()}
    assert load_cursor().packets == frozenset(names) and names, "un-mute must catch up on muted arrivals"


def test_plist_watches_the_switch_file_so_launchd_wakes_on_a_toggle(root):
    pl = watchagent.render_plist()
    assert str(root / watch.SWITCH_NAME) in pl["WatchPaths"], (
        "launchd must watch the mute file so an external un-mute wakes the agent"
    )


def test_concurrent_dispatches_do_not_double_fire(root):
    """Reviewer P1: the --on catch-up and the switch-file WatchPaths handler can dispatch concurrently.
    An inter-process lock must serialize them so a single queued packet launches the audit exactly
    ONCE (the second pass reads the cursor the first advanced and finds nothing new)."""
    import threading

    inbox.publish(valid_packet())
    launches: list[str] = []
    guard = threading.Lock()

    def run_cmd(cmd):
        with guard:
            launches.append(cmd)
        return 1  # a pid — launch "succeeded"

    threads = [
        threading.Thread(
            target=lambda: dispatch_once(audit_cmd="audit", notify_fn=lambda *_: True, run_fn=run_cmd)
        )
        for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert launches == ["audit"], f"exactly one launch across concurrent dispatches, got {launches!r}"


def test_dispatch_lock_degrades_to_a_no_op_when_flock_is_unsupported(root, monkeypatch):
    """Reviewer nit: on a filesystem where locking is unsupported, `flock` acquisition raises OSError.
    The dispatch lock must degrade to the un-serialized behaviour (a no-op yield) rather than crash the
    watcher — so a single pass still reacts to a waiting packet, never raising."""
    inbox.publish(valid_packet())

    def boom(_handle, _op):
        raise OSError("locking not supported on this filesystem")

    monkeypatch.setattr(watch.fcntl, "flock", boom)

    rec = Recorder()
    report = dispatch_once(audit_cmd="audit", notify_fn=rec.notify, run_fn=rec.run)
    assert "reviewer" in report.notified and rec.commands == ["audit"], (
        "an unsupported-lock filesystem must still dispatch, un-serialized, never raising"
    )


def test_dispatch_lock_degrades_to_a_no_op_when_the_lock_file_cannot_be_opened(root, monkeypatch):
    """The other lock failure surface: the lock file itself cannot be opened (unwritable root). Same
    contract — degrade to a no-op yield and still react, never raise."""
    inbox.publish(valid_packet())

    real_open = open

    def guarded_open(path, *a, **k):
        if str(path).endswith(watch.DISPATCH_LOCK_NAME):
            raise OSError("cannot create lock file")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", guarded_open)

    rec = Recorder()
    report = dispatch_once(audit_cmd="audit", notify_fn=rec.notify, run_fn=rec.run)
    assert "reviewer" in report.notified and rec.commands == ["audit"], (
        "an unopenable lock file must still dispatch, un-serialized, never raising"
    )


def test_a_mute_toggled_on_while_blocked_on_the_lock_still_wins(root, monkeypatch):
    """Reviewer nit: mute is re-checked INSIDE the dispatch lock. Simulate a mute that lands after the
    pre-lock fast-path but before the body runs (as if the switch flipped while we were blocked
    acquiring the lock): the pass must bail as muted, firing nothing and leaving the cursor untouched."""
    inbox.publish(valid_packet())

    real_is_muted = watch.is_muted
    calls = {"n": 0}

    def is_muted_flips_on_second_call(*a, **k):
        # First call is the pre-lock fast-path (still ON); the second is the in-lock re-check (now muted).
        calls["n"] += 1
        if calls["n"] >= 2:
            return True
        return real_is_muted(*a, **k)

    monkeypatch.setattr(watch, "is_muted", is_muted_flips_on_second_call)

    rec = Recorder()
    report = dispatch_once(audit_cmd="audit", notify_fn=rec.notify, run_fn=rec.run)
    assert report.muted is True
    assert rec.notes == [] and rec.commands == [], "in-lock mute re-check must fire nothing"
    assert load_cursor().packets == frozenset(), "a bail-as-muted pass must not advance the cursor"


# --------------------------------------------------------------------------------------------
# The advisory lanes: consult (wake Reviewer) and advice (wake Builder), symmetric with the audit pair.
# A consult LANDS -> Reviewer WAKES -> REPLIES, driven by its own launch command (TWOPERSON_ON_CONSULT).
# --------------------------------------------------------------------------------------------

def _publish_a_consult():
    from twoperson.consult import build_consult
    return inbox.publish_consult(build_consult(question="claim or peek?", area="architecture"))


def _publish_an_advice():
    from twoperson.advice import build_advice
    return inbox.publish_advice(build_advice(consult_id="cns-x", recommendation="claim it"))


def test_scan_new_sees_a_fresh_consult_and_advice(root):
    _publish_a_consult()
    _publish_an_advice()
    delta = scan_new(None, Cursor())
    assert len(delta.new_consults) == 1
    assert len(delta.new_advice) == 1
    assert not delta.is_empty


def test_dispatch_launches_the_consult_command_so_codex_replies_asap(root):
    """The load-bearing change: a consult LANDS and immediately WAKES Reviewer via its own command."""
    _publish_a_consult()
    rec = Recorder()
    report = dispatch_once(consult_cmd="run-reviewer-consult", notify_fn=rec.notify, run_fn=rec.run)
    assert "reviewer" in report.notified
    assert rec.commands == ["run-reviewer-consult"]
    assert "reviewer" in report.launched


def test_dispatch_launches_the_advice_command_to_wake_the_manager(root):
    _publish_an_advice()
    rec = Recorder()
    report = dispatch_once(advice_cmd="wake-builder-advice", notify_fn=rec.notify, run_fn=rec.run)
    assert "builder" in report.notified
    assert rec.commands == ["wake-builder-advice"]
    assert "builder" in report.launched


def test_a_consult_never_fires_the_audit_command(root):
    """A consult is not a packet: the AUDIT runner must never be launched on it — only the consult
    runner is. This is why the consult lane has its own command rather than reusing audit_cmd."""
    _publish_a_consult()
    rec = Recorder()
    report = dispatch_once(audit_cmd="run-reviewer-audit", notify_fn=rec.notify, run_fn=rec.run)
    assert "reviewer" in report.notified
    assert rec.commands == [], "the audit runner claims a PACKET; it must never be fired on a consult"
    assert not report.launched  # no consult_cmd configured ⇒ notify only for the consult


def test_a_failed_consult_launch_is_retried_not_suppressed(root):
    """Symmetry with the audit lane: if the consult wake fails to start, the consult stays 'new' so
    the next inbox change retries it — a failed wake must never silently swallow the consult."""
    _publish_a_consult()
    rec = Recorder()
    report = dispatch_once(consult_cmd="boom", notify_fn=rec.notify,
                           run_fn=lambda *_a, **_k: None)  # launch fails to start
    assert "reviewer" in report.launch_failed
    # cursor did NOT advance for the consult ⇒ a second pass sees it as new again and retries
    second = dispatch_once(consult_cmd="ok", notify_fn=rec.notify, run_fn=rec.run)
    assert second.new_consults and rec.commands == ["ok"]


def test_advisory_lanes_are_idempotent_across_two_passes(root):
    _publish_a_consult()
    _publish_an_advice()
    rec = Recorder()
    first = dispatch_once(notify_fn=rec.notify, run_fn=rec.run)
    assert first.acted and len(rec.notes) == 2
    second = dispatch_once(notify_fn=rec.notify, run_fn=rec.run)
    assert not second.acted, "a second pass over the same advisory items does nothing"
    assert len(rec.notes) == 2, "no double notification"


def test_cursor_round_trips_the_advisory_lanes(root):
    _publish_a_consult()
    _publish_an_advice()
    delta = scan_new(None, Cursor())
    save_cursor(delta.cursor)
    loaded = load_cursor()
    assert loaded.consults == delta.cursor.consults
    assert loaded.advice == delta.cursor.advice


def test_an_old_cursor_without_advisory_lanes_loads_as_empty_lanes():
    """A cursor written before the advisory lanes existed must load, not crash (re-notify once)."""
    old = Cursor.from_json({"packets": ["p.json"], "verdicts": ["v.json"]})
    assert old.packets == frozenset({"p.json"})
    assert old.consults == frozenset() and old.advice == frozenset()
