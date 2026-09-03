"""The tracked completion mechanism: the hook script, its canonical config, and the installer.

The point of tracking the mechanism is that a fresh clone can reproduce it exactly — so these are
deterministic checks on the *repo artifacts*, not on a machine's live `.builder/` directory. The
installer is exercised against temp settings files only; no test ever writes to the real one.

Two failure modes are worth more than the rest and are pinned hardest:

* **Clobbering the owner's settings.** The installer merges; it must preserve unrelated top-level
  keys, unrelated hook events, and unrelated `Stop` hooks, and must refuse a file it cannot parse
  rather than overwrite it.
* **A hook that can wedge a session.** Claude Code reads exit code 2 from a `Stop` hook as "block
  stopping". The script must always exit 0, and `signal` must never return the rejection code.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from twoperson.hook import (
    HOOK_COMMAND,
    HOOK_EVENT,
    HOOK_MARKER,
    HOOK_SCRIPT_NAME,
    SCRIPTS_DIR,
    HookInstallError,
    default_settings_path,
    hook_script_path,
    hook_settings,
    install_hook,
)

SCRIPT = hook_script_path()


@pytest.fixture
def settings(tmp_path) -> Path:
    target = tmp_path / ".claude" / "settings.json"
    target.parent.mkdir(parents=True)
    return target


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _stop_hooks(path: Path) -> list:
    return _read(path)["hooks"][HOOK_EVENT]


# --------------------------------------------------------------------------------------------
# The tracked artifacts
# --------------------------------------------------------------------------------------------

def test_the_hook_script_exists_and_is_executable():
    assert SCRIPT.exists(), f"{HOOK_SCRIPT_NAME} must ship inside the package, not just on one machine"
    assert SCRIPT.stat().st_mode & stat.S_IXUSR, "the hook script must be executable"


def test_the_hook_script_is_tracked_by_git():
    """Tracked is the whole point: a fresh clone must get the mechanism, not re-derive it.

    Skipped where there is no git checkout: a source tarball or an installed wheel has no `.git`,
    and must not fail a test about repository hygiene.
    """
    inside = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                            cwd=SCRIPTS_DIR, capture_output=True, text=True, check=False)
    if inside.returncode != 0:
        pytest.skip("not a git checkout (sandbox); tracking is asserted where git is available")
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", HOOK_SCRIPT_NAME],
        cwd=SCRIPTS_DIR, capture_output=True, text=True, check=False,
    )
    assert tracked.returncode == 0, f"{HOOK_SCRIPT_NAME} is not tracked by git"


def test_the_hook_script_is_valid_posix_shell():
    assert subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True).returncode == 0


def test_the_hook_script_always_exits_zero_by_construction():
    """A Stop hook that exits 2 blocks the session. The script must not be able to."""
    body = SCRIPT.read_text(encoding="utf-8")
    assert body.rstrip().endswith("exit 0")
    assert "exit 0" in body and "exit 1" not in body and "exit 2" not in body


def test_the_hook_command_points_at_the_tracked_script():
    assert HOOK_MARKER in HOOK_COMMAND
    assert HOOK_SCRIPT_NAME in HOOK_COMMAND
    assert "CLAUDE_PROJECT_DIR" in SCRIPT.read_text(), "the hook must run in the session's checkout"


def test_the_canonical_settings_block_is_a_single_stop_command_hook():
    block = hook_settings()
    assert set(block) == {"hooks"} and set(block["hooks"]) == {HOOK_EVENT}
    groups = block["hooks"][HOOK_EVENT]
    assert len(groups) == 1 and len(groups[0]["hooks"]) == 1
    entry = groups[0]["hooks"][0]
    assert entry["type"] == "command" and entry["command"] == HOOK_COMMAND
    assert isinstance(entry["timeout"], int) and 0 < entry["timeout"] <= 60


def test_the_default_settings_target_is_project_scoped(tmp_path):
    assert default_settings_path(tmp_path) == tmp_path / ".claude" / "settings.json"


# --------------------------------------------------------------------------------------------
# Installing
# --------------------------------------------------------------------------------------------

def test_installing_into_a_missing_file_creates_it(settings):
    result = install_hook(settings)
    assert result.status == "installed" and result.changed and result.ok
    assert _stop_hooks(settings) == hook_settings()["hooks"][HOOK_EVENT]


def test_installing_creates_the_settings_directory_if_needed(tmp_path):
    target = tmp_path / "fresh-clone" / ".claude" / "settings.json"
    assert install_hook(target).ok
    assert target.exists()


def test_installing_twice_changes_nothing(settings):
    install_hook(settings)
    before = settings.read_text(encoding="utf-8")
    result = install_hook(settings)
    assert result.status == "current" and not result.changed
    assert settings.read_text(encoding="utf-8") == before


def test_installing_preserves_unrelated_settings(settings):
    settings.write_text(json.dumps({
        "permissions": {"allow": ["Bash(git fetch *)"]},
        "model": "opus",
    }), encoding="utf-8")
    install_hook(settings)
    after = _read(settings)
    assert after["permissions"] == {"allow": ["Bash(git fetch *)"]}
    assert after["model"] == "opus"


def test_installing_preserves_unrelated_hook_events_and_stop_hooks(settings):
    other_stop = {"hooks": [{"type": "command", "command": "echo unrelated"}]}
    settings.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "lint"}]}],
            HOOK_EVENT: [other_stop],
        }
    }), encoding="utf-8")
    install_hook(settings)
    after = _read(settings)
    assert after["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "lint"
    assert other_stop in after["hooks"][HOOK_EVENT]
    assert len(after["hooks"][HOOK_EVENT]) == 2


def test_an_older_revision_of_our_command_is_replaced_not_duplicated(settings):
    """Otherwise an upgrade leaves two hooks and every session emits two signals."""
    settings.write_text(json.dumps({
        "hooks": {HOOK_EVENT: [
            {"hooks": [{"type": "command", "command": f"sh ./legacy/{HOOK_SCRIPT_NAME} --old-flag"}]}
        ]}
    }), encoding="utf-8")
    result = install_hook(settings)
    assert result.status == "updated"
    stop = _stop_hooks(settings)
    assert len(stop) == 1
    assert stop[0]["hooks"][0]["command"] == HOOK_COMMAND


def test_duplicate_copies_of_our_hook_collapse_to_one(settings):
    ours = {"hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": 15}]}
    settings.write_text(json.dumps({"hooks": {HOOK_EVENT: [ours, ours]}}), encoding="utf-8")
    assert install_hook(settings).status == "updated"
    assert len(_stop_hooks(settings)) == 1


def test_an_empty_settings_file_is_treated_as_empty_settings(settings):
    settings.write_text("   \n", encoding="utf-8")
    assert install_hook(settings).ok


def test_the_settings_file_keeps_its_permissions(settings):
    settings.write_text("{}", encoding="utf-8")
    os.chmod(settings, 0o600)
    install_hook(settings)
    assert stat.S_IMODE(settings.stat().st_mode) == 0o600


# --------------------------------------------------------------------------------------------
# Refusing rather than damaging
# --------------------------------------------------------------------------------------------

def test_unparseable_settings_are_refused_not_overwritten(settings):
    settings.write_text('{"permissions": broken', encoding="utf-8")
    with pytest.raises(HookInstallError, match="not valid JSON"):
        install_hook(settings)
    assert settings.read_text(encoding="utf-8") == '{"permissions": broken'


@pytest.mark.parametrize("body,match", [
    ('["not", "an", "object"]', "expected a JSON object"),
    ('{"hooks": []}', "must be an object"),
    ('{"hooks": {"Stop": "nope"}}', "must be a list"),
])
def test_structurally_wrong_settings_are_refused(settings, body, match):
    settings.write_text(body, encoding="utf-8")
    with pytest.raises(HookInstallError, match=match):
        install_hook(settings)
    assert settings.read_text(encoding="utf-8") == body


def test_a_target_that_is_not_a_settings_file_is_refused(tmp_path):
    target = tmp_path / "authorized_keys"
    with pytest.raises(HookInstallError, match="must be named"):
        install_hook(target)
    assert not target.exists()


def test_a_symlinked_target_is_refused(tmp_path, settings):
    real = tmp_path / "real.json"
    real.write_text("{}", encoding="utf-8")
    link = tmp_path / ".claude" / "settings.local.json"
    link.symlink_to(real)
    with pytest.raises(HookInstallError, match="symlink"):
        install_hook(link)
    assert real.read_text(encoding="utf-8") == "{}"


def test_check_mode_never_writes(settings):
    result = install_hook(settings, check=True)
    assert result.status == "missing" and not result.changed and not result.ok
    assert not settings.exists()


def test_check_mode_reports_an_installed_hook(settings):
    install_hook(settings)
    result = install_hook(settings, check=True)
    assert result.status == "current" and result.ok and not result.changed


def test_check_mode_reports_a_stale_hook_as_missing(settings):
    settings.write_text(json.dumps({
        "hooks": {HOOK_EVENT: [{"hooks": [{"type": "command", "command": f"./legacy/{HOOK_SCRIPT_NAME}"}]}]}
    }), encoding="utf-8")
    assert install_hook(settings, check=True).status == "missing"


# --------------------------------------------------------------------------------------------
# The script actually emits a signal
# --------------------------------------------------------------------------------------------

def test_the_hook_script_emits_exactly_one_signal_end_to_end(tmp_path):
    """The whole tracked path: Claude Code payload on stdin -> a signal file in the inbox."""
    inbox_root = tmp_path / "twoperson"
    env = {
        **os.environ,
        "TWOPERSON_INBOX": str(inbox_root),
        "TWOPERSON_PYTHON": sys.executable,
        "TWOPERSON_BRANCH": "session/hook-test",
        "CLAUDE_PROJECT_DIR": str(SCRIPTS_DIR.parents[2]),
    }
    payload = json.dumps({"session_id": "sess-hook-1", "hook_event_name": "Stop"})
    completed = subprocess.run([str(SCRIPT)], input=payload, env=env, text=True,
                               capture_output=True, timeout=60)

    assert completed.returncode == 0, completed.stderr
    signals = sorted((inbox_root / "signals").glob("*.json"))
    assert len(signals) == 1
    emitted = json.loads(signals[0].read_text(encoding="utf-8"))
    assert emitted["source"] == "claude-code-stop-hook"
    assert emitted["session_id"] == "sess-hook-1"
    assert emitted["branch"] == "session/hook-test"
    assert emitted["packet_pending"] is False
    assert not list((inbox_root / "pending").glob("*.json")), "a hook must not create a packet"


def test_the_hook_script_exits_zero_even_when_the_bridge_cannot_run(tmp_path):
    """A broken interpreter must not block a session from stopping."""
    env = {
        **os.environ,
        "TWOPERSON_INBOX": str(tmp_path / "twoperson"),
        "TWOPERSON_PYTHON": str(tmp_path / "no-such-python"),
        "CLAUDE_PROJECT_DIR": str(SCRIPTS_DIR.parents[2]),
    }
    completed = subprocess.run([str(SCRIPT)], input="{}", env=env, text=True,
                               capture_output=True, timeout=60)
    assert completed.returncode == 0
    assert not (tmp_path / "twoperson" / "signals").exists()
