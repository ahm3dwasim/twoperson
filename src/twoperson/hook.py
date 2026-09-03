"""The tracked Claude Code completion hook: its canonical config, and an idempotent installer.

The bridge needed one thing it did not have — a mechanism that fires **without a human remembering
to fire it**. This module is that mechanism, kept as small as it can be:

* `src/twoperson/scripts/twoperson_stop_hook.sh` — a packaged POSIX script Claude Code runs on `Stop`. It emits a
  completion **signal** (`src/twoperson/signal.py`) and nothing else. It never fabricates a review
  packet, because a hook knows nothing a packet must assert.
* `hook_settings()` — the canonical settings block, defined once here in code so the installer, the
  tests, and the docs cannot drift apart.
* `install_hook()` — merges that block into a Claude Code `settings.json`, preserving everything
  already there.

**Why the settings file is not itself tracked.** `.claude/settings.json` is per-checkout and already
exists on the owner's machine with unrelated `permissions` in it. Tracking it would fight that file
on every clone and checkout, and the repo's worktree law means several checkouts exist at once.
Tracking the *script + the block + the installer + these tests* gets the reproducibility (a fresh
clone runs one documented command and is identical to any other) without the collision.

**A Stop hook must never fail a session.** Claude Code treats hook exit code 2 as "block", feeding
stderr back to the model — a bridge that did that could trap a session in a loop it cannot exit. So
the script always exits 0, the signal path degrades to ``"unknown"`` instead of raising, and the
`signal` subcommand never returns the rejection code.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The shell scripts ship *inside* the package, so their path is correct whether twoperson was
#: cloned or pip-installed. Resolving them against a repo root only works for a checkout.
SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"

#: Filename of the tracked hook script inside `SCRIPTS_DIR`.
HOOK_SCRIPT_NAME = "twoperson_stop_hook.sh"

#: The Claude Code event we hook. `Stop` fires when a session finishes responding — the one moment
#: that maps to "a task is complete", which is exactly what the signal reports.
HOOK_EVENT = "Stop"

#: The command Claude Code runs. `$CLAUDE_PROJECT_DIR` is set by Claude Code for hooks; the script
#: falls back to its own location if it is not, so the command works when run by hand too.
#: Invoked through `sh` rather than executed directly: a wheel does not reliably carry the
#: executable bit, and site-packages may be read-only, so relying on +x breaks the hook silently.
HOOK_COMMAND = f'sh "{SCRIPTS_DIR / HOOK_SCRIPT_NAME}"'

#: Seconds. Emitting a signal is a small file write; anything slower is a broken environment, and
#: waiting on it would stall the end of every session.
HOOK_TIMEOUT_SECONDS = 15

#: Any Stop command containing this marker is considered ours and is replaced on install, so an
#: older revision of the command upgrades in place instead of firing twice.
HOOK_MARKER = HOOK_SCRIPT_NAME

#: Settings files we will write. A guard against `--settings /etc/passwd`, not a security boundary:
#: the installer runs as the owner and can only be pointed at a plausible settings file.
SETTINGS_FILENAMES = frozenset({"settings.json", "settings.local.json"})

DEFAULT_SETTINGS_REL = ".claude/settings.json"

__all__ = [
    "DEFAULT_SETTINGS_REL",
    "HOOK_COMMAND",
    "HOOK_EVENT",
    "HOOK_MARKER",
    "HOOK_SCRIPT_NAME",
    "SCRIPTS_DIR",
    "HOOK_TIMEOUT_SECONDS",
    "HookInstallError",
    "InstallResult",
    "default_settings_path",
    "hook_script_path",
    "hook_settings",
    "install_hook",
]


class HookInstallError(RuntimeError):
    """The settings file cannot be read, parsed, or safely written."""


@dataclass(frozen=True)
class InstallResult:
    """``status`` is one of ``installed`` / ``updated`` / ``current`` / ``missing``."""

    status: str
    path: Path
    changed: bool

    @property
    def ok(self) -> bool:
        """True when the hook is present and current — the `--check` contract."""
        return self.status in ("installed", "updated", "current")


def hook_script_path(root: Path | str | None = None) -> Path:
    """Absolute path of the hook script. ``root`` overrides the packaged copy (tests, vendoring)."""
    return (Path(root) / "src" / "twoperson" / "scripts" / HOOK_SCRIPT_NAME) if root else \
        SCRIPTS_DIR / HOOK_SCRIPT_NAME


def default_settings_path(root: Path | str | None = None) -> Path:
    """`<repo>/.claude/settings.json` — project scope, so every session in the checkout gets it.

    Defaults to the *current working directory*: `install-hook` configures the repo you run it in.
    """
    return Path(root or Path.cwd()) / DEFAULT_SETTINGS_REL


def hook_settings() -> dict[str, Any]:
    """The canonical settings fragment. One definition, used by the installer, tests, and docs."""
    return {
        "hooks": {
            HOOK_EVENT: [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": HOOK_COMMAND,
                            "timeout": HOOK_TIMEOUT_SECONDS,
                        }
                    ]
                }
            ]
        }
    }


def _load_settings(path: Path) -> dict[str, Any]:
    """Existing settings, or an empty object. Refuses anything that is not a JSON object."""
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HookInstallError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HookInstallError(
            f"{path} is not valid JSON ({exc}) — fix it by hand; refusing to overwrite it"
        ) from exc
    if not isinstance(parsed, dict):
        raise HookInstallError(f"{path}: expected a JSON object, got {type(parsed).__name__}")
    return parsed


def _check_target(path: Path) -> Path:
    """Refuse an implausible or symlinked settings target before anything is written."""
    if path.name not in SETTINGS_FILENAMES:
        raise HookInstallError(
            f"{path}: settings file must be named one of {sorted(SETTINGS_FILENAMES)}"
        )
    if path.is_symlink():
        raise HookInstallError(f"{path}: refusing to write through a symlink")
    return path


def _is_ours(entry: Any) -> bool:
    """True for a Stop group this installer owns (any revision of our command)."""
    if not isinstance(entry, dict):
        return False
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return False
    return any(
        isinstance(h, dict) and isinstance(h.get("command"), str) and HOOK_MARKER in h["command"]
        for h in hooks
    )


def _write_atomically(path: Path, settings: dict[str, Any]) -> None:
    """Replace the settings file in one step, preserving its mode if it already exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(settings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def install_hook(settings_path: Path | str | None = None, *, check: bool = False) -> InstallResult:
    """Merge the completion hook into a Claude Code settings file, idempotently.

    Everything already in the file survives: unrelated top-level keys, unrelated hook events, and
    unrelated `Stop` hooks are all preserved, and a previous revision of *our* command is replaced
    rather than duplicated. ``check=True`` reports without writing.
    """
    path = _check_target(Path(settings_path) if settings_path else default_settings_path())
    settings = _load_settings(path)

    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        raise HookInstallError(f"{path}: 'hooks' must be an object, got {type(hooks).__name__}")
    stop = hooks.get(HOOK_EVENT, [])
    if not isinstance(stop, list):
        raise HookInstallError(
            f"{path}: 'hooks.{HOOK_EVENT}' must be a list, got {type(stop).__name__}"
        )

    desired = hook_settings()["hooks"][HOOK_EVENT][0]
    ours = [i for i, entry in enumerate(stop) if _is_ours(entry)]

    if ours and len(ours) == 1 and stop[ours[0]] == desired:
        return InstallResult(status="current", path=path, changed=False)
    if check:
        return InstallResult(status="missing", path=path, changed=False)

    merged = [entry for i, entry in enumerate(stop) if i not in set(ours)]
    merged.append(desired)
    settings["hooks"] = {**hooks, HOOK_EVENT: merged}

    try:
        _write_atomically(path, settings)
    except OSError as exc:
        raise HookInstallError(f"cannot write {path}: {exc.strerror or exc}") from exc
    return InstallResult(status="updated" if ours else "installed", path=path, changed=True)
