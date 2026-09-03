"""The launchd agent that makes the inbox watcher fire *without a human running a loop*.

`watch.py` reacts to one change; this module is how that reaction gets triggered automatically on
macOS. It renders a launchd ``WatchPaths`` agent — launchd runs our tracked handler
(`src/twoperson/scripts/twoperson_watch.sh`) every time an actionable inbox lane changes (``pending/``, ``verdicts/``,
``consult/``, or ``advice/``), and once at load to catch anything already waiting. No daemon to
babysit, survives logout/reboot.

The split mirrors `hook.py`: a **pure renderer** (`render_plist`) the tests and docs share, and an
**idempotent installer** (`install_watch_agent`) that writes the plist and (best-effort) reloads it.
Only the plist path under the user's ``LaunchAgents`` is writable by this installer — a guard, not a
security boundary.

Why a tracked *script* + a generated *plist* (not a tracked plist): the plist embeds absolute,
per-machine paths (this checkout, this inbox, the user's home) — tracking it would fight every clone.
Tracking the handler + this renderer + its tests gives reproducibility without the collision, exactly
as the Stop hook does.
"""
from __future__ import annotations

import os
import plistlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .inbox import _ensure_tree, inbox_root
from .watch import SWITCH_NAME

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"

#: Repo-relative handler launchd runs on each inbox change.
WATCH_SCRIPT_NAME = "twoperson_watch.sh"

#: The launchd label. Stable, reverse-DNS, one agent per user.
AGENT_LABEL = "dev.twoperson.inbox-watch"

#: Lanes we watch — the ones that carry *actionable* arrivals: the audit pair (packets/verdicts) and
#: the advisory pair (consults/advice). We deliberately do NOT watch claimed/, consult_claimed/,
#: signals/, or the _seen lanes: a claim or an ack is not a new item to react to, and watching them
#: would just wake the agent to compute an empty delta.
WATCHED_LANES = ("pending", "verdicts", "consult", "advice")

__all__ = [
    "AGENT_LABEL",
    "WATCH_SCRIPT_NAME",
    "WATCHED_LANES",
    "WatchInstallError",
    "WatchInstallResult",
    "agent_plist_path",
    "watch_script_path",
    "render_plist",
    "install_watch_agent",
]


class WatchInstallError(RuntimeError):
    """The launch agent cannot be rendered or written."""


@dataclass(frozen=True)
class WatchInstallResult:
    """``status`` is ``installed`` / ``updated`` / ``current`` / ``missing`` (mirrors the hook)."""

    status: str
    path: Path
    changed: bool
    loaded: bool = False

    @property
    def ok(self) -> bool:
        return self.status in ("installed", "updated", "current")


def watch_script_path(root: Path | str | None = None) -> Path:
    return SCRIPTS_DIR / WATCH_SCRIPT_NAME


def agent_plist_path(home: Path | str | None = None) -> Path:
    base = Path(home) if home else Path.home()
    return base / "Library" / "LaunchAgents" / f"{AGENT_LABEL}.plist"


def render_plist(
    *,
    repo_root: Path | str | None = None,
    inbox: Path | str | None = None,
    log_dir: Path | str | None = None,
) -> dict:
    """The launchd agent definition as a plist dict. Pure — no filesystem writes.

    ``WatchPaths`` points at the actual resolved inbox lanes, so the agent watches the *shared* inbox
    the bridge uses (honouring ``TWOPERSON_INBOX``), not a guess. ``RunAtLoad`` does one pass at
    login so a packet that arrived while logged out is not missed.
    """
    script = watch_script_path(repo_root)
    root = inbox_root(inbox)
    lanes = [str((root / lane)) for lane in WATCHED_LANES]
    # Also watch the mute switch file itself, so flipping it (create=off, remove=on) wakes the agent.
    # Without this, un-muting in launchd mode would only delete the file and nothing would run until an
    # unrelated lane change — leaving work that arrived while muted silently unannounced. (The CLI
    # `watch --on` also runs an immediate catch-up pass; this covers an external/manual toggle.)
    watch_paths = lanes + [str(root / SWITCH_NAME)]
    project = Path(repo_root or Path.cwd()).resolve()
    logs = Path(log_dir) if log_dir else (project / ".twoperson" / "logs")
    return {
        "Label": AGENT_LABEL,
        # launchd starts the handler with no useful cwd and none of the installer's environment. The
        # wrapper finds `<root>/.twoperson/watch.env` (where the launch commands live) via
        # TWOPERSON_ROOT, so without this pin the documented reviewer command is silently never run.
        "WorkingDirectory": str(project),
        "ProgramArguments": ["/bin/sh", str(script)],
        "WatchPaths": watch_paths,
        "RunAtLoad": True,
        # launchd does NOT inherit the installing shell's environment, so pin the resolved inbox into
        # the agent's own environment. Otherwise WatchPaths (rendered here from `root`) and the
        # handler's runtime scan could target DIFFERENT inboxes — the handler would watch one and read
        # another. Embedding it makes the watched lanes and the scanned inbox provably the same root.
        "EnvironmentVariables": {"TWOPERSON_INBOX": str(root), "TWOPERSON_ROOT": str(project)},
        # Keep the agent event-driven: launchd starts it on a WatchPaths change, it runs one pass and
        # exits. KeepAlive would turn it into a spinning daemon, the opposite of the design.
        "StandardOutPath": str(logs / "inbox-watch.out.log"),
        "StandardErrorPath": str(logs / "inbox-watch.err.log"),
        "ProcessType": "Background",
    }


def _load_existing(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise WatchInstallError(f"cannot read {path}: {exc.strerror or exc}") from exc


def install_watch_agent(
    *,
    repo_root: Path | str | None = None,
    inbox: Path | str | None = None,
    home: Path | str | None = None,
    log_dir: Path | str | None = None,
    check: bool = False,
    reload: bool = True,
) -> WatchInstallResult:
    """Write (and best-effort reload) the launchd agent, idempotently.

    ``check=True`` reports whether the on-disk plist already matches without writing. Reloading uses
    ``launchctl`` and is best-effort: a failure to reload is logged into the result (``loaded=False``)
    but never raises — the plist is on disk and will load at next login regardless.
    """
    path = agent_plist_path(home)
    desired = plistlib.dumps(render_plist(repo_root=repo_root, inbox=inbox, log_dir=log_dir))
    existing = _load_existing(path)

    if existing == desired:
        return WatchInstallResult(status="current", path=path, changed=False, loaded=True)
    if check:
        # `--check` is read-only: report status, create NOTHING (no inbox tree, no log dir, no plist).
        return WatchInstallResult(status="missing", path=path, changed=False)

    # From here we are writing. Only now do we create the directories the running agent needs:
    # WatchPaths must point at existing dirs (else launchd may not arm the watch until they appear),
    # and launchd writes the Standard{Out,Error} logs but does not create their parent.
    _ensure_tree(inbox_root(inbox))
    logs = Path(log_dir) if log_dir else (Path(repo_root or Path.cwd()) / ".twoperson" / "logs")
    try:
        logs.mkdir(parents=True, exist_ok=True)
    except OSError:  # non-fatal: launchd will just drop the log if the dir cannot be made
        pass

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_bytes(desired)
        os.replace(tmp, path)
    except OSError as exc:
        raise WatchInstallError(f"cannot write {path}: {exc.strerror or exc}") from exc

    loaded = _reload_agent(path) if reload else False
    return WatchInstallResult(
        status="updated" if existing is not None else "installed",
        path=path,
        changed=True,
        loaded=loaded,
    )


def _reload_agent(path: Path) -> bool:
    """`launchctl unload` then `load`. Best-effort; returns True only if load succeeded."""
    try:
        subprocess.run(["launchctl", "unload", str(path)], capture_output=True, timeout=15)
        done = subprocess.run(["launchctl", "load", str(path)], capture_output=True, timeout=15)
        return done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
