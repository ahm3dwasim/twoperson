"""Close the handoff loop: react the instant the inbox changes, in BOTH directions.

The bridge was event-driven only in the cheap-poll sense — `check` costs nothing, but *something*
still had to run it. This module is that something: a small, side-effect-isolated watcher that turns
a filesystem change on the shared inbox into two reactions:

* a new **packet** in ``pending/``  → notify the *Reviewer* side, and (if configured) launch the audit;
* a new **verdict** in ``verdicts/`` → notify the *Builder* side, and (if configured) wake the manager;
* a new **consult** in ``consult/``  → notify the *Reviewer* side, and (if configured) launch the consult;
* a new **advice** in ``advice/``    → notify the *Builder* side, and (if configured) wake the manager.

The advisory pair is symmetric with the audit pair: a consult lands → Reviewer wakes → replies with
advice, the same land→wake→reply loop the audit runs. Its launch command is a *separate* owner-set
command (``TWOPERSON_ON_CONSULT``) pointing at Reviewer's consult runner, never the audit runner — a
consult is not a packet, so the two tools differ even though the mechanism is identical.

It is deliberately split into a **pure core** (`scan_new`) and **isolated effects** (`notify`,
`run_command`, `dispatch_once`) so the interesting logic — "what is new, and what do we do about it" —
is unit-testable without timers, subprocesses, or a real desktop.

Design rules, all load-bearing:

* **The launch command is owner configuration, never packet-derived.** The command comes only from an
  environment variable the owner sets (`TWOPERSON_ON_PACKET` / `TWOPERSON_ON_VERDICT`); packet
  and verdict *contents* are never interpolated into it. Untrusted bytes stay untrusted — this module
  reads only filenames from the lanes, never the file bodies.
* **Idempotent under a coalescing watcher.** launchd ``WatchPaths`` fires once for a burst of changes
  and says nothing about *what* changed, so every pass recomputes "new since last seen" from a small
  cursor and acts only on the delta. Re-firing on an unrelated change (a claim, a verdict write) does
  nothing twice.
* **Never raises into the watcher.** A notification backend that is missing, a launch command that
  exits non-zero, an unreadable cursor — all degrade to a logged warning. A watcher that crashed on
  the first odd input would defeat its own purpose.
* **Detection only; it grants nothing.** Firing the audit command still runs the *real* audit through
  the same packet/verdict gates. This module never claims a packet, writes a verdict, or ships — it
  only wakes the side that does.
"""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
from typing import Mapping, Sequence
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import structlog

from .inbox import inbox_root, pending, pending_advice, pending_consults, pending_verdicts

log = structlog.get_logger(__name__)

#: Owner-set command launched when a new packet arrives (the Reviewer/audit side). Unset ⇒ notify only.
AUDIT_CMD_ENV = "TWOPERSON_ON_PACKET"

#: Owner-set command launched when a new verdict arrives (the Builder/manager side). Unset ⇒ notify only.
WAKE_CMD_ENV = "TWOPERSON_ON_VERDICT"

#: Owner-set command launched when a new CONSULT arrives — wakes Reviewer to advise ASAP, the advisory
#: twin of AUDIT_CMD_ENV. It points at Reviewer's *consult* runner (which runs `consult-check &&
#: consult-next`, advises, and returns `consult-advise`), NOT the audit runner: a consult is not a
#: packet, so firing the audit command on it would be wrong. Unset ⇒ notify only.
CONSULT_CMD_ENV = "TWOPERSON_ON_CONSULT"

#: Owner-set command launched when a new ADVICE arrives — wakes the Builder/manager side, the advisory
#: twin of WAKE_CMD_ENV. Unset ⇒ notify only.
ADVICE_CMD_ENV = "TWOPERSON_ON_ADVICE"

#: Cursor file inside the inbox root. Ephemeral bookkeeping, not tracked — it only records which
#: filenames we have already reacted to, so a re-fire is a no-op.
CURSOR_NAME = ".watch_seen.json"

#: The master mute switch. Its *presence* in the inbox root means the watcher is OFF: it notifies no
#: one and launches nothing, for BOTH sides. Absence means ON. A file (not an env var) so the owner
#: can flip it from anywhere that sees the inbox, and so launchd/loop both observe the same state.
SWITCH_NAME = ".watch_muted"

#: Inter-process lock so at most one dispatch pass runs at a time. Several triggers can fire at once —
#: a launchd WatchPaths change, the switch-file handler, an `--on` catch-up, a `--loop` tick — and
#: without serialization two passes could read the same cursor before either saves it and double-fire
#: notifications/launches. Held only for the brief read→react→save-cursor window (the audit launch is
#: detached), so a blocking wait is cheap.
DISPATCH_LOCK_NAME = ".watch.lock"

#: Default poll cadence for the portable ``--loop`` mode. launchd ``WatchPaths`` mode ignores this —
#: it calls ``--once`` on each change and does no polling at all.
DEFAULT_INTERVAL_SECONDS = 5.0

__all__ = [
    "AUDIT_CMD_ENV",
    "WAKE_CMD_ENV",
    "CONSULT_CMD_ENV",
    "ADVICE_CMD_ENV",
    "CURSOR_NAME",
    "SWITCH_NAME",
    "Cursor",
    "WatchDelta",
    "DispatchReport",
    "scan_new",
    "notify",
    "run_command",
    "dispatch_once",
    "watch_loop",
    "load_cursor",
    "save_cursor",
    "is_muted",
    "set_muted",
]


# --------------------------------------------------------------------------------------------
# The master mute switch — presence of a file means OFF.
# --------------------------------------------------------------------------------------------

def _switch_path(root: Path | str | None) -> Path:
    return inbox_root(root) / SWITCH_NAME


def is_muted(root: Path | str | None = None) -> bool:
    """True when the watcher is switched OFF (the mute file exists). Never raises."""
    try:
        return _switch_path(root).exists()
    except OSError:
        return False  # an unreadable inbox is not a mute; the caller's own probe will fail closed


def set_muted(muted: bool, root: Path | str | None = None) -> bool:
    """Flip the switch. ``muted=True`` mutes (creates the file); ``False`` un-mutes (removes it).

    Returns the resulting muted state. Idempotent — muting an already-muted watcher is a no-op — and
    best-effort: a filesystem error is logged, not raised, so a toggle never crashes the caller.
    """
    path = _switch_path(root)
    try:
        if muted:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
        else:
            path.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("twoperson.watch_switch_failed", muted=muted, error=str(exc))
    return is_muted(root)


@dataclass(frozen=True)
class Cursor:
    """Filenames already reacted to, per lane. Pruned to what is still present, so it stays small.

    Four lanes now: the audit pair (packets/verdicts) and the advisory pair (consults/advice). A lane
    absent from an older on-disk cursor loads as empty, so an upgrade re-notifies each already-present
    advisory item at most once — the same benign worst case the tolerant loader gives everywhere else.
    """

    packets: frozenset[str] = frozenset()
    verdicts: frozenset[str] = frozenset()
    consults: frozenset[str] = frozenset()
    advice: frozenset[str] = frozenset()

    def to_json(self) -> dict[str, list[str]]:
        return {"packets": sorted(self.packets), "verdicts": sorted(self.verdicts),
                "consults": sorted(self.consults), "advice": sorted(self.advice)}

    @classmethod
    def from_json(cls, obj: object) -> "Cursor":
        """Tolerant load: anything malformed degrades to an empty cursor (worst case: re-notify once)."""
        if not isinstance(obj, dict):
            return cls()
        def _lane(key: str) -> frozenset[str]:
            v = obj.get(key)
            return frozenset(x for x in v if isinstance(x, str)) if isinstance(v, list) else frozenset()
        return cls(packets=_lane("packets"), verdicts=_lane("verdicts"),
                   consults=_lane("consults"), advice=_lane("advice"))


@dataclass(frozen=True)
class WatchDelta:
    """What is new since the cursor, plus the cursor to persist (pruned to current lane contents)."""

    new_packets: tuple[str, ...]
    new_verdicts: tuple[str, ...]
    cursor: Cursor
    new_consults: tuple[str, ...] = ()
    new_advice: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (self.new_packets or self.new_verdicts
                    or self.new_consults or self.new_advice)


@dataclass
class DispatchReport:
    """Outcome of one pass — returned for the CLI to print and for tests to assert on."""

    new_packets: tuple[str, ...] = ()
    new_verdicts: tuple[str, ...] = ()
    new_consults: tuple[str, ...] = ()
    new_advice: tuple[str, ...] = ()
    notified: list[str] = field(default_factory=list)
    launched: list[str] = field(default_factory=list)
    launch_failed: list[str] = field(default_factory=list)
    muted: bool = False

    @property
    def acted(self) -> bool:
        return bool(self.new_packets or self.new_verdicts
                    or self.new_consults or self.new_advice)


# --------------------------------------------------------------------------------------------
# Pure core — no I/O beyond listing the lanes; trivially testable.
# --------------------------------------------------------------------------------------------

def scan_new(root: Path | str | None, cursor: Cursor) -> WatchDelta:
    """Compute what packets/verdicts are new since ``cursor``, and the cursor to persist next.

    "New" is *present in the lane now and not in the cursor*. The next cursor is pruned to **exactly
    the current lane contents**, so a file that has since been claimed/acked drops out and can never
    pin the cursor open — and because inbox filenames are unique (timestamp + id), a name never
    legitimately reappears, so pruning cannot cause a re-fire of real work.
    """
    packets_now = frozenset(p.name for p in pending(root))
    verdicts_now = frozenset(p.name for p in pending_verdicts(root))
    consults_now = frozenset(p.name for p in pending_consults(root))
    advice_now = frozenset(p.name for p in pending_advice(root))
    new_packets = tuple(sorted(packets_now - cursor.packets))
    new_verdicts = tuple(sorted(verdicts_now - cursor.verdicts))
    new_consults = tuple(sorted(consults_now - cursor.consults))
    new_advice = tuple(sorted(advice_now - cursor.advice))
    return WatchDelta(
        new_packets=new_packets,
        new_verdicts=new_verdicts,
        new_consults=new_consults,
        new_advice=new_advice,
        cursor=Cursor(packets=packets_now, verdicts=verdicts_now,
                      consults=consults_now, advice=advice_now),
    )


# --------------------------------------------------------------------------------------------
# Cursor persistence — best-effort, never fatal.
# --------------------------------------------------------------------------------------------

def _cursor_path(root: Path | str | None) -> Path:
    return inbox_root(root) / CURSOR_NAME


@contextmanager
def _dispatch_lock(root: Path | str | None):
    """Blocking inter-process lock (the repo's flock idiom) so one dispatch pass runs at a time.

    Lives on its own ``.watch.lock`` file, distinct from the publish lock, so serializing dispatches
    never contends with publishing a packet. The lock degrades to a **no-op** rather than crashing the
    watcher on either failure surface: (a) the inbox tree cannot be created / the lock file cannot be
    opened (an unwritable or not-yet-existing root), or (b) ``flock`` acquisition itself fails because
    locking is unsupported on the filesystem (e.g. some network mounts return ``ENOTSUP``). In both
    cases the worst case is the un-serialized behaviour we had before, never a raised exception.
    """
    try:
        directory = inbox_root(root)
        directory.mkdir(parents=True, exist_ok=True)
        handle = open(directory / DISPATCH_LOCK_NAME, "w")
    except OSError as exc:
        log.warning("twoperson.watch_lock_unavailable", error=str(exc))
        yield
        return
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
        except OSError as exc:
            # Locking unsupported on this filesystem — degrade to un-serialized behaviour, don't crash.
            log.warning("twoperson.watch_lock_unavailable", error=str(exc))
            yield
            return
        try:
            yield
        finally:
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        handle.close()


def load_cursor(root: Path | str | None = None) -> Cursor:
    path = _cursor_path(root)
    try:
        return Cursor.from_json(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return Cursor()  # missing or corrupt ⇒ start clean; the only cost is one duplicate notify


def save_cursor(cursor: Cursor, root: Path | str | None = None) -> None:
    path = _cursor_path(root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_text(json.dumps(cursor.to_json(), ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        log.warning("twoperson.watch_cursor_save_failed", error=str(exc))


# --------------------------------------------------------------------------------------------
# Isolated effects — notification + command launch. Each swallows its own failure.
# --------------------------------------------------------------------------------------------

def notify(title: str, message: str) -> bool:
    """Best-effort desktop notification. Returns True if a backend accepted it.

    Tries ``terminal-notifier`` then macOS ``osascript``; on any other platform (or if both are
    absent) it logs and rings the terminal bell. Never raises. ``title``/``message`` are our own
    strings (counts + lane names), not packet content.
    """
    def _safe_run(argv: list[str]) -> bool:
        try:
            subprocess.run(argv, check=True, capture_output=True, timeout=10)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    tn = shutil.which("terminal-notifier")
    if tn and _safe_run([tn, "-title", title, "-message", message]):
        return True
    osa = shutil.which("osascript")
    if osa:
        script = f'display notification {json.dumps(message)} with title {json.dumps(title)}'
        if _safe_run([osa, "-e", script]):
            return True
    # Fallback: a log line and a BEL, so a headless/Linux run still surfaces something.
    log.info("twoperson.watch_notify", title=title, message=message)
    try:
        sys.stderr.write("\a")
        sys.stderr.flush()
    except OSError:
        pass
    return False


def run_command(command: str, env: Mapping[str, str] | None = None) -> int | None:
    """Launch an owner-configured command **detached** and return immediately. Never raises.

    The watcher's job is to *trigger* the audit/wake, not to run it. An audit can take minutes, so the
    watcher must never block on it or kill it with a timeout — it launches the command in its own
    session (``start_new_session=True``) and does not wait. Fire-and-forget is also why a hung audit
    can never wedge the watcher: there is nothing to hang on. The completed audit announces itself the
    normal way — a verdict lands in ``verdicts/`` and wakes the manager side on the next pass.

    The command is trusted owner configuration (from an env var), run with the same authority as the
    owner's shell — like a git hook. It is *never* built from packet/verdict content. stdio is
    detached to ``/dev/null`` (the launched tool keeps its own logs). Returns the child pid, or
    ``None`` if nothing was launched.
    """
    if not command.strip():
        return None
    try:
        devnull = subprocess.DEVNULL
        # ``env`` adds the tier hints (`twoperson.tier.tier_env`) on top of the inherited environment;
        # the command string itself is untouched, so packet content never reaches the shell.
        child_env = {**os.environ, **dict(env)} if env else None
        proc = subprocess.Popen(  # noqa: S602 - owner config, detached by design
            command, shell=True, stdin=devnull, stdout=devnull, stderr=devnull,
            start_new_session=True, env=child_env,
        )
        return proc.pid
    except (OSError, ValueError) as exc:
        log.warning("twoperson.watch_launch_failed", command=command, error=str(exc))
        return None


# --------------------------------------------------------------------------------------------
# One pass — scan, notify both sides, optionally launch, persist cursor. launchd calls this.
# --------------------------------------------------------------------------------------------

def _launch(run_fn, command: str, env: Mapping[str, str] | None):
    """Call an owner launch function with the tier environment when it accepts one. A ``run_fn``
    written before tiers existed (``run_fn(command)``) keeps working unchanged."""
    if env:
        try:
            return run_fn(command, env=env)
        except TypeError as exc:
            if "env" not in str(exc):
                raise
    return run_fn(command)


def _tier_env_for_oldest(root: Path | str | None, names: Sequence[str]) -> dict[str, str]:
    """Tier hints for the oldest of the newly seen packets — the one the reviewer will claim first.
    Best-effort: any failure yields an empty environment, never a failed launch."""
    if not names:
        return {}
    try:
        from . import inbox as _inbox
        from .tier import tier_env
        directory = _inbox.inbox_root(root) / "pending"
        path = Path(sorted(names)[0])
        if not path.is_absolute():
            path = directory / path.name
        return tier_env(_inbox._load(path))
    except Exception as exc:  # noqa: BLE001 - a hint, not a gate; say why it was skipped
        log.warning("twoperson.tier_hint_skipped", error=repr(exc))
        return {}


def dispatch_once(
    root: Path | str | None = None,
    *,
    audit_cmd: str | None = None,
    wake_cmd: str | None = None,
    consult_cmd: str | None = None,
    advice_cmd: str | None = None,
    notify_fn=notify,
    run_fn=run_command,
) -> DispatchReport:
    """React to whatever is new in the inbox since the last pass. Idempotent, never raises.

    Four lanes, two paired directions. The **audit** pair: a new packet wakes the Reviewer/audit side, a
    new verdict wakes the Builder/manager side. The **advisory** pair, symmetric with it: a new consult
    wakes the Reviewer side to advise ASAP, a new advice wakes the Builder/manager side. Each side has its
    own owner-set launch command — ``audit_cmd``/``wake_cmd``/``consult_cmd``/``advice_cmd`` default to
    the matching env vars, and an unset command means *notify only* for that side. The consult command
    is a **separate** command from the audit command on purpose: a consult is not a packet, so Reviewer's
    consult runner (`consult-check`/`consult-next`/`consult-advise`) is a different tool from its audit
    runner — but the *mechanism* (land → wake → reply) is identical, which is the whole point.

    **A configured launch that FAILS keeps its items unseen.** The cursor normally advances to the
    current lane contents, so an item is reacted to once. But if a launch command *is configured* and
    fails to start (``run_fn`` returns ``None``), marking that item seen would leave the packet pending
    yet permanently suppressed from future wakeups — the audit would never happen. So on a launch
    failure we **retain** those filenames as unseen: the next inbox change retries them. A successful
    launch (a pid) or a notify-only side (no command) advances normally. The cursor is saved **after**
    reacting, so a crash mid-pass re-reacts rather than silently swallowing an item.

    **The master mute switch wins over everything.** If the watcher is switched OFF (`is_muted`), this
    returns immediately: no notification, no launch, and — crucially — the cursor is **left untouched**,
    so whatever arrives while muted is picked up and announced the moment the switch is turned back on.
    Mute is a *pause*, not a *skip*. The switch is checked twice: once as a cheap fast-path before the
    lock, and again **inside** the lock, so a mute flipped on while this pass was blocked waiting for the
    lock still wins — the re-check pins mute's precedence against an off-toggle racing an in-flight pass.
    """
    if is_muted(root):
        return DispatchReport(muted=True)  # no scan, no notify, no launch, no cursor change

    audit_cmd = os.environ.get(AUDIT_CMD_ENV, "") if audit_cmd is None else audit_cmd
    wake_cmd = os.environ.get(WAKE_CMD_ENV, "") if wake_cmd is None else wake_cmd
    consult_cmd = os.environ.get(CONSULT_CMD_ENV, "") if consult_cmd is None else consult_cmd
    advice_cmd = os.environ.get(ADVICE_CMD_ENV, "") if advice_cmd is None else advice_cmd

    # Serialize the whole read→react→save-cursor window across processes. Concurrent triggers (a
    # launchd lane change, the switch-file handler, an `--on` catch-up, a loop tick) would otherwise
    # each load the SAME cursor, both see the work as new, and double-fire notifications and launches.
    # Under the lock the second dispatch reads the cursor the first already advanced ⇒ nothing new.
    with _dispatch_lock(root):
        # Re-check under the lock: a mute toggled on while we were blocked acquiring the lock must
        # still win. Bail with the cursor untouched, exactly as the pre-lock fast-path does.
        if is_muted(root):
            return DispatchReport(muted=True)
        delta = scan_new(root, load_cursor(root))
        report = DispatchReport(new_packets=delta.new_packets, new_verdicts=delta.new_verdicts,
                                new_consults=delta.new_consults, new_advice=delta.new_advice)

        # Advance the cursor to the current lanes by default; below we RETAIN (keep unseen) any lane
        # whose configured launch failed, so a failed audit/wake/consult is retried rather than
        # suppressed. All four lanes now follow this same rule — a notify-only side (no command
        # configured) advances normally.
        save_packets = set(delta.cursor.packets)
        save_verdicts = set(delta.cursor.verdicts)
        save_consults = set(delta.cursor.consults)
        save_advice = set(delta.cursor.advice)

        if delta.new_packets:
            n = len(delta.new_packets)
            if notify_fn("TWOPERSON · Reviewer audit waiting", f"{n} packet(s) in the inbox to audit"):
                report.notified.append("reviewer")
            if audit_cmd.strip():
                hints = _tier_env_for_oldest(root, delta.new_packets)
                if _launch(run_fn, audit_cmd, hints) is None:  # launch failed to start — retry next fire
                    save_packets -= set(delta.new_packets)
                    report.launch_failed.append("reviewer")
                    log.warning("twoperson.watch_audit_launch_failed", packets=n)
                else:
                    report.launched.append("reviewer")

        if delta.new_verdicts:
            n = len(delta.new_verdicts)
            if notify_fn("TWOPERSON · Reviewer verdict returned", f"{n} verdict(s) for the manager to process"):
                report.notified.append("builder")
            if wake_cmd.strip():
                if run_fn(wake_cmd) is None:  # launch failed to start — retry these next fire
                    save_verdicts -= set(delta.new_verdicts)
                    report.launch_failed.append("builder")
                    log.warning("twoperson.watch_wake_launch_failed", verdicts=n)
                else:
                    report.launched.append("builder")

        # Advisory lanes, symmetric with the audit pair: a consult wakes the Reviewer side to advise
        # ASAP ("advise me"), a returned advice wakes the Builder/manager side ("counsel is back"). Each
        # launches its own owner-set command when configured, with the same launch-failure-retain rule
        # as the audit lanes so a failed wake is retried rather than suppressed. Unset ⇒ notify only.
        if delta.new_consults:
            n = len(delta.new_consults)
            if notify_fn("TWOPERSON · Reviewer consult waiting", f"{n} consult(s) awaiting Reviewer's advice"):
                report.notified.append("reviewer")
            if consult_cmd.strip():
                if run_fn(consult_cmd) is None:  # launch failed to start — retry these next fire
                    save_consults -= set(delta.new_consults)
                    report.launch_failed.append("reviewer")
                    log.warning("twoperson.watch_consult_launch_failed", consults=n)
                else:
                    report.launched.append("reviewer")

        if delta.new_advice:
            n = len(delta.new_advice)
            if notify_fn("TWOPERSON · Reviewer advice returned", f"{n} advice reply(ies) for the manager"):
                report.notified.append("builder")
            if advice_cmd.strip():
                if run_fn(advice_cmd) is None:  # launch failed to start — retry these next fire
                    save_advice -= set(delta.new_advice)
                    report.launch_failed.append("builder")
                    log.warning("twoperson.watch_advice_launch_failed", advice=n)
                else:
                    report.launched.append("builder")

        save_cursor(Cursor(packets=frozenset(save_packets), verdicts=frozenset(save_verdicts),
                           consults=frozenset(save_consults), advice=frozenset(save_advice)), root)
    return report


def watch_loop(
    root: Path | str | None = None,
    *,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    max_passes: int | None = None,
    **dispatch_kwargs,
) -> int:
    """Portable polling loop for a foreground/manual run. Returns the number of passes that acted.

    launchd users do **not** need this — they wire ``watch --once`` to ``WatchPaths`` and pay nothing
    between events. This exists for a `tmux` window or a machine without launchd. ``max_passes`` bounds
    it for tests; ``None`` runs until interrupted.
    """
    acted = 0
    passes = 0
    try:
        while max_passes is None or passes < max_passes:
            if dispatch_once(root, **dispatch_kwargs).acted:
                acted += 1
            passes += 1
            if max_passes is not None and passes >= max_passes:
                break
            time.sleep(max(0.1, interval))
    except KeyboardInterrupt:
        log.info("twoperson.watch_stopped", passes=passes, acted=acted)
    return acted
