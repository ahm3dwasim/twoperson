"""The completion **signal**: a tiny, schema-safe "a session finished" event — never a packet.

A Claude Code session ends whether or not it produced anything auditable. The signal records only
that fact, so Reviewer can be woken by an event instead of polling on a timer. It deliberately carries
**no claim about the work**: no goal, no tests, no diff, no cost. Fabricating those from a hook
would be worse than useless — it would look like an audit brief while asserting things nobody
verified.

    signal  = "a session stopped here, and this is whether a packet was waiting when it did"
    packet  = "here is the change, the evidence, and the claims — audit it"

The audit gate is unchanged: Reviewer claims and audits **packets** (`check` / `next`). A signal only
tells it when looking is worthwhile. See `docs/PROTOCOL.md` §5.

Everything reaching this module is untrusted — the hook payload is JSON handed to us by another
process, and `branch` comes from the environment. Values are sanitised to a conservative charset,
length-capped, secret-scanned, and anything that fails degrades to ``"unknown"`` rather than
raising: a Stop hook that errors would block a session, which is a far worse failure than a signal
that says less than it could.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

# The `_`-prefixed field validators are package-internal on purpose: the signal deliberately reuses
# the packet's exact string/bool/enum rules rather than growing a second, subtly different set.
from .packet import (
    MAX_SHORT,
    UNKNOWN,
    PacketError,
    SchemaError,
    SecretLeakError,
    _boolean,
    _enum,
    _iso_timestamp,
    _short,
    _slug,
    find_secrets,
)

SIGNAL_SCHEMA_VERSION = "1"
SIGNAL_KIND = "completion_signal"

#: A signal is a handful of short scalars. The cap is two orders of magnitude under the packet's,
#: so a hostile or runaway hook payload cannot turn the inbox into a memory sink.
MAX_SIGNAL_BYTES = 8_192

#: The Claude Code hook payload we are handed on stdin. Bounded before it is parsed.
MAX_HOOK_PAYLOAD_BYTES = 65_536

SOURCES = frozenset({"claude-code-stop-hook", "manual"})

BRANCH_ENV = "TWOPERSON_BRANCH"

#: Conservative: git ref and session-id characters only. `/` is allowed because branch names use it
#: (`session/foo`); every shell-dangerous character is not. A value that does not match is dropped,
#: not escaped — the signal has nothing important enough to be worth rescuing a hostile string for.
_SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,%d}$" % (MAX_SHORT - 1))

_DEFAULT_NOTE = "Claude Code session completion signal — not a review packet."

_SIGNAL_SCHEMA: dict[str, Any] = {
    "schema_version": lambda v, f: _enum(v, f, frozenset({SIGNAL_SCHEMA_VERSION})),
    "kind": lambda v, f: _enum(v, f, frozenset({SIGNAL_KIND})),
    "signal_id": _slug,
    "created_at": _iso_timestamp,
    "source": lambda v, f: _enum(v, f, SOURCES),
    "session_id": _short,
    "branch": _short,
    "packet_pending": _boolean,
    "note": _short,
}

SIGNAL_FIELDS = frozenset(_SIGNAL_SCHEMA)

__all__ = [
    "MAX_HOOK_PAYLOAD_BYTES",
    "MAX_SIGNAL_BYTES",
    "SIGNAL_FIELDS",
    "SIGNAL_KIND",
    "SIGNAL_SCHEMA_VERSION",
    "SOURCES",
    "build_signal",
    "current_branch",
    "dumps_signal",
    "new_signal_id",
    "loads_signal",
    "render_signal",
    "safe_note",
    "safe_value",
    "session_id_from_hook_payload",
    "validate_signal",
]


def safe_value(value: Any) -> str:
    """Untrusted scalar -> a short, safe string, or ``"unknown"``. Total: never raises.

    Rejection is silent by design. The caller is usually a Stop hook, where the only alternatives
    to degrading are lying or failing the session.
    """
    if not isinstance(value, str):
        return UNKNOWN
    text = value.strip()
    if not text or not _SAFE_VALUE_RE.match(text):
        return UNKNOWN
    # These values are only ever displayed — `signal_id` is what becomes a filename, and it is
    # generated here, not accepted. Refusing path-shaped values anyway keeps a hostile session id
    # from ever *looking* like a path to a downstream tool that is less careful than the inbox.
    if ".." in text or "//" in text or text.endswith("/"):
        return UNKNOWN
    # Charset alone does not exclude credentials: `sk-ant-…` and `ghp_…` are both charset-legal.
    return UNKNOWN if find_secrets(text) else text


def safe_note(value: Any) -> str:
    """A human-readable note reduced to one safe line, or the default. Total: never raises.

    Notes are prose, so the identifier charset above is far too strict for them. They get the
    treatment prose needs instead: control characters (including the newlines that would let a
    note forge extra lines in `render_signal`) collapse to spaces, length is capped, and a
    token-shaped note is dropped entirely.
    """
    if not isinstance(value, str):
        return _DEFAULT_NOTE
    text = "".join(" " if (ord(ch) < 32 or ord(ch) == 127) else ch for ch in value).strip()
    text = " ".join(text.split())[:MAX_SHORT].strip()
    if not text or find_secrets(text):
        return _DEFAULT_NOTE
    return text


def current_branch(root: Path | str | None = None) -> str:
    """The current git branch, or ``"unknown"``. Env override first so callers can pin it.

    Fails soft on every path (no git, no repo, detached HEAD, slow disk) — a signal that cannot
    name the branch is still a useful signal, and a hook may not hang.
    """
    override = os.environ.get(BRANCH_ENV, "").strip()
    if override:
        return safe_value(override)
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(root) if root else None,
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN
    if completed.returncode != 0:
        return UNKNOWN
    return safe_value(completed.stdout.strip())


def session_id_from_hook_payload(raw: bytes | str) -> str:
    """The ``session_id`` out of a Claude Code hook payload, or ``"unknown"``. Never raises.

    The payload is an external contract we do not own, so unknown keys are ignored rather than
    rejected — only the one field we use is read, and it is sanitised like any other hostile input.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_HOOK_PAYLOAD_BYTES:
        return UNKNOWN
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return UNKNOWN
    if not isinstance(payload, Mapping):
        return UNKNOWN
    return safe_value(payload.get("session_id"))


def new_signal_id(now: datetime | None = None) -> str:
    """A slug that sorts chronologically and cannot collide across concurrent sessions."""
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"sig-{stamp}-{secrets.token_hex(4)}"


def build_signal(
    *,
    source: str = "manual",
    session_id: Any = UNKNOWN,
    branch: Any = None,
    packet_pending: bool = False,
    note: Any = None,
    now: datetime | None = None,
) -> dict:
    """Assemble a validated signal. Untrusted inputs are sanitised, not trusted or echoed."""
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    signal = {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "kind": SIGNAL_KIND,
        "signal_id": new_signal_id(moment),
        "created_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source if source in SOURCES else "manual",
        "session_id": safe_value(session_id),
        "branch": safe_value(branch) if branch is not None else current_branch(),
        "packet_pending": bool(packet_pending),
        "note": safe_note(note) if note is not None else _DEFAULT_NOTE,
    }
    return validate_signal(signal)


def validate_signal(signal: Any) -> dict:
    """Return a validated copy of ``signal``, or raise a :class:`PacketError` subclass.

    Same trust boundary as a packet, at a smaller scale: secrets first, unknown keys rejected, every
    field required and typed.
    """
    if not isinstance(signal, Mapping):
        raise SchemaError(f"signal: expected an object, got {type(signal).__name__}")

    leaks = find_secrets(signal)
    if leaks:
        raise SecretLeakError(
            "refusing to emit: token-shaped value(s) found at " + ", ".join(sorted(leaks))
            + " — values are never echoed here"
        )

    unknown = sorted(set(signal) - SIGNAL_FIELDS)
    if unknown:
        raise SchemaError(f"signal: unknown key(s) {unknown}")

    out: dict[str, Any] = {}
    for field, check in _SIGNAL_SCHEMA.items():
        if field not in signal:
            raise SchemaError(f"{field}: missing (required)")
        out[field] = check(signal[field], field)
    return out


def loads_signal(raw: bytes | str) -> dict:
    """Size-guard, parse, and validate untrusted signal bytes."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, (bytes, bytearray)):
        raise PacketError(f"signal: expected bytes or str, got {type(raw).__name__}")
    if len(raw) > MAX_SIGNAL_BYTES:
        raise PacketError(f"signal: size {len(raw)} exceeds the {MAX_SIGNAL_BYTES}-byte limit")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PacketError(f"signal: not valid UTF-8 JSON ({exc})") from exc
    return validate_signal(parsed)


def dumps_signal(signal: Mapping) -> str:
    """Canonical, stable JSON for a validated signal (used by the inbox writer)."""
    return json.dumps(signal, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_signal(signal: Mapping) -> str:
    """One dense line per signal — this is a wake-up, not a brief, so it never grows a body."""
    return (f"{signal['created_at']} {signal['signal_id']} source={signal['source']} "
            f"branch={signal['branch']} session={signal['session_id']} "
            f"packet_pending={str(signal['packet_pending']).lower()}")
