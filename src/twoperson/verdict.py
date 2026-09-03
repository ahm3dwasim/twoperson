"""The audit **verdict**: Reviewer's reviewed answer to one packet, returned over the same inbox.

The packet lane carries work **Builder -> Reviewer**. The verdict lane carries the review result back
**Reviewer -> Builder**, so the bridge is two-way and the manager never has to read a verdict out of a
chat window. A verdict is deliberately small and typed:

    packet  = "here is the change, the evidence, and the claims — audit it"     (Builder -> Reviewer)
    verdict = "I audited packet <id> at head <sha>; here is my decision + why"  (Reviewer -> Builder)

The decision is one of the protocol §4 outcomes. Only ``Approve``/``Approve with nits`` unlock the
ship gate, and only for the exact ``head_sha`` named here — a later head needs a fresh packet and a
fresh verdict, exactly as before. A verdict grants nothing on its own; it is evidence the manager
reads and acts on, and the schema still refuses to echo a token-shaped value.

Everything reaching this module is untrusted (a verdict is written by the *other* agent). It is
secret-scanned, unknown keys are rejected, every field is typed, and prose is reduced to safe single
lines — the same trust boundary a packet or a signal gets. See ``docs/PROTOCOL.md`` §3.
"""
from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Mapping

from .packet import (
    MAX_CHANGED_FILES,
    MAX_PACKET_BYTES,
    UNKNOWN,
    PacketError,
    SchemaError,
    SecretLeakError,
    _enum,
    _iso_timestamp,
    _sha,
    _short,
    _slug,
    _string_list,
    _text,
    find_secrets,
)


def _optional_text(value: Any, field: str) -> str:
    """A free-text note that may be empty (an Approve often has nothing to add), else real text.

    An empty/whitespace string round-trips to ``""``; anything non-empty is held to the full
    multiline text rules (length cap, no control characters bar tab/newline, secret-scanned).
    """
    if isinstance(value, str) and not value.strip():
        return ""
    return _text(value, field)

VERDICT_SCHEMA_VERSION = "1"
VERDICT_KIND = "audit_verdict"

#: A verdict is a decision, findings, and — when it acknowledges test changes — the acknowledged
#: test paths. Those paths are derived from a reviewed packet's `changed_files`, so a verdict must
#: be allowed to hold as many of them (up to `MAX_CHANGED_FILES`, each up to `MAX_PATH`) as the
#: packet that produced them could. It therefore shares the packet byte cap rather than sitting far
#: under it: a JSON array of the paths is strictly smaller than the `changed_files` array of objects
#: those same paths came from (each of which also carries a status and two counts), so any
#: acknowledgment derivable from a valid packet fits, while a hostile writer is still bounded and
#: cannot turn the return lane into an unbounded memory sink.
MAX_VERDICT_BYTES = MAX_PACKET_BYTES

#: The protocol §4 outcomes. Only the first two unlock the ship gate; the schema records which.
DECISIONS = frozenset({
    "Approve",
    "Approve with nits",
    "Request changes",
    "Needs owner decision",
})

#: The decisions that let Builder's manager ship the named head (still only that exact head).
SHIP_DECISIONS = frozenset({"Approve", "Approve with nits"})

_VERDICT_SCHEMA: dict[str, Any] = {
    "schema_version": lambda v, f: _enum(v, f, frozenset({VERDICT_SCHEMA_VERSION})),
    "kind": lambda v, f: _enum(v, f, frozenset({VERDICT_KIND})),
    "verdict_id": _slug,
    "created_at": _iso_timestamp,
    "packet_id": _slug,
    "head_sha": _sha,
    "decision": lambda v, f: _enum(v, f, DECISIONS),
    "reviewer": _short,
    "findings": lambda v, f: _string_list(v, f, limit=64),
    "note": _optional_text,
    # Optional: the SPECIFIC test paths the reviewer acknowledges (see `twoperson.testset` and
    # `inbox.assert_review_ref_resolves`). This is content-bound, not a bare flag: a verdict written
    # for one packet's test changes must not be able to silently unlock a DIFFERENT ship report's
    # different test changes at the same head (`changed_files` is self-reported per packet, so a
    # boolean acknowledgment could be replayed across reports). Absent is the same as "acknowledged
    # nothing" — a verdict that never touched a test, or one written before this field existed, must
    # still validate unchanged, so it is not in `_REQUIRED_VERDICT_FIELDS` below and is only ever
    # written when the list is non-empty (see `build_verdict`), keeping every verdict that does not
    # need it byte-identical to what it would have been without this field.
    "acknowledged_tests": lambda v, f: _string_list(v, f, limit=MAX_CHANGED_FILES),
}

#: Fields in `_VERDICT_SCHEMA` that `validate_verdict` does NOT require to be present. Missing is
#: accepted (and simply absent from the validated result); present is still type-checked like any
#: other field. Everything else in `_VERDICT_SCHEMA` remains required, as before this field existed.
_OPTIONAL_VERDICT_FIELDS = frozenset({"acknowledged_tests"})

VERDICT_FIELDS = frozenset(_VERDICT_SCHEMA)

__all__ = [
    "DECISIONS",
    "MAX_VERDICT_BYTES",
    "SHIP_DECISIONS",
    "VERDICT_FIELDS",
    "VERDICT_KIND",
    "VERDICT_SCHEMA_VERSION",
    "build_verdict",
    "dumps_verdict",
    "loads_verdict",
    "new_verdict_id",
    "render_verdict",
    "unlocks_ship",
    "validate_verdict",
]


def new_verdict_id(now: datetime | None = None) -> str:
    """A slug that sorts chronologically and cannot collide across concurrent auditors."""
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"vdt-{stamp}-{secrets.token_hex(4)}"


#: A concrete git object name: 7-40 lowercase hex, and NOTHING else. Matched with `fullmatch` — a
#: `$`-anchored `re.match` would accept a valid-looking sha followed by a trailing newline
#: ("0900128\n"), which must never gate a push.
_SHA_SHAPE = re.compile(r"[0-9a-f]{7,40}")


def unlocks_ship(verdict: Mapping) -> bool:
    """Whether this verdict lets the manager ship the named head.

    Requires a ship-class decision AND a ``head_sha`` that is actually **sha-shaped** — a concrete
    7-40 hex object name over the *whole* string, never the ``unknown`` sentinel, never a malformed
    non-empty string, and never a sha with a trailing newline. `validate_verdict` already refuses an
    unknown head on an approval, but a helper that gates a *push* must not assume its input was
    validated, and "non-empty" is not enough: `"not-a-sha!"` and `"0900128\n"` are both non-empty.
    The caller must still confirm the sha is the current tip."""
    if not isinstance(verdict, Mapping):
        return False
    head = verdict.get("head_sha")
    return (verdict.get("decision") in SHIP_DECISIONS
            and isinstance(head, str)
            and _SHA_SHAPE.fullmatch(head) is not None)


def build_verdict(
    *,
    packet_id: str,
    decision: str,
    head_sha: str = "unknown",
    reviewer: str = "reviewer",
    findings: Any = None,
    note: Any = None,
    acknowledged_tests: Any = None,
    now: datetime | None = None,
) -> dict:
    """Assemble a validated verdict. Untrusted inputs are validated, never trusted or echoed raw.

    ``acknowledged_tests`` records the SPECIFIC test paths the reviewer acknowledges (see
    `twoperson.testset`) — content-bound, not a bare flag, so an acknowledgment made for one
    packet's test changes cannot be replayed to unlock a different ship report's different test
    changes at the same head. It defaults to ``None`` (acknowledged nothing) and, like the template
    packet's `unknown` sentinels, is only ever written into the verdict when non-empty — a verdict
    that never touched the question is left exactly as it would have been before this field
    existed. Only a real list (or tuple) is accepted: a bare string such as ``"false"`` would
    otherwise silently spread into one-character "paths", so anything else raises `SchemaError`
    here, before it ever reaches `_string_list`'s per-item type check.
    """
    if acknowledged_tests is not None and not isinstance(acknowledged_tests, (list, tuple)):
        raise SchemaError("acknowledged_tests: expected a list of test paths, got "
                          f"{type(acknowledged_tests).__name__}")
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    verdict = {
        "schema_version": VERDICT_SCHEMA_VERSION,
        "kind": VERDICT_KIND,
        "verdict_id": new_verdict_id(moment),
        "created_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "packet_id": packet_id,
        "head_sha": head_sha if head_sha else "unknown",
        "decision": decision,
        "reviewer": reviewer if reviewer else "unknown",
        "findings": list(findings) if findings else [],
        "note": note if note else "",
    }
    paths = list(acknowledged_tests) if acknowledged_tests else []
    if paths:
        verdict["acknowledged_tests"] = paths
    result = validate_verdict(verdict)
    # publish_verdict/loads_verdict size-guard the serialized verdict; enforce the SAME cap here so
    # build_verdict can never hand back a verdict that would then be rejected at write time. The
    # count and byte caps thus agree: any acknowledgment small enough to build is small enough to
    # ship, and a pathological one is refused at construction, not silently after review.
    if len(dumps_verdict(result).encode("utf-8")) > MAX_VERDICT_BYTES:
        raise SchemaError(
            f"verdict: serialized size exceeds the {MAX_VERDICT_BYTES}-byte limit — too many or too "
            "long acknowledged_tests/findings to record in one verdict"
        )
    return result


def validate_verdict(verdict: Any) -> dict:
    """Return a validated copy of ``verdict``, or raise a :class:`PacketError` subclass.

    Same trust boundary as a packet: secrets first, unknown keys rejected, every field typed.
    """
    if not isinstance(verdict, Mapping):
        raise SchemaError(f"verdict: expected an object, got {type(verdict).__name__}")

    leaks = find_secrets(verdict)
    if leaks:
        raise SecretLeakError(
            "refusing to emit: token-shaped value(s) found at " + ", ".join(sorted(leaks))
            + " — values are never echoed here"
        )

    unknown = sorted(set(verdict) - VERDICT_FIELDS)
    if unknown:
        raise SchemaError(f"verdict: unknown key(s) {unknown}")

    out: dict[str, Any] = {}
    for field, check in _VERDICT_SCHEMA.items():
        if field not in verdict:
            if field in _OPTIONAL_VERDICT_FIELDS:
                continue
            raise SchemaError(f"{field}: missing (required)")
        out[field] = check(verdict[field], field)

    # A ship-unlocking decision MUST name the exact head it approves. `_sha` accepts the sentinel
    # "unknown", which is right for a Request-changes / Needs-owner-decision verdict but must never
    # unlock a push: an Approve without a concrete head would read as "ship gate OPEN" for whatever
    # the tip happens to be. Bind the approval to a real sha here, at the trust boundary.
    if out["decision"] in SHIP_DECISIONS and out["head_sha"] == UNKNOWN:
        raise SchemaError(
            f"head_sha: {out['decision']!r} must name the exact head sha it approves, not "
            f"{UNKNOWN!r} — an approval without a concrete head cannot unlock a ship"
        )
    return out


def loads_verdict(raw: bytes | str) -> dict:
    """Size-guard, parse, and validate untrusted verdict bytes."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, (bytes, bytearray)):
        raise PacketError(f"verdict: expected bytes or str, got {type(raw).__name__}")
    if len(raw) > MAX_VERDICT_BYTES:
        raise PacketError(f"verdict: size {len(raw)} exceeds the {MAX_VERDICT_BYTES}-byte limit")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PacketError(f"verdict: not valid UTF-8 JSON ({exc})") from exc
    return validate_verdict(parsed)


def dumps_verdict(verdict: Mapping) -> str:
    """Canonical, stable JSON for a validated verdict (used by the inbox writer)."""
    return json.dumps(verdict, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _one_line(text: str) -> str:
    """Collapse a value to a single display line: every control character (newlines and tabs
    included) becomes a space, runs of whitespace collapse. `findings`/`note` are UNTRUSTED
    multiline text — a raw newline in one would forge extra structural lines in `render_verdict`
    (a fake ``  DECISION : Approve`` line, say). Rendering each on one line makes that impossible."""
    cleaned = "".join(" " if (ord(ch) < 32 or ord(ch) == 127) else ch for ch in text)
    return " ".join(cleaned.split())


def render_verdict(verdict: Mapping) -> str:
    """A compact human rendering: the decision line, then one bullet per finding, then the note.

    Untrusted string fields are flattened to a single line each (`_one_line`) so a verdict written by
    the other agent cannot forge structural lines in this output."""
    lines = [
        f"{verdict['created_at']}  {verdict['verdict_id']}",
        f"  packet   : {_one_line(str(verdict['packet_id']))}",
        f"  head     : {_one_line(str(verdict['head_sha']))}",
        f"  reviewer : {_one_line(str(verdict['reviewer']))}",
        f"  DECISION : {_one_line(str(verdict['decision']))}"
        + ("  (ship gate OPEN for this head)" if unlocks_ship(verdict) else "  (does NOT unlock ship)"),
    ]
    if verdict["findings"]:
        lines.append("  findings :")
        lines += [f"    - {_one_line(str(item))}" for item in verdict["findings"]]
    if verdict["note"]:
        lines.append(f"  note     : {_one_line(str(verdict['note']))}")
    return "\n".join(lines) + "\n"
