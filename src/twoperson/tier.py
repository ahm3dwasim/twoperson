"""Difficulty tiers: pick a reviewer by how hard a packet is, without asking a model.

The builder is a language model, so the packet's prose cannot be trusted to say how risky the
change is. What can be trusted is the *shape* the schema already validated: which review areas were
named, which paths changed, how big the diff is, whether tests ran and passed, whether the builder
left open questions, whether something has already shipped. `classify_packet` turns that shape into
one of four tiers using substring checks only, so a packet cannot talk its way down a tier.

`twoperson` does not run reviewers, so it does not map tiers to models. It exposes the tier two
ways: the `tier` subcommand (peek, never claim), and `TWOPERSON_TIER` / `TWOPERSON_TIER_SCORE` /
`TWOPERSON_PACKET_ID` in the environment of the reviewer command the watcher launches. A reviewer
that wants to escalate records a `Needs owner decision` verdict whose note begins `ESCALATE:`; the
convention is documented in `docs/PROTOCOL.md` so a stronger reviewer can be assigned by whatever
runs the reviewer side.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

__all__ = ["ESCALATE_PREFIX", "HEAVY_MARKERS", "TIERS", "Classification", "classify_packet",
           "classify_consult", "is_escalation", "tier_env"]

Tier = Literal["low", "medium", "high", "critical"]
TIERS: tuple[Tier, ...] = ("low", "medium", "high", "critical")

#: A verdict of ``Needs owner decision`` whose note begins with this is a reviewer saying "assign a
#: stronger reviewer", not "the owner must decide" — the decision is protocol-legal either way.
ESCALATE_PREFIX = "ESCALATE:"

#: Words in a review area or a changed path that mark a change as one where a wrong approval is
#: expensive. Case-insensitive substrings; extend for your project, never shorten for a packet.
HEAVY_MARKERS: tuple[str, ...] = (
    "security", "auth", "credential", "secret", "vault", "payment", "billing", "deploy",
    "migration", "infra", "delete", "policy", "routing", "release", "kernel",
)


@dataclass(frozen=True)
class Classification:
    tier: Tier
    score: int
    reasons: tuple[str, ...]


def _tier_for(score: int) -> Tier:
    if score >= 9:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _heavy(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in HEAVY_MARKERS)


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def classify_packet(packet: Mapping[str, Any]) -> Classification:
    """Score a review packet from its validated fields. Pure; the same packet always scores the same."""
    score = 0
    reasons: list[str] = []

    areas = [str(a) for a in packet.get("review_areas", []) or []]
    if any(_heavy(a) for a in areas):
        score += 3
        reasons.append("review area touches a heavy surface (+3)")

    files = packet.get("changed_files", []) or []
    paths = [str(f.get("path", "")) for f in files if isinstance(f, Mapping)]
    if any(_heavy(p) for p in paths):
        score += 2
        reasons.append("changed path touches a heavy surface (+2)")
    if len(paths) > 25:
        score += 2
        reasons.append(f"{len(paths)} files changed (+2)")
    elif len(paths) > 8:
        score += 1
        reasons.append(f"{len(paths)} files changed (+1)")

    diff = packet.get("diff_summary", {}) or {}
    ins, dels = _int_or_none(diff.get("insertions")), _int_or_none(diff.get("deletions"))
    if ins is None or dels is None:
        score += 1
        reasons.append("diff size unknown (+1)")
    elif ins + dels > 800:
        score += 2
        reasons.append(f"{ins + dels} lines changed (+2)")
    elif ins + dels > 200:
        score += 1
        reasons.append(f"{ins + dels} lines changed (+1)")

    tests = packet.get("tests", []) or []
    failed = sum(1 for t in tests if isinstance(t, Mapping) and t.get("result") == "failed")
    unrun = sum(1 for t in tests if isinstance(t, Mapping) and t.get("result") in ("not_run", "skipped"))
    if failed:
        score += min(2, failed)
        reasons.append(f"{failed} failed test(s) (+{min(2, failed)})")
    if unrun or not tests:
        score += 1
        reasons.append("tests not run or not stated (+1)")

    if packet.get("open_questions"):
        score += 1
        reasons.append("open questions for the reviewer (+1)")
    if len(packet.get("tradeoffs", []) or []) > 2:
        score += 1
        reasons.append("several stated tradeoffs (+1)")

    push = packet.get("push_status", {}) or {}
    if push.get("pushed") or push.get("deployed") or push.get("restarted"):
        score += 2
        reasons.append("ship report: something already moved (+2)")

    return Classification(tier=_tier_for(score), score=score, reasons=tuple(reasons))


def classify_consult(consult: Mapping[str, Any]) -> Classification:
    """Consults gate nothing, so they start low and never reach ``critical``."""
    score = 0
    reasons: list[str] = []
    area = str(consult.get("area", "unknown"))
    if area in ("architecture", "product-direction"):
        score += 3
        reasons.append(f"area {area} (+3)")
    elif area == "evidence-metrics":
        score += 2
        reasons.append("area evidence-metrics (+2)")
    question = str(consult.get("question", ""))
    if _heavy(question):
        score += 2
        reasons.append("question touches a heavy surface (+2)")
    if len(question) > 1500:
        score += 1
        reasons.append("long question (+1)")
    if len(consult.get("options", []) or []) > 3:
        score += 1
        reasons.append("many options to weigh (+1)")
    return Classification(tier=_tier_for(min(score, 8)), score=score, reasons=tuple(reasons))


def is_escalation(decision: str, note: str | None) -> bool:
    return decision == "Needs owner decision" and bool(note) and note.lstrip().startswith(ESCALATE_PREFIX)


def tier_env(packet: Mapping[str, Any]) -> dict[str, str]:
    """The environment a reviewer command receives from the watcher: tier, score, packet id.
    Values are short slugs/ints only — never packet prose — so nothing here can carry an injection
    into a shell command."""
    cls = classify_packet(packet)
    packet_id = str(packet.get("packet_id", "unknown"))
    safe_id = "".join(ch for ch in packet_id if ch.isalnum() or ch in "._-")[:64] or "unknown"
    return {"TWOPERSON_TIER": cls.tier, "TWOPERSON_TIER_SCORE": str(cls.score),
            "TWOPERSON_PACKET_ID": safe_id}
