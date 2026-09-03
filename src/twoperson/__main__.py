"""The explicit launcher for the Builder->Reviewer handoff bridge.

    python -m twoperson template                 # a skeleton packet: evidence `unknown`, fixed placeholders
    python -m twoperson verify   --from p.json   # validate only; writes nothing
    python -m twoperson publish  --from p.json   # Builder, at completion: emit the packet
    python -m twoperson check                    # Reviewer: is a PACKET waiting? (0=yes, 1=no)
    python -m twoperson list                     # what is waiting
    python -m twoperson tier                     # difficulty tier of the oldest packet (no claim)
    python -m twoperson next                     # claim + render the oldest packet
    python -m twoperson signal                   # emit a completion signal (the Stop hook)
    python -m twoperson signals --ack            # Reviewer: which sessions finished?
    python -m twoperson verdict  --packet <id> --decision Approve   # Reviewer: return the audit result
    python -m twoperson verdicts --ack           # Builder: read the audit verdicts Reviewer returned

    python -m twoperson consult-template          # a skeleton consult (advisory question)
    python -m twoperson consult-verify  --from c.json  # validate only; writes nothing
    python -m twoperson consult-publish --from c.json  # Builder: ask Reviewer to advise (gates nothing)
    python -m twoperson consult-check             # Reviewer: is a CONSULT waiting? (0=yes, 1=no)
    python -m twoperson consult-list              # what advisory questions are waiting
    python -m twoperson consult-next              # claim + render the oldest consult
    python -m twoperson consult-advise --consult <id> --recommendation "..."  # Reviewer: return counsel
    python -m twoperson consult-advice --ack      # Builder: read the advice Reviewer returned
    python -m twoperson install-hook             # install the Stop hook into settings.json
    python -m twoperson watch --once             # react to inbox changes: notify both sides + launch
    python -m twoperson watch --off / --on       # master mute switch (both sides); --status prints it
    python -m twoperson install-watch            # install the launchd agent that fires the watcher

`--from -` reads the packet from stdin.

**The packet command is still the gate.** `publish` is the only way a change becomes auditable, and
its schema is what refuses a ship report that lacks an approving verdict for its commit. The `signal` command added alongside it
does strictly less: it announces that a session stopped, so Reviewer can be woken by an event instead
of a timer. The `consult-*` commands are a **parallel, non-gating** lane: a consult asks Reviewer to
*advise*, not to *audit*, so it never enters `pending/`, `consult-advise` returns counsel rather than
a verdict, and nothing on the consult lane unlocks a push. The audit gate is untouched by all of it. A signal never becomes a packet, is never listed by `check`/`list`/`next`, and asserts
nothing about the work — a hook has none of the facts a packet must carry, and inventing them would
produce a confident, unverified brief. See `src/twoperson/hook.py` for the tracked mechanism.

Exit codes are the whole machine-facing contract: **0** success, **1** nothing to do (empty inbox,
or `install-hook --check` finding no hook), **2** the packet or the arguments were rejected.
`signal` is the exception that proves the rule: a valid invocation never returns 2, because Claude Code reads a 2
from a Stop hook as "block stopping" and would trap the session. `check` is deliberately free to
poll — it lists a directory and spends no tokens, which is what makes the handoff event-driven
rather than a conversation.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import structlog

from . import inbox
from .hook import HookInstallError, hook_script_path, install_hook
from .packet import PacketError, dumps_packet, loads_packet, render_for_review, template_packet
from .watch import DEFAULT_INTERVAL_SECONDS, dispatch_once, is_muted, set_muted, watch_loop
from .watchagent import WatchInstallError, install_watch_agent, watch_script_path
from .signal import (
    MAX_HOOK_PAYLOAD_BYTES,
    build_signal,
    render_signal,
    session_id_from_hook_payload,
)
from .verdict import DECISIONS, build_verdict, render_verdict
from .consult import (
    AREAS,
    build_consult,
    dumps_consult,
    loads_consult,
    render_for_consult,
    template_consult,
)
from .advice import CONFIDENCES, build_advice, render_advice

SUBCOMMANDS = frozenset({
    "template", "verify", "publish", "check", "list", "next", "tier", "signal", "signals",
    "verdict", "verdicts", "install-hook", "watch", "install-watch",
    "consult-template", "consult-verify", "consult-publish", "consult-check", "consult-list",
    "consult-next", "consult-advise", "consult-advice",
})

EXIT_OK = 0
EXIT_NOTHING = 1
EXIT_REJECTED = 2


def _read_source(source: str) -> str:
    """Packet bytes from a file or stdin. Raises PacketError so the caller has one failure mode."""
    if source == "-":
        return sys.stdin.read()
    try:
        return Path(source).read_text(encoding="utf-8")
    except OSError as exc:
        raise PacketError(f"cannot read packet from {source}: {exc.strerror or exc}") from exc


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return EXIT_REJECTED


class _LateBoundStderr:
    """A write proxy that resolves ``sys.stderr`` on every call, never at configure time.

    `structlog.configure` is process-global and sticky, so capturing the *current* `sys.stderr`
    object would pin whatever stream happened to be installed at the first `main()` call — under
    pytest that is a per-test capture buffer, which is closed by the time the next test logs.
    """

    def write(self, text: str) -> int:
        return sys.stderr.write(text)

    def flush(self) -> None:
        sys.stderr.flush()

    def isatty(self) -> bool:
        return sys.stderr.isatty()


def _logs_to_stderr() -> None:
    """Keep stdout a machine-readable channel.

    The repo never calls `structlog.configure`, so structlog's default `PrintLogger` writes to
    **stdout** — which would interleave `twoperson.published` lines into `next --json` and
    `list` output and break any consumer piping them. Owning the stdout contract is the
    entrypoint's job, so the redirect lives here and not in the library modules.
    """
    structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=_LateBoundStderr()))


def _hook_payload() -> str:
    """The Claude Code hook payload, bounded. Empty when nothing is piped: never blocks on a tty."""
    if sys.stdin is None or sys.stdin.isatty():
        return ""
    try:
        return sys.stdin.read(MAX_HOOK_PAYLOAD_BYTES)
    except OSError:
        return ""


def _emit_signal(args) -> int:
    """`signal`: announce that a session finished. Returns 0 or 1 — never the rejection code.

    The Stop hook runs this. Claude Code reads a 2 from a Stop hook as "block stopping" and feeds
    stderr back to the model, so this path degrades (unknown fields, a printed warning, exit 1)
    where every other subcommand would reject.
    """
    session_id = args.session_id
    if args.hook_stdin and not session_id:
        session_id = session_id_from_hook_payload(_hook_payload())
    try:
        signal = build_signal(
            source=args.source,
            session_id=session_id if session_id is not None else "unknown",
            packet_pending=inbox.has_pending(),
            note=args.note,
        )
        path = inbox.publish_signal(signal)
    except (PacketError, OSError) as exc:
        print(f"signal not emitted — {exc}", file=sys.stderr)
        return EXIT_NOTHING
    print(str(path))
    return EXIT_OK


def _report_signals(args) -> int:
    """`signals`: what finished since the last look. Exit 1 when nothing has — same probe contract.

    Acknowledging is deliberately a separate flag: reading the lane must stay a safe, repeatable
    operation, and only an auditor that has actually taken the signals should clear them.
    """
    found = inbox.read_signals()
    if not found:
        return EXIT_NOTHING
    for _path, signal in found:
        print(json.dumps(signal, indent=2, sort_keys=True, ensure_ascii=False) if args.as_json
              else render_signal(signal))
    if args.ack:
        # Ack only the signals we just read — never a re-scan, so a signal arriving between this
        # read and the ack is not swept out of the waiting lane unseen.
        inbox.ack_signals([path for path, _ in found])
    return EXIT_OK


def _emit_verdict(args) -> int:
    """`verdict`: Reviewer writes an audited decision back to the inbox (the return leg).

    Unlike `signal`, this is invoked by hand, not by a Stop hook, so a rejected argument returns the
    normal rejection code. It writes nothing on a bad decision or a token-shaped finding — the
    schema validates before the tree is touched, exactly like `publish`.
    """
    try:
        head = args.head
        if head is None:
            # No --head: bind to the packet's own head rather than guessing. If the packet does not
            # exist, publish_verdict will say so; keep the sentinel so the schema path is unchanged.
            found = inbox.find_packet(args.packet)
            head = found[2]["git"]["head_sha"] if found else "unknown"
        verdict = build_verdict(
            packet_id=args.packet,
            decision=args.decision,
            head_sha=head,
            reviewer=args.reviewer,
            findings=args.finding or [],
            note=args.note,
            acknowledges_test_changes=args.ack_test_changes,
        )
        path = inbox.publish_verdict(verdict)
    except (PacketError, OSError) as exc:
        return _fail(f"verdict rejected — {exc}")
    print(str(path))
    return EXIT_OK


def _report_verdicts(args) -> int:
    """`verdicts`: what Reviewer has answered since the last look. Exit 1 when nothing has.

    Reading is a safe, repeatable probe; only `--ack` clears the lane, and only after the manager
    has actually taken the verdicts. Reading a verdict does not ship anything — the manager still
    checks the decision and that the head is current before it acts.
    """
    found = inbox.read_verdicts()
    if not found:
        return EXIT_NOTHING
    for _path, verdict in found:
        if args.as_json:
            print(json.dumps(verdict, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(render_verdict(verdict), end="")  # render already ends with a newline
    if args.ack:
        # Ack exactly the verdicts we just read — never a re-scan, so a verdict that arrives between
        # this read and the ack is not swept out of sight unseen.
        inbox.ack_verdicts([path for path, _ in found])
    return EXIT_OK


def _emit_consult(args) -> int:
    """`consult-advise`: Reviewer writes advisory counsel back to the inbox (the advisory return leg).

    Invoked by hand, not by a hook, so a rejected argument returns the normal rejection code. It
    writes nothing on a bad field or a token-shaped value — the schema validates before the tree is
    touched, exactly like `publish` and `verdict`. Advice gates nothing, so there is no head to bind.
    """
    try:
        advice = build_advice(
            consult_id=args.consult,
            recommendation=args.recommendation,
            reviewer=args.reviewer,
            rationale=args.rationale,
            considerations=args.consideration or [],
            beyond_the_ask=args.beyond or [],
            references=args.reference or [],
            confidence=args.confidence,
            note=args.note,
        )
        path = inbox.publish_advice(advice)
    except (PacketError, OSError) as exc:
        return _fail(f"advice rejected — {exc}")
    print(str(path))
    return EXIT_OK


def _report_advice(args) -> int:
    """`consult-advice`: what counsel Reviewer has returned since the last look. Exit 1 when nothing has.

    Reading is a safe, repeatable probe; only `--ack` clears the lane, and only after the manager has
    actually taken the advice. Reading advice ships nothing — advice is counsel the manager weighs,
    never a grant.
    """
    found = inbox.read_advice()
    if not found:
        return EXIT_NOTHING
    for _path, advice in found:
        if args.as_json:
            print(json.dumps(advice, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(render_advice(advice), end="")  # render already ends with a newline
    if args.ack:
        # Ack exactly the advice we just read — never a re-scan, so an answer that arrives between
        # this read and the ack is not swept out of sight unseen.
        inbox.ack_advice([path for path, _ in found])
    return EXIT_OK


def _install_hook(args) -> int:
    """`install-hook`: merge the tracked Stop hook into a settings file (or report on it)."""
    script = hook_script_path()
    if not script.exists():
        return _fail(f"install-hook failed — tracked hook script missing: {script}")
    try:
        result = install_hook(args.settings, check=args.check)
    except HookInstallError as exc:
        return _fail(f"install-hook failed — {exc}")
    print(f"{result.status}: {result.path}")
    return EXIT_OK if result.ok else EXIT_NOTHING


def _watch(args) -> int:
    """`watch`: react to inbox changes — notify both sides, and launch the configured audit/wake.

    `--on`/`--off` flip the master mute switch (and `--status` reports it): while OFF, no pass
    notifies or launches anything, for either side, and nothing is skipped — items that arrive while
    muted are announced when it is turned back on. `--once` is a single pass (what launchd's
    WatchPaths runs on each change); the default is a foreground poll loop for a manual/tmux run.
    Notify-only unless the launch commands are configured (TWOPERSON_ON_PACKET /
    TWOPERSON_ON_VERDICT). It never claims, audits, or ships — it wakes the side that does.
    """
    if args.off or args.on:
        muted = set_muted(args.off)  # --off mutes, --on un-mutes
        if muted:
            print("watch: OFF (muted — no notifications or auto-audit)")
            return EXIT_OK
        # Un-muted: immediately run a catch-up pass so work that arrived while muted is announced NOW,
        # not whenever the next unrelated lane change happens to wake the agent. This makes un-mute
        # actually resume in every mode (CLI toggle, launchd, loop), honouring "pause, not skip".
        report = dispatch_once()
        print("watch: ON" + (" — catching up" if report.acted else ""))
        for side in report.notified:
            print(f"notified: {side}")
        for side in report.launched:
            print(f"launched: {side}")
        return EXIT_OK
    if args.status:
        print(f"watch: {'OFF (muted)' if is_muted() else 'ON'}")
        return EXIT_OK
    if args.once:
        report = dispatch_once()
        if report.muted:
            print("watch: OFF (muted) — no action")
            return EXIT_OK
        for side in report.notified:
            print(f"notified: {side}")
        for side in report.launched:
            print(f"launched: {side}")
        if not report.acted:
            print("watch: nothing new")
        return EXIT_OK
    print(f"watch: polling the inbox every {args.interval:g}s (Ctrl-C to stop)", file=sys.stderr)
    watch_loop(interval=args.interval)
    return EXIT_OK


def _install_watch(args) -> int:
    """`install-watch`: install the launchd agent that fires the watcher on every inbox change."""
    script = watch_script_path()
    if not script.exists():
        return _fail(f"install-watch failed — tracked watch script missing: {script}")
    try:
        result = install_watch_agent(check=args.check, reload=not args.no_reload)
    except WatchInstallError as exc:
        return _fail(f"install-watch failed — {exc}")
    loaded = " (launchctl loaded)" if result.loaded else ""
    print(f"{result.status}: {result.path}{loaded}")
    return EXIT_OK if result.ok else EXIT_NOTHING


def main(argv: list[str] | None = None) -> int:
    _logs_to_stderr()
    parser = argparse.ArgumentParser(
        prog="twoperson",
        description="Durable Builder->Reviewer review-packet bridge (docs/PROTOCOL.md).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("template", help="print a skeleton packet: evidence fields 'unknown'; fixed placeholders for "
                                    "schema_version, packet_id (replace-me), created_at (epoch), base_ref (origin/main), "
                                    "acceptance_criteria (['unknown']) and false push flags")
    for name, help_text in (("verify", "validate a packet without publishing it"),
                            ("publish", "validate and atomically publish a packet to the inbox")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--from", dest="source", required=True,
                       help="path to the packet JSON, or '-' for stdin")
    sub.add_parser("check", help="exit 0 if a packet is waiting, 1 if not (cheap event probe)")
    sub.add_parser("list", help="list pending packets, oldest first")
    tier = sub.add_parser("tier", help="difficulty tier of the oldest pending packet (or --packet ID); "
                                       "reads without claiming; exit 1 if nothing is pending")
    tier.add_argument("--packet", default=None, help="a packet id anywhere in pending/claimed/audited")
    nxt = sub.add_parser("next", help="claim and render the oldest pending packet")
    nxt.add_argument("--peek", action="store_true", help="render without claiming")
    nxt.add_argument("--json", dest="as_json", action="store_true",
                     help="emit the raw packet JSON instead of the review rendering")

    sig = sub.add_parser("signal", help="emit a completion signal (NOT a review packet)")
    sig.add_argument("--hook-stdin", action="store_true",
                     help="read the Claude Code hook payload from stdin (used by the Stop hook)")
    sig.add_argument("--source", default="manual",
                     help="'claude-code-stop-hook' or 'manual' (anything else becomes 'manual')")
    sig.add_argument("--session-id", default=None, help="session id, when not read from the hook")
    sig.add_argument("--note", default=None, help="one short line of context")

    sigs = sub.add_parser("signals", help="list completion signals, oldest first")
    sigs.add_argument("--ack", action="store_true",
                      help="acknowledge the listed signals (move them out of the waiting lane)")
    sigs.add_argument("--json", dest="as_json", action="store_true",
                      help="emit the raw signal JSON instead of one line each")

    vdt = sub.add_parser("verdict", help="Reviewer: write an audited decision back to the inbox")
    vdt.add_argument("--packet", required=True, help="the packet_id this verdict audits")
    vdt.add_argument("--decision", required=True, choices=sorted(DECISIONS),
                     help="the protocol §4 outcome (only Approve/'Approve with nits' unlock ship)")
    vdt.add_argument("--head", default=None,
                     help="the head sha audited (default: the packet's own head); an approval must "
                          "match the packet's head exactly")
    vdt.add_argument("--reviewer", default="reviewer", help="who audited (default: reviewer)")
    vdt.add_argument("--finding", action="append", default=None, metavar="TEXT",
                     help="a finding; repeatable for several")
    vdt.add_argument("--note", default=None, help="one free-text summary line")
    vdt.add_argument("--ack-test-changes", dest="ack_test_changes", action="store_true",
                     help="acknowledge that the packet altered a test file (required for "
                          "Approve/'Approve with nits' on a packet whose changed_files modifies, "
                          "deletes, or renames a test — see docs/PROTOCOL.md)")

    vdts = sub.add_parser("verdicts", help="Builder: read audit verdicts Reviewer has returned")
    vdts.add_argument("--ack", action="store_true",
                      help="acknowledge the listed verdicts (move them out of the waiting lane)")
    vdts.add_argument("--json", dest="as_json", action="store_true",
                      help="emit the raw verdict JSON instead of the rendering")

    sub.add_parser("consult-template",
                   help="print a skeleton consult (advisory question) to fill in and publish")
    for name, help_text in (("consult-verify", "validate a consult without publishing it"),
                            ("consult-publish", "validate and atomically publish a consult to Reviewer")):
        cp = sub.add_parser(name, help=help_text)
        cp.add_argument("--from", dest="source", required=True,
                        help="path to the consult JSON, or '-' for stdin")
    sub.add_parser("consult-check",
                   help="exit 0 if a consult is waiting for Reviewer, 1 if not (cheap event probe)")
    sub.add_parser("consult-list", help="list pending consults, oldest first")
    cnx = sub.add_parser("consult-next", help="claim and render the oldest pending consult")
    cnx.add_argument("--peek", action="store_true", help="render without claiming")
    cnx.add_argument("--json", dest="as_json", action="store_true",
                     help="emit the raw consult JSON instead of the advisory rendering")

    adv = sub.add_parser("consult-advise", help="Reviewer: write advisory counsel back to the inbox")
    adv.add_argument("--consult", required=True, help="the consult_id this advice answers")
    adv.add_argument("--recommendation", required=True, help="the headline advice (required)")
    adv.add_argument("--rationale", default=None, help="why — one paragraph of reasoning")
    adv.add_argument("--consideration", action="append", default=None, metavar="TEXT",
                     help="a caveat or point to weigh; repeatable for several")
    adv.add_argument("--beyond", action="append", default=None, metavar="TEXT",
                     help="something NOT in the asker's proposed discussion — a future consequence, "
                          "out-of-the-box option, or blind spot; repeatable for several")
    adv.add_argument("--reference", action="append", default=None, metavar="TEXT",
                     help="a file/doc/PR the advice cites; repeatable for several")
    adv.add_argument("--confidence", default="unknown", choices=sorted(CONFIDENCES),
                     help="how firm the recommendation is (advisory only — unlocks nothing)")
    adv.add_argument("--reviewer", default="reviewer", help="who advised (default: reviewer)")
    adv.add_argument("--note", default=None, help="one free-text summary line")

    advs = sub.add_parser("consult-advice", help="Builder: read advisory counsel Reviewer has returned")
    advs.add_argument("--ack", action="store_true",
                      help="acknowledge the listed advice (move it out of the waiting lane)")
    advs.add_argument("--json", dest="as_json", action="store_true",
                      help="emit the raw advice JSON instead of the rendering")

    hook = sub.add_parser("install-hook", help="install the Stop hook into a Builder settings file")
    hook.add_argument("--settings", default=None,
                      help="target settings.json (default: <repo>/.claude/settings.json)")
    hook.add_argument("--check", action="store_true",
                      help="report whether the hook is installed and current; write nothing")

    wat = sub.add_parser("watch", help="react to inbox changes: notify both sides + launch the audit")
    wat.add_argument("--once", action="store_true",
                     help="one pass then exit (what launchd's WatchPaths runs on each change)")
    wat.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS,
                     help="poll cadence in seconds for the foreground loop (ignored with --once)")
    wat_sw = wat.add_mutually_exclusive_group()
    wat_sw.add_argument("--off", action="store_true",
                        help="MUTE the watcher: no notifications or auto-audit until turned back on")
    wat_sw.add_argument("--on", action="store_true",
                        help="un-mute the watcher (resume notifications + auto-audit)")
    wat_sw.add_argument("--status", action="store_true",
                        help="print whether the watcher is ON or OFF; change nothing")

    iwat = sub.add_parser("install-watch",
                          help="install the launchd agent that fires the watcher on every inbox change")
    iwat.add_argument("--check", action="store_true",
                      help="report whether the agent is installed and current; write nothing")
    iwat.add_argument("--no-reload", action="store_true",
                      help="write the plist but do not launchctl (re)load it")

    args = parser.parse_args(argv)

    if args.cmd == "template":
        print(dumps_packet(template_packet()), end="")
        return EXIT_OK

    if args.cmd in ("verify", "publish"):
        try:
            raw = _read_source(args.source)
            packet = loads_packet(raw)
        except PacketError as exc:
            return _fail(f"packet rejected — {exc}")
        if args.cmd == "verify":
            # Resolve a push's review_ref against the inbox too: `verify` is the dry run of
            # `publish`, so it must fail for every reason `publish` would. It still writes nothing.
            try:
                inbox.assert_review_ref_resolves(packet)
            except PacketError as exc:
                return _fail(f"packet rejected — {exc}")
            print(f"ok: packet {packet['packet_id']} is valid (nothing was written)")
            return EXIT_OK
        try:
            path = inbox.publish(packet)
        except (PacketError, OSError) as exc:
            return _fail(f"publish failed — {exc}")
        print(str(path))
        return EXIT_OK

    if args.cmd == "check":
        return EXIT_OK if inbox.has_pending() else EXIT_NOTHING

    if args.cmd == "list":
        for path in inbox.pending():
            print(path)
        return EXIT_OK

    if args.cmd == "tier":
        from .tier import classify_packet
        if args.packet:
            found = inbox.find_packet(args.packet)
            if found is None:
                return _fail(f"no packet {args.packet!r} in this inbox")
            packet = found[2]
        else:
            peeked = inbox.peek_next()
            if peeked is None:
                return EXIT_NOTHING
            packet = peeked.packet
        cls = classify_packet(packet)
        print(json.dumps({"packet_id": packet["packet_id"], "tier": cls.tier, "score": cls.score,
                          "reasons": list(cls.reasons)}))
        return EXIT_OK

    if args.cmd == "signal":
        return _emit_signal(args)

    if args.cmd == "signals":
        return _report_signals(args)

    if args.cmd == "verdict":
        return _emit_verdict(args)

    if args.cmd == "verdicts":
        return _report_verdicts(args)

    if args.cmd == "consult-template":
        print(dumps_consult(template_consult()), end="")
        return EXIT_OK

    if args.cmd in ("consult-verify", "consult-publish"):
        try:
            raw = _read_source(args.source)
            consult = loads_consult(raw)
        except PacketError as exc:
            return _fail(f"consult rejected — {exc}")
        if args.cmd == "consult-verify":
            print(f"ok: consult {consult['consult_id']} is valid (nothing was written)")
            return EXIT_OK
        try:
            path = inbox.publish_consult(consult)
        except (PacketError, OSError) as exc:
            return _fail(f"consult publish failed — {exc}")
        print(str(path))
        return EXIT_OK

    if args.cmd == "consult-check":
        return EXIT_OK if inbox.has_pending_consults() else EXIT_NOTHING

    if args.cmd == "consult-list":
        for path in inbox.pending_consults():
            print(path)
        return EXIT_OK

    if args.cmd == "consult-next":
        found = inbox.peek_consult() if args.peek else inbox.claim_consult()
        if found is None:
            return EXIT_NOTHING
        if args.as_json:
            print(json.dumps(found.packet, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(render_for_consult(found.packet), end="")
        return EXIT_OK

    if args.cmd == "consult-advise":
        return _emit_consult(args)

    if args.cmd == "consult-advice":
        return _report_advice(args)

    if args.cmd == "install-hook":
        return _install_hook(args)

    if args.cmd == "watch":
        return _watch(args)

    if args.cmd == "install-watch":
        return _install_watch(args)

    # next
    found = inbox.peek_next() if args.peek else inbox.claim_next()
    if found is None:
        return EXIT_NOTHING
    if args.as_json:
        print(json.dumps(found.packet, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(render_for_review(found.packet), end="")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
