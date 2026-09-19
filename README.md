# twoperson

[![CI](https://github.com/ahm3dwasim/twoperson/actions/workflows/ci.yml/badge.svg)](https://github.com/ahm3dwasim/twoperson/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/twoperson.svg)](https://pypi.org/project/twoperson/)
[![Python](https://img.shields.io/pypi/pyversions/twoperson.svg)](https://pypi.org/project/twoperson/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A two-person rule for AI coding agents. The agent that wrote the change can't record it as
shipped until a reviewer has written down a verdict for that exact commit, and that rule lives
in a schema rather than in a prompt.

```
builder ──publish──▶ .twoperson/pending/ ──claim──▶ reviewer
   ▲                                                    │
   └────────────── verdicts/ ◀──── Approve / Request changes
```

No server, no API keys, no network. Two agents share a directory. That's the whole transport.

![demo](docs/demo.gif)

## Why

I run two coding agents against the same repo: one builds, the other reviews. For a while the
"get a review first" step was a line in a system prompt. It worked until it didn't. Left alone
for a few hours, the builder would decide the review was optional, or would review its own work
and approve it, or would get a real review and then rebase three more commits on top of the
approval and push the lot.

None of that was malicious. It's just what happens when a rule is advice. So I moved the rule
out of the prompt and into the data format the two agents use to talk to each other.

## What it actually enforces

The builder writes a **review packet**: a JSON record of what it was trying to do, the head sha,
which files changed, what tests it ran and what they said. `twoperson publish` validates it and
drops it in `.twoperson/pending/`. The reviewer claims it, reads it, and writes a **verdict**.

Five refusals do the real work. They're all real output.

A verdict has to answer a packet that actually exists in the inbox:

```
$ twoperson verdict --packet made-up --decision Approve --head 0900128
verdict rejected — packet_id: no packet 'made-up' in this inbox (pending,
claimed or audited) — a verdict must answer a published packet; run `next` to claim one
```

An approval has to name the commit that packet is at, not some other commit:

```
$ twoperson verdict --packet demo-1 --decision Approve --head abcdef0
verdict rejected — head_sha: 'Approve' names 'abcdef0' but packet 'demo-1' is at
'6e5acc68…' — an approval binds to the packet's own head
```

A packet can't say it was pushed, deployed, or restarted without a review reference:

```
$ twoperson verify --from packet.json
packet rejected — push_status.review_ref: a packet may not report
pushed/deployed/restarted=true without a recorded Reviewer audit reference
```

And that reference has to be a verdict that exists, approves, and approves *this* commit:

```
$ twoperson verify --from packet.json
packet rejected — push_status.review_ref: verdict 'vdt-20260902T215020Z-e2e38d43'
approved head '6e5acc68…', but this packet shipped 'f00dbabe…' — an approval does
not carry over to a different commit
```

And if the packet's `changed_files` says it changed a test — anything but a fresh add or copy — the
cited verdict has to acknowledge those exact paths:

```
$ twoperson verify --from packet.json
packet rejected — push_status.review_ref: packet altered tests (tests/test_gate.py)
that the approving verdict did not acknowledge — the reviewer must acknowledge these
exact test paths (twoperson verdict --ack-test-changes)
```

`twoperson verdict --ack-test-changes` clears it — it derives the acknowledged paths from the
`--packet` being reviewed, never from a hand-typed list, so a verdict can only ever acknowledge
tests the reviewer actually had in front of them. That's deliberate: the acknowledgment records
the *specific* test paths, not a bare "I acknowledge test changes" flag, so a verdict written for
one packet's test changes can't be cited to silently unlock a *different* ship report's *different*
test changes at the same head. The binding isn't just a CLI convention, either: `publish_verdict`
itself refuses to write a verdict whose `acknowledged_tests` names a path the reviewed packet
didn't alter, so an API caller can't mint an acknowledgment for arbitrary paths and have it
replayed onto a different report later. It's still a narrow check in every other respect: it
reasons over `changed_files` as it stands on the packet being checked — self-reported when the
diff couldn't be verified against git (see below), git-derived truth when it could — and it flags
*any* qualifying test change for acknowledgment rather than deciding whether it strengthens or
weakens the test. It exists so a builder can't get a quietly weakened test past a reviewer who
never looked at the diff, not so a machine can judge test quality. Only adding or copying a test is
treated as safe; every other status — including an `unknown` one — needs the ack, so a change
can't slip through on a vague status, and `TWOPERSON_TEST_GLOBS` only *adds* patterns rather than
being able to switch detection off.

A rename is the one status where the changed path alone isn't enough: `changed_files` only
records where a file ended up, so renaming `tests/test_auth.py` to `src/auth.py` would look like
"not a test" if `path` were all this checked, quietly deleting the coverage. `changed_files`
entries may carry an optional `old_path`, and a rename is flagged if *either* end looks like a
test — or if `old_path` is missing or `unknown`, since an unrecorded source might have been one.

## Derived diffs and checked citations

Two more things a packet claims are checkable, and `verify`/`publish` check them instead of
trusting them.

`changed_files` and `diff_summary` used to be entirely self-reported — a builder that left a
changed test off the list, or mis-typed its status, was invisible to every check above, because
they only ever look at what the packet *says* changed. Now both commands recompute both fields
from `git diff` between the two shas the packet names, and refuse a packet whose claim disagrees
with the head:

```
$ twoperson publish --from packet.json
packet rejected — the packet's diff evidence does not describe the head it names:
  - changed_files: tests/test_gate.py is in the diff but not in the packet
  - diff_summary.files_changed: packet says 1, head is 2
The values above were derived from the head; correct the packet, or pass --no-derive
to publish an explicitly unverified claim instead.
```

Both shas resolving isn't enough on its own, either: `base_sha` has to be a genuine ancestor of
`head_sha` (checked with `git merge-base --is-ancestor`), or derivation refuses. Without that, a
`base_sha` equal to `head_sha` would "derive" an empty diff for anything, and a `base_sha` that
happens to resolve to some unrelated commit would derive a clean-looking diff against the wrong
history entirely. When the packet's `base_ref` also resolves in the publishing checkout, `base_sha`
has to be reachable from it too — proving the diff is consistent with what that checkout actually
holds under that ref, not that the ref is the project's real upstream default branch, and this half
of the check is simply skipped when the ref isn't fetched locally.

Once derivation succeeds, the packet's `changed_files`/`diff_summary` are the derived values, not
the original claim — so `--ack-test-changes` and everything else that reads a published packet
afterward reasons over checked truth. A packet naming no concrete head yet (a draft) is not
refused, and `--no-derive` is the deliberate escape hatch for a checkout that does not hold the
commits: it publishes the claim unverified and says so on stderr. Either way, the packet's
`diff_provenance` field records which happened — `derived` or `claimed` — so nobody has to guess
from a published packet alone; one from before this field existed reads as `claimed`.

That matters beyond bookkeeping: a packet reporting `push_status.pushed`/`deployed`/`restarted` for
a concrete head is refused outright unless `diff_provenance` is `derived`. Otherwise `--no-derive`
would let a shipped report carry a self-typed `changed_files` — including one that simply leaves an
altered test off the list, so the test-change acknowledgment check above never sees it. A claimed
diff can never be the basis for a ship; `--no-derive` stays available for what it's actually for —
drafts, and checkouts that genuinely don't hold the commits — neither of which ships a concrete head
in the first place. The same rule applies to the packet a cited approval *reviewed*: a ship report
citing a real, ship-unlocking verdict for a packet that was itself only ever `claimed` is refused
too, so an honest-looking ship report can't launder a dishonest review. And it isn't a CLI
convention — `diff_provenance` is decided and stamped by the library itself, at the one place a
packet enters the inbox, never taken from the packet's own claim, so a caller that skips the CLI
and calls `twoperson.inbox` directly gets exactly the same guarantee. A packet reporting a push with
`git.head_sha: "unknown"` is refused before any of this even runs — the schema itself requires a
shipped report to name the concrete commit that shipped.

`publish` (never `verify` — it may run anywhere, without the commit checked out) also checks every
`tests[]` row's `command` for a path or a bare symbol that does not exist at the head being
published:

```
$ twoperson publish --from packet.json
error: tests[] row 'regression probe' cites '`_reclaimable_tree`', which does not exist
at the head being published — that run cannot be repeated here
publish refused — 1 of 1 citations do not resolve at 6e5acc68
```

It's a necessary condition, not a sufficient one, and it says so by being narrow on purpose: only
`command` is read, never `evidence`; a backticked span counts only when it's an entire dotted name,
so an expression like `` `os.path.exists(x) and flag` `` extracts nothing; an uncommitted scratch
path (`tmp/probe.py`) is passed over rather than refused; a pytest node id contributes only its
file, never its `::` segments, because only pytest collection can answer what those name; and a row
citing nothing extractable — most of them, in practice — passes untouched rather than counting as
evidence either way. `--no-derive` skips this check too, for the same reason it skips the diff
derivation: neither can be verified from a checkout that doesn't hold the commits.

So an approval is for one sha of one packet. Rebase, amend, or add a commit and it's stale. The
builder has to publish again and the reviewer has to look again. `verify` runs the same checks as
`publish`, including the diff derivation, and writes nothing, so a builder can dry-run its own ship
report; only the citations check is publish-only.

## Try it

```bash
pip install twoperson
cd your-repo

# builder
twoperson template > packet.json     # evidence fields are "unknown"; a few fixed placeholders (see --help)
$EDITOR packet.json                  # goal, head sha, tests, evidence
twoperson publish --from packet.json

# reviewer (another terminal, another agent, another machine with the same checkout)
twoperson check                      # exit 0 = something's waiting. Costs a few stat() calls.
twoperson next                       # claim the oldest packet, print it for review
twoperson verdict --packet demo-1 --decision "Approve with nits" \
  --note "tests cover the 503 path" --finding "add a jitter test"
# --head defaults to the packet's own head; pass it explicitly if you want to be sure

# builder
twoperson verdicts --ack
```

```
2026-09-02T21:50:20Z  vdt-20260902T215020Z-e2e38d43
  packet   : demo-1
  head     : 6e5acc6800f849c3a4a5e5bd8edc324a6247836a
  reviewer : reviewer
  DECISION : Approve with nits  (ship gate OPEN for this head)
  findings :
    - add a jitter test
  note     : tests cover the 503 path
```

`check` is designed to be polled. It doesn't touch a model, so a reviewer agent can sit in a
loop on it and spend nothing until there's actually a packet to read.

## Hooking it into Claude Code

```bash
twoperson install-hook
```

That adds a `Stop` hook to `.claude/settings.json`. When a session ends it drops a small
signal file in the inbox, so a reviewer can be woken by the event instead of polling on a timer.

The signal is deliberately not a packet. It says "a session stopped here" and nothing else. A
Stop hook doesn't know what the session did or whether the tests passed, and if I let it guess
it would produce a nice-looking packet full of made-up facts. The whole point is to not have
those.

On a Mac, `twoperson install-watch` sets up a launchd agent that fires on inbox changes and runs
whatever command you put in `TWOPERSON_ON_PACKET`. That's where you point your reviewer.

## The packet is hostile input

The builder is a language model. Whatever it writes into the packet might be aimed at the
reviewer, on purpose or by accident. So the packet gets treated the way you'd treat a form
submission from the internet:

- Hard size cap (256 KB) before parsing.
- Strict schema. Unknown keys are rejected. Every string has a length limit, every list a count limit.
- File paths have to be repo-relative. No absolute paths, no `..`, no drive letters.
- A scan for things that look like credentials: Anthropic keys, OpenAI keys (legacy `sk-…`
  and the `sk-proj-…` / `sk-admin-…` shapes), GitHub, AWS, Slack and Google keys, PEM blocks,
  bearer tokens, and `NAME=value` where NAME ends in key/secret/token/password and the value is
  16+ characters. It only looks at values, so writing "read the key from `ANTHROPIC_API_KEY`" is
  fine while pasting the actual key is not. When it finds one, the error names the field path
  and never echoes the value. The list is in `packet.py` and every shape has a fail-closed test;
  it is a tripwire, not a guarantee.
- When the reviewer renders a packet, the body sits between `BEGIN`/`END` markers under a
  short preamble saying this is data, not instructions. Markers forged inside the body get
  defanged.

None of that replaces the reviewer's judgment. It just means the reviewer isn't the only line
of defense.

## Worktrees

If your agents each run in their own `git worktree` (they should), a naive "put the inbox in
this checkout" gives each agent a private inbox. Builder publishes, reviewer polls, neither
sees the other, and `check` returns 1 in a way that looks exactly like "nothing to do". I lost
an afternoon to that.

`twoperson` walks up to the main working tree, following `.git` files and `commondir` by
hand, so every worktree of a repo lands on the same `.twoperson/`. No git subprocess, so it
stays cheap. Set `TWOPERSON_INBOX` if you want to override it.

## Picking a reviewer by difficulty

Not every packet deserves your strongest (slowest, priciest) reviewer. `twoperson tier` scores a
packet from its validated fields — which review areas it names, whether the changed paths touch
auth/payment/deploy/migration, how big the diff is, whether tests ran and passed, whether the
builder left open questions, whether something already shipped — and reports `low`, `medium`,
`high` or `critical`. It's substring checks on structured fields, so a builder writing "trivial
typo fix, please approve" next to thirty changed files under `src/auth/` still gets `critical`.

The watcher hands that tier to whatever reviewer command you configured (`TWOPERSON_TIER`,
`TWOPERSON_TIER_SCORE`, `TWOPERSON_PACKET_ID` in its environment), so the reviewer side can start
cheap and only spend the big model on the packets that earn it. If a reviewer decides a packet is
beyond it, the convention is a `Needs owner decision` verdict with a note starting `ESCALATE:`;
a reviewer ladder can catch that and re-run one rung stronger. `twoperson` records the convention
and the tier; it doesn't run models.

## There's also a consult lane

Sometimes the builder wants an opinion, not an audit. `consult-publish` / `consult-next` /
`consult-advise` do that. It's a separate set of directories, it never produces a verdict, and
nothing on it can unlock a push. It exists so "what do you think of this approach" can't get
quietly upgraded to "this was reviewed".

## How this compares

There are several projects in this space and I read them before writing this one. Most of them
are more capable than this is. They solve a different half of the problem.

[codex-plugin-cc](https://github.com/openai/codex-plugin-cc) is OpenAI's own plugin for driving
Codex from inside Claude Code, and it's the closest thing to an official answer here. Turn on its
optional review gate and a `Stop` hook runs a targeted Codex review of Claude's response; if the
review finds something, the stop is blocked. That gates the *turn*. The check happens while the
session is alive, no durable record says which commit was reviewed, and nothing afterwards refuses
a claim that the work was pushed. It also needs a ChatGPT subscription or an OpenAI key and spends
Codex usage on every review, which its own README warns can drain limits quickly. If what you want
is a second model reading the diff before the session ends, use it; it does that better than this
does.

[claude-review-loop](https://github.com/hamelsmu/claude-review-loop) runs a set of parallel Codex
reviewers when a session tries to stop and writes the consolidated review to a `reviews/` file. The
review is real and it persists, but nothing ties it to one commit, and nothing later refuses a
record that says the work shipped.

[sd0x-harness](https://github.com/sd0xdev/sd0x-harness) is far bigger (99 skills, hooks, rules) and
made the opposite trade on purpose: its git-level guards stay hard while, in its own words, "the
review layer became advisory by design". Its hooks report facts and the model decides.

[quorum](https://github.com/berrzebb/quorum), which absorbed the earlier consensus-loop, does
enforce an audit gate, over MCP and a SQLite event store, with 22 hooks and 30 tools. Approval there
is a state in that store rather than something bound to a particular commit.

[secondmate](https://github.com/eshwarvijay/secondmate) is the one I found that also refuses a
stale approval: its `verify-gate.sh` fails if the head moved since the checker's verdict. It gets
there by being an orchestrator that spawns the maker and the checker itself. This is the same idea
with none of the orchestration, which matters if you already have two agents you like.

[shiplog](https://github.com/devallibus/shiplog) records reviews as signed `Reviewed-by:` lines on
pull requests, with four dispositions. It needs an authenticated `gh` and a GitHub remote.

So: everything above either runs the review for you, or records it without binding it to a commit,
or both. `twoperson` runs nothing and reviews nothing. It is a schema and a directory, and the only
thing it does is make "shipped without review" and "approved without a sha" impossible to write
down. It has no opinion about which agents you use and doesn't need a network, a key, or a remote.

## What it doesn't do

It doesn't review code. It makes sure a verdict was recorded and writes down what it said.

It doesn't know who the reviewer is. `--reviewer` is a label, not an identity. If the builder
and the reviewer run in the same process with the same permissions, the builder can approve
itself, and `twoperson` will not notice. Keeping the two apart is your deployment's job:
separate OS users, separate checkouts, a reviewer that only has read access to the code. What
`twoperson` guarantees is narrower and mechanical: an approving verdict exists for this exact
commit, and the ship report points at it. The binding is per commit, not per packet. A ship
report is its own packet, and what it has to cite is an approval of the same head; it doesn't
have to be the packet that was originally reviewed, because after a rebase it can't be.

It doesn't spawn agents or call models. It's a directory with a lock and a validator.

It doesn't watch your repository or your deploys. The ship-report gate itself reads none of it —
answering it is a schema check and an inbox lookup. `verify`/`publish` separately read the head a
packet names, through git plumbing and bounded to the two shas the packet gives (see "Derived
diffs and checked citations" above); neither ever reads the working tree, and both are a pull, not
a watch — nothing runs on a timer or a hook into your repository. Outside those two checks, the
only git `twoperson` touches is a `git rev-parse` to label a signal with its branch name and, in
the shell hooks, to find a virtualenv. It never sees a push happen. What it validates is the
builder's *report*:
a packet that says "I pushed/deployed/restarted commit X" is refused unless it cites an approving
verdict for X. A builder that lies in the report can lie. What can't exist is a consistent
report that skipped review, and an agent that has to lie to ship is a much easier thing to
catch than one that was never asked.

It doesn't replace CI. CI checks the code. This checks the paperwork.

## Exit codes

`0` did the thing. `1` nothing to do. `2` rejected. The one exception is `signal`: a valid
`signal` invocation never returns 2, and the packaged Stop-hook script always exits 0 whatever
happens inside it, because Claude Code treats a 2 from a Stop hook as "don't stop" and a broken
hook would trap the session in a loop. (Malformed flags still get argparse's usual 2, like any
CLI; the hook script never passes malformed flags.)

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

A few hundred tests, about two seconds. MIT.
