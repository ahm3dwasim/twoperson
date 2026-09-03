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

## Why I built it

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

Four refusals do the real work. They're all real output.

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

So an approval is for one sha of one packet. Rebase, amend, or add a commit and it's stale. The
builder has to publish again and the reviewer has to look again. `verify` runs the same checks as
`publish` and writes nothing, so a builder can dry-run its own ship report.

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

There are a few projects in this space and I looked at them before writing this one.

[claude-review-loop](https://github.com/hamelsmu/claude-review-loop) runs Codex on Claude's
work from a slash command. It writes each review to a `reviews/` file, and its Stop hook asks for
a Codex pass once the loop is invoked (failing open if the review can't be produced). What it
doesn't have is a sha-bound approval or a ship-report binding: nothing ties "reviewed" to one
commit, and nothing refuses a "shipped" record that lacks one.
[sd0x-harness](https://github.com/sd0xdev/sd0x-harness) is much bigger (skills, agents,
hooks) and puts its hard gates at the git level with review as a reminder layer.
[quorum](https://github.com/berrzebb/quorum) does enforce an audit gate, over MCP and SQLite,
with a lot more machinery. [shiplog](https://github.com/devallibus/shiplog) leans on GitHub
branch protection and needs a remote.

`twoperson` is smaller than all of those and does one thing: the schema won't let "shipped
without review" or "approved without a sha" exist. It doesn't care which agents you use or
whether you have a GitHub remote.

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

It doesn't watch your repository or your deploys. Nothing in the gate reads HEAD or the working
tree; the only git it touches is a `git rev-parse` to label a signal with its branch name and, in
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
