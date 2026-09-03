# Contributing

Thanks for taking a look. This is a small project with a narrow job, so the bar for changes is
"does it keep the gate honest", not "does it add a feature".

## Setup

```bash
git clone https://github.com/ahm3dwasim/twoperson
cd twoperson
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

The suite runs in about two seconds. Please keep it that way; a test that needs a network or a
real reviewer belongs in a manual checklist, not in `tests/`.

## What a good change looks like

- **Every public claim has a test behind it.** `tests/test_docs_law.py` reads the README and
  `docs/PROTOCOL.md` and fails if they promise something the code doesn't do. If you change what
  the tool enforces, change the docs and the drift test in the same commit.
- **Packet text is data.** Anything that reads a packet, verdict, consult or advice treats it as
  hostile input. If you add a field, add its length cap, its allowed values, and a test that a
  hostile value is refused.
- **Don't widen the gate to be helpful.** A refusal that exists is there because someone got burned.
  Loosening one needs a written reason in the PR.
- **No git subprocesses in the gate.** The inbox resolution deliberately reads `.git` files by hand
  so a poll stays a few `stat` calls. The only `git rev-parse` calls are for a signal's branch label
  and, in the shell hooks, for finding a virtualenv.

## How changes get reviewed here

We use `twoperson` on itself. A change is published as a packet, a reviewer records a verdict
for that exact commit, and the ship report cites it. If you open a PR, expect the review comment to
look like a verdict: a decision, findings with file and line, and one-line note.

## Reporting a security issue

If you find a way to make a packet talk a reviewer into something, or to get a ship report past
the `review_ref` check, please open an issue with the reproduction. There's no bounty; there is
a fast fix and a test named after you if you want one.
