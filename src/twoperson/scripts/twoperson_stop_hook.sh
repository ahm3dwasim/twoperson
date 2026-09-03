#!/bin/sh
# Claude Code `Stop` hook -> one completion SIGNAL in the durable Reviewer inbox.
#
# A signal says "a Builder session finished here, and this is whether a review packet was waiting
# when it did". It is NOT the review packet: it asserts nothing about the work, and it does not
# satisfy the audit gate. Reviewer still claims and audits packets
# (`python -m twoperson check && python -m twoperson next`).
# Runbook: docs/PROTOCOL.md §5.
#
# This script ALWAYS exits 0. Claude Code reads exit code 2 from a Stop hook as "block stopping"
# and feeds stderr back to the model, so a failing bridge could trap a session in a loop. A missed
# signal is a cheap, recoverable failure (Reviewer also polls); a wedged session is not.
#
# Environment (all optional):
#   CLAUDE_PROJECT_DIR      set by Claude Code; the checkout to signal from
#   TWOPERSON_PYTHON   interpreter override (the tests use it; so can a non-standard venv)
#   TWOPERSON_INBOX      inbox root override, as everywhere else in the bridge
set -u

# Claude Code sets CLAUDE_PROJECT_DIR for hooks. Run by hand, fall back to the CWD — the script
# now ships inside the installed package, so its own location says nothing about which repo you are
# in, and guessing from $0 would signal the wrong inbox.
root="${CLAUDE_PROJECT_DIR:-$PWD}"
cd "$root" 2>/dev/null || exit 0

py="${TWOPERSON_PYTHON:-}"
if [ -z "$py" ]; then
	# A linked `git worktree` usually has no `.venv` of its own: the venv lives in the main
	# checkout, which is the parent of the shared git dir. Try this checkout, then that one.
	main_root=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || main_root=""
	main_root=${main_root%/.git}
	for candidate in "$root/.venv/bin/python" "$main_root/.venv/bin/python"; do
		if [ -x "$candidate" ]; then
			py="$candidate"
			break
		fi
	done
	[ -n "$py" ] || py=python3
fi

# stdin carries the Claude Code hook payload (session_id etc.); the CLI reads it if it is piped.
"$py" -m twoperson signal --hook-stdin --source claude-code-stop-hook >/dev/null 2>&1 || true
exit 0
