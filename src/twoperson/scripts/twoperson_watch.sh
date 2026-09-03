#!/bin/sh
# launchd `WatchPaths` handler -> one inbox watch PASS.
#
# launchd runs this whenever the shared Reviewer inbox lanes change (a packet lands in pending/, a
# verdict lands in verdicts/). One pass notifies BOTH sides and, if a launch command is configured,
# fires it: a new packet wakes the Reviewer/audit side, a new verdict wakes the Builder/manager side.
# Runbook: docs/PROTOCOL.md §5.
#
# This script ALWAYS exits 0. A non-zero exit makes launchd throttle/■retry, which would turn a
# transient hiccup into a wedged agent; a missed pass is cheap and self-heals on the next change.
#
# Configuration (all optional) — put these in <root>/.twoperson/watch.env (git-ignored) or the
# environment, NEVER in a tracked file, and never build them from packet content:
#   TWOPERSON_ON_PACKET   command launched when a new packet arrives (e.g. your Reviewer app audit)
#   TWOPERSON_ON_VERDICT   command launched when a new verdict arrives (wake the manager)
#   TWOPERSON_INBOX       inbox root override, as everywhere else in the bridge
#   TWOPERSON_PYTHON    interpreter override
set -u

# launchd starts us with no useful CWD. TWOPERSON_ROOT is pinned into the agent plist at install
# time; fall back to the CWD so the script is still runnable by hand from a checkout.
root="${TWOPERSON_ROOT:-$PWD}"
cd "$root" 2>/dev/null || exit 0

# The inbox launchd pinned into the agent (plist EnvironmentVariables). WatchPaths is rendered from
# THIS root, so the scan must use it too — capture it before sourcing the env file so a stray
# TWOPERSON_INBOX in that file cannot point `watch --once` at a different inbox than we are watching.
pinned_inbox="${TWOPERSON_INBOX:-}"

# Optional owner config, kept OUT of git so the launch command is not a tracked, auditable secret.
# It is for the LAUNCH COMMANDS only (TWOPERSON_ON_PACKET / TWOPERSON_ON_VERDICT).
env_file="${TWOPERSON_WATCH_ENV:-$root/.twoperson/watch.env}"
if [ -f "$env_file" ]; then
	# shellcheck disable=SC1090
	. "$env_file" 2>/dev/null || true
fi

# Enforce the plist-pinned inbox: the env file must not silently repoint the scan away from the
# watched lanes. Preserve the pin, and warn (to the agent log) if the env file tried to override it.
if [ -n "$pinned_inbox" ]; then
	if [ -n "${TWOPERSON_INBOX:-}" ] && [ "$TWOPERSON_INBOX" != "$pinned_inbox" ]; then
		echo "inbox_watch: ignoring TWOPERSON_INBOX override in the watch env file; using plist-pinned '$pinned_inbox'" >&2
	fi
	TWOPERSON_INBOX="$pinned_inbox"
	export TWOPERSON_INBOX
fi

py="${TWOPERSON_PYTHON:-}"
if [ -z "$py" ]; then
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

"$py" -m twoperson watch --once >/dev/null 2>&1 || true
exit 0
