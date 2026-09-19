"""The one bounded subprocess runner every git call in this package goes through.

`subprocess.run(capture_output=True)` buffers ALL of stdout and stderr before a caller gets to look
at either — the byte ceiling `gitfacts`/`citations` each enforced only caught a runaway *after* the
memory was already spent, which is not a memory bound at all, and neither of them bounded stderr in
the first place. This streams both pipes with `selectors`, one read syscall at a time, and kills the
process the instant either stream crosses its cap or the timeout elapses. A caller never receives a
partial buffer dressed up as a complete answer — only ever the full result, or a raised refusal.

One runner, not two: `gitfacts` and `citations` each used to run `subprocess.run` directly, and nothing
stopped a THIRD module from adding its own unbounded copy. `tests/test_gitrun_guard.py` is a
structural check that `gitfacts.py`/`citations.py` never call `subprocess.run`/`subprocess.Popen`
themselves — every git invocation in this package's diff/citation machinery is `run_git`, once.
"""
from __future__ import annotations

import os
import selectors
import subprocess
import time
from pathlib import Path
from typing import NamedTuple

#: One read() per ready fd is capped at this many bytes, so a single burst cannot overshoot a small
#: `max_bytes` cap by much — the cap is enforced within one chunk of slack, never a full pipe buffer.
_CHUNK = 65536

#: Grace window granted to the final `proc.wait()` once both pipes have hit EOF. Reading to EOF on a
#: pipe-only child happens at/after process exit, so the process is normally already gone by then;
#: this is slack for the reap to land, not extra runtime budget for git itself.
_REAP_GRACE_S = 1.0


class GitRunError(Exception):
    """git could not be run at all, or a hard bound — time, or bytes on either stream — was hit.

    One exception type for every way this module's contract can fail to be met, so a caller has
    exactly one thing to catch rather than needing to know whether `OSError`,
    `subprocess.SubprocessError`, or a bytes-cap check applies this time.
    """


class GitResult(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes


def run_git(repo: Path | str, *args: str, timeout: float, max_bytes: int) -> GitResult:
    """Run ``git -C repo <args>``, streaming stdout/stderr with a hard cap on EACH.

    Raises `GitRunError` — never returns a partial result — when git cannot be started, when
    ``timeout`` elapses before the process exits, or when either stream exceeds ``max_bytes``. In
    every failure case the process is killed rather than left running.
    """
    label = " ".join(args)
    try:
        proc = subprocess.Popen(
            ("git", "-C", str(repo), *args),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise GitRunError(f"git {label} failed to start: {exc}") from exc

    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    names_by_fd = {proc.stdout.fileno(): "stdout", proc.stderr.fileno(): "stderr"}
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    sel.register(proc.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout

    def _kill() -> None:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass  # best-effort reap; the process is killed either way

    try:
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill()
                raise GitRunError(f"git {label} timed out after {timeout}s")
            for key, _events in sel.select(timeout=remaining):
                name = names_by_fd[key.fd]
                try:
                    # safefs: out-of-model — a pipe fd of this package's OWN git child process,
                    # never a name resolved from a shared directory; there is no path here for a
                    # hostile entry to occupy, so `_safefs`'s threat model does not apply.
                    chunk = os.read(key.fd, _CHUNK)
                except OSError as exc:
                    _kill()
                    raise GitRunError(f"git {label} failed while reading {name}: {exc}") from exc
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                buffers[name].extend(chunk)
                if len(buffers[name]) > max_bytes:
                    _kill()
                    raise GitRunError(
                        f"git {label} produced more than {max_bytes} bytes on {name} — refusing "
                        "rather than buffering a runaway stream"
                    )
        try:
            returncode = proc.wait(timeout=max(0.0, deadline - time.monotonic()) + _REAP_GRACE_S)
        except subprocess.TimeoutExpired:
            _kill()
            raise GitRunError(f"git {label} timed out after {timeout}s") from None
    finally:
        sel.close()
        proc.stdout.close()
        proc.stderr.close()

    return GitResult(returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
