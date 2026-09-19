"""`twoperson._gitrun`: the one bounded subprocess runner every git call in this package goes
through — streamed stdout/stderr, each independently capped, timeout preserved, over-cap or
over-time is always a raise, never a partial result.

Every test here replaces the CHILD PROCESS, not `run_git` itself: `subprocess.Popen` is monkeypatched
to launch a small Python script instead of ``git``, so a stream's size and timing are exact and
deterministic rather than dependent on git's own output for some contrived repository state.
"""
from __future__ import annotations

import sys

import pytest

from twoperson._gitrun import GitRunError, run_git


def _redirect_popen(monkeypatch, code: str):
    """Make the next `run_git` call launch `python -c code` instead of `git`, keeping the caller's
    own stdout/stderr/timeout wiring untouched."""
    import twoperson._gitrun as gitrun_mod

    real_popen = gitrun_mod.subprocess.Popen

    def _fake_popen(argv, **kwargs):
        return real_popen([sys.executable, "-c", code], **kwargs)

    monkeypatch.setattr(gitrun_mod.subprocess, "Popen", _fake_popen)


def test_run_git_returns_the_real_result_for_an_ordinary_command(tmp_path):
    result = run_git(tmp_path, "--version", timeout=5, max_bytes=1_000_000)
    assert result.returncode == 0
    assert b"git version" in result.stdout
    assert result.stderr == b""


def test_run_git_refuses_oversized_stdout(tmp_path, monkeypatch):
    """The byte cap must bound MEMORY, not just be checked after the fact: this proves a stream
    over `max_bytes` is refused rather than fully buffered and checked afterward."""
    _redirect_popen(monkeypatch, "import sys; sys.stdout.buffer.write(b'x' * 5000)")
    with pytest.raises(GitRunError, match="stdout"):
        run_git(tmp_path, "status", timeout=5, max_bytes=100)


def test_run_git_refuses_oversized_stderr(tmp_path, monkeypatch):
    """`gitfacts._git`'s old bound checked only `len(result.stdout)` — stderr was never capped.
    This proves stderr is now bounded exactly the same way stdout is."""
    _redirect_popen(monkeypatch, "import sys; sys.stderr.buffer.write(b'x' * 5000)")
    with pytest.raises(GitRunError, match="stderr"):
        run_git(tmp_path, "status", timeout=5, max_bytes=100)


def test_run_git_refuses_oversized_output_on_both_streams_at_once(tmp_path, monkeypatch):
    """Neither stream may smuggle a runaway past the other's cap — both are enforced independently
    and concurrently, not one after the other."""
    _redirect_popen(
        monkeypatch,
        "import sys\n"
        "sys.stdout.buffer.write(b'x' * 5000)\n"
        "sys.stderr.buffer.write(b'y' * 5000)\n",
    )
    with pytest.raises(GitRunError):
        run_git(tmp_path, "status", timeout=5, max_bytes=100)


def test_run_git_accepts_output_at_or_under_the_cap(tmp_path, monkeypatch):
    _redirect_popen(monkeypatch, "import sys; sys.stdout.buffer.write(b'x' * 100)")
    result = run_git(tmp_path, "status", timeout=5, max_bytes=100)
    assert result.stdout == b"x" * 100
    assert result.returncode == 0


def test_run_git_preserves_the_timeout(tmp_path, monkeypatch):
    """A hung git process must not be left running past `timeout`, and the caller must not block
    past it either."""
    _redirect_popen(monkeypatch, "import time; time.sleep(30)")
    with pytest.raises(GitRunError, match="timed out"):
        run_git(tmp_path, "status", timeout=0.3, max_bytes=1_000_000)


def test_run_git_refuses_when_git_cannot_be_started(tmp_path, monkeypatch):
    import twoperson._gitrun as gitrun_mod

    def _broken_popen(*args, **kwargs):
        raise FileNotFoundError("git: command not found")

    monkeypatch.setattr(gitrun_mod.subprocess, "Popen", _broken_popen)
    with pytest.raises(GitRunError, match="failed to start"):
        run_git(tmp_path, "status", timeout=5, max_bytes=1_000_000)


def test_run_git_preserves_a_nonzero_returncode(tmp_path, monkeypatch):
    _redirect_popen(monkeypatch, "raise SystemExit(1)")
    result = run_git(tmp_path, "status", timeout=5, max_bytes=1_000_000)
    assert result.returncode == 1
