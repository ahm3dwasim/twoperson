"""Where the inbox lives by default — the property that makes the handoff reachable at all.

Repo law puts every session in its own `git worktree`, and a worktree is a full checkout with its
own `state/`. If the inbox defaults to "this checkout's state dir", Builder publishes into the
worktree's inbox and Reviewer — polling from the main checkout — sees an empty directory. Nothing
errors: `check` exits 1, which is indistinguishable from "no work waiting", so the audit gate is
silently satisfied by a packet nobody can read.

These tests pin the fix and its bounds: every worktree of one repository resolves to ONE default
inbox, an explicit override still wins outright, and a malformed git pointer degrades to the local
checkout instead of raising or wandering off to an arbitrary path.
"""
from __future__ import annotations

import json

import pytest

from twoperson import inbox
from twoperson.signal import build_signal
from tests.fixtures import valid_packet


@pytest.fixture(autouse=True)
def _no_ambient_overrides(monkeypatch):
    """The default is what is under test, so neither override may leak in from the environment."""
    monkeypatch.delenv("TWOPERSON_INBOX", raising=False)
    monkeypatch.delenv("TWOPERSON_HOME", raising=False)


def _main_checkout(tmp_path):
    """A main working tree: `.git` is a real directory."""
    main = tmp_path / "Twoperson"
    (main / ".git").mkdir(parents=True)
    return main.resolve()


def _worktree(main, name):
    """A linked worktree, laid out exactly as `git worktree add` lays one out."""
    gitdir = main / ".git" / "worktrees" / name
    gitdir.mkdir(parents=True)
    (gitdir / "commondir").write_text("../..\n", encoding="utf-8")
    tree = main / ".claude" / "worktrees" / name
    tree.mkdir(parents=True)
    (tree / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
    return tree.resolve()


# --- the blocker: one repository, one inbox -----------------------------------------------------

def test_two_worktrees_and_the_main_checkout_resolve_to_the_same_root(tmp_path):
    main = _main_checkout(tmp_path)
    first, second = _worktree(main, "alpha"), _worktree(main, "beta")

    assert inbox.shared_repo_root(first) == main
    assert inbox.shared_repo_root(second) == main
    assert inbox.shared_repo_root(main) == main


def test_two_worktrees_default_to_the_same_inbox(tmp_path, monkeypatch):
    """The property Reviewer depends on: the default is a function of the repo, not of the checkout."""
    main = _main_checkout(tmp_path)
    first, second = _worktree(main, "alpha"), _worktree(main, "beta")

    monkeypatch.setattr(inbox, "_SEARCH_START", first)
    from_first = inbox.inbox_root()
    monkeypatch.setattr(inbox, "_SEARCH_START", second)
    from_second = inbox.inbox_root()

    assert from_first == from_second == main / ".twoperson"


def test_a_packet_published_from_one_worktree_is_visible_from_another(tmp_path, monkeypatch):
    """End to end: the failure this fixes was a published packet reading as an empty inbox."""
    main = _main_checkout(tmp_path)
    publisher, auditor = _worktree(main, "builder"), _worktree(main, "reviewer")

    monkeypatch.setattr(inbox, "_SEARCH_START", publisher)
    published = inbox.publish(valid_packet())
    published_id = json.loads(published.read_text(encoding="utf-8"))["packet_id"]

    monkeypatch.setattr(inbox, "_SEARCH_START", auditor)
    assert inbox.has_pending()
    claimed = inbox.claim_next()
    assert claimed is not None
    assert claimed.packet["packet_id"] == published_id


def test_a_signal_emitted_from_a_worktree_is_visible_from_the_main_checkout(tmp_path, monkeypatch):
    """The wake-up lane shares the root, so a hook firing in a worktree still wakes an auditor."""
    main = _main_checkout(tmp_path)
    monkeypatch.setattr(inbox, "_SEARCH_START", _worktree(main, "builder"))
    inbox.publish_signal(build_signal(source="manual", session_id="s1"))

    monkeypatch.setattr(inbox, "_SEARCH_START", main)
    assert inbox.has_pending_signals()
    assert not inbox.has_pending()  # a signal is still not a packet


# --- explicit overrides still win ---------------------------------------------------------------

def test_the_env_override_beats_the_shared_default(tmp_path, monkeypatch):
    main = _main_checkout(tmp_path)
    monkeypatch.setattr(inbox, "_SEARCH_START", _worktree(main, "alpha"))
    explicit = tmp_path / "elsewhere" / "twoperson"
    monkeypatch.setenv("TWOPERSON_INBOX", str(explicit))

    assert inbox.inbox_root() == explicit
    assert inbox.publish(valid_packet()).parent == explicit / "pending"
    assert not (main / ".twoperson").exists()  # the shared default was not touched


def test_an_explicit_argument_beats_both_the_env_and_the_shared_default(tmp_path, monkeypatch):
    main = _main_checkout(tmp_path)
    monkeypatch.setattr(inbox, "_SEARCH_START", _worktree(main, "alpha"))
    monkeypatch.setenv("TWOPERSON_INBOX", str(tmp_path / "env"))
    argument = tmp_path / "argument"

    assert inbox.inbox_root(argument) == argument
    assert inbox.publish(valid_packet(), root=argument).parent == argument / "pending"


def test_twoperson_home_still_wins_over_git_detection(tmp_path, monkeypatch):
    """TWOPERSON_HOME is how the deployed box is configured; the fix must not quietly override it."""
    main = _main_checkout(tmp_path)
    monkeypatch.setattr(inbox, "_SEARCH_START", _worktree(main, "alpha"))
    home = tmp_path / "home"
    monkeypatch.setenv("TWOPERSON_HOME", str(home))

    assert inbox.inbox_root() == home / ".twoperson"


# --- bounds: a malformed pointer degrades, it never wanders ------------------------------------

@pytest.mark.parametrize("body", [
    "",
    "not a git file at all\n",
    "gitdir:\n",
    "gitdir: /nonexistent/worktrees/alpha\n",
])
def test_an_unusable_git_pointer_falls_back_to_this_checkout(tmp_path, body):
    tree = tmp_path / "checkout"
    tree.mkdir()
    (tree / ".git").write_text(body, encoding="utf-8")

    assert inbox.shared_repo_root(tree) == tree.resolve()


def test_a_gitdir_without_a_commondir_falls_back_to_this_checkout(tmp_path):
    tree = tmp_path / "checkout"
    gitdir = tmp_path / "gitdir"
    tree.mkdir()
    gitdir.mkdir()
    (tree / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")

    assert inbox.shared_repo_root(tree) == tree.resolve()


def test_a_commondir_that_is_not_a_dot_git_directory_is_refused(tmp_path):
    """A bare repo has no working tree above it, so its parent must never be adopted as a root."""
    tree = tmp_path / "checkout"
    gitdir = tmp_path / "gitdir"
    bare = tmp_path / "repo.git"
    tree.mkdir()
    gitdir.mkdir()
    bare.mkdir()
    (tree / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
    (gitdir / "commondir").write_text(str(bare), encoding="utf-8")

    assert inbox.shared_repo_root(tree) == tree.resolve()


def test_outside_a_checkout_there_is_no_shared_root(tmp_path, monkeypatch):
    """An installed package has no `.git` anywhere above it: report None so the caller can fall back.

    `tmp_path` itself sits under a real filesystem root, so the walk is forced to terminate by
    pretending nothing on the way up is a git marker.
    """
    monkeypatch.setattr(inbox.Path, "is_dir", lambda self: False)
    monkeypatch.setattr(inbox.Path, "is_file", lambda self: False)
    assert inbox.shared_repo_root(tmp_path) is None