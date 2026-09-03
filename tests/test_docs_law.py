"""The docs may not drift from the code.

A README that documents a command the CLI dropped — or a CLI that grows one the runbook never
mentions — is worse than no README: it teaches people a workflow that silently does not exist.
These are deterministic drift guards, not prose review, so they stay honest without a human.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from twoperson.__main__ import SUBCOMMANDS
from twoperson.hook import HOOK_SCRIPT_NAME, hook_script_path

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs" / "PROTOCOL.md"
README = ROOT / "README.md"


def _text(path: Path) -> str:
    """Doc text, lowercased and whitespace-collapsed.

    Collapsing matters: these are markdown files a human rewraps, and a command that survives a
    reflow onto two lines has not drifted. Without it the guard fails on formatting, which trains
    people to delete the guard.
    """
    assert path.exists(), f"canonical doc missing: {path.relative_to(ROOT)}"
    return " ".join(path.read_text(encoding="utf-8").lower().split())


@pytest.mark.parametrize("command", sorted(SUBCOMMANDS))
def test_every_subcommand_is_documented(command: str) -> None:
    assert command in _text(PROTOCOL), (
        f"`twoperson {command}` exists but docs/PROTOCOL.md never mentions it"
    )


def test_readme_states_the_gate() -> None:
    """The one claim the project makes must survive a rewrite of the README."""
    text = _text(README)
    for phrase in ("review_ref", "publish", "verdict"):
        assert phrase in text, f"README no longer explains `{phrase}`"


def test_the_hook_script_the_installer_points_at_exists() -> None:
    """`install-hook` writes a path into settings.json; a wrong path fails only at Stop time."""
    assert hook_script_path().exists(), f"missing packaged hook script: {HOOK_SCRIPT_NAME}"


def test_the_docs_do_not_claim_reviewer_independence_is_enforced() -> None:
    """Reviewer r2/r3: `reviewer` is free text and self-approval is accepted, so no public text may
    promise an independent or second-party check. The caveat must be stated, and the claim absent."""
    readme = _text(README)
    protocol = _text(PROTOCOL)
    pyproject = " ".join((ROOT / "pyproject.toml").read_text(encoding="utf-8").lower().split())
    assert "doesn't know who the reviewer is" in readme
    assert "per commit, not per packet" in readme
    assert "operating assumption" in protocol
    assert "nothing in the gate reads head or the working tree" in readme, \
        "README must say the gate validates reports, not repository state"
    assert "never runs `git`" not in readme, "signal.py and the hook scripts DO call git rev-parse"
    assert "never observes the repository" not in protocol, "inbox.py reads .git/commondir; signal.py runs git rev-parse"
    assert "does not inspect commit or worktree contents" in protocol
    assert "find a virtualenv" in protocol, "the hook scripts' git rev-parse must be in the stated boundary"
    assert "a valid `signal` invocation never returns 2" in readme
    assert "never returns exit 2" not in protocol, "PROTOCOL must carry the same scoped exit-code claim"
    assert "a valid invocation never returns 2" in protocol
    assert "every field `unknown`" not in protocol and 'every field starts as "unknown"' not in readme
    assert "every fact" not in readme and "every fact" not in protocol, "enumerate the fixed placeholders instead"
    for placeholder in ("replace-me", "1970-01-01t00:00:00z", "origin/main", '["unknown"]'):
        assert placeholder in protocol, f"PROTOCOL must list the fixed template placeholder {placeholder}"
    assert "fixed placeholders" in readme
    import io, contextlib
    from twoperson.__main__ import main as _main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        _main(["--help"])
    help_text = " ".join(buf.getvalue().lower().split())
    assert "every field" not in help_text and "every fact" not in help_text, "CLI help must not overclaim the template"
    assert "replace-me" in help_text
    assert "signal`, which never" not in readme
    assert "operator policy (not enforced by the tool)" in protocol, \
        "the before-it-moves rule is policy, not something the tool can see"
    for forbidden in ("independent reviewer", "different agent", "second party", "someone else"):
        assert forbidden not in pyproject, f"pyproject promises `{forbidden}`"
        assert forbidden not in readme, f"README promises `{forbidden}`"


def test_no_public_text_cites_a_hook_path_that_does_not_exist() -> None:
    """Reviewer r10: docstrings named hooks/… while the scripts ship under src/twoperson/scripts/."""
    import re
    src = ROOT / "src" / "twoperson"
    for path in list(src.rglob("*.py")) + list(src.rglob("*.sh")) + [README, PROTOCOL]:
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"hooks/twoperson_[a-z_]+\.(?:sh|env)", text):
            raise AssertionError(f"{path.relative_to(ROOT)} cites {m.group(0)}, which does not exist")
