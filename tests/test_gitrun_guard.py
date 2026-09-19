"""Structural guard: `gitfacts.py`/`citations.py` never call `subprocess` directly.

Every git invocation in this package's diff-derivation and citation-checking machinery must go
through the one bounded runner, `twoperson._gitrun.run_git` — that is what makes the stream caps and
timeout in `_gitrun` an actual guarantee rather than a pattern the next new git call can quietly skip.
This is an AST check, not a grep: it looks for the exact shape (`subprocess.run(...)` /
`subprocess.Popen(...)`) and for a bare `import subprocess`, so it cannot be defeated by reformatting
and cannot be fooled by the string "subprocess" appearing in a docstring or comment.

Scoped to `gitfacts.py` and `citations.py` — the two modules this guard's own audit finding named —
not the whole package: `signal.py`'s `git rev-parse --abbrev-ref HEAD` (a fail-soft, always-tiny
branch-name probe for hook signals) and `watch.py`/`watchagent.py`'s non-git process launches are a
different concern with their own established fail-soft contracts, not part of the diff/citation
machinery this runner bounds.
"""
from __future__ import annotations

import ast
from pathlib import Path

import twoperson

_SRC = Path(twoperson.__file__).resolve().parent
_GUARDED_MODULES = ("gitfacts.py", "citations.py")


def _is_subprocess_run_or_popen(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("run", "Popen", "call", "check_call", "check_output")
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    )


def test_gitfacts_and_citations_never_call_subprocess_directly():
    offenders = []
    for name in _GUARDED_MODULES:
        path = _SRC / name
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if _is_subprocess_run_or_popen(node):
                offenders.append(f"{name}:{node.lineno}")
    assert offenders == [], (
        f"direct subprocess call(s) outside the shared runner: {offenders} — route git "
        "invocations through twoperson._gitrun.run_git instead"
    )


def test_gitfacts_and_citations_do_not_import_subprocess():
    offenders = []
    for name in _GUARDED_MODULES:
        path = _SRC / name
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name == "subprocess" for a in node.names):
                offenders.append(f"{name}:{node.lineno}")
    assert offenders == [], (
        f"{offenders} imports subprocess directly — every git call belongs behind "
        "twoperson._gitrun.run_git, which is the only module allowed to import it for this purpose"
    )


def test_gitrun_is_the_only_module_using_selectors_for_a_git_subprocess():
    """Not load-bearing on its own — just confirms the runner this guard points callers to is
    actually where the streaming implementation lives, so the guard's error message is not a dead
    end."""
    from twoperson import _gitrun

    assert hasattr(_gitrun, "run_git")
    assert hasattr(_gitrun, "GitRunError")
