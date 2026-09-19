"""The structural guard: ONE module resolves names, and nothing else may.

Three audit rounds each found the next file operation the previous round's fix had not reached — a
symlinked lane, then the writes, then FIFOs on the readers, then hard links, FIFOs on the writers,
the cursor read, the lane ``mkdir``. Each round fixed the sites the reviewer named and the next round
named the sites it had not. The list was never the problem; *having a list* was. A guarantee that
holds only where somebody remembered to use the right helper is a guarantee that expires with the
next commit.

So the rule is mechanical and total: every file operation in this package goes through
:mod:`twoperson._safefs`, and this module fails the build when one does not. It reads the AST rather
than the text, because a regex over source cannot tell ``text.replace("a", "b")`` — a string method —
from ``os.replace(src, dst)``, and a guard that cries wolf gets an allowlist entry it did not earn.

An allowlist entry is a claim that a site is OUTSIDE the threat model, and the threat model is stated
in `_safefs`'s module docstring: the parent directories of a root, and the paths the operator types
or configures, belong to the operator's own layout. Each entry below has to say WHICH path that is
and why it is not ours. An entry with a reason nobody could check is worse than no guard at all, so
every reason is asserted to be a real sentence.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

from twoperson import _safefs

#: The package under guard. `_safefs` itself is exempt BY NAME below, not by being absent from this
#: glob — a module that stopped being scanned would be a silent hole in the guard.
SOURCE_DIR = pathlib.Path(_safefs.__file__).resolve().parent

#: The one module allowed to name a file operation.
PRIMITIVE = "_safefs.py"

#: Calls made through one of these names are file operations by definition. `fcntl` is here for
#: `flock`: the lock/unlock pair is as much a name-scoped operation as `os.open` is — a lock taken
#: on the wrong descriptor is not a lock — and two audit rounds each found a raw `fcntl.flock` call
#: outside the primitive (`inbox._publish_lock`'s release, then `watch._dispatch_lock`'s) before this
#: rule existed to catch either on the commit that (re)introduced it.
_IO_MODULES = frozenset({"os", "shutil", "pathlib", "fcntl"})

#: ...and these are the operations, on those modules.
_MODULE_OPS = frozenset({
    "open", "read", "write", "fdopen", "truncate", "utime",
    "mkdir", "makedirs", "rmdir", "remove", "unlink", "rename", "replace",
    "chmod", "lchmod", "symlink", "link", "mkfifo",
    "scandir", "stat", "lstat",
    "flock", "lockf", "fcntl",
})

#: The same question asked as a METHOD on a `pathlib.Path`. `replace` is deliberately absent: `str`
#: and `bytes` both have it, and `os.replace` is already covered above, so including it here would
#: flag every string substitution in the package and earn itself an allowlist entry for nothing.
_PATH_OPS = frozenset({
    "open", "read_text", "read_bytes", "write_text", "write_bytes",
    "mkdir", "touch", "unlink", "rmdir", "rename", "symlink_to", "hardlink_to", "chmod",
})

#: An escape hatch for a single site that is genuinely out of the model, written on the call itself
#: so it cannot be added without being read. The reason is mandatory and is checked below.
_MARKER = re.compile(r"#\s*safefs:\s*out-of-model\s*[—-]\s*(?P<reason>\S.*)")

#: The only whole-module exemptions. Each is a claim about WHERE its paths come from, and each is a
#: one-line justification, not a blanket "this file is fine".
ALLOWLIST: dict[str, dict[str, str]] = {
    "hook.py": {
        "Path.read_text": "reads the operator's own ~/.claude/settings.json, an explicit path they "
                          "name at install time and which is never inside an inbox root",
        "Path.mkdir": "creates the PARENT of that settings file, in the operator's ~/.claude tree",
        "Path.write_text": "writes the hook settings temp beside that same operator-owned file",
        "os.chmod": "restores that file's mode after the rewrite, on the same operator-owned path",
        "os.replace": "reveals the rewritten hook settings at the operator's own path",
    },
    "watchagent.py": {
        "Path.read_bytes": "reads back the launchd plist this package installed, at the explicit "
                           "~/Library/LaunchAgents path the operator chose",
        "Path.mkdir": "creates that plist's directory and the operator's chosen log directory",
        "Path.write_bytes": "writes the plist temp, beside the plist, at the operator's path",
        "os.replace": "reveals the plist at the operator's own path",
    },
}

#: A reason has to be a reason. Ten characters would admit "out of model", which says nothing.
_MIN_REASON = 20


def _modules() -> list[pathlib.Path]:
    found = sorted(SOURCE_DIR.glob("*.py"))
    assert len(found) >= 10, f"the guard scanned {len(found)} modules — the package moved"
    return found


def _bindings(tree: ast.AST) -> dict[str, str | tuple[str, str]]:
    """Every name this module binds by importing, resolved to what it actually names.

    A binding is one of two shapes:

    * a plain string — the dotted module the name refers to (``"os"``, ``"os.path"``, ``"_safefs"``,
      ``"fcntl"``, …) — for ``import X [as Y]`` and for ``from . import X`` (which names a SUBMODULE
      of this package, the same shape as a module import, not a from-imported attribute);
    * a ``(module, original_name)`` pair — for ``from <module> import <name> [as Y]``, where
      ``<module>`` is a real dotted module name.

    This is the difference between ``import os as fs; fs.open(...)`` and ``_safefs.unlink(...)``
    that a bare name set could not make: both "fs" and "_safefs" are imported names, but only "fs"
    resolves to the guarded module "os" — the alias is a second NAME for the same binding, not a
    different question, and `from os import open as raw_open` must resolve to the same call the
    un-aliased spelling would.
    """
    bindings: dict[str, str | tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bindings[alias.asname] = alias.name          # `import os.path as p` -> "os.path"
                else:
                    top = alias.name.split(".")[0]
                    bindings[top] = top                           # `import os.path` -> "os"
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                if node.module is None:
                    bindings[bound] = alias.name      # `from . import _safefs`: a submodule, not an attribute
                else:
                    bindings[bound] = (node.module, alias.name)
    return bindings


def _resolve_module(name: str, bindings: dict[str, str | tuple[str, str]]) -> str | None:
    """The dotted module ``name`` is bound to, or ``None`` when it is not an imported MODULE name
    (either unbound, or bound to a specific from-imported attribute rather than a module)."""
    target = bindings.get(name)
    return target if isinstance(target, str) else None


def _module_op_shape(module: str, attr: str) -> str | None:
    """``"<module>.<attr>"`` when that pair is a guarded file operation, else ``None``."""
    if module in _IO_MODULES and attr in _MODULE_OPS:
        return f"{module}.{attr}"
    return None


def _attr_shape(attr_node: ast.Attribute, bindings: dict[str, str | tuple[str, str]]) -> str | None:
    """The spelling of ``<receiver>.<attr>`` if it is a guarded file operation, else ``None``.

    Shared by the call-site check and the bare-reference check below: whether ``os.unlink`` is
    called directly, reached through an ``import os as fs`` / ``import fcntl as f`` alias, or just
    assigned to a variable and never called here, it is asking the same question about the same
    binding, so it gets the same answer.
    """
    receiver = attr_node.value
    attr = attr_node.attr
    if isinstance(receiver, ast.Name):
        module = _resolve_module(receiver.id, bindings)
        if module is not None:
            return _module_op_shape(module, attr)
        if receiver.id in bindings:
            return None          # a from-imported NAME, or a reference into another local module
        if attr not in _PATH_OPS:
            return None
        return f"Path.{attr}"
    if isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name):
        base_module = _resolve_module(receiver.value.id, bindings)
        if base_module is not None and base_module.split(".")[0] in _IO_MODULES:
            return None          # `os.path.…` (however `os` is spelled): a path helper, not a file op
    if attr not in _PATH_OPS:
        return None
    return f"Path.{attr}"        # `path.parent.mkdir()`, `Path(x).read_text()` and friends


def _shape(node: ast.Call, bindings: dict[str, str | tuple[str, str]]) -> str | None:
    """The call's spelling, or ``None`` when it is not a file operation."""
    func = node.func
    if isinstance(func, ast.Name):
        target = bindings.get(func.id)
        if isinstance(target, tuple):
            return _module_op_shape(*target)     # `from os import unlink as u; u(...)`
        if target is None and func.id == "open":
            return "open"
        return None
    if isinstance(func, ast.Attribute):
        return _attr_shape(func, bindings)
    return None


def _reference_shape(node: ast.Attribute | ast.Name,
                      bindings: dict[str, str | tuple[str, str]]) -> str | None:
    """The spelling of a guarded operation referenced WITHOUT being called here — ``os.unlink``
    assigned to a variable, passed as a callback, returned — anything that is not itself a `Call`'s
    own `.func`. A reference is exactly as able to reach the filesystem as a call once whatever holds
    it is invoked, and that invocation is not required to be visible in this module for the reference
    itself to be the evasion: naming the primitive is what this guard exists to make impossible to do
    quietly, whether or not the call happens on the same line.
    """
    if isinstance(node, ast.Attribute):
        return _attr_shape(node, bindings)
    target = bindings.get(node.id)
    if isinstance(target, tuple):
        return _module_op_shape(*target)         # `from os import unlink as u; callback(u)`
    return None


def _escape_hatch(source: str, node: ast.Call) -> str | None:
    """The reason on an inline marker for this call, if there is one.

    The marker goes on the call's own line, or in the comment block immediately above it — the two
    places a reader of that call actually looks. The block is scanned upwards through CONTIGUOUS
    comment lines only, so a marker can never be claimed by a call that drifted away from it.
    """
    lines = source.splitlines()
    start = node.lineno - 1
    if 0 <= start < len(lines):
        found = _MARKER.search(lines[start])
        if found:
            return found.group("reason").strip()
    index = start - 1
    while 0 <= index < len(lines) and lines[index].lstrip().startswith("#"):
        found = _MARKER.search(lines[index])
        if found:
            return found.group("reason").strip()
        index -= 1
    return None


def _scan_source(source: str, allowed: dict[str, str] | None = None) -> list[tuple[int, str, str]]:
    """Every guarded operation in ``source`` outside an allowlisted shape or an inline escape hatch —
    called, or merely referenced. ``(lineno, shape, verb)`` per finding, shared between the
    whole-package sweep below and the unit tests that exercise the detector directly on a fixture
    string for one evasion form at a time.

    Two passes over the same walk: a `Call` node is checked against its own spelling (`_shape`,
    which resolves the callee through this module's import bindings); every OTHER `Attribute`/`Name`
    node — one not itself a `Call`'s `.func`, so not already accounted for by the first pass — is
    checked as a bare reference (`_reference_shape`). `call_func_ids` is what tells them apart: the
    id of the `.func` AST node is identity, not value, so a call's own callee is never double-counted
    as a second, reference-shaped offense on the same line.
    """
    allowed = allowed or {}
    tree = ast.parse(source)
    bindings = _bindings(tree)
    call_func_ids = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    found: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            shape, verb = _shape(node, bindings), "calls"
        elif isinstance(node, (ast.Attribute, ast.Name)) and id(node) not in call_func_ids:
            shape, verb = _reference_shape(node, bindings), "references"
        else:
            continue
        if shape is None or shape in allowed:
            continue
        if _escape_hatch(source, node) is not None:
            continue
        found.append((node.lineno, shape, verb))
    return found


def _offenders() -> list[tuple[str, int, str, str]]:
    bad: list[tuple[str, int, str, str]] = []
    for path in _modules():
        if path.name == PRIMITIVE:
            continue
        source = path.read_text(encoding="utf-8")
        allowed = ALLOWLIST.get(path.name, {})
        for line, shape, verb in _scan_source(source, allowed):
            bad.append((path.name, line, shape, verb))
    return bad


def test_no_module_outside_the_primitive_touches_a_file():
    """THE guard. A raw `open()` in inbox.py — or anywhere else — fails here.

    Revert-proved in the r4 report: adding `open("x")` to `inbox.py` turns this red with the module,
    the line and the spelling; removing it turns it green. Extended in r7: the callee is resolved
    through this module's own import bindings first, so `import os as fs; fs.open(...)` and
    `from os import open as raw_open; raw_open(...)` are the same finding as the unaliased spelling,
    and a guarded operation merely REFERENCED (assigned to a variable, passed as a callback) without
    being called here fails the same way a call does.
    """
    bad = _offenders()
    assert not bad, (
        "these file operations bypass twoperson._safefs, the one place the threat model is "
        "enforced — route them through the primitive, or add an allowlist entry that names the "
        "operator path they are for:\n  "
        + "\n  ".join(f"{name}:{line} {verb} {shape}" for name, line, shape, verb in bad)
    )


# --------------------------------------------------------------------------------------------
# The detector itself, on fixture strings: each evasion form the r7 verdict named, unit-tested
# directly rather than through a file on disk — a shape that either the resolver gets right or it
# does not, independent of what happens to live in the package today.
# --------------------------------------------------------------------------------------------

#: Each evasion the module-name check alone could not see: an aliased module import, an aliased
#: from-import of a guarded function, and a dotted submodule import under an alias. Every one of
#: these binds a NAME other than the literal module name to a guarded operation, which is exactly
#: what `_bindings` exists to resolve back to the real target.
_EVASION_FIXTURES = {
    "aliased module import": ("import os as fs\nfs.open('x', 'r')\n", "os.open"),
    "aliased from-import of the function": (
        "from os import open as raw_open\nraw_open('x', 'r')\n", "os.open",
    ),
    "aliased from-import of a different guarded function": (
        "from os import unlink as raw_unlink\nraw_unlink('x')\n", "os.unlink",
    ),
    "unaliased from-import (shadows the builtin)": ("from os import open\nopen('x', 'r')\n", "os.open"),
    "aliased fcntl import": ("import fcntl as f\nf.flock(3, 1)\n", "fcntl.flock"),
}


@pytest.mark.parametrize("name", sorted(_EVASION_FIXTURES), ids=str)
def test_each_import_alias_evasion_is_flagged(name):
    """Renaming the import must not rename the finding: every alias form below resolves to the same
    guarded shape the un-aliased spelling would, so none of them can slip past a name check that only
    knows the literal spellings ``os.open`` / ``os.unlink`` / ``fcntl.flock``."""
    source, expected_shape = _EVASION_FIXTURES[name]
    found = {shape for _line, shape, _verb in _scan_source(source)}
    assert expected_shape in found, f"{name!r} ({source!r}) was not flagged as {expected_shape}"


def test_a_dotted_submodule_import_resolves_to_its_own_module_not_the_parent():
    """`import os.path as p` binds `p` to `os.path`, a real but UNGUARDED module — not to `os`. The
    resolver must tell the two apart, or this alias form would either wrongly clear a real `os` call
    routed through it, or wrongly flag ordinary `os.path` helpers like `.exists`/`.join`."""
    source = "import os.path as p\np.exists('x')\n"
    found = {shape for _line, shape, _verb in _scan_source(source)}
    assert found == set(), f"os.path is not a guarded module, but {source!r} was flagged as {found}"


def test_an_aliased_pathlib_class_import_still_flags_its_path_methods():
    """`from pathlib import Path as P` must not launder a `Path` construction-and-call through the
    alias: `P(x).write_text(...)` is exactly `Path(x).write_text(...)` under another name."""
    source = "from pathlib import Path as P\nP('x').write_text('data')\n"
    found = {shape for _line, shape, _verb in _scan_source(source)}
    assert "Path.write_text" in found, f"{source!r} was not flagged as Path.write_text"


def test_a_guarded_reference_without_a_call_is_flagged_the_same_as_a_call():
    """Assigning `os.unlink` to a variable — never calling it in this module — is still the same
    finding: whatever holds that reference can call it later, somewhere this guard cannot see, so the
    NAMING of the primitive is what must be caught, not just the call syntax."""
    source = "import os\nraw = os.unlink\n"
    found = [(shape, verb) for _line, shape, verb in _scan_source(source)]
    assert ("os.unlink", "references") in found, f"{source!r} was not flagged as a bare reference"


def test_a_from_imported_function_referenced_without_a_call_is_flagged():
    """The from-import twin of the above: `from os import unlink as u` then `cb = u` never calls `u`
    in this module either, and must still be caught by NAME."""
    source = "from os import unlink as u\ncb = u\n"
    found = [(shape, verb) for _line, shape, verb in _scan_source(source)]
    assert ("os.unlink", "references") in found, f"{source!r} was not flagged as a bare reference"


def test_a_call_is_not_double_counted_as_a_bare_reference():
    """The callee of a `Call` is itself an `Attribute`/`Name` node, walked once as the call and once
    as a plain node — it must be reported exactly once, as the call, or the count in every assertion
    above would be off by one for reasons that have nothing to do with the evasion being tested."""
    source = "import os\nos.unlink('x')\n"
    found = [(shape, verb) for _line, shape, verb in _scan_source(source)]
    assert found == [("os.unlink", "calls")], found


def test_a_real_cross_module_reference_is_still_not_flagged():
    """The negative case every positive one above depends on: a reference into another LOCAL module
    (not a guarded stdlib one) — called or merely named — must still pass clean, the same as it did
    before aliases were resolved at all. Otherwise the fix for the evasions would just be a new,
    wider false-positive machine."""
    source = "from . import _safefs\nkind = _safefs.SafeFsRefusal\n_safefs.replace_regular(1, 'x', b'')\n"
    found = [(shape, verb) for _line, shape, verb in _scan_source(source)]
    assert found == [], found


def test_the_real_tree_stays_clean_under_the_new_resolver():
    """The property that matters most: none of the above comes at the cost of a false positive on the
    actual package. `_offenders()` (the whole-tree sweep `test_no_module_outside_the_primitive_touches_a_file`
    asserts on) is exercised again here under its own name, so a regression in the resolver shows up
    as this test's failure, not just as noise in the main guard's assertion message."""
    assert _offenders() == []


def test_the_primitive_is_the_only_exempt_module_by_name():
    """`_safefs` is exempt because it is the primitive, and for no other reason.

    Pinned so the exemption cannot quietly grow into a list: adding a second name here is a change to
    the security model and should be impossible to make by accident.
    """
    assert PRIMITIVE == "_safefs.py"
    assert PRIMITIVE not in ALLOWLIST, (
        "the primitive is exempt by NAME; an allowlist entry would suggest it is exempt site by site"
    )
    assert (SOURCE_DIR / PRIMITIVE).exists()


def test_the_primitive_actually_makes_the_calls_it_is_exempt_for():
    """An exemption that exempts nothing is a hole. The primitive must be where the calls live."""
    source = (SOURCE_DIR / PRIMITIVE).read_text(encoding="utf-8")
    tree = ast.parse(source)
    bindings = _bindings(tree)
    shapes = {_shape(node, bindings) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    for required in ("os.open", "os.mkdir", "os.replace", "os.rename",
                     "os.unlink", "os.stat", "os.scandir", "fcntl.flock"):
        assert required in shapes, f"_safefs does not call {required} — so who does?"
    # `fchmod` is a DESCRIPTOR operation, not a name operation, so it is deliberately not in
    # `_MODULE_OPS` — but the primitive is the only module allowed to set a directory's mode at all,
    # and this is where that is checked.
    assert "os.fchmod(" in source, "nothing in the primitive sets a created directory's mode"


# --------------------------------------------------------------------------------------------
# Inside the primitive: one conversion point, proved rather than described.
#
# `_safefs` is exempt from the guard above because it is where the calls live. That exemption is only
# safe if the module's OWN error contract holds, and for four audit rounds it did not: every round
# found the next syscall whose `OSError` left the module raw. The rule below is the mechanical form
# of "one conversion point": a syscall inside `_safefs` is written inside a `with _converting(...)`
# block, or it fails this test. A newly added syscall is therefore covered on the commit that adds
# it, without a reviewer having to notice.
# --------------------------------------------------------------------------------------------

#: The modules and the calls on them that are syscalls for THIS rule. Wider than `_MODULE_OPS`,
#: which answers a different question (which calls move a NAME): `close`, `fsync`, `fchmod`, `write`
#: and `fdopen` are all descriptor operations that `_MODULE_OPS` deliberately omits, and every one of
#: them can fail with an errno a caller must see as a refusal.
_PRIMITIVE_SYSCALLS: dict[str, frozenset[str]] = {
    "os": frozenset({
        "open", "read", "write", "close", "fstat", "stat", "lstat", "fchmod", "chmod",
        "mkdir", "makedirs", "rmdir", "remove", "unlink", "rename", "replace", "link", "symlink",
        "scandir", "fdopen", "fsync", "fdatasync", "lseek", "truncate", "ftruncate", "dup", "utime",
    }),
    "fcntl": frozenset({"flock", "lockf", "fcntl"}),
}

#: The functions inside the primitive allowed to name a syscall OUTSIDE a `_converting` block, each
#: with the reason. These are the conversion machinery itself, and one deliberate exception.
_PRIMITIVE_ALLOWLIST: dict[str, str] = {
    "close_quietly": "releases a descriptor from a finally block, where raising would replace the "
                     "outcome that brought us there; every close error, EINTR included, is dropped "
                     "rather than retried",
    "unlock_quietly": "releases an flock from a finally block, for the same reason as close_quietly "
                      "above — the locked work is already finished, so a failed LOCK_UN must not "
                      "replace that outcome",
}


def _syscall_shape(node: ast.Call) -> str | None:
    """``"os.open"`` for a syscall call, else ``None``."""
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
            and func.attr in _PRIMITIVE_SYSCALLS.get(func.value.id, ()):
        return f"{func.value.id}.{func.attr}"
    return None


def _is_converting(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "_converting")


def _unconverted_syscalls(source: str) -> list[tuple[int, str, str]]:
    """Every syscall in the primitive that is not inside a `_converting` block.

    The walk carries two pieces of state down the tree and resets the guard on entering a function
    DEFINITION: a `with` in one function must not appear to cover a sibling's body, and a function in
    the allowlist is exempt whatever it is nested in.
    """
    tree = ast.parse(source)
    bad: list[tuple[int, str, str]] = []

    def walk(node: ast.AST, guarded: bool, func: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func, guarded = node.name, node.name in _PRIMITIVE_ALLOWLIST
        if isinstance(node, ast.With) and any(_is_converting(item.context_expr)
                                              for item in node.items):
            guarded = True
        if isinstance(node, ast.Call):
            shape = _syscall_shape(node)
            if shape is not None and not guarded:
                bad.append((node.lineno, shape, func))
        for child in ast.iter_child_nodes(node):
            walk(child, guarded, func)

    walk(tree, False, "<module>")
    return bad


def test_every_syscall_in_the_primitive_is_converted_at_one_point():
    """THE guard for the module's own error contract, and the one the four findings were about.

    Revert-proved in the r5 report: taking `_converting` off `read_regular`'s file-object read (the
    syscall finding 2 named) turns this red with the line and the spelling, and
    `tests/test_safefs_faults.py` turns red with it — the structural guard and the behavioural sweep
    fail together, which is what makes the contract provable rather than asserted.
    """
    source = (SOURCE_DIR / PRIMITIVE).read_text(encoding="utf-8")
    bad = _unconverted_syscalls(source)
    assert not bad, (
        "these syscalls in the primitive can raise a raw OSError past every caller's refusal "
        "handler — put them inside `with _converting(label, verb, kind[, passthrough])`:\n  "
        + "\n  ".join(f"_safefs.py:{line} calls {shape} in {func}()" for line, shape, func in bad)
    )


def test_the_conversion_rule_actually_covers_the_syscalls_the_primitive_calls():
    """A rule with nothing to check is not a rule. This pins that the sweep has real work to do."""
    source = (SOURCE_DIR / PRIMITIVE).read_text(encoding="utf-8")
    shapes = {_syscall_shape(node) for node in ast.walk(ast.parse(source))
              if isinstance(node, ast.Call)}
    for required in ("os.open", "os.mkdir", "os.fchmod", "os.fstat", "os.fdopen", "os.write",
                     "os.fsync", "os.close", "os.scandir", "os.stat", "os.unlink", "os.rename",
                     "os.replace", "fcntl.flock"):
        assert required in shapes, (
            f"the primitive no longer calls {required} — if that is a refactor, this list and the "
            f"sweep's are both stale; if it is not, a syscall moved somewhere this rule cannot see"
        )


def test_every_primitive_allowlist_entry_names_a_real_function_and_a_real_reason():
    """An allowlist entry here is a claim that a function may raise outside the contract."""
    tree = ast.parse((SOURCE_DIR / PRIMITIVE).read_text(encoding="utf-8"))
    defined = {node.name for node in ast.walk(tree)
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name, reason in _PRIMITIVE_ALLOWLIST.items():
        assert name in defined, f"{name} is allowlisted but not defined in the primitive"
        assert len(reason) >= _MIN_REASON, f"{name} — the reason is not a reason: {reason!r}"
    assert set(_PRIMITIVE_ALLOWLIST) == {"close_quietly", "unlock_quietly"}, (
        "a third exception to the conversion rule is a change to the error contract, not a detail"
    )


@pytest.mark.parametrize("module,shape,reason", [
    (module, shape, reason)
    for module, entries in ALLOWLIST.items()
    for shape, reason in entries.items()
])
def test_every_allowlisted_entry_states_a_real_reason(module, shape, reason):
    """An allowlist entry is a claim about a path. A claim that says nothing is not reviewable."""
    assert (SOURCE_DIR / module).exists(), f"{module} is allowlisted but does not exist"
    assert len(reason) >= _MIN_REASON, f"{module}:{shape} — the reason is not a reason: {reason!r}"
    assert reason.endswith(".") is False or len(reason) > _MIN_REASON, reason
    assert any(word in reason for word in ("operator", "explicit", "outside", "install")), (
        f"{module}:{shape} — the reason does not say WHOSE path this is: {reason!r}"
    )


def test_every_allowlisted_entry_is_still_needed():
    """A stale exemption is a hole nobody is looking at: it would cover a future site silently."""
    for module, entries in ALLOWLIST.items():
        tree = ast.parse((SOURCE_DIR / module).read_text(encoding="utf-8"))
        bindings = _bindings(tree)
        shapes = {_shape(node, bindings) for node in ast.walk(tree)
                  if isinstance(node, ast.Call)}
        for shape in entries:
            assert shape in shapes, (
                f"{module}:{shape} is allowlisted but no longer called — remove the entry, or the "
                f"next raw call of that shape in this module is covered for free"
            )


def test_the_inline_escape_hatches_each_state_a_real_reason():
    """Every `# safefs: out-of-model — …` in the package has to say which path it is about."""
    seen = 0
    for path in _modules():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            found = _MARKER.search(line)
            if not found:
                continue
            seen += 1
            reason = found.group("reason").strip()
            assert len(reason) >= _MIN_REASON, f"{path.name}:{number} — {reason!r} is not a reason"
    assert seen >= 3, (
        "the out-of-model sites this package documents (the two reads of a checkout's own .git "
        "marker, and the operator's packet path on the command line) are no longer marked — either "
        "they moved into the primitive, or the marker was lost"
    )
