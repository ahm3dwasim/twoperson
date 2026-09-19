"""`twoperson.citations`: does a `tests[]` row cite a run that can still be repeated at the head?

Built on real commits (`tests.fixtures.git_repo`), because the whole point is reading the head
through git plumbing rather than trusting a packet's claim about it.
"""
from __future__ import annotations

from tests.fixtures import git_repo
from twoperson.citations import (
    MAX_CITATIONS,
    MISSING,
    RESOLVES,
    UNDETERMINABLE,
    check_citations,
    cited_symbols,
    citation_findings,
)


def _packet(head_sha: str, command: str, evidence: str = "") -> dict:
    return {"git": {"head_sha": head_sha},
           "tests": [{"name": "probe", "result": "passed", "command": command,
                      "evidence": evidence}]}


# --------------------------------------------------------------------------------------------
# cited_symbols: what counts as a citation at all
# --------------------------------------------------------------------------------------------

def test_a_backticked_symbol_is_a_citation():
    packet = _packet("x", "replace `_reload_tree(parent)` with `parent`")
    kinds = [(c.kind, c.token) for c in cited_symbols(packet)]
    assert ("symbol", "_reload_tree") in kinds


def test_a_dotted_name_is_not_a_citation():
    """`wrong.module.symbol` must not pass on the strength of `symbol` existing somewhere else."""
    packet = _packet("x", "see `wrong.module.inbox_root` at this head")
    assert cited_symbols(packet) == []


def test_an_expression_is_not_mistaken_for_a_name():
    packet = _packet("x", "drop the `os.path.exists(target) and registered` condition")
    assert cited_symbols(packet) == []


def test_a_node_id_contributes_its_file_and_nothing_else():
    packet = _packet("x", "pytest tests/eyes/test_hardening.py::TestThing::test_gone")
    cites = cited_symbols(packet)
    assert [(c.kind, c.token) for c in cites] == [("path", "tests/eyes/test_hardening.py")]


def test_a_plain_py_path_is_a_citation():
    packet = _packet("x", "pytest src/twoperson/citations.py -q")
    assert ("path", "src/twoperson/citations.py") in [(c.kind, c.token) for c in cited_symbols(packet)]


def test_evidence_is_never_read_for_citations():
    """An absence assertion in evidence ('X is deleted, 0 references') must never be refused."""
    packet = _packet("x", "re-read src/twoperson/citations.py in full",
                     evidence="`_no_such_symbol_anywhere` is deleted, not orphaned; 0 references")
    assert all(c.token != "_no_such_symbol_anywhere" for c in cited_symbols(packet))


def test_a_bare_word_in_prose_is_not_a_citation():
    packet = _packet("x", "run the full suite and confirm test_thing passes")
    assert cited_symbols(packet) == []


# --------------------------------------------------------------------------------------------
# check_citations: resolving against a real repository
# --------------------------------------------------------------------------------------------

def test_resolves_when_the_cited_symbol_exists_at_the_head(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "def _helper():\n    pass\n")
    head = repo.commit()
    packet = _packet(head, "call `_helper()` directly")
    check = check_citations(repo.path, packet)
    assert check.state == RESOLVES
    assert check.checked >= 1


def test_missing_when_the_cited_symbol_was_deleted_by_a_later_commit(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "def _helper():\n    pass\n")
    still_true = repo.commit("still true")
    repo.write("pkg/mod.py", "def _other():\n    pass\n")
    went_stale = repo.commit("went stale")

    packet_before = _packet(still_true, "call `_helper()` directly")
    assert check_citations(repo.path, packet_before).state == RESOLVES

    packet_after = _packet(went_stale, "call `_helper()` directly")
    check = check_citations(repo.path, packet_after)
    assert check.state == MISSING
    assert any("_helper" in c.raw for c in check.missing)


def test_a_tracked_path_the_head_does_not_contain_is_refused(tmp_path):
    """`pkg/` exists at the head (so this is not the scratch-directory exemption) but the specific
    file the row cites does not."""
    repo = git_repo(tmp_path)
    repo.write("pkg/keep.py", "x = 1\n")
    head = repo.commit()
    packet = _packet(head, "pytest pkg/no_such_module_here.py")
    check = check_citations(repo.path, packet)
    assert check.state == MISSING
    assert any(c.kind == "path" for c in check.missing)


def test_a_scratch_harness_outside_the_tree_is_passed_over_not_refused(tmp_path):
    """`tmp/probe.py` is a real, routinely-uncommitted counterfactual harness."""
    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "x = 1\n")
    head = repo.commit()
    packet = _packet(head, "python tmp/probe.py && pytest pkg/mod.py")
    check = check_citations(repo.path, packet)
    assert check.state == RESOLVES
    assert check.checked >= 1


def test_a_head_this_repository_does_not_hold_is_undeterminable(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    repo.commit()
    packet = _packet("0" * 40, "pytest a.txt")
    assert check_citations(repo.path, packet).state == UNDETERMINABLE


def test_an_absent_head_is_undeterminable_even_with_no_extractable_citation(tmp_path):
    """The head is established BEFORE the zero-citation shortcut, or a packet naming a head this
    repository does not hold would publish just by citing nothing checkable."""
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    repo.commit()
    packet = _packet("0" * 40, "the full suite")
    assert cited_symbols(packet) == []
    assert check_citations(repo.path, packet).state == UNDETERMINABLE


def test_a_packet_citing_nothing_extractable_reports_zero_rather_than_success(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("a.txt", "x\n")
    head = repo.commit()
    packet = _packet(head, "the full suite", evidence="312 passed")
    check = check_citations(repo.path, packet)
    assert check.state == RESOLVES
    assert check.checked == 0


def test_a_citation_set_over_the_cap_cannot_report_success(tmp_path):
    repo = git_repo(tmp_path)
    names = []
    for i in range(MAX_CITATIONS + 5):
        repo.write(f"pkg/mod{i}.py", f"def sym{i}(): pass\n")
        names.append(f"sym{i}")
    head = repo.commit()
    command = " ".join(f"`{n}`" for n in names) + " `no_such_symbol_zzz`"
    packet = _packet(head, command)
    assert len(cited_symbols(packet)) > MAX_CITATIONS
    check = check_citations(repo.path, packet)
    assert check.state == UNDETERMINABLE, "a truncated citation set must never report success"


def test_an_unexpected_git_failure_after_a_good_head_probe_is_undeterminable_not_resolves(
    tmp_path, monkeypatch
):
    """A head probe succeeding must not let a SUBSEQUENT, unrelated git failure on the top-level
    directory probe read as "directory absent, exempt". `git cat-file -e` used to return the SAME
    exit status (128) for a genuinely absent path as for other ways it failed to resolve, so any
    nonzero there silently passed a citation as resolved. This proves the `git ls-tree` rewrite
    raises on an unexpected status instead of treating it as an exemption."""
    import twoperson.citations as citations_mod

    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "x = 1\n")
    head = repo.commit()
    packet = _packet(head, "pytest pkg/mod.py")

    real_git = citations_mod._git

    def _fake_git(repo_path, *args):
        if args[:1] == ("ls-tree",):
            return citations_mod._gitrun.GitResult(128, b"", b"fatal: injected failure")
        return real_git(repo_path, *args)

    monkeypatch.setattr(citations_mod, "_git", _fake_git)
    check = check_citations(repo.path, packet)
    assert check.state == UNDETERMINABLE


def test_citation_findings_names_the_row_and_the_stale_citation(tmp_path):
    repo = git_repo(tmp_path)
    repo.write("pkg/mod.py", "def _helper():\n    pass\n")
    repo.commit("still true")
    repo.write("pkg/mod.py", "def _other():\n    pass\n")
    head = repo.commit("went stale")
    packet = _packet(head, "call `_helper()` directly")
    packet["tests"][0]["name"] = "regression probe"
    check = check_citations(repo.path, packet)
    findings = citation_findings(check)
    assert len(findings) == 1
    assert "regression probe" in findings[0]
    assert "_helper" in findings[0]
