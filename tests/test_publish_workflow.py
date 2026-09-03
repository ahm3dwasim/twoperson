"""The publish workflow is its own gate.

Pushing a tag is enough to reach the job that can mint a PyPI token, and that job publishes an
artifact which cannot be withdrawn. Whatever checks a maintainer runs beforehand cannot bind a push
that did not come from them, so the checks that matter live in the workflow, and these tests are
what keep them there.

They parse the workflow rather than searching its text. A comment mentioning `needs: guard` would
satisfy a substring check exactly as well as the dependency edge does, which would leave the guard
deletable while the test still passed.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

def _is_pinned(ref: str) -> bool:
    """An immutable reference. A 40-character commit for an action; a digest for a container.

    `docker://` is not a free pass: `docker://alpine:latest` is every bit as mutable as `@main`.
    A local `./path` action is part of this repository and is covered by the commit under review.
    """
    if ref.startswith("./"):
        return True
    if ref.startswith("docker://"):
        return bool(re.search(r"@sha256:[0-9a-f]{64}$", ref))
    return bool(re.search(r"@[0-9a-f]{40}$", ref))


def _workflow_files() -> list[Path]:
    """Both extensions. GitHub reads `.yaml` as happily as `.yml`, so a guard that only globs one
    can be stepped around by naming a file the other way."""
    d = ROOT / ".github" / "workflows"
    return sorted(list(d.glob("*.yml")) + list(d.glob("*.yaml")))


def _every_uses() -> list[tuple[str, str]]:
    """(workflow name, action reference) for every step in every job, read from the PARSED file.

    Scanning physical lines misses what YAML permits: a `uses` value can be folded across lines, or
    written in a flow mapping, and either would slip a mutable reference past a line-based guard
    while GitHub read it perfectly well.
    """
    import yaml
    found = []
    for path in _workflow_files():
        wf = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in (wf.get("jobs") or {}).values():
            # A job can BE a reusable workflow rather than contain steps, and that reference is
            # every bit as mutable as an action's. Walking only steps would leave `@main` on a
            # called workflow invisible to this guard.
            job_ref = job.get("uses")
            if job_ref:
                found.append((path.name, str(job_ref).strip()))
            for step in job.get("steps", []) or []:
                ref = step.get("uses")
                if ref:
                    found.append((path.name, str(ref).strip()))
    return found


def test_every_action_in_every_workflow_is_pinned_to_a_commit() -> None:
    """Anything reachable from the publishing workflow can influence what gets published, and the
    publish job holds id-token: write. A tag or branch reference is mutable by whoever owns it."""
    refs = _every_uses()
    assert len(refs) >= 5, f"expected to find the workflow actions, only matched {len(refs)}"
    for name, ref in refs:
        assert _is_pinned(ref), f"{name} uses {ref}, which is not pinned to an immutable reference"


@pytest.mark.parametrize(
    "ref",
    [
        "actions/checkout@v4",
        "actions/checkout@main",
        "docker://alpine:latest",
        "docker://alpine",
        "docker://alpine@sha256:",
        "docker://alpine@sha256:abc",
        "docker://alpine@sha256:" + "z" * 64,
        "docker://alpine@sha256:" + "a" * 63,
    ],
)
def test_the_pin_predicate_rejects_everything_mutable(ref: str) -> None:
    assert not _is_pinned(ref)


@pytest.mark.parametrize(
    "ref",
    [
        "actions/checkout@" + "a" * 40,
        "docker://alpine@sha256:" + "0123456789abcdef" * 4,
        "./.github/actions/local",
    ],
)
def test_the_pin_predicate_accepts_immutable_references(ref: str) -> None:
    assert _is_pinned(ref)


def test_the_pin_guard_reads_yaml_not_lines() -> None:
    """A `uses` value folded across lines, or written in a flow mapping, is valid YAML that GitHub
    honours and a line scanner misses. The guard has to see what GitHub sees."""
    import yaml
    folded = yaml.safe_load(
        "jobs:\n  j:\n    steps:\n      - uses: >-\n          actions/checkout@main\n"
    )
    assert folded["jobs"]["j"]["steps"][0]["uses"].strip() == "actions/checkout@main"
    flow = yaml.safe_load("jobs:\n  j:\n    steps:\n      - {uses: actions/checkout@main}\n")
    assert flow["jobs"]["j"]["steps"][0]["uses"] == "actions/checkout@main"
    for shape in (folded, flow):
        ref = shape["jobs"]["j"]["steps"][0]["uses"].strip()
        assert not _is_pinned(ref), "the predicate must reject what the parser found"


def test_the_pinning_guard_covers_both_workflow_extensions() -> None:
    assert {p.suffix for p in _workflow_files()} <= {".yml", ".yaml"}


@pytest.mark.parametrize(
    "ref",
    [
        "docker://alpine@sha256:",
        "docker://alpine@sha256:abc",
        "docker://alpine@sha256:" + "z" * 64,
        "docker://alpine@sha256:" + "a" * 63,
        "docker://alpine@sha256:" + "a" * 65,
    ],
)
def test_a_docker_reference_needs_a_real_digest_not_the_word_sha256(ref: str) -> None:
    assert not _is_pinned(ref)


def test_a_docker_reference_with_a_real_digest_is_accepted() -> None:
    assert _is_pinned("docker://alpine@sha256:" + "0123456789abcdef" * 4)


def _publish_workflow() -> dict:
    """The publish workflow, PARSED.

    Searching the raw text for phrases proves nothing about the pipeline: a comment mentioning
    `needs: guard` satisfies a substring check just as well as the dependency edge does, so the gate
    could be deleted while every assertion still passed. These read the job graph instead.
    """
    import yaml
    return yaml.safe_load((ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8"))


def _job_runs(job: dict) -> str:
    return "\n".join(str(s.get("run", "")) for s in job.get("steps", []))


def test_the_publish_workflow_checks_the_tag_it_was_handed() -> None:
    wf = _publish_workflow()
    assert "guard" in wf["jobs"], "the publish workflow needs a job that checks the tag"
    runs = _job_runs(wf["jobs"]["guard"])
    assert "merge-base --is-ancestor" in runs, "the tag must be proven to be on main"
    assert "pyproject.toml" in runs, "the tag must be proven to match the declared version"


def test_the_on_main_guard_actually_rejects_a_commit_that_is_not_on_main(tmp_path: Path) -> None:
    """Run the ancestry check, rather than confirming the workflow contains the words for it.

    Presence of `merge-base --is-ancestor` somewhere in a script says nothing about whether the
    result is acted on. This lifts the step's own body out of the parsed workflow and runs it against
    a real repository with a real remote: once for a commit that is on main, once for a commit that
    is not. Without it, that gate could be inverted or deleted and every other test here would stay
    green.
    """
    import subprocess

    env_git = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }

    def run(cmd, cwd, extra=None):
        return subprocess.run(cmd, cwd=cwd, env={**env_git, **(extra or {})},
                              capture_output=True, text=True)

    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
    repo = tmp_path / "work"
    repo.mkdir()
    (repo / "f").write_text("x")
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                ["git", "commit", "-qm", "on main"],
                ["git", "remote", "add", "origin", f"file://{bare}"],
                ["git", "push", "-q", "origin", "main"]):
        r = run(cmd, repo)
        assert r.returncode == 0, r.stderr
    on_main = run(["git", "rev-parse", "HEAD"], repo).stdout.strip()

    # A commit that exists but was never merged: the case the gate is for.
    for cmd in (["git", "checkout", "-q", "-b", "elsewhere"],
                ["git", "commit", "-q", "--allow-empty", "-m", "not on main"]):
        assert run(cmd, repo).returncode == 0
    off_main = run(["git", "rev-parse", "HEAD"], repo).stdout.strip()

    steps = _publish_workflow()["jobs"]["guard"]["steps"]
    body = next(s["run"] for s in steps if "on main" in str(s.get("name", "")))

    good = run(["bash", "-c", body], repo, {"SHA": on_main, "TAG": "v0.1.1"})
    assert good.returncode == 0, good.stdout + good.stderr

    bad = run(["bash", "-c", body], repo, {"SHA": off_main, "TAG": "v0.1.1"})
    assert bad.returncode != 0, "a tag on a commit that is not on main must not publish"
    assert "not on main" in bad.stdout + bad.stderr


def test_nothing_reaches_the_upload_without_passing_every_gate() -> None:
    """The dependency edges are the gate. Read them from the parsed graph, then walk it."""
    jobs = _publish_workflow()["jobs"]

    def needs(name: str) -> list[str]:
        n = jobs[name].get("needs", [])
        return [n] if isinstance(n, str) else list(n)

    # every ancestor of the publishing job
    seen, stack = set(), list(needs("pypi"))
    while stack:
        j = stack.pop()
        if j in seen:
            continue
        seen.add(j)
        stack.extend(needs(j))
    for required in ("guard", "build", "test"):
        assert required in seen, f"the {required} job is not upstream of pypi, so it gates nothing"


def test_a_job_level_reusable_workflow_reference_is_not_invisible() -> None:
    """`jobs.<id>.uses` calls a reusable workflow and takes the same kind of reference an action
    does. A guard that only walked steps would let `@main` in on that line."""
    import yaml
    wf = yaml.safe_load(
        "jobs:\n  called:\n    uses: someone/repo/.github/workflows/w.yml@main\n"
    )
    job = wf["jobs"]["called"]
    assert job.get("uses") and not job.get("steps"), "a reusable-workflow job has no steps at all"
    assert not _is_pinned(job["uses"])


def test_every_version_this_package_claims_to_support_is_tested() -> None:
    """The classifiers are the support claim, and this keeps them honest.

    `requires-python` is a floor, not a promise about the top: `>=3.10` also permits interpreters
    that did not exist when this was written, and nothing can test those in advance. So the versions
    this package says it supports are listed explicitly, and every one of them has to appear in the
    matrix that gates a release, in both directions — a claim with no test, or a test for something
    not claimed, is a discrepancy either way.
    """
    import re
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    claimed = set(re.findall(r'"Programming Language :: Python :: (\d+\.\d+)"', pyproject))
    assert claimed, "the package must say which versions it supports, not only a floor"

    tested = {str(v) for v in _publish_workflow()["jobs"]["test"]["strategy"]["matrix"]["python"]}
    assert claimed == tested, f"claimed {sorted(claimed)} but the release gate tests {sorted(tested)}"

    floor = re.search(r'requires-python = ">=(\d+\.\d+)"', pyproject)
    assert floor and floor.group(1) in claimed, "the install floor must be a version that is tested"
    # Deliberate, and written down so it is not mistaken for an oversight: the floor has no ceiling,
    # so a Python released later is installable and untested until the matrix is extended. Capping
    # would close that at the cost of refusing to install on every new interpreter.
    assert "deliberately not a ceiling" in pyproject, \
        "the uncapped floor is a decision and must stay documented where it is made"


def test_the_version_guard_actually_rejects_a_mismatched_tag(tmp_path: Path) -> None:
    """Run the guard's own shell body rather than checking it mentions a filename.

    A test that only looks for the word `pyproject.toml` in the step passes just as happily after
    the comparison itself is deleted, which is the one thing that step exists to do. So the body is
    lifted out of the parsed workflow and executed against the real pyproject.toml, once with the
    tag that matches and once with one that does not.

    The step calls `python`, which is what a runner has after setup-python. A shim supplies it here
    rather than changing the workflow to suit the test.
    """
    import subprocess
    import sys

    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "python").write_text(f'#!/usr/bin/env bash\nexec "{sys.executable}" "$@"\n')
    (shim / "python").chmod(0o755)
    env = {"PATH": f"{shim}:{os.environ['PATH']}"}

    steps = _publish_workflow()["jobs"]["guard"]["steps"]
    body = next(s["run"] for s in steps if "version" in str(s.get("name", "")))

    right = subprocess.run(["bash", "-c", body], cwd=ROOT, capture_output=True, text=True,
                           env={**env, "TAG": "v0.1.1"})
    assert right.returncode == 0, right.stdout + right.stderr

    wrong = subprocess.run(["bash", "-c", body], cwd=ROOT, capture_output=True, text=True,
                           env={**env, "TAG": "v9.9.9"})
    assert wrong.returncode != 0, "a tag that does not match the declared version must not publish"
    assert "does not match" in wrong.stdout + wrong.stderr


def test_the_artifact_itself_is_tested_on_every_supported_version() -> None:
    """Testing the source tree on one interpreter and uploading a wheel nobody ran proves the wrong
    thing. The versions come from the package's own declared classifiers-in-practice: the CI matrix."""
    jobs = _publish_workflow()["jobs"]
    test = jobs["test"]
    versions = {str(v) for v in test["strategy"]["matrix"]["python"]}
    assert len(versions) >= 4, versions
    runs = _job_runs(test)
    assert "dist/*.whl" in runs, "the built wheel must be what is installed and tested"
    assert "pytest" in runs
    ci = ROOT / ".github" / "workflows" / "ci.yml"
    import yaml
    ci_versions = {str(v) for v in yaml.safe_load(ci.read_text())["jobs"]["test"]["strategy"]["matrix"]["python"]}
    assert versions == ci_versions, "the publish gate must cover the same versions CI does"


def test_the_gate_installs_what_the_suite_itself_needs() -> None:
    """This job decides whether anything is published. If it cannot run the suite, nothing ships and
    the failure reads like a broken release rather than a missing dependency line."""
    import yaml
    jobs = _publish_workflow()["jobs"]
    runs = _job_runs(jobs["test"])
    imported = set()
    for path in sorted((ROOT / "tests").glob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("import yaml") or s.startswith("from yaml"):
                imported.add("PyYAML")
    for dep in {"pytest"} | imported:
        assert dep in runs, f"the publish gate never installs {dep}, which its own tests need"


def test_both_workflows_are_read_only_and_keep_no_token() -> None:
    """Every workflow, not only the publishing one: CI checks out the repository and runs its tests
    and dependencies too."""
    import yaml
    for path in _workflow_files():
        wf = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert wf.get("permissions", {}).get("contents") == "read", f"{path.name} is not read-only by default"
        for name, job in wf["jobs"].items():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    assert step.get("with", {}).get("persist-credentials") is False, \
                        f"the checkout in {path.name}:{name} keeps its credentials"


def test_the_workflow_is_read_only_by_default_and_does_not_keep_a_token() -> None:
    """These jobs run code out of the repository — the test suite, the build backend. A checkout
    that leaves a write-capable token behind lets any of it change the repository after the checks
    have passed."""
    wf = _publish_workflow()
    assert wf.get("permissions", {}).get("contents") == "read"
    for name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            uses = str(step.get("uses", ""))
            if uses.startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") is False, \
                    f"the checkout in {name} keeps its credentials"
    assert wf["jobs"]["pypi"]["permissions"] == {"id-token": "write"}, \
        "only the publishing job may hold more than read"


def test_the_toolchain_that_builds_the_artifact_is_frozen() -> None:
    """Pinning the actions while pip resolves the build environment freely leaves the same door
    open: anything reachable from there can change what ends up in a wheel that cannot be
    unpublished."""
    jobs = _publish_workflow()["jobs"]
    runs = _job_runs(jobs["build"])
    assert "--require-hashes" in runs and "requirements-build.txt" in runs
    assert "--no-isolation" in runs, "an isolated build resolves its backend at release time"
    reqs = (ROOT / "requirements-build.txt").read_text(encoding="utf-8")
    import re
    pinned = re.findall(r"^([A-Za-z0-9_.\-]+)==", reqs, re.M)
    assert {"build", "hatchling"} <= set(pinned), pinned
    assert reqs.count("--hash=sha256:") >= 2 * len(pinned), "every pinned distribution needs a hash"


def test_the_sdist_is_tested_too_because_the_sdist_is_uploaded() -> None:
    """Both distributions go to PyPI, and the sdist is what anyone without a matching wheel builds
    from. Testing only the wheel would leave half the release unexercised."""
    test = _publish_workflow()["jobs"]["test"]
    kinds = {str(k) for k in test["strategy"]["matrix"]["dist"]}
    assert kinds == {"wheel", "sdist"}, kinds
    runs = _job_runs(test)
    assert "dist/*.whl" in runs and "dist/*.tar.gz" in runs


def test_no_workflow_splices_a_ref_name_into_a_shell_body() -> None:
    """`${{ }}` is substituted into the script source before bash parses it, so a tag named with
    shell metacharacters becomes code rather than the string being compared. Values that come from
    outside travel through the environment instead."""
    import yaml
    for path in _workflow_files():
        wf = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in (wf.get("jobs") or {}).items():
            for step in job.get("steps", []) or []:
                body = str(step.get("run", ""))
                assert "${{" not in body, (
                    f"{path.name}:{job_name} interpolates an expression into a shell body: "
                    f"{step.get('name', body[:40])!r}"
                )


def test_the_frozen_toolchain_is_proven_to_resolve_on_the_oldest_supported_version() -> None:
    """requirements-build.txt is resolved by hand, on whatever interpreter the author had.

    Conditional dependencies are the trap. `build` and `hatchling` need `tomli` only before 3.11, so
    a file resolved on a newer Python silently omits it and everything looks fine until the release
    itself fails on the oldest supported version, at the point where failing is most expensive. CI
    resolves it on the floor version so that happens on a pull request instead.
    """
    import re
    import yaml
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    jobs = ci["jobs"]
    candidates = [
        j for j in jobs.values()
        if "requirements-build.txt" in "\n".join(str(s.get("run", "")) for s in j.get("steps", []))
    ]
    assert candidates, "no CI job resolves the frozen build toolchain"

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    floor = re.search(r'requires-python = ">=(\d+\.\d+)"', pyproject).group(1)
    versions = set()
    for job in candidates:
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        versions |= {str(v) for v in matrix.get("python", [])}
        for step in job.get("steps", []):
            v = (step.get("with") or {}).get("python-version")
            if v and "${{" not in str(v):
                versions.add(str(v))

    claimed = set(re.findall(r'"Programming Language :: Python :: (\d+\.\d+)"', pyproject))
    assert versions == claimed, (
        f"the toolchain is resolved on {sorted(versions)} but support is claimed for "
        f"{sorted(claimed)}; a dependency conditional on any of the untested ones stays invisible "
        f"until a release"
    )
    assert floor in versions

    runs = "\n".join(
        str(s.get("run", "")) for j in candidates for s in j.get("steps", [])
    )
    assert "--require-hashes" in runs and "--no-isolation" in runs


def test_the_frozen_toolchain_carries_the_dependency_older_pythons_need() -> None:
    """A regression with a name. This exact entry was missing, and its absence was invisible on a
    modern interpreter: the marker means it is skipped there, so only 3.10 ever noticed."""
    reqs = (ROOT / "requirements-build.txt").read_text(encoding="utf-8")
    assert "tomli==" in reqs, "build and hatchling need tomli before 3.11"
    line = next(l for l in reqs.splitlines() if l.startswith("tomli=="))
    assert 'python_version < "3.11"' in line, "it must be conditional, not installed everywhere"
