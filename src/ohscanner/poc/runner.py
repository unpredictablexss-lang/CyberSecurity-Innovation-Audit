"""Isolated build-and-run driver for a family PoC.

The driver compiles a harness together with the pinned revision of the target
translation unit, runs it under a sanitizer, classifies what happened, replays
the triggering case for stability, and records everything. It never touches a
live service: the target is a local scratch copy built from a local object store.
"""
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .reachability import verify as verify_reachability
from .records import BuildRecord, CaseOutcome, PatchRevalidation, PocResult, RevisionRun
from .sources import materialize, pinned_files
from .states import evidence_for, ladder_state, replay_label

SANITIZER_MARKERS = ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:")
SIGNAL = re.compile(r"([A-Za-z_]\w*)=(-?\d+)")
DEFAULT_CUTILS = Path.home() / "openharmony-targets" / "commonlibrary_c_utils"


def _run(command, cwd, timeout, env=None):
    return subprocess.run(list(command), cwd=str(cwd), env=env, text=True,
                          capture_output=True, timeout=timeout, check=False)


def _first_line(text):
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def environment_fingerprint(compiler, sanitizers, source_origin):
    """What the result must be read against: toolchain, platform, source origin."""
    version = _run([compiler, "--version"], cwd=".", timeout=60)
    return {
        "compiler": compiler,
        "compiler_version": _first_line(version.stdout) or _first_line(version.stderr),
        "sanitizers": list(sanitizers),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "source_origin": source_origin,
        "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def parse_signals(stdout):
    """Last `key=value` group the harness printed, as integers."""
    signals = {}
    for line in (stdout or "").splitlines():
        found = SIGNAL.findall(line)
        if found:
            signals = {key: int(value) for key, value in found}
    return signals


def classify_case(stdout, stderr, signals, observable):
    """`crash` beats everything: a sanitizer report is not a clean outcome."""
    combined = (stdout or "") + "\n" + (stderr or "")
    if any(marker in combined for marker in SANITIZER_MARKERS):
        return "crash"
    field = str(observable["field"])
    minimum = int(observable.get("trigger_min", 1))
    return "trigger" if signals.get(field, 0) >= minimum else "no_trigger"


def build_revision(manifest, harness_dir, revision, component_root, binary_dir,
                   compiler, cutils_dir, timeout=300):
    """Compile one pinned revision; returns a BuildRecord either way."""
    entry = manifest["revisions"][revision]
    source = next(item for item in manifest["sources"] if item["revision"] == revision)
    return build_translation_unit(
        manifest, harness_dir, label=revision, commit=entry["commit"],
        source_path=source["path"], source_sha256=source["sha256"],
        component_root=component_root, binary_dir=binary_dir, compiler=compiler,
        cutils_dir=cutils_dir, timeout=timeout)


def build_translation_unit(manifest, harness_dir, *, label, commit, source_path, source_sha256,
                           component_root, binary_dir, compiler, cutils_dir, timeout=300):
    """Compile one translation unit against the harness; returns a BuildRecord either way.

    `label` names the output binary and the record. It is separate from the commit
    so a derived revision (a patched copy of a pinned one) can be built through the
    same path without pretending to be a commit that does not exist.
    """
    support = manifest.get("support_sources", {}).get("parcel", {})
    support_files = [cutils_dir / name for name in support.get("files", ())]
    support_includes = [cutils_dir / name for name in support.get("include_dirs", ())]

    flags = list(manifest.get("compile_flags", ("-std=c++17", "-g", "-O1")))
    flags.append("-fsanitize=" + ",".join(manifest["sanitizers"]))
    binary = Path(binary_dir) / ("poc_" + label)

    command = [compiler, *flags,
               "-include", str(Path(harness_dir) / "poc_compat.h"),
               "-I", str(Path(harness_dir) / "stub"),
               "-I", str(harness_dir),
               "-I", str(Path(component_root) / "services" / "include"),
               *[item for path in support_includes for item in ("-I", str(path))],
               str(Path(component_root) / source_path),
               *[str(path) for path in support_files],
               str(Path(harness_dir) / "stubs.cpp"),
               str(Path(harness_dir) / "harness.cpp"),
               "-o", str(binary)]

    result = _run(command, cwd=harness_dir, timeout=timeout)
    return BuildRecord(
        revision=label, commit=commit,
        source_sha256=(source_sha256,),
        compiler=compiler,
        compiler_version=environment_fingerprint(compiler, manifest["sanitizers"], "")["compiler_version"],
        sanitizers=tuple(manifest["sanitizers"]),
        command=tuple(command), returncode=result.returncode,
        stdout=result.stdout[-4000:], stderr=result.stderr[-4000:],
        binary=str(binary))


def run_case(binary, case, observable, timeout=60):
    env = {"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
           "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
           "PATH": "/usr/bin:/bin"}
    result = _run([binary, *case["args"]], cwd=Path(binary).parent, timeout=timeout, env=env)
    signals = parse_signals(result.stdout)
    return CaseOutcome(
        case_id=case["id"], role=case.get("role", ""), args=tuple(case["args"]),
        returncode=result.returncode, signals=signals,
        verdict=classify_case(result.stdout, result.stderr, signals, observable),
        stdout=result.stdout[-4000:], stderr=result.stderr[-4000:])


def _expectation_met(case, revision, verdict):
    expected = case.get("expect", {}).get(revision, "any")
    return True if expected == "any" else verdict == expected


def apply_patch(component_root, patch_file, timeout=120):
    """Apply a harness-supplied patch to a scratch copy of the source.

    `--batch` keeps the call non-interactive and `--forward` makes a reversed or
    already-applied patch fail loudly instead of being silently undone.
    """
    return _run(["patch", "--batch", "--forward", "-p1", "-i", str(patch_file)],
                cwd=component_root, timeout=timeout)


def patch_revalidation_state(*, applied, build, expectations):
    """Whether a patch revalidation passed, judged only on recorded evidence.

    A build that succeeded but changed nothing is not a pass: every case must meet
    the equivalent revision's expectation, and that set includes the positive
    control, so a patch that simply rejects everything fails here rather than
    looking like a fix.
    """
    if not applied:
        return "not_applied"
    if build is None or not build.ok:
        return "build_failed"
    if not expectations:
        return "run_failed"
    return "passed" if all(expectations.values()) else "failed"


def _revalidate_patch(manifest, entry, harness_dir, work_dir, binary_dir, compiler,
                      cutils_dir, build_timeout, run_timeout):
    """Patch the vulnerable revision, rebuild it, re-run every case, judge the result."""
    applies_to = entry.get("applies_to", "vulnerable")
    source = next(item for item in manifest["sources"] if item["revision"] == applies_to)
    patched_root = Path(work_dir) / "component" / "patched"
    if patched_root.exists():
        shutil.rmtree(patched_root)
    shutil.copytree(Path(work_dir) / "component" / applies_to, patched_root)

    applied = apply_patch(patched_root, Path(harness_dir) / entry["file"], timeout=build_timeout)
    ok = applied.returncode == 0

    patched_sha256 = ""
    build = None
    cases, expectations = [], {}
    if ok:
        patched_sha256 = hashlib.sha256((patched_root / source["path"]).read_bytes()).hexdigest()
        build = build_translation_unit(
            manifest, harness_dir, label="patched",
            commit=manifest["revisions"][applies_to]["commit"],
            source_path=source["path"], source_sha256=source["sha256"],
            component_root=patched_root, binary_dir=binary_dir, compiler=compiler,
            cutils_dir=cutils_dir, timeout=build_timeout)
        if build.ok:
            equivalent = entry.get("expected_equivalent_revision", "fixed")
            for case in manifest["cases"]:
                outcome = run_case(build.binary, case, manifest["observable"], timeout=run_timeout)
                cases.append(outcome)
                expectations[outcome.case_id] = _expectation_met(case, equivalent, outcome.verdict)

    return PatchRevalidation(
        patch_id=entry["id"], applies_to=applies_to, file=entry["file"],
        rationale=entry.get("rationale", ""), applied=ok, patched_sha256=patched_sha256,
        apply_stdout=applied.stdout[-4000:], apply_stderr=applied.stderr[-4000:],
        build=build, cases=tuple(cases), expectations_met=expectations,
        state=patch_revalidation_state(applied=ok, build=build, expectations=expectations))


def run_poc(manifest_path, git_dir, work_dir, compiler="clang++", cutils_dir=None,
            repeats=3, build_timeout=300, run_timeout=60):
    """Build every revision, run every case, replay the attack cases, record."""
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    harness_dir = manifest_path.parent
    cutils_dir = Path(cutils_dir or DEFAULT_CUTILS)
    work_dir = Path(work_dir)
    binary_dir = work_dir / "bin"
    binary_dir.mkdir(parents=True, exist_ok=True)

    headers = pinned_files(manifest["headers"])
    observable = manifest["observable"]
    revisions = {}
    for revision in manifest["revisions"]:
        # Each revision gets its own root: the two revisions of the same file sit
        # at the same path, so a shared root would silently compile whichever was
        # written last.
        component_root = work_dir / "component" / revision
        revision_sources = pinned_files(
            [item for item in manifest["sources"] if item["revision"] == revision],
            revision_field=True)
        materialize(revision_sources + headers, git_dir, component_root)

        build = build_revision(manifest, harness_dir, revision, component_root,
                               binary_dir, compiler, cutils_dir, timeout=build_timeout)
        cases, expectations = [], {}
        if build.ok:
            for case in manifest["cases"]:
                outcome = run_case(build.binary, case, observable, timeout=run_timeout)
                cases.append(outcome)
                expectations[outcome.case_id] = _expectation_met(case, revision, outcome.verdict)

        attack = [outcome for outcome in cases if outcome.role == "attack"]
        # Replay only the cases this revision is expected to trigger on. Replaying
        # a case that is meant to be rejected would report a stable trigger as
        # "flaky", which is a measurement artefact rather than a property of the
        # target.
        replayable = [case for case in manifest["cases"]
                      if case.get("role") == "attack"
                      and case.get("expect", {}).get(revision) == "trigger"]
        attempts = tuple(
            run_case(build.binary, case, observable, timeout=run_timeout).verdict == "trigger"
            for case in replayable
            for _ in range(max(1, repeats)))
        label = replay_label(attempts) if attempts else "no_trigger"
        revisions[revision] = RevisionRun(
            revision=revision, commit=manifest["revisions"][revision]["commit"],
            state=ladder_state(generated=True, built=build.ok, ran=bool(cases),
                               triggered=any(o.verdict == "trigger" for o in attack),
                               stable=label == "stable_reproduced"),
            build=build, cases=tuple(cases),
            replay={"label": label, "attempts": len(attempts),
                    "triggered": sum(1 for item in attempts if item)},
            expectations_met=expectations)

    vulnerable = revisions.get("vulnerable")
    expected_trigger = manifest["revisions"].get("vulnerable", {}).get("expected") == "trigger"
    triggered = bool(expected_trigger and vulnerable and
                     any(case.verdict == "trigger" for case in vulnerable.cases
                         if case.role == "attack"))
    stable = bool(vulnerable and vulnerable.replay.get("label") == "stable_reproduced")
    built = all(run.build.ok for run in revisions.values())
    ran = all(len(run.cases) == len(manifest["cases"]) for run in revisions.values())
    state = ladder_state(generated=True, built=built, ran=ran, triggered=triggered, stable=stable)

    revalidation = None
    if manifest.get("patch") and "vulnerable" in revisions:
        revalidation = _revalidate_patch(manifest, manifest["patch"], harness_dir, work_dir,
                                         binary_dir, compiler, cutils_dir, build_timeout, run_timeout)

    return PocResult(
        schema_version=1, family=manifest["family"], family_name=manifest["family_name"],
        harness=manifest["harness"], root_cause_instance_id=manifest["root_cause_instance_id"],
        repository=manifest["repository"], pr_url=manifest["pr_url"],
        reported_symbol=manifest["reported_symbol"], candidate_cwe=manifest["candidate_cwe"],
        environment=environment_fingerprint(compiler, manifest["sanitizers"],
                                            manifest["source_origin"]),
        revisions=revisions, state=state, evidence_level=evidence_for(state),
        validated_vulnerability=0,
        limitations=tuple(manifest["known_limitations"]),
        reachability=verify_reachability(manifest.get("reachability"), git_dir),
        patch_revalidation=revalidation)
