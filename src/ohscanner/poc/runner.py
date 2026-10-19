"""Isolated build-and-run driver for a family PoC.

The driver compiles a harness together with the pinned revision of the target
translation unit, runs it under a sanitizer, classifies what happened, replays
the triggering case for stability, and records everything. It never touches a
live service: the target is a local scratch copy built from a local object store.
"""
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

from .reachability import verify as verify_reachability
from .records import BuildRecord, CaseOutcome, PocResult, RevisionRun
from .sources import materialize, pinned_files
from .states import classify_expected_replay, evidence_for, ladder_state, replay_label

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
    commit = entry["commit"]
    source = next(item for item in manifest["sources"] if item["revision"] == revision)
    support = manifest.get("support_sources", {}).get("parcel", {})
    support_files = [cutils_dir / name for name in support.get("files", ())]
    support_includes = [cutils_dir / name for name in support.get("include_dirs", ())]

    flags = list(manifest.get("compile_flags", ("-std=c++17", "-g", "-O1")))
    flags.append("-fsanitize=" + ",".join(manifest["sanitizers"]))
    binary = Path(binary_dir) / ("poc_" + revision)

    command = [compiler, *flags,
               "-include", str(Path(harness_dir) / "poc_compat.h"),
               "-I", str(Path(harness_dir) / "stub"),
               "-I", str(harness_dir),
               "-I", str(Path(component_root) / "services" / "include"),
               *[item for path in support_includes for item in ("-I", str(path))],
               str(Path(component_root) / source["path"]),
               *[str(path) for path in support_files],
               str(Path(harness_dir) / "stubs.cpp"),
               str(Path(harness_dir) / "harness.cpp"),
               "-o", str(binary)]

    result = _run(command, cwd=harness_dir, timeout=timeout)
    return BuildRecord(
        revision=revision, commit=commit,
        source_sha256=(source["sha256"],),
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


def run_poc(manifest_path, git_dir, work_dir, compiler="clang++", cutils_dir=None,
            harness_dir=None, repeats=3, build_timeout=300, run_timeout=60):
    """Build every revision and run it only inside the dedicated Docker worker."""
    if os.environ.get("OHSCANNER_VALIDATION_CONTAINER") != "1" or not Path("/.dockerenv").is_file():
        raise RuntimeError("PoC execution is restricted to the Docker validation container")
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    harness_dir = Path(harness_dir) if harness_dir is not None else manifest_path.parent
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
        replay_cases = [case for case in manifest["cases"]
                        if case.get("expect", {}).get(revision) in {"trigger", "no_trigger"}]
        replay_rows = []
        for case in replay_cases:
            expected = case["expect"][revision]
            observed = [run_case(build.binary, case, observable, timeout=run_timeout).verdict
                        for _ in range(max(1, repeats))]
            label, matches = classify_expected_replay(expected, observed)
            matches = list(matches)
            replay_rows.append({"case_id": case["id"], "role": case.get("role", ""),
                                "expected": expected, "observed": observed,
                                "matches_expectation": matches, "label": label})
        replay_ok = bool(replay_rows) and all(all(row["matches_expectation"]) for row in replay_rows)
        attack_replay = [row for row in replay_rows if row["role"] == "attack"]
        attack_expected = {row["expected"] for row in attack_replay}
        attack_ok = bool(attack_replay) and all(all(row["matches_expectation"]) for row in attack_replay)
        if attack_ok and attack_expected == {"trigger"}:
            label = "stable_reproduced"
        elif attack_ok and attack_expected == {"no_trigger"}:
            label = "stable_rejected"
        elif replay_ok:
            label = "no_attack_expectation"
        else:
            label = "expectation_failed"
        attempts = [value == "trigger" for row in replay_rows for value in row["observed"]]
        revisions[revision] = RevisionRun(
            revision=revision, commit=manifest["revisions"][revision]["commit"],
            state=ladder_state(generated=True, built=build.ok, ran=bool(cases),
                               triggered=any(o.verdict == "trigger" for o in attack),
                               stable=label == "stable_reproduced" and replay_ok),
            build=build, cases=tuple(cases),
            replay={"label": label, "attempts": len(attempts),
                    "triggered": sum(1 for item in attempts if item), "all_cases_match": replay_ok,
                    "cases": replay_rows},
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
        reachability=verify_reachability(manifest.get("reachability"), git_dir))
