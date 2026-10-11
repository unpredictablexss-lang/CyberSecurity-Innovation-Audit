"""Controlled DelayedSingleton shared_ptr race PoC and TSan validation.

This family runner verifies pinned local Git objects, materializes only the
required headers into isolated temporary/output directories, builds a
self-authored harness and records vulnerable/fixed/patched outcomes. It never
fetches, checks out, edits the source repository or targets remote services.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from src.ohscanner.git_source import (
    GitSource,
    load_git_sources,
    resolve_commit,
    verify_repository_identity,
)


REPOSITORY = "openharmony/commonlibrary_c_utils"
VULNERABLE_COMMIT = "bdfafdaafddb01ab7ae13354ce2ada9555d7935c"
FIXED_COMMIT = "9a3f281120307ec7dcce17fae882dcc4e6a6f4d7"
SOURCE_PATHS = ("base/include/nocopyable.h", "base/include/singleton.h")
HARNESS_PATH = (
    Path(__file__).resolve().parent
    / "templates"
    / "cpp_shared_ptr_race_harness.cpp"
)
EXPECTED_REVISIONS = {
    "vulnerable": {
        "commit": VULNERABLE_COMMIT,
        "git_tree": "b3ec65d247c4ca1ff07318fa72c0daa368128563",
        "sources": {
            "base/include/nocopyable.h": {
                "blob_oid": "75876b5dfba53d00ed2c30151a8f6a5ec629ac80",
                "source_sha256": "388f5c506f925f6f4fbe00e9937c4ff2550a65a4058a57fe110f54735579a30e",
            },
            "base/include/singleton.h": {
                "blob_oid": "0e0c91010e39558202ab1c7f628c618fd7a09d23",
                "source_sha256": "ce04ace5a2ad702d3f56e30be347dc9583c808dcf5aac80ee761bd70e05f1ad4",
            },
        },
    },
    "fixed": {
        "commit": FIXED_COMMIT,
        "git_tree": "69fbea434f22e2174a4dd79dff6ad25833e0ea49",
        "sources": {
            "base/include/nocopyable.h": {
                "blob_oid": "75876b5dfba53d00ed2c30151a8f6a5ec629ac80",
                "source_sha256": "388f5c506f925f6f4fbe00e9937c4ff2550a65a4058a57fe110f54735579a30e",
            },
            "base/include/singleton.h": {
                "blob_oid": "fb65b4d89ff9c60c54bc6a8e106b06935f23f633",
                "source_sha256": "9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606",
            },
        },
    },
}
TSAN_MARKERS = (
    "WARNING: ThreadSanitizer:",
    "SUMMARY: ThreadSanitizer:",
    "ERROR: ThreadSanitizer:",
)


@dataclass(frozen=True)
class BuildRecord:
    revision: str
    command: Tuple[str, ...]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    outcome: str
    peak_rss_upper_bound_kb: Optional[int] = None


@dataclass(frozen=True)
class RunRecord:
    revision: str
    repeat: int
    command: Tuple[str, ...]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    timed_out: bool
    sanitizer_detected: bool
    race_detected: bool
    use_after_free_detected: bool
    outcome: str
    log_sha256: str
    peak_rss_upper_bound_kb: Optional[int] = None


@dataclass(frozen=True)
class RevisionValidation:
    revision: str
    role: str
    commit: str
    git_tree: str
    source_binding: Mapping[str, Mapping[str, str]]
    build: BuildRecord
    runs: Tuple[RunRecord, ...]
    status: str
    trigger_count: int
    interpretation: str


@dataclass(frozen=True)
class SharedPtrRacePoCResult:
    schema_version: int
    package_id: str
    repository: str
    binding_status: str
    binding_manifest_sha256: str
    harness_sha256: str
    environment: Mapping[str, str]
    repeats: int
    revisions: Mapping[str, RevisionValidation]
    poc_state: str
    patch_revalidation: str
    interpretation: str
    limitations: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "package_id": self.package_id,
            "repository": self.repository,
            "binding_status": self.binding_status,
            "binding_manifest_sha256": self.binding_manifest_sha256,
            "harness_sha256": self.harness_sha256,
            "environment": dict(self.environment),
            "repeats": self.repeats,
            "revisions": {
                name: {
                    **asdict(value),
                    "build": asdict(value.build),
                    "runs": [asdict(run) for run in value.runs],
                    "source_binding": {
                        path: dict(binding)
                        for path, binding in value.source_binding.items()
                    },
                }
                for name, value in self.revisions.items()
            },
            "poc_state": self.poc_state,
            "patch_revalidation": self.patch_revalidation,
            "interpretation": self.interpretation,
            "limitations": list(self.limitations),
        }


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def binding_manifest_sha256(value: Mapping[str, object]) -> str:
    return sha256_text(canonical_json(value))


def detect_tsan(text: str) -> Tuple[bool, bool, bool]:
    lowered = text.lower()
    sanitizer = any(marker.lower() in lowered for marker in TSAN_MARKERS)
    race = sanitizer and ("data race" in lowered or "threadsanitizer: data race" in lowered)
    use_after_free = sanitizer and (
        "heap-use-after-free" in lowered or "use-after-free" in lowered
    )
    return sanitizer, race, use_after_free


def build_poc_binding(repo: Path, repository: str = REPOSITORY) -> Dict[str, object]:
    verify_repository_identity(repo, repository)
    revisions: Dict[str, object] = {}
    for role, expected in EXPECTED_REVISIONS.items():
        commit, tree = resolve_commit(repo, expected["commit"])
        if tree != expected["git_tree"]:
            raise ValueError(f"{role} Git tree mismatch")
        sources: Dict[str, object] = {}
        loaded = {
            item.path: item
            for item in load_git_sources(repo, commit, SOURCE_PATHS)[2]
        }
        for path, expected_source in expected["sources"].items():
            source = loaded.get(path)
            if not isinstance(source, GitSource):
                raise ValueError(f"missing pinned source: {path}")
            actual_hash = sha256_bytes(source.data)
            if source.oid != expected_source["blob_oid"]:
                raise ValueError(f"{role} blob mismatch: {path}")
            if actual_hash != expected_source["source_sha256"]:
                raise ValueError(f"{role} source hash mismatch: {path}")
            sources[path] = {
                "blob_oid": source.oid,
                "source_sha256": actual_hash,
            }
        revisions[role] = {
            "commit": commit,
            "git_tree": tree,
            "sources": sources,
        }
    return {
        "schema_version": 1,
        "kind": "cpp_shared_ptr_race_poc_binding",
        "repository": repository,
        "source_paths": list(SOURCE_PATHS),
        "revisions": revisions,
    }


def verify_poc_binding(binding: Mapping[str, object], binding_sha256: str) -> None:
    if binding_manifest_sha256(binding) != binding_sha256:
        raise ValueError("PoC binding manifest hash mismatch")
    if binding.get("kind") != "cpp_shared_ptr_race_poc_binding":
        raise ValueError("unsupported PoC binding kind")
    if binding.get("repository") != REPOSITORY:
        raise ValueError("PoC binding repository mismatch")
    if tuple(binding.get("source_paths", ())) != SOURCE_PATHS:
        raise ValueError("PoC binding source paths mismatch")
    revisions = binding.get("revisions")
    if not isinstance(revisions, Mapping):
        raise ValueError("PoC binding revisions are required")
    for role, expected in EXPECTED_REVISIONS.items():
        record = revisions.get(role)
        if not isinstance(record, Mapping):
            raise ValueError(f"missing PoC binding revision: {role}")
        if record.get("commit") != expected["commit"] or record.get("git_tree") != expected["git_tree"]:
            raise ValueError(f"PoC binding revision identity mismatch: {role}")
        sources = record.get("sources")
        if not isinstance(sources, Mapping):
            raise ValueError(f"PoC binding sources missing: {role}")
        for path, expected_source in expected["sources"].items():
            if sources.get(path) != expected_source:
                raise ValueError(f"PoC binding source mismatch: {role}:{path}")


def _run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: Optional[Mapping[str, str]] = None,
) -> Tuple[Optional[int], float, str, str, bool, Optional[int]]:
    started = time.perf_counter()
    try:
        process = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(env or os.environ),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        peak_rss = None
        try:
            import resource

            peak_rss = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        except (ImportError, AttributeError):
            peak_rss = None
        return (
            process.returncode,
            time.perf_counter() - started,
            process.stdout,
            process.stderr,
            False,
            peak_rss,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        return None, time.perf_counter() - started, stdout, stderr, True, None


def environment_fingerprint(compiler: str) -> Dict[str, str]:
    compiler_version = ""
    try:
        compiler_version = subprocess.run(
            [compiler, "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        ).stdout.splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        compiler_version = "unavailable"
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "compiler": compiler,
        "compiler_version": compiler_version,
        "sanitizer": "ThreadSanitizer",
    }


def _write_sources(target: Path, sources: Mapping[str, GitSource]) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for path in SOURCE_PATHS:
        source = sources[path]
        destination = target / Path(path).name
        destination.write_bytes(source.data)


def _build_revision(
    revision: str,
    target: Path,
    compiler: str,
    build_timeout: float,
) -> BuildRecord:
    binary = target / f"{revision}_harness"
    command = (
        compiler,
        "-std=c++17",
        "-fsanitize=thread",
        "-O1",
        "-g",
        "-pthread",
        "-I",
        str(target),
        str(HARNESS_PATH),
        "-o",
        str(binary),
    )
    exit_code, elapsed, stdout, stderr, timed_out, peak_rss = _run_process(
        command, cwd=target, timeout=build_timeout
    )
    if timed_out:
        outcome = "build_timeout"
    elif exit_code == 0:
        outcome = "build_success"
    else:
        outcome = "build_failed"
    return BuildRecord(
        revision=revision,
        command=tuple(command),
        exit_code=exit_code,
        elapsed_seconds=elapsed,
        stdout=stdout,
        stderr=stderr,
        outcome=outcome,
        peak_rss_upper_bound_kb=peak_rss,
    )


def classify_runs(
    role: str,
    build: BuildRecord,
    runs: Sequence[RunRecord],
) -> Tuple[str, int]:
    if build.outcome != "build_success":
        return "build_failed", 0
    if not runs:
        return "not_run", 0
    triggers = sum(1 for run in runs if run.sanitizer_detected)
    if role == "vulnerable":
        if triggers == len(runs):
            return "stable_reproduced", triggers
        if triggers:
            return "flaky_trigger", triggers
        return "no_trigger", triggers
    if triggers:
        return "patch_revalidation_failed", triggers
    if all(run.outcome == "clean" for run in runs):
        return "patch_revalidation_passed", triggers
    return "inconclusive", triggers


def validate_materialized_revision(
    *,
    role: str,
    revision: str,
    commit: str,
    git_tree: str,
    source_binding: Mapping[str, Mapping[str, str]],
    target: Path,
    compiler: str,
    repeats: int,
    build_timeout: float,
    run_timeout: float,
    use_setarch: bool,
    log_dir: Path,
) -> RevisionValidation:
    build = _build_revision(revision, target, compiler, build_timeout)
    runs: List[RunRecord] = []
    if build.outcome == "build_success":
        binary = target / f"{revision}_harness"
        base_command = [str(binary)]
        if use_setarch:
            base_command = ["setarch", platform.machine(), "-R", *base_command]
        runtime_env = dict(os.environ)
        runtime_env["TSAN_OPTIONS"] = "halt_on_error=0:exitcode=66:history_size=7"
        log_dir.mkdir(parents=True, exist_ok=True)
        for index in range(1, repeats + 1):
            command = [*base_command]
            exit_code, elapsed, stdout, stderr, timed_out, peak_rss = _run_process(
                command, cwd=target, timeout=run_timeout, env=runtime_env
            )
            sanitizer, race, use_after_free = detect_tsan(stderr)
            if timed_out:
                outcome = "timeout"
            elif sanitizer:
                outcome = "sanitizer_triggered"
            elif exit_code == 0:
                outcome = "clean"
            else:
                outcome = "nonzero_exit"
            log_text = (
                f"command={shlex.join(command)}\nexit_code={exit_code}\n"
                f"elapsed_seconds={elapsed:.6f}\n--- stdout ---\n{stdout}"
                f"\n--- stderr ---\n{stderr}"
            )
            log_path = log_dir / f"{revision}-{index:02d}.log"
            log_path.write_text(log_text, encoding="utf-8")
            runs.append(
                RunRecord(
                    revision=revision,
                    repeat=index,
                    command=tuple(command),
                    exit_code=exit_code,
                    elapsed_seconds=elapsed,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=timed_out,
                    sanitizer_detected=sanitizer,
                    race_detected=race,
                    use_after_free_detected=use_after_free,
                    outcome=outcome,
                    log_sha256=sha256_text(log_text),
                    peak_rss_upper_bound_kb=peak_rss,
                )
            )
    status, trigger_count = classify_runs(role, build, runs)
    if role == "vulnerable":
        interpretation = (
            "Pinned component API-level concurrency reproduction only; this does "
            "not establish product entry-point reachability or attacker control."
        )
    else:
        interpretation = (
            "The same controlled harness did not trigger on this revision. This is "
            "patch revalidation evidence, not proof of universal safety."
        )
    return RevisionValidation(
        revision=revision,
        role=role,
        commit=commit,
        git_tree=git_tree,
        source_binding=source_binding,
        build=build,
        runs=tuple(runs),
        status=status,
        trigger_count=trigger_count,
        interpretation=interpretation,
    )


def validate_shared_ptr_race(
    *,
    repo: Path,
    output_dir: Path,
    repeats: int = 3,
    compiler: str = "clang++",
    build_timeout: float = 60.0,
    run_timeout: float = 15.0,
    use_setarch: bool = True,
) -> SharedPtrRacePoCResult:
    if repeats < 1:
        raise ValueError("repeats must be >= 1")
    repo = repo.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    binding = build_poc_binding(repo)
    binding_hash = binding_manifest_sha256(binding)
    verify_poc_binding(binding, binding_hash)
    harness_sha256 = sha256_bytes(HARNESS_PATH.read_bytes())

    loaded = {
        role: {
            item.path: item
            for item in load_git_sources(repo, expected["commit"], SOURCE_PATHS)[2]
        }
        for role, expected in EXPECTED_REVISIONS.items()
    }
    revision_specs = {
        "vulnerable": ("vulnerable", loaded["vulnerable"]),
        "fixed": ("fixed", loaded["fixed"]),
        "patched": ("patched", {
            "base/include/nocopyable.h": loaded["vulnerable"]["base/include/nocopyable.h"],
            "base/include/singleton.h": loaded["fixed"]["base/include/singleton.h"],
        }),
    }
    validations: Dict[str, RevisionValidation] = {}
    for revision, (role, sources) in revision_specs.items():
        expected = EXPECTED_REVISIONS["fixed" if role == "fixed" else "vulnerable"]
        source_binding = {
            "base/include/nocopyable.h": dict(
                EXPECTED_REVISIONS["vulnerable"]["sources"]["base/include/nocopyable.h"]
            ),
            "base/include/singleton.h": dict(
                EXPECTED_REVISIONS[
                    "fixed" if revision in {"fixed", "patched"} else "vulnerable"
                ]["sources"]["base/include/singleton.h"]
            ),
        }
        target = output_dir / "build" / revision
        if target.exists():
            shutil.rmtree(target)
        _write_sources(target, sources)
        validations[revision] = validate_materialized_revision(
            role=role,
            revision=revision,
            commit=expected["commit"],
            git_tree=expected["git_tree"],
            source_binding=source_binding,
            target=target,
            compiler=compiler,
            repeats=repeats,
            build_timeout=build_timeout,
            run_timeout=run_timeout,
            use_setarch=use_setarch,
            log_dir=output_dir / "logs" / revision,
        )

    vulnerable = validations["vulnerable"]
    fixed = validations["fixed"]
    patched = validations["patched"]
    patch_revalidation = (
        "passed"
        if fixed.status == "patch_revalidation_passed"
        and patched.status == "patch_revalidation_passed"
        else fixed.status
    )
    if vulnerable.status == "stable_reproduced" and patch_revalidation == "passed":
        poc_state = "stable_reproduced"
    elif vulnerable.trigger_count:
        poc_state = "trigger_success"
    else:
        poc_state = "run_success"
    limitations = (
        "The source binding is generated from pinned local Git objects but remains draft until an independent evaluator pins its hash.",
        "API-level concurrent use is reproduced; product-level caller, privilege boundary and attacker control remain unproven.",
        "A clean fixed/patched run is not a proof of safety and does not replace independent holdout evaluation.",
    )
    return SharedPtrRacePoCResult(
        schema_version=1,
        package_id="teammate-a-cpp-shared-ptr-race-poc",
        repository=REPOSITORY,
        binding_status="draft_unpinned",
        binding_manifest_sha256=binding_hash,
        harness_sha256=harness_sha256,
        environment=environment_fingerprint(compiler),
        repeats=repeats,
        revisions=validations,
        poc_state=poc_state,
        patch_revalidation=patch_revalidation,
        interpretation=(
            "Controlled local TSan evidence for one pinned historical C++ component "
            "case; not an exploit and not a product vulnerability verdict."
        ),
        limitations=limitations,
    )


def render_markdown(result: SharedPtrRacePoCResult) -> str:
    lines = [
        "# DelayedSingleton shared_ptr race PoC validation",
        "",
        "> Controlled local component-level dynamic evidence only.",
        "",
        f"- Repository: `{result.repository}`",
        f"- Binding status: `{result.binding_status}`",
        f"- Binding manifest SHA-256: `{result.binding_manifest_sha256}`",
        f"- Harness SHA-256: `{result.harness_sha256}`",
        f"- PoC state: `{result.poc_state}`",
        f"- Patch revalidation: `{result.patch_revalidation}`",
        f"- Repeats: `{result.repeats}`",
        "",
        "## Environment",
        "",
    ]
    lines.extend(f"- {key}: `{value}`" for key, value in sorted(result.environment.items()))
    lines.extend(["", "## Revisions", ""])
    revision_order = ("vulnerable", "fixed", "patched")
    for name in [item for item in revision_order if item in result.revisions]:
        revision = result.revisions[name]
        lines.extend(
            [
                f"### {name}",
                "",
                f"- Role: `{revision.role}`",
                f"- Commit: `{revision.commit}`",
                f"- Git tree: `{revision.git_tree}`",
                f"- Status: `{revision.status}`",
                f"- Triggered runs: `{revision.trigger_count}/{len(revision.runs)}`",
                f"- Build: `{revision.build.outcome}`",
                f"- Build elapsed: `{revision.build.elapsed_seconds:.6f}`",
            ]
        )
        for run in revision.runs:
            lines.append(
                f"- Run {run.repeat}: `{run.outcome}`, exit={run.exit_code}, "
                f"race={run.race_detected}, uaf={run.use_after_free_detected}, "
                f"log_sha256=`{run.log_sha256}`"
            )
        lines.extend(["", revision.interpretation, ""])
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in result.limitations)
    return "\n".join(lines) + "\n"


def write_reports(result: SharedPtrRacePoCResult, json_out: Path, md_out: Path) -> None:
    if json_out.resolve() == md_out.resolve():
        raise ValueError("JSON and Markdown output paths must differ")
    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md_out.write_text(render_markdown(result), encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--compiler", default="clang++")
    parser.add_argument("--build-timeout", type=float, default=60.0)
    parser.add_argument("--run-timeout", type=float, default=15.0)
    parser.add_argument("--no-setarch", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    result = validate_shared_ptr_race(
        repo=args.repo_root,
        output_dir=args.output_dir,
        repeats=args.repeats,
        compiler=args.compiler,
        build_timeout=args.build_timeout,
        run_timeout=args.run_timeout,
        use_setarch=not args.no_setarch,
    )
    write_reports(
        result,
        args.output_dir / "poc-validation.json",
        args.output_dir / "poc-validation.md",
    )
    (args.output_dir / "poc-binding-draft.json").write_text(
        json.dumps(build_poc_binding(args.repo_root), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[OK] PoC state: {result.poc_state}")
    print(f"[OK] Patch revalidation: {result.patch_revalidation}")
    print(f"[OK] Binding manifest SHA-256: {result.binding_manifest_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
