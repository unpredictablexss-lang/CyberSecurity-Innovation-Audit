"""Source-bound controlled PoC for the DelayedSingleton shared_ptr race.

The runner verifies preserved vulnerable and fixed ``singleton.h`` bytes before
building a self-authored workload against those exact headers. It also derives
and revalidates a fully-atomic patch. All execution is local and isolated; no
live service is contacted.

The result remains candidate/unassessed. Dynamic reproduction establishes a
component-level race behavior only, not product reachability, attacker control,
security impact or a reportable vulnerability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence, Tuple

from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST = (
    Path(__file__).resolve().parent
    / "harnesses/cpp_shared_ptr_delayed_singleton/manifest.json"
)
DEFAULT_HARNESS = DEFAULT_MANIFEST.parent / "harness.cpp"
SOURCE_REVISIONS = ("vulnerable", "upstream_fix")
RUN_REVISIONS = ("vulnerable", "upstream_fix", "fully_atomic_patch")
TSAN_MARKERS = ("WARNING: ThreadSanitizer:", "SUMMARY: ThreadSanitizer:")


class SourceMismatch(ValueError):
    pass


@dataclass(frozen=True)
class SourceRecord:
    revision: str
    commit: str
    path: str
    sha256: str
    verified_sha256: str
    binding: str
    quotes: Tuple[str, ...]


@dataclass(frozen=True)
class BuildRecord:
    revision: str
    command: Tuple[str, ...]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    outcome: str


@dataclass(frozen=True)
class RunRecord:
    revision: str
    mode: str
    command: Tuple[str, ...]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    sanitizer_detected: bool
    outcome: str


@dataclass(frozen=True)
class SharedPtrRacePoCResult:
    package_id: str
    detector_id: str
    detector_version: str
    source_binding_status: str
    builds: Tuple[BuildRecord, ...]
    runs: Tuple[RunRecord, ...]
    repeats: int
    outcome: str
    sources: Mapping[str, SourceRecord] = field(default_factory=dict)
    environment: Mapping[str, object] = field(default_factory=dict)
    limitations: Tuple[str, ...] = ()
    detector_runs: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "package_id": self.package_id,
            "detector": {
                "id": self.detector_id,
                "version": self.detector_version,
                "rule_id": "ohcpp-shared-ptr-race-candidate-001",
            },
            "candidate_status": "candidate/unassessed",
            "candidate_cwe": "CWE-362",
            "possible_consequence_cwe": "CWE-416",
            "source_binding_status": self.source_binding_status,
            "sources": {
                name: asdict(record) for name, record in sorted(self.sources.items())
            },
            "environment": dict(self.environment),
            "builds": [asdict(item) for item in self.builds],
            "runs": [asdict(item) for item in self.runs],
            "repeats": self.repeats,
            "outcome": self.outcome,
            "evidence_level": "controlled_dynamic_reproduction",
            "validated_vulnerability": 0,
            "patch_revalidation": {
                "status": (
                    "passed"
                    if self.outcome
                    in {
                        "stable_reproduced_mixed_fix_residual",
                        "stable_reproduced_upstream_fix_clean",
                    }
                    else "failed_or_inconclusive"
                ),
                "variant": "fully_atomic_patch",
            },
            "limitations": list(self.limitations),
            "detector_runs": dict(self.detector_runs),
        }


def load_manifest(path: Path = DEFAULT_MANIFEST) -> Dict[str, object]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def verify_sources(
    manifest: Mapping[str, object], root: Path = ROOT
) -> Dict[str, SourceRecord]:
    root = Path(root)
    records: Dict[str, SourceRecord] = {}
    revisions = manifest["revisions"]
    for revision in SOURCE_REVISIONS:
        entry = revisions[revision]
        path = root / entry["path"]
        if not path.is_file():
            raise SourceMismatch(f"missing pinned source: {path}")
        data = path.read_bytes()
        actual = _sha256_bytes(data)
        if actual != entry["sha256"]:
            raise SourceMismatch(
                f"source SHA-256 mismatch for {revision}: "
                f"expected {entry['sha256']}, read {actual}"
            )
        text = data.decode("utf-8")
        quotes = tuple(entry.get("required_quotes", ()))
        missing = [quote for quote in quotes if quote not in text]
        if missing:
            raise SourceMismatch(
                f"source quote mismatch for {revision}: {missing!r}"
            )
        records[revision] = SourceRecord(
            revision=revision,
            commit=entry["commit"],
            path=entry["path"],
            sha256=entry["sha256"],
            verified_sha256=actual,
            binding="preserved_artifact_hash_verified",
            quotes=quotes,
        )
    return records


def run_detector_on_source(path: str, source: str) -> Dict[str, object]:
    unit = SourceUnit(
        path=path,
        language="cpp",
        text=source,
        sha256=_sha256_text(source),
        parse_status="complete",
    )
    run = SharedPtrRaceDetector().detect(None, (unit,))
    return {
        "detector_id": run.detector_id,
        "version": run.version,
        "status": run.status,
        "finding_count": len(run.findings),
        "findings": [
            {
                "line": finding.line,
                "column": finding.column,
                "rule_id": finding.rule_id,
                "candidate_cwe": finding.candidate_cwe,
                "symbol": finding.symbol,
                "source_sha256": finding.source_sha256,
                "evidence_obligations": [
                    {
                        "kind": obligation.kind,
                        "status": obligation.status,
                        "description": obligation.description,
                    }
                    for obligation in finding.evidence_obligations
                ],
            }
            for finding in run.findings
        ],
        "limitations": list(run.limitations),
    }


def patch_fixed_source(source: str) -> str:
    start = source.index(
        "std::shared_ptr<T> DelayedSingleton<T>::GetInstance()"
    )
    end = source.index("void DelayedSingleton<T>::DestroyInstance()", start)
    block = source[start:end]
    replacements = (
        ("if (instance_ == nullptr) {", "if (atomic_load(&instance_) == nullptr) {"),
        ("instance_ = temp;", "atomic_store(&instance_, temp);"),
        ("return instance_;", "return atomic_load(&instance_);"),
    )
    for old, new in replacements:
        if block.count(old) != 1:
            raise SourceMismatch(
                f"patch precondition changed: expected one {old!r}"
            )
        block = block.replace(old, new)
    return source[:start] + block + source[end:]


def _run_process(
    command: Sequence[str], cwd: Path, timeout: float, env: Optional[Dict[str, str]] = None
) -> Tuple[Optional[int], float, str, str, bool]:
    started = time.perf_counter()
    try:
        process = subprocess.run(
            list(command),
            cwd=str(cwd),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return (
            process.returncode,
            time.perf_counter() - started,
            process.stdout,
            process.stderr,
            False,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return None, time.perf_counter() - started, stdout, stderr, True


def _run_outcome(exit_code: Optional[int], stderr: str, timed_out: bool) -> Tuple[bool, str]:
    sanitizer = any(marker in stderr for marker in TSAN_MARKERS)
    if timed_out:
        return sanitizer, "timeout"
    if sanitizer:
        return True, "sanitizer_triggered"
    if exit_code == 0:
        return False, "clean"
    return False, "nonzero_exit"


def classify_runs(runs: Sequence[RunRecord], repeats: int) -> str:
    controls = [item for item in runs if item.mode == "single"]
    if (
        len(controls) != len(RUN_REVISIONS)
        or {item.revision for item in controls} != set(RUN_REVISIONS)
        or any(item.outcome != "clean" for item in controls)
    ):
        return "harness_invalid"

    races = [item for item in runs if item.mode == "race"]
    if repeats < 1 or len(races) != repeats * len(RUN_REVISIONS):
        return "inconclusive"
    if any(item.outcome == "timeout" for item in races):
        return "inconclusive"

    outcomes = {
        revision: {item.outcome for item in races if item.revision == revision}
        for revision in RUN_REVISIONS
    }
    if len(outcomes["vulnerable"]) != 1:
        return "unstable"
    if outcomes["vulnerable"] != {"sanitizer_triggered"}:
        return "not_reproduced"
    if outcomes["fully_atomic_patch"] != {"clean"}:
        return "patch_revalidation_failed"
    if outcomes["upstream_fix"] == {"sanitizer_triggered"}:
        return "stable_reproduced_mixed_fix_residual"
    if outcomes["upstream_fix"] == {"clean"}:
        return "stable_reproduced_upstream_fix_clean"
    return "unstable"


def _build(
    revision: str,
    source: Path,
    harness: Path,
    harness_dir: Path,
    binary: Path,
    compiler: str,
    timeout: float,
) -> BuildRecord:
    command = (
        compiler,
        "-std=c++17",
        "-g",
        "-O1",
        "-fno-omit-frame-pointer",
        "-fsanitize=thread",
        "-no-pie",
        "-I",
        str(source.parent),
        "-I",
        str(harness_dir),
        str(harness),
        "-lpthread",
        "-o",
        str(binary),
    )
    exit_code, elapsed, stdout, stderr, timed_out = _run_process(
        command, cwd=source.parent, timeout=timeout
    )
    outcome = "build_timeout" if timed_out else "build_success" if exit_code == 0 else "build_failed"
    return BuildRecord(
        revision=revision,
        command=command,
        exit_code=exit_code,
        elapsed_seconds=elapsed,
        stdout=stdout,
        stderr=stderr,
        outcome=outcome,
    )


def run_poc(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    harness: Path = DEFAULT_HARNESS,
    output: Path,
    root: Path = ROOT,
    compiler: str = "clang++",
    repeats: int = 3,
    readers: int = 4,
    iterations: int = 20000,
    build_timeout: float = 60.0,
    run_timeout: float = 120.0,
) -> SharedPtrRacePoCResult:
    manifest = load_manifest(manifest_path)
    source_records = verify_sources(manifest, root)
    harness = Path(harness).resolve()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    work = output / "work"
    work.mkdir(parents=True, exist_ok=True)

    source_paths: Dict[str, Path] = {
        revision: root / manifest["revisions"][revision]["path"]
        for revision in SOURCE_REVISIONS
    }
    source_texts = {
        revision: path.read_text(encoding="utf-8")
        for revision, path in source_paths.items()
    }
    patch_source = patch_fixed_source(source_texts["upstream_fix"])
    patched_path = work / "fully_atomic_patch" / "singleton.h"
    patched_path.parent.mkdir(parents=True, exist_ok=True)
    patched_path.write_text(patch_source, encoding="utf-8")
    source_paths["fully_atomic_patch"] = patched_path
    source_texts["fully_atomic_patch"] = patch_source
    detector_runs = {
        revision: run_detector_on_source(
            manifest["revisions"].get(revision, {}).get(
                "path", "generated/fully_atomic_patch/singleton.h"
            ),
            source_texts[revision],
        )
        for revision in RUN_REVISIONS
    }

    builds = []
    binaries: Dict[str, Path] = {}
    for revision in RUN_REVISIONS:
        revision_work = work / revision
        revision_work.mkdir(parents=True, exist_ok=True)
        include_dir = revision_work / "include"
        include_dir.mkdir(parents=True, exist_ok=True)
        installed_source = include_dir / "singleton.h"
        shutil.copyfile(source_paths[revision], installed_source)
        binary = revision_work / "poc"
        builds.append(
            _build(
                revision,
                installed_source,
                harness,
                harness.parent,
                binary,
                compiler,
                build_timeout,
            )
        )
        binaries[revision] = binary

    runs = []
    if all(item.outcome == "build_success" for item in builds):
        prefix = []
        setarch = shutil.which("setarch")
        if setarch:
            prefix = [setarch, platform.machine(), "-R"]
        env = dict(os.environ)
        env["TSAN_OPTIONS"] = "halt_on_error=1:second_deadlock_stack=1"

        def execute(revision: str, mode: str) -> None:
            command = prefix + [str(binaries[revision]), mode]
            if mode == "race":
                command += [str(readers), str(iterations)]
            exit_code, elapsed, stdout, stderr, timed_out = _run_process(
                command, cwd=work, timeout=run_timeout, env=env
            )
            sanitizer, outcome = _run_outcome(exit_code, stderr, timed_out)
            runs.append(
                RunRecord(
                    revision=revision,
                    mode=mode,
                    command=tuple(command),
                    exit_code=exit_code,
                    elapsed_seconds=elapsed,
                    stdout=stdout,
                    stderr=stderr,
                    sanitizer_detected=sanitizer,
                    outcome=outcome,
                )
            )

        for revision in RUN_REVISIONS:
            execute(revision, "single")
        if all(item.outcome == "clean" for item in runs):
            for _ in range(repeats):
                for revision in RUN_REVISIONS:
                    execute(revision, "race")

    if any(item.outcome != "build_success" for item in builds):
        outcome = "build_failed"
    elif any(item.outcome != "clean" for item in runs if item.mode == "single"):
        outcome = "harness_invalid"
    else:
        outcome = classify_runs(runs, repeats=repeats)

    compiler_version = subprocess.run(
        [compiler, "--version"], text=True, capture_output=True, check=False
    )
    environment = {
        "compiler": compiler,
        "compiler_version": (
            compiler_version.stdout or compiler_version.stderr
        ).splitlines()[0],
        "sanitizers": ["thread"],
        "platform": platform.platform(),
        "aslr_workaround": bool(shutil.which("setarch")),
        "readers": readers,
        "iterations": iterations,
    }
    limitations = tuple(manifest["known_limitations"])
    return SharedPtrRacePoCResult(
        package_id=manifest["package_id"],
        detector_id=manifest["detector_id"],
        detector_version=manifest["detector_version"],
        source_binding_status=manifest["source_binding_status"],
        builds=tuple(builds),
        runs=tuple(runs),
        repeats=repeats,
        outcome=outcome,
        sources=source_records,
        environment=environment,
        limitations=limitations,
        detector_runs=detector_runs,
    )


def write_reports(
    result: SharedPtrRacePoCResult, json_output: Path, markdown_output: Path
) -> None:
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# shared_ptr DelayedSingleton PoC",
        "",
        "> controlled component-level dynamic evidence；结果保持 candidate/unassessed。",
        "",
        f"- package: `{result.package_id}`",
        f"- detector: `{result.detector_id}` `{result.detector_version}`",
        f"- source binding: `{result.source_binding_status}`",
        f"- outcome: **{result.outcome}**",
        "- evidence level: `controlled_dynamic_reproduction`",
        "- `validated_vulnerability`: 0",
        "",
        "## Source binding",
        "",
    ]
    for name, source in sorted(result.sources.items()):
        lines.append(
            f"- `{name}`: commit `{source.commit}`, path `{source.path}`, "
            f"SHA-256 `{source.verified_sha256}`"
        )
    lines.extend(["", "## Builds", "", "| revision | outcome | exit |", "|---|---|---:|"])
    for build in result.builds:
        lines.append(
            f"| `{build.revision}` | {build.outcome} | {build.exit_code} |"
        )
    lines.extend(
        [
            "",
            "## Runtime",
            "",
            "| revision | mode | outcome | TSan |",
            "|---|---|---|---|",
        ]
    )
    for run in result.runs:
        lines.append(
            f"| `{run.revision}` | {run.mode} | {run.outcome} | "
            f"{run.sanitizer_detected} |"
        )
    lines.extend(["", "## Detector linkage", ""])
    for name, summary in sorted(result.detector_runs.items()):
        lines.append(
            f"- `{name}`: `{summary['detector_id']}` `{summary['version']}`, "
            f"status `{summary['status']}`, findings `{summary['finding_count']}`"
        )
    lines.extend(["", "## Interpretation boundary", ""])
    lines.append(
        "本记录提供 controlled component-level dynamic evidence；它不证明产品入口、"
        "权限/身份边界、攻击者控制、具体 CIA 影响或可利用性。候选不自动升级。"
    )
    lines.extend(["", "## Remaining limitations", ""])
    lines.extend(f"- {item}" for item in result.limitations)
    markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--harness", type=Path, default=DEFAULT_HARNESS)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", default="clang++")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--readers", type=int, default=4)
    parser.add_argument("--iterations", type=int, default=20000)
    args = parser.parse_args()
    result = run_poc(
        manifest_path=args.manifest,
        harness=args.harness,
        output=args.output,
        compiler=args.compiler,
        repeats=args.repeats,
        readers=args.readers,
        iterations=args.iterations,
    )
    write_reports(
        result,
        args.output / "poc.json",
        args.output / "poc.md",
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()