from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_MANIFEST = (
    ROOT
    / "research"
    / "tests"
    / "cpp_detector_controls"
    / "manifest.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "research"
    / "evidence"
    / "cpp"
    / "four_class_controls"
    / "run-001"
)
DETECTOR_CLASSES = {
    "ohscanner.cpp.shared_ptr_race": "SharedPtrRaceDetector",
    "ohscanner.cpp.lifetime": "LifetimeOwnershipGuardDetector",
}
ASAN_MARKERS = ("ERROR: AddressSanitizer:", "SUMMARY: AddressSanitizer:")
TSAN_MARKERS = ("WARNING: ThreadSanitizer:", "SUMMARY: ThreadSanitizer:")


class ControlError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class CommandRecord:
    argv: Tuple[str, ...]
    cwd: str
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    timed_out: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "elapsed_seconds": self.elapsed_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
        }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _read_source(entry: Mapping[str, object]) -> Tuple[Path, bytes, str]:
    source_path = ROOT / str(entry["path"])
    if not source_path.is_file():
        raise ControlError(f"missing source: {source_path}")
    data = source_path.read_bytes()
    actual_sha256 = _sha256_bytes(data)
    if actual_sha256 != entry.get("sha256"):
        raise ControlError(
            f"source SHA-256 mismatch for {entry['path']}: "
            f"expected {entry.get('sha256')}, read {actual_sha256}"
        )
    actual_blob = _git_blob_sha1(data)
    if actual_blob != entry.get("git_blob_sha1"):
        raise ControlError(
            f"source Git blob mismatch for {entry['path']}: "
            f"expected {entry.get('git_blob_sha1')}, read {actual_blob}"
        )
    return source_path, data, actual_sha256


def load_manifest(path: Path = DEFAULT_MANIFEST) -> Dict[str, object]:
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ControlError("unsupported four-class control manifest schema")
    if manifest.get("evidence_scope") != "synthetic_development_controls":
        raise ControlError("controls must remain synthetic development controls")
    if manifest.get("is_independent_holdout") is not False:
        raise ControlError("controls must not claim independent holdout status")
    controls = manifest.get("controls")
    if not isinstance(controls, list) or not controls:
        raise ControlError("manifest requires controls")
    required_categories = {"vulnerable", "fixed", "safe", "unrelated"}
    for detector_id in manifest["detectors"]:
        categories = {
            str(item["category"])
            for item in controls
            if item["detector_id"] == detector_id
        }
        if categories != required_categories:
            raise ControlError(
                f"{detector_id} categories {sorted(categories)} do not cover four classes"
            )
    return manifest


def verify_manifest_sources(
    manifest: Mapping[str, object],
) -> List[Dict[str, object]]:
    controls = manifest["controls"]
    identities = []
    for control in controls:
        source_path, data, source_sha256 = _read_source(control["source"])
        identities.append(
            {
                "control_id": control["id"],
                "path": _relative(source_path),
                "bytes": len(data),
                "sha256": source_sha256,
                "git_blob_sha1": _git_blob_sha1(data),
            }
        )
    snapshot_input = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
            "git_blob_sha1": item["git_blob_sha1"],
        }
        for item in sorted(identities, key=lambda item: item["path"])
    ]
    snapshot_sha256 = _sha256_bytes(_canonical_json(snapshot_input))
    if snapshot_sha256 != manifest["provenance"]["snapshot_sha256"]:
        raise ControlError(
            "control snapshot SHA-256 mismatch: "
            f"expected {manifest['provenance']['snapshot_sha256']}, read {snapshot_sha256}"
        )
    return identities


def _run_command(
    argv: Sequence[str],
    *,
    cwd: Path = ROOT,
    timeout: float = 60.0,
    env: Optional[Mapping[str, str]] = None,
) -> CommandRecord:
    started = time.perf_counter()
    try:
        process = subprocess.run(
            list(argv),
            cwd=str(cwd),
            env=dict(env) if env is not None else None,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CommandRecord(
            tuple(str(item) for item in argv),
            str(cwd),
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
        return CommandRecord(
            tuple(str(item) for item in argv),
            str(cwd),
            None,
            time.perf_counter() - started,
            stdout,
            stderr,
            True,
        )


def _detector_for(detector_id: str):
    if detector_id == "ohscanner.cpp.shared_ptr_race":
        from src.ohscanner.detectors.cpp.shared_ptr_race_detector import (
            SharedPtrRaceDetector,
        )

        return SharedPtrRaceDetector()
    if detector_id == "ohscanner.cpp.lifetime":
        from src.ohscanner.detectors.cpp.lifetime_detector import (
            LifetimeOwnershipGuardDetector,
        )

        return LifetimeOwnershipGuardDetector()
    raise ControlError(f"unsupported detector: {detector_id}")


def run_detector_control(control: Mapping[str, object]) -> Dict[str, object]:
    from src.ohscanner.contracts import SourceUnit

    source_path, data, source_sha256 = _read_source(control["source"])
    text = data.decode("utf-8")
    unit = SourceUnit(
        path=str(control["source"]["path"]),
        language="cpp",
        text=text,
        sha256=source_sha256,
        parse_status="complete",
    )
    detector = _detector_for(str(control["detector_id"]))
    observed_detector_version = detector.version
    run = detector.detect(None, (unit,))
    expected = control["expected_detector"]
    failures: List[str] = []
    if run.status != expected["status"]:
        failures.append(
            f"status expected {expected['status']}, observed {run.status}"
        )
    if len(run.findings) != expected["finding_count"]:
        failures.append(
            f"finding_count expected {expected['finding_count']}, "
            f"observed {len(run.findings)}"
        )
    joined_messages = " ".join(finding.message for finding in run.findings)
    for fragment in expected.get("message_contains", []):
        if fragment not in joined_messages:
            failures.append(f"missing expected message fragment: {fragment}")
    if expected.get("unknown_obligation_kinds"):
        observed_unknown = {
            obligation.kind
            for finding in run.findings
            for obligation in finding.evidence_obligations
            if obligation.status == "unknown"
        }
        missing = set(expected["unknown_obligation_kinds"]) - observed_unknown
        if missing:
            failures.append(
                "missing unknown obligation kinds: " + ",".join(sorted(missing))
            )
    return {
        "control_id": control["id"],
        "detector_id": control["detector_id"],
        "category": control["category"],
        "source_path": _relative(source_path),
        "detector_version_binding": {
            "manifest": control["detector_version"],
            "observed": observed_detector_version,
            "matches": observed_detector_version == control["detector_version"],
        },
        "status": run.status,
        "finding_count": len(run.findings),
        "findings": [
            {
                "line": finding.line,
                "column": finding.column,
                "rule_id": finding.rule_id,
                "candidate_cwe": finding.candidate_cwe,
                "symbol": finding.symbol,
                "message": finding.message,
                "evidence_obligations": [
                    {"kind": item.kind, "status": item.status}
                    for item in finding.evidence_obligations
                ],
            }
            for finding in run.findings
        ],
        "limitations": list(run.limitations),
        "expected": dict(expected),
        "status_result": "passed" if not failures else "failed",
        "failures": failures,
    }


def run_detector_matrix(manifest: Mapping[str, object]) -> List[Dict[str, object]]:
    return [run_detector_control(control) for control in manifest["controls"]]


def verify_patch(
    control: Mapping[str, object], *, patch_tool: str = "patch"
) -> Dict[str, object]:
    patch = control.get("patch")
    if not patch:
        return {
            "control_id": control["id"],
            "status": "not_applicable",
            "reason": "negative control has no remediation patch",
        }
    patch_path = ROOT / str(patch["path"])
    if not patch_path.is_file():
        raise ControlError(f"missing patch: {patch_path}")
    patch_bytes = patch_path.read_bytes()
    patch_sha256 = _sha256_bytes(patch_bytes)
    if patch_sha256 != patch.get("sha256"):
        raise ControlError(
            f"patch SHA-256 mismatch for {control['id']}: "
            f"expected {patch.get('sha256')}, read {patch_sha256}"
        )
    base_path, base_bytes, base_sha256 = _read_source(patch["base_source"])
    fixed_path, fixed_bytes, fixed_sha256 = _read_source(patch["fixed_source"])
    if base_sha256 != patch.get("base_sha256"):
        raise ControlError(f"patch base SHA-256 mismatch for {control['id']}")
    if fixed_sha256 != patch.get("fixed_sha256"):
        raise ControlError(f"patch fixed SHA-256 mismatch for {control['id']}")
    with tempfile.TemporaryDirectory(prefix="ohscanner-control-patch-") as temp_name:
        temp_root = Path(temp_name)
        relative_base = Path(str(patch["base_source"]["path"]))
        temp_base = temp_root / relative_base
        temp_base.parent.mkdir(parents=True, exist_ok=True)
        temp_base.write_bytes(base_bytes)
        command = _run_command(
            (
                patch_tool,
                "-p1",
                "--fuzz=0",
                "--batch",
                "-i",
                str(patch_path.resolve()),
            ),
            cwd=temp_root,
            timeout=20.0,
        )
        patched_bytes = temp_base.read_bytes() if temp_base.is_file() else b""
    patched_sha256 = _sha256_bytes(patched_bytes)
    failures = []
    if command.exit_code != 0 or command.timed_out:
        failures.append("patch did not apply with zero fuzz")
    if patched_sha256 != fixed_sha256:
        failures.append(
            "patched bytes do not match the fixed source: "
            f"expected {fixed_sha256}, read {patched_sha256}"
        )
    return {
        "control_id": control["id"],
        "status": "passed" if not failures else "failed",
        "patch_path": _relative(patch_path),
        "patch_sha256": patch_sha256,
        "base_path": _relative(base_path),
        "base_sha256": base_sha256,
        "fixed_path": _relative(fixed_path),
        "fixed_sha256": fixed_sha256,
        "patched_sha256": patched_sha256,
        "patch_kind": patch["kind"],
        "upstream_status": patch["upstream_status"],
        "command": command.to_dict(),
        "failures": failures,
    }


def verify_patches(
    manifest: Mapping[str, object], *, patch_tool: str = "patch"
) -> List[Dict[str, object]]:
    return [
        verify_patch(control, patch_tool=patch_tool)
        for control in manifest["controls"]
    ]


def _write_command_log(path: Path, record: CommandRecord, env: Mapping[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "environment": dict(env),
        "command": record.to_dict(),
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _sanitizer_outcome(
    sanitizer: str, command: CommandRecord
) -> Tuple[str, bool]:
    markers = ASAN_MARKERS if sanitizer == "address" else TSAN_MARKERS
    detected = any(marker in command.stderr for marker in markers)
    if command.timed_out:
        return "timed_out", detected
    if detected:
        return "sanitizer_triggered", detected
    if command.exit_code == 0:
        return "clean", False
    return "failed", False


def run_native_control(
    control: Mapping[str, object],
    *,
    compiler: str,
    repeats: int,
    work_dir: Path,
    evidence_dir: Path,
    timeout: float,
) -> Dict[str, object]:
    source_path, _data, source_sha256 = _read_source(control["source"])
    build = control["build"]
    sanitizer = str(build["sanitizer"])
    sanitizer_flags = {
        "address": ("-fsanitize=address",),
        "thread": ("-fsanitize=thread",),
    }[sanitizer]
    build_dir = work_dir / str(control["id"])
    binary = build_dir / "control"
    build_dir.mkdir(parents=True, exist_ok=True)
    build_argv = [
        compiler,
        *build["arguments"],
        *sanitizer_flags,
        str(source_path),
        "-o",
        str(binary),
    ]
    build_record = _run_command(
        build_argv, cwd=ROOT, timeout=float(build["timeout_seconds"])
    )
    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in build.get("environment", {}).items()})
    build_log = evidence_dir / "logs" / f"{control['id']}.build.json"
    _write_command_log(build_log, build_record, build.get("environment", {}))
    runs: List[Dict[str, object]] = []
    if build_record.exit_code == 0 and not build_record.timed_out:
        for repeat in range(1, repeats + 1):
            setarch = shutil.which("setarch")
            run_argv = (
                (setarch, platform.machine(), "-R", str(binary))
                if setarch
                else (str(binary),)
            )
            run_record = _run_command(
                run_argv,
                cwd=build_dir,
                timeout=timeout,
                env=env,
            )
            observed, detected = _sanitizer_outcome(sanitizer, run_record)
            expected = control["expected_dynamic"]
            passed = observed == expected["outcome"]
            run_log = (
                evidence_dir
                / "logs"
                / f"{control['id']}.run-{repeat:02d}.json"
            )
            _write_command_log(run_log, run_record, build.get("environment", {}))
            runs.append(
                {
                    "repeat": repeat,
                    "command": run_record.to_dict(),
                    "sanitizer_detected": detected,
                    "observed_outcome": observed,
                    "expected_outcome": expected["outcome"],
                    "status": "passed" if passed else "failed",
                    "log_path": _relative(run_log),
                    "log_sha256": _sha256_bytes(run_log.read_bytes()),
                }
            )
    failures = []
    if build_record.exit_code != 0 or build_record.timed_out:
        failures.append("native build failed")
    if len(runs) != repeats:
        failures.append("native runs were not executed for every repeat")
    for run in runs:
        if run["status"] != "passed":
            failures.append(
                f"repeat {run['repeat']} expected {run['expected_outcome']} "
                f"but observed {run['observed_outcome']}"
            )
    binary_sha256 = _sha256_bytes(binary.read_bytes()) if binary.is_file() else None
    return {
        "control_id": control["id"],
        "detector_id": control["detector_id"],
        "category": control["category"],
        "source_path": _relative(source_path),
        "source_sha256": source_sha256,
        "sanitizer": sanitizer,
        "build": {
            "command": build_record.to_dict(),
            "binary_path": str(binary),
            "binary_sha256": binary_sha256,
            "log_path": _relative(build_log),
            "log_sha256": _sha256_bytes(build_log.read_bytes()),
        },
        "runs": runs,
        "status": "passed" if not failures else "failed",
        "failures": failures,
    }


def run_native_controls(
    manifest: Mapping[str, object],
    *,
    compiler: str,
    repeats: int,
    work_dir: Path,
    evidence_dir: Path,
    timeout: float,
) -> List[Dict[str, object]]:
    return [
        run_native_control(
            control,
            compiler=compiler,
            repeats=repeats,
            work_dir=work_dir,
            evidence_dir=evidence_dir,
            timeout=timeout,
        )
        for control in manifest["controls"]
    ]


def run_regressions(repeats: int) -> List[Dict[str, object]]:
    commands = [
        (
            "detector_source_compile",
            (
                sys.executable,
                "-m",
                "py_compile",
                "src/ohscanner/detectors/cpp/shared_ptr_race_detector.py",
                "src/ohscanner/detectors/cpp/lifetime_detector.py",
                "tests/detectors/test_cpp_shared_ptr_race_detector.py",
                "tests/detectors/test_cpp_lifetime_detector.py",
                "tests/test_cpp_four_class_controls.py",
            ),
        ),
        (
            "detector_unit_regression",
            (
                sys.executable,
                "-m",
                "unittest",
                "-q",
                "tests.detectors.test_cpp_shared_ptr_race_detector",
                "tests.detectors.test_cpp_lifetime_detector",
            ),
        ),
        (
            "four_class_manifest_regression",
            (
                sys.executable,
                "-m",
                "unittest",
                "-q",
                "tests.test_cpp_four_class_controls",
            ),
        ),
    ]
    results = []
    for name, argv in commands:
        record = _run_command(argv, cwd=ROOT, timeout=180.0)
        results.append(
            {
                "name": name,
                "status": (
                    "passed"
                    if record.exit_code == 0 and not record.timed_out
                    else "failed"
                ),
                "repeats": repeats,
                "command": record.to_dict(),
            }
        )
    return results


def run_family_pocs(
    *, repeats: int, evidence_dir: Path, work_dir: Path
) -> List[Dict[str, object]]:
    family_dir = evidence_dir / "family_poc"
    family_dir.mkdir(parents=True, exist_ok=True)
    shared_output = work_dir / "family_shared_ptr"
    lifetime_output = work_dir / "family_lifetime"
    commands = [
        (
            "shared_ptr_delayed_singleton",
            (
                sys.executable,
                "-m",
                "src.ohscanner.poc.cpp_shared_ptr_race",
                "--output",
                str(shared_output),
                "--repeats",
                str(repeats),
                "--compiler",
                "clang++",
            ),
        ),
        (
            "lifetime_unique_ptr_alias",
            (
                sys.executable,
                "-m",
                "src.ohscanner.poc.cpp_lifetime_uaf",
                "--output",
                str(lifetime_output),
                "--repeats",
                str(repeats),
                "--compiler",
                "clang++",
            ),
        ),
    ]
    results = []
    for name, argv in commands:
        record = _run_command(argv, cwd=ROOT, timeout=300.0)
        source_json = (Path(argv[argv.index("--output") + 1]) / "poc.json")
        source_md = source_json.with_name("poc.md")
        copied = {}
        for source in (source_json, source_md):
            if source.is_file():
                target = family_dir / f"{name}.{source.suffix.lstrip('.')}"
                target.write_bytes(source.read_bytes())
                copied[source.suffix.lstrip(".")] = {
                    "path": _relative(target),
                    "sha256": _sha256_bytes(target.read_bytes()),
                }
        results.append(
            {
                "name": name,
                "status": (
                    "passed"
                    if record.exit_code == 0
                    and not record.timed_out
                    and "json" in copied
                    else "failed"
                ),
                "command": record.to_dict(),
                "artifacts": copied,
            }
        )
    return results


def _git_identity() -> Dict[str, object]:
    commands = {
        "head": ("rev-parse", "HEAD"),
        "tree": ("rev-parse", "HEAD^{tree}"),
        "remote": ("remote", "get-url", "origin"),
    }
    values = {}
    for name, suffix in commands.items():
        record = _run_command(("git", *suffix), cwd=ROOT, timeout=10.0)
        values[name] = record.stdout.strip() if record.exit_code == 0 else None
    status = _run_command(
        ("git", "status", "--short", "--branch"), cwd=ROOT, timeout=10.0
    )
    values["status"] = status.stdout.splitlines()
    return values


def _compiler_identity(compiler: str) -> Dict[str, object]:
    record = _run_command((compiler, "--version"), cwd=ROOT, timeout=10.0)
    version = (record.stdout or record.stderr).splitlines()
    return {
        "command": compiler,
        "version": version[0] if version else None,
        "full_output": version,
    }


def write_reports(
    *,
    manifest: Mapping[str, object],
    manifest_path: Path,
    output: Path,
    identities: Sequence[Mapping[str, object]],
    patches: Sequence[Mapping[str, object]],
    matrix: Sequence[Mapping[str, object]],
    native: Sequence[Mapping[str, object]],
    regressions: Sequence[Mapping[str, object]],
    family_pocs: Sequence[Mapping[str, object]],
    compiler: str,
    repeats: int,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    manifest_sha256 = _sha256_bytes(manifest_path.read_bytes())
    stages = {
        "manifest": {
            "status": "passed",
            "source_count": len(identities),
            "snapshot_sha256": manifest["provenance"]["snapshot_sha256"],
        },
        "patch_revalidation": {
            "status": (
                "passed"
                if all(item["status"] in {"passed", "not_applicable"} for item in patches)
                else "failed"
            ),
            "items": list(patches),
        },
        "detector_matrix": {
            "status": "passed" if all(item["status_result"] == "passed" for item in matrix) else "failed",
            "passed": sum(item["status_result"] == "passed" for item in matrix),
            "failed": sum(item["status_result"] != "passed" for item in matrix),
            "items": list(matrix),
        },
        "detector_regression": {
            "status": "passed" if all(item["status"] == "passed" for item in regressions) else "failed",
            "items": list(regressions),
        },
        "native_controls": {
            "status": "passed" if all(item["status"] == "passed" for item in native) else "failed",
            "passed": sum(item["status"] == "passed" for item in native),
            "failed": sum(item["status"] != "passed" for item in native),
            "items": list(native),
        },
        "family_poc_harnesses": {
            "status": (
                "passed"
                if family_pocs and all(item["status"] == "passed" for item in family_pocs)
                else "skipped" if not family_pocs else "failed"
            ),
            "items": list(family_pocs),
        },
    }
    result = {
        "schema_version": 1,
        "package_id": manifest["package_id"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_scope": manifest["evidence_scope"],
        "candidate_status": "candidate/unassessed",
        "validated_vulnerability": 0,
        "is_independent_holdout": False,
        "accuracy_metrics_permitted": False,
        "manifest": {
            "path": _relative(manifest_path),
            "sha256": manifest_sha256,
        },
        "checkout": _git_identity(),
        "source_identities": list(identities),
        "detector_version_observations": [
            {
                "control_id": item["control_id"],
                **item["detector_version_binding"],
            }
            for item in matrix
        ],
        "toolchain": {
            "python": sys.version,
            "compiler": _compiler_identity(compiler),
            "platform": platform.platform(),
            "patch_tool": shutil.which("patch"),
            "aslr_workaround": bool(shutil.which("setarch")),
            "repeats": repeats,
        },
        "stages": stages,
        "limitations": list(manifest["limitations"])
        + (
            [
                "实际 worktree 中 Detector 版本与控制基线版本存在漂移；行为矩阵记录 observed/manifest 两个版本，不把 observed 冒充基线版本。"
            ]
            if any(not item["detector_version_binding"]["matches"] for item in matrix)
            else []
        ),
    }
    json_path = output / "results.json"
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    regression_passed = sum(item["status"] == "passed" for item in regressions)
    regression_failed = sum(item["status"] == "failed" for item in regressions)
    native_runs = [run for item in native for run in item["runs"]]
    dynamic_triggered = sum(
        run["observed_outcome"] == "sanitizer_triggered" for run in native_runs
    )
    dynamic_clean = sum(
        run["observed_outcome"] == "clean" for run in native_runs
    )
    dynamic_other = len(native_runs) - dynamic_triggered - dynamic_clean
    lines = [
        "# C/C++ four-class detector controls",
        "",
        "> Synthetic development controls only; not an independent holdout and not accuracy data.",
        "",
        f"- package: `{manifest['package_id']}`",
        f"- manifest SHA-256: `{manifest_sha256}`",
        f"- snapshot SHA-256: `{manifest['provenance']['snapshot_sha256']}`",
        f"- detector matrix: {stages['detector_matrix']['passed']} passed, "
        f"{stages['detector_matrix']['failed']} failed, 0 skipped",
        f"- native builds/controls: {stages['native_controls']['passed']} passed, "
        f"{stages['native_controls']['failed']} failed, 0 skipped",
        f"- sanitizer runs: {dynamic_triggered} triggered, {dynamic_clean} clean, "
        f"{dynamic_other} other",
        f"- detector regressions: {regression_passed} passed, "
        f"{regression_failed} failed, 0 skipped",
        f"- family PoC harnesses: {stages['family_poc_harnesses']['status']}",
        "- `validated_vulnerability`: 0",
        "",
        "## Detector version binding",
        "",
        "| detector | manifest baseline | observed worktree | matches |",
        "|---|---|---|---|",
    ]
    version_pairs = sorted(
        {
            (
                item["detector_id"],
                item["detector_version_binding"]["manifest"],
                item["detector_version_binding"]["observed"],
                item["detector_version_binding"]["matches"],
            )
            for item in matrix
        }
    )
    for detector_id, manifest_version, observed_version, matches in version_pairs:
        lines.append(
            f"| `{detector_id}` | `{manifest_version}` | "
            f"`{observed_version}` | {matches} |"
        )
    lines.extend(
        [
            "",
            "## Controls",
            "",
            "| id | class | detector findings | native result | status |",
            "|---|---|---:|---|---|",
        ]
    )
    native_by_id = {item["control_id"]: item for item in native}
    for item in matrix:
        native_item = native_by_id[item["control_id"]]
        observed_runs = ",".join(
            str(run["observed_outcome"]) for run in native_item["runs"]
        ) or "not_run"
        overall = (
            "passed"
            if item["status_result"] == "passed" and native_item["status"] == "passed"
            else "failed"
        )
        lines.append(
            f"| `{item['control_id']}` | {item['category']} | "
            f"{item['finding_count']} | {observed_runs} | {overall} |"
        )
    lines.extend(
        [
            "",
            "## Patch revalidation",
            "",
            "| control | patch kind | upstream status | result |",
            "|---|---|---|---|",
        ]
    )
    for item in patches:
        lines.append(
            f"| `{item['control_id']}` | {item.get('patch_kind', 'n/a')} | "
            f"{item.get('upstream_status', 'n/a')} | {item['status']} |"
        )
    lines.extend(["", "## Interpretation boundary", ""])
    lines.append(
        "`safe`/`unrelated` 的 0 告警只表示当前窄规则未观察到目标形状，"
        "不是安全结论，也不按告警数量强判 miss。`fixed` 使用可复核的"
        "authored remediation patch 稳定拒绝；它不冒充上游产品补丁。"
    )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in result["limitations"])
    (output / "results.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--compiler", default="clang++")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--skip-regression", action="store_true")
    parser.add_argument("--skip-family-poc", action="store_true")
    args = parser.parse_args()
    if args.repeats < 1:
        raise ControlError("--repeats must be positive")
    manifest_path = args.manifest.resolve()
    manifest = load_manifest(manifest_path)
    output = args.output.resolve()
    work_dir = (
        args.work_dir.resolve()
        if args.work_dir
        else ROOT / "outputs" / "poc" / "cpp-four-class-controls-20261015"
    )
    output.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    identities = verify_manifest_sources(manifest)
    patches = verify_patches(manifest)
    matrix = run_detector_matrix(manifest)
    regressions = [] if args.skip_regression else run_regressions(args.repeats)
    native = run_native_controls(
        manifest,
        compiler=args.compiler,
        repeats=args.repeats,
        work_dir=work_dir,
        evidence_dir=output,
        timeout=args.timeout,
    )
    family_pocs = (
        []
        if args.skip_family_poc
        else run_family_pocs(
            repeats=args.repeats, evidence_dir=output, work_dir=work_dir
        )
    )
    write_reports(
        manifest=manifest,
        manifest_path=manifest_path,
        output=output,
        identities=identities,
        patches=patches,
        matrix=matrix,
        native=native,
        regressions=regressions,
        family_pocs=family_pocs,
        compiler=args.compiler,
        repeats=args.repeats,
    )
    failed = (
        any(item["status"] not in {"passed", "not_applicable"} for item in patches)
        or any(item["status_result"] != "passed" for item in matrix)
        or any(item["status"] != "passed" for item in native)
        or any(item["status"] != "passed" for item in regressions)
        or any(item["status"] != "passed" for item in family_pocs)
    )
    print(json.dumps({"output": str(output), "failed": failed}, indent=2))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()