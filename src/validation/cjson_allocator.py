import json
import os
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence


SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)


@dataclass
class BuildRecord:
    command: List[str]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    outcome: str


@dataclass
class RunRecord:
    case: str
    allocator_mode: str
    command: List[str]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    sanitizer_detected: bool
    outcome: str


@dataclass
class AllocatorValidationResult:
    target: str
    harness: str
    compiler: str
    binary: str
    repeats: int
    build: BuildRecord
    runs: List[RunRecord] = field(default_factory=list)
    outcome: str = "inconclusive"
    interpretation: str = (
        "Controlled component-level robustness evidence only. "
        "A sanitizer finding or process failure does not by itself establish "
        "OpenHarmony system reachability, attacker control, security impact, "
        "or a reportable vulnerability."
    )

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "harness": self.harness,
            "compiler": self.compiler,
            "binary": self.binary,
            "repeats": self.repeats,
            "build": asdict(self.build),
            "runs": [asdict(item) for item in self.runs],
            "outcome": self.outcome,
            "interpretation": self.interpretation,
        }


def detect_sanitizer(text: str) -> bool:
    return any(marker in text for marker in SANITIZER_MARKERS)


def _run_outcome(
    *,
    exit_code: Optional[int],
    stderr: str,
    timed_out: bool,
) -> tuple[bool, str]:
    if timed_out:
        return False, "timeout"

    sanitizer_detected = detect_sanitizer(stderr)
    if sanitizer_detected:
        return True, "sanitizer_triggered"
    if exit_code == 0:
        return False, "clean"
    return False, "nonzero_exit"


def classify_validation(build: BuildRecord, runs: Sequence[RunRecord]) -> str:
    if build.outcome != "build_success":
        return "build_failed"

    normal_runs = [item for item in runs if item.allocator_mode == "normal"]
    if len(normal_runs) < 2 or any(item.outcome != "clean" for item in normal_runs):
        return "harness_invalid"

    failure_runs = [
        item for item in runs if item.allocator_mode == "fail-second"
    ]
    if not failure_runs:
        return "inconclusive"
    if any(item.outcome == "sanitizer_triggered" for item in failure_runs):
        return "controlled_failure_sanitizer"
    if any(item.outcome == "nonzero_exit" for item in failure_runs):
        return "controlled_failure_nonzero"
    if any(item.outcome == "timeout" for item in failure_runs):
        return "inconclusive"
    if all(item.outcome == "clean" for item in failure_runs):
        return "failure_not_triggered"
    return "inconclusive"


def _run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: Optional[Dict[str, str]] = None,
) -> tuple[Optional[int], float, str, str, bool]:
    started = time.perf_counter()
    try:
        process = subprocess.run(
            list(command),
            cwd=cwd,
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


def run_cjson_allocator_validation(
    *,
    target: Path,
    harness: Path,
    binary: Path,
    compiler: str = "clang",
    repeats: int = 3,
    build_timeout: float = 60.0,
    run_timeout: float = 5.0,
    extra_compile_args: Optional[Sequence[str]] = None,
) -> AllocatorValidationResult:
    root = target.resolve()
    harness_path = harness.resolve()
    binary_path = binary.resolve()

    if not root.is_dir():
        raise ValueError(f"Target is not a directory: {root}")
    if not harness_path.is_file():
        raise ValueError(f"Harness does not exist: {harness_path}")
    if repeats < 1:
        raise ValueError("repeats must be >= 1")

    required = [root / "cJSON.c", root / "cJSON_Utils.c", root / "cJSON.h", root / "cJSON_Utils.h"]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise ValueError("Missing required cJSON files: " + ", ".join(missing))

    binary_path.parent.mkdir(parents=True, exist_ok=True)

    build_command = [
        compiler,
        "-std=c99",
        "-g",
        "-O1",
        "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined",
        "-I",
        str(root),
        str(harness_path),
        str(root / "cJSON.c"),
        str(root / "cJSON_Utils.c"),
        "-lm",
        *list(extra_compile_args or []),
        "-o",
        str(binary_path),
    ]

    build_exit, build_elapsed, build_stdout, build_stderr, build_timed_out = _run_process(
        build_command,
        cwd=root,
        timeout=build_timeout,
    )

    if build_timed_out:
        build_outcome = "build_timeout"
    elif build_exit == 0:
        build_outcome = "build_success"
    else:
        build_outcome = "build_failed"

    build_record = BuildRecord(
        command=build_command,
        exit_code=build_exit,
        elapsed_seconds=build_elapsed,
        stdout=build_stdout,
        stderr=build_stderr,
        outcome=build_outcome,
    )

    result = AllocatorValidationResult(
        target=str(root),
        harness=str(harness_path),
        compiler=compiler,
        binary=str(binary_path),
        repeats=repeats,
        build=build_record,
    )

    if build_outcome != "build_success":
        result.outcome = "build_failed"
        return result

    runtime_env = dict(os.environ)
    runtime_env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
    runtime_env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"

    cases: List[tuple[str, str]] = [
        ("array", "normal"),
        ("object", "normal"),
    ]
    for _ in range(repeats):
        cases.extend(
            [
                ("array", "fail-second"),
                ("object", "fail-second"),
            ]
        )

    for case, allocator_mode in cases:
        command = [str(binary_path), case, allocator_mode]
        exit_code, elapsed, stdout, stderr, timed_out = _run_process(
            command,
            cwd=root,
            timeout=run_timeout,
            env=runtime_env,
        )
        sanitizer_detected, outcome = _run_outcome(
            exit_code=exit_code,
            stderr=stderr,
            timed_out=timed_out,
        )
        result.runs.append(
            RunRecord(
                case=case,
                allocator_mode=allocator_mode,
                command=command,
                exit_code=exit_code,
                elapsed_seconds=elapsed,
                stdout=stdout,
                stderr=stderr,
                sanitizer_detected=sanitizer_detected,
                outcome=outcome,
            )
        )

    result.outcome = classify_validation(result.build, result.runs)
    return result


def render_markdown(result: AllocatorValidationResult) -> str:
    lines = [
        "# cJSON Allocator Robustness Validation",
        "",
        "> Controlled component-level robustness evidence only. A crash or sanitizer "
        "finding is not automatically an OpenHarmony vulnerability.",
        "",
        "## Summary",
        "",
        f"- Target: {result.target}",
        f"- Harness: {result.harness}",
        f"- Compiler: {result.compiler}",
        f"- Binary: {result.binary}",
        f"- Failure repeats per case: {result.repeats}",
        f"- Build outcome: {result.build.outcome}",
        f"- Overall outcome: {result.outcome}",
        "",
        "## Build",
        "",
        f"- Exit code: {result.build.exit_code}",
        f"- Elapsed seconds: {result.build.elapsed_seconds:.6f}",
        f"- Command: `{shlex.join(result.build.command)}`",
        "",
        "## Runs",
        "",
    ]

    if not result.runs:
        lines.append("No runtime cases executed because the build did not succeed.")
    else:
        for index, run in enumerate(result.runs, start=1):
            lines.extend(
                [
                    f"### Run {index}: {run.case} / {run.allocator_mode}",
                    "",
                    f"- Outcome: {run.outcome}",
                    f"- Exit code: {run.exit_code}",
                    f"- Sanitizer detected: {run.sanitizer_detected}",
                    f"- Elapsed seconds: {run.elapsed_seconds:.6f}",
                    f"- Command: `{shlex.join(run.command)}`",
                    "",
                ]
            )

    lines.extend(
        [
            "## Interpretation boundary",
            "",
            result.interpretation,
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(
    result: AllocatorValidationResult,
    json_output: Path,
    markdown_output: Path,
) -> None:
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(render_markdown(result), encoding="utf-8")
