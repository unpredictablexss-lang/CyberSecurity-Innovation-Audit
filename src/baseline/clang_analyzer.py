import json
import re
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}

_DIAGNOSTIC_PATTERN = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+): "
    r"(?P<level>warning|error|note): (?P<message>.*)$"
)
_CHECKER_PATTERN = re.compile(r"\s*\[(?P<checker>[^\[\]]+)\]\s*$")


@dataclass(frozen=True)
class AnalyzerDiagnostic:
    file: str
    line: int
    column: int
    level: str
    message: str
    checker: Optional[str] = None


@dataclass
class AnalyzerFileResult:
    file: str
    command: List[str]
    exit_code: int
    elapsed_seconds: float
    diagnostic_count: int
    stdout: str
    stderr: str


@dataclass
class ClangAnalyzerResult:
    target: str
    clang_executable: str
    clang_version: str
    files: List[str]
    file_results: List[AnalyzerFileResult] = field(default_factory=list)
    diagnostics: List[AnalyzerDiagnostic] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    @property
    def diagnostic_count(self) -> int:
        return len(self.diagnostics)

    @property
    def failed_files(self) -> List[str]:
        return [item.file for item in self.file_results if item.exit_code != 0]

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "tool": "clang-static-analyzer",
            "clang_executable": self.clang_executable,
            "clang_version": self.clang_version,
            "files": self.files,
            "file_count": len(self.files),
            "diagnostic_count": self.diagnostic_count,
            "failed_files": self.failed_files,
            "elapsed_seconds": self.elapsed_seconds,
            "file_results": [asdict(item) for item in self.file_results],
            "diagnostics": [asdict(item) for item in self.diagnostics],
            "interpretation": (
                "Baseline diagnostics only. A warning is not a validated vulnerability "
                "and a clean run is not proof of absence."
            ),
        }


def _normalize_target_path(root: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        raise ValueError(f"Source path must be relative to target root: {raw_path}")

    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"Source path escapes target root: {raw_path}") from error

    if not resolved.is_file():
        raise ValueError(f"Source file does not exist: {raw_path}")
    if resolved.suffix.lower() not in SOURCE_SUFFIXES:
        raise ValueError(f"Unsupported source suffix: {raw_path}")

    return resolved


def parse_clang_diagnostics(text: str, target: Optional[Path] = None) -> List[AnalyzerDiagnostic]:
    diagnostics: List[AnalyzerDiagnostic] = []

    for line in text.splitlines():
        match = _DIAGNOSTIC_PATTERN.match(line.strip())
        if not match:
            continue

        file_text = match.group("file")
        file_path = Path(file_text)
        if target is not None:
            try:
                file_text = str(file_path.resolve().relative_to(target.resolve()))
            except (OSError, ValueError):
                pass

        message = match.group("message")
        checker_match = _CHECKER_PATTERN.search(message)
        checker = checker_match.group("checker") if checker_match else None
        if checker_match:
            message = message[: checker_match.start()].rstrip()

        diagnostics.append(
            AnalyzerDiagnostic(
                file=file_text,
                line=int(match.group("line")),
                column=int(match.group("column")),
                level=match.group("level"),
                message=message,
                checker=checker,
            )
        )

    return diagnostics


def _read_clang_version(clang_executable: str) -> str:
    process = subprocess.run(
        [clang_executable, "--version"],
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip() or "unknown error"
        raise RuntimeError(f"Unable to run {clang_executable} --version: {detail}")
    return process.stdout.splitlines()[0].strip() if process.stdout else "unknown"


def run_clang_analyzer(
    target: Path,
    files: Sequence[str],
    clang_executable: str = "clang",
    extra_args: Optional[Sequence[str]] = None,
) -> ClangAnalyzerResult:
    root = target.resolve()
    if not root.is_dir():
        raise ValueError(f"Target is not a directory: {root}")
    if not files:
        raise ValueError("At least one --file is required")

    resolved_files = [_normalize_target_path(root, value) for value in files]
    normalized_files = [str(path.relative_to(root)) for path in resolved_files]
    clang_version = _read_clang_version(clang_executable)
    extra = list(extra_args or [])

    result = ClangAnalyzerResult(
        target=str(root),
        clang_executable=clang_executable,
        clang_version=clang_version,
        files=normalized_files,
    )

    total_start = time.perf_counter()
    for source_file, normalized_file in zip(resolved_files, normalized_files):
        command = [
            clang_executable,
            "--analyze",
            "-Xanalyzer",
            "-analyzer-output=text",
            "-I",
            str(root),
            *extra,
            str(source_file),
        ]

        started = time.perf_counter()
        process = subprocess.run(
            command,
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        elapsed = time.perf_counter() - started

        parsed = parse_clang_diagnostics(
            "\n".join(part for part in (process.stdout, process.stderr) if part),
            target=root,
        )
        result.diagnostics.extend(parsed)
        result.file_results.append(
            AnalyzerFileResult(
                file=normalized_file,
                command=command,
                exit_code=process.returncode,
                elapsed_seconds=elapsed,
                diagnostic_count=len(parsed),
                stdout=process.stdout,
                stderr=process.stderr,
            )
        )

    result.elapsed_seconds = time.perf_counter() - total_start
    return result


def render_markdown(result: ClangAnalyzerResult) -> str:
    lines = [
        "# Clang Static Analyzer Baseline",
        "",
        "> Baseline diagnostics only. Warnings are not validated vulnerabilities, "
        "and a clean run does not prove absence of vulnerabilities.",
        "",
        "## Run Summary",
        "",
        f"- Target: {result.target}",
        f"- Tool: clang --analyze",
        f"- Clang version: {result.clang_version}",
        f"- Files: {len(result.files)}",
        f"- Diagnostics: {result.diagnostic_count}",
        f"- Failed files: {len(result.failed_files)}",
        f"- Elapsed seconds: {result.elapsed_seconds:.6f}",
        "",
        "## Files",
        "",
    ]

    for file_result in result.file_results:
        lines.extend(
            [
                f"### {file_result.file}",
                "",
                f"- Exit code: {file_result.exit_code}",
                f"- Diagnostics: {file_result.diagnostic_count}",
                f"- Elapsed seconds: {file_result.elapsed_seconds:.6f}",
                f"- Command: `{shlex.join(file_result.command)}`",
                "",
            ]
        )

    lines.extend(["## Diagnostics", ""])
    if not result.diagnostics:
        lines.append("No parsed warning/error diagnostics.")
    else:
        for index, diagnostic in enumerate(result.diagnostics, start=1):
            checker = f" [{diagnostic.checker}]" if diagnostic.checker else ""
            lines.extend(
                [
                    f"### Diagnostic {index}",
                    "",
                    f"- Location: `{diagnostic.file}:{diagnostic.line}:{diagnostic.column}`",
                    f"- Level: {diagnostic.level}",
                    f"- Checker: {diagnostic.checker or 'unresolved'}",
                    f"- Message: {diagnostic.message}{checker}",
                    "",
                ]
            )

    return "\n".join(lines).rstrip() + "\n"


def write_reports(
    result: ClangAnalyzerResult,
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
