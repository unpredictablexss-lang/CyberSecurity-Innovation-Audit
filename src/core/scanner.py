import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from src.core.context import (
    _strip_comments_and_literals,
    find_top_level_function_spans,
    resolve_context,
)
from src.core.finding import Finding


DANGEROUS_CALLS = {
    "strcpy": ("CWE-120", "Potential buffer overflow"),
    "strcat": ("CWE-120", "Potential buffer overflow"),
    "sprintf": ("CWE-120", "Potential buffer overflow"),
    "gets": ("CWE-242", "Inherently dangerous function"),
    "memcpy": ("CWE-787", "Potential out-of-bounds write"),
}

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}
EXCLUDED_DIRECTORIES = {".git", ".venv", "__pycache__", ".cache"}
CALL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(" + "|".join(DANGEROUS_CALLS) + r")\s*\("
)


@dataclass
class ScanResult:
    target: str
    engine: str = "text"
    scanned_files: int = 0
    scanned_lines: int = 0
    findings: List[Finding] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)
    scope_includes: List[str] = field(default_factory=lambda: ["."])
    scope_excludes: List[str] = field(default_factory=list)
    parsing: List[dict] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "engine": self.engine,
            "scope": {
                "include_paths": self.scope_includes,
                "exclude_paths": self.scope_excludes,
            },
            "scanned_files": self.scanned_files,
            "scanned_lines": self.scanned_lines,
            "skipped_file_count": len(self.skipped_files),
            "skipped_files": self.skipped_files,
            "finding_count": self.finding_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "parsing": self.parsing,
        }


def _scan_lines(path: Path, lines: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    function_spans = find_top_level_function_spans(lines)

    # Mask comments and string literals before matching so that a dangerous
    # call-shaped text inside a comment or string literal is not reported.
    # The mask preserves every newline, keeping line numbers aligned with the
    # original source. A match can still come from a macro, declaration, or
    # unreachable code; only comment/string false positives are suppressed.
    cleaned_text = _strip_comments_and_literals("\n".join(lines))
    cleaned_lines = cleaned_text.split("\n")

    for idx, (raw_line, cleaned_line) in enumerate(
        zip(lines, cleaned_lines), start=1
    ):
        for func in dict.fromkeys(CALL_PATTERN.findall(cleaned_line)):
            cwe, vuln_type = DANGEROUS_CALLS[func]
            context = resolve_context(lines, idx, spans=function_spans)
            findings.append(
                Finding(
                    rule_id=f"cpp.dangerous_call.{func}",
                    title=f"Candidate dangerous C/C++ call: {func}",
                    vulnerability_type=vuln_type,
                    cwe=cwe,
                    severity="unassessed",
                    confidence="unassessed",
                    file_path=str(path),
                    line=idx,
                    function=context.function,
                    evidence=raw_line.strip(),
                    explanation=(
                        f"The text contains a call-shaped use of {func}(). "
                        "Arguments, destination capacity, reachability, and "
                        "security impact have not been verified."
                    ),
                    remediation=(
                        "Check the source and destination bounds in context. "
                        "Only propose a code change after confirming the risk."
                    ),
                    function_start_line=context.function_start_line,
                    function_end_line=context.function_end_line,
                    context_start_line=context.context_start_line,
                    context_end_line=context.context_end_line,
                    context=context.snippet,
                    context_status=context.status,
                )
            )

    return findings


def scan_file(path: Path) -> List[Finding]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return _scan_lines(path, lines)


def _resolve_scope_path(root: Path, raw_path: str, label: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        raise ValueError(f"{label} path must be relative to target root: {raw_path}")

    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(
            f"{label} path escapes target root: {raw_path}"
        ) from error
    return resolved


def _relative_scope_text(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    return "." if str(relative) == "." else relative.as_posix()


def _is_excluded(path: Path, excluded_paths: List[Path]) -> bool:
    return any(path == excluded or excluded in path.parents for excluded in excluded_paths)


def _read_and_record_source(path: Path, result: ScanResult, seen_files: Set[Path]) -> None:
    resolved = path.resolve()
    if resolved in seen_files:
        return
    seen_files.add(resolved)

    if path.suffix.lower() not in SOURCE_SUFFIXES:
        return
    if path.is_symlink():
        result.skipped_files.append(f"{path}: symbolic link")
        return

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        result.skipped_files.append(f"{path}: {error.strerror}")
        return

    result.scanned_files += 1
    result.scanned_lines += len(lines)
    result.findings.extend(_scan_lines(path, lines))


def scan_directory(
    root: Path,
    include_paths: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
) -> ScanResult:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Target is not a directory: {root}")

    raw_includes = include_paths or ["."]
    raw_excludes = exclude_paths or []

    resolved_includes = [
        _resolve_scope_path(root, value, "Include") for value in raw_includes
    ]
    resolved_excludes = [
        _resolve_scope_path(root, value, "Exclude") for value in raw_excludes
    ]

    for raw_value, include_path in zip(raw_includes, resolved_includes):
        if not include_path.exists():
            raise ValueError(f"Included path does not exist: {raw_value}")

    result = ScanResult(
        target=str(root),
        scope_includes=[_relative_scope_text(root, path) for path in resolved_includes],
        scope_excludes=[_relative_scope_text(root, path) for path in resolved_excludes],
    )
    seen_files: Set[Path] = set()

    def record_walk_error(error: OSError) -> None:
        result.skipped_files.append(f"{error.filename}: {error.strerror}")

    for include_path in resolved_includes:
        if _is_excluded(include_path, resolved_excludes):
            continue

        if include_path.is_file():
            _read_and_record_source(include_path, result, seen_files)
            continue

        for current_dir, dirs, files in os.walk(
            include_path, onerror=record_walk_error
        ):
            current_path = Path(current_dir)

            dirs[:] = sorted(
                name
                for name in dirs
                if name not in EXCLUDED_DIRECTORIES
                and not _is_excluded(current_path / name, resolved_excludes)
            )

            for name in sorted(files):
                path = current_path / name
                if _is_excluded(path, resolved_excludes):
                    continue
                _read_and_record_source(path, result, seen_files)

    return result
