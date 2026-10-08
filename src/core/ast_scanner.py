"""AST-based candidate scanner (tree-sitter upgrade of src.core.scanner).

Instead of regex-matching raw lines, this parses each C/C++ file into an AST
index and reports dangerous call expressions. It produces the same
Finding/Candidate shape and statuses as the text scanner; nothing here is a
validated vulnerability.
"""

import os
from pathlib import Path
from typing import List, Optional, Set

from src.core.finding import Finding
from src.core.scanner import (
    DANGEROUS_CALLS,
    EXCLUDED_DIRECTORIES,
    SOURCE_SUFFIXES,
    ScanResult,
    _is_excluded,
    _relative_scope_text,
    _resolve_scope_path,
)
from src.parser.ast import FunctionDef, parse_source


def _language_for_path(path: Path) -> Optional[str]:
    suffix = path.suffix.lower()
    if suffix == ".c":
        return "c"
    if suffix in {".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}:
        return "cpp"
    return None


def _enclosing_function(
    functions: List[FunctionDef], line: int
) -> Optional[FunctionDef]:
    for function in functions:
        if function.start_line <= line <= function.end_line:
            return function
    return None


def _call_evidence(name: str, arguments: List[str]) -> str:
    return f"{name}({', '.join(arguments)})"


def _scan_lines_ast(path: Path, lines: List[str], language: str, index=None) -> List[Finding]:
    code = "\n".join(lines)
    index = index if index is not None else parse_source(code, language=language)
    findings: List[Finding] = []

    for call in index.calls:
        if call.name not in DANGEROUS_CALLS:
            continue
        cwe, vuln_type = DANGEROUS_CALLS[call.name]
        function = _enclosing_function(index.functions, call.line)

        function_start = function.start_line if function else None
        function_end = function.end_line if function else None
        context_start = max(1, call.line - 3)
        context_end = min(len(lines), call.line + 3)
        if function is not None:
            context_start = max(function.start_line, context_start)
            context_end = min(function.end_line, context_end)
        snippet = "\n".join(lines[context_start - 1 : context_end])
        evidence = _call_evidence(call.name, call.arguments)

        findings.append(
            Finding(
                rule_id=f"cpp.dangerous_call.{call.name}",
                title=f"Candidate dangerous C/C++ call: {call.name}",
                vulnerability_type=vuln_type,
                cwe=cwe,
                severity="unassessed",
                confidence="unassessed",
                file_path=str(path),
                line=call.line,
                function=function.name if function else None,
                evidence=evidence,
                explanation=(
                    f"AST-resolved call expression {evidence}. "
                    "Arguments, destination capacity, reachability, and "
                    "security impact have not been verified."
                ),
                remediation=(
                    "Check the source and destination bounds in context. "
                    "Only propose a code change after confirming the risk."
                ),
                function_start_line=function_start,
                function_end_line=function_end,
                context_start_line=context_start,
                context_end_line=context_end,
                context=snippet,
                context_status=("ast_partial_context" if index.parse_status != "complete"
                                else "ast_function_context" if function else "unresolved"),
            )
        )

    return findings


def scan_file_ast(path: Path) -> List[Finding]:
    """Parse one .c/.cpp/.h file into an AST index and report dangerous calls."""
    language = _language_for_path(path)
    if language is None:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return _scan_lines_ast(path, lines, language)


def _read_and_record_source_ast(
    path: Path, result: ScanResult, seen_files: Set[Path]
) -> None:
    resolved = path.resolve()
    if resolved in seen_files:
        return
    seen_files.add(resolved)

    if path.suffix.lower() not in SOURCE_SUFFIXES:
        return
    if path.is_symlink():
        result.skipped_files.append(f"{path}: symbolic link")
        return

    language = _language_for_path(path)
    if language is None:
        return

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        result.skipped_files.append(f"{path}: {error.strerror}")
        return

    result.scanned_files += 1
    result.scanned_lines += len(lines)
    try:
        index = parse_source("\n".join(lines), language=language)
    except (RuntimeError, ValueError) as error:
        result.parsing.append({"file": str(path), "status": "failed", "reason": str(error)})
        return
    result.parsing.append({"file": str(path), "status": index.parse_status,
                           "issues": index.parse_issues})
    result.findings.extend(_scan_lines_ast(path, lines, language, index=index))


def scan_directory_ast(
    root: Path,
    include_paths: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
) -> ScanResult:
    """AST-scanner equivalent of src.core.scanner.scan_directory."""
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
        engine="ast",
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
            _read_and_record_source_ast(include_path, result, seen_files)
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
                _read_and_record_source_ast(path, result, seen_files)

    return result
