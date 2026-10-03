import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

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
    scanned_files: int = 0
    scanned_lines: int = 0
    findings: List[Finding] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scanned_files": self.scanned_files,
            "scanned_lines": self.scanned_lines,
            "skipped_file_count": len(self.skipped_files),
            "skipped_files": self.skipped_files,
            "finding_count": self.finding_count,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _scan_lines(path: Path, lines: List[str]) -> List[Finding]:
    findings: List[Finding] = []

    for idx, line in enumerate(lines, start=1):
        # This is a text candidate generator, not a C/C++ parser. A match can
        # still be in a comment, macro, declaration, or unreachable code.
        for func in dict.fromkeys(CALL_PATTERN.findall(line)):
            cwe, vuln_type = DANGEROUS_CALLS[func]
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
                    function=None,
                    evidence=line.strip(),
                    explanation=(
                        f"The text contains a call-shaped use of {func}(). "
                        "Arguments, destination capacity, reachability, and "
                        "security impact have not been verified."
                    ),
                    remediation=(
                        "Check the source and destination bounds in context. "
                        "Only propose a code change after confirming the risk."
                    ),
                )
            )

    return findings


def scan_file(path: Path) -> List[Finding]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return _scan_lines(path, lines)


def scan_directory(root: Path) -> ScanResult:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Target is not a directory: {root}")

    result = ScanResult(target=str(root))

    def record_walk_error(error: OSError) -> None:
        result.skipped_files.append(f"{error.filename}: {error.strerror}")

    for current_dir, dirs, files in os.walk(root, onerror=record_walk_error):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRECTORIES)
        for name in sorted(files):
            path = Path(current_dir) / name
            if path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            if path.is_symlink():
                result.skipped_files.append(f"{path}: symbolic link")
                continue
            try:
                lines = path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError as error:
                result.skipped_files.append(f"{path}: {error.strerror}")
                continue
            result.scanned_files += 1
            result.scanned_lines += len(lines)
            result.findings.extend(_scan_lines(path, lines))

    return result
