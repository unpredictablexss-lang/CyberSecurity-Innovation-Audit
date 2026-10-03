from pathlib import Path
from typing import List

from src.core.finding import Finding


DANGEROUS_CALLS = {
    "strcpy": ("CWE-120", "Classic Buffer Overflow"),
    "strcat": ("CWE-120", "Classic Buffer Overflow"),
    "sprintf": ("CWE-120", "Classic Buffer Overflow"),
    "gets": ("CWE-242", "Use of Inherently Dangerous Function"),
    "memcpy": ("CWE-787", "Out-of-bounds Write"),
}


SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"
}


def scan_file(path: Path) -> List[Finding]:
    findings: List[Finding] = []

    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return findings

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        for func, (cwe, vuln_type) in DANGEROUS_CALLS.items():
            if f"{func}(" in stripped:
                findings.append(
                    Finding(
                        rule_id=f"cpp.dangerous_call.{func}",
                        title=f"Potential dangerous C/C++ call: {func}",
                        vulnerability_type=vuln_type,
                        cwe=cwe,
                        severity="medium",
                        confidence="candidate",
                        file_path=str(path),
                        line=idx,
                        function=None,
                        evidence=stripped,
                        explanation=(
                            f"The code calls {func}(), which can be unsafe when "
                            "buffer size, input length, or destination capacity is not verified. "
                            "This is only a candidate and requires context analysis or runtime validation."
                        ),
                        remediation=(
                            "Verify input length and destination capacity before the call. "
                            "Prefer bounded alternatives or safer abstractions where appropriate."
                        ),
                    )
                )

    return findings


def scan_directory(root: Path) -> List[Finding]:
    all_findings: List[Finding] = []

    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
            all_findings.extend(scan_file(path))

    return all_findings
