from html import escape

from src.core.scanner import ScanResult


def _text(value: object) -> str:
    return escape(str(value)).replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    lines = [
        "# Candidate Scan Report",
        "",
        ("> Syntax-pattern candidates only. No finding has been validated as a vulnerability."
         if result.engine == "ast" else
         "> Text-pattern candidates only. No finding has been validated as a vulnerability."),
        "",
        "## Scan Summary",
        "",
        f"- Target: {_text(result.target)}",
        f"- Include scope: {_text(', '.join(result.scope_includes))}",
        (
            "- Exclude scope: "
            + _text(", ".join(result.scope_excludes) if result.scope_excludes else "(none)")
        ),
        f"- Scanned files: {result.scanned_files}",
        f"- Scanned lines: {result.scanned_lines}",
        f"- Skipped source files: {len(result.skipped_files)}",
        f"- Candidate findings: {result.finding_count}",
        "",
    ]

    if result.skipped_files:
        lines += ["## Skipped Source Files", ""]
        lines += [f"- {_text(item)}" for item in result.skipped_files]
        lines.append("")

    if result.parsing:
        lines += ["## AST parsing coverage", "",
                  "Complete means syntactically parsed, not semantic or security coverage.", ""]
        lines += [f"- {_text(item['file'])}: {_text(item['status'])}; "
                  f"issues: {_text(item.get('issues', []))}; {_text(item.get('reason', ''))}"
                  for item in result.parsing]
        lines.append("")

    for number, finding in enumerate(result.findings, start=1):
        lines += [
            f"## Candidate {number}: {_text(finding.title)}",
            "",
            f"- Rule ID: {_text(finding.rule_id)}",
            f"- Status: {_text(finding.status)}",
            f"- CWE (provisional): {_text(finding.cwe)}",
            f"- Severity: {_text(finding.severity)}",
            f"- Confidence: {_text(finding.confidence)}",
            f"- File: {_text(finding.file_path)}",
            f"- Line: {finding.line}",
            f"- Function: {_text(finding.function or 'unresolved')}",
            (
                "- Function range: "
                + (
                    f"{finding.function_start_line}-{finding.function_end_line}"
                    if finding.function_start_line is not None
                    and finding.function_end_line is not None
                    else "unresolved"
                )
            ),
            f"- Context status: {_text(finding.context_status)}",
            (
                "- Context lines: "
                + (
                    f"{finding.context_start_line}-{finding.context_end_line}"
                    if finding.context_start_line is not None
                    and finding.context_end_line is not None
                    else "unresolved"
                )
            ),
            "",
            "**Evidence**",
            "",
            "    " + finding.evidence.replace("\n", "\n    "),
            "",
            "**Context**",
            "",
            "    " + (finding.context or "(unavailable)").replace("\n", "\n    "),
            "",
            f"**Explanation:** {_text(finding.explanation)}",
            "",
            f"**Remediation:** {_text(finding.remediation)}",
            "",
        ]

    return "\n".join(lines).rstrip() + "\n"
