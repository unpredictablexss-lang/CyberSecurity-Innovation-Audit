"""Convert a normalized ToolDiagnostic into the project Evidence schema.

This standardizes evidence shape only; it does not judge the diagnostic as a
true or false positive and does not change any candidate status.
"""

from src.benchmark.tool_result import ToolDiagnostic
from src.core.case import make_evidence_id
from src.core.evidence import Evidence


def evidence_from_tool_diagnostic(
    diagnostic: ToolDiagnostic,
    target_id: str,
) -> Evidence:
    if diagnostic.line is not None:
        location = f"{diagnostic.file}:{diagnostic.line}"
    else:
        location = diagnostic.file
    content = diagnostic.message or f"{diagnostic.provider} {diagnostic.rule_id or ''}".strip()
    return Evidence(
        evidence_id=make_evidence_id(
            f"{diagnostic.provider}:{diagnostic.diagnostic_id}", content
        ),
        type=diagnostic.evidence_type,
        source=diagnostic.provider,
        location=location,
        content=content,
        proposition=f"Tool {diagnostic.provider} reported a finding at this location",
        confidence=0.0,
    )
