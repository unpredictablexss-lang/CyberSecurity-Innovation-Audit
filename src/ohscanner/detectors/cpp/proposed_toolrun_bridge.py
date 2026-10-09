"""Proposed detector-to-ToolRunResult v1 mapping.

The mapping only reads the existing public ToolRunResult/ToolDiagnostic schema.
It does not add fields or change providers, frontend, IR, integration, CLI,
triage, or reporting.
"""

from __future__ import annotations

from typing import Set

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult

from .proposed_contract import ProposedDetectorRun, ProposedScanRequest


def map_detector_run_to_toolrun_v1(
    request: ProposedScanRequest,
    run: ProposedDetectorRun,
    run_id: str,
) -> ToolRunResult:
    unique_diagnostics = {}
    duplicate_ids = set()
    for item in run.diagnostics:
        if item.diagnostic_id in unique_diagnostics:
            duplicate_ids.add(item.diagnostic_id)
            continue
        unique_diagnostics[item.diagnostic_id] = ToolDiagnostic(
            diagnostic_id=item.diagnostic_id,
            provider=item.provider,
            evidence_type=item.evidence_type,
            file=item.file,
            line=item.line,
            column=item.column,
            rule_id=item.rule_id,
            severity=item.severity,
            message=item.message,
            candidate_cwe=item.candidate_cwe,
            confidence=item.confidence,
            symbol=item.symbol,
        )
    diagnostics = list(unique_diagnostics.values())
    parsing = [item.to_parsing_entry() for item in run.coverage]
    limitations: Set[str] = set(run.limitations)
    limitations.update(f"Duplicate diagnostic_id ignored in proposed bridge: {item}" for item in sorted(duplicate_ids))
    for item in run.diagnostics:
        limitations.update(item.limitations)
    limitations.update(run.missing_obligations)

    return ToolRunResult(
        schema_version=1,
        run_id=run_id,
        tool=run.detector_id,
        tool_version=run.version,
        target_id=request.target_id,
        commit=request.commit,
        scope_files=run.scope_files,
        scope_loc=run.scope_loc,
        status=run.status,
        elapsed_seconds=run.elapsed_seconds,
        peak_memory_mb=None,
        diagnostics=diagnostics,
        limitations=sorted(limitations),
        parsing=parsing,
    )
