"""Semgrep JSON -> normalized benchmark result adapter."""

from typing import Any, Mapping

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.providers.base import AdapterContext, ToolAdapter, first_cwe


class SemgrepAdapter(ToolAdapter):
    provider = "semgrep"

    def normalize(self, payload: Any, context: AdapterContext) -> ToolRunResult:
        if not isinstance(payload, Mapping):
            raise ValueError("Semgrep payload must be a mapping")

        diagnostics = []
        for index, item in enumerate(payload.get("results", []) or []):
            extra = item.get("extra", {}) or {}
            start = item.get("start", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            path = str(item.get("path", ""))
            rule_id = str(item.get("check_id", "")) or None
            line = start.get("line")
            column = start.get("col")
            diagnostic_id = (
                f"semgrep:{path}:{line or 0}:{rule_id or 'unresolved'}:{index}"
            )
            diagnostics.append(
                ToolDiagnostic(
                    diagnostic_id=diagnostic_id,
                    provider=self.provider,
                    evidence_type="pattern",
                    file=path,
                    line=int(line) if line is not None else None,
                    column=int(column) if column is not None else None,
                    rule_id=rule_id,
                    severity=str(extra.get("severity", "unassessed")).lower(),
                    message=str(extra.get("message", "")),
                    candidate_cwe=first_cwe(metadata.get("cwe")),
                )
            )

        version = (
            context.tool_version
            or str(payload.get("version", "") or "")
            or "unknown"
        )
        limitations = list(context.limitations)
        limitations.append(
            "Semgrep adapter normalizes reported patterns only; rule semantics and "
            "reachability are not re-evaluated by the adapter."
        )
        return ToolRunResult(
            schema_version=1,
            run_id=context.run_id,
            tool=self.provider,
            tool_version=version,
            target_id=context.target_id,
            commit=context.commit,
            scope_files=context.scope_files,
            scope_loc=context.scope_loc,
            status=context.status,
            elapsed_seconds=context.elapsed_seconds,
            peak_memory_mb=context.peak_memory_mb,
            diagnostics=diagnostics,
            limitations=limitations,
        )
