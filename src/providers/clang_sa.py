"""Existing Clang Static Analyzer JSON -> normalized benchmark adapter."""

from typing import Any, Mapping

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.providers.base import AdapterContext, ToolAdapter, first_cwe


class ClangSAAdapter(ToolAdapter):
    provider = "clang_sa"

    def normalize(self, payload: Any, context: AdapterContext) -> ToolRunResult:
        if not isinstance(payload, Mapping):
            raise ValueError("Clang baseline payload must be a mapping")

        diagnostics = []
        for index, item in enumerate(payload.get("diagnostics", []) or []):
            file = str(item.get("file", "") or "")
            line = item.get("line")
            column = item.get("column")
            checker = str(item.get("checker", "") or "") or None
            message = str(item.get("message", "") or "")
            diagnostic_id = (
                f"clang_sa:{file}:{line or 0}:{checker or 'unresolved'}:{index}"
            )
            diagnostics.append(
                ToolDiagnostic(
                    diagnostic_id=diagnostic_id,
                    provider=self.provider,
                    evidence_type="symbolic",
                    file=file,
                    line=int(line) if line is not None else None,
                    column=int(column) if column is not None else None,
                    rule_id=checker,
                    severity=str(item.get("level", "unassessed")).lower(),
                    message=message,
                    candidate_cwe=first_cwe(message),
                )
            )

        version = (
            context.tool_version
            or str(payload.get("clang_version", "") or "")
            or "unknown"
        )
        limitations = list(context.limitations)
        limitations.append(
            "Clang SA diagnostics are path/symbolic evidence only; zero diagnostics "
            "do not prove safety and diagnostics are not vulnerability verdicts."
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
