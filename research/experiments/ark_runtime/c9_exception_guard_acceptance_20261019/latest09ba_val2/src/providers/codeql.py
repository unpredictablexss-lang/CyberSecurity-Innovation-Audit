"""CodeQL SARIF -> normalized benchmark result adapter."""

from typing import Any, Mapping

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.providers.base import AdapterContext, ToolAdapter, first_cwe


def _message_text(message: Any) -> str:
    if isinstance(message, Mapping):
        return str(message.get("text", "") or "")
    return str(message or "")


def _first_location(result: Mapping[str, Any]):
    locations = result.get("locations", []) or []
    if not locations:
        return "", None, None
    physical = (locations[0].get("physicalLocation", {}) or {})
    artifact = physical.get("artifactLocation", {}) or {}
    region = physical.get("region", {}) or {}
    return (
        str(artifact.get("uri", "") or ""),
        int(region["startLine"]) if region.get("startLine") is not None else None,
        int(region["startColumn"]) if region.get("startColumn") is not None else None,
    )


class CodeQLAdapter(ToolAdapter):
    provider = "codeql"

    def normalize(self, payload: Any, context: AdapterContext) -> ToolRunResult:
        if not isinstance(payload, Mapping):
            raise ValueError("CodeQL SARIF payload must be a mapping")

        diagnostics = []
        runs = payload.get("runs", []) or []
        version = context.tool_version or "unknown"

        for run_index, run in enumerate(runs):
            driver = ((run.get("tool", {}) or {}).get("driver", {}) or {})
            if version == "unknown":
                version = str(
                    driver.get("semanticVersion")
                    or driver.get("version")
                    or "unknown"
                )

            for result_index, result in enumerate(run.get("results", []) or []):
                path, line, column = _first_location(result)
                rule_id = str(result.get("ruleId", "") or "") or None
                properties = result.get("properties", {}) or {}
                tags = properties.get("tags", []) or []
                diagnostic_id = (
                    f"codeql:{run_index}:{result_index}:{path}:{line or 0}:"
                    f"{rule_id or 'unresolved'}"
                )
                diagnostics.append(
                    ToolDiagnostic(
                        diagnostic_id=diagnostic_id,
                        provider=self.provider,
                        evidence_type="dataflow",
                        file=path,
                        line=line,
                        column=column,
                        rule_id=rule_id,
                        severity=str(result.get("level", "unassessed")).lower(),
                        message=_message_text(result.get("message")),
                        candidate_cwe=first_cwe(tags),
                    )
                )

        limitations = list(context.limitations)
        limitations.append(
            "CodeQL adapter uses provider-level evidence_type=dataflow; individual "
            "query semantics must still be reviewed before treating the result as "
            "a source-to-sink proof."
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
