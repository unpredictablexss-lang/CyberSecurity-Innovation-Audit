"""Joern query-result JSON -> normalized benchmark result adapter.

Joern is a code-property-graph query engine; it has no native "findings"
format. This adapter consumes the JSON convention emitted by the project's
Joern query scripts (see ``scripts/joern_nothrow_guard.sc``): either a bare
list of findings, or an object with a ``findings`` list. Each finding declares
its own ``rule_id``, ``file``/``line`` and metadata.

Like the other adapters this only translates already-produced query output. It
does not build CPGs, does not run Joern, and does not decide whether a finding
is a vulnerability.
"""

from typing import Any, List, Mapping, Optional

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.providers.base import AdapterContext, ToolAdapter, first_cwe


# Joern queries are project-authored and can be structural, control-flow or
# dataflow. When a query does not declare its evidence type the adapter records
# "unknown" rather than guessing a mechanism (matches the schema's
# confidence="unassessed" default).
_DEFAULT_EVIDENCE_TYPE = "unknown"


def _extract_findings(payload: Any) -> List[Any]:
    if isinstance(payload, Mapping):
        findings = payload.get("findings")
    elif isinstance(payload, list):
        findings = payload
    else:
        raise ValueError(
            "Joern payload must be a mapping with 'findings' or a list of findings"
        )

    if findings is None:
        return []
    if isinstance(findings, (str, bytes)) or not isinstance(findings, (list, tuple)):
        raise ValueError("Joern 'findings' must be a list of finding objects")
    return list(findings)


def _optional_positive_int(value: Any) -> Optional[int]:
    """Coerce a coordinate to a positive int, or None when unusable.

    Joern line/column metadata can be -1/0/null for synthetic CPG nodes; those
    are modelled as "unknown" rather than as invalid coordinates.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 1 else None


class JoernAdapter(ToolAdapter):
    provider = "joern"

    def normalize(self, payload: Any, context: AdapterContext) -> ToolRunResult:
        findings = _extract_findings(payload)

        declared_version = None
        if isinstance(payload, Mapping):
            declared_version = payload.get("joern_version")
        version = (
            context.tool_version
            or (str(declared_version) if declared_version else "")
            or "unknown"
        )

        diagnostics: List[ToolDiagnostic] = []
        for index, item in enumerate(findings):
            if not isinstance(item, Mapping):
                raise ValueError(f"Joern finding #{index} must be a mapping")

            file = str(item.get("file", "") or "")
            line = _optional_positive_int(item.get("line"))
            column = _optional_positive_int(item.get("column"))
            rule_id = str(item.get("rule_id", "") or "") or None
            evidence_type = str(
                item.get("evidence_type", "") or _DEFAULT_EVIDENCE_TYPE
            )
            cwe = first_cwe(item.get("cwe") or item.get("candidate_cwe"))

            diagnostics.append(
                ToolDiagnostic(
                    diagnostic_id=(
                        f"joern:{file}:{line or 0}:{rule_id or 'unresolved'}:{index}"
                    ),
                    provider=self.provider,
                    evidence_type=evidence_type,
                    file=file,
                    line=line,
                    column=column,
                    rule_id=rule_id,
                    severity=str(item.get("severity", "unassessed")).lower(),
                    message=str(item.get("message", "")),
                    candidate_cwe=cwe,
                    symbol=item.get("symbol"),
                )
            )

        limitations = list(context.limitations)
        limitations.append(
            "Joern findings come from project-authored CPG queries, not from a "
            "standard rule format; query semantics must be read alongside the "
            "script that produced them."
        )
        limitations.append(
            "Joern c2cpg parses without a build, so statements whose headers are "
            "absent from the scanned tree may be extracted only partially."
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
