"""Infer/Pulse JSON -> normalized benchmark result adapter."""

from pathlib import PurePosixPath
from typing import Any, List, Mapping, Optional

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.providers.base import AdapterContext, ToolAdapter, first_cwe


_SYMBOLIC_BUG_TYPES = {
    "NULL_DEREFERENCE",
    "USE_AFTER_FREE",
    "RESOURCE_LEAK",
    "MEMORY_LEAK",
    "UNINITIALIZED_VALUE",
    "DATA_RACE",
    "THREAD_SAFETY",
}


def _extract_bugs(payload: Any) -> List[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, Mapping):
        bugs = payload.get("bugs", payload.get("results"))
        if bugs is None:
            return []
        if not isinstance(bugs, list):
            raise ValueError("Infer 'bugs' must be a list")
        return bugs
    raise ValueError("Infer payload must be a mapping or list")


def _coordinate(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 1 else None


def _relative_file(value: Any) -> str:
    text = str(value or "").replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or ":" in text or ".." in path.parts:
        raise ValueError(f"Infer file must be repository-relative: {text}")
    return path.as_posix()


class InferAdapter(ToolAdapter):
    provider = "infer"

    def normalize(self, payload: Any, context: AdapterContext) -> ToolRunResult:
        bugs = _extract_bugs(payload)
        version = context.tool_version
        if not version and isinstance(payload, Mapping):
            version = str(payload.get("infer_version", "") or "") or None
        diagnostics: List[ToolDiagnostic] = []
        for index, item in enumerate(bugs):
            if not isinstance(item, Mapping):
                raise ValueError(f"Infer bug #{index} must be a mapping")
            file = _relative_file(item.get("file", item.get("file_name", "")))
            line = _coordinate(item.get("line"))
            column = _coordinate(item.get("column"))
            bug_type = str(item.get("bug_type", "") or "unknown")
            rule_id = bug_type or None
            evidence_type = (
                "symbolic" if bug_type.upper() in _SYMBOLIC_BUG_TYPES else "unknown"
            )
            symbol = item.get("procedure") or item.get("function")
            if symbol is not None:
                symbol = str(symbol) or None
            diagnostics.append(ToolDiagnostic(
                diagnostic_id=f"infer:{file}:{line or 0}:{bug_type}:{index}",
                provider=self.provider,
                evidence_type=evidence_type,
                file=file,
                line=line,
                column=column,
                rule_id=rule_id,
                severity=str(item.get("severity", "unassessed")).lower(),
                message=str(item.get("qualifier", item.get("message", "")) or ""),
                candidate_cwe=first_cwe(item.get("cwe")),
                symbol=symbol,
            ))

        limitations = list(context.limitations)
        limitations.append(
            "Infer/Pulse output is normalized as descriptive symbolic/unknown evidence; "
            "the adapter does not re-run Infer or prove exploitability."
        )
        return ToolRunResult(
            schema_version=1,
            run_id=context.run_id,
            tool=self.provider,
            tool_version=version or "unknown",
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
