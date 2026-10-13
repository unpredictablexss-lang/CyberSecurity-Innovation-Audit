"""Read-only fact views for a future evidence-investigation Agent.

The view exposes only facts already bound to a ScanContext. Missing CFG, call
graphs, guard dominance and reachability remain unknown; this module cannot
execute tools or change finding status.
"""

from dataclasses import asdict
from typing import Any, Dict, Optional

from .contracts import ScanContext, safe_relative_path


class ReadOnlyFactView:
    def __init__(self, context: ScanContext) -> None:
        self._context = context
        self._units = {unit.path: unit for unit in context.units}

    @property
    def request(self) -> Dict[str, Any]:
        return asdict(self._context.request)

    def get_source_context(
        self,
        path: str,
        *,
        start_line: int = 1,
        end_line: Optional[int] = None,
    ) -> Dict[str, Any]:
        safe_relative_path(path)
        unit = self._units.get(path)
        if unit is None:
            return {"status": "unknown", "reason": "path is not present in ScanContext"}
        if isinstance(start_line, bool) or not isinstance(start_line, int) or start_line < 1:
            raise ValueError("start_line must be a positive integer")
        lines = unit.text.splitlines()
        stop = len(lines) if end_line is None else end_line
        if isinstance(stop, bool) or not isinstance(stop, int) or stop < start_line:
            raise ValueError("end_line must be >= start_line")
        return {
            "status": "observed",
            "path": path,
            "sha256": unit.sha256,
            "parse_status": unit.parse_status,
            "start_line": start_line,
            "end_line": min(stop, len(lines)),
            "text": "\n".join(lines[start_line - 1:stop]),
            "truncated": stop > len(lines),
        }

    def get_syntax_facts(self, path: Optional[str] = None) -> Dict[str, Any]:
        facts = self._context.shared_facts.get("syntax_facts")
        if not isinstance(facts, dict):
            return {"status": "unknown", "reason": "syntax facts were not supplied"}
        if path is None:
            return {"status": "observed", "facts": facts}
        safe_relative_path(path)
        if path not in facts:
            return {"status": "unknown", "reason": "syntax facts are unavailable for path"}
        return {"status": "observed", "path": path, "facts": facts[path]}

    def get_guard_facts(self, path: str) -> Dict[str, Any]:
        safe_relative_path(path)
        syntax = self.get_syntax_facts(path)
        if syntax["status"] != "observed":
            return syntax
        guards = syntax["facts"].get("guards", [])
        return {
            "status": "observed" if guards else "unknown",
            "path": path,
            "guards": guards,
            "reason": None if guards else "No guard-dominance facts were supplied.",
        }

    def get_call_path(self, source: str, destination: str) -> Dict[str, Any]:
        if not source.strip() or not destination.strip():
            raise ValueError("call-path endpoints must not be empty")
        return {
            "status": "unknown",
            "source": source,
            "destination": destination,
            "reason": "No validated cross-function call graph is available in ScanContext.",
        }

    def get_detector_results(self) -> Dict[str, Any]:
        results = self._context.shared_facts.get("detector_results")
        if results is None:
            return {"status": "unknown", "reason": "detector results were not supplied"}
        return {"status": "observed", "results": results}

    def get_coverage(self) -> Dict[str, Any]:
        return {
            "status": "observed",
            "files": {
                unit.path: {"parse_status": unit.parse_status, "parse_issues": list(unit.parse_issues)}
                for unit in self._context.units
            },
            "limitations": [
                "Parse status is syntax coverage, not type, CFG, reachability or safety proof."
            ],
        }

    def get_evidence_obligations(self) -> Dict[str, Any]:
        results = self.get_detector_results()
        if results["status"] != "observed":
            return results
        obligations = []
        for result in results["results"]:
            if isinstance(result, dict):
                obligations.extend(result.get("evidence_obligations", []) or [])
        return {"status": "observed", "obligations": obligations}
