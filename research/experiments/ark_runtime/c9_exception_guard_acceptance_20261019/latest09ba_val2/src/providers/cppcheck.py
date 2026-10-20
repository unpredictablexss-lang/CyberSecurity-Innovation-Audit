"""Cppcheck XML -> normalized benchmark result adapter."""

import xml.etree.ElementTree as ET
from typing import Any

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.providers.base import AdapterContext, ToolAdapter


class CppcheckAdapter(ToolAdapter):
    provider = "cppcheck"

    def normalize(self, payload: Any, context: AdapterContext) -> ToolRunResult:
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="replace")
        if not isinstance(payload, str):
            raise ValueError("Cppcheck payload must be XML text")

        try:
            root = ET.fromstring(payload)
        except ET.ParseError as error:
            raise ValueError(f"invalid Cppcheck XML: {error}") from error

        cppcheck_node = root.find(".//cppcheck")
        version = context.tool_version or (
            cppcheck_node.get("version") if cppcheck_node is not None else None
        ) or "unknown"

        diagnostics = []
        for error_index, error_node in enumerate(root.findall(".//error")):
            locations = error_node.findall("location")
            if not locations:
                locations = [None]

            cwe_value = error_node.get("cwe")
            cwe = f"CWE-{cwe_value}" if cwe_value and cwe_value.isdigit() else None
            rule_id = error_node.get("id")
            message = error_node.get("verbose") or error_node.get("msg") or ""

            for location_index, location in enumerate(locations):
                file = location.get("file", "") if location is not None else ""
                line_text = location.get("line") if location is not None else None
                col_text = location.get("column") if location is not None else None
                line = int(line_text) if line_text and line_text.isdigit() else None
                column = int(col_text) if col_text and col_text.isdigit() else None
                # cppcheck emits column="0" for diagnostics where the column is
                # intentionally unknown (e.g. unusedFunction). Model "0" as
                # unknown (None) instead of an invalid coordinate.
                if column == 0:
                    column = None
                diagnostic_id = (
                    f"cppcheck:{error_index}:{location_index}:{file}:{line or 0}:"
                    f"{rule_id or 'unresolved'}"
                )
                diagnostics.append(
                    ToolDiagnostic(
                        diagnostic_id=diagnostic_id,
                        provider=self.provider,
                        evidence_type="syntax",
                        file=file,
                        line=line,
                        column=column,
                        rule_id=rule_id,
                        severity=str(error_node.get("severity", "unassessed")).lower(),
                        message=message,
                        candidate_cwe=cwe,
                    )
                )

        limitations = list(context.limitations)
        limitations.append(
            "Cppcheck adapter normalizes XML findings as lightweight static evidence; "
            "it does not infer reachability or exploitability."
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
