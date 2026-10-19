"""A-UNSAFE-01 bounded C/C++ unsafe memory/format call detector."""

from __future__ import annotations

import re
from typing import List, Sequence, Set, Tuple

from src.ohscanner.contracts import (
    DetectorFinding,
    DetectorRun,
    EvidenceObligation,
    ScanContext,
    SourceUnit,
)
from .memory_safety import (
    MAX_TOTAL_BYTES,
    MAX_UNIT_BYTES,
    call_argument_span,
    line_column,
    mask_comments_and_literals,
    split_call_arguments,
)


RULE_MEMORY = "ohcpp-unsafe-memory-call-candidate-001"
RULE_FORMAT = "ohcpp-format-string-candidate-002"
RULE_VERSION = "0.1.0"
RULE_LINEAGE_ID = "A-UNSAFE-01:ohcpp-unsafe-call-candidate"

_UNSAFE_MEMORY = {"gets", "strcpy", "strcat", "sprintf"}
_FORMAT_CALLS = {"printf", "fprintf", "syslog", "vprintf", "vfprintf"}
_SAFE_PREFIXES = ("strcpy_s", "strcat_s", "sprintf_s", "snprintf", "vsnprintf", "fgets")

_OBLIGATIONS = (
    EvidenceObligation(
        "source_control_and_format_identity",
        "Resolve attacker-controlled input and whether the format string is literal/trusted.",
        "unknown",
    ),
    EvidenceObligation(
        "destination_capacity",
        "Bind the destination buffer to its exact capacity and alias identity.",
        "unknown",
    ),
    EvidenceObligation(
        "cross_function_and_macro_context",
        "Resolve wrappers, macros, varargs, templates and compile configuration.",
        "missing",
    ),
    EvidenceObligation(
        "entry_or_privilege_boundary",
        "Establish a realistic reachable entry and privilege boundary.",
        "missing",
    ),
    EvidenceObligation(
        "trigger_conditions",
        "Reproduce the unsafe call in an isolated target.",
        "missing",
    ),
    EvidenceObligation(
        "cia_impact",
        "Establish concrete confidentiality, integrity or availability impact.",
        "missing",
    ),
)


def _stable_unique(findings: Sequence[DetectorFinding]) -> Tuple[DetectorFinding, ...]:
    seen: Set[Tuple[object, ...]] = set()
    result: List[DetectorFinding] = []
    for finding in findings:
        key = (finding.file, finding.line, finding.column, finding.rule_id, finding.symbol, finding.message)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return tuple(sorted(result, key=lambda item: (item.file, item.line, item.column or 0, item.rule_id)))


def _finding(
    unit: SourceUnit,
    position: int,
    rule_id: str,
    symbol: str,
    message: str,
    cwe: str,
) -> DetectorFinding:
    line, column = line_column(unit.text, position)
    return DetectorFinding(
        file=unit.path,
        line=line,
        column=column,
        rule_id=rule_id,
        message=message,
        evidence_type="syntax",
        candidate_cwe=cwe,
        symbol=symbol,
        evidence_obligations=_OBLIGATIONS,
        consequence_impact="memory_safety" if rule_id == RULE_MEMORY else "format_string_or_info_leak",
        consequence_cwe=cwe,
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
    )


def _detect_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool]:
    findings: List[DetectorFinding] = []
    if unit.parse_status != "complete":
        return findings, [f"{unit.path}: parse_status={unit.parse_status}; unsafe-call coverage remains unknown."], False
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return findings, [f"{unit.path}: source exceeds the 1MiB per-unit fail-closed budget."], False
    masked = mask_comments_and_literals(unit.text)
    for match in re.finditer(r"\b(?P<name>[A-Za-z_]\w*)\s*\(", masked):
        name = match.group("name")
        if name in _SAFE_PREFIXES:
            continue
        span = call_argument_span(masked, match.start())
        if span is None:
            continue
        original_args = unit.text[span[0]:span[1]]
        args = split_call_arguments(original_args)
        if name in _UNSAFE_MEMORY:
            destination = args[0].strip() if args else "unknown"
            findings.append(_finding(
                unit,
                match.start(),
                RULE_MEMORY,
                destination,
                f"Candidate only: unbounded `{name}` has no modeled destination-length contract. "
                "Capacity, aliases, wrapper semantics and attacker control remain unknown.",
                "CWE-120" if name != "gets" else "CWE-242",
            ))
        elif name in _FORMAT_CALLS and args:
            format_expression = args[-1].strip() if name in {"syslog"} else args[0].strip()
            if name == "syslog" and len(args) >= 2:
                format_expression = args[1].strip()
            if not (format_expression.startswith('"') or format_expression.startswith("'")):
                findings.append(_finding(
                    unit,
                    match.start(),
                    RULE_FORMAT,
                    format_expression,
                    f"Candidate only: `{name}` receives a non-literal format expression `{format_expression}`. "
                    "Control, intended format ownership and concrete impact remain unknown.",
                    "CWE-134",
                ))
        elif name == "scanf" and args:
            format_expression = args[0].strip()
            if re.fullmatch(r'"[^"%]*%s[^"]*"', format_expression) and "%s" in format_expression:
                findings.append(_finding(
                    unit,
                    match.start(),
                    RULE_MEMORY,
                    args[1].strip() if len(args) > 1 else "unknown",
                    "Candidate only: `scanf` uses unbounded `%s`; destination capacity and input control remain unknown.",
                    "CWE-120",
                ))
    return findings, [
        "Candidate only: lexical unsafe-call recognition does not prove exploitability.",
        "Wrappers, macros, varargs, destination aliases, compile context and attacker control remain unknown.",
        "Absence of a finding is not a safe verdict.",
    ], True


class CppUnsafeMemoryCallDetector:
    detector_id = "ohscanner.cpp.unsafe_memory_call"
    version = RULE_VERSION
    supported_languages = ("c", "cpp")
    required_facts = ()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        selected = tuple(unit for unit in units if unit.language in self.supported_languages)
        if not selected:
            return DetectorRun(
                self.detector_id,
                self.version,
                "blocked",
                limitations=("not_applicable: no source with supported language.",),
            )
        ordered = tuple(sorted({unit.path: unit for unit in selected}.values(), key=lambda unit: unit.path))
        total_bytes = sum(len(unit.text.encode("utf-8")) for unit in ordered)
        if any(len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES for unit in ordered) or total_bytes > MAX_TOTAL_BYTES:
            return DetectorRun(
                self.detector_id,
                self.version,
                "failed",
                limitations=("Selected source exceeds the fail-closed unit/run budget.",),
            )
        findings: List[DetectorFinding] = []
        limitations: List[str] = []
        analyzed: List[str] = []
        complete = True
        for unit in ordered:
            unit_findings, unit_limitations, unit_complete = _detect_unit(unit)
            findings.extend(unit_findings)
            limitations.extend(unit_limitations)
            if unit_complete:
                analyzed.append(unit.path)
            else:
                complete = False
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if complete else "blocked",
            analyzed_files=tuple(sorted(analyzed)),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
