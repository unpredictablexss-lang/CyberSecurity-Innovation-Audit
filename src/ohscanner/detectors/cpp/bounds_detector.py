"""A-BOF-01 bounded C/C++ array and copy-length candidate detector.

This detector intentionally reports only a small set of local memory-bound
violations whose destination or index capacity is syntactically available.
Unknown aliases, macros, interprocedural lengths and partial parses remain
unknown and never become safe verdicts.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from typing import Dict, List, Optional, Sequence, Set, Tuple

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
    ArrayShape,
    call_argument_span,
    declarations,
    expression_interval,
    function_shapes,
    function_at,
    guard_constraints,
    guard_shapes,
    line_column,
    mask_comments_and_literals,
    split_call_arguments,
)


RULE_COPY = "ohcpp-memory-bounds-copy-candidate-001"
RULE_INDEX = "ohcpp-memory-bounds-index-candidate-002"
RULE_ELEMENT_ACCESS = "ohcpp-memory-bounds-element-access-candidate-003"
RULE_VERSION = "0.2.0"
RULE_LINEAGE_ID = "A-BOF-01:ohcpp-memory-bounds-candidate"

_OBLIGATIONS = (
    EvidenceObligation(
        "capacity_and_alias_identity",
        "Bind the destination/index object to its exact storage, byte width and aliases.",
        "unknown",
    ),
    EvidenceObligation(
        "guard_dominance",
        "Prove every violating path is dominated by complete lower/upper length guards.",
        "unknown",
    ),
    EvidenceObligation(
        "cross_function_and_macro_context",
        "Resolve parameters, wrappers, macros, templates and compile-time constants.",
        "missing",
    ),
    EvidenceObligation(
        "entry_or_privilege_boundary",
        "Establish a realistic reachable entry and privilege boundary.",
        "missing",
    ),
    EvidenceObligation(
        "attacker_control",
        "Show attacker influence over the index or copy length.",
        "missing",
    ),
    EvidenceObligation(
        "trigger_conditions",
        "Reproduce a concrete violating path in an isolated harness.",
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
        key = (
            finding.file, finding.line, finding.column, finding.rule_id,
            finding.symbol, finding.message,
        )
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return tuple(sorted(result, key=lambda item: (item.file, item.line, item.column or 0, item.rule_id)))


def _finding(
    unit: SourceUnit,
    text: str,
    position: int,
    rule_id: str,
    symbol: str,
    message: str,
    candidate_cwe: str,
    consequence_cwe: str,
) -> DetectorFinding:
    line, column = line_column(text, position)
    return DetectorFinding(
        file=unit.path,
        line=line,
        column=column,
        rule_id=rule_id,
        message=message,
        evidence_type="syntax",
        candidate_cwe=candidate_cwe,
        symbol=symbol,
        evidence_obligations=_OBLIGATIONS,
        consequence_impact="memory_safety",
        consequence_cwe=consequence_cwe,
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
    )


def _size_of_value(expression: str, arrays: Dict[str, ArrayShape]) -> Optional[int]:
    match = re.fullmatch(r"\s*sizeof\s*\(\s*(?P<name>[A-Za-z_]\w*)\s*\)", expression)
    if not match:
        return None
    shape = arrays.get(match.group("name"))
    if shape is None or shape.capacity is None or shape.element_size is None:
        return None
    return shape.capacity * shape.element_size


def _safe_copy_length(
    expression: str,
    destination: str,
    arrays: Dict[str, ArrayShape],
) -> bool:
    text = re.sub(r"\s+", "", expression)
    safe_tokens = {
        "sizeof(" + destination + ")",
        "sizeof(" + destination + "[0])",
        "sizeof" + destination,
    }
    if text in safe_tokens:
        return True
    if re.fullmatch(r"sizeof\(" + re.escape(destination) + r"\[0\]\)\*" + re.escape(destination) + r"size", text):
        return True
    return False


def _effective_upper_guard(
    length_expression: str,
    destination_capacity: int,
    constraints: Dict[str, Tuple[Optional[int], Optional[int]]],
) -> bool:
    interval = expression_interval(length_expression, {}, constraints)
    return interval.maximum is not None and interval.maximum <= destination_capacity


def _contains_symbol(expression: str) -> bool:
    return bool(re.search(r"[A-Za-z_]\w*", re.sub(r"\bsizeof\b", "", expression)))


def _nonnegative_symbols(masked: str) -> Set[str]:
    symbols: Set[str] = set()
    for match in re.finditer(
        r"\b(?:unsigned(?:\s+int)?|size_t|u?int(?:8|16|32|64)_t|uintptr_t)\s+"
        r"(?P<name>[A-Za-z_]\w*)",
        masked,
    ):
        symbols.add(match.group("name"))
    return symbols


def _detect_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool]:
    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    complete = True
    if unit.parse_status != "complete":
        return findings, [f"{unit.path}: parse_status={unit.parse_status}; bounds coverage remains unknown."], False
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return findings, [f"{unit.path}: source exceeds the 1MiB per-unit fail-closed budget."], False

    masked = mask_comments_and_literals(unit.text)
    functions = function_shapes(masked)
    arrays, _integers, constants = declarations(masked)
    guards = guard_shapes(masked, functions)
    nonnegative = _nonnegative_symbols(masked)
    sizeof_values = {
        name: shape.capacity * shape.element_size
        for name, shape in arrays.items()
        if shape.capacity is not None and shape.element_size is not None
    }

    for match in re.finditer(r"\b(?P<name>memcpy|memmove|strncpy|snprintf|sprintf|strcpy|strcat)\s*\(", masked):
        span = call_argument_span(masked, match.start())
        if span is None:
            limitations.append(f"{unit.path}: unbalanced call at offset {match.start()} remains unknown.")
            complete = False
            continue
        args = split_call_arguments(span[2])
        if len(args) < 2:
            continue
        destination = args[0].strip()
        destination_shape = arrays.get(destination)
        if destination_shape is None or destination_shape.capacity is None or destination_shape.element_size is None:
            continue
        capacity_bytes = destination_shape.capacity * destination_shape.element_size
        call_name = match.group("name")
        if call_name in {"strcpy", "strcat", "sprintf"}:
            findings.append(_finding(
                unit, unit.text, match.start(), RULE_COPY, destination,
                f"Candidate only: `{call_name}` writes to fixed array `{destination}` "
                f"({capacity_bytes} bytes) without a modeled destination upper bound; "
                "alias, format and source length semantics remain unknown.",
                "CWE-120", "CWE-787",
            ))
            continue
        if call_name in {"memcpy", "memmove"} and len(args) < 3:
            continue
        length_expression = args[2] if call_name in {"memcpy", "memmove"} else args[-1]
        if _safe_copy_length(length_expression, destination, arrays):
            continue
        explicit_size = _size_of_value(length_expression, arrays)
        constraints = guard_constraints(guards, match.start(), constants, sizeof_values)
        interval = expression_interval(length_expression, constants, constraints)
        if explicit_size is not None and explicit_size <= capacity_bytes:
            continue
        definite = (
            interval.definitely_greater_than(capacity_bytes)
            or (explicit_size is not None and explicit_size > capacity_bytes)
        )
        unbounded = _contains_symbol(length_expression) and not _effective_upper_guard(
            length_expression, capacity_bytes, constraints
        )
        if definite or unbounded:
            qualifier = "demonstrated upper-bound violation" if definite else "unproven upper bound"
            findings.append(_finding(
                unit, unit.text, match.start(), RULE_COPY, destination,
                f"Candidate only: `{call_name}` length `{length_expression.strip()}` has an "
                f"{qualifier} against fixed array `{destination}` ({capacity_bytes} bytes). "
                "Byte/element units, aliases and complete guard dominance remain unknown.",
                "CWE-119", "CWE-787" if call_name != "strncpy" else "CWE-120",
            ))

    for match in re.finditer(r"\b(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<index>[^]\[]+)\s*\]", masked):
        before = masked[:match.start()]
        if re.search(r"(?:char|short|int|long|u?int(?:8|16|32|64)_t)\s+$", before):
            continue
        shape = arrays.get(match.group("name"))
        if shape is None or shape.capacity is None:
            continue
        index_expression = match.group("index").strip()
        constraints = guard_constraints(guards, match.start(), constants, sizeof_values)
        interval = expression_interval(index_expression, constants, constraints)
        safe_upper = interval.maximum is not None and interval.maximum < shape.capacity
        safe_lower = interval.is_nonnegative() or index_expression in nonnegative
        definite = interval.definitely_at_least(shape.capacity) or (
            interval.maximum is not None and interval.maximum < 0
        )
        unbounded_index = _contains_symbol(index_expression) and not (safe_upper and safe_lower)
        if definite or unbounded_index:
            qualifier = "demonstrated out-of-range index" if definite else "unproven in-range index"
            findings.append(_finding(
                unit, unit.text, match.start(), RULE_INDEX, shape.name,
                f"Candidate only: index `{index_expression}` has an {qualifier} for fixed array "
                f"`{shape.name}` with capacity {shape.capacity}. Complete CFG, signedness and "
                "alias facts remain unknown.",
                "CWE-125" if not definite or interval.maximum is not None and interval.maximum < 0 else "CWE-787",
                "CWE-125" if interval.maximum is not None and interval.maximum < 0 else "CWE-787",
            ))
    for match in re.finditer(r"\bElementAccessor::(?P<kind>Get|Set)\s*\(", masked):
        function = function_at(functions, match.start())
        if function is None or not re.search(r"SortElements", function.name):
            continue
        if function.name.startswith("CheckStableArray"):
            continue
        body = function.text
        if re.search(r"\bindex\s*<\s*ElementAccessor::GetElementsLength", body):
            continue
        findings.append(_finding(
            unit,
            unit.text,
            match.start(),
            RULE_ELEMENT_ACCESS,
            function.name,
            f"Candidate only: direct `ElementAccessor::{match.group('kind')}` in `{function.name}` lacks a "
            "modeled stable-array/index guard; backing-store shrink or comparator mutation may cause an "
            "out-of-bounds read/write. Runtime reachability and product impact remain unknown.",
            "CWE-787" if match.group("kind") == "Set" else "CWE-125",
            "CWE-787" if match.group("kind") == "Set" else "CWE-125",
        ))
    return findings, limitations, complete


class CppBoundsDetector:
    detector_id = "ohscanner.cpp.bounds"
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
        oversized = tuple(unit.path for unit in ordered if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES)
        if oversized or total_bytes > MAX_TOTAL_BYTES:
            reason = (
                "Selected source exceeds the 32MiB fail-closed run budget."
                if total_bytes > MAX_TOTAL_BYTES
                else "Selected source exceeds the 1MiB per-unit fail-closed budget."
            )
            return DetectorRun(
                self.detector_id,
                self.version,
                "failed",
                limitations=(reason,),
            )
        findings: List[DetectorFinding] = []
        limitations: List[str] = []
        analyzed_files: List[str] = []
        complete = True
        for unit in ordered:
            unit_findings, unit_limitations, unit_complete = _detect_unit(unit)
            findings.extend(unit_findings)
            limitations.extend(unit_limitations)
            if unit_complete:
                analyzed_files.append(unit.path)
            else:
                complete = False
        limitations.extend((
            "Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.",
            "Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.",
            "Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.",
        ))
        status = "completed" if complete else "blocked"
        return DetectorRun(
            self.detector_id,
            self.version,
            status,
            analyzed_files=tuple(sorted(analyzed_files)),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
