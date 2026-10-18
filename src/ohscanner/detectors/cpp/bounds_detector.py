"""A-BOF-01 bounded C/C++ array and copy-length candidate detector.

This detector intentionally reports only a small set of local memory-bound
violations whose destination or index capacity is syntactically available.
Unknown aliases, macros, interprocedural lengths and partial parses remain
unknown and never become safe verdicts.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
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
    parameter_names,
    pointer_declarations,
    split_call_arguments,
)


RULE_COPY = "ohcpp-memory-bounds-copy-candidate-001"
RULE_INDEX = "ohcpp-memory-bounds-index-candidate-002"
RULE_ELEMENT_ACCESS = "ohcpp-memory-bounds-element-access-candidate-003"
RULE_VERSION = "0.2.3"
RULE_LINEAGE_ID = "A-BOF-01:ohcpp-memory-bounds-candidate"


@dataclass(frozen=True)
class CopyWrapper:
    function: str
    dest_index: int
    length_index: Optional[int]
    fixed_length: Optional[str]
    call_name: str

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


def _normalized_expression(expression: str) -> str:
    return re.sub(r"\s+", "", expression)


def _nonnegative_symbols(masked: str) -> Set[str]:
    symbols: Set[str] = set()
    for match in re.finditer(
        r"\b(?:unsigned(?:\s+int)?|size_t|u?int(?:8|16|32|64)_t|uintptr_t)\s+"
        r"(?P<name>[A-Za-z_]\w*)",
        masked,
    ):
        symbols.add(match.group("name"))
    return symbols


def _destination_capacity(
    destination: str,
    arrays: Dict[str, object],
    pointers: Dict[str, object],
) -> Tuple[Optional[int], Optional[str], bool]:
    shape = arrays.get(destination)
    if (
        shape is not None
        and getattr(shape, "capacity", None) is not None
        and getattr(shape, "element_size", None) is not None
    ):
        return shape.capacity * shape.element_size, None, True
    pointer = pointers.get(destination)
    if pointer is not None:
        return pointer.capacity_bytes, pointer.capacity_expression, False
    return None, None, False


def _copy_wrappers(
    masked: str,
    functions: Sequence[object],
) -> Tuple[CopyWrapper, ...]:
    wrappers: List[CopyWrapper] = []
    for function in functions:
        params = {name: index for index, name in enumerate(parameter_names(function.params))}
        if not params:
            continue
        candidates: List[CopyWrapper] = []
        region = masked[function.body_start:function.body_end]
        for match in re.finditer(
            r"\b(?P<name>memcpy|memmove|strncpy|strcpy|strcat|sprintf)\s*\(", region
        ):
            position = function.body_start + match.start()
            span = call_argument_span(masked, position)
            if span is None:
                continue
            args = split_call_arguments(span[2])
            if not args or args[0].strip() not in params:
                continue
            name = match.group("name")
            length_index: Optional[int] = None
            fixed_length: Optional[str] = None
            if name in {"memcpy", "memmove", "strncpy"}:
                if len(args) < 3:
                    continue
                length_expression = args[2].strip()
                if length_expression in params:
                    length_index = params[length_expression]
                elif re.fullmatch(r"\d+(?:[uUlL]*)", length_expression):
                    fixed_length = length_expression
                else:
                    continue
            candidates.append(CopyWrapper(
                function.name, params[args[0].strip()], length_index, fixed_length, name
            ))
        if len(candidates) == 1:
            wrappers.append(candidates[0])
    return tuple(wrappers)


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
    pointers = pointer_declarations(masked, constants)
    wrappers = _copy_wrappers(masked, functions)
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
        enclosing = function_at(functions, match.start())
        parameter_set = set(parameter_names(enclosing.params)) if enclosing is not None else set()
        destination_shape = arrays.get(destination) if destination not in parameter_set else None
        pointer_shape = pointers.get(destination) if destination not in parameter_set else None
        capacity_bytes: Optional[int] = None
        capacity_expression: Optional[str] = None
        if (
            destination_shape is not None
            and destination_shape.capacity is not None
            and destination_shape.element_size is not None
        ):
            capacity_bytes = destination_shape.capacity * destination_shape.element_size
        elif pointer_shape is not None:
            capacity_bytes = pointer_shape.capacity_bytes
            capacity_expression = pointer_shape.capacity_expression
            if capacity_bytes is None and not capacity_expression:
                continue
        else:
            continue
        call_name = match.group("name")
        if call_name in {"strcpy", "strcat", "sprintf"}:
            findings.append(_finding(
                unit, unit.text, match.start(), RULE_COPY, destination,
                f"Candidate only: `{call_name}` writes to "
                f"{'fixed array' if destination_shape is not None else 'allocation'} `{destination}` "
                f"({capacity_bytes if capacity_bytes is not None else capacity_expression} bytes) "
                "without a modeled destination upper bound; "
                "alias, format and source length semantics remain unknown.",
                "CWE-120", "CWE-787",
            ))
            continue
        if call_name == "snprintf":
            if len(args) < 2:
                continue
            length_expression = args[1]
        else:
            if call_name in {"memcpy", "memmove", "strncpy"} and len(args) < 3:
                continue
            length_expression = args[2]
        if destination_shape is not None and _safe_copy_length(length_expression, destination, arrays):
            continue
        if capacity_bytes is None:
            if _normalized_expression(length_expression) == _normalized_expression(capacity_expression or ""):
                continue
            if _contains_symbol(length_expression) and _contains_symbol(capacity_expression or ""):
                findings.append(_finding(
                    unit, unit.text, match.start(), RULE_COPY, destination,
                    f"Candidate only: `{call_name}` length `{length_expression.strip()}` is not proven "
                    f"<= allocation capacity `{capacity_expression}` for `{destination}`. Allocation "
                    "source, aliases, guard dominance and reachability remain unknown.",
                    "CWE-119", "CWE-787" if call_name != "strncpy" else "CWE-120",
                ))
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

    for wrapper in wrappers:
        for match in re.finditer(r"\b" + re.escape(wrapper.function) + r"\s*\(", masked):
            caller = function_at(functions, match.start())
            if caller is not None and caller.name == wrapper.function:
                continue
            span = call_argument_span(masked, match.start())
            if span is None:
                continue
            args = split_call_arguments(span[2])
            if len(args) <= wrapper.dest_index:
                continue
            destination = args[wrapper.dest_index].strip()
            capacity_bytes, capacity_expression, is_array = _destination_capacity(
                destination, arrays, pointers
            )
            if capacity_bytes is None and not capacity_expression:
                continue
            if wrapper.length_index is not None:
                if len(args) <= wrapper.length_index:
                    continue
                length_expression = args[wrapper.length_index].strip()
            elif wrapper.fixed_length is not None:
                length_expression = wrapper.fixed_length
            else:
                length_expression = None
            capacity_kind = "fixed array" if is_array else "allocation"
            if length_expression is None:
                findings.append(_finding(
                    unit, unit.text, match.start(), RULE_COPY, destination,
                    f"Candidate only: wrapper `{wrapper.function}` calls `{wrapper.call_name}` "
                    f"into {capacity_kind} `{destination}` "
                    f"({capacity_bytes if capacity_bytes is not None else capacity_expression} bytes) "
                    "without a modeled destination upper bound; interprocedural alias and guard "
                    "context remain unknown.",
                    "CWE-120", "CWE-787",
                ))
                continue
            if is_array and _safe_copy_length(length_expression, destination, arrays):
                continue
            if capacity_bytes is None:
                if _normalized_expression(length_expression) == _normalized_expression(
                    capacity_expression or ""
                ):
                    continue
                if _contains_symbol(length_expression) and _contains_symbol(capacity_expression or ""):
                    findings.append(_finding(
                        unit, unit.text, match.start(), RULE_COPY, destination,
                        f"Candidate only: wrapper `{wrapper.function}` length `{length_expression}` "
                        f"is not proven <= allocation capacity `{capacity_expression}` for "
                        f"`{destination}`; interprocedural alias and guard context remain unknown.",
                        "CWE-119", "CWE-787",
                    ))
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
                    f"Candidate only: wrapper `{wrapper.function}` length `{length_expression}` has "
                    f"an {qualifier} against {capacity_kind} `{destination}` "
                    f"({capacity_bytes} bytes); one-hop summary excludes deeper aliases and guards.",
                    "CWE-119", "CWE-787",
                ))

    for match in re.finditer(r"\b(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<index>[^]\[]+)\s*\]", masked):
        before = masked[:match.start()]
        if re.search(r"(?:char|short|int|long|u?int(?:8|16|32|64)_t)\s+$", before):
            continue
        name = match.group("name")
        enclosing = function_at(functions, match.start())
        if enclosing is not None and name in parameter_names(enclosing.params):
            continue
        shape = arrays.get(name)
        capacity: Optional[int] = shape.capacity if shape is not None else None
        if capacity is None:
            pointer_shape = pointers.get(name)
            if (
                pointer_shape is not None
                and pointer_shape.capacity_bytes is not None
                and pointer_shape.element_size is not None
            ):
                capacity = pointer_shape.capacity_bytes // pointer_shape.element_size
        if capacity is None:
            continue
        index_expression = match.group("index").strip()
        constraints = guard_constraints(guards, match.start(), constants, sizeof_values)
        interval = expression_interval(index_expression, constants, constraints)
        safe_upper = interval.maximum is not None and interval.maximum < capacity
        safe_lower = interval.is_nonnegative() or index_expression in nonnegative
        definite = interval.definitely_at_least(capacity) or (
            interval.maximum is not None and interval.maximum < 0
        )
        unbounded_index = _contains_symbol(index_expression) and not (safe_upper and safe_lower)
        if definite or unbounded_index:
            qualifier = "demonstrated out-of-range index" if definite else "unproven in-range index"
            findings.append(_finding(
                unit, unit.text, match.start(), RULE_INDEX, name,
                f"Candidate only: index `{index_expression}` has an {qualifier} for fixed array "
                f"`{name}` with capacity {capacity}. Complete CFG, signedness and "
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
            "Only direct one-hop copy wrappers are summarized; deeper wrappers, function pointers, aliases, macros, templates and full C++ CFG semantics remain unknown.",
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
