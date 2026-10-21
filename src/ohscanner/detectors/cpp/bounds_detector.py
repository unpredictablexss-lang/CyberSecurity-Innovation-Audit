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
    balanced_end,
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
RULE_POINTER_OFFSET = "ohcpp-memory-bounds-pointer-offset-candidate-004"
RULE_VECTOR_INDEX = "ohcpp-memory-bounds-vector-index-candidate-005"
RULE_VERSION = "0.3.0"
RULE_POINTER_OFFSET_VERSION = "0.1.0"
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
    rule_version: str = RULE_VERSION,
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
        rule_version=rule_version,
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


def _pointer_offset_underflow_is_guarded(
    function_text: str,
    expression_start: int,
    left: str,
    right: str,
) -> bool:
    """Recognize only direct, local guards for unsigned dimension subtraction."""
    left = re.escape(left)
    right = re.escape(right)
    # A positive comparison enclosing the offset proves the subtraction order
    # on that branch (for example, if (h > image.height) { p += (h-height)*w; }).
    for guard in re.finditer(
        r"\bif\s*\(\s*" + left + r"\s*(?:>=|>)\s*" + right + r"\s*\)\s*\{",
        function_text,
    ):
        open_brace = function_text.find("{", guard.start(), guard.end())
        close_brace = balanced_end(function_text, open_brace)
        if close_brace is not None and open_brace < expression_start < close_brace:
            return True
    # A reject-on-underflow guard must exit before the pointer expression.
    prefix = function_text[:expression_start]
    if re.search(
        r"\bif\s*\(\s*" + left + r"\s*<\s*" + right +
        r"\s*\)\s*(?:\{\s*return\b[^}]*\}|return\b[^;]*;)",
        prefix,
    ):
        return True
    return False


def _unsigned_scalar_names(function_text: str, integers: Dict[str, object]) -> Set[str]:
    names = {
        name for name, shape in integers.items()
        if not getattr(shape, "signed", True)
    }
    # The shared lexical declaration helper intentionally models locals and
    # fields only; collect simple unsigned function parameters here.
    for match in re.finditer(
        r"\b(?:unsigned\s+(?:char|short|int|long)|size_t|u?int(?:8|16|32|64)_t|uintptr_t)"
        r"\s*\*?\s*(?P<name>[A-Za-z_]\w*)\b",
        function_text,
    ):
        names.add(match.group("name"))
    return names


def _pointer_names(function_text: str) -> Set[str]:
    return {
        match.group("name") for match in re.finditer(
            r"\b[A-Za-z_]\w*\s*\*\s*(?P<name>[A-Za-z_]\w*)\b",
            function_text,
        )
    }


def _vector_capacities(masked: str, functions) -> Dict[str, Optional[str]]:
    """Return syntactically declared std::vector objects and exact size arguments."""
    result: Dict[str, Optional[str]] = {}
    for match in re.finditer(r"\bstd\s*::\s*vector\s*<", masked):
        angle_start = masked.find("<", match.start())
        depth = 0
        angle_end = None
        for offset in range(angle_start, len(masked)):
            if masked[offset] == "<":
                depth += 1
            elif masked[offset] == ">":
                depth -= 1
                if depth == 0:
                    angle_end = offset + 1
                    break
        if angle_end is None:
            continue
        declarator = re.match(
            r"\s*(?:(?:const|volatile)\s+)?(?:[&*]\s*)?(?P<name>[A-Za-z_]\w*)\s*\(",
            masked[angle_end:],
        )
        if declarator is None:
            continue
        opening = angle_end + declarator.end() - 1
        closing = balanced_end(masked, opening, "(", ")")
        if closing is None:
            continue
        arguments = split_call_arguments(masked[opening + 1:closing - 1])
        capacity = arguments[0].strip() if arguments else ""
        if capacity:
            result[declarator.group("name")] = re.sub(r"\s+", "", capacity)
    for function in functions:
        for match in re.finditer(r"\bstd\s*::\s*vector\s*<", function.text):
            angle_start = function.start + match.start()
            angle_start = masked.find("<", angle_start)
            depth = 0
            angle_end = None
            for offset in range(angle_start, function.end):
                if masked[offset] == "<":
                    depth += 1
                elif masked[offset] == ">":
                    depth -= 1
                    if depth == 0:
                        angle_end = offset + 1
                        break
            if angle_end is None:
                continue
            parameter = re.match(
                r"\s*(?:const\s+)?[&*]\s*(?P<name>[A-Za-z_]\w*)",
                masked[angle_end:function.end],
            )
            if parameter:
                result[parameter.group("name")] = None
    return result


def _index_is_nonnegative(function_text: str, function_start: int, position: int, index: str) -> bool:
    """Prove only the nearest visible unsigned binding or a zero-init binding."""
    local_position = position - function_start
    escaped = re.escape(index)
    declaration = re.compile(
        r"\b(?P<type>(?:unsigned\s+(?:char|short|int|long)|std\s*::\s*size_t|size_t|"
        r"u?int(?:8|16|32|64)_t|uintptr_t|int|long|ssize_t|ptrdiff_t))\s+"
        + escaped + r"\b(?:\s*=\s*(?P<initial>[^;,()]+))?"
    )
    declarations_before_use = [item for item in declaration.finditer(function_text) if item.start() < local_position]
    if not declarations_before_use:
        return False
    binding = declarations_before_use[-1]
    type_text = re.sub(r"\s+", "", binding.group("type"))
    if type_text.startswith("unsigned") or type_text in {
        "size_t", "std::size_t", "uintptr_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    }:
        return True
    if binding.group("initial") is None or re.sub(r"\s+", "", binding.group("initial")) != "0":
        return False
    tail = function_text[binding.end():local_position]
    # Accept only explicit zero resets and positive increments; any other
    # assignment, decrement, or subtraction makes the sign unknown.
    tail = re.sub(r"\+\+\s*" + escaped + r"\b", "", tail)
    tail = re.sub(r"\b" + escaped + r"\s*\+\+", "", tail)
    tail = re.sub(r"\b" + escaped + r"\s*\+=\s*[1-9]\d*\b", "", tail)
    tail = re.sub(r"\b" + escaped + r"\s*=\s*0\b", "", tail)
    if re.search(
        r"(?:--\s*" + escaped + r"\b|\b" + escaped
        + r"\s*--|\b" + escaped + r"\s*(?:-=|=(?!=)|\+=))",
        tail,
    ):
        return False
    return True


def _body_span(masked: str, after_header: int) -> Optional[Tuple[int, int]]:
    start_match = re.search(r"\S", masked[after_header:])
    if start_match is None:
        return None
    start = after_header + start_match.start()
    if masked[start] == "{":
        end = balanced_end(masked, start)
        return None if end is None else (start, end)
    semicolon = masked.find(";", start)
    return None if semicolon < 0 else (start, semicolon + 1)


def _vector_access_is_guarded(
    masked: str,
    functions,
    access_position: int,
    vector_name: str,
    index: str,
    capacity: Optional[str],
) -> bool:
    function = function_at(functions, access_position)
    if function is None:
        return False
    index_escaped = re.escape(index)
    capacity_normalized = re.sub(r"\s+", "", capacity or "")
    is_nonnegative = _index_is_nonnegative(function.text, function.start, access_position, index)

    # A same-branch nonnegative check plus the exact vector's size() is local
    # and does not depend on aliases or constructor arithmetic.
    for guard in re.finditer(r"\bif\s*\(", masked[function.start:function.end]):
        opening = function.start + guard.end() - 1
        closing = balanced_end(masked, opening, "(", ")")
        if closing is None:
            continue
        condition = masked[opening + 1:closing - 1]
        if "||" in condition:
            continue
        lower = is_nonnegative or bool(re.search(r"\b" + index_escaped + r"\s*>=\s*0\b", condition))
        upper = re.search(
            r"(?:\b" + index_escaped + r"\b|\bstatic_cast\s*<\s*(?:std\s*::\s*)?size_t\s*>\s*\(\s*"
            + index_escaped + r"\s*\))\s*<\s*" + re.escape(vector_name)
            + r"\s*\.\s*size\s*\(\s*\)", condition,
        )
        body = _body_span(masked, closing)
        if lower and upper and body and body[0] <= access_position < body[1]:
            prefix = masked[body[0]:access_position]
            vector_mutation = re.search(
                r"\b" + re.escape(vector_name)
                + r"\s*\.\s*(?:clear|resize|reserve|push_back|emplace_back|insert|erase|assign|swap)\s*\(",
                prefix,
            )
            if not vector_mutation and not re.search(
                r"(?:--\s*" + index_escaped + r"\b|\b" + index_escaped
                + r"\s*(?:--|-=|=(?!=)|\+=))",
                prefix,
            ):
                return True

    for loop in re.finditer(r"\b(?:while|for)\s*\(", masked[function.start:function.end]):
        opening = function.start + loop.end() - 1
        closing = balanced_end(masked, opening, "(", ")")
        if closing is None:
            continue
        condition = masked[opening + 1:closing - 1]
        parts = condition.split(";")
        for_loop = loop.group(0).lstrip().startswith("for") and len(parts) == 3
        loop_index_nonnegative = is_nonnegative
        step_ok = True
        if for_loop:
            init, predicate, step = (part.strip() for part in parts)
            if re.search(r"\b" + index_escaped + r"\s*=\s*0\b", init):
                loop_index_nonnegative = True
            step_ok = bool(re.fullmatch(
                r"(?:\+\+\s*" + index_escaped + r"|" + index_escaped
                + r"\s*\+\+|" + index_escaped + r"\s*\+=\s*[1-9]\d*)",
                step,
            ))
            condition = predicate
        body = _body_span(masked, closing)
        if not body or not (body[0] <= access_position < body[1]):
            continue
        # Exact vector.size() guard is valid for a nonnegative index. A named
        # bound is accepted only when it is exactly the vector constructor size.
        bound = re.search(
            r"\b" + index_escaped + r"\s*<\s*(?P<bound>"
            + re.escape(vector_name) + r"\s*\.\s*size\s*\(\s*\)|[A-Za-z_]\w*)(?!\w)",
            condition,
        )
        if bound is None or not loop_index_nonnegative or not step_ok:
            continue
        bound_text = re.sub(r"\s+", "", bound.group("bound"))
        if bound_text == vector_name + ".size()":
            pass
        elif capacity_normalized and _capacity_bound_matches(
            masked[function.start:function.end], bound_text, capacity_normalized
        ):
            pass
        else:
            continue
        body_text = masked[body[0]:body[1]]
        body_prefix = masked[body[0]:access_position]
        if re.search(
            r"\b" + re.escape(vector_name)
            + r"\s*\.\s*(?:clear|resize|reserve|push_back|emplace_back|insert|erase|assign|swap)\s*\(",
            body_prefix,
        ):
            continue
        if re.search(
            r"(?:--\s*" + index_escaped + r"\b|\b" + index_escaped
            + r"\s*(?:--|-=|=(?!=)|\+=))",
            body_prefix,
        ):
            continue
        if re.search(
            r"(?:--\s*" + index_escaped + r"\b|\b" + index_escaped
            + r"\s*--|\b" + index_escaped + r"\s*(?:-=|=(?!=)|\+=\s*-)\b)",
            body_text,
        ):
            continue
        return True
    return False


def _capacity_bound_matches(function_text: str, bound: str, capacity: str) -> bool:
    """Match a loop bound to the exact vector constructor expression or simple alias."""
    normalize = lambda value: re.sub(r"\s+", "", re.sub(
        r"static_cast\s*<[^>]+>\s*\(\s*([A-Za-z_]\w*)\s*\)",
        r"\1", value,
    ))
    expected = normalize(capacity)
    if normalize(bound) == expected:
        return True
    for match in re.finditer(
        r"\b(?:int|long|size_t|ssize_t|uint\w*_t)\s+" + re.escape(bound)
        + r"\s*=\s*(?P<value>[^;]+);",
        function_text,
    ):
        if normalize(match.group("value")) == expected:
            return True
    return False


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
    arrays, integers, constants = declarations(masked)
    guards = guard_shapes(masked, functions)
    nonnegative = _nonnegative_symbols(masked)
    sizeof_values = {
        name: shape.capacity * shape.element_size
        for name, shape in arrays.items()
        if shape.capacity is not None and shape.element_size is not None
    }
    vector_capacities = _vector_capacities(masked, functions)

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
        name = match.group("name")
        index_expression = match.group("index").strip()
        if name in vector_capacities and re.fullmatch(r"[A-Za-z_]\w*", index_expression):
            if not _vector_access_is_guarded(
                masked, functions, match.start(), name, index_expression,
                vector_capacities[name],
            ):
                findings.append(_finding(
                    unit, unit.text, match.start(), RULE_VECTOR_INDEX, name,
                    f"Candidate only: dynamic container `{name}` is indexed by `{index_expression}` "
                    "without a same-loop, same-container bound that proves the index in range. "
                    "Aliases, complete CFG, container mutation and reachability remain unknown.",
                    "CWE-125", "CWE-787", "0.1.0",
                ))
            continue
        shape = arrays.get(match.group("name"))
        if shape is None or shape.capacity is None:
            continue
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

    # Unsigned dimension underflow can create a huge pointer displacement even
    # when no array-index syntax or allocation expression is present.
    pointer_offset_re = re.compile(
        r"\b(?P<base>[A-Za-z_]\w*)\s*\+\s*\(\s*"
        r"(?P<left>[A-Za-z_]\w*)\s*-\s*"
        r"(?P<right>[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?)\s*\)\s*"
        r"\*\s*(?P<scale>[A-Za-z_]\w*)"
    )
    for match in pointer_offset_re.finditer(masked):
        function = function_at(functions, match.start())
        if function is None:
            continue
        function_text = function.text
        local_start = match.start() - function.start
        base = match.group("base")
        left = match.group("left")
        right_expression = re.sub(r"\s+", "", match.group("right"))
        right = right_expression.rsplit(".", 1)[-1]
        unsigned_names = _unsigned_scalar_names(function_text, integers)
        pointer_names = _pointer_names(function_text)
        if base not in pointer_names or left not in unsigned_names or right not in unsigned_names:
            continue
        if _pointer_offset_underflow_is_guarded(function_text, local_start, left, right_expression):
            continue
        findings.append(_finding(
            unit, unit.text, match.start(), RULE_POINTER_OFFSET, base,
            f"Candidate only: pointer `{base}` is offset by unsigned dimension difference "
            f"`{match.group('left')} - {match.group('right').strip()}` times "
            f"`{match.group('scale')}` without a modeled ordering guard; underflow may move "
            "the pointer outside its raster or buffer. Object extent and reachability remain unknown.",
            "CWE-191", "CWE-787", RULE_POINTER_OFFSET_VERSION,
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
