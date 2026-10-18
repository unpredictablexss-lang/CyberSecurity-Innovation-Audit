"""A-INT-01 bounded integer/size calculation candidate detector."""

from __future__ import annotations

import re
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
    call_argument_span,
    declarations,
    expression_interval,
    function_at,
    function_shapes,
    guard_constraints,
    guard_shapes,
    line_column,
    mask_comments_and_literals,
    split_call_arguments,
    type_shape,
)


RULE_ARITHMETIC = "ohcpp-integer-bounds-arithmetic-candidate-001"
RULE_TRUNCATION = "ohcpp-integer-bounds-truncation-candidate-002"
RULE_NARROW_INDEX = "ohcpp-integer-bounds-narrow-index-candidate-003"
RULE_VERSION = "0.2.3"
RULE_LINEAGE_ID = "A-INT-01:ohcpp-integer-bounds-candidate"

_OBLIGATIONS = (
    EvidenceObligation(
        "integer_range_and_signedness",
        "Prove complete type width, signedness, promotions and arithmetic range.",
        "unknown",
    ),
    EvidenceObligation(
        "overflow_guard_dominance",
        "Prove a complete checked-arithmetic guard dominates every allocation/copy path.",
        "unknown",
    ),
    EvidenceObligation(
        "allocation_or_memory_consequence",
        "Connect overflow/truncation to undersized allocation or out-of-bounds access.",
        "unknown",
    ),
    EvidenceObligation(
        "cross_function_and_macro_context",
        "Resolve wrappers, constants, macros, templates and compile-time configuration.",
        "missing",
    ),
    EvidenceObligation(
        "entry_or_privilege_boundary",
        "Establish a realistic reachable entry and privilege boundary.",
        "missing",
    ),
    EvidenceObligation(
        "attacker_control",
        "Show attacker influence over count, size, offset or length.",
        "missing",
    ),
    EvidenceObligation(
        "cia_impact",
        "Establish concrete confidentiality, integrity or availability impact.",
        "missing",
    ),
)


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
        consequence_impact="allocation_or_memory_safety",
        consequence_cwe=consequence_cwe,
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
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


def _safe_constant(expression: str, constants: Dict[str, int]) -> Tuple[bool, int]:
    value = expression.strip()
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        return True, int(value, 16)
    if re.fullmatch(r"\d+(?:[uUlL]*)", value):
        return True, int(re.sub(r"[uUlL]+$", "", value), 10)
    if value in constants:
        return True, constants[value]
    return False, 0


def _constant_arithmetic(expression: str, constants: Dict[str, int]) -> Tuple[Optional[int], str, int, int]:
    match = re.fullmatch(
        r"\s*(?P<left>[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+(?:[uUlL]*)?)\s*"
        r"(?P<op>\*|\+|-)\s*(?P<right>[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+(?:[uUlL]*)?)\s*",
        expression,
    )
    if not match:
        return None, "", 0, 0
    left_ok, left = _safe_constant(match.group("left"), constants)
    right_ok, right = _safe_constant(match.group("right"), constants)
    op = match.group("op")
    if not left_ok or not right_ok:
        return None, op, 0, 0
    value = left * right if op == "*" else left + right if op == "+" else left - right
    return value, op, left, right


def _range(bits: Optional[int], signed: bool) -> Tuple[Optional[int], Optional[int]]:
    if bits is None:
        return None, None
    if signed:
        return -(2 ** (bits - 1)), 2 ** (bits - 1) - 1
    return 0, 2 ** bits - 1


def _has_checked_guard(function_text: str, names: Sequence[str], operation: str) -> bool:
    text = function_text
    escaped = [re.escape(name) for name in names if name]
    if not escaped:
        return False
    alternatives = "|".join(escaped)
    if operation == "*":
        return bool(re.search(r"(?:__builtin_mul_overflow|__builtin_umull_overflow|__builtin_smull_overflow|SIZE_MAX\s*/)", text)
                    or re.search(r"if\s*\([^)]*(?:" + alternatives + r")[^)]*(?:SIZE_MAX|overflow)", text))
    if operation == "+":
        return bool(re.search(r"(?:__builtin_add_overflow|__builtin_uadd_overflow|SIZE_MAX\s*-)", text)
                    or re.search(r"if\s*\([^)]*(?:" + alternatives + r")[^)]*(?:SIZE_MAX|overflow)", text))
    return bool(re.search(r"(?:__builtin_sub_overflow|__builtin_usub_overflow)", text)
                or re.search(r"if\s*\([^)]*(?:" + alternatives + r")[^)]*(?:<|>=|SIZE_MAX|overflow)", text))


def _sensitive_names(masked: str) -> Set[str]:
    names: Set[str] = set()
    for match in re.finditer(r"\b(?:malloc|calloc|memcpy|memmove|strncpy|snprintf|strcpy|strcat)\s*\(", masked):
        span = call_argument_span(masked, match.start())
        if span is None:
            continue
        for arg in split_call_arguments(span[2]):
            names.update(re.findall(r"[A-Za-z_]\w*", arg))
    return names


def _guarded_strnlen_symbols(function_text: str) -> Set[str]:
    symbols: Set[str] = set()
    for match in re.finditer(
        r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*strnlen\s*\([^,]+,\s*(?P<cap>[A-Za-z_]\w*)\s*\)",
        function_text,
    ):
        name = re.escape(match.group("name"))
        cap = re.escape(match.group("cap"))
        tail = function_text[match.end():]
        guarded = re.search(
            r"\b" + name + r"\s*>=\s*" + cap + r"\b",
            tail,
        ) and re.search(r"\breturn\b", tail)
        if guarded:
            symbols.add(match.group("name"))
    return symbols


def _promotion_safe_addition(
    expression: str,
    integers: Dict[str, Any],
    constants: Dict[str, int],
) -> bool:
    match = re.fullmatch(
        r"\s*(?P<name>[A-Za-z_]\w*)\s*\+\s*(?P<value>\d+(?:[uUlL]*)?)\s*",
        expression,
    )
    if not match:
        return False
    shape = integers.get(match.group("name"))
    if shape is None or shape.bits is None or shape.bits > 16:
        return False
    _ok, value = _safe_constant(match.group("value"), constants)
    return value >= 0 and value <= 2 ** 30


def _macro_only_expression(expression: str) -> bool:
    tokens = re.findall(r"[A-Za-z_]\w*", expression)
    return bool(tokens) and all(
        token.isupper() or token in {"SIZE_MAX", "PATH_MAX"} for token in tokens
    )


def _bounded_addition(
    guards,
    functions,
    position: int,
    expression: str,
    integers: Dict[str, Any],
    constants: Dict[str, int],
    sizeof_values: Dict[str, int],
) -> bool:
    """True when a ``name + constant`` addition is bounded by an upper guard."""

    match = re.fullmatch(
        r"\s*(?P<name>[A-Za-z_]\w*)\s*\+\s*(?P<value>\d+(?:[uUlL]*)?)\s*",
        expression,
    )
    if not match:
        return False
    name = match.group("name")
    shape = integers.get(name)
    bits = shape.bits if shape is not None else None
    signed = shape.signed if shape is not None else None
    if bits is None:
        function = function_at(functions, position)
        if function is not None:
            for item in split_call_arguments(function.params):
                declaration = item.split("=", 1)[0].strip()
                identifiers = re.findall(r"[A-Za-z_]\w*", declaration)
                if identifiers and identifiers[-1] == name:
                    bits, signed = type_shape(" ".join(identifiers[:-1]))
                    break
    if bits is None:
        return False
    constraints = guard_constraints(guards, position, constants, sizeof_values)
    interval = expression_interval(expression, constants, constraints)
    _low, high = _range(bits, signed)
    return interval.maximum is not None and high is not None and interval.maximum <= high


def _detect_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool]:
    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    if unit.parse_status != "complete":
        return findings, [f"{unit.path}: parse_status={unit.parse_status}; integer coverage remains unknown."], False
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return findings, [f"{unit.path}: source exceeds the 1MiB per-unit fail-closed budget."], False
    masked = mask_comments_and_literals(unit.text)
    functions = function_shapes(masked)
    arrays, integers, constants = declarations(masked)
    sizeof_values = {
        name: shape.capacity * shape.element_size
        for name, shape in arrays.items()
        if shape.capacity is not None and shape.element_size is not None
    }
    guards = guard_shapes(masked, functions)
    sensitive = _sensitive_names(masked)

    assignment_re = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);")
    for match in assignment_re.finditer(masked):
        name = match.group("name")
        expression = match.group("expr").strip()
        shape = integers.get(name)
        if shape is None:
            continue
        value, operation, left, right = _constant_arithmetic(expression, constants)
        function = function_at(functions, match.start())
        function_text = function.text if function is not None else ""
        names = tuple(re.findall(r"[A-Za-z_]\w*", expression))
        checked = _has_checked_guard(function_text, names, operation) if operation else False
        if operation == "+" and _guarded_strnlen_symbols(function_text) & set(names):
            checked = True
        if operation == "+" and _promotion_safe_addition(expression, integers, constants):
            checked = True
        if operation == "+" and _bounded_addition(
            guards, functions, match.start(), expression, integers, constants,
            sizeof_values,
        ):
            checked = True
        if value is not None and shape.bits is not None:
            low, high = _range(shape.bits, shape.signed)
            if low is not None and high is not None and (value < low or value > high):
                findings.append(_finding(
                    unit, unit.text, match.start(), RULE_TRUNCATION, name,
                    f"Candidate only: constant `{expression}` evaluates to {value} but destination "
                    f"`{name}` has type `{shape.type_text}` range [{low}, {high}]; promotion, "
                    "macro and build semantics remain unknown.",
                    "CWE-190", "CWE-681",
                ))
                continue
        if operation and name in sensitive and not checked:
            if operation == "*":
                message = (
                    f"Candidate only: multiplication `{expression}` feeds a size/allocation-sensitive value "
                    f"without a modeled checked multiplication; overflow may undersize a buffer."
                )
                cwe, consequence = "CWE-190", "CWE-787"
            elif operation == "+":
                message = (
                    f"Candidate only: addition `{expression}` feeds a size/index-sensitive value without "
                    "a modeled checked addition; overflow/truncation remains possible."
                )
                cwe, consequence = "CWE-190", "CWE-787"
            else:
                message = (
                    f"Candidate only: subtraction `{expression}` feeds a size-sensitive value without a "
                    "modeled lower-bound guard; underflow remains possible."
                )
                cwe, consequence = "CWE-191", "CWE-787"
            findings.append(_finding(
                unit, unit.text, match.start(), RULE_ARITHMETIC, name, message, cwe, consequence,
            ))

    for match in re.finditer(
        r"\bint32_t\s+(?P<name>[A-Za-z_]\w*)\s*=\s*[^;]*?DoubleInRangeInt32\s*\(",
        masked,
    ):
        name = match.group("name")
        function = function_at(functions, match.start())
        if function is None:
            continue
        body = function.text
        guarded_compare = re.search(r"\bif\s*\([^)]*\b" + re.escape(name) + r"\s*>=\s*[A-Za-z_]\w*[^)]*\)", body)
        arithmetic_use = re.search(r"\b" + re.escape(name) + r"\b(?:\s*\)|\s*\*)?\s*\*|static_cast<[^>]+>\(\s*" + re.escape(name) + r"\s*\)\s*\*", body)
        if guarded_compare and arithmetic_use:
            findings.append(_finding(
                unit,
                unit.text,
                match.start(),
                RULE_NARROW_INDEX,
                name,
                f"Candidate only: `{name}` narrows a ToIndex/double result to `int32_t` before a bounds check "
                "and offset multiplication; wrap/truncation may bypass the check. Exact runtime range and "
                "product reachability remain unknown.",
                "CWE-190",
                "CWE-787",
            ))

    for match in re.finditer(r"\b(?:malloc|calloc)\s*\(", masked):
        span = call_argument_span(masked, match.start())
        if span is None:
            continue
        for arg in split_call_arguments(span[2]):
            value, operation, left, right = _constant_arithmetic(arg, constants)
            if not operation or _macro_only_expression(arg):
                continue
            function = function_at(functions, match.start())
            function_text = function.text if function is not None else ""
            names = tuple(re.findall(r"[A-Za-z_]\w*", arg))
            checked = _has_checked_guard(function_text, names, operation)
            if operation == "+" and _guarded_strnlen_symbols(function_text) & set(names):
                checked = True
            if operation == "+" and _promotion_safe_addition(arg, integers, constants):
                checked = True
            if operation == "+" and _bounded_addition(
                guards, functions, match.start(), arg.strip(), integers, constants,
                sizeof_values,
            ):
                checked = True
            if not checked:
                findings.append(_finding(
                    unit, unit.text, match.start(), RULE_ARITHMETIC, arg.strip(),
                    f"Candidate only: allocation size expression `{arg.strip()}` uses `{operation}` without "
                    "a modeled checked-arithmetic guard; overflow may yield an undersized allocation. "
                    "Allocator semantics and reachability remain unknown.",
                    "CWE-190", "CWE-787",
                ))
    for match in re.finditer(
        r"\bnew\s+(?:\([^)]*\)\s*)?[A-Za-z_][A-Za-z0-9_:<>*\s]*\[\s*(?P<size>[^]]+)\s*\]",
        masked,
    ):
        expression = match.group("size").strip()
        value, operation, left, right = _constant_arithmetic(expression, constants)
        if not operation or _macro_only_expression(expression):
            continue
        function = function_at(functions, match.start())
        function_text = function.text if function is not None else ""
        names = tuple(re.findall(r"[A-Za-z_]\w*", expression))
        checked = _has_checked_guard(function_text, names, operation)
        if operation == "+" and _guarded_strnlen_symbols(function_text) & set(names):
            checked = True
        if operation == "+" and _promotion_safe_addition(expression, integers, constants):
            checked = True
        if operation == "+" and _bounded_addition(
            guards, functions, match.start(), expression, integers, constants,
            sizeof_values,
        ):
            checked = True
        if not checked:
            findings.append(_finding(
                unit, unit.text, match.start(), RULE_ARITHMETIC, expression,
                f"Candidate only: array allocation size `{expression}` uses `{operation}` without "
                "a modeled checked-arithmetic guard; overflow may yield an undersized allocation.",
                "CWE-190", "CWE-787",
            ))

    return findings, limitations, True


class CppIntegerBoundsDetector:
    detector_id = "ohscanner.cpp.integer_bounds"
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
            "Candidate only: lexical integer arithmetic does not prove allocation undersizing or product impact.",
            "Signedness, promotions, macro constants, overflow intrinsics, templates and interprocedural range facts remain unknown unless explicitly modeled.",
            "A guarded or unknown expression is not a safe verdict; partial/failed source remains unknown.",
        ))
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if complete else "blocked",
            analyzed_files=tuple(sorted(analyzed_files)),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )

