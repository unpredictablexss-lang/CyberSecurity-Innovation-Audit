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
    guard_shapes,
    line_column,
    mask_comments_and_literals,
    split_call_arguments,
    type_shape,
)


RULE_ARITHMETIC = "ohcpp-integer-bounds-arithmetic-candidate-001"
RULE_TRUNCATION = "ohcpp-integer-bounds-truncation-candidate-002"
RULE_NARROW_INDEX = "ohcpp-integer-bounds-narrow-index-candidate-003"
RULE_POINTER_OFFSET = "ohcpp-integer-bounds-pointer-offset-underflow-candidate-004"
RULE_VERSION = "0.2.1"
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


_UNSIGNED_TYPE = r"(?:unsigned\s+(?:char|short|int|long(?:\s+long)?)|u?int(?:8|16|32|64)_t|size_t|uintptr_t)"


def _function_parameters(function) -> Tuple[str, ...]:
    match = re.search(
        r"\b" + re.escape(function.name) + r"\s*\((?P<params>[^;{}]*)\)",
        function.text,
    )
    return split_call_arguments(match.group("params")) if match else ()


def _unsigned_parameter(function, name: str) -> bool:
    """Recognize a directly declared unsigned function parameter only."""
    if function is None:
        return False
    for parameter in _function_parameters(function):
        declaration = parameter.split("=", 1)[0].strip()
        identifiers = re.findall(r"[A-Za-z_]\w*", declaration)
        if identifiers and identifiers[-1] == name:
            return bool(re.search(r"\b" + _UNSIGNED_TYPE + r"\b", " ".join(identifiers[:-1])))
    return False


def _pointer_parameter_or_local(function, name: str) -> bool:
    if function is None:
        return False
    for parameter in _function_parameters(function):
        declaration = parameter.split("=", 1)[0].strip()
        identifiers = re.findall(r"[A-Za-z_]\w*", declaration)
        if identifiers and identifiers[-1] == name and "*" in declaration:
            return True
    return bool(re.search(
        r"\b[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*\s*\*+\s*"
        + re.escape(name) + r"\s*(?:=[^;]+)?;",
        function.text,
    ))


def _unsigned_members(units: Sequence[SourceUnit]) -> Dict[str, Set[str]]:
    """Collect plainly declared unsigned fields from the selected source units."""
    structures: Dict[str, Set[str]] = {}
    aliases: Dict[str, str] = {}
    for unit in units:
        masked = mask_comments_and_literals(unit.text)
        for match in re.finditer(
            r"\bstruct\s+(?P<tag>[A-Za-z_]\w*)\s*\{(?P<body>[\s\S]*?)\n\s*\};",
            masked,
        ):
            fields = set(re.findall(
                r"\b" + _UNSIGNED_TYPE + r"\s+(?P<field>[A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*;",
                match.group("body"),
            ))
            structures[match.group("tag")] = fields
        for match in re.finditer(
            r"\btypedef\s+struct\s+(?P<tag>[A-Za-z_]\w*)\s+(?P<alias>[A-Za-z_]\w*)\s*;",
            masked,
        ):
            aliases[match.group("alias")] = match.group("tag")
    result = dict(structures)
    result.update({alias: structures.get(tag, set()) for alias, tag in aliases.items()})
    return result


def _has_lower_bound_guard(function_text: str, left: str, right: str, position: int) -> bool:
    """Recognize a narrow return guard or a positive branch enclosing the use."""
    before = function_text[:position]
    left_re, right_re = re.escape(left), re.escape(right)
    early = re.compile(
        r"\bif\s*\(\s*" + left_re + r"\s*<\s*" + right_re
        + r"\s*\)\s*(?:\{\s*return\b[^}]*\}|return\b[^;]*;)", re.S,
    )
    if early.search(before):
        return True
    for match in re.finditer(
        r"\bif\s*\(\s*" + left_re + r"\s*(?:>=|>)\s*" + right_re + r"\s*\)\s*\{",
        before,
    ):
        open_brace = before.find("{", match.start())
        depth = 0
        for index in range(open_brace, len(function_text)):
            if function_text[index] == "{":
                depth += 1
            elif function_text[index] == "}":
                depth -= 1
                if depth == 0:
                    if match.start() < position < index:
                        return True
                    break
    return False


def _detect_unit(
    unit: SourceUnit,
    unsigned_members: Optional[Dict[str, Set[str]]] = None,
) -> Tuple[List[DetectorFinding], List[str], bool]:
    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    if unit.parse_status not in ("complete", "partial"):
        return findings, [f"{unit.path}: parse_status={unit.parse_status}; integer coverage remains unknown."], False
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return findings, [f"{unit.path}: source exceeds the 1MiB per-unit fail-closed budget."], False
    masked = mask_comments_and_literals(unit.text)
    functions = function_shapes(masked)
    _arrays, integers, constants = declarations(masked)
    guards = guard_shapes(masked, functions)
    sensitive = _sensitive_names(masked)

    # A plainly unsigned dimension difference may be dangerous when used as a
    # scaled pointer displacement even if it is never assigned to a size local.
    # This intentionally needs an observed unsigned field type and pointer base;
    # aliases, macros, indirect pointer origins and unknown types remain out of
    # scope. On partial parses this is the only analysis performed and coverage
    # remains blocked, so a local candidate is preserved without implying a
    # complete-file result.
    member_types = unsigned_members if unsigned_members is not None else _unsigned_members((unit,))
    pointer_offset = re.compile(
        r"\b(?P<pointer>[A-Za-z_]\w*)\s*(?:\+|\+=)\s*"
        r"(?:\(\s*(?:size_t|uintptr_t)\s*\)\s*)?\(\s*"
        r"(?P<left>[A-Za-z_]\w*)\s*-\s*(?P<object>[A-Za-z_]\w*)"
        r"(?P<member_op>\.|->)\s*(?P<field>[A-Za-z_]\w*)\s*\)\s*\*\s*"
        r"(?P<scale>[A-Za-z_]\w*|\d+(?:[uUlL]*))"
    )
    for match in pointer_offset.finditer(masked):
        function = function_at(functions, match.start())
        if function is None or not _pointer_parameter_or_local(function, match.group("pointer")):
            continue
        left = match.group("left")
        left_shape = integers.get(left)
        left_unsigned = bool(left_shape and left_shape.bits and not left_shape.signed)
        left_unsigned = left_unsigned or _unsigned_parameter(function, left)
        if not left_unsigned:
            continue
        object_name = match.group("object")
        object_types = re.findall(
            r"\b([A-Za-z_]\w*)\s*\*?\s+" + re.escape(object_name) + r"\s*(?:=[^;]+)?;",
            function.text,
        )
        object_type = object_types[-1] if object_types else None
        if object_type is None:
            for parameter in _function_parameters(function):
                ids = re.findall(r"[A-Za-z_]\w*", parameter.split("=", 1)[0])
                if ids and ids[-1] == object_name and len(ids) > 1:
                    object_type = ids[-2]
                    break
        if object_type is None or match.group("field") not in member_types.get(object_type, set()):
            continue
        right_expression = object_name + match.group("member_op") + match.group("field")
        if _has_lower_bound_guard(function.text, left, right_expression, match.start() - function.start):
            continue
        expression = f"{left} - {right_expression}"
        findings.append(_finding(
            unit, unit.text, match.start(), RULE_POINTER_OFFSET, expression,
            f"Candidate only: unsigned difference `{expression}` feeds a scaled pointer offset "
            "without a modeled lower-bound guard; the result may wrap before pointer arithmetic. "
            "Object aliasing, allocation extent, path feasibility, input control and product impact remain unknown.",
            "CWE-191", "CWE-787",
        ))

    if unit.parse_status == "partial":
        limitations.append(
            f"{unit.path}: parser reported partial syntax; only the bounded unsigned pointer-offset shape was inspected."
        )
        return findings, limitations, False

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
        unsigned_members = _unsigned_members(ordered)
        for unit in ordered:
            unit_findings, unit_limitations, unit_complete = _detect_unit(unit, unsigned_members)
            findings.extend(unit_findings)
            limitations.extend(unit_limitations)
            if unit_complete:
                analyzed_files.append(unit.path)
            else:
                complete = False
                # Partial source receives only the bounded pointer-offset pass.
                # Record that limited inspection so source-bound candidates pass
                # the Runner's analyzed-scope invariant while status remains blocked.
                if unit.parse_status == "partial" and any(
                    "parser reported partial syntax" in limitation
                    for limitation in unit_limitations
                ):
                    analyzed_files.append(unit.path)
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

