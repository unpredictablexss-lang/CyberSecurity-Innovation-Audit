"""A-NULL-01 bounded lexical C/C++ NULL-dereference detector.

This implementation intentionally does not parse or execute external analyzers.
It recognizes only the source, sink, guard, alias and unsupported shapes approved
in the A-NULL-01 implementation design. Semantic obligations stay unknown/missing.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from src.ohscanner.contracts import (
    DetectorFinding,
    DetectorRun,
    EvidenceObligation,
    ScanContext,
    SourceUnit,
)


RULE_ID = "ohcpp-null-dereference-candidate-001"
RULE_VERSION = "1.4.0"
RULE_LINEAGE_ID = "A-NULL-01:ohcpp-null-dereference-candidate"
WEAK_RETURN_RULE_ID = "ohcpp-null-dereference-unknown-return-observation-001"
WEAK_RETURN_RULE_VERSION = "0.1.0"
WEAK_RETURN_RULE_LINEAGE_ID = "A-NULL-RETURN-OBSERVATION-01:unknown-return-nullability"
MAX_UNIT_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
_CONTROL_WORDS = frozenset({"if", "for", "while", "switch", "catch", "return", "sizeof", "do", "else"})
_NULLPTR_WORDS = frozenset({"nullptr", "NULL", "0"})
_OBLIGATIONS = (
    EvidenceObligation("guard_dominance", "Establish complete CFG dominance for every sink.", "unknown"),
    EvidenceObligation("cross_function_alias", "Resolve parameter, return, member and escaped aliases.", "unknown"),
    EvidenceObligation("compile_context", "Bind compiler, defines, includes, language mode and instantiations.", "missing"),
    EvidenceObligation("entry_or_privilege_boundary", "Establish a realistic reachable entry and privilege boundary.", "missing"),
    EvidenceObligation("attacker_control", "Show attacker influence over the null source or trigger.", "missing"),
    EvidenceObligation("sensitive_operation_reachability", "Show the sink is reachable in the affected build.", "missing"),
    EvidenceObligation("trigger_conditions", "Record reproducible trigger conditions and observed behavior.", "missing"),
    EvidenceObligation("cia_impact", "Establish concrete confidentiality, integrity or availability impact.", "missing"),
)


@dataclass(frozen=True)
class NullSource:
    symbol: str
    kind: str
    position: int
    nullability: str
    declaration_span: Tuple[int, int]
    binding_id: str
    source_path: str
    source_sha256: str
    type_text: str = ""


@dataclass(frozen=True)
class DereferenceSink:
    symbol: str
    kind: str
    position: int
    function_span: Tuple[int, int]
    source_path: str
    source_sha256: str
    shape: str


@dataclass(frozen=True)
class GuardShape:
    symbol: str
    condition: str
    branch_spans: Tuple[Tuple[int, int], ...]
    returns_on_null_path: bool
    relation: str
    source_path: str
    source_sha256: str
    guard_span: Tuple[int, int]


@dataclass(frozen=True)
class UnsupportedShape:
    kind: str
    span: Tuple[int, int]
    missing_fact: str
    source_path: str
    source_sha256: str


@dataclass(frozen=True)
class _Span:
    start: int
    end: int

    def contains(self, position: int) -> bool:
        return self.start <= position < self.end


@dataclass(frozen=True)
class _FunctionShape:
    name: str
    span: _Span
    body: _Span
    header: str
    params: str
    params_start: int
    class_name: Optional[str]


@dataclass(frozen=True)
class _ClassShape:
    name: str
    span: _Span


@dataclass(frozen=True)
class _GuardEvaluation:
    relation: str
    error_path: str
    guard: Optional[GuardShape]


def _mask_comments_and_literals(text: str) -> str:
    chars = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(chars):
        pair = text[index : index + 2]
        char = text[index]
        if state == "code":
            if pair == "//":
                chars[index : index + 2] = [" ", " "]
                index += 2
                state = "line_comment"
                continue
            if pair == "/*":
                chars[index : index + 2] = [" ", " "]
                index += 2
                state = "block_comment"
                continue
            if char in {'"', "'"}:
                quote = char
                chars[index] = " "
                index += 1
                state = "literal"
                continue
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                chars[index] = " "
            index += 1
            continue
        if state == "block_comment":
            if pair == "*/":
                chars[index : index + 2] = [" ", " "]
                index += 2
                state = "code"
                continue
            if char != "\n":
                chars[index] = " "
            index += 1
            continue
        if char == "\\" and index + 1 < len(chars):
            chars[index] = " "
            if chars[index + 1] != "\n":
                chars[index + 1] = " "
            index += 2
            continue
        if char == quote:
            chars[index] = " "
            index += 1
            state = "code"
            continue
        if char != "\n":
            chars[index] = " "
        index += 1
    return "".join(chars)


def _matching_delimiter(masked: str, opening: int, left: str, right: str) -> Optional[int]:
    depth = 0
    for index in range(opening, len(masked)):
        char = masked[index]
        if char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def _brace_spans(masked: str) -> Tuple[Tuple[_Span, ...], bool]:
    spans: List[_Span] = []
    stack: List[int] = []
    malformed = False
    for index, char in enumerate(masked):
        if char == "{":
            stack.append(index)
        elif char == "}":
            if not stack:
                malformed = True
                continue
            opening = stack.pop()
            spans.append(_Span(opening, index + 1))
    if stack:
        malformed = True
    spans.sort(key=lambda item: (item.start, -(item.end - item.start)))
    return tuple(spans), malformed


def _delimiter_integrity(masked: str) -> bool:
    pairs = {")": "(", "]": "["}
    stack: List[str] = []
    for char in masked:
        if char in "([":
            stack.append(char)
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                return True
    return bool(stack)


def _class_shapes(masked: str, brace_spans: Sequence[_Span]) -> Tuple[_ClassShape, ...]:
    shapes: List[_ClassShape] = []
    for match in re.finditer(r"\b(?:class|struct)\s+([A-Za-z_]\w*)[^;{}]*\{", masked):
        opening = masked.find("{", match.start(), match.end())
        if opening < 0:
            continue
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing is not None:
            shapes.append(_ClassShape(match.group(1), _Span(match.start(), closing + 1)))
    return tuple(shapes)


def _header_start(masked: str, opening: int) -> int:
    index = opening - 1
    while index >= 0 and masked[index].isspace():
        index -= 1
    while index >= 0 and masked[index] not in ";{}":
        index -= 1
    return index + 1


def _strip_preprocessor_prefix(header: str) -> Tuple[str, int]:
    offset = 0
    in_continued_directive = False
    for line in header.splitlines(keepends=True):
        if in_continued_directive or not line.strip() or line.lstrip().startswith("#"):
            offset += len(line)
            in_continued_directive = line.rstrip("\r\n").endswith("\\")
            continue
        break
    return header[offset:], offset


def _function_shapes(masked: str, brace_spans: Sequence[_Span], classes: Sequence[_ClassShape]) -> Tuple[_FunctionShape, ...]:
    functions: List[_FunctionShape] = []
    for brace in brace_spans:
        start = _header_start(masked, brace.start)
        raw_header = masked[start : brace.start]
        cleaned_header, preprocessor_offset = _strip_preprocessor_prefix(raw_header)
        clean_start = start + preprocessor_offset
        opening_paren = cleaned_header.find("(")
        if opening_paren < 0:
            continue
        prefix = cleaned_header[:opening_paren]
        name_match = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
        if not name_match:
            continue
        name = name_match.group(1)
        if name.lower() in _CONTROL_WORDS:
            continue
        actual_paren = clean_start + opening_paren
        closing_paren = _matching_delimiter(masked, actual_paren, "(", ")")
        if closing_paren is None or closing_paren >= brace.end:
            continue
        params_start = actual_paren + 1
        params = masked[params_start:closing_paren]
        span = _Span(clean_start, brace.end)
        containing = [item for item in classes if item.span.start <= span.start and span.end <= item.span.end]
        class_name = min(containing, key=lambda item: item.span.end - item.span.start).name if containing else None
        functions.append(_FunctionShape(name, span, brace, cleaned_header, params, params_start, class_name))
    functions.sort(key=lambda item: (item.span.start, item.span.end))
    return tuple(functions)


def _split_top_level(value: str, delimiter: str = ",") -> Tuple[str, ...]:
    parts: List[str] = []
    start = 0
    round_depth = square_depth = angle_depth = 0
    for index, char in enumerate(value):
        if char == "(":
            round_depth += 1
        elif char == ")":
            round_depth = max(0, round_depth - 1)
        elif char == "[":
            square_depth += 1
        elif char == "]":
            square_depth = max(0, square_depth - 1)
        elif char == "<":
            angle_depth += 1
        elif char == ">":
            angle_depth = max(0, angle_depth - 1)
        elif char == delimiter and round_depth == square_depth == angle_depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        parts.append(tail)
    return tuple(parts)


def _last_declarator_name(param: str) -> Optional[str]:
    matches = list(re.finditer(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:=|$)", param))
    if matches:
        return matches[-1].group(1)
    identifiers = re.findall(r"[A-Za-z_]\w*", param)
    return identifiers[-1] if identifiers else None


def _is_call_expression(value: str) -> bool:
    return bool(re.match(r"~?[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s*(?:<[^;]*>)?\s*\(", value.strip()))


def _return_nullability(masked: str, expression: str) -> str:
    call = re.match(r"~?([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)(?:<[^;]*>)?\s*\(", expression.strip())
    if not call:
        return "unknown"
    qualified_name = call.group(1)
    # Without a type/name resolver, a qualified call cannot safely be matched
    # to an unrelated declaration that happens to share its final identifier.
    if "::" in qualified_name:
        return "unknown"
    name = qualified_name
    marker = re.compile(
        r"(?:\b_Nullable\b|\b__nullable\b|\bnullable\b|"
        r"annotate\s*\(\s*\"nullable\"\s*\))",
        re.IGNORECASE,
    )
    declarations = []
    for match in re.finditer(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*(?:;|\{)", masked):
        start = max(
            masked.rfind(";", 0, match.start()),
            masked.rfind("{", 0, match.start()),
            masked.rfind("}", 0, match.start()),
        ) + 1
        header = masked[start:match.start()]
        if "=" in header or re.search(r"\b(?:return|co_return|if|while|for|switch)\b", header):
            continue
        declarations.append(marker.search(masked[start:match.end()]) is not None)
    # Multiple declarations may belong to overloads, namespaces, or unrelated
    # scopes. The bounded source scan cannot prove which declaration was called.
    return "explicit_nullable" if len(declarations) == 1 and declarations[0] else "unknown"


def _parameter_sources(unit: SourceUnit, function: _FunctionShape, unsupported: List[UnsupportedShape]) -> Tuple[NullSource, ...]:
    sources: List[NullSource] = []
    cursor = 0
    for raw_param in _split_top_level(function.params):
        offset = function.params.find(raw_param, cursor)
        if offset < 0:
            offset = 0
        else:
            cursor = offset + len(raw_param)
        param_start = function.params_start + offset
        function_pointer = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", raw_param)
        if function_pointer:
            unsupported.append(UnsupportedShape("indirect_call", (param_start + function_pointer.start(1), param_start + function_pointer.end(1)), "function_pointer_target_unresolved; callee_dereference_unknown", unit.path, unit.sha256))
            continue
        name = _last_declarator_name(raw_param)
        if not name or name in {"const", "volatile", "void", "auto"}:
            continue
        name_match = re.search(r"\b" + re.escape(name) + r"\b", raw_param)
        name_position = param_start + (name_match.start() if name_match else 0)
        smart_pointer = bool(re.search(r"\b(?:unique_ptr|shared_ptr|weak_ptr)\b", raw_param))
        raw_pointer = "*" in raw_param and not function_pointer
        if not (raw_pointer or smart_pointer):
            continue
        explicit_nullable = bool(re.search(
            r"(?:\b_Nullable\b|\b__nullable\b|\bnullable\b|"
            r"annotate\s*\(\s*\"nullable\"\s*\))",
            raw_param,
            re.IGNORECASE,
        ))
        nullability = (
            "unknown" if smart_pointer else
            "explicit_nullable" if explicit_nullable else
            "may_be_null"
        )
        sources.append(NullSource(name, "parameter", name_position, nullability, (param_start, param_start + len(raw_param)), f"param:{unit.path}:{function.span.start}:{name}", unit.path, unit.sha256, raw_param.strip()))
    return tuple(sources)


def _local_and_return_sources(unit: SourceUnit, function: _FunctionShape, masked: str, unsupported: List[UnsupportedShape]) -> Tuple[NullSource, ...]:
    body_text = masked[function.body.start : function.body.end]
    sources: List[NullSource] = []
    pointer_names = set()
    assignments = list(re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*([^;]+);", body_text))
    for match in assignments:
        absolute_name = function.body.start + match.start(1)
        statement_start = max(
            masked.rfind(";", function.body.start, absolute_name),
            masked.rfind("{", function.body.start, absolute_name),
            masked.rfind("}", function.body.start, absolute_name),
        )
        statement_start = max(statement_start, function.body.start) + 1
        if "*" in masked[statement_start:absolute_name]:
            pointer_names.add(match.group(1))

    for match in re.finditer(
        r"\b([A-Za-z_]\w*)\s*=\s*new\s*\(\s*(?:std::)?nothrow\s*\)\s+[^;]+;",
        body_text,
    ):
        name = match.group(1)
        absolute_name = function.body.start + match.start(1)
        statement_start = max(
            masked.rfind(";", function.body.start, absolute_name),
            masked.rfind("{", function.body.start, absolute_name),
            masked.rfind("}", function.body.start, absolute_name),
        )
        statement_start = max(statement_start, function.body.start) + 1
        prefix = masked[statement_start:absolute_name]
        sources.append(
            NullSource(
                name,
                "nothrow_allocation",
                absolute_name,
                "may_be_null",
                (statement_start, function.body.start + match.end() + 1),
                f"nothrow:{unit.path}:{function.span.start}:{name}",
                unit.path,
                unit.sha256,
                prefix.strip(),
            )
        )

    for match in assignments:
        name = match.group(1)
        rhs = match.group(2).strip()
        absolute_name = function.body.start + match.start(1)
        statement_start = max(masked.rfind(";", function.body.start, absolute_name), masked.rfind("{", function.body.start, absolute_name), masked.rfind("}", function.body.start, absolute_name))
        statement_start = max(statement_start, function.body.start) + 1
        prefix = masked[statement_start:absolute_name]
        has_pointer_declarator = "*" in prefix
        known_pointer = name in pointer_names
        if (has_pointer_declarator or known_pointer) and rhs in _NULLPTR_WORDS:
            sources.append(NullSource(name, "local", absolute_name, "explicit_null", (statement_start, function.body.start + match.end() + 1), f"local:{unit.path}:{function.span.start}:{name}", unit.path, unit.sha256, prefix.strip()))
            continue
        if _is_nothrow_allocation(rhs):
            continue
        if (has_pointer_declarator or known_pointer) and _is_call_expression(rhs):
            nullability = _return_nullability(masked, rhs)
            sources.append(NullSource(name, "return_value", absolute_name, nullability, (statement_start, function.body.start + match.end() + 1), f"return:{unit.path}:{function.span.start}:{name}", unit.path, unit.sha256, prefix.strip()))
            if nullability == "unknown":
                unsupported.append(UnsupportedShape("alias", (statement_start, function.body.start + match.end() + 1), "cross_function_alias; unresolved_function_return_nullability; function_return_nullability_unknown", unit.path, unit.sha256))
    return tuple(sources)


def _member_sources(unit: SourceUnit, function: _FunctionShape, masked: str, classes: Sequence[_ClassShape]) -> Tuple[NullSource, ...]:
    function_text = masked[function.span.start : function.span.end]
    sources: List[NullSource] = []
    class_shape = next((item for item in classes if item.name == function.class_name), None) if function.class_name else None
    class_text = masked[class_shape.span.start : class_shape.span.end] if class_shape is not None else ""
    member_names = set()
    if class_text:
        for field in re.finditer(r"([^;{}]*?\b([A-Za-z_]\w*)\s*(?:=[^;]+)?;)", class_text):
            member_names.add(field.group(2))
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*(?:nullptr|NULL)\s*;", class_text):
            name = match.group(1)
            if name not in member_names:
                continue
            absolute = class_shape.span.start + match.start(1)
            field = re.search(r"([^;{}]*\b" + re.escape(name) + r"\s*=)", class_text)
            sources.append(NullSource(name, "member", absolute, "explicit_null", (absolute, class_shape.span.start + match.end()), f"member:{unit.path}:{function.class_name}:{name}:default", unit.path, unit.sha256, field.group(1).strip() if field else ""))
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(\s*(?:nullptr|NULL)\s*\)", function_text):
        name = match.group(1)
        absolute = function.span.start + match.start(1)
        owner = function.class_name or function.name
        type_text = ""
        if class_text:
            field = re.search(r"([^;{}]*\b" + re.escape(name) + r"\s*;)", class_text)
            if field:
                type_text = field.group(1).strip()
        sources.append(NullSource(name, "member", absolute, "explicit_null", (absolute, function.span.start + match.end()), f"member:{unit.path}:{owner}:{name}", unit.path, unit.sha256, type_text))
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*(?:nullptr|NULL)\s*;", function_text):
        name = match.group(1)
        if name not in member_names:
            continue
        absolute = function.span.start + match.start(1)
        sources.append(NullSource(name, "member", absolute, "explicit_null", (absolute, function.span.start + match.end()), f"member:{unit.path}:{function.class_name or function.name}:{name}:assignment", unit.path, unit.sha256, ""))
    return tuple(sources)


def _sources_for_function(unit: SourceUnit, masked: str, function: _FunctionShape, classes: Sequence[_ClassShape], unsupported: List[UnsupportedShape]) -> Tuple[NullSource, ...]:
    combined = list(_parameter_sources(unit, function, unsupported))
    combined.extend(_local_and_return_sources(unit, function, masked, unsupported))
    combined.extend(_member_sources(unit, function, masked, classes))
    deduplicated: Dict[str, NullSource] = {}
    for source in combined:
        deduplicated.setdefault(source.binding_id, source)
    return tuple(deduplicated.values())

def _macro_definition_rows(masked: str) -> Tuple[Tuple[str, Tuple[int, int], str, bool], ...]:
    definitions = []
    lines = masked.splitlines(keepends=True)
    offset = 0
    index = 0
    while index < len(lines):
        start = offset
        line = lines[index]
        if not re.match(r"^[ \t]*#[ \t]*define[ \t]+", line):
            offset += len(line)
            index += 1
            continue

        parts = [line]
        offset += len(line)
        while parts[-1].rstrip("\r\n").endswith("\\") and index + 1 < len(lines):
            parts[-1] = parts[-1].rstrip("\r\n")[:-1] + " "
            index += 1
            parts.append(lines[index])
            offset += len(lines[index])
        end = offset
        logical = "".join(parts).replace("\r", "").replace("\n", " ")
        match = re.match(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(.*)$", logical)
        if match:
            name, tail = match.group(1), match.group(2)
            function_like = tail.startswith("(")
            if function_like:
                closing = _matching_delimiter(tail, 0, "(", ")")
                if closing is None:
                    body = ""
                else:
                    body = tail[closing + 1 :].strip()
            else:
                body = tail.strip()
            definitions.append((name, (start, end), body, function_like))
        index += 1
    return tuple(definitions)


def _macro_body_has_dereference(name: str, body: str) -> bool:
    return bool(
        "*" in body
        or "->" in body
        or re.search(r"\[[^\]]*\]", body)
        or re.search(r"\b(?:DEREFERENCE|DEREF)\b", name)
    )


def _macro_shapes(unit: SourceUnit, masked: str) -> Tuple[Tuple[str, Tuple[int, int]], ...]:
    del unit
    return tuple(
        (name, span)
        for name, span, body, function_like in _macro_definition_rows(masked)
        if function_like and _macro_body_has_dereference(name, body)
    )


def _object_macro_shapes(masked: str) -> Tuple[Tuple[str, Tuple[int, int], str], ...]:
    return tuple(
        (name, span, body)
        for name, span, body, function_like in _macro_definition_rows(masked)
        if not function_like and _macro_body_has_dereference(name, body)
    )


def _global_unsupported_shapes(unit: SourceUnit, masked: str) -> List[UnsupportedShape]:
    shapes: List[UnsupportedShape] = []
    for _name, span in _macro_shapes(unit, masked):
        shapes.append(UnsupportedShape("macro", span, "macro_not_expanded; compile_context_missing", unit.path, unit.sha256))
    for _name, span, _body in _object_macro_shapes(masked):
        shapes.append(UnsupportedShape("macro", span, "macro_not_expanded; compile_context_missing", unit.path, unit.sha256))
    for match in re.finditer(r"\btemplate\s*<", masked):
        shapes.append(UnsupportedShape("template", (match.start(), match.end()), "template_instantiation_unknown; type_system_unknown", unit.path, unit.sha256))
    for match in re.finditer(r"\b(?:try|catch|throw)\b", masked):
        shapes.append(UnsupportedShape("exception", (match.start(), match.end()), "exception_edges_unknown; destructor_order_unknown; cross_function_alias", unit.path, unit.sha256))
    for match in re.finditer(r"\b(?:unique_ptr|shared_ptr|weak_ptr)\b", masked):
        shapes.append(UnsupportedShape("destructor", (match.start(), match.end()), "destructor_order_unknown", unit.path, unit.sha256))
    for match in re.finditer(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)\s*\(", masked):
        shapes.append(UnsupportedShape("indirect_call", (match.start(), match.end()), "function_pointer_target_unresolved; callee_dereference_unknown", unit.path, unit.sha256))
    for match in re.finditer(r"\bgoto\b", masked):
        shapes.append(UnsupportedShape("alias", (match.start(), match.end()), "unresolved_control_transfer", unit.path, unit.sha256))
    return shapes


def _function_pointer_names(function: _FunctionShape) -> Tuple[str, ...]:
    names = []
    for param in _split_top_level(function.params):
        match = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", param)
        if match:
            names.append(match.group(1))
    return tuple(names)


def _direct_sinks(unit: SourceUnit, masked: str, function: _FunctionShape, template_present: bool) -> List[DereferenceSink]:
    sinks: List[DereferenceSink] = []
    body = masked[function.body.start : function.body.end]
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*(\()?", body):
        is_method = bool(match.group(3))
        sinks.append(DereferenceSink(match.group(1), "method" if is_method else "member", function.body.start + match.start(), (function.span.start, function.span.end), unit.path, unit.sha256, "method_dereference" if is_method else "member_dereference"))
    unary_pattern = re.compile(r"(?P<prefix>return|[=(,+\-*/?:]|&&|\|\|)\s*\*\s*(?P<expr>[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?)")
    for match in unary_pattern.finditer(body):
        shape = "dependent_unary_dereference" if template_present else "unary_dereference"
        sinks.append(DereferenceSink(re.sub(r"\s+", "", match.group("expr")), "unary", function.body.start + match.start(), (function.span.start, function.span.end), unit.path, unit.sha256, shape))
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\[", body):
        sinks.append(DereferenceSink(match.group(1), "subscript", function.body.start + match.start(), (function.span.start, function.span.end), unit.path, unit.sha256, "subscript_dereference"))
    return sinks


def _macro_and_indirect_sinks(unit: SourceUnit, masked: str, function: _FunctionShape, macros: Sequence[Tuple[str, Tuple[int, int]]], source_symbols: Sequence[str]) -> List[DereferenceSink]:
    sinks: List[DereferenceSink] = []
    body = masked[function.body.start : function.body.end]
    macro_names = tuple(name for name, _ in macros)
    if macro_names:
        pattern = re.compile(r"\b(" + "|".join(map(re.escape, macro_names)) + r")\s*\(([^)]*)\)")
        for match in pattern.finditer(body):
            args = _split_top_level(match.group(2))
            if not args:
                continue
            arg_match = re.search(r"[A-Za-z_]\w*", args[0])
            if arg_match:
                sinks.append(DereferenceSink(arg_match.group(0), "unary", function.body.start + match.start(), (function.span.start, function.span.end), unit.path, unit.sha256, "macro_expanded_unary_dereference"))
    for callee in _function_pointer_names(function):
        for match in re.finditer(r"\b" + re.escape(callee) + r"\s*\(([^)]*)\)", body):
            for arg in _split_top_level(match.group(1)):
                arg_match = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*", arg)
                if arg_match and arg_match.group(1) in source_symbols:
                    sinks.append(DereferenceSink(arg_match.group(1), "alias", function.body.start + match.start(1) + arg_match.start(1), (function.span.start, function.span.end), unit.path, unit.sha256, "indirect_call_argument"))
    return sinks


def _object_macro_sinks(
    unit: SourceUnit,
    masked: str,
    function: _FunctionShape,
    macros: Sequence[Tuple[str, Tuple[int, int], str]],
    source_symbols: Sequence[str],
) -> List[DereferenceSink]:
    sinks: List[DereferenceSink] = []
    body = masked[function.body.start : function.body.end]
    for name, _definition_span, replacement in macros:
        referenced_sources = tuple(
            symbol
            for symbol in source_symbols
            if re.search(r"\b" + re.escape(symbol) + r"\b", replacement)
        )
        if not referenced_sources:
            continue
        for match in re.finditer(r"\b" + re.escape(name) + r"\b", body):
            for symbol in referenced_sources:
                sinks.append(
                    DereferenceSink(
                        symbol,
                        "unary",
                        function.body.start + match.start(),
                        (function.span.start, function.span.end),
                        unit.path,
                        unit.sha256,
                        "object_macro_dereference",
                    )
                )
    return sinks


def _alias_map(masked: str, function: _FunctionShape, source_symbols: Iterable[str]) -> Dict[str, str]:
    known = set(source_symbols)
    aliases: Dict[str, str] = {}
    body = masked[function.body.start : function.body.end]
    pattern = re.compile(
        r"\b([A-Za-z_]\w*)\s*(?:\*+\s*|&\s*)?(?:=|\{)\s*"
        r"([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?)\s*(?:;|\})"
    )
    for _ in range(8):
        changed = False
        for match in pattern.finditer(body):
            alias, base = match.group(1), re.sub(r"\s+", "", match.group(2))
            resolved_base = aliases.get(base, base)
            if alias not in known and base not in aliases and resolved_base in known:
                aliases[alias] = resolved_base
                changed = True
        if not changed:
            break
    return aliases


def _strip_outer_parentheses(value: str) -> str:
    value = value.strip()
    while value.startswith("(") and value.endswith(")"):
        closing = _matching_delimiter(value, 0, "(", ")")
        if closing != len(value) - 1:
            break
        value = value[1:-1].strip()
    return value


def _guard_predicate(condition: str) -> Optional[Tuple[str, str]]:
    stripped = _strip_outer_parentheses(re.sub(r"\s+", " ", condition.strip()))
    match = re.fullmatch(r"!\s*([A-Za-z_]\w*)", stripped)
    if match:
        return match.group(1), "null"
    match = re.fullmatch(r"([A-Za-z_]\w*)\s*==\s*(?:nullptr|NULL|0)", stripped)
    if match:
        return match.group(1), "null"
    match = re.fullmatch(r"(?:nullptr|NULL|0)\s*==\s*([A-Za-z_]\w*)", stripped)
    if match:
        return match.group(1), "null"
    match = re.fullmatch(r"([A-Za-z_]\w*)\s*!=\s*(?:nullptr|NULL|0)", stripped)
    if match:
        return match.group(1), "non_null"
    match = re.fullmatch(r"(?:nullptr|NULL|0)\s*!=\s*([A-Za-z_]\w*)", stripped)
    if match:
        return match.group(1), "non_null"
    match = re.fullmatch(r"([A-Za-z_]\w*)", stripped)
    if match:
        return match.group(1), "non_null"
    return None


def _branch_terminates_error_path(branch_text: str) -> bool:
    inner = branch_text.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1].strip()
    terminal = re.compile(
        r"(?:^|[;{}])\s*(?:return\b[^;]*;|throw\b[^;]*;|break\s*;|continue\s*;"
        r"|(?:std::)?abort\s*\([^;]*\)\s*;|(?:std::)?exit\s*\([^;]*\)\s*;"
        r"|(?:std::)?terminate\s*\([^;]*\)\s*;|assert\s*\(\s*(?:false|0)\s*\)\s*;)\s*$"
    )
    return bool(terminal.search(inner))


def _is_nothrow_allocation(rhs: str) -> bool:
    return bool(
        re.fullmatch(
            r"new\s*\(\s*(?:std::)?nothrow\s*\)\s+[^;]+",
            rhs.strip(),
        )
    )


def _assignment_expression_is_non_null(rhs: str) -> bool:
    value = rhs.strip()
    if _is_nothrow_allocation(value):
        return False
    return bool(
        value.startswith("&")
        or re.fullmatch(r"new\s+[^;]+", value)
        or value in {"this", "nullptr + 1"}
    )


def _assignments_between(masked: str, symbol: str, start: int, end: int) -> Tuple[Tuple[int, str], ...]:
    if end <= start:
        return ()
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\s*=\s*([^;]+);")
    return tuple(
        (match.start(), match.group(1).strip())
        for match in pattern.finditer(masked, start, end)
    )


def _source_rebound_before(source: NullSource, sink: DereferenceSink, masked: str) -> bool:
    assignments = _assignments_between(masked, source.symbol, source.position, sink.position)
    return bool(assignments) and _assignment_expression_is_non_null(assignments[-1][1])


def _symbol_base(symbol: str, aliases: Mapping[str, str]) -> str:
    current = symbol
    for _ in range(8):
        next_symbol = aliases.get(current)
        if next_symbol is None or next_symbol == current:
            return current
        current = next_symbol
    return current


def _same_binding(left: str, right: str, aliases: Mapping[str, str]) -> bool:
    return _symbol_base(left, aliases) == _symbol_base(right, aliases)


def _short_circuit_guarded(source: NullSource, sink: DereferenceSink, masked: str, aliases: Mapping[str, str]) -> bool:
    statement_start = max(
        masked.rfind(";", 0, sink.position),
        masked.rfind("{", 0, sink.position),
        masked.rfind("}", 0, sink.position),
        masked.rfind("?", 0, sink.position),
    ) + 1
    statement_end = min(
        value for value in (
            masked.find(";", sink.position),
            masked.find("}", sink.position),
            len(masked),
        ) if value >= 0
    )
    prefix = masked[statement_start:sink.position]
    suffix = masked[sink.position:statement_end]
    base = _symbol_base(source.symbol, aliases)

    for operator in ("&&", "||"):
        split = prefix.rfind(operator)
        if split < 0:
            continue
        left = re.sub(
            r"^\s*(?:return|if|while|for|switch)\s*\(?\s*",
            "",
            prefix[:split],
        )
        left = _strip_outer_parentheses(left)
        predicate = _guard_predicate(left)
        if predicate is None or not _same_binding(predicate[0], base, aliases):
            continue
        safe_condition = (
            operator == "&&" and predicate[1] == "non_null"
        ) or (
            operator == "||" and predicate[1] == "null"
        )
        if safe_condition and source.symbol in masked[statement_start:statement_end]:
            return True

    question = masked.rfind("?", statement_start, sink.position)
    if question >= 0:
        colon = masked.find(":", question, statement_end)
        condition_start = max(
            masked.rfind(";", statement_start, question),
            masked.rfind("{", statement_start, question),
            masked.rfind("}", statement_start, question),
            masked.rfind("?", statement_start, question),
            masked.rfind(":", statement_start, question),
        ) + 1
        predicate = _guard_predicate(masked[condition_start:question])
        if predicate is not None and _same_binding(predicate[0], base, aliases):
            in_true_branch = colon < 0 or sink.position < colon
            if (predicate[1] == "non_null" and in_true_branch) or (
                predicate[1] == "null" and not in_true_branch
            ):
                return True
    return False


def _parse_guards(unit: SourceUnit, masked: str, function: _FunctionShape) -> Tuple[GuardShape, ...]:
    guards: List[GuardShape] = []
    for match in re.compile(r"\bif\s*\(").finditer(masked, function.span.start, function.span.end):
        opening = masked.find("(", match.start(), match.end())
        if opening < 0:
            continue
        closing = _matching_delimiter(masked, opening, "(", ")")
        if closing is None:
            continue
        condition = masked[opening + 1 : closing].strip()
        after = closing + 1
        while after < len(masked) and masked[after].isspace():
            after += 1
        if after >= len(masked):
            continue
        if masked[after] == "{":
            branch_close = _matching_delimiter(masked, after, "{", "}")
            if branch_close is None:
                continue
            branch = (after, branch_close + 1)
            branch_text = masked[after + 1 : branch_close]
        else:
            semicolon = masked.find(";", after, function.span.end)
            if semicolon < 0:
                continue
            branch = (after, semicolon + 1)
            branch_text = masked[after : semicolon + 1]
        predicate = _guard_predicate(condition)
        if predicate is None:
            continue
        symbol, condition_kind = predicate
        spans = [branch]
        else_start = branch[1]
        while else_start < function.span.end and masked[else_start].isspace():
            else_start += 1
        if masked.startswith("else", else_start):
            else_start += len("else")
            while else_start < function.span.end and masked[else_start].isspace():
                else_start += 1
            if else_start < function.span.end and masked[else_start] == "{":
                else_close = _matching_delimiter(masked, else_start, "{", "}")
                if else_close is not None:
                    spans.append((else_start, else_close + 1))
            else:
                else_semicolon = masked.find(";", else_start, function.span.end)
                if else_semicolon >= 0:
                    spans.append((else_start, else_semicolon + 1))
        returns = _branch_terminates_error_path(branch_text)
        guards.append(GuardShape(symbol, condition_kind, tuple(spans), returns, "unknown", unit.path, unit.sha256, (match.start(), spans[0][1])))
    return tuple(guards)

def _span_candidates(shapes: Sequence[UnsupportedShape], start: int, end: int) -> Tuple[UnsupportedShape, ...]:
    return tuple(item for item in shapes if not (item.span[1] <= start or item.span[0] >= end))


def _rebind_between(masked: str, symbol: str, start: int, end: int) -> bool:
    if end <= start:
        return False
    return bool(re.search(r"\b" + re.escape(symbol) + r"\s*(?:=[^=;]|\+\+|--)", masked[start:end]))


def _evaluate_guard(source: NullSource, sink: DereferenceSink, guards: Sequence[GuardShape], unsupported: Sequence[UnsupportedShape], masked: str, aliases: Mapping[str, str]) -> _GuardEvaluation:
    function_kinds = {item.kind for item in _span_candidates(unsupported, sink.function_span[0], sink.function_span[1])}
    matching = [item for item in guards if _same_binding(item.symbol, source.symbol, aliases)]
    if sink.shape in {"macro_expanded_unary_dereference", "indirect_call_argument", "dependent_unary_dereference"}:
        return _GuardEvaluation("unknown", "not_applicable", matching[0] if matching else None)
    if function_kinds & {"macro", "template", "indirect_call"}:
        return _GuardEvaluation("unknown", "not_applicable", matching[0] if matching else None)
    if not matching:
        return _GuardEvaluation(
            "unknown" if "exception" in function_kinds else "none",
            "exception_unmodeled" if "exception" in function_kinds else "not_applicable",
            None,
        )
    for guard in matching:
        branch_start, branch_end = guard.branch_spans[0]
        if guard.condition == "non_null" and branch_start <= sink.position < branch_end and not _rebind_between(masked, _symbol_base(source.symbol, aliases), guard.guard_span[0], sink.position):
            return _GuardEvaluation("unknown", "lexical_protecting_positive_guard_pattern", guard)
        if guard.condition == "null" and len(guard.branch_spans) > 1:
            else_start, else_end = guard.branch_spans[1]
            if else_start <= sink.position < else_end:
                return _GuardEvaluation("unknown", "lexical_protecting_else_branch_pattern", guard)
        if guard.condition == "null" and guard.returns_on_null_path and sink.position >= branch_end and not _rebind_between(masked, _symbol_base(source.symbol, aliases), branch_end, sink.position):
            return _GuardEvaluation("unknown", "lexical_protecting_early_return_pattern", guard)
    for guard in matching:
        branch_start, branch_end = guard.branch_spans[0]
        if guard.condition == "null" and not guard.returns_on_null_path and sink.position >= branch_end and not (
            len(guard.branch_spans) > 1 and guard.branch_spans[1][0] <= sink.position < guard.branch_spans[1][1]
        ):
            return _GuardEvaluation("unknown", "lexical_error_branch_falls_through", guard)
    return _GuardEvaluation(
        "unknown",
        "exception_unmodeled" if "exception" in function_kinds else "guard_relation_unresolved_without_cfg",
        matching[0],
    )


def _source_role(source: NullSource) -> str:
    if "unique_ptr" in source.type_text or "shared_ptr" in source.type_text:
        return "smart_pointer_value_unknown_nullability"
    if source.kind == "nothrow_allocation" and source.nullability == "may_be_null":
        return "nothrow_allocation_may_be_null"
    if source.kind == "local" and source.nullability == "explicit_null":
        return "local_pointer_explicit_null"
    if source.kind == "parameter" and source.nullability == "may_be_null":
        return "parameter_may_be_null"
    if source.kind == "parameter" and source.nullability == "explicit_nullable":
        return "parameter_explicit_nullable"
    if source.kind == "member" and source.nullability == "explicit_null":
        return "member_pointer_explicit_null"
    if source.kind == "member" and source.nullability == "unknown":
        return "member_pointer_unknown"
    if source.kind == "return_value":
        return (
            "function_return_value_explicit_nullable"
            if source.nullability == "explicit_nullable"
            else "function_return_value_unknown_nullability"
        )
    if source.kind == "parameter":
        return "parameter_may_be_null"
    return source.kind + "_" + source.nullability


def _unknown_reasons_for_shape(shape: UnsupportedShape) -> Tuple[str, ...]:
    return tuple(part.strip() for part in shape.missing_fact.split(";") if part.strip())


def _dedupe_strings(values: Iterable[str]) -> Tuple[str, ...]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _line_column(text: str, position: int) -> Tuple[int, int]:
    line = text.count("\n", 0, position) + 1
    previous = text.rfind("\n", 0, position)
    column = position + 1 if previous < 0 else position - previous
    return line, column


def _select_source(
    candidates: Iterable[NullSource],
    sink: DereferenceSink,
    aliases: Mapping[str, str],
) -> Optional[NullSource]:
    matching = [
        item for item in candidates
        if _same_binding(item.symbol, sink.symbol, aliases)
    ]
    before_sink = [item for item in matching if item.position <= sink.position]
    if before_sink:
        return max(before_sink, key=lambda item: item.position)
    member_candidates = [item for item in matching if item.kind == "member"]
    return member_candidates[0] if member_candidates else None


def _finding_identity(
    source: NullSource,
    sink: DereferenceSink,
    evaluation: _GuardEvaluation,
    function: _FunctionShape,
) -> Tuple[str, str, str]:
    symbol_identity = "::".join((
        function.class_name or "<free-function>",
        function.name,
        source.symbol,
    ))
    fingerprint_data = (
        source.kind,
        source.nullability,
        sink.kind,
        sink.shape,
        evaluation.relation,
        evaluation.error_path,
        source.position - function.span.start,
        sink.position - function.span.start,
    )
    ast_fingerprint = hashlib.sha256(
        repr(fingerprint_data).encode("utf-8")
    ).hexdigest()
    return symbol_identity, ast_fingerprint, "complete"


class NullDereferenceDetector:
    detector_id = "ohscanner.cpp.null_dereference"
    version = "0.6.0"
    supported_languages = ("c", "cpp")
    required_facts = ()
    ast_scope = "per_file"

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        unique = {}
        for unit in units:
            unique.setdefault(unit.path, unit)
        ordered = tuple(unique[path] for path in sorted(unique))
        outcomes: List[Tuple[str, str]] = []
        analyzed: List[str] = []
        findings: List[DetectorFinding] = []
        limitations: List[str] = []
        total_bytes = 0

        for unit in ordered:
            if unit.language not in self.supported_languages:
                outcomes.append((unit.path, "not_analyzed"))
                limitations.append("No absence, safety, miss or product conclusion is published for failed/not-analyzed coverage.")
                limitations.append(f"not_analyzed language={unit.language}; no C/C++ conclusion for {unit.path}.")
                continue
            if unit.parse_status == "failed":
                outcomes.append((unit.path, "failed"))
                limitations.append("parse_failed: " + unit.path)
                limitations.append("No absence, safety, miss or product conclusion is published for failed/not-analyzed coverage.")
                continue
            unit_bytes = len(unit.text.encode("utf-8"))
            if unit_bytes > MAX_UNIT_BYTES or total_bytes + unit_bytes > MAX_TOTAL_BYTES:
                reason = "input_limit_unit_exceeded" if unit_bytes > MAX_UNIT_BYTES else "input_limit_total_exceeded"
                outcomes.append((unit.path, "not_analyzed"))
                limitations.append(f"{reason}: {unit.path}; bounded lexical analysis was not run.")
                limitations.append("No absence, safety, miss or product conclusion is published for failed/not-analyzed coverage.")
                continue
            total_bytes += unit_bytes

            masked = _mask_comments_and_literals(unit.text)
            brace_spans, malformed = _brace_spans(masked)
            malformed = malformed or _delimiter_integrity(masked)
            classes = _class_shapes(masked, brace_spans)
            functions = _function_shapes(masked, brace_spans, classes)
            unsupported = _global_unsupported_shapes(unit, masked)
            macros = _macro_shapes(unit, masked)
            object_macros = _object_macro_shapes(masked)
            template_present = any(item.kind == "template" for item in unsupported)
            sources_by_function: Dict[Tuple[int, int], Tuple[NullSource, ...]] = {}
            for function in functions:
                sources_by_function[(function.span.start, function.span.end)] = _sources_for_function(unit, masked, function, classes, unsupported)

            class_sources: Dict[str, Dict[str, NullSource]] = {}
            for function in functions:
                if not function.class_name:
                    continue
                bucket = class_sources.setdefault(function.class_name, {})
                for source in sources_by_function.get((function.span.start, function.span.end), ()):
                    bucket.setdefault(source.symbol, source)

            unit_findings: List[Tuple[int, DetectorFinding]] = []
            unknown_reasons: List[str] = []
            for shape in unsupported:
                unknown_reasons.extend(_unknown_reasons_for_shape(shape))

            for function in functions:
                key = (function.span.start, function.span.end)
                sources = sources_by_function.get(key, ())
                source_symbols = tuple(source.symbol for source in sources)
                aliases = _alias_map(masked, function, source_symbols)
                sinks = sorted(
                    _direct_sinks(unit, masked, function, template_present)
                    + _macro_and_indirect_sinks(unit, masked, function, macros, source_symbols)
                    + _object_macro_sinks(
                        unit,
                        masked,
                        function,
                        object_macros,
                        tuple(source_symbols) + tuple(aliases),
                    ),
                    key=lambda item: (item.position, item.kind, item.shape),
                )
                guards = _parse_guards(unit, masked, function)
                function_unsupported = _span_candidates(unsupported, function.span.start, function.span.end)

                for sink in sinks:
                    source = _select_source(sources, sink, aliases)
                    if source is None:
                        source = _select_source(
                            class_sources.get(function.class_name or "", {}).values(),
                            sink,
                            aliases,
                        )
                    if source is None and function.class_name:
                        source = class_sources.get(function.class_name, {}).get(sink.symbol)
                    if source is None and template_present and "." in sink.symbol:
                        owner = function.class_name or function.name
                        source = NullSource(sink.symbol, "member", sink.position, "unknown", (sink.position, sink.position + len(sink.symbol)), f"member:{unit.path}:{owner}:{sink.symbol}", unit.path, unit.sha256, "template-dependent member pointer")
                    if source is None:
                        continue
                    if _source_rebound_before(source, sink, masked):
                        continue
                    if _short_circuit_guarded(source, sink, masked, aliases):
                        continue
                    if source.nullability in ("explicit_null", "explicit_nullable", "may_be_null") or source.kind == "return_value":
                        emit = True
                    else:
                        emit = bool(_span_candidates(unsupported, sink.position, sink.position + 1) or function_unsupported)
                    if not emit:
                        continue
                    evaluation = _evaluate_guard(source, sink, guards, function_unsupported, masked, aliases)
                    if evaluation.error_path.startswith("lexical_protecting_"):
                        unknown_reasons.append("guard_dominance_unknown_without_compile_context")
                        continue
                    line, column = _line_column(unit.text, sink.position)
                    weak_unknown_return = source.kind == "return_value" and source.nullability == "unknown"
                    message_prefix = (
                        "Weak observation/needs review; unknown return nullability is not a strong source: "
                        if weak_unknown_return else
                        "Bounded same-function NULL-dereference candidate/unassessed: "
                    )
                    message = message_prefix + (
                        f"null_source={_source_role(source)}; sink={sink.shape}; "
                        f"guard_relation={evaluation.relation}; error_path={evaluation.error_path}; "
                        "syntax evidence is not proof of dereference failure, attacker control, product reachability or CIA impact."
                    )
                    symbol_identity, ast_fingerprint, identity_quality = _finding_identity(
                        source, sink, evaluation, function
                    )
                    finding = DetectorFinding(
                        file=unit.path,
                        line=line,
                        column=column,
                        rule_id=WEAK_RETURN_RULE_ID if weak_unknown_return else RULE_ID,
                        message=message,
                        evidence_type="syntax",
                        candidate_cwe="CWE-476",
                        symbol=source.symbol,
                        evidence_obligations=_OBLIGATIONS,
                        source_sha256=unit.sha256,
                        rule_version=WEAK_RETURN_RULE_VERSION if weak_unknown_return else RULE_VERSION,
                        rule_lineage_id=WEAK_RETURN_RULE_LINEAGE_ID if weak_unknown_return else RULE_LINEAGE_ID,
                        symbol_identity=symbol_identity,
                        ast_fingerprint=ast_fingerprint,
                        identity_quality=identity_quality,
                    )
                    unit_findings.append((sink.position, finding))
                    if source.nullability == "unknown":
                        if source.kind == "return_value":
                            unknown_reasons.extend(("unresolved_function_return_nullability", "function_return_nullability_unknown", "cross_function_alias"))
                        elif "unique_ptr" in source.type_text:
                            unknown_reasons.append("smart_pointer_value_unknown_nullability")
                        elif source.kind == "member":
                            unknown_reasons.append("type_system_unknown")
                    if evaluation.relation == "unknown":
                        unknown_reasons.append("guard_dominance_unknown_without_compile_context")

            unit_findings.sort(key=lambda item: (item[0], item[1].message))
            findings.extend(finding for _, finding in unit_findings)
            has_unknown_reason = bool(unknown_reasons)
            if unit.parse_status in ("partial", "not_run"):
                outcome = "partial"
                unknown_reasons.append("parse_status_" + unit.parse_status)
                if malformed:
                    unknown_reasons.append("source_syntax_malformed")
            elif malformed or not functions:
                outcome = "partial"
                unknown_reasons.append(
                    "source_syntax_malformed" if malformed else "function_region_unresolved"
                )
            elif has_unknown_reason:
                outcome = "partial"
            else:
                outcome = "complete"
            outcomes.append((unit.path, outcome))
            if outcome in ("complete", "partial"):
                analyzed.append(unit.path)
            if outcome == "complete" and not unit_findings:
                limitations.append("narrow negative only: no bounded source/sink candidate matched; compile_context and product evidence remain missing; not a safe verdict.")
            limitations.extend("unknown_reason: " + item for item in unknown_reasons)

        if any(value == "failed" for _, value in outcomes):
            status = "failed"
        elif any(value in ("partial", "not_analyzed") for _, value in outcomes):
            status = "blocked"
        else:
            status = "completed"
        limitations.insert(0, "Bounded lexical C/C++ analysis only; CFG/dominance, cross-function alias, macro, template, exception, destructor and build context may remain unknown.")
        limitations.append("Zero findings under this bounded rule are not a safe verdict.")
        if any(value in ("failed", "not_analyzed") for _, value in outcomes):
            limitations.append("No absence, safety, miss or product conclusion is published for failed/not-analyzed coverage.")
        limitations.append("Member bindings are matched only by one lexically enclosing class and qualified member name; cross-class or shadowed identity remains unknown.")
        # The shared diagnostic identity intentionally excludes column and symbol.
        # Two same-line sinks with identical explanatory text therefore collide in
        # runner.py. Keep the first deterministic occurrence rather than failing the
        # whole detector or manufacturing distinct messages to evade the contract.
        unique_findings: Dict[Tuple[str, str, int, str, str], DetectorFinding] = {}
        for finding in findings:
            identity = (
                finding.source_sha256,
                finding.file,
                finding.line,
                finding.rule_id,
                finding.message,
            )
            unique_findings.setdefault(identity, finding)
        findings = sorted(
            unique_findings.values(),
            key=lambda item: (item.file, item.line, item.column or 0, item.message),
        )
        return DetectorRun(
            detector_id=self.detector_id,
            version=self.version,
            status=status,
            analyzed_files=tuple(sorted(analyzed)),
            findings=tuple(findings),
            limitations=_dedupe_strings(limitations),
            file_outcomes=tuple(outcomes),
        )
