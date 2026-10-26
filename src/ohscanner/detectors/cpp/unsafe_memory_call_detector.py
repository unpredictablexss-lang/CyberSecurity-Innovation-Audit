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
    balanced_end,
    call_argument_span,
    line_column,
    mask_comments_and_literals,
    raw_string_literal_span,
    split_call_arguments,
)


RULE_MEMORY = "ohcpp-unsafe-memory-call-candidate-001"
RULE_FORMAT = "ohcpp-format-string-candidate-002"
RULE_VERSION = "0.5.0"
RULE_LINEAGE_ID = "A-UNSAFE-01:ohcpp-unsafe-call-candidate"

_UNSAFE_MEMORY = {"gets", "strcpy", "strcat", "sprintf"}
_FORMAT_CALLS = {"printf", "fprintf", "syslog", "vprintf", "vfprintf"}
_FORMAT_ARGUMENT_INDEX = {
    "printf": 0,
    "vprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "syslog": 1,
}
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


def _has_local_format_declaration(masked: str, name: str) -> bool:
    declaration = re.compile(
        r"^[ \t]*(?:(?:static|extern|inline|constexpr|virtual)\s+)*"
        r"(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*(?:[ \t]*<[^;{}()\n]*>)?[ \t]*[*&]*[ \t]+)+"
        + re.escape(name)
        + r"[ \t]*\([^;{}()\n]*\)[ \t]*(?:;|\{)",
    )
    for line in masked.splitlines():
        if name not in line:
            continue
        # A pathological generated line is not safe to classify as the standard
        # API. Keep it unknown rather than running an unbounded backtracking regex.
        if len(line) > 16384:
            return True
        if declaration.search(line) is not None:
            return True
    return False


def _strip_outer_parentheses(expression: str) -> str:
    value = expression.strip()
    while value.startswith("("):
        masked = mask_comments_and_literals(value)
        closing = balanced_end(masked, 0, "(", ")")
        if closing != len(masked):
            break
        value = value[1:-1].strip()
    return value


def _top_level_conditional_parts(expression: str) -> Tuple[str, str, str] | None:
    masked = mask_comments_and_literals(expression)
    paren_depth = bracket_depth = brace_depth = 0
    conditional_depth = 0
    question_index = None
    for index, char in enumerate(masked):
        at_top_level = paren_depth == bracket_depth == brace_depth == 0
        if at_top_level and char == "?":
            if (index and masked[index - 1] == "?") or (index + 1 < len(masked) and masked[index + 1] == "?"):
                continue
            if question_index is None:
                question_index = index
            conditional_depth += 1
            continue
        if at_top_level and char == ":":
            if (index and masked[index - 1] == ":") or (index + 1 < len(masked) and masked[index + 1] == ":"):
                continue
            if conditional_depth:
                conditional_depth -= 1
                if conditional_depth == 0 and question_index is not None:
                    return (
                        expression[:question_index],
                        expression[question_index + 1:index],
                        expression[index + 1:],
                    )
            continue
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
    return None


def _is_string_literal_sequence(expression: str) -> bool:
    """Parse adjacent ordinary or raw string tokens in linear time."""
    index = 0
    found_literal = False
    length = len(expression)
    while True:
        while index < length and expression[index].isspace():
            index += 1
        if index == length:
            return found_literal

        raw_span = raw_string_literal_span(expression, index)
        if raw_span is not None:
            raw_end, closed = raw_span
            if not closed:
                return False
            index = raw_end
            found_literal = True
            continue

        if expression.startswith("u8", index):
            index += 2
        elif expression[index] in "uUL":
            index += 1
        if index >= length or expression[index] != '"':
            return False
        index += 1

        while index < length:
            char = expression[index]
            if char == "\\":
                if index + 1 >= length:
                    return False
                if expression[index + 1] == "\r" and index + 2 < length and expression[index + 2] == "\n":
                    index += 3
                else:
                    index += 2
            elif char == '"':
                index += 1
                found_literal = True
                break
            else:
                index += 1
        else:
            return False


def _is_literal_format_expression(expression: str, depth: int = 0) -> bool:
    """Recognize only direct string literals and ternaries of literal arms."""
    if depth > 12:
        return False
    value = _strip_outer_parentheses(expression)
    if value.startswith("'") or _is_string_literal_sequence(value):
        return True
    parts = _top_level_conditional_parts(value)
    if parts is None:
        return False
    _condition, when_true, when_false = parts
    return (
        _is_literal_format_expression(when_true, depth + 1)
        and _is_literal_format_expression(when_false, depth + 1)
    )


def _detect_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool]:
    findings: List[DetectorFinding] = []
    if unit.parse_status != "complete":
        return findings, [f"{unit.path}: parse_status={unit.parse_status}; unsafe-call coverage remains unknown."], False
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return findings, [f"{unit.path}: source exceeds the 1MiB per-unit fail-closed budget."], False
    masked = mask_comments_and_literals(unit.text)
    local_format_declarations = {
        name for name in _FORMAT_CALLS if _has_local_format_declaration(masked, name)
    }
    signature_unknown = False
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
        elif name in _FORMAT_CALLS:
            qualifier = masked[max(0, match.start() - 2):match.start()]
            if name in local_format_declarations or qualifier.endswith(("::", ".", "->")):
                signature_unknown = True
                continue
            format_index = _FORMAT_ARGUMENT_INDEX[name]
            if len(args) <= format_index:
                continue
            format_expression = args[format_index].strip()
            if not _is_literal_format_expression(format_expression):
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
    limitations = [
        "Candidate only: lexical unsafe-call recognition does not prove exploitability.",
        "Wrappers, macros, varargs, destination aliases, compile context and attacker control remain unknown.",
        "Absence of a finding is not a safe verdict.",
    ]
    if signature_unknown:
        limitations.append(
            "format_call_signature_unknown: qualified call or same-file declaration prevents binding the name to the standard API; affected scope is partial."
        )
    return findings, limitations, not signature_unknown


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
        outcomes: List[Tuple[str, str]] = []
        complete = True
        for unit in ordered:
            unit_findings, unit_limitations, unit_complete = _detect_unit(unit)
            findings.extend(unit_findings)
            limitations.extend(unit_limitations)
            outcomes.append((unit.path, "complete" if unit_complete else "partial"))
            # The runner requires every inspected per-file outcome, including
            # partial files, to appear in analyzed_files. It keeps partial
            # coverage unknown and does not count it as complete analysis.
            analyzed.append(unit.path)
            if not unit_complete:
                complete = False
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if complete else "blocked",
            analyzed_files=tuple(sorted(analyzed)),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
            file_outcomes=tuple(outcomes),
        )
