"""Narrow shared_ptr concurrency candidate detector.

This detector recognizes one syntactic shape only: a class/static member of the
form ``std::shared_ptr<T> name;`` is read or written through a non-atomic
``shared_ptr`` operation inside a function body. The matching is lexical and
does not model CFG, lock semantics, cross-thread interleavings, cross-function
escape, template instantiation, or a real product build. A same-scope mutex
guard only suppresses a non-atomic occurrence when the same member also has an
``atomic_load``/``atomic_store`` observation; this is a heuristic, not a proof
of synchronization.

All output remains candidate/unassessed syntax evidence. ``completed`` means
only that the selected source units were processed under the declared narrow
lexical scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from src.ohscanner.contracts import (
    DetectorFinding,
    DetectorRun,
    ScanContext,
    SourceUnit,
)


_RULE_ID = "ohcpp-shared-ptr-race-candidate-001"

_MEMBER_DECL_RE = re.compile(
    r"\bstd\s*::\s*shared_ptr\s*<\s*(?P<type>[^;{}()=]+?)\s*>\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:\s*=\s*[^;]*)?\s*;"
)
_ATOMIC_ACCESS_RE = re.compile(
    r"\b(?:std\s*::\s*)?atomic_(?:load|store)\s*\(\s*&\s*"
    r"(?P<name>[A-Za-z_]\w*)\b"
)
_LOCK_DECL_RE = re.compile(
    r"\bstd\s*::\s*(?:lock_guard|unique_lock|scoped_lock)\s*<[^;{}]+>\s*"
    r"(?P<lock>[A-Za-z_]\w*)\s*(?:\(|\{|;)"
)
_FUNCTION_RE = re.compile(
    r"\b(?!if\b|for\b|while\b|switch\b|catch\b|return\b)"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)\s*"
    r"(?:->[^;{}]+)?\s*(?:const\s*)?(?:noexcept(?:\([^)]*\))?\s*)?\{"
)
_CLASS_DECL_RE = re.compile(r"\b(?:class|struct)\s+(?P<name>[A-Za-z_]\w*)\b")
_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "return"}
_IDENTIFIER_TOKEN_RE = re.compile(r"\b[A-Za-z_]\w*\b")


@dataclass(frozen=True)
class _Span:
    start: int
    end: int

    def contains(self, position: int) -> bool:
        return self.start <= position < self.end


@dataclass(frozen=True)
class _MemberShape:
    name: str
    type_name: str
    position: int
    name_position: int
    declaration_span: _Span
    class_name: Optional[str]


@dataclass(frozen=True)
class _LockScope:
    declaration_position: int
    span: _Span

    def contains_after(self, position: int) -> bool:
        return self.declaration_position <= position and self.span.contains(position)


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


def _line_col(text: str, position: int) -> Tuple[int, int]:
    line = text.count("\n", 0, position) + 1
    last_newline = text.rfind("\n", 0, position)
    column = position + 1 if last_newline < 0 else position - last_newline
    return line, column


def _matching_delimiter(masked: str, opening: int, left: str, right: str) -> Optional[int]:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == left:
            depth += 1
        elif masked[index] == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def _block_spans(masked: str) -> Tuple[_Span, ...]:
    spans: List[_Span] = []
    for match in re.finditer(r"\{", masked):
        closing = _matching_delimiter(masked, match.start(), "{", "}")
        if closing is not None:
            spans.append(_Span(match.start(), closing + 1))
    return tuple(sorted(spans, key=lambda item: (item.start, -(item.end - item.start))))


def _function_spans(masked: str) -> Tuple[Tuple[str, str, _Span], ...]:
    found: List[Tuple[str, str, _Span]] = []
    for match in _FUNCTION_RE.finditer(masked):
        name = match.group("name")
        if name in _CONTROL_KEYWORDS:
            continue
        opening = match.end() - 1
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing is None:
            continue
        line_start = masked.rfind("\n", 0, match.start()) + 1
        prefix = masked[line_start:match.start()]
        found.append((name, prefix, _Span(match.start(), closing + 1)))
    return tuple(sorted(found, key=lambda item: (item[2].start, item[0])))


def _class_spans(masked: str) -> Tuple[Tuple[str, _Span], ...]:
    found: List[Tuple[str, _Span]] = []
    for match in _CLASS_DECL_RE.finditer(masked):
        opening = masked.find("{", match.end())
        if opening < 0:
            continue
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing is None:
            continue
        found.append((match.group("name"), _Span(match.start(), closing + 1)))
    return tuple(sorted(found, key=lambda item: (item[1].start, item[0])))


def _innermost_span(spans: Sequence[_Span], position: int) -> Optional[_Span]:
    containing = [span for span in spans if span.contains(position)]
    if not containing:
        return None
    return min(containing, key=lambda span: (span.end - span.start, -span.start))


def _is_plain_identifier_at(masked: str, position: int) -> bool:
    index = position - 1
    while index >= 0 and masked[index].isspace():
        index -= 1
    return index < 0 or masked[index] not in {".", ">", "*", "&", ":"}


def _looks_like_write(masked: str, position: int, name: str) -> bool:
    end = position + len(name)
    tail = masked[end:end + 32]
    if re.match(r"\s*\.\s*reset\s*\(", tail):
        return True
    if re.match(r"\s*=(?!=)", tail):
        return True
    return False


def _stable_unique(findings: Iterable[DetectorFinding]) -> Tuple[DetectorFinding, ...]:
    unique = {
        (finding.file, finding.line, finding.column, finding.rule_id, finding.message): finding
        for finding in findings
    }
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (item.file, item.line, item.column or 0, item.rule_id, item.message),
        )
    )


def _lock_scopes(masked: str, spans: Sequence[_Span]) -> Tuple[_LockScope, ...]:
    scopes: List[_LockScope] = []
    for match in _LOCK_DECL_RE.finditer(masked):
        span = _innermost_span(spans, match.start())
        if span is None:
            continue
        declaration = masked[match.start():match.end()]
        if "defer_lock" in declaration or "try_to_lock" in declaration:
            continue
        scopes.append(_LockScope(match.start(), span))
    return tuple(scopes)


def _is_inside_lock(scopes: Sequence[_LockScope], position: int) -> bool:
    return any(scope.contains_after(position) for scope in scopes)


def _analyze_unit(
    unit: SourceUnit,
) -> Tuple[Tuple[DetectorFinding, ...], List[str], bool]:
    masked = _mask_comments_and_literals(unit.text)
    spans = _block_spans(masked)
    functions = _function_spans(masked)
    function_spans = [span for _name, _prefix, span in functions]
    class_spans = _class_spans(masked)
    class_span_list = [span for _name, span in class_spans]
    lock_scopes = _lock_scopes(masked, spans)
    limitations: List[str] = []
    findings: List[DetectorFinding] = []
    coverage_complete = True

    members: List[_MemberShape] = []
    for match in _MEMBER_DECL_RE.finditer(masked):
        if _innermost_span(function_spans, match.start()) is not None:
            continue
        class_span = _innermost_span(class_span_list, match.start())
        owning_class = next(
            (name for name, span in class_spans if span is class_span),
            None,
        )
        members.append(
            _MemberShape(
                name=match.group("name"),
                type_name=match.group("type").strip(),
                position=match.start(),
                name_position=match.start("name"),
                declaration_span=_Span(match.start(), match.end()),
                class_name=owning_class,
            )
        )

    atomic_positions: Dict[str, set] = {}
    for match in _ATOMIC_ACCESS_RE.finditer(masked):
        atomic_positions.setdefault(match.group("name"), set()).add(match.start("name"))

    for member in members:
        name = member.name
        has_atomic = bool(atomic_positions.get(name))
        for token in _IDENTIFIER_TOKEN_RE.finditer(masked):
            if token.group(0) != name or token.start() == member.name_position:
                continue
            if member.declaration_span.contains(token.start()):
                continue
            if not _is_plain_identifier_at(masked, token.start()):
                continue
            if token.start() in atomic_positions.get(name, set()):
                continue
            enclosing_function = min(
                ((name, prefix, span) for name, prefix, span in functions if span.contains(token.start())),
                key=lambda item: (item[2].end - item[2].start, -item[2].start),
                default=None,
            )
            if enclosing_function is None:
                # Qualified template-static definitions such as
                # DelayedSingleton<T>::instance_ = nullptr are definitions, not
                # entry-point accesses, so they remain out of this narrow model.
                before = masked[:token.start()].rstrip()
                if before.endswith("::"):
                    continue
                if _innermost_span(class_span_list, token.start()) is not None:
                    # A same-named member declaration in another class is not
                    # the shared_ptr member under analysis.
                    continue
                line, _column = _line_col(unit.text, token.start())
                limitations.append(
                    f"{unit.path}: shared_ptr member '{name}' occurrence at line {line} "
                    "is outside a modeled function span; analysis remains unknown."
                )
                coverage_complete = False
                continue
            function_name, function_prefix, function_scope = enclosing_function
            if member.class_name is not None and member.class_name not in function_prefix:
                # The same identifier can belong to a different class in the same
                # translation unit (for example DelayedRefSingleton<T>::instance_).
                # Without symbol resolution this occurrence is not attributed to
                # the shared_ptr member.
                continue
            if _is_inside_lock(lock_scopes, token.start()) and has_atomic:
                continue
            line, column = _line_col(unit.text, token.start())
            operation = "write" if _looks_like_write(masked, token.start(), name) else "read"
            message = (
                f"Candidate only: non-atomic shared_ptr member {operation} of ''{name}''. "
                "Primary candidate root cause is a possible race condition (CWE-362); "
                "CWE-416/use-after-free is only a possible consequence. This syntax "
                "evidence does not prove UAF, guard dominance, concurrent interleaving, "
                "attacker control, or security impact; it is not proof of safety."
            )
            findings.append(
                DetectorFinding(
                    file=unit.path,
                    line=line,
                    column=column,
                    rule_id=_RULE_ID,
                    message=message,
                    evidence_type="syntax",
                    candidate_cwe="CWE-362",
                    symbol=name,
                )
            )

    if not members and not any("shared_ptr" in line for line in unit.text.splitlines()):
        limitations.append(
            f"{unit.path}: no class-member shared_ptr declaration was observed in the "
            "narrow lexical scope; absence of a finding is not a safe verdict."
        )
    return _stable_unique(findings), limitations, coverage_complete


class SharedPtrRaceDetector:
    detector_id = "ohscanner.cpp.shared_ptr_race"
    version = "0.1.0-proposed"
    supported_languages = ("cpp",)
    required_facts = ()

    def detect(
        self, context: ScanContext, units: Tuple[SourceUnit, ...]
    ) -> DetectorRun:
        del context
        selected = tuple(unit for unit in units if unit.language in self.supported_languages)
        if not selected:
            return DetectorRun(
                detector_id=self.detector_id,
                version=self.version,
                status="blocked",
                limitations=("not_applicable: no source with supported language.",),
            )

        ordered = tuple(
            sorted({unit.path: unit for unit in selected}.values(), key=lambda unit: unit.path)
        )
        findings: List[DetectorFinding] = []
        limitations: List[str] = []
        analyzed_files: List[str] = []
        coverage_complete = True

        for unit in ordered:
            if unit.parse_status != "complete":
                limitations.append(
                    f"{unit.path}: parse_status={unit.parse_status}; analysis remains unknown for this unit."
                )
                coverage_complete = False
                continue
            unit_findings, unit_limitations, unit_complete = _analyze_unit(unit)
            findings.extend(unit_findings)
            limitations.extend(f"{unit.path}: {item}" for item in unit_limitations)
            analyzed_files.append(unit.path)
            if not unit_complete:
                coverage_complete = False

        status = "completed" if coverage_complete else "blocked"
        limitations.extend(
            (
                "completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.",
                "Lock scope and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.",
                "No CFG, dataflow, cross-function escape, template instantiation or real product build is modeled.",
            )
        )
        return DetectorRun(
            detector_id=self.detector_id,
            version=self.version,
            status=status,
            analyzed_files=tuple(sorted(analyzed_files)),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
