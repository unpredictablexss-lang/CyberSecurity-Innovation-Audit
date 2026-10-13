"""Narrow shared_ptr concurrency candidate detector.

This detector recognizes class or static data members declared as
``std::shared_ptr<T> name;`` and non-atomic accesses that can be attributed to
the same owning class. Global shared_ptr objects, aliases, object-member
access through an unresolved expression, template instantiation and cross
translation-unit identity are outside this rule and are not silently promoted.

The synchronization model is deliberately narrow. Pure ``atomic_load`` /
``atomic_store`` access sets are accepted as the atomic shared_ptr API path.
A mutex suppresses candidates only when every modeled access in the same
translation unit is inside reliable RAII scopes sharing at least one mutex.
Different locks, one-sided locking, conditional/deferred locks, manual lock
APIs and mixed atomic/mutex paths remain candidate or unknown evidence.

All output remains candidate/unassessed syntax evidence. ``completed`` means
only that the selected source units were processed under the declared narrow
lexical scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from src.ohscanner.contracts import (
    DetectorFinding,
    DetectorRun,
    ScanContext,
    SourceUnit,
)


_RULE_ID = "ohcpp-shared-ptr-race-candidate-001"

_SHARED_PTR_DECL_RE = re.compile(
    r"\bstd\s*::\s*shared_ptr\s*<\s*(?P<type>[^;{}()=]+?)\s*>\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:\s*=\s*[^;]*)?\s*;"
)
_LOCK_DECL_RE = re.compile(
    r"\bstd\s*::\s*(?P<kind>lock_guard|unique_lock|scoped_lock)\s*"
    r"<(?P<template>[^;{}]+)>\s*(?P<guard>[A-Za-z_]\w*)\s*"
    r"(?P<open>[({])(?P<args>[^;{}]*)(?P<close>[)}])\s*;"
)
_FUNCTION_RE = re.compile(
    r"\b(?!if\b|for\b|while\b|switch\b|catch\b|return\b)"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)\s*"
    r"(?:->[^;{}]+)?\s*(?:const\s*)?(?:noexcept(?:\([^)]*\))?\s*)?\{"
)
_CLASS_DECL_RE = re.compile(r"\b(?:class|struct)\s+(?P<name>[A-Za-z_]\w*)\b")
_NAMESPACE_DECL_RE = re.compile(
    r"\bnamespace(?:\s+(?P<name>[A-Za-z_]\w*))?\s*\{"
)
_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "return"}
_IDENTIFIER_TOKEN_RE = re.compile(r"\b[A-Za-z_]\w*\b")
_QUALIFIER_RE = re.compile(
    r"((?:[A-Za-z_]\w*(?:<[^;{}()\s<>]+>)?\s*::\s*)+)\s*$"
)
_ATOMIC_PREFIX_RE = re.compile(
    r"\b(?:std\s*::\s*)?atomic_(?:load|store)\s*\(\s*&\s*"
    r"(?:this\s*->\s*)?(?:[A-Za-z_]\w*\s*::\s*)*$"
)
_THIS_PREFIX_RE = re.compile(r"\bthis\s*->\s*$")
_OBJECT_PREFIX_RE = re.compile(r"(?:\.|->)\s*$")
_MUTEX_ARGUMENT_RE = re.compile(r"[A-Za-z_]\w*")
_MUTEX_QUALIFIER_RE = re.compile(r"(?:[A-Za-z_]\w*\s*::\s*)+$")


@dataclass(frozen=True)
class _Span:
    start: int
    end: int

    def contains(self, position: int) -> bool:
        return self.start <= position < self.end


@dataclass(frozen=True)
class _NamedSpan:
    name: str
    qualified_name: str
    span: _Span


@dataclass(frozen=True)
class _MemberShape:
    name: str
    type_name: str
    position: int
    name_position: int
    declaration_span: _Span
    class_name: str
    qualified_class_name: str


@dataclass(frozen=True)
class _FunctionShape:
    name: str
    owner_class: Optional[str]
    span: _Span


@dataclass(frozen=True)
class _LocalBinding:
    name: str
    declaration_position: int
    scope: _Span


@dataclass(frozen=True)
class _LockScope:
    declaration_position: int
    span: _Span
    guard_name: str
    held_mutexes: FrozenSet[str]
    reliable: bool
    reason: str


@dataclass(frozen=True)
class _MemberAccess:
    member: _MemberShape
    position: int
    operation: str
    atomic: bool
    held_mutexes: FrozenSet[str]


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


def _innermost_span(spans: Sequence[_Span], position: int) -> Optional[_Span]:
    containing = [span for span in spans if span.contains(position)]
    if not containing:
        return None
    return min(containing, key=lambda span: (span.end - span.start, -span.start))


def _innermost_named_span(
    spans: Sequence[_NamedSpan], position: int
) -> Optional[_NamedSpan]:
    containing = [item for item in spans if item.span.contains(position)]
    if not containing:
        return None
    return min(
        containing,
        key=lambda item: (item.span.end - item.span.start, -item.span.start),
    )


def _join_qualified(prefix: Optional[str], leaf: str) -> str:
    return leaf if not prefix else prefix + "::" + leaf


def _namespace_spans(masked: str) -> Tuple[_NamedSpan, ...]:
    found: List[_NamedSpan] = []
    for match in _NAMESPACE_DECL_RE.finditer(masked):
        opening = masked.find("{", match.end() - 1)
        if opening < 0:
            continue
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing is None:
            continue
        span = _Span(match.start(), closing + 1)
        name = match.group("name") or "<anonymous>"
        parents = [item for item in found if item.span.contains(match.start())]
        prefix = max(parents, key=lambda item: item.span.end - item.span.start) if parents else None
        found.append(
            _NamedSpan(
                name=name,
                qualified_name=_join_qualified(prefix.qualified_name if prefix else None, name),
                span=span,
            )
        )
    return tuple(found)


def _qualified_container(
    spans: Sequence[_NamedSpan], position: int
) -> Optional[str]:
    containing = [span for span in spans if span.span.contains(position)]
    if not containing:
        return None
    return max(containing, key=lambda item: item.span.end - item.span.start).qualified_name


def _class_spans(
    masked: str, namespace_spans: Sequence[_NamedSpan]
) -> Tuple[_NamedSpan, ...]:
    found: List[_NamedSpan] = []
    for match in _CLASS_DECL_RE.finditer(masked):
        opening = masked.find("{", match.end())
        if opening < 0:
            continue
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing is None:
            continue
        name = match.group("name")
        found.append(
            _NamedSpan(
                name=name,
                qualified_name=_join_qualified(
                    _qualified_container(namespace_spans, match.start()), name
                ),
                span=_Span(match.start(), closing + 1),
            )
        )
    return tuple(found)


def _normalize_qualified_name(value: str) -> str:
    without_templates = re.sub(r"<[^>]*>", "", value)
    return re.sub(r"\s*::\s*", "::", without_templates).rstrip(":")


def _resolve_class_qualifier(
    qualifier: str,
    position: int,
    namespace_spans: Sequence[_NamedSpan],
    class_spans: Sequence[_NamedSpan],
) -> Optional[str]:
    cleaned = _normalize_qualified_name(qualifier)
    candidates = {cleaned}
    namespace_name = _qualified_container(namespace_spans, position)
    if namespace_name:
        candidates.add(namespace_name + "::" + cleaned)
    for class_span in class_spans:
        if class_span.qualified_name in candidates:
            return class_span.qualified_name
        if class_span.name == cleaned:
            matching = [
                item for item in class_spans if item.name == cleaned
            ]
            if len(matching) == 1:
                return matching[0].qualified_name
    return None


def _function_spans(
    masked: str,
    namespace_spans: Sequence[_NamedSpan],
    class_spans: Sequence[_NamedSpan],
) -> Tuple[_FunctionShape, ...]:
    found: List[_FunctionShape] = []
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
        owner_class: Optional[str] = None
        enclosing_classes = [
            item for item in class_spans if item.span.contains(match.start())
        ]
        if enclosing_classes:
            owner_class = max(
                enclosing_classes, key=lambda item: item.span.end - item.span.start
            ).qualified_name
        qualifier_match = _QUALIFIER_RE.search(prefix)
        if qualifier_match:
            resolved = _resolve_class_qualifier(
                qualifier_match.group(1),
                match.start(),
                namespace_spans,
                class_spans,
            )
            if resolved is not None:
                owner_class = resolved
        found.append(
            _FunctionShape(
                name=name,
                owner_class=owner_class,
                span=_Span(match.start(), closing + 1),
            )
        )
    return tuple(sorted(found, key=lambda item: (item.span.start, item.name)))


def _local_bindings(
    masked: str,
    class_spans: Sequence[_NamedSpan],
    block_spans: Sequence[_Span],
    functions: Sequence[_FunctionShape],
) -> Tuple[_LocalBinding, ...]:
    found: List[_LocalBinding] = []
    for match in _SHARED_PTR_DECL_RE.finditer(masked):
        position = match.start("name")
        if _function_for(functions, position) is None and (
            _innermost_named_span(class_spans, position) is not None
        ):
            continue
        scope = _innermost_span(block_spans, position)
        if scope is None:
            continue
        found.append(
            _LocalBinding(
                name=match.group("name"),
                declaration_position=position,
                scope=scope,
            )
        )
    return tuple(found)


def _mutex_names(arguments: str) -> FrozenSet[str]:
    cleaned = _MUTEX_QUALIFIER_RE.sub("", arguments)
    names = set(_MUTEX_ARGUMENT_RE.findall(cleaned))
    names -= {"std", "defer_lock", "try_to_lock", "adopt_lock"}
    return frozenset(names)


def _lock_scopes(masked: str, block_spans: Sequence[_Span]) -> Tuple[_LockScope, ...]:
    scopes: List[_LockScope] = []
    for match in _LOCK_DECL_RE.finditer(masked):
        span = _innermost_span(block_spans, match.start())
        if span is None:
            continue
        arguments = match.group("args")
        held = _mutex_names(arguments)
        reason = ""
        if "defer_lock" in arguments:
            reliable = False
            reason = "defer_lock does not hold the mutex at declaration"
        elif "try_to_lock" in arguments:
            reliable = False
            reason = "try_to_lock does not prove the mutex is held"
        elif "adopt_lock" in arguments:
            reliable = False
            reason = "adopt_lock ownership cannot be proven lexically"
        elif not held:
            reliable = False
            reason = "lock identity is unresolved"
        else:
            reliable = True
        scopes.append(
            _LockScope(
                declaration_position=match.start(),
                span=span,
                guard_name=match.group("guard"),
                held_mutexes=held,
                reliable=reliable,
                reason=reason,
            )
        )
    return tuple(scopes)


def _held_mutexes(
    scopes: Sequence[_LockScope], position: int
) -> FrozenSet[str]:
    held: Set[str] = set()
    for scope in scopes:
        if (
            scope.reliable
            and scope.declaration_position <= position
            and scope.span.contains(position)
        ):
            held.update(scope.held_mutexes)
    return frozenset(held)


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


def _is_atomic_access(masked: str, position: int) -> bool:
    return _ATOMIC_PREFIX_RE.search(masked[:position]) is not None


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


def _member_candidates(
    masked: str,
    class_spans: Sequence[_NamedSpan],
    functions: Sequence[_FunctionShape],
):
    members: List[_MemberShape] = []
    global_names: Set[str] = set()
    for match in _SHARED_PTR_DECL_RE.finditer(masked):
        position = match.start("name")
        if _function_for(functions, position) is not None:
            continue
        class_span = _innermost_named_span(class_spans, position)
        if class_span is None:
            global_names.add(match.group("name"))
            continue
        members.append(
            _MemberShape(
                name=match.group("name"),
                type_name=match.group("type").strip(),
                position=match.start(),
                name_position=position,
                declaration_span=_Span(match.start(), match.end()),
                class_name=class_span.name,
                qualified_class_name=class_span.qualified_name,
            )
        )
    return tuple(members), global_names


def _function_for(
    functions: Sequence[_FunctionShape], position: int
) -> Optional[_FunctionShape]:
    containing = [item for item in functions if item.span.contains(position)]
    if not containing:
        return None
    return min(containing, key=lambda item: (item.span.end - item.span.start, -item.span.start))


def _access_owner(
    masked: str,
    position: int,
    function: Optional[_FunctionShape],
    namespace_spans: Sequence[_NamedSpan],
    class_spans: Sequence[_NamedSpan],
) -> Tuple[str, Optional[str]]:
    before = masked[:position]
    if _THIS_PREFIX_RE.search(before):
        return "this", function.owner_class if function else None
    qualifier_match = _QUALIFIER_RE.search(before)
    if qualifier_match:
        return (
            "qualified",
            _resolve_class_qualifier(
                qualifier_match.group(1),
                position,
                namespace_spans,
                class_spans,
            ),
        )
    if _OBJECT_PREFIX_RE.search(before):
        return "object", None
    if function is not None:
        return "unqualified", function.owner_class
    return "free", None


def _is_shadowed(
    bindings: Sequence[_LocalBinding], name: str, position: int
) -> bool:
    return any(
        binding.name == name
        and binding.declaration_position <= position
        and binding.scope.contains(position)
        for binding in bindings
    )


def _common_mutex(
    accesses: Sequence[_MemberAccess],
) -> Optional[str]:
    if not accesses:
        return None
    common: Optional[Set[str]] = None
    for access in accesses:
        current = set(access.held_mutexes)
        common = current if common is None else common & current
    if not common:
        return None
    return sorted(common)[0]


def _analyze_unit(
    unit: SourceUnit,
) -> Tuple[Tuple[DetectorFinding, ...], Tuple[str, ...], bool]:
    masked = _mask_comments_and_literals(unit.text)
    block_spans = _block_spans(masked)
    namespace_spans = _namespace_spans(masked)
    class_spans = _class_spans(masked, namespace_spans)
    functions = _function_spans(masked, namespace_spans, class_spans)
    locals_by_name: Dict[str, List[_LocalBinding]] = {}
    for binding in _local_bindings(masked, class_spans, block_spans, functions):
        locals_by_name.setdefault(binding.name, []).append(binding)
    lock_scopes = _lock_scopes(masked, block_spans)
    members, global_names = _member_candidates(masked, class_spans, functions)

    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    coverage_complete = True

    for name in sorted(global_names):
        limitations.append(
            f"not_applicable: global shared_ptr declaration '{name}' is outside "
            "the class-member race rule and is not analyzed."
        )

    accesses_by_member: Dict[str, List[_MemberAccess]] = {
        member.qualified_class_name + "::" + member.name: []
        for member in members
    }
    members_by_name: Dict[str, List[_MemberShape]] = {}
    for member in members:
        members_by_name.setdefault(member.name, []).append(member)

    for token in _IDENTIFIER_TOKEN_RE.finditer(masked):
        name = token.group(0)
        candidates = members_by_name.get(name)
        if not candidates:
            continue
        if any(
            member.declaration_span.contains(token.start()) for member in candidates
        ):
            continue
        function = _function_for(functions, token.start())
        access_kind, owner = _access_owner(
            masked,
            token.start(),
            function,
            namespace_spans,
            class_spans,
        )
        if access_kind != "this" and _is_shadowed(
            locals_by_name.get(name, ()), name, token.start()
        ):
            continue
        selected: Optional[_MemberShape] = None
        if access_kind in {"unqualified", "this"}:
            selected = next(
                (
                    member
                    for member in candidates
                    if owner is not None and member.qualified_class_name == owner
                ),
                None,
            )
        elif access_kind == "qualified":
            if function is None:
                continue
            selected = next(
                (
                    member
                    for member in candidates
                    if owner is not None and member.qualified_class_name == owner
                ),
                None,
            )
            if selected is None and owner is None:
                line, _column = _line_col(unit.text, token.start())
                limitations.append(
                    f"{unit.path}: qualified shared_ptr member '{name}' occurrence "
                    f"at line {line} cannot be bound to a modeled class and remains unknown."
                )
                coverage_complete = False
                continue
        elif access_kind == "object":
            line, _column = _line_col(unit.text, token.start())
            limitations.append(
                f"{unit.path}: shared_ptr member '{name}' occurrence at line {line} "
                "is accessed through an unresolved object expression and remains unknown."
            )
            coverage_complete = False
            continue
        else:
            if name in global_names:
                continue
            if function is None:
                before = masked[:token.start()].rstrip()
                if before.endswith("::"):
                    continue
                if _innermost_named_span(class_spans, token.start()) is not None:
                    continue
                line, _column = _line_col(unit.text, token.start())
                limitations.append(
                    f"{unit.path}: shared_ptr member '{name}' occurrence at line {line} "
                    "is outside a modeled function span; analysis remains unknown."
                )
                coverage_complete = False
            continue

        if selected is None:
            continue

        key = selected.qualified_class_name + "::" + selected.name
        accesses_by_member[key].append(
            _MemberAccess(
                member=selected,
                position=token.start(),
                operation="write"
                if _looks_like_write(masked, token.start(), name)
                else "read",
                atomic=_is_atomic_access(masked, token.start()),
                held_mutexes=_held_mutexes(lock_scopes, token.start()),
            )
        )

    for key in sorted(accesses_by_member):
        accesses = sorted(
            accesses_by_member[key], key=lambda item: item.position
        )
        if not accesses:
            continue
        non_atomic = [access for access in accesses if not access.atomic]
        if not non_atomic:
            continue
        common_mutex = _common_mutex(non_atomic)
        if common_mutex is not None:
            limitations.append(
                f"{unit.path}: all modeled non-atomic accesses to '{key}' share "
                f"reliable lexical mutex '{common_mutex}' in this translation unit; "
                "atomic_load/store and mutex paths are modeled separately, and this "
                "is a narrow suppression rather than a cross-function concurrency proof."
            )
            continue

        unprotected = [
            access for access in non_atomic if not access.held_mutexes
        ]
        candidate_accesses = unprotected or non_atomic
        unreliable_locks = [
            scope.reason
            for scope in lock_scopes
            if not scope.reliable and scope.reason
        ]
        for access in candidate_accesses:
            line, column = _line_col(unit.text, access.position)
            findings.append(
                DetectorFinding(
                    file=unit.path,
                    line=line,
                    column=column,
                    rule_id=_RULE_ID,
                    message=(
                        f"Candidate only: non-atomic shared_ptr member {access.operation} "
                        f"of ''{access.member.name}''. Primary candidate root cause is a "
                        "possible race condition (CWE-362); CWE-416/use-after-free is only "
                        "a possible consequence. This syntax evidence does not prove UAF, "
                        "guard dominance, concurrent interleaving, attacker control, or "
                        "security impact; it is not proof of safety."
                    ),
                    evidence_type="syntax",
                    candidate_cwe="CWE-362",
                    symbol=access.member.name,
                )
            )
        limitations.append(
            f"{unit.path}: accesses to '{key}' do not share one reliable lexical "
            "mutex across all modeled atomic and non-atomic operations; mixed, "
            "different, conditional or one-sided synchronization remains unproven."
        )
        for reason in sorted(set(unreliable_locks)):
            limitations.append(f"{unit.path}: {reason}; candidate suppression was not applied.")
        if unreliable_locks:
            coverage_complete = False

    if not members and not any("shared_ptr" in line for line in unit.text.splitlines()):
        limitations.append(
            f"{unit.path}: no class-member shared_ptr declaration was observed in the "
            "narrow lexical scope; absence of a finding is not a safe verdict."
        )
    return _stable_unique(findings), tuple(sorted(set(limitations))), coverage_complete


class SharedPtrRaceDetector:
    detector_id = "ohscanner.cpp.shared_ptr_race"
    version = "0.2.0-proposed"
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
                "Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.",
                "No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.",
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
