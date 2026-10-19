"""Narrow shared_ptr concurrency candidate detector.

This detector recognizes class or static data members declared as
``std::shared_ptr<T> name;`` and non-atomic accesses that can be attributed to
the same owning class. Global shared_ptr objects, unresolved object-member
access, template instantiation and identity outside the selected source units
are outside this rule and are not silently promoted. The detector aggregates
modeled accesses to the same qualified class/member across selected translation
units, resolves simple intra-function object aliases, and distinguishes
constructor initialization from later owner mutation. Cross-unit access sets
remain bounded by the selected units and do not prove a complete product access
protocol.

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
from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from src.ohscanner.contracts import (
    DetectorFinding,
    EvidenceObligation,
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
    r"\b(?:std\s*::\s*)?atomic_(?P<operation>load|store|exchange|"
    r"compare_exchange_strong|compare_exchange_weak)(?:_explicit)?\s*\(\s*&\s*"
    r"(?:this\s*->\s*)?(?:[A-Za-z_]\w*\s*::\s*)*$"
)
_THIS_PREFIX_RE = re.compile(r"\bthis\s*->\s*$")
_OBJECT_PREFIX_RE = re.compile(r"(?:\.|->)\s*$")
_OBJECT_ALIAS_DECL_RE = re.compile(
    r"\b(?:(?P<type>[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)\s*\*+\s*|auto\s+)"
    r"(?P<alias>[A-Za-z_]\w*)\s*=\s*(?:&\s*)?(?P<target>[A-Za-z_]\w*)\s*(?:;|=)"
)
_OBJECT_ALIAS_TOKEN_RE = re.compile(
    r"(?P<alias>[A-Za-z_]\w*)\s*(?:\.|->)\s*$"
)
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
    source_path: str = "<lexical>"


@dataclass(frozen=True)
class _FunctionShape:
    name: str
    owner_class: Optional[str]
    span: _Span


@dataclass(frozen=True)
class _ObjectBinding:
    name: str
    target_class: str
    declaration_position: int
    scope: _Span


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
    declaration_end: int
    name_position: int
    uncertain_after: Optional[int] = None
    uncertainty_reason: str = ""


@dataclass(frozen=True)
class _MemberAccess:
    unit: SourceUnit
    member: _MemberShape
    position: int
    operation: str
    atomic: bool
    held_mutexes: FrozenSet[str]
    unreliable_lock_reasons: FrozenSet[str]
    function_name: str
    function_span: Optional[_Span]


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
    known_class_names: Sequence[str] = (),
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
    for known in known_class_names:
        normalized = _normalize_qualified_name(known)
        if normalized in candidates or normalized.endswith("::" + cleaned):
            return normalized
    return None


def _function_spans(
    masked: str,
    namespace_spans: Sequence[_NamedSpan],
    class_spans: Sequence[_NamedSpan],
    known_class_names: Sequence[str] = (),
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
                known_class_names,
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


def _object_bindings(
    masked: str,
    class_spans: Sequence[_NamedSpan],
    block_spans: Sequence[_Span],
    functions: Sequence[_FunctionShape],
) -> Tuple[_ObjectBinding, ...]:
    found: List[_ObjectBinding] = []
    known_classes = {
        item.qualified_class_name
        for item in _member_candidates(masked, class_spans, functions)[0]
    }
    known_classes.update({item.qualified_name for item in class_spans})
    for match in _OBJECT_ALIAS_DECL_RE.finditer(masked):
        if _function_for(functions, match.start()) is None:
            continue
        scope = _innermost_span(block_spans, match.start())
        if scope is None:
            continue
        target_class = match.group("type")
        if target_class is not None:
            target_class = _resolve_class_qualifier(
                target_class + "::",
                match.start(),
                _namespace_spans(masked),
                class_spans,
                tuple(known_classes),
            ) or _normalize_qualified_name(target_class)
        else:
            target_class = None
        if target_class is None:
            continue
        found.append(
            _ObjectBinding(
                name=match.group("alias"),
                target_class=target_class,
                declaration_position=match.start(),
                scope=scope,
            )
        )
    return tuple(found)


def _resolve_object_binding(
    bindings: Sequence[_ObjectBinding], name: str, position: int
) -> Optional[_ObjectBinding]:
    candidates = [
        item for item in bindings
        if item.name == name
        and item.declaration_position <= position
        and item.scope.contains(position)
    ]
    return min(
        candidates,
        key=lambda item: (item.scope.end - item.scope.start, -item.declaration_position),
    ) if candidates else None


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


def _mutex_identity(expression: str) -> Optional[str]:
    compact = re.sub(r"\s+", "", expression)
    if re.fullmatch(
        r"(?:this->)?(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*",
        compact,
    ):
        return compact
    return None


def _mutex_lock_state(arguments: str) -> Tuple[FrozenSet[str], bool, str]:
    reason = ""
    if re.search(r"\b(?:std\s*::\s*)?defer_lock\b", arguments):
        reason = "defer_lock does not hold the mutex at declaration"
    elif re.search(r"\b(?:std\s*::\s*)?try_to_lock\b", arguments):
        reason = "try_to_lock does not prove the mutex is held"
    elif re.search(r"\b(?:std\s*::\s*)?adopt_lock\b", arguments):
        reason = "adopt_lock ownership cannot be proven lexically"

    without_policies = re.sub(
        r"\b(?:std\s*::\s*)?(?:defer_lock|try_to_lock|adopt_lock)\b",
        "",
        arguments,
    )
    expressions = [item.strip() for item in without_policies.split(",") if item.strip()]
    identities = [_mutex_identity(item) for item in expressions]
    if not expressions or any(item is None for item in identities):
        identity_reason = "lock identity is unresolved"
        return frozenset(), False, reason or identity_reason
    held = frozenset(item for item in identities if item is not None)
    return held, not bool(reason), reason


def _lock_scopes(masked: str, block_spans: Sequence[_Span]) -> Tuple[_LockScope, ...]:
    scopes: List[_LockScope] = []
    for match in _LOCK_DECL_RE.finditer(masked):
        span = _innermost_span(block_spans, match.start())
        if span is None:
            continue
        arguments = match.group("args")
        held, reliable, reason = _mutex_lock_state(arguments)
        scopes.append(
            _LockScope(
                declaration_position=match.start(),
                span=span,
                guard_name=match.group("guard"),
                held_mutexes=held,
                reliable=reliable,
                reason=reason,
                declaration_end=match.end(),
                name_position=match.start("guard"),
            )
        )
    return _guard_lifetime_scopes(masked, scopes)


def _guard_lifetime_scopes(
    masked: str, scopes: Sequence[_LockScope]
) -> Tuple[_LockScope, ...]:
    """Stop RAII credit after an explicit guard use that may change ownership.

    This is deliberately not a guard CFG. Apart from owns_lock(), later guard
    references (including address escape and move) retain unknown ownership.
    No subsequent lock() or branch restores proof. An invalidation covers its
    entire statement, since C++ evaluation order is not lexical token order.
    """
    by_name: Dict[str, List[int]] = {}
    declaration_names = {scope.name_position for scope in scopes}
    for index, scope in enumerate(scopes):
        by_name.setdefault(scope.guard_name, []).append(index)
    result = list(scopes)
    for token in _IDENTIFIER_TOKEN_RE.finditer(masked):
        indices = by_name.get(token.group())
        if not indices or token.start() in declaration_names:
            continue
        if masked[:token.start()].rstrip().endswith((".", "->", "::")):
            continue  # obj.guard is not the local variable guard.
        eligible = [index for index in indices
                    if scopes[index].declaration_end <= token.start()
                    and scopes[index].span.contains(token.start())]
        if not eligible:
            continue
        index = min(eligible, key=lambda i: (
            scopes[i].span.end - scopes[i].span.start, -scopes[i].declaration_position))
        scope = result[index]
        if scope.uncertain_after is not None:
            continue
        tail = masked[token.end():]
        if re.match(r"\s*\.\s*owns_lock\s*\(\s*\)", tail):
            continue  # Const query only; this does not re-establish ownership.
        if re.match(r"\s*\.\s*unlock\s*\(", tail):
            detail = "unlock observed; later lock ownership is not proven"
        elif re.match(r"\s*\.\s*release\s*\(", tail):
            detail = "release relinquishes RAII ownership and does not itself unlock the mutex"
        else:
            detail = "guard reference/transfer/escape makes later lock ownership unknown"
        statement_start = max(
            scope.declaration_end,
            masked.rfind(";", scope.declaration_end, token.start()) + 1,
            masked.rfind("{", scope.declaration_end, token.start()) + 1,
        )
        result[index] = replace(
            scope, uncertain_after=statement_start,
            uncertainty_reason=f"guard '{scope.guard_name}' ownership unknown: {detail}",
        )
    return tuple(result)


def _access_lock_state(
    scopes: Sequence[_LockScope], position: int
) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    held: Set[str] = set()
    unreliable: Set[str] = set()
    for scope in scopes:
        if (
            scope.declaration_position <= position
            and scope.span.contains(position)
        ):
            if scope.uncertain_after is not None and position >= scope.uncertain_after:
                unreliable.add(scope.uncertainty_reason)
            elif scope.reliable:
                held.update(scope.held_mutexes)
            elif scope.reason:
                unreliable.add(scope.reason)
    return frozenset(held), frozenset(unreliable)


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


def _atomic_access_kind(masked: str, position: int) -> Optional[str]:
    match = _ATOMIC_PREFIX_RE.search(masked[:position])
    return match.group("operation") if match else None


def _is_atomic_access(masked: str, position: int) -> bool:
    return _atomic_access_kind(masked, position) is not None


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
    source_path: str = "<lexical>",
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
                source_path=source_path,
            )
        )
    return tuple(members), global_names


def _member_key(member: _MemberShape) -> str:
    return (
        member.source_path + "::"
        + member.qualified_class_name + "::" + member.name
    )


def _select_member(
    candidates: Sequence[_MemberShape],
    owner: Optional[str],
    unit_path: str,
) -> Tuple[Optional[_MemberShape], bool]:
    matching = [
        member for member in candidates
        if owner is not None and member.qualified_class_name == owner
    ]
    if not matching:
        return None, False
    local = [member for member in matching if member.source_path == unit_path]
    if local:
        return local[0], False
    if len({member.source_path for member in matching}) != 1:
        return None, True
    return matching[0], False


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
    object_bindings: Sequence[_ObjectBinding] = (),
    known_class_names: Sequence[str] = (),
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
                known_class_names,
            ),
        )
    if _OBJECT_PREFIX_RE.search(before):
        object_match = _OBJECT_ALIAS_TOKEN_RE.search(before)
        if object_match is not None:
            binding = _resolve_object_binding(
                object_bindings, object_match.group("alias"), position
            )
            if binding is not None:
                return "object_alias", binding.target_class
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


def _potential_conflict_pairs(
    accesses: Sequence[_MemberAccess],
) -> Tuple[Tuple[int, int], ...]:
    pairs: List[Tuple[int, int]] = []
    for left_index, left in enumerate(accesses):
        for right_index in range(left_index + 1, len(accesses)):
            right = accesses[right_index]
            if left.atomic and right.atomic:
                continue
            if (
                not left.atomic
                and not right.atomic
                and left.operation == "read"
                and right.operation == "read"
            ):
                continue
            if (
                not left.atomic
                and not right.atomic
                and "initialization" in {left.operation, right.operation}
                and {left.operation, right.operation} <= {"initialization", "read"}
            ):
                continue
            pairs.append((left_index, right_index))
    return tuple(pairs)


def _candidate_finding(
    access: _MemberAccess,
    reasons: Iterable[str],
) -> DetectorFinding:
    unit = access.unit
    line, column = _line_col(unit.text, access.position)
    explanation = "; ".join(sorted(set(reasons))) or (
        "a synchronization proof is unavailable for the potential conflicting access"
    )
    return DetectorFinding(
        file=unit.path,
        line=line,
        column=column,
        rule_id=_RULE_ID,
        message=(
            f"Candidate only: candidate/unknown {access.atomic and 'atomic' or 'non-atomic'} "
            f"shared_ptr member {access.operation} of ''{access.member.name}''. "
            "Primary candidate root cause is a possible race condition (CWE-362); "
            "CWE-416/use-after-free is only a possible consequence. This syntax "
            "evidence does not prove UAF, guard dominance, concurrent interleaving, "
            "attacker control, or security impact; it is not proof of safety. "
            f"Synchronization evidence: {explanation}."
        ),
        evidence_type="syntax",
        candidate_cwe="CWE-362",
        symbol=access.member.name,
        evidence_obligations=(
            EvidenceObligation(
                kind="synchronization_proof",
                description=(
                    "Synchronization proof is unknown: "
                    f"{explanation}. Prove the complete access protocol, lock "
                    "identity/dominance and cross-function ordering before promotion."
                ),
                status="unknown",
            ),
        ),
        source_sha256=unit.sha256,
    )


def _analyze_member_accesses(
    key: str,
    accesses: Sequence[_MemberAccess],
) -> Tuple[Tuple[DetectorFinding, ...], Tuple[str, ...], bool]:
    unit = accesses[0].unit
    if accesses and all(access.atomic for access in accesses):
        return (
            (),
            (
                f"{unit.path}: modeled accesses to '{key}' use only the "
                "atomic shared_ptr API; this narrow atomic-only shape is not a "
                "concurrency proof.",
            ),
            True,
        )
    if accesses and all(access.operation == "initialization" for access in accesses):
        return (
            (),
            (
                f"{unit.path}: modeled accesses to '{key}' are constructor "
                "initialization only; stable-owner shape is not a concurrency proof.",
            ),
            True,
        )

    conflict_pairs = _potential_conflict_pairs(accesses)
    if len(accesses) > 1 and not conflict_pairs:
        shape = (
            "constructor initialization followed only by stable reads"
            if any(item.operation == "initialization" for item in accesses)
            else "read-only"
        )
        return (
            (),
            (
                f"{unit.path}: modeled non-atomic accesses to '{key}' are {shape} "
                "and do not form a potential conflicting pair in this narrow model.",
            ),
            True,
        )

    candidate_indices: Set[int] = set()
    reasons_by_index: Dict[int, Set[str]] = {}
    covered_pairs: List[str] = []
    unreliable_reasons: Set[str] = set()
    for access in accesses:
        unreliable_reasons.update(access.unreliable_lock_reasons)

    def add_candidate(index: int, reason: str) -> None:
        candidate_indices.add(index)
        reasons_by_index.setdefault(index, set()).add(reason)

    if len(accesses) == 1 and not accesses[0].atomic and accesses[0].operation != "read":
        add_candidate(
            0,
            "a single modeled lexical write cannot prove external or "
            "cross-function synchronization",
        )
        for reason in accesses[0].unreliable_lock_reasons:
            add_candidate(0, reason)

    for left_index, right_index in conflict_pairs:
        left = accesses[left_index]
        right = accesses[right_index]
        unreliable_reasons.update(left.unreliable_lock_reasons)
        unreliable_reasons.update(right.unreliable_lock_reasons)
        cross_function = (
            left.function_span is not None
            and right.function_span is not None
            and left.function_span != right.function_span
        )
        cross_function_reason = (
            "; cross-function synchronization protocol is unknown"
            if cross_function
            else ""
        )

        if left.atomic != right.atomic:
            shared = left.held_mutexes & right.held_mutexes
            if (
                shared
                and not left.unreliable_lock_reasons
                and not right.unreliable_lock_reasons
            ):
                covered_pairs.append("/".join(sorted(shared)))
                continue
            non_atomic_indices = [
                index
                for index, access in ((left_index, left), (right_index, right))
                if not access.atomic
            ]
            for index in non_atomic_indices:
                add_candidate(
                    index,
                    "mixed atomic/non-atomic access pair has no proven common "
                    f"synchronization protocol{cross_function_reason}",
                )
            for index, access in ((left_index, left), (right_index, right)):
                for reason in access.unreliable_lock_reasons:
                    add_candidate(index, reason)
            continue

        shared = left.held_mutexes & right.held_mutexes
        if (
            shared
            and not left.unreliable_lock_reasons
            and not right.unreliable_lock_reasons
        ):
            covered_pairs.append("/".join(sorted(shared)))
            continue

        implicated = {
            index
            for index, access in ((left_index, left), (right_index, right))
            if access.unreliable_lock_reasons
        }
        if left.unreliable_lock_reasons or right.unreliable_lock_reasons:
            if not implicated:
                implicated = {left_index, right_index}
            pair_reason = (
                "conditional, deferred or unresolved lock identity prevents a "
                f"reliable synchronization proof{cross_function_reason}"
            )
        elif bool(left.held_mutexes) != bool(right.held_mutexes):
            unprotected = (
                right_index if left.held_mutexes else left_index
            )
            implicated = {unprotected}
            pair_reason = (
                f"one-sided mutex leaves one access unprotected{cross_function_reason}"
            )
        elif left.held_mutexes and right.held_mutexes:
            implicated = {left_index, right_index}
            pair_reason = (
                f"different mutex identities do not synchronize the pair{cross_function_reason}"
            )
        else:
            implicated = {left_index, right_index}
            pair_reason = (
                f"no reliable mutex covers the pair{cross_function_reason}"
            )

        for index in implicated:
            access_reasons = {pair_reason}
            access_reasons.update(accesses[index].unreliable_lock_reasons)
            add_candidate(index, "; ".join(sorted(access_reasons)))

    limitations: List[str] = []
    if conflict_pairs and len(covered_pairs) == len(conflict_pairs):
        labels = ", ".join(f"'{item}'" for item in sorted(set(covered_pairs)))
        limitations.append(
            f"{unit.path}: all potential conflicting access pairs to '{key}' "
            f"share reliable lexical mutex {labels}; pairwise suppression is "
            "limited to this translation unit and lexical lock model."
        )
    elif covered_pairs:
        labels = ", ".join(f"'{item}'" for item in sorted(set(covered_pairs)))
        limitations.append(
            f"{unit.path}: {len(covered_pairs)} potential conflicting pair(s) "
            f"for '{key}' share reliable lexical mutex {labels}; remaining pairs "
            "were not suppressed."
        )

    if candidate_indices:
        limitations.append(
            f"{unit.path}: pairwise analysis of '{key}' leaves synchronization "
            "unproven for the mixed atomic/non-atomic synchronization protocol, "
            "different or one-sided mutexes, conditional/deferred locks, unresolved "
            "lock aliases or cross-function paths."
        )
    for reason in sorted(unreliable_reasons):
        limitations.append(f"{unit.path}: {reason}; candidate suppression was not applied.")

    findings = tuple(
        _candidate_finding(accesses[index], reasons_by_index[index])
        for index in sorted(candidate_indices)
    )
    return findings, tuple(limitations), not unreliable_reasons


def _analyze_unit(
    unit: SourceUnit,
    *,
    external_members: Sequence[_MemberShape] = (),
    access_sink: Optional[Dict[str, List[_MemberAccess]]] = None,
    emit_findings: bool = True,
) -> Tuple[Tuple[DetectorFinding, ...], Tuple[str, ...], bool]:
    masked = _mask_comments_and_literals(unit.text)
    block_spans = _block_spans(masked)
    namespace_spans = _namespace_spans(masked)
    class_spans = _class_spans(masked, namespace_spans)
    known_class_names = tuple(sorted({
        item.qualified_name for item in class_spans
    } | {item.qualified_class_name for item in external_members}))
    functions = _function_spans(
        masked, namespace_spans, class_spans, known_class_names
    )
    object_bindings = _object_bindings(masked, class_spans, block_spans, functions)
    locals_by_name: Dict[str, List[_LocalBinding]] = {}
    for binding in _local_bindings(masked, class_spans, block_spans, functions):
        locals_by_name.setdefault(binding.name, []).append(binding)
    lock_scopes = _lock_scopes(masked, block_spans)
    local_members, global_names = _member_candidates(
        masked, class_spans, functions, unit.path
    )
    local_declaration_spans = tuple(item.declaration_span for item in local_members)
    members = tuple({
        _member_key(item): item
        for item in tuple(local_members) + tuple(external_members)
    }.values())

    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    coverage_complete = True

    for name in sorted(global_names):
        limitations.append(
            f"not_applicable: global shared_ptr declaration '{name}' is outside "
            "the class-member race rule and is not analyzed."
        )

    accesses_by_member: Dict[str, List[_MemberAccess]] = {
        _member_key(member): []
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
            declaration.contains(token.start())
            for declaration in local_declaration_spans
        ):
            continue
        function = _function_for(functions, token.start())
        access_kind, owner = _access_owner(
            masked,
            token.start(),
            function,
            namespace_spans,
            class_spans,
            object_bindings,
            known_class_names,
        )
        if access_kind != "this" and _is_shadowed(
            locals_by_name.get(name, ()), name, token.start()
        ):
            continue
        selected: Optional[_MemberShape] = None
        ambiguous_member = False
        if access_kind in {"unqualified", "this"}:
            selected, ambiguous_member = _select_member(candidates, owner, unit.path)
        elif access_kind == "qualified":
            if function is None:
                continue
            selected, ambiguous_member = _select_member(candidates, owner, unit.path)
            if selected is None and owner is None:
                line, _column = _line_col(unit.text, token.start())
                limitations.append(
                    f"{unit.path}: qualified shared_ptr member '{name}' occurrence "
                    f"at line {line} cannot be bound to a modeled class and remains unknown."
                )
                coverage_complete = False
                continue
        elif access_kind == "object_alias":
            selected, ambiguous_member = _select_member(candidates, owner, unit.path)
            if selected is None and ambiguous_member:
                line, _column = _line_col(unit.text, token.start())
                limitations.append(
                    f"{unit.path}: shared_ptr member '{name}' occurrence at line {line} "
                    "matches multiple selected-unit declarations and remains unknown."
                )
                coverage_complete = False
                continue
            if selected is None:
                line, _column = _line_col(unit.text, token.start())
                limitations.append(
                    f"{unit.path}: simple object alias for shared_ptr member '{name}' "
                    f"at line {line} is unresolved and remains unknown."
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
            if ambiguous_member:
                line, _column = _line_col(unit.text, token.start())
                limitations.append(
                    f"{unit.path}: shared_ptr member '{name}' occurrence at line {line} "
                    "matches multiple selected-unit declarations and remains unknown."
                )
                coverage_complete = False
            continue

        key = _member_key(selected)
        held_mutexes, unreliable_lock_reasons = _access_lock_state(
            lock_scopes, token.start()
        )
        atomic_operation = _atomic_access_kind(masked, token.start())
        accesses_by_member[key].append(
            _MemberAccess(
                unit=unit,
                member=selected,
                position=token.start(),
                operation=(
                    "write"
                    if atomic_operation
                    in {
                        "store",
                        "exchange",
                        "compare_exchange_strong",
                        "compare_exchange_weak",
                    }
                    or (
                        atomic_operation is None
                        and _looks_like_write(masked, token.start(), name)
                    )
                    else (
                        "initialization"
                        if (
                            atomic_operation is None
                            and function is not None
                            and token.start() < masked.find("{", function.span.start)
                        )
                        else "read"
                    )
                ),
                atomic=atomic_operation is not None,
                held_mutexes=held_mutexes,
                unreliable_lock_reasons=unreliable_lock_reasons,
                function_name=(
                    f"{function.owner_class}::{function.name}"
                    if function and function.owner_class
                    else function.name if function else "<lexical>"
                ),
                function_span=function.span if function else None,
            )
        )

    for key in sorted(accesses_by_member):
        accesses = sorted(
            accesses_by_member[key], key=lambda item: item.position
        )
        if not accesses:
            continue
        if access_sink is not None:
            access_sink.setdefault(key, []).extend(accesses)
        if emit_findings:
            member_findings, member_limitations, member_complete = (
                _analyze_member_accesses(key, accesses)
            )
            findings.extend(member_findings)
            limitations.extend(member_limitations)
            if not member_complete:
                coverage_complete = False

    if not members and not any("shared_ptr" in line for line in unit.text.splitlines()):
        limitations.append(
            f"{unit.path}: no class-member shared_ptr declaration was observed in the "
            "narrow lexical scope; absence of a finding is not a safe verdict."
        )
    return _stable_unique(findings), tuple(sorted(set(limitations))), coverage_complete

class SharedPtrRaceDetector:
    detector_id = "ohscanner.cpp.shared_ptr_race"
    version = "0.5.1"
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
        complete_units = tuple(unit for unit in ordered if unit.parse_status == "complete")
        external_members: Dict[Tuple[str, str], _MemberShape] = {}
        for unit in complete_units:
            masked = _mask_comments_and_literals(unit.text)
            namespace_spans = _namespace_spans(masked)
            class_spans = _class_spans(masked, namespace_spans)
            functions = _function_spans(masked, namespace_spans, class_spans)
            members, _globals = _member_candidates(
                masked, class_spans, functions, unit.path
            )
            for member in members:
                external_members.setdefault(_member_key(member), member)
        external_member_tuple = tuple(external_members[key] for key in sorted(external_members))
        access_sink: Dict[str, List[_MemberAccess]] = {}
        for unit in ordered:
            if unit.parse_status != "complete":
                limitations.append(
                    f"{unit.path}: parse_status={unit.parse_status}; analysis remains unknown for this unit."
                )
                coverage_complete = False
                continue
            _unit_findings, unit_limitations, unit_complete = _analyze_unit(
                unit,
                external_members=external_member_tuple,
                access_sink=access_sink,
                emit_findings=False,
            )
            limitations.extend(f"{unit.path}: {item}" for item in unit_limitations)
            analyzed_files.append(unit.path)
            if not unit_complete:
                coverage_complete = False
        for key in sorted(access_sink):
            accesses = sorted(access_sink[key], key=lambda item: (item.unit.path, item.position))
            member_findings, member_limitations, member_complete = (
                _analyze_member_accesses(key, accesses)
            )
            findings.extend(member_findings)
            limitations.extend(member_limitations)
            if not member_complete:
                coverage_complete = False

        status = "completed" if coverage_complete else "blocked"
        limitations.extend(
            (
                "completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.",
                "Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.",
                "Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.",
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
