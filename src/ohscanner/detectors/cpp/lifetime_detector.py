"""Narrow C++ lifetime candidate detector against the current M0 contract.

Scope: one explicit ownership shape and one synchronization classification.
The detector recognizes a same-function ``std::unique_ptr`` owner, a raw alias
obtained with ``owner.get()``, owner invalidation with ``reset()``, and a later
dereference of that raw alias before a supported straight-line rebinding from
the owner, another object's address, or nullptr. A scoped
mutex is recorded as a synchronization constraint, but never treated as proof
that the destroyed object remains alive.

Detector Contract v1 is not frozen. This implementation uses the M0 classes in
``src.ohscanner.contracts`` and produces only syntax-level candidate evidence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from src.ohscanner.contracts import (
    DetectorFinding,
    DetectorRun,
    ScanContext,
    SourceUnit,
)


_OWNER_DECL_RE = re.compile(
    r"\bstd\s*::\s*unique_ptr\s*<\s*(?P<type>[^;{}()=]+?)\s*>\s*"
    r"(?P<owner>[A-Za-z_]\w*)\s*(?P<decl_end>=|;|\()"
)
_RAW_ALIAS_RE = re.compile(
    r"\b(?:(?:auto|[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)\s*\*+\s*|auto\s+)"
    r"(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<owner>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*\)"
)
_MEMBER_RAW_ALIAS_RE = re.compile(
    r"\b(?P<target>(?:[A-Za-z_]\w*\s*(?:\.|->)\s*)+[A-Za-z_]\w*)\s*=\s*"
    r"(?P<owner>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*\)"
)
_ALIAS_ASSIGN_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<owner>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*\)"
)
_ALIAS_CHAIN_DECL_RE = re.compile(
    r"\b(?:(?:auto|[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)\s*\*+\s*|auto\s+)"
    r"(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<source>[A-Za-z_]\w*)\s*;"
)
_ALIAS_CHAIN_ASSIGN_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<source>[A-Za-z_]\w*)\s*;"
)
_POINTER_BINDING_RE = re.compile(
    r"\b(?:(?:auto|[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)\s*\*+\s*|auto\s+)"
    r"(?P<alias>[A-Za-z_]\w*)\s*(?P<decl_end>=|;|\()"
)
_RESET_RE = re.compile(r"\b(?P<owner>[A-Za-z_]\w*)\s*\.\s*reset\s*\(")
_OWNER_ASSIGN_RE = re.compile(r"\b(?P<owner>[A-Za-z_]\w*)\s*=(?!=)")
_MOVE_TRANSFER_RE = re.compile(
    r"\b(?P<target>[A-Za-z_]\w*)\s*=\s*std\s*::\s*move\s*\(\s*(?P<owner>[A-Za-z_]\w*)\s*\)"
)
_REBIND_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*=\s*(?:"
    r"(?P<owner>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*\)"
    r"|nullptr\b|&\s*[A-Za-z_]\w*\b)\s*;"
)
_LOCK_RE = re.compile(
    r"\bstd\s*::\s*(?:lock_guard|unique_lock|scoped_lock)\s*<[^;{}]+>\s*"
    r"(?P<lock>[A-Za-z_]\w*)\s*(?:\(|\{|;)"
)
_FUNCTION_RE = re.compile(
    r"\b(?!if\b|for\b|while\b|switch\b|catch\b|return\b)"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)\s*"
    r"(?:->[^;{}]+)?\s*(?:const\s*)?(?:noexcept(?:\([^)]*\))?\s*)?\{"
)
_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "return"}
_CONTROL_BOUNDARY_RE = re.compile(
    r"\b(?:if|else|for|while|do|switch|case|default|break|continue|return|goto|try|catch|throw)\b"
    r"|[{}?]|&&|\|\|"
)
_IDENTIFIER_TOKEN_RE = re.compile(r"\b[A-Za-z_]\w*\b")
_LAMBDA_CAPTURE_RE = re.compile(r"\[\s*(?P<captures>[^\]=]*)\]\s*\(")
_CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\(")


@dataclass(frozen=True)
class _Span:
    start: int
    end: int

    def contains(self, position: int) -> bool:
        return self.start <= position < self.end


@dataclass(frozen=True)
class _OwnerShape:
    owner: str
    owner_type: str
    position: int
    name_position: int
    declaration_span: _Span
    span: _Span
    binding_scope: Optional[_Span]
    binding_id: str


@dataclass(frozen=True)
class _AliasShape:
    alias: str
    owner: str
    position: int
    name_position: int
    declaration_span: _Span
    span: _Span
    binding_scope: Optional[_Span]
    binding_id: str
    source_alias: Optional[str] = None


@dataclass(frozen=True)
class _PointerBinding:
    alias: str
    position: int
    name_position: int
    declaration_span: _Span
    span: _Span
    binding_scope: Optional[_Span]
    binding_id: str


@dataclass(frozen=True)
class _ResetShape:
    owner: str
    position: int
    call_end: int
    span: _Span
    invalidation_kind: str
    description: str
    transfer_scope_end: Optional[int] = None


@dataclass(frozen=True)
class LifetimeAnalysisOptions:
    """Ablation switches used by the research slice and deterministic tests.

    ``timeout_check`` is cooperative only. The shared Runner does not provide a
    hard timeout or memory sandbox; this callback lets a detector fail its own
    run without affecting another detector.
    """

    suppress_rebound_alias: bool = True
    classify_sync_scope: bool = True
    timeout_check: Optional[Callable[[], bool]] = None


class _CooperativeTimeout(Exception):
    pass


def _mask_comments_and_literals(text: str) -> str:
    """Replace comments/literal contents with spaces while preserving offsets."""

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


def _call_end(masked: str, opening_paren: int) -> Optional[int]:
    return _matching_delimiter(masked, opening_paren, "(", ")")


def _block_spans(masked: str) -> Tuple[_Span, ...]:
    spans: List[_Span] = []
    for match in re.finditer(r"\{", masked):
        closing = _matching_delimiter(masked, match.start(), "{", "}")
        if closing is not None:
            spans.append(_Span(match.start(), closing + 1))
    return tuple(sorted(spans, key=lambda item: (item.start, -(item.end - item.start))))


def _function_spans(masked: str) -> Tuple[Tuple[str, _Span], ...]:
    found: List[Tuple[str, _Span]] = []
    for match in _FUNCTION_RE.finditer(masked):
        name = match.group("name")
        if name in _CONTROL_KEYWORDS:
            continue
        opening = match.end() - 1
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing is None:
            continue
        found.append((name, _Span(match.start(), closing + 1)))
    return tuple(sorted(found, key=lambda item: (item[1].start, item[0])))


def _innermost_span(spans: Sequence[_Span], position: int) -> Optional[_Span]:
    containing = [span for span in spans if span.contains(position)]
    if not containing:
        return None
    return min(containing, key=lambda span: (span.end - span.start, -span.start))


def _function_name_at(
    functions: Sequence[Tuple[str, _Span]], position: int
) -> str:
    containing = [
        (name, span) for name, span in functions if span.contains(position)
    ]
    if not containing:
        return "unmodeled"
    name, _span = min(
        containing, key=lambda item: (item[1].end - item[1].start, -item[1].start)
    )
    return name


def _binding_id(
    kind: str,
    name: str,
    position: int,
    function_scope: _Span,
    binding_scope: _Span,
) -> str:
    identity = (
        f"{kind}:{name}@{position}:"
        f"function={function_scope.start}-{function_scope.end}:"
        f"block={binding_scope.start}-{binding_scope.end}"
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _is_plain_identifier_at(masked: str, position: int) -> bool:
    index = position - 1
    while index >= 0 and masked[index].isspace():
        index -= 1
    return index < 0 or masked[index] not in {".", ">", "*", "&", ":"}


def _resolve_binding(
    bindings: Sequence[_PointerBinding],
    alias_name: str,
    position: int,
    *,
    at_or_before: bool = True,
) -> Optional[_PointerBinding]:
    candidates = [
        binding
        for binding in bindings
        if binding.alias == alias_name
        and (binding.position <= position if at_or_before else binding.position < position)
        and binding.binding_scope is not None
        and binding.binding_scope.contains(position)
        and binding.span.contains(position)
    ]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda binding: (
            binding.binding_scope.end - binding.binding_scope.start,
            binding.span.end - binding.span.start,
            -binding.position,
        ),
    )


def _resolve_owner(
    owners: Sequence[_OwnerShape], owner_name: str, position: int
) -> Optional[_OwnerShape]:
    candidates = [
        owner
        for owner in owners
        if owner.owner == owner_name
        and owner.position < position
        and owner.binding_scope is not None
        and owner.binding_scope.contains(position)
        and owner.span.contains(position)
    ]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda owner: (
            owner.binding_scope.end - owner.binding_scope.start,
            owner.span.end - owner.span.start,
            -owner.position,
        ),
    )


def _use_positions(masked: str, alias: str) -> Tuple[int, ...]:
    escaped = re.escape(alias)
    patterns = (
        rf"\*\s*(?P<alias>{escaped})\b",
        rf"\(\s*\*\s*(?P<alias>{escaped})\s*\)",
        rf"\b(?P<alias>{escaped})\s*->",
    )
    spans = sorted(
        (match.start("alias"), match.end("alias"))
        for pattern in patterns
        for match in re.finditer(pattern, masked)
    )
    merged: List[Tuple[int, int]] = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(start for start, _end in merged)


def _lambda_capture_positions(masked: str, alias: str) -> Tuple[int, ...]:
    escaped = re.escape(alias)
    positions: List[int] = []
    for match in _LAMBDA_CAPTURE_RE.finditer(masked):
        token = re.search(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])", match.group("captures"))
        if token is not None:
            positions.append(match.start("captures") + token.start())
    return tuple(sorted(set(positions)))


def _call_name_at(masked: str, position: int) -> Optional[str]:
    for match in _CALL_RE.finditer(masked):
        opening = match.end() - 1
        closing = _call_end(masked, opening)
        if closing is not None and opening < position < closing:
            return match.group("name")
    return None


def _escape_positions(
    masked: str,
    alias: str,
    binding: _PointerBinding,
    bindings: Sequence[_PointerBinding],
    use_positions: Sequence[int],
    rebind_positions: Sequence[int],
) -> Tuple[Tuple[int, str], ...]:
    uses = set(use_positions)
    rebound = set(rebind_positions)
    captures = set(_lambda_capture_positions(masked, alias))
    escapes: List[Tuple[int, str]] = []
    for match in _IDENTIFIER_TOKEN_RE.finditer(masked):
        position = match.start()
        if match.group(0) != alias or position == binding.name_position:
            continue
        if not _is_plain_identifier_at(masked, position):
            continue
        if position in uses or position in rebound:
            continue
        if _resolve_binding(bindings, alias, position) != binding:
            continue
        tail = masked[position + len(alias):]
        if (
            re.match(r"\s*;", tail)
            and re.search(r"=\s*$", masked[:position].rstrip())
        ):
            continue
        call_name = _call_name_at(masked, position)
        if position in captures:
            kind = "lambda_capture"
        elif call_name is not None:
            kind = f"cross_function_call:{call_name}"
        else:
            kind = "alias_transfer_or_escape"
        escapes.append((position, kind))
    return tuple(sorted(set(escapes)))


def _finding_key(finding: DetectorFinding) -> Tuple[str, int, str, str]:
    return finding.file, finding.line, finding.rule_id, finding.message


def _stable_unique(findings: Iterable[DetectorFinding]) -> Tuple[DetectorFinding, ...]:
    unique: Dict[Tuple[str, int, str, str], DetectorFinding] = {}
    for finding in findings:
        unique.setdefault(_finding_key(finding), finding)
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (item.file, item.line, item.column or 0, item.rule_id, item.message),
        )
    )


def _if_branch_regions(masked: str) -> Tuple[Tuple[_Span, Optional[_Span]], ...]:
    regions: List[Tuple[_Span, Optional[_Span]]] = []
    for match in re.finditer(r"\bif\s*\(", masked):
        opening = masked.find("(", match.start())
        closing = _call_end(masked, opening) if opening >= 0 else None
        if closing is None:
            continue
        body_open = masked.find("{", closing)
        if body_open < 0:
            continue
        body_close = _matching_delimiter(masked, body_open, "{", "}")
        if body_close is None:
            continue
        else_match = re.search(r"\belse\b", masked[body_close + 1:])
        else_span = None
        if else_match is not None:
            else_start = body_close + 1 + else_match.start()
            after_else = body_close + 1 + else_match.end()
            next_token = re.match(r"\s*(if\b|\{)", masked[after_else:])
            if next_token and next_token.group(1) == "if":
                continue
            else_open = masked.find("{", else_start)
            if else_open >= 0:
                else_close = _matching_delimiter(masked, else_open, "{", "}")
                if else_close is not None:
                    else_span = _Span(else_open, else_close + 1)
        regions.append((_Span(body_open, body_close + 1), else_span))
    return tuple(regions)


def _mutually_exclusive_branches(
    masked: str, first: int, second: int
) -> bool:
    for then_span, else_span in _if_branch_regions(masked):
        if else_span is None:
            continue
        if (
            then_span.contains(first) and else_span.contains(second)
        ) or (
            else_span.contains(first) and then_span.contains(second)
        ):
            return True
    return False


def _sync_context(
    masked: str,
    spans: Sequence[_Span],
    reset_position: int,
    use_position: int,
) -> str:
    for match in _LOCK_RE.finditer(masked):
        lock_span = _innermost_span(spans, match.start())
        if lock_span is None:
            continue
        if match.start() < reset_position and lock_span.contains(reset_position) and lock_span.contains(use_position):
            declaration_end = masked.find(";", match.end())
            declaration = masked[match.start():declaration_end]
            lock_name = re.escape(match.group("lock"))
            if (declaration_end < 0 or "defer_lock" in declaration
                    or "try_to_lock" in declaration
                    or re.search(rf"\b{lock_name}\s*\.\s*(?:unlock|release)\s*\(", masked[match.end():use_position])):
                return "lock_acquisition_or_retention_unknown"
            return "same_scoped_mutex_lock"
    return "no_same_scoped_mutex_lock_observed"


def _check_timeout(options: LifetimeAnalysisOptions) -> None:
    if options.timeout_check is not None and options.timeout_check():
        raise _CooperativeTimeout()


def _analyze_unit(
    unit: SourceUnit,
    options: LifetimeAnalysisOptions,
) -> Tuple[Tuple[DetectorFinding, ...], List[str], bool]:
    masked = _mask_comments_and_literals(unit.text)
    spans = _block_spans(masked)
    functions = _function_spans(masked)
    limitations: List[str] = []
    findings: List[DetectorFinding] = []
    analysis_complete = True
    function_spans = [span for _name, span in functions]

    owners: List[_OwnerShape] = []
    for match in _OWNER_DECL_RE.finditer(masked):
        function_scope = _innermost_span(function_spans, match.start())
        binding_scope = _innermost_span(spans, match.start())
        if function_scope is None or binding_scope is None:
            owners.append(
                _OwnerShape(
                    owner=match.group("owner"),
                    owner_type=match.group("type").strip(),
                    position=match.start(),
                    name_position=match.start("owner"),
                    declaration_span=_Span(match.start(), match.end()),
                    span=function_scope or _Span(0, len(masked)),
                    binding_scope=binding_scope,
                    binding_id="unresolved-owner",
                )
            )
            continue
        owners.append(
            _OwnerShape(
                owner=match.group("owner"),
                owner_type=match.group("type").strip(),
                position=match.start(),
                name_position=match.start("owner"),
                declaration_span=_Span(match.start(), match.end()),
                span=function_scope,
                binding_scope=binding_scope,
                binding_id=_binding_id(
                    "owner",
                    match.group("owner"),
                    match.start(),
                    function_scope,
                    binding_scope,
                ),
            )
        )

    pointer_bindings: List[_PointerBinding] = []
    for match in _POINTER_BINDING_RE.finditer(masked):
        function_scope = _innermost_span(function_spans, match.start())
        binding_scope = _innermost_span(spans, match.start())
        if function_scope is None or binding_scope is None:
            continue
        pointer_bindings.append(
            _PointerBinding(
                alias=match.group("alias"),
                position=match.start(),
                name_position=match.start("alias"),
                declaration_span=_Span(match.start(), match.end()),
                span=function_scope,
                binding_scope=binding_scope,
                binding_id=_binding_id(
                    "alias",
                    match.group("alias"),
                    match.start(),
                    function_scope,
                    binding_scope,
                ),
            )
        )

    aliases: List[_AliasShape] = []
    for match in _RAW_ALIAS_RE.finditer(masked):
        function_scope = _innermost_span(function_spans, match.start())
        binding_scope = _innermost_span(spans, match.start())
        binding = _resolve_binding(
            pointer_bindings, match.group("alias"), match.start("alias")
        )
        aliases.append(
            _AliasShape(
                alias=match.group("alias"),
                owner=match.group("owner"),
                position=match.start(),
                name_position=match.start("alias"),
                declaration_span=_Span(match.start(), match.end()),
                span=function_scope,
                binding_scope=binding_scope,
                binding_id=binding.binding_id if binding is not None else "unresolved-alias",
            )
        )

    for match in _ALIAS_ASSIGN_RE.finditer(masked):
        if not _is_plain_identifier_at(masked, match.start("alias")):
            continue
        function_scope = _innermost_span(function_spans, match.start())
        binding_scope = _innermost_span(spans, match.start())
        if function_scope is None or binding_scope is None:
            continue
        binding = _resolve_binding(
            pointer_bindings, match.group("alias"), match.start("alias")
        )
        aliases.append(
            _AliasShape(
                alias=match.group("alias"),
                owner=match.group("owner"),
                position=match.start(),
                name_position=match.start("alias"),
                declaration_span=_Span(match.start(), match.end()),
                span=function_scope,
                binding_scope=binding.binding_scope if binding is not None else binding_scope,
                binding_id=binding.binding_id if binding is not None else "unresolved-alias",
            )
        )

    for pattern in (_ALIAS_CHAIN_DECL_RE, _ALIAS_CHAIN_ASSIGN_RE):
        for match in pattern.finditer(masked):
            if (
                pattern is _ALIAS_CHAIN_ASSIGN_RE
                and not _is_plain_identifier_at(masked, match.start("alias"))
            ):
                continue
            function_scope = _innermost_span(function_spans, match.start())
            binding_scope = _innermost_span(spans, match.start())
            if function_scope is None or binding_scope is None:
                continue
            binding = _resolve_binding(
                pointer_bindings, match.group("alias"), match.start("alias")
            )
            source = next(
                (
                    item for item in aliases
                    if item.alias == match.group("source")
                    and item.position < match.start()
                    and item.span.contains(match.start())
                ),
                None,
            )
            if source is None:
                continue
            aliases.append(
                _AliasShape(
                    alias=match.group("alias"),
                    owner=source.owner if source is not None else "<unresolved>",
                    position=match.start(),
                    name_position=match.start("alias"),
                    declaration_span=_Span(match.start(), match.end()),
                    span=function_scope,
                    binding_scope=binding.binding_scope if binding is not None else binding_scope,
                    binding_id=binding.binding_id if binding is not None else "unresolved-alias",
                    source_alias=match.group("source"),
                )
            )

    member_raw_alias_seen = False
    for match in _MEMBER_RAW_ALIAS_RE.finditer(masked):
        member_raw_alias_seen = True
    if member_raw_alias_seen:
        limitations.append(
            "Member-access owner.get() storage is outside local declaration binding and "
            "may escape the modeled scope; those observations remain unknown."
        )
        analysis_complete = False

    resets = []
    for match in _RESET_RE.finditer(masked):
        if not _is_plain_identifier_at(masked, match.start("owner")):
            continue
        opening = match.end() - 1
        closing = _call_end(masked, opening)
        if closing is None:
            limitations.append("Unbalanced owner.reset() parentheses were left unanalyzed.")
            analysis_complete = False
            continue
        resets.append(
            _ResetShape(
                owner=match.group("owner"),
                position=match.start(),
                call_end=closing + 1,
                span=_innermost_span(function_spans, match.start()) or _Span(0, len(masked)),
                invalidation_kind="reset",
                description=f"'{match.group('owner')}.reset()' invalidated the unique_ptr-owned object",
                transfer_scope_end=None,
            )
        )

    for match in _OWNER_ASSIGN_RE.finditer(masked):
        owner_name = match.group("owner")
        if not _is_plain_identifier_at(masked, match.start("owner")):
            continue
        if any(owner.name_position == match.start("owner") for owner in owners):
            continue
        if _resolve_owner(owners, owner_name, match.start("owner")) is None:
            continue
        statement_end = masked.find(";", match.end())
        if statement_end < 0:
            limitations.append(
                f"Owner assignment '{owner_name}' had no modeled statement end and remains unknown."
            )
            analysis_complete = False
            continue
        resets.append(
            _ResetShape(
                owner=owner_name,
                position=match.start("owner"),
                call_end=statement_end + 1,
                span=_innermost_span(function_spans, match.start())
                or _Span(0, len(masked)),
                invalidation_kind="owner assignment",
                description=(
                    f"owner assignment to '{owner_name}' replaced or cleared the "
                    "unique_ptr-owned object"
                ),
                transfer_scope_end=None,
            )
        )

    for match in _MOVE_TRANSFER_RE.finditer(masked):
        owner_name = match.group("owner")
        if not _is_plain_identifier_at(masked, match.start("owner")):
            continue
        if _resolve_owner(owners, owner_name, match.start("owner")) is None:
            continue
        opening = masked.find("(", match.start())
        closing = _call_end(masked, opening) if opening >= 0 else None
        if closing is None:
            limitations.append(
                f"Move transfer from owner '{owner_name}' had unbalanced parentheses."
            )
            analysis_complete = False
            continue
        resets.append(
            _ResetShape(
                owner=owner_name,
                position=match.start("owner"),
                call_end=closing + 1,
                span=_innermost_span(function_spans, match.start())
                or _Span(0, len(masked)),
                invalidation_kind="move transfer",
                description=(
                    f"std::move transfer from owner '{owner_name}' changed ownership; "
                    "the raw alias remains live until the destination owner scope ends"
                ),
                transfer_scope_end=(
                    _innermost_span(spans, match.start("target")).end
                    if _innermost_span(spans, match.start("target")) is not None
                    else None
                ),
            )
        )

    alias_owner = {
        alias.position: _resolve_owner(owners, alias.owner, alias.name_position)
        for alias in aliases
    }
    alias_binding = {
        alias.position: _resolve_binding(
            pointer_bindings, alias.alias, alias.name_position
        )
        for alias in aliases
    }
    reset_owner = {
        reset.position: _resolve_owner(owners, reset.owner, reset.position)
        for reset in resets
    }
    unresolved_symbols = (
        any(
            alias_owner.get(alias.position) is None
            for alias in aliases
        )
        or any(
            alias_binding.get(alias.position) is None
            for alias in aliases
        )
        or any(
            reset_owner.get(reset.position) is None
            for reset in resets
        )
    )
    if unresolved_symbols:
        limitations.append(
            "Unresolved rule symbols prevented complete owner/alias binding; "
            "the observation remains unknown."
        )
        analysis_complete = False

    for owner in owners:
        _check_timeout(options)
        owner_aliases = [
            alias for alias in aliases
            if alias_owner.get(alias.position) == owner
        ]
        owner_resets = [
            reset for reset in resets
            if reset_owner.get(reset.position) == owner
        ]
        if not owner_aliases:
            continue
        for alias in owner_aliases:
            binding = alias_binding.get(alias.position)
            if binding is None or binding.binding_id != alias.binding_id:
                continue
            use_positions = _use_positions(masked, alias.alias)
            rebind_positions = []
            for rebind in _REBIND_RE.finditer(masked):
                if not _is_plain_identifier_at(masked, rebind.start("alias")):
                    continue
                if _resolve_binding(
                    pointer_bindings, alias.alias, rebind.start("alias")
                ) != binding:
                    continue
                if rebind.group("owner") is not None and _resolve_owner(
                    owners, owner.owner, rebind.start("owner")
                ) != owner:
                    continue
                if (
                    alias.binding_scope is not None
                    and alias.binding_scope.contains(rebind.start())
                    and alias.span.contains(rebind.start())
                ):
                    rebind_positions.append(rebind.start("alias"))
            escapes = _escape_positions(
                masked,
                alias.alias,
                binding,
                pointer_bindings,
                use_positions,
                rebind_positions,
            )
            modeled_transfer_spans = tuple(
                item.declaration_span
                for item in aliases
                if item.source_alias == alias.alias
            )
            escapes = tuple(
                item for item in escapes
                if not any(span.contains(item[0]) for span in modeled_transfer_spans)
            )
            if escapes:
                analysis_complete = False
                escaped_kinds = ",".join(sorted({kind for _position, kind in escapes}))
                limitations.append(
                    f"Raw alias '{alias.alias}' has modeled binding {binding.binding_id[:12]} "
                    f"but escapes/transfers through {escaped_kinds}; downstream lifetime "
                    "semantics remain unknown and are not treated as safe."
                )
            scope_end_resets = list(owner_resets)
            if (
                owner.binding_scope is not None
                and alias.binding_scope is not None
                and alias.binding_scope.end > owner.binding_scope.end
            ):
                scope_end_resets.append(
                    _ResetShape(
                        owner=owner.owner,
                        position=owner.binding_scope.end,
                        call_end=owner.binding_scope.end,
                        span=owner.span,
                        invalidation_kind="owner scope end",
                        description=(
                            f"owner scope end for '{owner.owner}' destroyed the "
                            "unique_ptr-owned object"
                        ),
                        transfer_scope_end=None,
                    )
                )
            for reset in scope_end_resets:
                if reset.position <= alias.position:
                    continue
                for use_position in use_positions:
                    if use_position <= reset.call_end or use_position <= alias.position:
                        continue
                    if (
                        reset.invalidation_kind == "move transfer"
                        and reset.transfer_scope_end is not None
                        and use_position <= reset.transfer_scope_end
                    ):
                        continue
                    if _resolve_binding(
                        pointer_bindings, alias.alias, use_position
                    ) != binding:
                        continue
                    if alias.binding_scope is None or owner.binding_scope is None:
                        continue
                    scope_boundary = reset.invalidation_kind == "owner scope end"
                    if not (
                        alias.binding_scope.contains(use_position)
                        and alias.span.contains(use_position)
                        and owner.span.contains(use_position)
                        and (
                            scope_boundary
                            or owner.binding_scope.contains(use_position)
                        )
                    ):
                        continue
                    if _mutually_exclusive_branches(
                        masked, reset.position, use_position
                    ):
                        limitations.append(
                            f"Raw alias '{alias.alias}' use and {reset.description} "
                            "occur in mutually exclusive narrow CFG branches; no "
                            "candidate was emitted for that path pair."
                        )
                        continue
                    rebound_matches = [
                        match
                        for match in _REBIND_RE.finditer(masked)
                        if match.start() > reset.call_end
                        and match.start() < use_position
                        and _is_plain_identifier_at(masked, match.start("alias"))
                        and _resolve_binding(
                            pointer_bindings, alias.alias, match.start("alias")
                        ) == binding
                        and (
                            match.group("owner") is None
                            or _resolve_owner(
                                owners, owner.owner, match.start("owner")
                            ) == owner
                        )
                        and alias.binding_scope is not None
                        and owner.binding_scope is not None
                        and alias.binding_scope.contains(match.start())
                        and owner.binding_scope.contains(match.start())
                    ]
                    rebound = bool(rebound_matches)
                    straight_line_rebound = rebound and not _CONTROL_BOUNDARY_RE.search(
                        masked[reset.call_end:use_position]
                    )
                    if straight_line_rebound and options.suppress_rebound_alias:
                        continue
                    _check_timeout(options)
                    line, column = _line_col(unit.text, use_position)
                    sync_context = (
                        _sync_context(masked, spans, reset.position, use_position)
                        if options.classify_sync_scope
                        else "not_classified"
                    )
                    constraints = (
                        "same_function_explicit_unique_ptr_owner",
                        "raw_alias_bound_with_owner_get",
                        f"owner_{reset.invalidation_kind}_precedes_alias_dereference",
                        (
                            "lexical_binding_identity="
                            f"owner-{owner.binding_id[:12]}:alias-{binding.binding_id[:12]}"
                        ),
                        f"function={_function_name_at(functions, alias.position)}",
                        f"sync_scope={sync_context}",
                    )
                    if escapes:
                        constraints += ("alias_escape_or_transfer_coverage_unknown",)
                    if rebound and not options.suppress_rebound_alias:
                        extra = "alias_rebinding_observed_but_not_suppressed_by_ablation"
                    elif rebound and not straight_line_rebound:
                        extra = (
                            "conditional_or_non_straight_line_alias_rebinding_"
                            "not_suppressed_without_cfg"
                        )
                    else:
                        extra = None
                    message = (
                        f"Candidate only: raw alias '{alias.alias}' is dereferenced after "
                        f"{reset.description} and "
                        f"without a later unconditional straight-line 'alias = owner.get()' "
                        f"rebinding; syntax evidence; "
                        f"sync_scope={sync_context}; not proof of UAF. "
                        f"Constraints: {', '.join(constraints)}."
                    )
                    if extra:
                        message += f" Constraint: {extra}."
                    findings.append(
                        DetectorFinding(
                            file=unit.path,
                            line=line,
                            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
                            message=message,
                            evidence_type="syntax",
                            column=column,
                            candidate_cwe="CWE-416",
                            symbol=alias.alias,
                            source_sha256=unit.sha256,
                        )
                    )
    if owners and any(owner.binding_scope is None for owner in owners):
        limitations.append(
            "Ownership syntax was observed outside a modeled block/function span and was not analyzed."
        )
        analysis_complete = False
    return _stable_unique(findings), limitations, analysis_complete


class LifetimeOwnershipGuardDetector:
    """M0-compatible narrow detector; v1 remains unfrozen."""

    detector_id = "ohscanner.cpp.lifetime"
    version = "0.4.0"
    supported_languages = ("cpp",)
    # Source path/text/hash/parse status and request provenance are mandatory
    # SourceUnit/ScanRequest fields. No synthetic shared-fact names are required.
    required_facts: Tuple[str, ...] = ()

    def __init__(self, options: Optional[LifetimeAnalysisOptions] = None) -> None:
        self.options = options or LifetimeAnalysisOptions()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        ordered_units = tuple(sorted({unit.path: unit for unit in units}.values(), key=lambda unit: unit.path))
        findings: List[DetectorFinding] = []
        analyzed_files: List[str] = []
        limitations = [
            "Detector Contract v1 remains unfrozen; this is a proposed implementation against the current M0 interface.",
            "Empty findings are not proof of safety and are never benchmark misses.",
            "Partial/failed/not_run parse coverage remains unknown and is never a benchmark miss.",
            "Sync scope classification is descriptive; a lock does not preserve destroyed-object lifetime.",
            "Dominating CFG paths, exception/early-return behavior, destructor timing, escaping aliases, and cross-function transfers are not modeled.",
            "Lock ordering, condition variables, callbacks, and concurrent alias publication are not modeled.",
        ]
        coverage_complete = True
        timed_out = False

        for unit in ordered_units:
            try:
                _check_timeout(self.options)
            except _CooperativeTimeout:
                timed_out = True
                limitations.append("Cooperative timeout stopped this detector run; remaining scope is unknown.")
                break
            if unit.parse_status != "complete":
                limitations.append(
                    f"{unit.path}: parse_status={unit.parse_status}; analysis remains unknown for this unit."
                )
                continue
            try:
                unit_findings, unit_limitations, unit_analysis_complete = _analyze_unit(unit, self.options)
            except _CooperativeTimeout:
                timed_out = True
                limitations.append("Cooperative timeout stopped this detector run; remaining scope is unknown.")
                break
            if not unit_analysis_complete:
                coverage_complete = False
            findings.extend(unit_findings)
            limitations.extend(f"{unit.path}: {item}" for item in unit_limitations)
            analyzed_files.append(unit.path)

        if timed_out:
            status = "failed"
        elif len(analyzed_files) != len(ordered_units) or not coverage_complete:
            status = "blocked"
        else:
            status = "completed"
        return DetectorRun(
            detector_id=self.detector_id,
            version=self.version,
            status=status,
            analyzed_files=tuple(sorted(analyzed_files)),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
