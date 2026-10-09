"""Narrow C++ lifetime candidate detector against the current M0 contract.

Scope: one explicit ownership shape and one synchronization classification.
The detector recognizes a same-function ``std::unique_ptr`` owner, a raw alias
obtained with ``owner.get()``, owner invalidation with ``reset()``, and a later
dereference of that raw alias before it is rebound from the owner. A scoped
mutex is recorded as a synchronization constraint, but never treated as proof
that the destroyed object remains alive.

Detector Contract v1 is not frozen. This implementation uses the M0 classes in
``src.ohscanner.contracts`` and produces only syntax-level candidate evidence.
"""

from __future__ import annotations

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
    r"\b(?:auto|[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)\s*\*+\s*"
    r"(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<owner>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*\)"
)
_RESET_RE = re.compile(r"\b(?P<owner>[A-Za-z_]\w*)\s*\.\s*reset\s*\(")
_REBIND_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<owner>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*\)"
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
    span: _Span


@dataclass(frozen=True)
class _AliasShape:
    alias: str
    owner: str
    position: int
    span: _Span


@dataclass(frozen=True)
class _ResetShape:
    owner: str
    position: int
    call_end: int
    span: _Span


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


def _use_positions(masked: str, alias: str) -> Tuple[int, ...]:
    escaped = re.escape(alias)
    patterns = (
        rf"\*\s*{escaped}\b",
        rf"\(\s*\*\s*{escaped}\s*\)",
        rf"\b{escaped}\s*->",
    )
    spans = sorted(
        (match.start(), match.end())
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
            return "same_scoped_mutex_lock"
    return "no_same_scoped_mutex_lock_observed"


def _check_timeout(options: LifetimeAnalysisOptions) -> None:
    if options.timeout_check is not None and options.timeout_check():
        raise _CooperativeTimeout()


def _analyze_unit(
    unit: SourceUnit,
    options: LifetimeAnalysisOptions,
) -> Tuple[Tuple[DetectorFinding, ...], List[str]]:
    masked = _mask_comments_and_literals(unit.text)
    spans = _block_spans(masked)
    functions = _function_spans(masked)
    limitations: List[str] = []
    findings: List[DetectorFinding] = []
    function_spans = [span for _name, span in functions]

    owners = [
        _OwnerShape(
            owner=match.group("owner"),
            owner_type=match.group("type").strip(),
            position=match.start(),
            span=_innermost_span(function_spans, match.start()) or _Span(0, len(masked)),
        )
        for match in _OWNER_DECL_RE.finditer(masked)
    ]
    aliases = [
        _AliasShape(
            alias=match.group("alias"),
            owner=match.group("owner"),
            position=match.start(),
            span=_innermost_span(function_spans, match.start()) or _Span(0, len(masked)),
        )
        for match in _RAW_ALIAS_RE.finditer(masked)
    ]
    resets = []
    for match in _RESET_RE.finditer(masked):
        opening = match.end() - 1
        closing = _call_end(masked, opening)
        if closing is None:
            limitations.append("Unbalanced owner.reset() parentheses were left unanalyzed.")
            continue
        resets.append(
            _ResetShape(
                owner=match.group("owner"),
                position=match.start(),
                call_end=closing + 1,
                span=_innermost_span(function_spans, match.start()) or _Span(0, len(masked)),
            )
        )

    for owner in owners:
        _check_timeout(options)
        owner_aliases = [
            alias for alias in aliases
            if alias.owner == owner.owner
            and alias.span.start == owner.span.start
            and alias.span.end == owner.span.end
        ]
        owner_resets = [
            reset for reset in resets
            if reset.owner == owner.owner
            and reset.span.start == owner.span.start
            and reset.span.end == owner.span.end
        ]
        if not owner_aliases or not owner_resets:
            continue
        for alias in owner_aliases:
            for reset in owner_resets:
                if reset.position <= alias.position:
                    continue
                for use_position in _use_positions(masked, alias.alias):
                    if use_position <= reset.call_end:
                        continue
                    if not (alias.span.contains(use_position) and owner.span.contains(use_position)):
                        continue
                    rebound_matches = [
                        match
                        for match in _REBIND_RE.finditer(masked)
                        if match.start() > reset.call_end
                        and match.start() < use_position
                        and match.group("alias") == alias.alias
                        and match.group("owner") == owner.owner
                    ]
                    rebound = bool(rebound_matches)
                    straight_line_rebound = rebound and not _CONTROL_BOUNDARY_RE.search(
                        masked, reset.call_end, use_position
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
                        "owner_reset_precedes_alias_dereference",
                        f"sync_scope={sync_context}",
                    )
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
                        f"'{owner.owner}.reset()' invalidated the unique_ptr-owned object and "
                        f"without a later unconditional straight-line 'alias = owner.get()' "
                        f"rebinding; syntax evidence; "
                        f"sync_scope={sync_context}; not proof of UAF."
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
                        )
                    )
    if owners and not functions:
        limitations.append(
            "Ownership syntax was observed outside a modeled function span and was not analyzed."
        )
    return _stable_unique(findings), limitations


class LifetimeOwnershipGuardDetector:
    """M0-compatible narrow detector; v1 remains unfrozen."""

    detector_id = "ohscanner.cpp.lifetime"
    version = "0.1.0-proposed"
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
                unit_findings, unit_limitations = _analyze_unit(unit, self.options)
            except _CooperativeTimeout:
                timed_out = True
                limitations.append("Cooperative timeout stopped this detector run; remaining scope is unknown.")
                break
            findings.extend(unit_findings)
            limitations.extend(f"{unit.path}: {item}" for item in unit_limitations)
            analyzed_files.append(unit.path)

        if timed_out:
            status = "failed"
        elif len(analyzed_files) != len(ordered_units):
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
