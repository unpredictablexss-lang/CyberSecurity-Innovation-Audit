"""Narrow C++ lifetime candidate detector (proposed local implementation).

Scope: one explicit ownership shape and one synchronization classification.

The detector recognizes a same-function explicit ``std::unique_ptr`` owner, a
raw alias obtained with ``owner.get()``, owner invalidation with ``reset()``,
and a later dereference of that raw alias before it is rebound from the owner.
A scoped mutex is recorded as a synchronization constraint, but never treated
as proof that the destroyed object remains alive.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .proposed_contract import (
    ProposedCoverage,
    ProposedDiagnostic,
    ProposedDetectorRun,
    ProposedScanContext,
    ProposedSourceUnit,
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
class _UseShape:
    alias: str
    position: int
    span: _Span


@dataclass(frozen=True)
class LifetimeAnalysisOptions:
    """Ablation switches used by the research slice and deterministic tests."""

    suppress_rebound_alias: bool = True
    classify_sync_scope: bool = True


def _mask_comments_and_literals(text: str) -> str:
    """Replace comments/literal contents with spaces while preserving offsets."""

    chars = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(chars):
        pair = text[index : index + 2]
        char = chars[index]
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


def _call_arguments(masked: str, opening_paren: int, closing_paren: int) -> str:
    return masked[opening_paren + 1 : closing_paren].strip()


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
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(start for start, _end in merged)


def _stable_unique(diagnoses: Iterable[ProposedDiagnostic]) -> Tuple[ProposedDiagnostic, ...]:
    unique: Dict[str, ProposedDiagnostic] = {}
    for diagnosis in diagnoses:
        unique.setdefault(diagnosis.diagnostic_id, diagnosis)
    return tuple(sorted(unique.values(), key=lambda item: item.sort_key()))


def _validate_request(context: ProposedScanContext) -> List[str]:
    request = context.request
    errors: List[str] = []
    for field_name in ("request_id", "target_id", "repository", "profile_id"):
        if not getattr(request, field_name).strip():
            errors.append(f"request.{field_name} must not be empty")
    if not re.fullmatch(r"[0-9a-f]{40}", request.commit):
        errors.append("request.commit must be a full lowercase 40-character SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", request.snapshot_sha256):
        errors.append("request.snapshot_sha256 must be a lowercase SHA-256")
    return errors


def _validate_source_unit(unit: ProposedSourceUnit) -> Optional[str]:
    normalized = unit.path.replace("\\", "/")
    pure_path = PurePosixPath(normalized)
    if pure_path.is_absolute() or normalized.startswith("/"):
        return "source path must be repository-relative"
    if re.match(r"^[A-Za-z]:", normalized):
        return "source path must not use a drive prefix"
    if ".." in pure_path.parts or pure_path.as_posix() != normalized:
        return "source path must be normalized and must not escape the repository"
    if unit.language != "cpp":
        return "only language_mode=cpp is in scope"
    actual_hash = hashlib.sha256(unit.text.encode("utf-8")).hexdigest()
    if actual_hash != unit.sha256:
        return "source unit sha256 does not match text"
    return None


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


def _analyze_unit(
    context: ProposedScanContext,
    unit: ProposedSourceUnit,
    options: LifetimeAnalysisOptions,
) -> Tuple[Tuple[ProposedDiagnostic, ...], List[str]]:
    masked = _mask_comments_and_literals(unit.text)
    spans = _block_spans(masked)
    functions = _function_spans(masked)
    limitations: List[str] = []
    diagnoses: List[ProposedDiagnostic] = []

    owners = [
        _OwnerShape(
            owner=match.group("owner"),
            owner_type=match.group("type").strip(),
            position=match.start(),
            span=_innermost_span(functions and [span for _, span in functions] or [], match.start())  # type: ignore[arg-type]
            or _Span(0, len(masked)),
        )
        for match in _OWNER_DECL_RE.finditer(masked)
    ]
    aliases = [
        _AliasShape(
            alias=match.group("alias"),
            owner=match.group("owner"),
            position=match.start(),
            span=_innermost_span([span for _, span in functions], match.start())  # type: ignore[arg-type]
            or _Span(0, len(masked)),
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
                span=_innermost_span([span for _, span in functions], match.start())  # type: ignore[arg-type]
                or _Span(0, len(masked)),
            )
        )
    for owner in owners:
        owner_aliases = [
            alias
            for alias in aliases
            if alias.owner == owner.owner and alias.span.start == owner.span.start and alias.span.end == owner.span.end
        ]
        owner_resets = [
            reset
            for reset in resets
            if reset.owner == owner.owner and reset.span.start == owner.span.start and reset.span.end == owner.span.end
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
                    rebound = any(
                        match.start() > reset.call_end
                        and match.start() < use_position
                        and match.group("alias") == alias.alias
                        and match.group("owner") == owner.owner
                        for match in _REBIND_RE.finditer(masked)
                    )
                    if rebound and options.suppress_rebound_alias:
                        continue
                    line, column = _line_col(unit.text, use_position)
                    if options.classify_sync_scope:
                        sync_context = _sync_context(masked, spans, reset.position, use_position)
                    else:
                        sync_context = "not_classified"
                    diagnosis_id = hashlib.sha256(
                        "|".join(
                            (
                                context.request.repository,
                                context.request.commit,
                                context.request.profile_id,
                                unit.path,
                                owner.owner,
                                alias.alias,
                                "lifetime_unique_ptr_raw_alias",
                                f"{line}:{column}",
                                unit.sha256,
                            )
                        ).encode("utf-8")
                    ).hexdigest()[:16]
                    constraints = [
                        "same_function_explicit_unique_ptr_owner",
                        "raw_alias_bound_with_owner_get",
                        "owner_reset_precedes_alias_dereference",
                        f"sync_scope={sync_context}",
                    ]
                    if rebound:
                        constraints.append("alias_rebinding_observed_but_not_suppressed_by_ablation")
                    diagnoses.append(
                        ProposedDiagnostic(
                            diagnostic_id=f"ohcpp-lifetime-{diagnosis_id}",
                            provider="ohscanner.cpp.lifetime",
                            evidence_type="syntax",
                            file=unit.path,
                            line=line,
                            column=column,
                            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
                            severity="unassessed",
                            message=(
                                f"Candidate: raw alias '{alias.alias}' is dereferenced after "
                                f"'{owner.owner}.reset()' invalidated the explicit unique_ptr owner."
                            ),
                            candidate_cwe="CWE-416",
                            confidence="unassessed",
                            symbol=alias.alias,
                            explanation=(
                                "Within one modeled function, the raw alias was obtained from "
                                f"'{owner.owner}.get()', the owner was reset, and the same alias was "
                                "dereferenced before a new owner.get() binding. This is syntax-level "
                                "candidate evidence and not a vulnerability verdict."
                            ),
                            source_sha256=unit.sha256,
                            limitations=(
                                "Same-function syntax slice only; no whole-program CFG, exception-path, or dataflow proof.",
                                "Mutex scope is descriptive and does not preserve the lifetime of a destroyed object.",
                                "Macros, lambdas, containers, smart-pointer conversion, escaping aliases, and cross-function transfers are out of scope.",
                            ),
                            constraints=tuple(constraints),
                            missing_obligations=(
                                "Prove object liveness on every reachable path from reset() to dereference.",
                                "Prove all alias publications, destruction order, and cross-thread visibility.",
                                "Validate security impact and runtime behavior through a separate review process.",
                            ),
                        )
                    )

    if owners and not functions:
        limitations.append("Ownership syntax was observed outside a modeled function span and was not analyzed.")
    return _stable_unique(diagnoses), limitations


class LifetimeOwnershipGuardDetector:
    """Proposed detector entry point; not a frozen OHScanner Detector API."""

    detector_id = "ohscanner.cpp.lifetime"
    version = "0.1.0-proposed"
    supported_languages = ("cpp",)
    required_facts = (
        "repository_commit_profile_provenance",
        "source_path",
        "source_text",
        "source_sha256",
        "parse_status",
    )

    def __init__(self, options: Optional[LifetimeAnalysisOptions] = None) -> None:
        self.options = options or LifetimeAnalysisOptions()

    def detect(
        self,
        context: ProposedScanContext,
        units: Sequence[ProposedSourceUnit],
    ) -> ProposedDetectorRun:
        started = time.perf_counter()
        request_errors = _validate_request(context)
        ordered_units = sorted(units, key=lambda unit: unit.path)
        diagnoses: List[ProposedDiagnostic] = []
        coverage: List[ProposedCoverage] = []
        analyzed_files: List[str] = []
        limitations = [
            "Detector Contract v1 remains proposed; this is a detector-local implementation.",
            "No diagnostics is not proof of safety and is never a benchmark miss.",
        ]
        limitations.extend(request_errors)
        input_failed = bool(request_errors)

        for unit in ordered_units:
            if request_errors:
                coverage.append(
                    ProposedCoverage(
                        file=unit.path,
                        parse_status=unit.parse_status,
                        parse_issues=tuple(unit.parse_issues) + tuple(request_errors),
                        analyzed=False,
                    )
                )
                continue
            source_error = _validate_source_unit(unit)
            if source_error:
                input_failed = True
                coverage.append(
                    ProposedCoverage(
                        file=unit.path,
                        parse_status="failed",
                        parse_issues=(source_error,),
                        analyzed=False,
                    )
                )
                limitations.append(f"{unit.path}: {source_error}")
                continue
            if unit.parse_status != "complete":
                coverage.append(
                    ProposedCoverage(
                        file=unit.path,
                        parse_status=unit.parse_status,
                        parse_issues=unit.parse_issues,
                        analyzed=False,
                    )
                )
                limitations.append(
                    f"{unit.path}: parse_status={unit.parse_status}; analysis remains unknown for this unit."
                )
                continue
            unit_diagnoses, unit_limitations = _analyze_unit(context, unit, self.options)
            diagnoses.extend(unit_diagnoses)
            limitations.extend(f"{unit.path}: {item}" for item in unit_limitations)
            analyzed_files.append(unit.path)
            coverage.append(
                ProposedCoverage(
                    file=unit.path,
                    parse_status="complete",
                    parse_issues=unit.parse_issues,
                    analyzed=True,
                )
            )

        if not analyzed_files:
            limitations.append(
                "No complete source unit was analyzed; empty diagnostics must remain unknown, not safe."
            )
        scope_loc = sum(max(1, len(unit.text.splitlines())) for unit in ordered_units)
        return ProposedDetectorRun(
            detector_id=self.detector_id,
            version=self.version,
            status="failed" if input_failed else "completed",
            diagnostics=_stable_unique(diagnoses),
            analyzed_files=tuple(sorted(analyzed_files)),
            coverage=tuple(sorted(coverage, key=lambda item: item.file)),
            limitations=tuple(sorted(set(limitations))),
            elapsed_seconds=max(0.0, time.perf_counter() - started),
            scope_files=len(ordered_units),
            scope_loc=scope_loc,
            failure_kind="input_validation" if input_failed else None,
            missing_obligations=(
                "Dominating CFG paths and exception/early-return behavior are not computed.",
                "Object liveness, destructor timing, escaping aliases, and cross-function ownership transfer are not proved.",
                "Lock ordering, condition variables, callbacks, and concurrent alias publication are not modeled.",
            ),
        )
