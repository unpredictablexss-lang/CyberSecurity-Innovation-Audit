"""A-RES-01 bounded C/C++ local resource lifetime candidate detector."""

from __future__ import annotations

import re
from dataclasses import dataclass
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
    balanced_end,
    call_argument_span,
    split_call_arguments,
    function_shapes,
    line_column,
    mask_comments_and_literals,
)
from .shared_state_lifetime_detector import detect_shared_state_candidates


RULE_DOUBLE_FREE = "ohcpp-resource-lifetime-double-free-candidate-001"
RULE_USE_AFTER_FREE = "ohcpp-resource-lifetime-use-after-free-candidate-002"
RULE_RECURSIVE_CLEANUP = "ohcpp-resource-exhaustion-recursive-cleanup-candidate-001"
RULE_CROSS_MEMBER_ALIAS_UAF = "ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003"
RULE_VERSION = "0.3.0"
RULE_LINEAGE_ID = "A-RES-01:ohcpp-resource-lifetime-candidate"

_ALLOC_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*(?:\([^;=]*?\)\s*)?(?P<alloc>(?:std\s*::\s*)?(?:malloc|calloc|realloc|new(?:\s*\[[^]]*\])?))\s*\("
)
_DECL_ALLOC_RE = re.compile(
    r"\b(?:auto|[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)\s*\*+\s*(?P<name>[A-Za-z_]\w*)\s*=\s*(?:\([^;=]*?\)\s*)?"
    r"(?P<alloc>(?:std\s*::\s*)?(?:malloc|calloc|realloc|new(?:\s*\[[^]]*\])?))\s*\("
)
_FREE_RE = re.compile(
    r"\b(?:free\s*\(\s*(?P<free_name>[A-Za-z_]\w*)\s*\)"
    r"|delete(?:\s*\[\s*\])?\s+(?P<delete_name>[A-Za-z_]\w*)\b)"
)
_ALIAS_RE = re.compile(
    r"\b(?P<target>[A-Za-z_]\w*)\s*=\s*(?P<source>[A-Za-z_]\w*)\s*;"
)
_NULL_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*(?:nullptr|NULL|0)\s*;")
_USE_PATTERNS = (
    re.compile(r"\*\s*(?P<name>[A-Za-z_]\w*)\b"),
    re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*->"),
    re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\["),
    re.compile(r"\b(?:memcpy|memmove|memset)\s*\([^;]*?\b(?P<name>[A-Za-z_]\w*)\b"),
)

_OBLIGATIONS = (
    EvidenceObligation(
        "allocation_release_alias_state",
        "Prove the exact allocation, alias, transfer and release state on every path.",
        "unknown",
    ),
    EvidenceObligation(
        "control_flow_dominance",
        "Prove the use or second release is reachable after the first release.",
        "unknown",
    ),
    EvidenceObligation(
        "cross_function_and_container_transfer",
        "Resolve calls, containers, fields, callbacks, move and ownership transfer.",
        "missing",
    ),
    EvidenceObligation(
        "entry_or_privilege_boundary",
        "Establish a realistic reachable entry and privilege boundary.",
        "missing",
    ),
    EvidenceObligation(
        "attacker_control",
        "Show attacker influence over the trigger or lifetime transition.",
        "missing",
    ),
    EvidenceObligation(
        "trigger_conditions",
        "Reproduce the exact lifetime failure in an isolated target.",
        "missing",
    ),
    EvidenceObligation(
        "cia_impact",
        "Establish concrete confidentiality, integrity or availability impact.",
        "missing",
    ),
)


@dataclass(frozen=True)
class _Event:
    position: int
    kind: str
    name: str
    detail: str = ""


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
) -> DetectorFinding:
    line, column = line_column(unit.text, position)
    cwe = "CWE-674" if rule_id == RULE_RECURSIVE_CLEANUP else ("CWE-415" if rule_id == RULE_DOUBLE_FREE else "CWE-416")
    return DetectorFinding(
        file=unit.path,
        line=line,
        column=column,
        rule_id=rule_id,
        message=message,
        evidence_type="syntax",
        candidate_cwe=cwe,
        symbol=symbol,
        evidence_obligations=_RECURSION_OBLIGATIONS if rule_id == RULE_RECURSIVE_CLEANUP else _OBLIGATIONS,
        consequence_impact="availability_exhaustion" if rule_id == RULE_RECURSIVE_CLEANUP else "memory_safety",
        consequence_cwe=cwe,
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
    )



_RECURSION_OBLIGATIONS = (
    EvidenceObligation("recursive_cleanup_cycle", "Verify callback registration and cleanup dispatch form a recursive cycle on the same graph.", "unknown"),
    EvidenceObligation("nesting_depth_control", "Establish whether externally constructible nested objects have an effective bound.", "unknown"),
    EvidenceObligation("attacker_control", "Establish control over nested resource structure.", "missing"),
    EvidenceObligation("entry_and_trigger", "Verify reachable entry invokes cleanup under relevant conditions.", "missing"),
    EvidenceObligation("availability_impact", "Reproduce resource exhaustion and process impact in isolation.", "missing"),
)
MAX_CROSS_MEMBER_FACTS = 50000
MAX_CROSS_MEMBER_PAIRS = 100000
_MEMBER_ALIAS_RE = re.compile(r"\b(?P<left>[A-Za-z_]\w*)\s*(?P<left_op>->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*=\s*(?P<right>[A-Za-z_]\w*)\s*(?P<right_op>->|\.)\s*(?P=field)\b")
_MEMBER_ACCESS_RE = re.compile(r"\b(?P<object>[A-Za-z_]\w*)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\b")
_DEALLOCATOR_SUFFIX_RE = re.compile(r"(?:free|release|destroy)$", re.IGNORECASE)
_CALL_NAME_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\(")
_MEMBER_FUNCTION_ASSIGN_RE = re.compile(r"(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*=\s*(?P<value>[^;]+);")
_NESTED_POINTER_ASSIGN_RE = re.compile(r"(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*=\s*(?:\([^;]*?\)\s*)?(?P<value>[A-Za-z_]\w*)\s*;")
_INDIRECT_MEMBER_CALL_RE = re.compile(r"\b(?P<object>[A-Za-z_]\w*)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*\(")
_DEPTH_LIMIT_RE = re.compile(r"\b(?:depth|level|nest(?:ing)?)\w*\s*(?:<=|<|>=|>)\s*(?:\d+|[A-Z_]\w*(?:MAX|LIMIT)\w*)\b|\b(?:\d+|[A-Z_]\w*(?:MAX|LIMIT)\w*)\s*(?:<=|<|>=|>)\s*(?:depth|level|nest(?:ing)?)\w*\b")

def _function_params(function) -> str:
    match = re.search(r"\b" + re.escape(function.name) + r"\s*\((.*?)\)\s*\{", function.text, re.S)
    return match.group(1) if match else ""

def _parameter_names(params: str) -> Tuple[str, ...]:
    names = []
    for part in params.split(","):
        identifiers = re.findall(r"[A-Za-z_]\w*", part)
        if identifiers and identifiers[-1] not in ("const", "volatile"):
            names.append(identifiers[-1])
    return tuple(names)

def _member_deallocations(unit: SourceUnit, masked: str):
    """Return member expressions passed to syntactically named deallocators.

    This deliberately recognizes only generic deallocator-name suffixes. It
    does not claim that arbitrary functions with these names actually release
    storage; that semantic obligation remains visible on every finding.
    """
    results = []
    for call in _CALL_NAME_RE.finditer(masked):
        name = call.group("name")
        if not _DEALLOCATOR_SUFFIX_RE.search(name):
            continue
        span = call_argument_span(masked, call.start())
        if span is None:
            continue
        for member in _MEMBER_ACCESS_RE.finditer(span[2]):
            results.append((name, member.group("object"), member.group("field"), span[0] + member.start()))
    return results


def _member_is_read(masked: str, match: re.Match, excluded_spans) -> bool:
    if any(start <= match.start() < end for start, end in excluded_spans):
        return False
    tail = masked[match.end():]
    next_char = re.search(r"\S", tail)
    if next_char is None:
        return False
    token = tail[next_char.start():]
    if token.startswith("=") and not token.startswith("=="):
        return False
    if token.startswith(("[", "->", ".")):
        return True
    return False


def _cross_member_alias_uaf(units: Sequence[SourceUnit]) -> Tuple[Tuple[DetectorFinding, ...], bool]:
    """Find a conservative cross-unit member-alias/release/use candidate.

    It supports partial C/C++ source, but intentionally proves only that a
    same-named member alias, a deallocator-shaped call, and a later-shaped
    member read occur in the selected source set. Object identity, invocation
    order, path feasibility, actual callee semantics and ownership remain
    unknown obligations.
    """
    masked_by_path = {
        unit.path: mask_comments_and_literals(unit.text)
        for unit in units
        if unit.language in ("c", "cpp") and unit.parse_status in ("complete", "partial")
    }
    deallocations = []
    deallocator_calls = {}
    for unit in units:
        masked = masked_by_path.get(unit.path)
        if masked is None:
            continue
        calls = []
        for call in _CALL_NAME_RE.finditer(masked):
            span = call_argument_span(masked, call.start())
            if span is not None:
                calls.append((call, span))
        deallocator_calls[unit.path] = calls
        for name, obj, field, position in _member_deallocations(unit, masked):
            deallocations.append((unit, name, obj, field, position))

    aliases = []
    for alias_unit in units:
        alias_masked = masked_by_path.get(alias_unit.path)
        if alias_masked is not None:
            aliases.extend((alias_unit, alias) for alias in _MEMBER_ALIAS_RE.finditer(alias_masked))
    uses_by_object_field = {}
    for use_unit in units:
        use_masked = masked_by_path.get(use_unit.path)
        if use_masked is None:
            continue
        excluded = tuple(
            (span[0], span[1])
            for call, span in deallocator_calls.get(use_unit.path, ())
            if _DEALLOCATOR_SUFFIX_RE.search(call.group("name"))
        )
        for use in _MEMBER_ACCESS_RE.finditer(use_masked):
            if _member_is_read(use_masked, use, excluded):
                uses_by_object_field.setdefault((use.group("object"), use.group("field")), []).append((use_unit, use.start()))
    fact_count = len(aliases) + len(deallocations) + sum(map(len, uses_by_object_field.values()))
    if fact_count > MAX_CROSS_MEMBER_FACTS:
        return (), True

    releases_by_field = {}
    for release in deallocations:
        releases_by_field.setdefault(release[3], []).append(release)
    findings = []
    seen = set()
    pair_count = 0
    for alias_unit, alias in aliases:
        left, right, field = alias.group("left"), alias.group("right"), alias.group("field")
        if left == right:
            continue
        for release_unit, release_name, released_object, _released_field, release_pos in releases_by_field.get(field, ()):
            if released_object not in (left, right):
                continue
            pair_count += 1
            if pair_count > MAX_CROSS_MEMBER_PAIRS:
                return _stable_unique(findings), True
            live_alias_object = right if released_object == left else left
            for use_unit, use_pos in uses_by_object_field.get((live_alias_object, field), ()):
                key = (alias_unit.path, alias.start(), release_unit.path, release_pos)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding(
                    use_unit,
                    use_pos,
                    RULE_CROSS_MEMBER_ALIAS_UAF,
                    f"{left}.{field}={right}.{field}",
                    "Candidate only (partial cross-unit lifetime evidence): member alias "
                    f"`{left}->{field} = {right}->{field}` at {alias_unit.path}:{line_column(alias_unit.text, alias.start())[0]}, "
                    f"deallocator-shaped call `{release_name}` receives `{released_object}->{field}` at "
                    f"{release_unit.path}:{line_column(release_unit.text, release_pos)[0]}, and the aliased "
                    f"member `{live_alias_object}->{field}` is read here. Call order, same-object identity, "
                    "callee release semantics, path feasibility, and ownership transfer remain unknown.",
                ))
    return _stable_unique(findings), False




def _recursive_cleanup_candidates(units: Sequence[SourceUnit]) -> Tuple[DetectorFinding, ...]:
    """Find callback-mediated recursive cleanup cycles over nested pointer data.

    The relation is intentionally limited to one translation unit: a callback
    must be stored in a member, a pointer parameter must be stored as nested
    member data, the callback must call into a cleanup chain, and that chain
    must dispatch the same callback member before reaching a release-shaped
    operation. This is still candidate evidence; it does not prove untrusted
    construction depth, runtime callback values, or stack exhaustion.
    """
    findings = []
    for unit in units:
        if unit.language not in ("c", "cpp") or unit.parse_status not in ("complete", "partial"):
            continue
        masked = mask_comments_and_literals(unit.text)
        functions = function_shapes(masked)
        if not functions:
            continue
        functions_by_name: Dict[str, List[int]] = {}
        for index, function in enumerate(functions):
            functions_by_name.setdefault(function.name, []).append(index)

        bodies = [masked[function.body_start:function.body_end] for function in functions]
        indirect_fields: List[Set[str]] = []
        for body in bodies:
            indirect_fields.append({m.group("field") for m in _INDIRECT_MEMBER_CALL_RE.finditer(body)})

        direct_edges: List[Set[int]] = [set() for _ in functions]
        call_sites: List[List[Tuple[re.Match, Tuple[int, int, str]]]] = [[] for _ in functions]
        for index, function in enumerate(functions):
            body = bodies[index]
            for call in _CALL_NAME_RE.finditer(body):
                span = call_argument_span(body, call.start())
                if span is None:
                    continue
                call_sites[index].append((call, span))
                for callee_index in functions_by_name.get(call.group("name"), ()):
                    direct_edges[index].add(callee_index)

        registrations = []
        for setter_index, function in enumerate(functions):
            body = bodies[setter_index]
            pointer_parameters = {
                name for name in _parameter_names(_function_params(function))
                if re.search(r"\*[^,)]*\b" + re.escape(name) + r"\b", _function_params(function))
            }
            if not pointer_parameters:
                continue
            member_assignments = tuple(_MEMBER_FUNCTION_ASSIGN_RE.finditer(body))
            for callback_assignment in member_assignments:
                field = callback_assignment.group("field")
                possible_callbacks = set(re.findall(r"\b[A-Za-z_]\w*\b", callback_assignment.group("value")))
                callbacks = possible_callbacks.intersection(functions_by_name)
                if not callbacks:
                    continue
                has_nested_pointer = False
                for nested in _NESTED_POINTER_ASSIGN_RE.finditer(body):
                    if nested.group("field") == field:
                        continue
                    rhs = nested.group("value")
                    if rhs in pointer_parameters and nested.start() < callback_assignment.start():
                        has_nested_pointer = True
                        break
                if not has_nested_pointer:
                    continue
                registrations.append((setter_index, field, callbacks, callback_assignment.start()))

        dispatch_reachable_cache: Dict[str, Tuple[Set[int], Set[int]]] = {}
        for setter_index, field, callbacks, assignment_pos in registrations:
            for callback in sorted(callbacks):
                callback_nodes = set(functions_by_name.get(callback, ()))
                if not callback_nodes:
                    continue
                # Add modeled indirect callback edges. A direct call to a helper
                # is removed when the caller clears this callback field on the
                # same argument before entering that helper (the fixed curl shape).
                edges = [set(children) for children in direct_edges]
                if field not in dispatch_reachable_cache:
                    dispatch_nodes = {
                        caller_index for caller_index in range(len(functions))
                        if field in indirect_fields[caller_index]
                    }
                    reverse_direct_edges: List[Set[int]] = [set() for _ in functions]
                    for caller_index, children in enumerate(direct_edges):
                        for child in children:
                            reverse_direct_edges[child].add(caller_index)
                    direct_dispatch_reachable = set(dispatch_nodes)
                    pending_direct = list(dispatch_nodes)
                    while pending_direct:
                        current = pending_direct.pop()
                        for caller_index in reverse_direct_edges[current]:
                            if caller_index not in direct_dispatch_reachable:
                                direct_dispatch_reachable.add(caller_index)
                                pending_direct.append(caller_index)
                    dispatch_reachable_cache[field] = (dispatch_nodes, direct_dispatch_reachable)
                dispatch_nodes, direct_dispatch_reachable = dispatch_reachable_cache[field]
                for caller_index in dispatch_nodes:
                    edges[caller_index].update(callback_nodes)

                for caller_index in range(len(functions)):
                    clear_positions = [
                        (m.group("object"), m.start())
                        for m in re.finditer(
                            r"\b(?P<object>[A-Za-z_]\w*(?:(?:->|\.)\s*[A-Za-z_]\w*)*)\s*(?:->|\.)\s*" + re.escape(field)
                            + r"\s*=\s*(?:NULL|nullptr|0)\s*;",
                            bodies[caller_index],
                        )
                    ]
                    if not clear_positions:
                        continue
                    for call, span in call_sites[caller_index]:
                        callee_nodes = functions_by_name.get(call.group("name"), ())
                        if not any(target in direct_dispatch_reachable for target in callee_nodes):
                            continue
                        if any(
                            position < call.start()
                            and re.search(re.escape(re.sub(r"\s+", "", obj)), re.sub(r"\s+", "", span[2]))
                            for obj, position in clear_positions
                        ):
                            edges[caller_index].difference_update(callee_nodes)

                reachable = set(callback_nodes)
                stack = list(callback_nodes)
                while stack:
                    node = stack.pop()
                    for child in edges[node]:
                        if child not in reachable:
                            reachable.add(child)
                            stack.append(child)
                has_callback_cycle = any(
                    node in reachable and any(child in callback_nodes for child in edges[node])
                    for node in dispatch_nodes
                )
                if not has_callback_cycle:
                    continue
                has_release = any(
                    node in direct_dispatch_reachable
                    and (
                        re.search(r"\b(?:delete\b|free|[A-Za-z_]\w*(?:free|release|destroy))\s*\(", bodies[node], re.I)
                        or re.search(r"\bdelete\s+", bodies[node])
                    )
                    for node in reachable
                )
                if not has_release:
                    continue
                relevant_nodes = reachable | {setter_index}
                if any(_DEPTH_LIMIT_RE.search(bodies[node]) for node in relevant_nodes):
                    continue
                findings.append(_finding(
                    unit,
                    functions[setter_index].body_start + assignment_pos,
                    RULE_RECURSIVE_CLEANUP,
                    f"member {field} callback {callback}",
                    "Recursive cleanup candidate: nested pointer data is stored alongside a cleanup callback; "
                    f"callback `{callback}` reaches cleanup/release code that dispatches member `{field}` back "
                    "into the callback cycle. No explicit depth bound was found in the modeled cycle. Actual "
                    "object graph, path feasibility, externally controllable nesting, stack limit, and impact "
                    "remain unknown.",
                ))
    return _stable_unique(findings)



def _contains_use(masked: str, position: int, name: str) -> Optional[Tuple[int, str]]:
    escaped = re.escape(name)
    patterns = (
        (re.compile(r"\*\s*" + escaped + r"\b"), "dereference"),
        (re.compile(r"\b" + escaped + r"\s*->"), "member_access"),
        (re.compile(r"\b" + escaped + r"\s*\["), "index_access"),
    re.compile(r"\b(?:memcpy|memmove|memset)\s*\([^;]*?\b(?P<name>[A-Za-z_]\w*)\b"),
    )
    matches = []
    for pattern, kind in patterns:
        match = pattern.search(masked, position)
        if match:
            matches.append((match.start(), kind))
    return min(matches) if matches else None


def _flow_segments(start: int, end: int, masked: str) -> Tuple[Tuple[int, int], ...]:
    boundaries = [start]
    pattern = re.compile(
        r"^\s*(?:if|else|for|while|switch|try|catch|do)\b"
        r"|\b(?:goto|return|break|continue)\b"
        r"|^[A-Za-z_]\w*\s*:",
        re.MULTILINE,
    )
    for match in pattern.finditer(masked, start, end):
        if match.start() > boundaries[-1]:
            boundaries.append(match.start())
    boundaries.append(end)
    return tuple((boundaries[i], boundaries[i + 1]) for i in range(len(boundaries) - 1) if boundaries[i] < boundaries[i + 1])


def _events(masked: str, start: int, end: int) -> Tuple[_Event, ...]:
    events: List[_Event] = []
    region = masked[start:end]
    offset = start
    for match in _ALLOC_RE.finditer(region):
        events.append(_Event(offset + match.start(), "alloc", match.group("name"), match.group("alloc")))
    for match in _DECL_ALLOC_RE.finditer(region):
        events.append(_Event(offset + match.start(), "alloc", match.group("name"), match.group("alloc")))
    for match in _FREE_RE.finditer(region):
        name = match.group("free_name") or match.group("delete_name")
        events.append(_Event(offset + match.start(), "release", name, match.group(0)))
    for match in _NULL_RE.finditer(region):
        events.append(_Event(offset + match.start(), "null", match.group("name")))
    for match in _ALIAS_RE.finditer(region):
        source = match.group("source")
        target = match.group("target")
        if source != target:
            events.append(_Event(offset + match.start(), "alias", target, source))
    for pattern in _USE_PATTERNS:
        for match in pattern.finditer(region):
            name = match.group("name")
            events.append(_Event(offset + match.start(), "use", name, match.group(0)))
    return tuple(sorted(set(events), key=lambda item: (item.position, item.kind, item.name)))


def _analyze_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool]:
    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    if unit.parse_status != "complete":
        return findings, [f"{unit.path}: parse_status={unit.parse_status}; resource lifetime remains unknown."], False
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return findings, [f"{unit.path}: source exceeds the 1MiB per-unit fail-closed budget."], False

    masked = mask_comments_and_literals(unit.text)
    functions = function_shapes(masked)
    for function in functions:
        states: Dict[str, str] = {}
        aliases: Dict[str, str] = {}
        reported_uaf: Set[str] = set()
        reported_double: Set[str] = set()
        for segment_start, segment_end in _flow_segments(
            function.body_start + 1, function.body_end - 1, masked
        ):
            states: Dict[str, str] = {}
            aliases: Dict[str, str] = {}
            for event in _events(masked, segment_start, segment_end):
                canonical = aliases.get(event.name, event.name)
                if event.kind == "alloc":
                    states[event.name] = "allocated"
                    aliases.pop(event.name, None)
                elif event.kind == "alias":
                    aliases[event.name] = event.detail
                    states[event.name] = states.get(event.detail, "unknown")
                elif event.kind == "null":
                    states[event.name] = "null"
                    aliases.pop(event.name, None)
                elif event.kind == "release":
                    state = states.get(canonical, "unknown")
                    if state == "freed" and canonical not in reported_double:
                        reported_double.add(canonical)
                        findings.append(_finding(
                            unit,
                            event.position,
                            RULE_DOUBLE_FREE,
                            canonical,
                            f"Candidate only: `{event.detail}` releases `{canonical}` again after a modeled release. "
                            "Aliases, ownership transfer and conditional paths remain unknown.",
                        ))
                    states[canonical] = "freed"
                elif event.kind == "use":
                    state = states.get(canonical, "unknown")
                    if state == "freed" and canonical not in reported_uaf:
                        reported_uaf.add(canonical)
                        findings.append(_finding(
                            unit,
                            event.position,
                            RULE_USE_AFTER_FREE,
                            canonical,
                            f"Candidate only: `{event.detail}` uses `{canonical}` after a modeled release. "
                            "Reallocation, alias recovery, destructor timing and path feasibility remain unknown.",
                        ))
        if any(value == "unknown" for value in states.values()):
            limitations.append(
                f"{unit.path}:{function.name}: unresolved allocation/release alias state remains unknown."
            )
    limitations.extend((
        "Candidate only: local lexical resource state does not prove UAF/double-free exploitability.",
        "Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.",
        "Absence of a finding is not a safe verdict; partial/failed source remains unknown.",
    ))
    return findings, limitations, True


class CppResourceLifetimeDetector:
    detector_id = "ohscanner.cpp.resource_lifetime"
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
        analyzed_files: List[str] = []
        complete = True
        shared_state_findings = detect_shared_state_candidates(ordered)
        findings.extend(shared_state_findings)
        shared_state_files = {finding.file for finding in shared_state_findings}
        for unit in ordered:
            unit_findings, unit_limitations, unit_complete = _analyze_unit(unit)
            recursive_findings = _recursive_cleanup_candidates((unit,))
            findings.extend(recursive_findings)
            if recursive_findings and unit.parse_status == "partial":
                analyzed_files.append(unit.path)
            if unit.path in shared_state_files and unit.parse_status == "partial":
                analyzed_files.append(unit.path)
            findings.extend(unit_findings)
            limitations.extend(unit_limitations)
            if unit_complete:
                analyzed_files.append(unit.path)
            else:
                complete = False
        cross_findings, cross_budget = _cross_member_alias_uaf(ordered)
        findings.extend(cross_findings)
        if cross_budget:
            complete = False
            limitations.append("Cross-member alias UAF candidate pair/fact budget exceeded; coverage remains unknown.")
        partial_syntax_files = {unit.path for unit in ordered if unit.parse_status == "partial"}
        if cross_findings:
            analyzed_files.extend(partial_syntax_files)
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if complete else "blocked",
            analyzed_files=tuple(sorted(set(analyzed_files))),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
