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
    FunctionShape,
    MAX_TOTAL_BYTES,
    MAX_UNIT_BYTES,
    balanced_end,
    function_shapes,
    line_column,
    mask_comments_and_literals,
)


RULE_DOUBLE_FREE = "ohcpp-resource-lifetime-double-free-candidate-001"
RULE_USE_AFTER_FREE = "ohcpp-resource-lifetime-use-after-free-candidate-002"
RULE_RECURSIVE_CLEANUP = "ohcpp-resource-lifetime-recursive-cleanup-candidate-003"
RULE_RECURSIVE_TREE_AMPLIFICATION = "ohcpp-resource-exhaustion-tree-amplification-candidate-004"
RULE_RECURSIVE_COMPARE_COST = "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005"
RULE_VERSION = "0.4.1"
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
    return DetectorFinding(
        file=unit.path,
        line=line,
        column=column,
        rule_id=rule_id,
        message=message,
        evidence_type="syntax",
        candidate_cwe="CWE-415" if rule_id == RULE_DOUBLE_FREE else "CWE-416",
        symbol=symbol,
        evidence_obligations=_OBLIGATIONS,
        consequence_impact="memory_safety",
        consequence_cwe="CWE-415" if rule_id == RULE_DOUBLE_FREE else "CWE-416",
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
    )


def _recursive_cleanup_finding(unit: SourceUnit, position: int, symbol: str) -> DetectorFinding:
    line, column = line_column(unit.text, position)
    return DetectorFinding(
        file=unit.path,
        line=line,
        column=column,
        rule_id=RULE_RECURSIVE_CLEANUP,
        message=(
            f"Candidate only: `{symbol}` reaches resource cleanup again through a registered callback cycle; "
            "attacker-controlled nesting and a safe recursion bound are not proven."
        ),
        evidence_type="syntax",
        candidate_cwe="CWE-674",
        symbol=symbol,
        evidence_obligations=(
            EvidenceObligation("callback_binding", "Bind the invoked callback to its concrete implementation.", "unknown"),
            EvidenceObligation("recursive_cleanup_path", "Prove the callback cycle is reachable for nested owned resources.", "unknown"),
            EvidenceObligation("input_depth_control", "Establish attacker control of nesting and absence of an effective bound.", "missing"),
            EvidenceObligation("entry_or_privilege_boundary", "Establish a realistic reachable entry and privilege boundary.", "missing"),
            EvidenceObligation("cia_impact", "Establish concrete availability impact in the target component.", "missing"),
        ),
        consequence_impact="availability",
        consequence_cwe="CWE-674",
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
    )


_DIRECT_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_CALLBACK_INVOKE_RE = re.compile(r"(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*\(")
_CALLBACK_ASSIGN_RE = re.compile(
    r"(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*=\s*(?P<target>[A-Za-z_]\w*)\b"
)
_DECORATED_FUNCTION_RE = re.compile(
    r"^\s*[A-Z_][A-Z0-9_]*\s*\([^()\n]*\)\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)\s*\{",
    re.MULTILINE,
)


def _named_function_shapes(masked: str) -> Tuple[FunctionShape, ...]:
    """Augment local function shapes for C APIs wrapped in export macros."""
    by_name: Dict[str, FunctionShape] = {}
    for function in function_shapes(masked):
        previous = by_name.get(function.name)
        if previous is None or len(function.text) > len(previous.text):
            by_name[function.name] = function
    for match in _DECORATED_FUNCTION_RE.finditer(masked):
        body_start = match.end() - 1
        body_end = balanced_end(masked, body_start)
        if body_end is None:
            continue
        name = match.group("name")
        start = max(0, masked.rfind("\n", 0, match.start()) + 1)
        function = FunctionShape(name, start, body_end, body_start, body_end, masked[start:body_end])
        previous = by_name.get(name)
        if previous is None or len(function.text) > len(previous.text):
            by_name[name] = function
    return tuple(sorted(by_name.values(), key=lambda item: (item.start, item.name)))


def _resource_exhaustion_finding(
    unit: SourceUnit, position: int, rule_id: str, cwe: str, symbol: str, root: str
) -> DetectorFinding:
    if rule_id == RULE_RECURSIVE_TREE_AMPLIFICATION:
        obligations = (
            EvidenceObligation("recursive_destructor_binding", "Bind cleanup to a recursive child-resource release implementation.", "unknown"),
            EvidenceObligation("tree_amplification", "Prove repeated input operations increase reachable tree size without a sufficient bound.", "unknown"),
            EvidenceObligation("attacker_control", "Establish attacker control over copy/patch contents and repetition count.", "missing"),
            EvidenceObligation("trigger_conditions", "Reproduce stack exhaustion in an isolated target.", "missing"),
        )
        message = f"Candidate only: `{symbol}` deep-copies and attaches tree data that can reach recursive cleanup in `{root}`. Repetition, depth limits, and input control remain unknown."
        impact = "availability_or_memory_safety"
    else:
        obligations = (
            EvidenceObligation("recursive_compare_shape", "Verify recursive comparison is reached from both directional sibling loops.", "unknown"),
            EvidenceObligation("lookup_cost", "Verify the per-element lookup helper is linear in sibling count.", "unknown"),
            EvidenceObligation("input_shape", "Establish attacker control over nested object width and depth.", "missing"),
            EvidenceObligation("trigger_conditions", "Measure the isolated comparison cost on a bounded input family.", "missing"),
        )
        message = f"Candidate only: `{symbol}` recursively compares both directions while each sibling loop performs a lookup; nested input may multiply the work. Cost growth and attacker control remain unknown."
        impact = "availability"
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
        evidence_obligations=obligations,
        consequence_impact=impact,
        consequence_cwe=cwe,
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
    )


def _loop_regions(body: str, offset: int) -> List[Tuple[str, str, int, int]]:
    """Return (iterator, sequence, start, end) for simple loops and ForEach macros."""
    regions: List[Tuple[str, str, int, int]] = []
    patterns = (
        re.compile(r"\b[A-Za-z_]\w*ForEach\s*\(\s*(?P<item>\w+)\s*,\s*(?P<seq>\w+)\s*\)\s*\{"),
        re.compile(r"\bfor\s*\(\s*[^;]*?\b(?P<item>\w+)\s*=\s*[^;]+;[^)]*\)\s*\{"),
    )
    for pattern in patterns:
        for match in pattern.finditer(body):
            brace = match.end() - 1
            end = balanced_end(body, brace)
            if end is None:
                continue
            sequence = match.groupdict().get("seq") or ""
            regions.append((match.group("item"), sequence, offset + brace, offset + end))
    return sorted(set(regions), key=lambda item: item[2])


def _recursive_compare_candidates(unit: SourceUnit, masked: str) -> List[DetectorFinding]:
    findings: List[DetectorFinding] = []
    functions = _named_function_shapes(masked)
    function_bodies = {
        function.name: masked[function.body_start:function.body_end]
        for function in functions
    }

    def is_visible_linear_sibling_lookup(name: str) -> bool:
        """Require a same-unit lookup implementation that visibly walks siblings."""
        lookup_body = function_bodies.get(name)
        if lookup_body is None:
            return False
        return bool(
            re.search(r"\b(?:while|for)\s*\(", lookup_body)
            and re.search(r"(?:->|\.)\s*next\b", lookup_body)
        ) or bool(re.search(r"\b[A-Za-z_]\w*ForEach\s*\(", lookup_body))

    for function in _named_function_shapes(masked):
        body = masked[function.body_start:function.body_end]
        loop_matches = _loop_regions(body, function.body_start)
        qualifying: List[Tuple[int, str, str]] = []
        for iterator, sequence, start, end in loop_matches:
            loop_body = masked[start:end]
            assignments: Dict[str, Set[str]] = {}
            assignment_re = re.compile(
                r"(?P<result>[A-Za-z_]\w*)\s*=\s*(?P<lookup>[A-Za-z_]\w*)\s*\((?P<args>[^;]*?)\)\s*;"
            )
            for assignment in assignment_re.finditer(loop_body):
                args = assignment.group("args")
                if re.search(rf"\b{re.escape(iterator)}\s*(?:->|\.)\s*[A-Za-z_]\w*", args):
                    lookup = assignment.group("lookup")
                    if is_visible_linear_sibling_lookup(lookup):
                        assignments.setdefault(assignment.group("result"), set()).add(lookup)
            for call in re.finditer(rf"\b{re.escape(function.name)}\s*\((?P<args>[^;]*)\)", loop_body):
                args = call.group("args")
                for result, helpers in assignments.items():
                    if re.search(rf"\b{re.escape(iterator)}\b", args) and re.search(rf"\b{re.escape(result)}\b", args):
                        qualifying.append((start + call.start(), iterator, sequence or next(iter(helpers))))
                        break
        if len({item[1] for item in qualifying}) < 2 or len(qualifying) < 2:
            continue
        # Require the two loops to compare distinct sibling sequences and use
        # helper lookups, avoiding a generic-recursion warning.
        if len({item[2] for item in qualifying}) < 2:
            continue
        position = min(item[0] for item in qualifying)
        findings.append(_resource_exhaustion_finding(
            unit, position, RULE_RECURSIVE_COMPARE_COST, "CWE-407", function.name, "the compared structure"
        ))
    return _stable_unique(findings)


def _recursive_destructors(units: Sequence[SourceUnit]) -> Set[str]:
    result: Set[str] = set()
    for unit in units:
        if unit.language not in ("c", "cpp"):
            continue
        masked = mask_comments_and_literals(unit.text)
        for function in _named_function_shapes(masked):
            body = masked[function.body_start:function.body_end]
            child_recursion = bool(
                re.search(rf"\b{re.escape(function.name)}\s*\([^;]*?(?:->|\.)\s*child\b", body)
            )
            # A recursive function named `*_delete` is not itself evidence of
            # a release sink. Require a distinct free/release/deallocator call
            # or the C++ delete operator. This still recognizes custom allocator
            # members such as `global_hooks.deallocate(...)`.
            release_calls = re.finditer(
                r"\b(?P<callee>(?:[A-Za-z_]\w*(?:free|destroy|release|dealloc(?:ate)?)|"
                r"free|destroy|release|dealloc(?:ate)?))\s*\(",
                body,
                re.IGNORECASE,
            )
            releases = any(
                match.group("callee").casefold() != function.name.casefold()
                for match in release_calls
            ) or bool(re.search(r"\bdelete\b", body))
            if child_recursion and releases:
                result.add(function.name)
    return result


def _while_regions(body: str) -> List[Tuple[str, int, int]]:
    result: List[Tuple[str, int, int]] = []
    pattern = re.compile(r"\bwhile\s*\(\s*(?P<item>[A-Za-z_]\w*)\s*(?:!=|)\s*(?:NULL|nullptr|0)\s*\)\s*\{")
    for match in pattern.finditer(body):
        brace = match.end() - 1
        end = balanced_end(body, brace)
        if end is not None:
            result.append((match.group("item"), brace, end))
    return result


def _tree_amplification_candidates(units: Sequence[SourceUnit]) -> List[DetectorFinding]:
    recursive_destructors = _recursive_destructors(units)
    if not recursive_destructors:
        return []
    functions_by_unit: Dict[str, Tuple[FunctionShape, ...]] = {}
    for unit in units:
        if unit.language in ("c", "cpp"):
            functions_by_unit[unit.path] = _named_function_shapes(mask_comments_and_literals(unit.text))
    repeated_mutators: Set[str] = set()
    for unit in units:
        masked = mask_comments_and_literals(unit.text)
        for function in functions_by_unit.get(unit.path, ()):
            body = masked[function.body_start:function.body_end]
            for item, start, end in _while_regions(body):
                loop = body[start:end]
                if not re.search(rf"\b{re.escape(item)}\s*=\s*{re.escape(item)}\s*(?:->|\.)\s*next\b", loop):
                    continue
                for call in re.finditer(r"\b([A-Za-z_]\w*)\s*\([^;]*\)", loop):
                    repeated_mutators.add(call.group(1))
    if not repeated_mutators:
        return []

    findings: List[DetectorFinding] = []
    for unit in units:
        if unit.language not in ("c", "cpp") or unit.parse_status != "complete":
            continue
        masked = mask_comments_and_literals(unit.text)
        for function in functions_by_unit.get(unit.path, ()):
            if function.name not in repeated_mutators:
                continue
            body = masked[function.body_start:function.body_end]
            copy_assignments = list(re.finditer(
                r"(?P<value>[A-Za-z_]\w*)\s*=\s*(?P<copy>[A-Za-z_]\w*)\s*\((?P<args>[^;]*,\s*(?:1|true)\s*)\)\s*;",
                body,
                re.IGNORECASE,
            ))
            if not copy_assignments:
                continue
            for copied in copy_assignments:
                value = copied.group("value")
                attached = re.search(
                    rf"\b\w*(?:add|insert|append|attach|adopt|splice)\w*\s*\([^;]*\b{re.escape(value)}\b[^;]*\)",
                    body,
                    re.IGNORECASE,
                )
                released = any(re.search(rf"\b{re.escape(name)}\s*\(\s*{re.escape(value)}\b", body) for name in recursive_destructors)
                if attached is None or not released:
                    continue
                if re.search(r"\b(?:max|maximum|limit|budget|node_count|depth)\b[^;{}]*(?:>|>=|==)", body, re.IGNORECASE):
                    continue
                findings.append(_resource_exhaustion_finding(
                    unit,
                    function.body_start + copied.start(),
                    RULE_RECURSIVE_TREE_AMPLIFICATION,
                    "CWE-674",
                    function.name,
                    ", ".join(sorted(recursive_destructors)),
                ))
                break
    return _stable_unique(findings)


def _recursive_cleanup_candidates(
    unit: SourceUnit, masked: str, functions: Sequence[object]
) -> List[DetectorFinding]:
    """Find same-translation-unit callback cycles that return to resource cleanup.

    This is a bounded may-call model: it only emits when a callback is assigned to
    a member function pointer, that callback can call a resource releaser, and a
    releaser-containing function can reach the callback invocation site. A visible
    reset or depth guard in the releaser suppresses the candidate.
    """
    by_name: Dict[str, object] = {}
    for function in functions:
        name = getattr(function, "name")
        previous = by_name.get(name)
        # C files commonly have a full implementation and a conditional stub
        # with the same name. Analyze the largest body conservatively.
        if previous is None or len(getattr(function, "text")) > len(getattr(previous, "text")):
            by_name[name] = function
    direct: Dict[str, Set[str]] = {name: set() for name in by_name}
    callback_fields: Dict[str, Set[str]] = {name: set() for name in by_name}
    registered: Dict[str, Set[str]] = {}
    for name, function in by_name.items():
        body = masked[function.body_start:function.body_end]
        direct[name].update(match.group(1) for match in _DIRECT_CALL_RE.finditer(body) if match.group(1) in by_name)
        callback_fields[name].update(match.group("field") for match in _CALLBACK_INVOKE_RE.finditer(body))
        for match in _CALLBACK_ASSIGN_RE.finditer(body):
            if match.group("target") in by_name:
                registered.setdefault(match.group("field"), set()).add(match.group("target"))

    calls = {name: set(targets) for name, targets in direct.items()}
    for name, fields in callback_fields.items():
        for field in fields:
            calls[name].update(registered.get(field, ()))

    def reachable(start: str) -> Set[str]:
        reached: Set[str] = set()
        pending = [start]
        while pending:
            current = pending.pop()
            if current in reached:
                continue
            reached.add(current)
            pending.extend(calls.get(current, ()) - reached)
        return reached

    findings: List[DetectorFinding] = []
    for field, callbacks in registered.items():
        invokers = {name for name, fields in callback_fields.items() if field in fields}
        if not invokers:
            continue
        for callback in callbacks:
            for releaser, function in by_name.items():
                body = masked[function.body_start:function.body_end]
                releases_resource = bool(re.search(r"\b(?:free|[A-Za-z_]\w*(?:free|destroy|release))\s*\(|\bdelete\b", body, re.IGNORECASE))
                iterates_children = bool(re.search(r"\b(?:while|for)\s*\(", body))
                if not releases_resource or not iterates_children or callback not in reachable(releaser):
                    continue
                releaser_reach = reachable(releaser)
                relevant_invokers = invokers & releaser_reach
                if not relevant_invokers:
                    continue
                if re.search(r"\b(?:depth|level|recursion|nesting)\b", body, re.IGNORECASE) and re.search(
                    r"(?:>|>=|==)\s*(?:\d+|[A-Z_]\w*)|(?:\d+|[A-Z_]\w*)\s*(?:<|<=)\s*\w*(?:depth|level|recursion|nesting)",
                    body,
                    re.IGNORECASE,
                ):
                    continue
                # Locate the first direct call that reaches the callback invocation.
                region = masked[function.body_start:function.body_end]
                call_positions = []
                for callee in direct[releaser] & relevant_invokers:
                    call = re.search(rf"\b{re.escape(callee)}\s*\(", region)
                    if call:
                        call_positions.append((call.start(), callee))
                if not call_positions:
                    # The invoking helper may be one or more direct calls away.
                    for callee in direct[releaser] & releaser_reach:
                        call = re.search(rf"\b{re.escape(callee)}\s*\(", region)
                        if call and (reachable(callee) & relevant_invokers):
                            call_positions.append((call.start(), callee))
                if not call_positions:
                    continue
                call_position = min(call_positions)[0]
                # A callback reset before the cleanup call is a meaningful local
                # guard (including iterative teardown implementations).
                reset = re.search(rf"(?:->|\.)\s*{re.escape(field)}\s*=\s*(?:NULL|nullptr|0)\b", region)
                if reset and reset.start() < call_position:
                    continue
                findings.append(_recursive_cleanup_finding(unit, function.body_start + call_position, releaser))
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
        if len(unit.text.encode("utf-8")) <= MAX_UNIT_BYTES:
            findings.extend(_recursive_compare_candidates(unit, mask_comments_and_literals(unit.text)))
        return findings, [f"{unit.path}: parse_status={unit.parse_status}; only bounded local complexity patterns are retained, semantic coverage remains unknown."], False
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return findings, [f"{unit.path}: source exceeds the 1MiB per-unit fail-closed budget."], False

    masked = mask_comments_and_literals(unit.text)
    functions = function_shapes(masked)
    findings.extend(_recursive_cleanup_candidates(unit, masked, functions))
    findings.extend(_recursive_compare_candidates(unit, masked))
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
        for unit in ordered:
            unit_findings, unit_limitations, unit_complete = _analyze_unit(unit)
            findings.extend(unit_findings)
            limitations.extend(unit_limitations)
            if unit_complete:
                analyzed_files.append(unit.path)
            else:
                complete = False
                # Partial translation units may still yield explicitly bounded
                # local candidates. Record them as inspected so the runner can
                # retain those candidates while keeping the run blocked.
                if unit.parse_status == "partial":
                    analyzed_files.append(unit.path)
        findings.extend(_tree_amplification_candidates(ordered))
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if complete else "blocked",
            analyzed_files=tuple(sorted(analyzed_files)),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
