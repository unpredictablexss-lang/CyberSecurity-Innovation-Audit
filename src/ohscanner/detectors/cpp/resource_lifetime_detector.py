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
    call_argument_span,
    function_shapes,
    line_column,
    mask_comments_and_literals,
)


RULE_DOUBLE_FREE = "ohcpp-resource-lifetime-double-free-candidate-001"
RULE_USE_AFTER_FREE = "ohcpp-resource-lifetime-use-after-free-candidate-002"
RULE_RECURSIVE_CLEANUP = "ohcpp-resource-lifetime-recursive-cleanup-candidate-003"
RULE_RECURSIVE_TREE_AMPLIFICATION = "ohcpp-resource-exhaustion-tree-amplification-candidate-004"
RULE_RECURSIVE_COMPARE_COST = "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005"
RULE_VERSION = "0.4.2"
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
                # Keep the source location tied to a duplicate that can fall
                # through from its own lexical branch to the later attach.
                # This is intentionally a bounded block check, not a CFG:
                # parser output gives us balanced function/block spans, but
                # does not prove arbitrary branch feasibility or dominance.
                branch_end = _innermost_block_end(body, copied.start())
                if branch_end is None or _has_direct_cleanup_exit(body, copied.end(), branch_end):
                    continue
                attach_start = copied.end() if branch_end == len(body) else branch_end
                attached = re.search(
                    rf"\b\w*(?:add|insert|append|attach|adopt|splice)\w*\s*\([^;]*\b{re.escape(value)}\b[^;]*\)",
                    body[attach_start:],
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
    return _stable_unique(findings)


def _innermost_block_end(body: str, position: int) -> Optional[int]:
    """Return the close of the innermost balanced block containing position."""
    stack: List[int] = []
    containing: List[Tuple[int, int]] = []
    for index, char in enumerate(body):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            start = stack.pop()
            if start != 0 and start < position < index:
                containing.append((start, index))
    return max(containing, key=lambda pair: pair[0])[1] if containing else len(body)


def _has_direct_cleanup_exit(body: str, start: int, end: int) -> bool:
    """Detect a cleanup goto at the selected block's direct brace depth."""
    depth = 0
    segment = body[start:end]
    for match in re.finditer(r"[{}]|\bgoto\s+cleanup\s*;", segment):
        token = match.group(0)
        if token == "{":
            depth += 1
        elif token == "}":
            depth = max(0, depth - 1)
        elif depth == 0:
            return True
    return False


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


RULE_CROSS_MEMBER_ALIAS_UAF = "ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003"

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


def _partial_recursive_cleanup_candidates(units: Sequence[SourceUnit]) -> Tuple[DetectorFinding, ...]:
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
            if unit.parse_status == "partial":
                partial_findings = _partial_recursive_cleanup_candidates((unit,))
                findings.extend(partial_findings)
                if partial_findings:
                    analyzed_files.append(unit.path)
            limitations.extend(unit_limitations)
            if unit_complete:
                analyzed_files.append(unit.path)
            else:
                complete = False
                # Partial translation units may still yield explicitly bounded
                # local candidates. Record them as inspected so the runner can
                # retain those candidates while keeping the run blocked.
                if unit.parse_status == "partial" and unit_findings:
                    analyzed_files.append(unit.path)
        findings.extend(_tree_amplification_candidates(ordered))
        cross_findings, cross_budget = _cross_member_alias_uaf(ordered)
        findings.extend(cross_findings)
        if cross_budget:
            complete = False
            limitations.append("Cross-member alias UAF fact budget exceeded; coverage remains unknown.")
        if cross_findings:
            analyzed_files.extend(unit.path for unit in ordered if unit.parse_status == "partial")
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if complete else "blocked",
            analyzed_files=tuple(sorted(set(analyzed_files))),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
