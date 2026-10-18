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
    function_shapes,
    line_column,
    mask_comments_and_literals,
    parameter_names,
    split_call_arguments,
)


RULE_DOUBLE_FREE = "ohcpp-resource-lifetime-double-free-candidate-001"
RULE_USE_AFTER_FREE = "ohcpp-resource-lifetime-use-after-free-candidate-002"
RULE_VERSION = "0.1.3"
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
    r"|delete(?:\s*\[\s*\])?\s+(?P<delete_name>[A-Za-z_]\w*)\s*;)"
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
_EXIT_RE = re.compile(r"\b(?:return|break|continue|goto)\b")

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


def _release_wrappers(masked: str, functions) -> Dict[str, int]:
    wrappers: Dict[str, int] = {}
    for function in functions:
        if "&" in function.params:
            continue
        params = parameter_names(function.params)
        if not params:
            continue
        body = masked[function.body_start:function.body_end]
        if re.search(r"\b(?:if|for|while|switch|return|break|continue|goto)\b", body):
            continue
        releases = list(_FREE_RE.finditer(body))
        if len(releases) != 1:
            continue
        name = releases[0].group("free_name") or releases[0].group("delete_name")
        if name in params:
            wrappers[function.name] = params.index(name)
    return wrappers


def _events(
    masked: str,
    start: int,
    end: int,
    release_wrappers: Optional[Dict[str, int]] = None,
    function_name: str = "",
) -> Tuple[_Event, ...]:
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
    for wrapper, parameter_index in (release_wrappers or {}).items():
        if wrapper == function_name:
            continue
        for match in re.finditer(r"\b" + re.escape(wrapper) + r"\s*\(", region):
            position = offset + match.start()
            span = call_argument_span(masked, position)
            if span is None:
                continue
            args = split_call_arguments(span[2])
            if len(args) <= parameter_index:
                continue
            name = args[parameter_index].strip()
            if re.fullmatch(r"[A-Za-z_]\w*", name):
                events.append(_Event(position, "release", name, wrapper + "()"))
    return tuple(sorted(set(events), key=lambda item: (item.position, item.kind, item.name)))


def _conditional_release_names(then_text: str) -> Set[str]:
    names: Set[str] = set()
    for match in _FREE_RE.finditer(then_text):
        name = match.group("free_name") or match.group("delete_name")
        tail = then_text[match.end():]
        escaped = re.escape(name)
        if re.search(r"\b" + escaped + r"\s*=\s*(?:nullptr|NULL|0)\s*;", tail):
            continue
        if re.search(r"\b" + escaped + r"\s*=\s*[A-Za-z_]\w*\s*;", tail):
            continue
        if re.search(r"\b" + escaped + r"\s*=\s*(?:malloc|calloc|realloc|new)\b", tail):
            continue
        names.add(name)
    return names


def _conditional_release_findings(
    unit: SourceUnit,
    masked: str,
    function,
    release_wrappers: Optional[Dict[str, int]] = None,
) -> List[DetectorFinding]:
    """Find a release on one falling-through if-path followed by use/release."""
    findings: List[DetectorFinding] = []
    region_start, region_end = function.body_start, function.body_end
    for match in re.finditer(r"\bif\s*\(", masked[region_start:region_end]):
        open_paren = region_start + match.end() - 1
        close_paren = balanced_end(masked, open_paren, "(", ")")
        if close_paren is None:
            continue
        then_start = close_paren
        while then_start < region_end and masked[then_start].isspace():
            then_start += 1
        if then_start >= region_end or masked[then_start] != "{":
            continue
        then_end = balanced_end(masked, then_start, "{", "}")
        if then_end is None:
            continue
        then_text = masked[then_start:then_end]
        if _EXIT_RE.search(then_text):
            continue
        names = _conditional_release_names(then_text)
        if not names:
            continue

        tail_start = then_end
        cursor = then_end
        while cursor < region_end and masked[cursor].isspace():
            cursor += 1
        if masked.startswith("else", cursor):
            cursor += len("else")
            while cursor < region_end and masked[cursor].isspace():
                cursor += 1
            if cursor >= region_end or masked[cursor] != "{":
                continue
            else_end = balanced_end(masked, cursor, "{", "}")
            if else_end is None:
                continue
            tail_start = else_end

        tail_events = _events(masked, tail_start, region_end, release_wrappers, function.name)
        for name in sorted(names):
            for event in tail_events:
                if event.name != name:
                    continue
                if event.kind in ("release", "use"):
                    rule = RULE_DOUBLE_FREE if event.kind == "release" else RULE_USE_AFTER_FREE
                    findings.append(_finding(
                        unit,
                        event.position,
                        rule,
                        name,
                        f"Candidate only: conditional path releases `{name}`, then `{event.detail}` "
                        "uses or releases it on a falling-through path. Path feasibility, aliases, "
                        "ownership transfer and guard dominance remain unknown.",
                    ))
                break
    return findings


def _analyze_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool]:
    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    if unit.parse_status != "complete":
        return findings, [f"{unit.path}: parse_status={unit.parse_status}; resource lifetime remains unknown."], False
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return findings, [f"{unit.path}: source exceeds the 1MiB per-unit fail-closed budget."], False

    masked = mask_comments_and_literals(unit.text)
    functions = function_shapes(masked)
    release_wrappers = _release_wrappers(masked, functions)
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
            for event in _events(masked, segment_start, segment_end, release_wrappers, function.name):
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
        findings.extend(_conditional_release_findings(unit, masked, function, release_wrappers))
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
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if complete else "blocked",
            analyzed_files=tuple(sorted(analyzed_files)),
            findings=_stable_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
