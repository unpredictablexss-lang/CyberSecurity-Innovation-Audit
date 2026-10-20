"""A bounded, source-to-file-sink path traversal research candidate detector.

This is intentionally not registered in the shared catalog.  It models only
DataShare ValuesBucket string extraction, same-translation-unit assignments,
and direct standard file APIs.  Unsupported parse/dataflow remains unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Set, Tuple

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
    function_shapes,
    line_column,
    mask_comments_and_literals,
)


RULE_ID = "ohcpp-path-traversal-candidate-001"
RULE_VERSION = "0.1.0-research"
RULE_LINEAGE_ID = "A-PATH-01:bounded-source-to-file-sink"
MAX_FUNCTIONS = 256
MAX_CALLS = 4096
MAX_FLOW_ROUNDS = 4

_DATA_SHARE_TYPE = re.compile(r"\b(?:DataShare\s*::\s*)?DataShareValuesBucket\b")
_STRING_ACCESSOR = re.compile(r"\.(?:GetString|GetStringValue)\s*\(")
_OBJECT_ACCESSOR = re.compile(r"\.(?:Get|GetValue)\s*\(")
_STRING_CONVERSION = re.compile(r"get_if\s*<\s*(?:std\s*::\s*)?string\s*>")
_ASSIGNMENT = re.compile(
    r"(?:\b(?:const\s+)?(?:auto|std\s*::\s*string|basic_string\s*<[^;=]+?>)\s+)?"
    r"(?P<name>[A-Za-z_]\w*)\s*(?P<op>\+=|=)\s*(?P<expr>[^;{}]+);"
)
_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
_RETURN = re.compile(r"\breturn\s+(?P<expr>[^;]+);?")
_CALL = re.compile(r"(?<![.>\w])(?P<name>[A-Za-z_]\w*)\s*\(")
_ANY_CALL = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\(")
_SAFE_FILENAME = re.compile(
    r"(?:std\s*::\s*filesystem\s*::\s*path\s*\([^;]*?\)|\b[A-Za-z_]\w*)"
    r"\s*\.\s*filename\s*\(\s*\)"
)
_CANONICAL = re.compile(r"(?:weakly_)?canonical\s*\(")
_REVIEWED_FILE_DELETE = "DeleteFile"
_REVIEWED_FILE_DELETE_RECEIVER = re.compile(r"(?P<receiver>[A-Za-z_]\w*)\s*(?:\.|->)\s*$")
_SINK_CALLS = {
    "open": (0,),
    "openat": (1,),
    "creat": (0,),
    "fopen": (0,),
    "freopen": (0,),
    "unlink": (0,),
    "unlinkat": (1,),
    "remove": (0,),
    "rename": (0, 1),
    "mkdir": (0,),
    "rmdir": (0,),
}
_KNOWN_PATH_TRANSFORMS = {
    "path", "canonical", "weakly_canonical", "lexically_relative",
    "filename", "string", "c_str", "GetString", "GetStringValue", "get_if",
}
_NON_PATH_CALLS = {"if", "for", "while", "switch", "catch", "sizeof", "close"}
_OBLIGATIONS = (
    EvidenceObligation(
        "source_model",
        "Confirm the DataShare ValuesBucket field/string accessor is externally influenced.",
    ),
    EvidenceObligation(
        "path_dataflow_and_sink",
        "Resolve aliases, wrapper APIs, macros, overloads and feasible control flow.",
    ),
    EvidenceObligation(
        "containment_and_filesystem_semantics",
        "Verify canonical containment, symlink behavior, root identity and the exact filesystem object.",
    ),
    EvidenceObligation(
        "entry_privilege_and_impact",
        "Establish a reachable entry, privilege boundary, trigger and concrete CIA impact.",
        "missing",
    ),
)


@dataclass(frozen=True)
class _Function:
    name: str
    start: int
    body_start: int
    body_end: int
    signature: str
    body: str
    params: Tuple[str, ...]


@dataclass(frozen=True)
class _CallSite:
    caller: str
    name: str
    start: int
    args: Tuple[str, ...]
    assigned_to: str = ""


def _call_arguments(function: "_Function", masked: str, match: re.Match[str]) -> Tuple[str, ...]:
    open_pos = function.body_start + 1 + match.end() - 1
    depth = 1
    cursor = open_pos + 1
    while cursor < function.body_end - 1 and depth:
        if masked[cursor] == "(":
            depth += 1
        elif masked[cursor] == ")":
            depth -= 1
        cursor += 1
    return () if depth else _split_args(masked[open_pos + 1:cursor - 1])


def _reviewed_member_file_delete(
    function: "_Function", masked: str, match: re.Match[str]
) -> Tuple[int, str] | None:
    absolute = function.body_start + 1 + match.start()
    prefix = masked[max(function.body_start + 1, absolute - 96):absolute]
    receiver = _REVIEWED_FILE_DELETE_RECEIVER.search(prefix)
    if not receiver or receiver.group("receiver").lower() != "fileutils":
        return None
    args = _call_arguments(function, masked, match)
    return (absolute, args[0]) if len(args) == 1 and args[0].strip() else None


def _split_args(value: str) -> Tuple[str, ...]:
    parts: List[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(value):
        if char in "([{<":
            depth += 1
        elif char in ")]}>" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        parts.append(tail)
    return tuple(parts)


def _parameters(signature: str) -> Tuple[str, ...]:
    opening = signature.find("(")
    closing = signature.rfind(")")
    if opening < 0 or closing <= opening:
        return ()
    result = []
    for item in _split_args(signature[opening + 1:closing]):
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*$", item)
        result.append(match.group(1) if match else "")
    return tuple(result)


def _functions(masked: str) -> Tuple[_Function, ...]:
    result = []
    for shape in function_shapes(masked):
        signature = masked[shape.start:shape.body_start]
        result.append(_Function(
            shape.name, shape.start, shape.body_start, shape.body_end,
            signature, masked[shape.body_start + 1:shape.body_end - 1],
            _parameters(signature),
        ))
    return tuple(result)


def _direct_source(function: _Function) -> bool:
    """Recognize string extraction from a typed DataShare values bucket."""
    if not _DATA_SHARE_TYPE.search(function.signature):
        return False
    body = function.body
    return bool(
        _STRING_ACCESSOR.search(body)
        or (_OBJECT_ACCESSOR.search(body) and _STRING_CONVERSION.search(body))
    )


def _source_receiver_names(function: _Function) -> Set[str]:
    if not _DATA_SHARE_TYPE.search(function.signature):
        return set()
    # A modeled source is a ValuesBucket parameter used as the receiver of a
    # known string/object accessor; method names alone never establish source.
    names = set()
    for name in function.params:
        if not name:
            continue
        if re.search(r"\b" + re.escape(name) + r"\s*\.\s*(?:GetString|GetStringValue|Get|GetValue)\s*\(", function.body):
            names.add(name)
    return names


def _call_sites(functions: Sequence[_Function], masked: str) -> Tuple[_CallSite, ...]:
    sites: List[_CallSite] = []
    by_name = {function.name: function for function in functions}
    for function in functions:
        for match in _CALL.finditer(function.body):
            name = match.group("name")
            if name not in by_name:
                continue
            open_pos = function.body_start + 1 + match.end() - 1
            depth = 1
            cursor = open_pos + 1
            while cursor < function.body_end - 1 and depth:
                if masked[cursor] == "(":
                    depth += 1
                elif masked[cursor] == ")":
                    depth -= 1
                cursor += 1
            if depth:
                continue
            args = _split_args(masked[open_pos + 1:cursor - 1])
            before = masked[function.body_start + 1 + match.start():]
            assignment = re.search(r"([A-Za-z_]\w*)\s*=\s*$", masked[max(function.body_start + 1, function.body_start + 1 + match.start() - 100):function.body_start + 1 + match.start()])
            sites.append(_CallSite(function.name, name, function.body_start + 1 + match.start(), args, assignment.group(1) if assignment else ""))
            if len(sites) > MAX_CALLS:
                raise OverflowError("call-site budget exceeded")
    return tuple(sites)


def _identifiers(expression: str) -> Set[str]:
    return set(_IDENT.findall(expression))


def _safe_name_transform(name: str, expression: str) -> bool:
    return bool(re.search(
        r"\b" + re.escape(name) + r"\s*=\s*(?:std\s*::\s*filesystem\s*::\s*path\s*\([^;]+?\)|[A-Za-z_]\w*)\s*\.\s*filename\s*\(\)",
        expression,
    ))


def _allowlisted(name: str, original_body: str, sink_position: int) -> bool:
    """Conservatively recognize a small literal equality allowlist before a sink."""
    prefix = original_body[:max(0, sink_position)]
    safe = re.search(
        r"if\s*\(\s*" + re.escape(name)
        + r"\s*!=\s*\"[A-Za-z0-9_.-]+\"(?:\s*&&\s*"
        + re.escape(name) + r"\s*!=\s*\"[A-Za-z0-9_.-]+\")+\s*\)\s*\{?\s*(?:return|throw)\b",
        prefix,
    )
    return bool(safe)


def _safe_path_value(
    function: _Function,
    variable: str,
    flow: Set[str],
    original_body: str,
    sink_offset: int,
    seen: Set[str] | None = None,
) -> bool:
    seen = set() if seen is None else seen
    if variable in seen:
        return False
    seen.add(variable)
    if _allowlisted(variable, original_body, sink_offset):
        return True
    if _canonical_containment(function, variable, original_body[:sink_offset]):
        return True
    assignments = [match for match in _ASSIGNMENT.finditer(function.body[:sink_offset]) if match.group("name") == variable]
    if not assignments:
        return False
    assignment = assignments[-1]
    expression = assignment.group("expr")
    if _SAFE_FILENAME.search(expression):
        return True
    sources = _identifiers(expression) & flow
    if sources and all(_safe_path_value(function, source, flow, original_body, sink_offset, set(seen)) for source in sources):
        return True
    return False


def _canonical_containment(function: _Function, variable: str, body: str) -> bool:
    """Accept only an explicit component-aware lexical-relative escape guard."""
    if not _CANONICAL.search(body):
        return False
    candidate = re.search(
        r"\b" + re.escape(variable) + r"\s*=\s*(?:std\s*::\s*filesystem\s*::\s*)?"
        r"(?:weakly_)?canonical\s*\(\s*(?P<root>[A-Za-z_]\w*)\s*/",
        body,
    )
    if not candidate:
        return False
    root = candidate.group("root")
    canonical_root = re.search(
        r"(?P<name>[A-Za-z_]\w*)\s*=\s*(?:std\s*::\s*filesystem\s*::\s*)?"
        r"(?:weakly_)?canonical\s*\(\s*" + re.escape(root) + r"\s*\)",
        body,
    )
    if not canonical_root:
        return False
    root_name = canonical_root.group("name")
    relative = re.search(
        r"(?P<name>[A-Za-z_]\w*)\s*=\s*" + re.escape(variable)
        + r"\s*\.\s*lexically_relative\s*\(\s*" + re.escape(root_name) + r"\s*\)",
        body,
    )
    if not relative:
        return False
    rel_name = relative.group("name")
    rejects_empty = re.search(r"\b" + re.escape(rel_name) + r"\s*\.\s*empty\s*\(\s*\)", body)
    rejects_parent = re.search(
        r"\*\s*" + re.escape(rel_name) + r"\s*\.\s*begin\s*\(\s*\)\s*==\s*\"\.\.\"",
        body,
    )
    guard = re.search(
        r"if\s*\([^{}]{0,240}" + re.escape(rel_name)
        + r"[^{}]{0,240}\)\s*\{?\s*(?:return|throw)\b",
        body,
    )
    if not (rejects_empty and rejects_parent):
        return False
    return bool(guard)


def _stable_findings(findings: Iterable[DetectorFinding]) -> Tuple[DetectorFinding, ...]:
    seen = set()
    output = []
    for finding in findings:
        key = (finding.file, finding.line, finding.column, finding.rule_id, finding.symbol)
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return tuple(sorted(output, key=lambda item: (item.file, item.line, item.column or 0, item.symbol or "")))


def _finding(unit: SourceUnit, position: int, symbol: str) -> DetectorFinding:
    line, column = line_column(unit.text, position)
    return DetectorFinding(
        file=unit.path,
        line=line,
        column=column,
        rule_id=RULE_ID,
        message=(
            "Candidate only: a string extracted through a typed DataShare ValuesBucket accessor "
            f"reaches direct file sink `{symbol}` without a modeled basename allowlist or canonical "
            "root-containment guard. This is bounded syntax dataflow, not exploitability proof."
        ),
        evidence_type="syntax",
        candidate_cwe="CWE-22",
        symbol=symbol,
        evidence_obligations=_OBLIGATIONS,
        consequence_impact="filesystem_path_control",
        consequence_cwe="CWE-22",
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
    )


def _analyze_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool]:
    if unit.parse_status != "complete":
        return [], [f"{unit.path}: parse_status={unit.parse_status}; path-flow remains unknown."], False
    encoded_size = len(unit.text.encode("utf-8"))
    if encoded_size > MAX_UNIT_BYTES:
        return [], [f"{unit.path}: source exceeds the 1MiB unit budget; path-flow remains unknown."], False

    masked = mask_comments_and_literals(unit.text)
    all_functions = _functions(masked)
    if len(all_functions) > MAX_FUNCTIONS:
        return [], [f"{unit.path}: function budget exceeded; path-flow remains unknown."], False
    # An unmatched brace or unterminated lexical construct invalidates lexical
    # offsets and prevents emitting a candidate from this unit.
    if masked.count("{") != masked.count("}"):
        return [], [f"{unit.path}: unbalanced function/body delimiters; path-flow remains unknown."], False
    names: Dict[str, List[_Function]] = {}
    for function in all_functions:
        names.setdefault(function.name, []).append(function)
    ambiguous_names = {name for name, items in names.items() if len(items) > 1}
    # Unrelated overloads must not erase a local flow through unambiguous
    # helpers. Skip only overloaded definitions and calls to their names.
    functions = tuple(function for function in all_functions if function.name not in ambiguous_names)
    by_name: Dict[str, List[_Function]] = {function.name: [function] for function in functions}
    sources = {function.name for function in functions if _direct_source(function)}
    # Also accept a typed bucket accessor as source even when its string
    # conversion is spread across local variables; the bucket itself is not
    # tainted until a string accessor is evaluated.
    receivers = {function.name: _source_receiver_names(function) for function in functions}
    if sources and re.search(r"^\s*#\s*(?:define|if|ifdef|ifndef|elif)", unit.text, re.MULTILINE):
        return [], [f"{unit.path}: preprocessor macros/configuration intersect a modeled source; path-flow remains unknown."], False
    try:
        calls = _call_sites(functions, masked)
    except OverflowError as exc:
        return [], [f"{unit.path}: {exc}; path-flow remains unknown."], False

    tainted: Dict[str, Set[str]] = {function.name: set() for function in functions}
    tainted_params: Dict[str, Set[int]] = {function.name: set() for function in functions}
    return_tainted: Set[str] = set(sources)
    out_tainted: Dict[str, Set[int]] = {name: set() for name in by_name}
    sinks: List[Tuple[_Function, int, str, str]] = []
    source_sites: Set[str] = set(sources)

    # Bounded monotone summaries: direct accessor -> local dataflow -> at most
    # four same-file call/return/out-parameter propagation rounds.
    for _round in range(MAX_FLOW_ROUNDS):
        changed = False
        call_by_caller: Dict[str, List[_CallSite]] = {}
        for site in calls:
            call_by_caller.setdefault(site.caller, []).append(site)
        for function in functions:
            flow = set(tainted[function.name])
            flow.update(function.params[index] for index in tainted_params[function.name] if index < len(function.params) and function.params[index])
            receiver_names = receivers[function.name]
            # Source receiver accessors yield path strings; arbitrary methods
            # with the same spelling do not qualify without the DataShare type.
            for match in _ASSIGNMENT.finditer(function.body):
                expression = match.group("expr")
                if any(re.search(r"\b" + re.escape(receiver) + r"\s*\.\s*(?:GetString|GetStringValue|Get|GetValue)\s*\(", expression) for receiver in receiver_names):
                    flow.add(match.group("name"))
            for site in call_by_caller.get(function.name, []):
                if site.name in return_tainted and site.assigned_to:
                    flow.add(site.assigned_to)
                callee = by_name[site.name][0]
                for index, arg in enumerate(site.args):
                    if index >= len(callee.params):
                        continue
                    if _identifiers(arg) & flow and index not in tainted_params[site.name]:
                        tainted_params[site.name].add(index)
                        changed = True
                    if index in out_tainted[site.name]:
                        target = re.fullmatch(r"\s*&?\s*([A-Za-z_]\w*)\s*(?:\.\s*[^.]+)?\s*", arg)
                        if target and target.group(1) not in flow:
                            flow.add(target.group(1))
            # Simple assignments and concatenations preserve taint. Function
            # calls outside this bounded summary are deliberately not guessed.
            for match in _ASSIGNMENT.finditer(function.body):
                name, expression = match.group("name"), match.group("expr")
                if name in flow:
                    continue
                if _identifiers(expression) & flow:
                    flow.add(name)
            if flow != tainted[function.name]:
                tainted[function.name] = flow
                changed = True
            body = function.body
            if function.name not in return_tainted:
                for match in _RETURN.finditer(body):
                    if _identifiers(match.group("expr")) & flow:
                        return_tainted.add(function.name)
                        source_sites.add(function.name)
                        changed = True
                        break
            for index, parameter in enumerate(function.params):
                if parameter and re.search(r"\b" + re.escape(parameter) + r"\s*=\s*[^;]*\b(?:GetString|GetStringValue)\s*\(", body):
                    if index not in out_tainted[function.name]:
                        out_tainted[function.name].add(index)
                        changed = True
                elif parameter and any(
                    re.search(r"\b" + re.escape(parameter) + r"\s*=\s*[^;]*\b" + re.escape(callee) + r"\s*\(", body)
                    and callee in return_tainted for callee in return_tainted
                ) and index not in out_tainted[function.name]:
                    out_tainted[function.name].add(index)
                    changed = True
        if not changed:
            break

    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    unresolved_path_calls: Set[str] = set()
    if ambiguous_names:
        limitations.append(
            f"{unit.path}: overloaded functions {', '.join(sorted(ambiguous_names)[:8])} were excluded from call summaries; their flows remain unknown."
        )
    modeled_source_functions = set(sources) | source_sites
    for function in functions:
        flow = tainted[function.name]
        for call in _ANY_CALL.finditer(function.body):
            name = call.group("name")
            if name in by_name or name in _SINK_CALLS or name in _KNOWN_PATH_TRANSFORMS or name in _NON_PATH_CALLS:
                continue
            open_pos = function.body_start + 1 + call.end() - 1
            depth = 1
            cursor = open_pos + 1
            while cursor < function.body_end - 1 and depth:
                if masked[cursor] == "(":
                    depth += 1
                elif masked[cursor] == ")":
                    depth -= 1
                cursor += 1
            if depth:
                continue
            args = _split_args(masked[open_pos + 1:cursor - 1])
            if any(_identifiers(arg) & flow for arg in args):
                if name != _REVIEWED_FILE_DELETE or not _reviewed_member_file_delete(function, masked, call):
                    unresolved_path_calls.add(name)
        # Member calls are excluded: project methods named open/remove/unlink
        # are not silently treated as libc sinks.
        for match in _CALL.finditer(function.body):
            name = match.group("name")
            if name not in _SINK_CALLS:
                continue
            absolute = function.body_start + 1 + match.start()
            if absolute > 0 and masked[absolute - 1] in ".>":
                continue
            open_pos = function.body_start + 1 + match.end() - 1
            depth = 1
            cursor = open_pos + 1
            while cursor < function.body_end - 1 and depth:
                if masked[cursor] == "(":
                    depth += 1
                elif masked[cursor] == ")":
                    depth -= 1
                cursor += 1
            if depth:
                continue
            args = _split_args(masked[open_pos + 1:cursor - 1])
            for sink_index in _SINK_CALLS[name]:
                if len(args) <= sink_index:
                    continue
                path_arg = args[sink_index]
                path_vars = _identifiers(path_arg) & flow
                if not path_vars:
                    continue
                original_body = unit.text[function.body_start + 1:function.body_end - 1]
                sink_offset = absolute - function.body_start - 1
                safe = all(
                    _safe_path_value(function, variable, flow, original_body, sink_offset)
                    for variable in path_vars
                )
                if not safe:
                    findings.append(_finding(unit, absolute, name))
                sinks.append((function, absolute, name, ",".join(sorted(path_vars))))

        # The reviewed project file-delete wrapper is a member call. Accept
        # only the exact `fileUtils.DeleteFile(path)` shape; unknown receivers,
        # arities and static/wrapper overloads remain unresolved rather than
        # being guessed as equivalent to libc deletion semantics.
        for match in _ANY_CALL.finditer(function.body):
            if match.group("name") != _REVIEWED_FILE_DELETE:
                continue
            parsed = _reviewed_member_file_delete(function, masked, match)
            if parsed is None:
                if any(_identifiers(arg) & flow for arg in _call_arguments(function, masked, match)):
                    unresolved_path_calls.add(_REVIEWED_FILE_DELETE)
                continue
            absolute, path_arg = parsed
            path_vars = _identifiers(path_arg) & flow
            if not path_vars:
                continue
            original_body = unit.text[function.body_start + 1:function.body_end - 1]
            sink_offset = absolute - function.body_start - 1
            safe = all(
                _safe_path_value(function, variable, flow, original_body, sink_offset)
                for variable in path_vars
            )
            if not safe:
                findings.append(_finding(unit, absolute, _REVIEWED_FILE_DELETE))
            sinks.append((function, absolute, _REVIEWED_FILE_DELETE, ",".join(sorted(path_vars))))

    has_source = bool(sources or any(receivers.values()))
    if unresolved_path_calls:
        limitations.append(
            f"{unit.path}: tainted path reaches unresolved external call(s) {', '.join(sorted(unresolved_path_calls)[:8])}; sink semantics remain unknown."
        )
    if has_source and not findings:
        limitations.append(
            f"{unit.path}: DataShare string source modeled, but no same-file bounded uncontained source-to-direct-file-sink flow was proven; wrappers/cross-file calls remain unknown."
        )
        if not sinks and any(name in _SINK_CALLS for function in functions for name in _CALL.findall(function.body)):
            # A source and a sink are present in this translation unit, but
            # their relation was not established inside the bounded summaries.
            # Do not turn this unresolved shape into a clean/no-findings result.
            return [], limitations, False
    if findings:
        limitations.extend((
            "Candidate only: lexical same-file summaries do not prove control-flow dominance, filesystem resolution, symlink safety or attacker reachability.",
            "Only typed DataShare ValuesBucket accessors and direct libc file calls are modeled; external wrappers/macros and unresolved overloads remain unknown.",
        ))
    else:
        limitations.append("No candidate is not a safe verdict; unmodeled or unresolved source-to-sink paths remain unknown.")
    return findings, limitations, not ambiguous_names and not unresolved_path_calls


class CppPathTraversalDetector:
    detector_id = "ohscanner.cpp.path_traversal"
    version = RULE_VERSION
    supported_languages = ("c", "cpp")
    required_facts = ()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        selected = tuple(unit for unit in units if unit.language in self.supported_languages)
        if not selected:
            return DetectorRun(self.detector_id, self.version, "blocked", limitations=("not_applicable: no C/C++ source.",))
        ordered = tuple(sorted({unit.path: unit for unit in selected}.values(), key=lambda unit: unit.path))
        if any(len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES for unit in ordered) or sum(len(unit.text.encode("utf-8")) for unit in ordered) > MAX_TOTAL_BYTES:
            return DetectorRun(self.detector_id, self.version, "failed", limitations=("Selected source exceeds the fail-closed byte budget; analysis not run.",))
        findings: List[DetectorFinding] = []
        limitations: List[str] = []
        analyzed: List[str] = []
        complete = True
        for unit in ordered:
            try:
                unit_findings, unit_limitations, unit_complete = _analyze_unit(unit)
            except Exception as exc:
                unit_findings, unit_limitations, unit_complete = [], [f"{unit.path}: {type(exc).__name__}; path-flow remains unknown."], False
            findings.extend(unit_findings)
            limitations.extend(unit_limitations)
            if unit_complete:
                analyzed.append(unit.path)
            else:
                complete = False
        return DetectorRun(
            self.detector_id, self.version, "completed" if complete else "blocked",
            analyzed_files=tuple(analyzed), findings=_stable_findings(findings),
            limitations=tuple(sorted(set(limitations))),
        )

