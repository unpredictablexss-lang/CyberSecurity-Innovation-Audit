"""Bounded C/C++ source-to-file-sink path safety candidate detector.

This is a deliberately small lexical may-flow model. It emits source-bound
candidates only when a modeled external string source reaches a modeled file
operation in the same translation unit. It is not a CFG, filesystem, or full
taint analysis; unsupported and partial inputs remain unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from src.ohscanner.contracts import (
    DetectorFinding,
    DetectorRun,
    EvidenceObligation,
    ScanContext,
    SourceUnit,
)
from .memory_safety import MAX_TOTAL_BYTES, MAX_UNIT_BYTES, line_column, mask_comments_and_literals, split_call_arguments


RULE_ID = "ohcpp.path-source-file-sink-candidate-001"
RULE_VERSION = "0.1.0"
RULE_LINEAGE = "A-PATH-01:bounded-source-to-file-sink"
MAX_FUNCTIONS_PER_UNIT = 256
MAX_CALLS_PER_UNIT = 12_000
MAX_RESCANNED_BODY_BYTES = 8 * 1024 * 1024

_SOURCE_GETTERS = {
    "GetStringValueFromDataShareValue", "GetStringFromValuesBucket",
    "GetStringParam", "GetStringParameter", "getStringParam",
}
_FILE_SINKS = {
    "unlink", "remove", "fopen", "open", "openat", "rename", "renameat",
}
_MODELED_MEMBER_SINKS = {"DeleteFile": "Contacts::FileUtils"}
_CONTROL_NAMES = {"if", "for", "while", "switch", "catch", "sizeof", "return"}
_OBLIGATIONS = (
    EvidenceObligation("source_control", "Confirm the modeled string accessor is populated by an attacker-controlled field at a reachable entry."),
    EvidenceObligation("path_resolution", "Resolve canonicalization, separator semantics, symlinks, root containment and platform filesystem behavior."),
    EvidenceObligation("cross_function_and_indirect_flow", "Resolve unmodeled helpers, aliases, macros, templates, function pointers and inter-translation-unit flow."),
    EvidenceObligation("entry_privilege_and_impact", "Establish the real entry, privilege boundary, trigger, affected files and concrete CIA impact."),
)


@dataclass(frozen=True)
class _Function:
    name: str
    start: int
    body_start: int
    body_end: int
    params: Tuple[str, ...]
    ref_params: Tuple[int, ...]


def _matching_brace(text: str, start: int) -> Optional[int]:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _functions(masked: str) -> Tuple[_Function, ...]:
    result: List[_Function] = []
    signature = re.compile(r"(?P<name>[A-Za-z_]\w*(?:::\w+)*)\s*\((?P<args>[^;{}]*)\)\s*\{")
    for match in signature.finditer(masked):
        name = match.group("name")
        if name in _CONTROL_NAMES:
            continue
        brace = masked.find("{", match.start(), match.end())
        end = _matching_brace(masked, brace)
        if end is None:
            continue
        raw_params = match.group("args")
        params: List[str] = []
        refs: List[int] = []
        if raw_params.strip() and raw_params.strip() != "void":
            for index, param in enumerate(split_call_arguments(raw_params)):
                names = re.findall(r"[A-Za-z_]\w*", param)
                if names:
                    params.append(names[-1])
                    if "&" in param or "*" in param:
                        refs.append(index)
        result.append(_Function(name, match.start(), brace + 1, end, tuple(params), tuple(refs)))
    return tuple(result)


def _call_matches(masked: str, body_start: int, body_end: int):
    for match in re.finditer(r"(?P<name>[A-Za-z_]\w*)\s*\(", masked[body_start:body_end]):
        absolute = body_start + match.start()
        name = match.group("name")
        if name in _CONTROL_NAMES:
            continue
        open_paren = masked.find("(", absolute, body_end)
        depth = 0
        close = None
        for pos in range(open_paren, body_end):
            if masked[pos] == "(":
                depth += 1
            elif masked[pos] == ")":
                depth -= 1
                if depth == 0:
                    close = pos
                    break
        if close is not None:
            yield name, absolute, open_paren + 1, close


def _contains_identifier(expr: str, tainted: Set[str]) -> bool:
    return any(re.search(r"\b" + re.escape(name) + r"\b", expr) for name in tainted)


def _function_summary(unit: SourceUnit, masked: str, fn: _Function) -> Dict[int, Set[str]]:
    """Return ref/out parameter indexes assigned from a modeled external getter."""
    out: Dict[int, Set[str]] = {}
    for getter, call_pos, arg_start, arg_end in _call_matches(masked, fn.body_start, fn.body_end):
        if getter not in _SOURCE_GETTERS:
            continue
        args = split_call_arguments(unit.text[arg_start:arg_end])
        fields = {m.group(1) for arg in args for m in re.finditer(r'"([^"\\]+)"', arg)}
        if not fields:
            continue
        # The source getter can only summarize a reference parameter when a
        # direct assignment to that parameter occurs in the same function.
        before = masked[fn.body_start:call_pos]
        assignment = re.search(r"\b([A-Za-z_]\w*)\s*=\s*$", before)
        if assignment:
            target = assignment.group(1)
            if target in fn.params and fn.params.index(target) in fn.ref_params:
                out.setdefault(fn.params.index(target), set()).update(fields)
    return out


def _call_args(unit: SourceUnit, start: int, end: int) -> Tuple[str, ...]:
    return split_call_arguments(unit.text[start:end])


def _analyze_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool, bool]:
    if len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES:
        return [], [f"{unit.path}: exceeds the 1 MiB per-unit budget; path analysis unknown."], False, False
    masked = mask_comments_and_literals(unit.text)
    functions = _functions(masked)
    limitations: List[str] = []
    if not functions:
        return [], [f"{unit.path}: no bounded function bodies recognized; source-to-sink coverage unknown."], False, False
    call_count = sum(1 for _ in re.finditer(r"\b[A-Za-z_]\w*\s*\(", masked))
    rescanned_bytes = sum(fn.body_end - fn.body_start for fn in functions)
    if (len(functions) > MAX_FUNCTIONS_PER_UNIT or call_count > MAX_CALLS_PER_UNIT
            or rescanned_bytes > MAX_RESCANNED_BODY_BYTES):
        return [], [
            f"{unit.path}: bounded analysis ceiling exceeded "
            f"(functions={len(functions)}, calls={call_count}, rescanned_bytes={rescanned_bytes}); coverage unknown."
        ], False, False

    summaries: Dict[str, Dict[int, Set[str]]] = {}
    for fn in functions:
        summary = _function_summary(unit, masked, fn)
        short_name = fn.name.rsplit("::", 1)[-1]
        if short_name in summaries:
            # Ambiguous overloads are not resolved by this lexical model.
            summaries[short_name] = {}
        else:
            summaries[short_name] = summary

    findings: List[DetectorFinding] = []
    complete = unit.parse_status == "complete"
    if not complete:
        limitations.append(f"{unit.path}: parse_status={unit.parse_status}; any lexical may-flow remains partial/unknown.")

    for fn in functions:
        tainted: Set[str] = set()
        source_fields: Dict[str, Set[str]] = {}
        body = masked[fn.body_start:fn.body_end]
        original_body = unit.text[fn.body_start:fn.body_end]

        for name, call_pos, arg_start, arg_end in _call_matches(masked, fn.body_start, fn.body_end):
            if name in _SOURCE_GETTERS:
                args = _call_args(unit, arg_start, arg_end)
                fields = {m.group(1) for arg in args for m in re.finditer(r'"([^"\\]+)"', arg)}
                before = masked[fn.body_start:call_pos]
                assignment = re.search(r"\b([A-Za-z_]\w*)\s*=\s*$", before)
                if assignment and fields:
                    variable = assignment.group(1)
                    tainted.add(variable)
                    source_fields.setdefault(variable, set()).update(fields)

            # A same-translation-unit direct reference-output summary is a
            # may-flow edge, not proof of binding or execution.
            if name in summaries and summaries[name]:
                args = _call_args(unit, arg_start, arg_end)
                for index, fields in summaries[name].items():
                    if index < len(args):
                        target_match = re.search(r"\b([A-Za-z_]\w*)\b", args[index])
                        if target_match:
                            target = target_match.group(1)
                            tainted.add(target)
                            source_fields.setdefault(target, set()).update(fields)

        # A literal allowlist is a safe basename boundary only when the
        # tainted variable is rejected before every sink. Other predicates and
        # externally implemented canonicalization helpers remain unknown.
        allowlisted: Set[str] = set()
        safe_after: Dict[str, int] = {}
        original_function_body = unit.text[fn.body_start:fn.body_end]
        for guard in re.finditer(r"if\s*\((?P<cond>(?:[^()]|\([^()]*\)){1,1000})\)\s*(?:\{\s*return\s*;\s*\}|return\s*;)", original_function_body):
            cond = guard.group("cond")
            for variable in tainted:
                # Accept only a complete conjunction of equality exclusions
                # for this exact variable. Any extra predicate (for example
                # `&& gate`) makes the rejection conditional and cannot prove
                # an allowlist.
                comparison = r"\s*" + re.escape(variable) + r"\s*!=\s*\"([A-Za-z0-9_.-]+)\"\s*"
                exact_allowlist = re.fullmatch(comparison + r"(?:&&" + comparison + r")*", cond)
                comparisons = re.findall(comparison, cond) if exact_allowlist else []
                if exact_allowlist and comparisons and all(
                    value not in (".", "..") for value in comparisons
                ):
                    allowlisted.add(variable)
                    safe_after[variable] = guard.end()
        safe_variables = set(allowlisted)
        canonical_variables: Set[str] = set()
        for assignment in re.finditer(r"\b(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^;]+);", body):
            if (_contains_identifier(assignment.group("rhs"), tainted)
                    and re.search(r"std\s*::\s*filesystem\s*::\s*(?:weakly_)?canonical\s*\(", assignment.group("rhs"))):
                canonical_variables.add(assignment.group("lhs"))
        # Recognize only a same-function early-return guard over a canonical
        # candidate and canonical root with an explicit separator boundary.
        # Prefix-only checks without the separator are deliberately rejected.
        for variable in canonical_variables:
            for guard in re.finditer(r"if\s*\((?P<cond>(?:[^()]|\([^()]*\)){1,1000})\)\s*(?:\{\s*return\s*;\s*\}|return\s*;)", original_function_body):
                condition = guard.group("cond")
                if not re.search(r"\b" + re.escape(variable) + r"\b", condition):
                    continue
                has_separator_prefix = (
                    re.search(r"!\s*" + re.escape(variable) + r"\s*\.\s*starts_with\s*\([^)]*\+\s*\"/\"", condition)
                    or re.search(r"\b" + re.escape(variable) + r"\b\s*\.\s*rfind\s*\([^)]*\+\s*\"/\"\s*,\s*0\s*\)\s*!\s*=\s*0", condition)
                )
                canonical_root = False
                for root in re.finditer(r"\b([A-Za-z_]\w*)\b", condition):
                    root_name = root.group(1)
                    if root_name == variable:
                        continue
                    for root_assignment in re.finditer(r"\b" + re.escape(root_name) + r"\s*=\s*([^;]+);", body):
                        if (re.search(r"(?:weakly_)?canonical\s*\(", root_assignment.group(1))
                                and re.search(r"std\s*::\s*filesystem\s*::\s*(?:weakly_)?canonical\s*\(", root_assignment.group(1))
                                and not _contains_identifier(root_assignment.group(1), tainted)):
                            canonical_root = True
                            break
                    if canonical_root:
                        break
                if has_separator_prefix and canonical_root:
                    safe_variables.add(variable)
                    safe_after[variable] = guard.end()

        # Bounded assignment closure, capped to prevent pathological rescans.
        for _ in range(min(8, max(1, len(body) // 200 + 1))):
            changed = False
            for assignment in re.finditer(r"\b(?P<lhs>[A-Za-z_]\w*)\s*(?:=|\+=)\s*(?P<rhs>[^;]+);", body):
                lhs, rhs = assignment.group("lhs"), assignment.group("rhs")
                if lhs not in tainted and _contains_identifier(rhs, tainted):
                    tainted.add(lhs)
                    inherited = set().union(*(source_fields.get(n, set()) for n in tainted if re.search(r"\b" + re.escape(n) + r"\b", rhs)))
                    source_fields[lhs] = inherited or {"<modeled external string field>"}
                    rhs_sources = {name for name in tainted if re.search(r"\b" + re.escape(name) + r"\b", rhs)}
                    rhs_still_safe = rhs_sources and rhs_sources.issubset(safe_variables)
                    if rhs_still_safe:
                        for safe_source in rhs_sources:
                            safe_source_reassigned = any(
                                prior.start() >= safe_after.get(safe_source, assignment.start())
                                and prior.start() < assignment.start()
                                and prior.group("lhs") == safe_source
                                for prior in re.finditer(r"\b(?P<lhs>[A-Za-z_]\w*)\s*(?:=|\+=)\s*(?P<rhs>[^;]+);", body)
                            )
                            if safe_source_reassigned:
                                rhs_still_safe = False
                                break
                    if rhs_still_safe:
                        safe_variables.add(lhs)
                        safe_after[lhs] = assignment.end()
                    changed = True
            if not changed:
                break

        for name, call_pos, arg_start, arg_end in _call_matches(masked, fn.body_start, fn.body_end):
            is_member_sink = False
            if name in _MODELED_MEMBER_SINKS:
                prefix = masked[fn.body_start:call_pos]
                receiver_match = re.search(r"([A-Za-z_]\w*)\s*\.\s*$", prefix)
                receiver = receiver_match.group(1) if receiver_match else None
                expected_type = _MODELED_MEMBER_SINKS[name]
                is_member_sink = bool(receiver and re.search(
                    r"\b" + re.escape(expected_type) + r"\s+" + re.escape(receiver) + r"\b",
                    masked,
                ))
            if name not in _FILE_SINKS and not is_member_sink:
                continue
            args = _call_args(unit, arg_start, arg_end)
            if not args:
                continue
            # File APIs consume argument 0 as the path, except rename* where
            # both old and new paths are sinks.
            path_args = args[:2] if name in {"rename", "renameat"} else args[:1]
            tainted_args = [arg for arg in path_args if _contains_identifier(arg, tainted)]
            if not tainted_args:
                continue
            sink_offset = call_pos - fn.body_start
            guarded_safe = {
                name for name in safe_variables
                if name in safe_after
                and not any(
                    assignment.start() >= safe_after[name] and assignment.start() < sink_offset
                    and assignment.group("lhs") == name
                    for assignment in re.finditer(r"\b(?P<lhs>[A-Za-z_]\w*)\s*(?:=|\+=)\s*(?P<rhs>[^;]+);", body)
                )
            }
            if any(_contains_identifier(arg, guarded_safe) for arg in tainted_args):
                continue
            fields = sorted(set().union(*(source_fields.get(identifier, set()) for arg in tainted_args for identifier in tainted if re.search(r"\b" + re.escape(identifier) + r"\b", arg))))
            line, column = line_column(unit.text, call_pos)
            findings.append(DetectorFinding(
                file=unit.path,
                line=line,
                column=column,
                rule_id=RULE_ID,
                message=("Candidate only: modeled external string source field(s) " + ", ".join(fields or ["unknown"])
                         + f" may-flow through path construction to file sink `{name}`. Path concatenation alone is not reported; "
                         "canonical containment, basename/allowlist semantics, symlinks and runtime reachability are not proven."),
                evidence_type="syntax",
                candidate_cwe="CWE-22",
                symbol=name,
                evidence_obligations=_OBLIGATIONS,
                consequence_impact="file_path_boundary",
                consequence_cwe="CWE-73",
                source_sha256=unit.sha256,
                rule_version=RULE_VERSION,
                rule_lineage_id=RULE_LINEAGE,
                identity_quality="partial",
            ))

    if any(token in unit.text for token in ("#define", "...")):
        complete = False
        limitations.append(f"{unit.path}: macros/variadics are present; source-to-sink expansion coverage remains unknown.")
    limitations.extend((
        "Candidate only: lexical intra-translation-unit may-flow does not prove CFG reachability, attacker control or impact.",
        "Unmodeled transformations, indirect calls, overloads, aliases and path-resolution semantics remain unknown.",
        "Absence of a finding is not a safe verdict; no whole-program or filesystem proof is claimed.",
    ))
    return findings, limitations, complete, True


class CppPathSafetyDetector:
    detector_id = "ohscanner.cpp.path_source_file_sink"
    version = RULE_VERSION
    supported_languages = ("c", "cpp")
    required_facts = ()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        selected = tuple(unit for unit in units if unit.language in self.supported_languages)
        if not selected:
            return DetectorRun(self.detector_id, self.version, "blocked", limitations=("not_applicable: no C/C++ source unit.",))
        ordered = tuple(sorted({unit.path: unit for unit in selected}.values(), key=lambda item: item.path))
        total = sum(len(unit.text.encode("utf-8")) for unit in ordered)
        if total > MAX_TOTAL_BYTES or any(len(unit.text.encode("utf-8")) > MAX_UNIT_BYTES for unit in ordered):
            return DetectorRun(self.detector_id, self.version, "failed", limitations=("Selected source exceeds the 32 MiB run / 1 MiB unit fail-closed budget.",))
        findings: List[DetectorFinding] = []
        limitations: List[str] = []
        analyzed: List[str] = []
        all_complete = True
        outcomes: List[Tuple[str, str]] = []
        for unit in ordered:
            unit_findings, unit_limits, complete, inspected = _analyze_unit(unit)
            findings.extend(unit_findings)
            limitations.extend(unit_limits)
            if complete:
                analyzed.append(unit.path)
                outcomes.append((unit.path, "complete"))
            elif inspected:
                # Runner uses analyzed_files to validate finding provenance;
                # file_outcomes carries the separate partial/unknown status.
                analyzed.append(unit.path)
                all_complete = False
                outcomes.append((unit.path, "partial"))
            else:
                all_complete = False
                outcomes.append((unit.path, "failed" if unit.parse_status == "failed" else "not_analyzed"))
        unique = {(f.file, f.line, f.column, f.rule_id, f.symbol, f.source_sha256): f for f in findings}
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if all_complete else "blocked",
            analyzed_files=tuple(analyzed),
            findings=tuple(sorted(unique.values(), key=lambda f: (f.file, f.line, f.column or 0))),
            limitations=tuple(sorted(set(limitations))),
            file_outcomes=tuple(outcomes),
        )
