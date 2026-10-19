"""Bounded C/C++ source-to-file-sink path traversal candidates.

This is a lexical, function-local may-flow prototype. It recognizes a small
set of string-field extraction and file API shapes; it is not a full taint or
path canonicalization proof. Unsupported/interprocedural relationships remain
unknown and parse limitations are preserved.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from src.ohscanner.contracts import (
    DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit,
)
from .memory_safety import line_column, mask_comments_and_literals


RULE_ID = "ohcpp-path-traversal-source-to-file-sink-candidate-001"
RULE_VERSION = "0.1.0"
RULE_LINEAGE_ID = "A-PATH-01:source-to-file-sink"
MAX_UNIT_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024

_OBLIGATIONS = (
    EvidenceObligation("source_binding", "Bind extracted field values to an attacker-controlled input boundary.", "unknown"),
    EvidenceObligation("path_semantics", "Resolve path normalization, symlinks, root and filesystem semantics.", "unknown"),
    EvidenceObligation("containment_dominance", "Prove canonical containment checks dominate the file operation.", "unknown"),
    EvidenceObligation("entry_privilege_and_impact", "Establish a reachable entry, caller permissions and concrete file impact.", "missing"),
)

_FUNC_RE = re.compile(r"(?:[A-Za-z_~][\w:<>*&\s]*?)\b(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;{}]*)\)\s*(?:const\s*)?\{", re.S)
_SOURCE_EXTRACT_RE = re.compile(
    r"(?P<dst>[A-Za-z_]\w*)\s*=\s*(?P<call>[A-Za-z_]\w*(?:::\w+)*)\s*\((?P<args>[^;]*)\)\s*;"
)
_PATH_ASSIGN_RE = re.compile(r"(?:std\s*::\s*filesystem\s*::\s*path|std\s*::\s*string|string|auto)\s+(?P<dst>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^;]+);|\b(?P<dst2>[A-Za-z_]\w*)\s*=\s*(?P<rhs2>[^;]+);")
_CALL_RE = re.compile(r"(?P<callee>(?:[A-Za-z_]\w*\s*::\s*)*[A-Za-z_]\w*)\s*\((?P<args>[^;()]*(?:\([^;()]*\)[^;()]*)*)\)")
_SINKS = {"unlink", "remove", "fopen", "open", "openat", "DeleteFile", "RemoveFile", "CreateFile"}


def _functions(text: str) -> List[Tuple[str, Tuple[str, ...], int, int, str]]:
    masked = mask_comments_and_literals(text)
    out: List[Tuple[str, Tuple[str, ...], int, int, str]] = []
    for match in _FUNC_RE.finditer(masked):
        brace = match.end() - 1
        depth = 1
        end = brace + 1
        while end < len(masked) and depth:
            if masked[end] == "{":
                depth += 1
            elif masked[end] == "}":
                depth -= 1
            end += 1
        if depth:
            continue
        params = []
        for arg in match.group("args").split(","):
            names = re.findall(r"[A-Za-z_]\w*", arg)
            if names and names[-1] not in {"const", "volatile", "unsigned", "signed"}:
                params.append(names[-1])
        out.append((match.group("name"), tuple(params), brace + 1, end - 1, text[brace + 1:end - 1]))
    return out


def _split_args(value: str) -> Tuple[str, ...]:
    parts: List[str] = []
    start = depth = 0
    for index, char in enumerate(value):
        if char == "(": depth += 1
        elif char == ")": depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(value[start:index].strip()); start = index + 1
    tail = value[start:].strip()
    if tail: parts.append(tail)
    return tuple(parts)


def _summaries(functions: Sequence[Tuple[str, Tuple[str, ...], int, int, str]]) -> Tuple[Set[str], Dict[str, Set[int]]]:
    returns: Set[str] = set()
    for name, _params, _start, _end, body in functions:
        code = mask_comments_and_literals(body)
        # Generic string-valued map/bucket extraction idiom: Get(key), variant
        # string extraction, then return the extracted string from the helper.
        if re.search(r"\.\s*Get\s*\(", code) and re.search(r"get_if\s*<\s*std\s*::\s*string\s*>", code):
            returned = set(re.findall(r"\breturn\s+([A-Za-z_]\w*)\s*;", code))
            extracted = set(re.findall(r"\b([A-Za-z_]\w*)\s*=\s*\*\s*[A-Za-z_]\w*\s*;", code))
            if returned & extracted:
                returns.add(name)
    out_parameters: Dict[str, Set[int]] = {}
    for name, params, _start, _end, body in functions:
        code = mask_comments_and_literals(body)
        positions: Set[int] = set()
        for index, param in enumerate(params):
            if re.search(r"\b" + re.escape(param) + r"\s*=\s*[A-Za-z_]\w*\s*\(", code):
                call_names = re.findall(r"\b" + re.escape(param) + r"\s*=\s*([A-Za-z_]\w*)\s*\(", code)
                if any(call in returns for call in call_names):
                    positions.add(index)
        if positions:
            out_parameters[name] = positions
    return returns, out_parameters


def _safe_transforms(code: str, tainted: Set[str]) -> Set[str]:
    safe: Set[str] = set()
    for match in _PATH_ASSIGN_RE.finditer(code):
        dst = match.group("dst") or match.group("dst2")
        rhs = (match.group("rhs") or match.group("rhs2") or "").strip()
        if dst and any(re.search(r"\b" + re.escape(name) + r"\b", rhs) for name in tainted):
            # A basename/filename extraction discards parent components. Other
            # normalizers alone are deliberately not treated as containment.
            if re.search(r"(?:\.\s*filename\s*\(|\bbasename\s*\()", rhs):
                safe.add(dst)
    return safe


def _guarded_call(code: str, call: re.Match[str], args: Sequence[str]) -> bool:
    if not args:
        return False
    names = re.findall(r"[A-Za-z_]\w*", args[0])
    prefix = code[max(0, call.start() - 180):call.start()]
    condition = prefix.rsplit("if", 1)[-1]
    guarded = re.search(r"(?:\.\s*starts_with\s*\(|\bis_subpath\s*\(|\bIsSubPath\s*\(|\bpath_under\s*\()", condition)
    return bool(guarded and any(re.search(r"\b" + re.escape(name) + r"\b", condition) for name in names))


def _detect_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], str]:
    if unit.language not in ("c", "cpp"):
        return [], [], "not_analyzed"
    raw = unit.text.encode("utf-8")
    if len(raw) > MAX_UNIT_BYTES:
        return [], ["source exceeds 1 MiB detector limit"], "not_analyzed"
    functions = _functions(unit.text)
    if not functions:
        return [], ["no bounded function body matched"], "partial" if unit.parse_status != "complete" else "complete"
    returns, out_params = _summaries(functions)
    # Propagate may-taint through direct, uniquely named calls. The fixed point
    # is bounded by the number of functions and tracks only parameter slots.
    incoming: Dict[str, Set[int]] = {}
    names = [item[0] for item in functions]
    for _ in range(min(len(functions), 16)):
        changed = False
        for caller, params, _start, _end, body in functions:
            code = mask_comments_and_literals(body)
            local = set(params[index] for index in incoming.get(caller, set()) if index < len(params))
            if re.search(r"\.\s*Get\s*\(", code) and re.search(r"get_if\s*<\s*std\s*::\s*string\s*>", code):
                local.update(re.findall(r"\b([A-Za-z_]\w*)\s*=\s*\*\s*[A-Za-z_]\w*\s*;", code))
            sanitized = _safe_transforms(code, local)
            for match in _PATH_ASSIGN_RE.finditer(code):
                dst = match.group("dst") or match.group("dst2")
                rhs = match.group("rhs") or match.group("rhs2") or ""
                if dst and dst not in sanitized and any(re.search(r"\b" + re.escape(var) + r"\b", rhs) for var in local):
                    local.add(dst)
            for call in _CALL_RE.finditer(code):
                callee = re.sub(r"\s*::\s*", "::", call.group("callee")).split("::")[-1]
                args = _split_args(call.group("args"))
                if callee in returns:
                    assigned = re.search(r"([A-Za-z_]\w*)\s*=\s*$", code[max(0, call.start() - 80):call.start()])
                    if assigned:
                        local.add(assigned.group(1))
                for out_index in out_params.get(callee, set()):
                    if out_index < len(args):
                        actual = re.fullmatch(r"\s*&?\s*([A-Za-z_]\w*)\s*", args[out_index])
                        if actual:
                            local.add(actual.group(1))
            # Out-parameter and returned-source summaries can introduce local
            # values after the first assignment pass (for example, a getter
            # followed by root + filename).
            sanitized.update(_safe_transforms(code, local))
            for match in _PATH_ASSIGN_RE.finditer(code):
                dst = match.group("dst") or match.group("dst2")
                rhs = match.group("rhs") or match.group("rhs2") or ""
                if dst and dst not in sanitized and any(re.search(r"\b" + re.escape(var) + r"\b", rhs) for var in local):
                    local.add(dst)
            for call in _CALL_RE.finditer(code):
                callee = re.sub(r"\s*::\s*", "::", call.group("callee")).split("::")[-1]
                args = _split_args(call.group("args"))
                if names.count(callee) != 1:
                    continue
                target = next(item for item in functions if item[0] == callee)
                if _guarded_call(code, call, args):
                    continue
                for index, arg in enumerate(args):
                    if index < len(target[1]) and any(re.search(r"\b" + re.escape(var) + r"\b", arg) for var in local):
                        before = len(incoming.setdefault(callee, set()))
                        incoming[callee].add(index)
                        changed |= len(incoming[callee]) != before
                for index in out_params.get(callee, set()):
                    if index < len(args) and re.fullmatch(r"\s*&?\s*[A-Za-z_]\w*\s*", args[index]):
                        # Out parameter local taint is picked up at its caller on
                        # the next pass through the callee summary below.
                        pass
        if not changed:
            break
    findings: List[DetectorFinding] = []
    limitations: List[str] = []
    for name, params, start, end, body in functions:
        code = mask_comments_and_literals(body)
        tainted: Set[str] = {params[index] for index in incoming.get(name, set()) if index < len(params)}
        # Values from string fields of bucket-like objects become sources when
        # a local string is extracted from a map value with std::get_if.
        if re.search(r"\.\s*Get\s*\(", code) and re.search(r"get_if\s*<\s*std\s*::\s*string\s*>", code):
            tainted.update(re.findall(r"\b([A-Za-z_]\w*)\s*=\s*\*\s*[A-Za-z_]\w*\s*;", code))
        # Apply exact local interprocedural summaries at calls in this function.
        for call in _CALL_RE.finditer(code):
            callee = re.sub(r"\s*::\s*", "::", call.group("callee"))
            args = _split_args(call.group("args"))
            if callee in returns:
                assigned = re.search(r"([A-Za-z_]\w*)\s*=\s*$", code[max(0, call.start() - 80):call.start()])
                if assigned: tainted.add(assigned.group(1))
            for index in out_params.get(callee, set()):
                if index < len(args):
                    actual = re.fullmatch(r"\s*&?\s*([A-Za-z_]\w*)\s*", args[index])
                    if actual: tainted.add(actual.group(1))
        if not tainted:
            continue
        safe = _safe_transforms(code, tainted)
        path_vars: Set[str] = set(tainted)
        for match in _PATH_ASSIGN_RE.finditer(code):
            dst = match.group("dst") or match.group("dst2")
            rhs = match.group("rhs") or match.group("rhs2") or ""
            if not dst or dst in safe:
                continue
            if any(re.search(r"\b" + re.escape(source) + r"\b", rhs) for source in tainted):
                # A direct tainted file argument is still a path candidate; a
                # path construction or recognized path transform is stronger.
                path_vars.add(dst)
            elif any(re.search(r"\b" + re.escape(source) + r"\b", rhs) for source in path_vars):
                path_vars.add(dst)
        if not path_vars:
            continue
        for call in _CALL_RE.finditer(code):
            callee = re.sub(r"\s*::\s*", "::", call.group("callee")).split("::")[-1]
            if callee not in _SINKS:
                continue
            args = _split_args(call.group("args"))
            if not args:
                continue
            if _guarded_call(code, call, args):
                continue
            first = re.fullmatch(r"\s*(?:&\s*)?([A-Za-z_]\w*)\s*(?:\.c_str\s*\(\))?\s*", args[0])
            if not first or first.group(1) not in path_vars:
                continue
            absolute = start + call.start()
            line, column = line_column(unit.text, absolute)
            findings.append(DetectorFinding(
                file=unit.path, line=line, column=column, rule_id=RULE_ID,
                message="Untrusted string-derived path reaches a file operation without a recognized containment guard; review as a path traversal candidate.",
                evidence_type="syntax", candidate_cwe="CWE-22", symbol=name,
                evidence_obligations=_OBLIGATIONS, consequence_impact="file_integrity_or_availability",
                consequence_cwe="CWE-22", source_sha256=unit.sha256,
                rule_version=RULE_VERSION, rule_lineage_id=RULE_LINEAGE_ID,
                symbol_identity=name, identity_quality="partial",
            ))
    coverage = "complete" if unit.parse_status == "complete" else "partial"
    if coverage == "partial": limitations.append("input parser status is partial; candidate results cannot establish a safe negative")
    elif unit.parse_status in ("failed", "not_run"):
        coverage = "partial"
        limitations.append("input parser status is " + unit.parse_status)
    return findings, limitations, coverage


class CppPathTraversalDetector:
    detector_id = "ohscanner.cpp.path_traversal"
    version = RULE_VERSION
    supported_languages = ("c", "cpp")
    required_facts = ()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        accepted: List[SourceUnit] = []
        total = 0
        findings: List[DetectorFinding] = []
        limitations: List[str] = []
        outcomes: List[Tuple[str, str]] = []
        for unit in units:
            if unit.language not in self.supported_languages:
                continue
            size = len(unit.text.encode("utf-8"))
            if total + size > MAX_TOTAL_BYTES:
                limitations.append("total source exceeds 32 MiB detector limit")
                outcomes.append((unit.path, "not_analyzed"))
                continue
            total += size
            accepted.append(unit)
            local, local_limits, outcome = _detect_unit(unit)
            findings.extend(local)
            limitations.extend(unit.path + ": " + item for item in local_limits)
            outcomes.append((unit.path, outcome))
        status = "completed" if all(state in ("complete", "not_analyzed") for _, state in outcomes) else "blocked"
        findings.sort(key=lambda item: (item.file, item.line, item.column or 0))
        return DetectorRun(
            detector_id=self.detector_id, version=self.version, status=status,
            analyzed_files=tuple(unit.path for unit in accepted), findings=tuple(findings),
            limitations=tuple(dict.fromkeys(limitations)), file_outcomes=tuple(outcomes),
        )
