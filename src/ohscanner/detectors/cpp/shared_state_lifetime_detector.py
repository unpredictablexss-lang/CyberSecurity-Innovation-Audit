"""Bounded lexical cross-function pointer/count state lifetime candidates.

This detector relates an input pointer/count pair populated by a refill path,
an owner-state release path, and a later consumer guarded by the count. It is a
candidate-only lexical analysis, not an interprocedural CFG or alias proof.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .memory_safety import MAX_TOTAL_BYTES, MAX_UNIT_BYTES, function_shapes, line_column, mask_comments_and_literals

RULE_STALE_SHARED_INPUT = "ohcpp-shared-state-stale-input-candidate-001"
RULE_VERSION = "0.1.0"
RULE_LINEAGE_ID = "A-D3-02:shared-pointer-count-lifetime-candidate"
_ASSIGN = re.compile(r"(?P<lhs>[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+)\s*=\s*(?P<rhs>[^;{}]+);", re.S)
_PARAM = re.compile(r"(?P<type>(?:struct\s+)?[A-Za-z_]\w*(?:\s+const)?\s*\**?)\s*(?P<name>[A-Za-z_]\w*)\s*(?:,|$)")
_CALL = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;{}()]*(?:\([^()]*\)[^;{}()]*)*)\)")
_POINTER_TYPEDEF = re.compile(
    r"\btypedef\s+[^;{}]*\*+\s*(?:[A-Z_]\w*\s+)?(?P<alias>[A-Za-z_]\w*)\s*;"
)
_OBLIGATIONS = (
    EvidenceObligation("shared_object_identity", "Prove the release and consumer refer to the same concrete shared object and nested state.", "unknown"),
    EvidenceObligation("backing_owner_lifetime", "Establish which allocation owns the bytes referenced by the shared input pointer and when that owner is released.", "unknown"),
    EvidenceObligation("state_transition_order", "Resolve call order, error exits, callbacks and control flow between ownership release and later consumption.", "missing"),
    EvidenceObligation("input_and_entry_control", "Establish that malformed input and the required read sequence are reachable in the target application.", "missing"),
    EvidenceObligation("memory_safety_impact", "Reproduce an invalid read under the affected allocator/build and distinguish crash from disclosure or corruption.", "missing"),
)


def _member_accesses(text: str) -> Tuple[Tuple[str, Tuple[str, ...], int], ...]:
    # Match a root object followed by one or more member hops. Each hop may
    # use either C pointer or C++ object syntax; identifiers are bound from
    # source and never used as rule signatures.
    pattern = re.compile(r"\b(?P<root>[A-Za-z_]\w*)\s*(?P<chain>(?:(?:->|\.)\s*[A-Za-z_]\w*\s*)+)")
    result = []
    for match in pattern.finditer(text):
        hops = tuple(re.findall(r"(?:->|\.)\s*([A-Za-z_]\w*)", match.group("chain")))
        if hops:
            result.append((match.group("root"), hops, match.start()))
    return tuple(result)


def pointer_typedefs(units: Iterable[SourceUnit]) -> Set[str]:
    """Collect pointer typedef names from the selected translation scope."""
    aliases: Set[str] = set()
    for unit in units:
        if unit.language not in ("c", "cpp"):
            continue
        masked = mask_comments_and_literals(unit.text)
        aliases.update(match.group("alias") for match in _POINTER_TYPEDEF.finditer(masked))
    return aliases


def _function_identity(function, aliases: Set[str]) -> Tuple[Optional[str], Tuple[str, ...]]:
    signature = function.text[:function.text.find("{")]
    open_paren = signature.find("(")
    close_paren = signature.rfind(")")
    if open_paren < 0 or close_paren < open_paren:
        return None, ()
    params = signature[open_paren + 1:close_paren]
    # Keep declaration order and only support simple single-declarator params.
    chunks = []
    depth = 0
    start = 0
    for i, char in enumerate(params):
        if char in "(<[": depth += 1
        elif char in ")>]": depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            chunks.append(params[start:i].strip()); start = i + 1
    chunks.append(params[start:].strip())
    for chunk in chunks:
        m = re.search(r"(?P<type>(?:struct\s+)?[A-Za-z_]\w*(?:\s+const)?)(?P<pointer>\s*\*+)?\s*(?P<name>[A-Za-z_]\w*)\s*$", chunk)
        base_type = re.sub(r"\s+const", "", m.group("type")).replace("struct ", "").replace("*", "").strip() if m else ""
        if m and (m.group("pointer") or "struct " in m.group("type") or base_type in aliases):
            typ = base_type
            return typ, (m.group("name"),)
    return None, ()


def _assignments(body: str):
    for match in _ASSIGN.finditer(body):
        lhs_accesses = _member_accesses(match.group("lhs"))
        if not lhs_accesses:
            continue
        root, hops, _ = lhs_accesses[-1]
        yield match, root, hops, match.group("rhs").strip()


def _member_pattern(root: str, hops: Sequence[str]) -> str:
    return r"\b" + re.escape(root) + r"\s*(?:->|\.)\s*" + r"\s*(?:->|\.)\s*".join(
        re.escape(hop) for hop in hops
    )


def _simple_arguments(text: str) -> Tuple[str, ...]:
    parts = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char in "([{": depth += 1
        elif char in ")]}": depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip()); start = index + 1
    parts.append(text[start:].strip())
    return tuple(parts)


def _zero_guard_paths(body: str) -> Set[Tuple[str, Tuple[str, ...]]]:
    result: Set[Tuple[str, Tuple[str, ...]]] = set()
    for control in re.finditer(r"\b(?:if|while)\s*\((?P<condition>[^)]*)\)", body):
        condition = control.group("condition")
        if not re.search(r"(?:==|<=|>)\s*0|\b0\s*(?:==|<)", condition):
            continue
        for root, hops, _ in _member_accesses(condition):
            result.add((root, hops))
    return result


def _analyze(unit: SourceUnit, aliases: Set[str]) -> Tuple[DetectorFinding, ...]:
    masked = mask_comments_and_literals(unit.text)
    functions = function_shapes(masked)
    records = []
    for fn in functions:
        body = masked[fn.body_start + 1:fn.body_end - 1]
        typ, roots = _function_identity(fn, aliases)
        if typ and roots:
            records.append((fn, body, typ, roots[0]))
    findings: List[DetectorFinding] = []

    # Infer pointer/count roles without field-name or CVE signatures. The
    # count field participates in a zero-refill guard; sibling state fields
    # are assigned from local values that also appear as adjacent pointer /
    # length arguments to the same call. Header typedef facts bind aggregate
    # parameters whose pointer type is declared outside this translation unit.
    pairs: Set[Tuple[str, Tuple[str, ...], str, Tuple[str, ...], str]] = set()
    types = {typ for _, _, typ, _ in records}
    for typ in types:
        count_paths = {hops for _, body, candidate_type, root in records if candidate_type == typ
                       for guard_root, hops in _zero_guard_paths(body)
                       if guard_root == root and len(hops) >= 2}
        for _, body, candidate_type, root in records:
            if candidate_type != typ:
                continue
            assignments = [(hops, rhs) for _, lhs_root, hops, rhs in _assignments(body)
                           if lhs_root == root and len(hops) >= 2]
            calls = [_simple_arguments(match.group("args")) for match in _CALL.finditer(body)]
            guarded = {hops for guard_root, hops in _zero_guard_paths(body) if guard_root == root}
            for count in count_paths & guarded:
                count_rhs = [rhs for hops, rhs in assignments if hops == count]
                for pointer, pointer_rhs in assignments:
                    if pointer[:-1] != count[:-1] or pointer == count or not re.fullmatch(r"[A-Za-z_]\w*", pointer_rhs):
                        continue
                    for count_value in count_rhs:
                        if not re.fullmatch(r"[A-Za-z_]\w*", count_value):
                            continue
                        if any(any(pointer_rhs in arg[i] and count_value in arg[i + 1]
                                   for i in range(len(arg) - 1)) for arg in calls):
                            pairs.add((typ, pointer[:-1], pointer[-1], count[:-1], count[-1]))

    for typ, parent, pointer_field, count_parent, count_field in pairs:
        for release_fn, release_body, release_type, release_root in records:
            if release_type != typ:
                continue
            release_assigns = list(_assignments(release_body))
            released_state = None
            release_pos = None
            for match, lhs_root, hops, rhs in release_assigns:
                if lhs_root == release_root and rhs.strip() in ("0", "NULL", "nullptr") and hops not in (parent + (pointer_field,), count_parent + (count_field,)):
                    released_state, release_pos = hops, release_fn.body_start + 1 + match.start()
                    break
            if released_state is None:
                continue

            # A direct reset or a direct helper that resets both halves of
            # the pair closes this lexical stale-state candidate.
            callees = {m.group("name") for m in _CALL.finditer(release_body)}
            cleared: Set[Tuple[str, ...]] = set()
            for _, lhs_root, hops, rhs in release_assigns:
                if lhs_root == release_root and rhs.strip() in ("0", "NULL", "nullptr"):
                    cleared.add(hops)
            for callee_fn, callee_body, callee_type, callee_root in records:
                if callee_fn.name not in callees or callee_type != typ:
                    continue
                for _, lhs_root, hops, rhs in _assignments(callee_body):
                    if lhs_root == callee_root and rhs.strip() in ("0", "NULL", "nullptr"):
                        cleared.add(hops)
            if (parent + (pointer_field,) in cleared and count_parent + (count_field,) in cleared):
                continue

            for consumer_fn, consumer_body, consumer_type, consumer_root in records:
                if consumer_type != typ or consumer_fn.name == release_fn.name:
                    continue
                guarded_count = re.search(
                    r"\b(?:if|while)\s*\([^)]*" + _member_pattern(consumer_root, count_parent + (count_field,))
                    + r"\s*(?:==|!=|>|>=)\s*0", consumer_body)
                has_pointer = bool(re.search(_member_pattern(consumer_root, parent + (pointer_field,)), consumer_body))
                local_calls = {m.group("name") for m in _CALL.finditer(consumer_body)
                               if consumer_root in m.group("args")}
                has_consumer_call = bool(local_calls)
                # Resolve one direct local call as a bounded consumer edge:
                # the called helper may dereference the pointer while the
                # caller's count guard controls whether it is invoked.
                if not has_pointer and has_consumer_call:
                    has_pointer = any(
                        callee.name in local_calls and callee_type == typ
                        and bool(re.search(_member_pattern(callee_root, parent + (pointer_field,)), callee_body))
                        for callee, callee_body, callee_type, callee_root in records
                    )
                if not guarded_count or not has_pointer or not has_consumer_call:
                    continue
                line, column = line_column(unit.text, release_pos)
                findings.append(DetectorFinding(
                    file=unit.path, line=line, column=column, rule_id=RULE_STALE_SHARED_INPUT,
                    message=("Candidate only: a shared aggregate has a dynamically inferred input pointer/count pair; "
                             "an owner-state release path leaves the pair uncleared while another path gates refill "
                             "on the count and passes the aggregate to a consumer."),
                    evidence_type="syntax", candidate_cwe="CWE-416", symbol=release_fn.name,
                    evidence_obligations=_OBLIGATIONS, consequence_impact="memory_safety",
                    consequence_cwe="CWE-416", source_sha256=unit.sha256,
                    rule_version=RULE_VERSION, rule_lineage_id=RULE_LINEAGE_ID,
                    identity_quality="partial",
                ))
                break
    unique = {(f.file, f.line, f.rule_id, f.symbol): f for f in findings}
    return tuple(sorted(unique.values(), key=lambda f: (f.file, f.line, f.rule_id)))


def detect_shared_state_candidates(units: Sequence[SourceUnit]) -> Tuple[DetectorFinding, ...]:
    """Run file-local relation checks with typedef facts from selected headers."""
    aliases = pointer_typedefs(units)
    return tuple(finding for unit in units if unit.language in ("c", "cpp")
                 for finding in _analyze(unit, aliases))


class CppSharedStateLifetimeDetector:
    detector_id = "ohscanner.cpp.shared_state_lifetime"
    version = RULE_VERSION
    supported_languages = ("c", "cpp")
    required_facts = ()
    ast_scope = "whole_scope"

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        selected = tuple(u for u in units if u.language in self.supported_languages)
        if not selected:
            return DetectorRun(self.detector_id, self.version, "blocked", limitations=("not_applicable: no C/C++ source.",))
        total = sum(len(u.text.encode("utf-8")) for u in selected)
        if any(len(u.text.encode("utf-8")) > MAX_UNIT_BYTES for u in selected) or total > MAX_TOTAL_BYTES:
            return DetectorRun(self.detector_id, self.version, "failed", limitations=("Selected source exceeds bounded lexical analysis budget.",))
        findings = detect_shared_state_candidates(selected)
        partial = any(u.parse_status != "complete" for u in selected)
        limitations = (
            "Candidate relates lexical refill, owner-state reset and guarded consumer shapes; it does not prove pointer aliasing, frees, call order or path reachability.",
            "Function/type matching is same-translation-unit and supports simple parameter declarations and direct cleanup helpers only.",
        )
        if partial:
            limitations += ("At least one source unit is partial or unparsed; findings remain candidates and empty results remain unknown.",)
        return DetectorRun(self.detector_id, self.version, "blocked" if partial else "completed",
                           analyzed_files=tuple(sorted(u.path for u in selected)),
                           findings=findings, limitations=limitations)
