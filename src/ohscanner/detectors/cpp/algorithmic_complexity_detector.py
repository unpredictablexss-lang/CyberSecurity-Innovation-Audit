"""Conservative, file-local candidates for recursive algorithmic exhaustion.

This lexical prototype recognizes structural relationships only. It does not
prove asymptotic bounds, attacker control, reachability, or product exposure.
"""
from __future__ import annotations

import re
from typing import List, Sequence, Tuple

from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .memory_safety import MAX_TOTAL_BYTES, MAX_UNIT_BYTES, function_shapes, line_column, mask_comments_and_literals

RULE_RECURSIVE_LOOKUP = "ohcpp-algorithmic-recursive-lookup-candidate-001"
RULE_RECURSIVE_GROWTH = "ohcpp-algorithmic-recursive-growth-cleanup-candidate-002"
RULE_VERSION = "0.1.0"
RULE_LINEAGE_ID = "A-D3-01:recursive-complexity-candidate"
_LOOP = re.compile(r"\b(?:for|while)\s*\(")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_DEPTH_GUARD = re.compile(r"\b(?:depth|level|nesting)\w*\s*(?:>=|>)\s*(?:\d+|[A-Z_]\w*)|\b(?:\d+|[A-Z_]\w*)\s*(?:<=|<)\s*(?:depth|level|nesting)\w*", re.I)
_ALLOC = re.compile(r"\b(?:malloc|calloc|realloc|strdup|new)\s*(?:\(|\[)")
_RELEASE = re.compile(r"\b(?:free|delete|destroy\w*|release\w*)\s*(?:\(|\b)")
_OBLIGATIONS = (
    EvidenceObligation("algorithm_model", "Prove the input-size recurrence and establish that repeated lookup multiplies recursive traversal cost.", "unknown"),
    EvidenceObligation("recursive_depth_bound", "Resolve effective input and recursion-depth limits, including indirect guards.", "unknown"),
    EvidenceObligation("attacker_control", "Establish control over the compared or expanded data structure and trigger.", "missing"),
    EvidenceObligation("entry_and_build_context", "Verify the candidate is reachable in the affected product build and configuration.", "missing"),
    EvidenceObligation("availability_impact", "Reproduce bounded CPU, memory, or stack exhaustion and its process impact.", "missing"),
)


def _inside_loop(text: str, position: int) -> bool:
    # Lexical scope approximation: loop body begins at the next brace or the
    # next semicolon, and ends at its matching brace / semicolon.
    for match in _LOOP.finditer(text):
        # Skip the complete for/while header; its semicolons are not body
        # delimiters.
        depth = 1
        close = match.end()
        while close < len(text) and depth:
            if text[close] == "(": depth += 1
            elif text[close] == ")": depth -= 1
            close += 1
        brace = text.find("{", close)
        semi = text.find(";", close)
        if semi >= 0 and (brace < 0 or semi < brace):
            if close <= position <= semi:
                return True
            continue
        if brace >= 0:
            depth = 0
            for i in range(brace, len(text)):
                if text[i] == "{": depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        if brace < position < i:
                            return True
                        break
    return False


def _calls(text: str) -> Tuple[str, ...]:
    return tuple(m.group(1) for m in _CALL.finditer(text) if m.group(1) not in {"if", "for", "while", "switch", "sizeof", "return"})


def _analyze(unit: SourceUnit) -> Tuple[DetectorFinding, ...]:
    masked = mask_comments_and_literals(unit.text)
    funcs = function_shapes(masked)
    by_name = {f.name: f for f in funcs}
    found: List[DetectorFinding] = []

    def emit(rule: str, shape, offset: int, explanation: str) -> None:
        line, col = line_column(unit.text, offset)
        found.append(DetectorFinding(
            file=unit.path, line=line, column=col, rule_id=rule,
            message=explanation, evidence_type="syntax", candidate_cwe="CWE-674",
            symbol=shape.name, evidence_obligations=_OBLIGATIONS,
            consequence_impact="availability_exhaustion", consequence_cwe="CWE-674",
            source_sha256=unit.sha256, rule_version=RULE_VERSION,
            rule_lineage_id=RULE_LINEAGE_ID, identity_quality="partial",
        ))

    for shape in funcs:
        body = masked[shape.body_start:shape.body_end]
        recursive = bool(re.search(r"\b" + re.escape(shape.name) + r"\s*\(", body))
        if not recursive or _DEPTH_GUARD.search(body):
            continue
        # Repeated linear lookup inside a recursive loop. Require a locally
        # defined helper with a loop to avoid function-name/CVE heuristics.
        for call in _CALL.finditer(body):
            helper = by_name.get(call.group(1))
            if helper is None or helper.name == shape.name or not _inside_loop(body, call.start()):
                continue
            helper_body = masked[helper.body_start:helper.body_end]
            if _LOOP.search(helper_body):
                recursive_call = re.search(r"\b" + re.escape(shape.name) + r"\s*\(", body)
                if recursive_call:
                    emit(RULE_RECURSIVE_LOOKUP, shape, shape.body_start + call.start(),
                         "Recursive traversal invokes a local loop-based lookup from a loop; multiplicative algorithmic cost is a candidate requiring recurrence and input-control review.")
                    break

        # Recursive expansion plus recursive teardown in one translation unit.
        alloc_pos = _ALLOC.search(body)
        grows_by_recursing = recursive and alloc_pos and bool(re.search(r"(?:->|\.)\s*\w+\s*=\s*" + re.escape(shape.name) + r"\s*\(", body))
        if grows_by_recursing:
            for cleanup in funcs:
                if cleanup.name == shape.name:
                    continue
                clean_body = masked[cleanup.body_start:cleanup.body_end]
                if (re.search(r"\b" + re.escape(cleanup.name) + r"\s*\(", clean_body)
                        and _RELEASE.search(clean_body)
                        and re.search(r"\b" + re.escape(cleanup.name) + r"\s*\([^;]*(?:->|\.)\s*\w+", clean_body)):
                    # Require a repeated caller of the copy routine as a weak
                    # tree-expansion cue; report the local recursive allocator.
                    for caller in funcs:
                        caller_body = masked[caller.body_start:caller.body_end]
                        copy_calls = list(re.finditer(r"\b" + re.escape(shape.name) + r"\s*\(", caller_body))
                        if caller.name != shape.name and len(copy_calls) >= 1 and _inside_loop(caller_body, copy_calls[0].start()):
                            emit(RULE_RECURSIVE_GROWTH, shape, shape.body_start + alloc_pos.start(),
                                 "Recursive node allocation/linking is paired with a recursive release routine and loop-driven repeated copying; tree growth and cleanup exhaustion are candidates, not proven impacts.")
                            break
                    else:
                        continue
                    break
    # Stable unique findings.
    return tuple({(f.rule_id, f.file, f.line, f.symbol): f for f in found}.values())


class CppAlgorithmicComplexityDetector:
    detector_id = "ohscanner.cpp.algorithmic_complexity"
    version = RULE_VERSION
    supported_languages = ("c", "cpp")
    required_facts = ()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        selected = tuple(u for u in units if u.language in self.supported_languages)
        if not selected:
            return DetectorRun(self.detector_id, self.version, "blocked", limitations=("not_applicable: no supported source.",))
        if any(len(u.text.encode("utf-8")) > MAX_UNIT_BYTES for u in selected) or sum(len(u.text.encode("utf-8")) for u in selected) > MAX_TOTAL_BYTES:
            return DetectorRun(self.detector_id, self.version, "failed", limitations=("Selected source exceeds lexical analysis budget.",))
        findings: List[DetectorFinding] = []
        for unit in selected:
            findings.extend(_analyze(unit))
        partial = any(u.parse_status != "complete" for u in selected)
        limitations = ("Static lexical candidates do not establish complexity, attacker control, reachability, or exhaustion.",)
        if partial:
            limitations += ("At least one source unit is partial or unparsed; absence of a finding is unknown.",)
        return DetectorRun(self.detector_id, self.version, "blocked" if partial else "completed",
                           # Lexical inspection can preserve a bounded candidate
                           # from a partial translation unit. Runner requires every
                           # partially inspected path to be listed here; aggregate
                           # blocked status still keeps the file unknown.
                           analyzed_files=tuple(sorted(u.path for u in selected)),
                           findings=tuple(sorted(findings, key=lambda f: (f.file, f.line, f.rule_id))), limitations=limitations)
