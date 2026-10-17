"""B-ARK-01 bounded JS/TS/ArkTS security candidate detector."""

from __future__ import annotations

import re
from typing import List, Sequence, Set, Tuple

from src.ohscanner.contracts import (
    DetectorFinding,
    DetectorRun,
    EvidenceObligation,
    ScanContext,
    SourceUnit,
)
from src.ohscanner.detectors.cpp.memory_safety import line_column, mask_comments_and_literals


RULE_DANGEROUS_EVAL = "ohscanner.js.dangerous-eval-candidate-001"
RULE_PATH_TAINT = "ohscanner.js.path-taint-candidate-002"
RULE_COMPONENT_EXPOSURE = "ohscanner.oh.arkts.component-exposure-candidate-003"
RULE_WEBVIEW_BRIDGE = "ohscanner.oh.arkts.webview-bridge-candidate-004"
RULE_NATIVE_BRIDGE = "ohscanner.oh.native-bridge-candidate-005"
RULE_VERSION = "0.1.0"
RULE_LINEAGE_ID = "B-ARK-01:script-security-candidate"

_OBLIGATIONS = (
    EvidenceObligation("entry_and_manifest", "Bind exported Ability/Extension/WebView/N-API entry to real manifest/profile configuration.", "unknown"),
    EvidenceObligation("source_to_sink", "Resolve source, wrapper and sink across modules and runtime dispatch.", "unknown"),
    EvidenceObligation("caller_permission", "Verify caller identity, origin, permission and guard dominance.", "missing"),
    EvidenceObligation("product_build", "Bind language/runtime versions, macros and product build.", "missing"),
    EvidenceObligation("attacker_control", "Show attacker-controlled input or untrusted remote content reaches the sink.", "missing"),
    EvidenceObligation("cia_impact", "Establish concrete confidentiality, integrity or availability impact.", "missing"),
)


def _finding(unit: SourceUnit, position: int, rule: str, symbol: str, message: str, cwe: str) -> DetectorFinding:
    line, column = line_column(unit.text, position)
    return DetectorFinding(
        file=unit.path,
        line=line,
        column=column,
        rule_id=rule,
        message=message,
        evidence_type="syntax",
        candidate_cwe=cwe,
        symbol=symbol,
        evidence_obligations=_OBLIGATIONS,
        consequence_impact="security_boundary",
        consequence_cwe=cwe,
        source_sha256=unit.sha256,
        rule_version=RULE_VERSION,
        rule_lineage_id=RULE_LINEAGE_ID,
        identity_quality="partial",
    )


def _unique(findings: Sequence[DetectorFinding]) -> Tuple[DetectorFinding, ...]:
    seen: Set[Tuple[object, ...]] = set()
    result = []
    for item in findings:
        key = (item.file, item.line, item.column, item.rule_id, item.symbol)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return tuple(sorted(result, key=lambda x: (x.file, x.line, x.column or 0, x.rule_id)))


def _detect_unit(unit: SourceUnit) -> Tuple[List[DetectorFinding], List[str], bool]:
    findings: List[DetectorFinding] = []
    if unit.parse_status != "complete":
        return findings, [f"{unit.path}: script parse is {unit.parse_status}; semantics remain unknown."], False
    masked = mask_comments_and_literals(unit.text)
    for match in re.finditer(r"\b(?:eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"'])", masked):
        findings.append(_finding(
            unit, match.start(), RULE_DANGEROUS_EVAL, "dynamic_execution",
            "Candidate only: dynamic code execution is present; source trust, sandbox and product reachability remain unknown.",
            "CWE-95",
        ))
    source_match = re.search(r"\b(?:req|request|params|query|argv|context|want|event|message)\b[^\n;]{0,80}\b(?:path|file|filename|url)\b", masked, re.I)
    if source_match:
        sinks = re.finditer(r"\b(?:readFile|writeFile|unlink|open|loadUrl|executeJavaScript)\s*\(", masked[source_match.end():])
        for relative in sinks:
            findings.append(_finding(
                unit, source_match.end() + relative.start(), RULE_PATH_TAINT, source_match.group(0),
                "Candidate only: a path-like request value reaches a file/URL sink in the same lexical unit; cross-module taint and permission checks remain unknown.",
                "CWE-22",
            ))
            break
    if re.search(r"export\s+default\s+class\s+[A-Za-z_$][\w$]*\s+extends\s+(?:Ability|Extension)\b", masked):
        findings.append(_finding(
            unit, masked.find("export"), RULE_COMPONENT_EXPOSURE, "component_entry",
            "Candidate only: exported Ability/Extension entry is present; manifest/profile exposure and access control remain unknown.",
            "CWE-749",
        ))
    if re.search(r"\b(?:javaScriptProxy|registerJavaScriptProxy|onMessageEvent)\b", masked) and re.search(r"https?://|loadUrl\s*\(", masked):
        findings.append(_finding(
            unit, 0, RULE_WEBVIEW_BRIDGE, "webview_bridge",
            "Candidate only: WebView bridge/remote content shape is present; origin trust and bridge permission remain unknown.",
            "CWE-749",
        ))
    if re.search(r"\b(?:napi_create_function|napi_define_properties|napi_get_cb_info)\b", masked) and re.search(r"\b(?:memcpy|strcpy|ReadBuffer|ReadRawData)\b", masked):
        findings.append(_finding(
            unit, 0, RULE_NATIVE_BRIDGE, "native_bridge",
            "Candidate only: N-API bridge and memory/Parcel-like operation coexist; parameter length, binding map and runtime reachability remain unknown.",
            "CWE-20",
        ))
    return findings, [
        "Lexical JS/TS/ArkTS analysis only; module graph, types, manifests and runtime dispatch remain unknown.",
        "Candidate presence is not a product vulnerability or permission bypass.",
        "Partial syntax is unknown, never safe.",
    ], True


class ScriptSecurityDetector:
    detector_id = "ohscanner.js_ts.security"
    version = RULE_VERSION
    supported_languages = ("js", "ts", "arkts")
    required_facts = ()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        selected = tuple(unit for unit in units if unit.language in self.supported_languages)
        if not selected:
            return DetectorRun(self.detector_id, self.version, "blocked", limitations=("not_applicable: no JS/TS/ArkTS source.",))
        findings: List[DetectorFinding] = []
        limitations: List[str] = []
        analyzed: List[str] = []
        complete = True
        for unit in sorted(selected, key=lambda item: item.path):
            item_findings, item_limitations, item_complete = _detect_unit(unit)
            findings.extend(item_findings)
            limitations.extend(item_limitations)
            if item_complete:
                analyzed.append(unit.path)
            else:
                complete = False
        return DetectorRun(
            self.detector_id,
            self.version,
            "completed" if complete else "blocked",
            analyzed_files=tuple(sorted(analyzed)),
            findings=_unique(findings),
            limitations=tuple(sorted(set(limitations))),
        )
