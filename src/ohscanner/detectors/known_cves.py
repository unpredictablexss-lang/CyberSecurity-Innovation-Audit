from __future__ import annotations
import re
from typing import List, Tuple
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .cpp.memory_safety import MAX_TOTAL_BYTES, MAX_UNIT_BYTES, line_column, mask_comments_and_literals

DETECTOR_ID = "ohscanner.known_disclosed_cves"
VERSION = "0.3.0"
LINEAGE = "OH-KNOWN-CVE:component-source-signatures"
OBLIGATIONS = (
    EvidenceObligation("component_identity", "Bind source to exact built component/version.", "missing"),
    EvidenceObligation("product_build", "Confirm component is included in target product build.", "missing"),
    EvidenceObligation("attacker_path", "Trace attacker-controlled input to the vulnerable API/path.", "missing"),
    EvidenceObligation("impact", "Verify product impact with controlled evidence.", "missing"),
)

def _body(text: str, name: str):
    # Match definitions only, not an earlier call or prototype followed by a
    # different function body.
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\([^;{}]*?\)\s*\{")
    for m in pattern.finditer(text):
        opening = m.end() - 1
        depth = 0
        for i in range(opening, len(text)):
            if text[i] == "{": depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0: return opening, text[opening + 1:i]
    return None

def _finding(unit: SourceUnit, pos: int, rule: str, cve: str, detail: str, cwe: str):
    line, col = line_column(unit.text, pos)
    return DetectorFinding(file=unit.path, line=line, column=col, rule_id=rule,
        message=f"Candidate component-code match for {cve}: {detail} Product reachability and vulnerability status remain unconfirmed.",
        evidence_type="syntax", candidate_cwe=cwe, symbol=cve, evidence_obligations=OBLIGATIONS,
        consequence_impact="availability_or_memory_safety", consequence_cwe=cwe,
        source_sha256=unit.sha256, rule_version=VERSION, rule_lineage_id=LINEAGE,
        symbol_identity=cve, identity_quality="partial")

def _scan(unit: SourceUnit):
    t = unit.text; s = mask_comments_and_literals(t); out = []
    # CVE-2025-9900: vulnerable libtiff offset is computed before dimension validation.
    pat = re.compile(r"TIFFRGBAImageGet\s*\(\s*&img\s*,\s*raster\s*\+\s*\(\s*rheight\s*-\s*img\.height\s*\)\s*\*\s*rwidth", re.S)
    for m in pat.finditer(s):
        prefix = s[max(0, m.start()-1500):m.start()]
        if not (re.search(r"rwidth\s*[<>=!]+\s*img\.width", prefix) and re.search(r"rheight\s*[<>=!]+\s*img\.height", prefix)):
            out.append(_finding(unit, m.start(), "ohknowncve-libtiff-cve-2025-9900", "CVE-2025-9900", "TIFFRGBAImageOriented offsets raster using unchecked image dimensions.", "CWE-787"))
    # CVE-2026-67216: recursive object comparison plus repeated linear matching.
    body = _body(s, "cJSON_Compare")
    if body:
        start, b = body
        if len(re.findall(r"\bcJSON_Compare\s*\(", b)) >= 2 and "get_object_item" in b and "cJSON_ArrayForEach" in b:
            out.append(_finding(unit, start, "ohknowncve-cjson-cve-2026-67216", "CVE-2026-67216", "cJSON_Compare recursively compares object pairs and repeats linear key lookups.", "CWE-407"))
    # CVE-2026-92391: owned subpart cleanup re-enters recursive mime free.
    cleaner = _body(s, "cleanup_part_content"); recursive = _body(s, "mime_subparts_free")
    freer = _body(s, "curl_mime_free"); setter = _body(s, "Curl_mime_set_subparts")
    if cleaner and recursive and freer and setter:
        pos, rb = recursive; cb = cleaner[1]; fb = freer[1]; sb = setter[1]
        path_text = rb + cb + fb + sb
        bounded_depth = bool(re.search(r"(?:depth|nest(?:ing)?_level)[^;{}]{0,120}(?:>|>=|MAX|LIMIT)", path_text, re.I)
                             or re.search(r"(?:MAX|LIMIT)[A-Z0-9_]*(?:MIME|NEST|DEPTH)", path_text, re.I))
        if ("curl_mime_free" in rb and re.search(r"freefunc\s*\([^)]*->arg\)", cb) and "Curl_mime_cleanpart(part)" in fb
                and "while" in fb and "mime_subparts_free" in sb and "take_ownership" in sb and not bounded_depth):
            out.append(_finding(unit, pos, "ohknowncve-curl-cve-2026-92391", "CVE-2026-92391", "owned nested MIME cleanup re-enters curl_mime_free without a visible depth bound.", "CWE-674"))
    # CVE-2026-46675: source version identity is useful when upstream source is
    # vendored. It is a version match only; package composition/reachability are obligations.
    for vm in re.finditer(r"PNG_LIBPNG_VER_STRING\s+\"(\d+)\.(\d+)\.(\d+)\"", t):
        if "PNG_LIBPNG_VER_STRING" not in s[vm.start():vm.end()]:
            continue  # Ignore a matching comment.
        version = tuple(int(part) for part in vm.groups())
        if (1, 6, 0) <= version <= (1, 6, 58):
            out.append(_finding(unit, vm.start(), "ohknowncve-libpng-cve-2026-46675", "CVE-2026-46675", f"vendored libpng version {'.'.join(vm.groups())} is within the disclosed affected range.", "CWE-416"))
    # CVE-2026-46675: per-function consumer sequence required by the advisory.
    for m in re.finditer(r"\b[A-Za-z_]\w*\s*\([^;{}]*\)\s*\{", s):
        start = s.find("{", m.start()); depth = 1; end = start + 1
        while end < len(s) and depth:
            depth += (s[end] == "{") - (s[end] == "}"); end += 1
        if depth: continue
        b = s[start+1:end-1]; info = re.search(r"\bpng_read_info\s*\(", b); finish = re.search(r"\bpng_read_end\s*\(", b)
        row = re.search(r"\b(?:png_read_row|png_read_rows|png_read_image|png_start_read_image)\s*\(", b)
        if info and finish and info.start() < finish.start() and not row:
            out.append(_finding(unit, start+1+finish.start(), "ohknowncve-libpng-cve-2026-46675", "CVE-2026-46675", "png_read_end follows png_read_info without reading image rows.", "CWE-416"))
    # CVE-2025-25212: observer registrations can accumulate without a
    # per-process quota. Lifecycle and Binder caller reachability remain
    # outside this local signature, so every match is a candidate.
    observer = _body(s, "AddPasteboardChangedObserver")
    if observer:
        pos, b = observer
        inserts = re.search(r"(?:observers|observerMap_)\s*(?:->|\.)\s*(?:insert|emplace|push_back)", b)
        process_key = re.search(r"(?:GetCallingPid|GetCallingTokenID|GetCallingUid)", b)
        quota = re.search(r"(?:size\s*\(\)\s*(?:>=|>)|(?:MAX|LIMIT|QUOTA)[A-Z0-9_]*|\b(?:max|limit|quota)\w*\b)", b, re.I)
        if inserts and not process_key and not quota:
            out.append(_finding(unit, pos, "ohknowncve-pasteboard-cve-2025-25212", "CVE-2025-25212", "pasteboard observer registration inserts into a shared collection without a visible per-process quota.", "CWE-770"))
    # CVE-2026-67215: untrusted JSON Patch can amplify nesting through deep
    # add/copy operations, then hit recursive cJSON_Delete cleanup. A local
    # shape match cannot prove that the file is built or fed untrusted input.
    apply_one = _body(s, "apply_patch")
    apply_many = _body(s, "cJSONUtils_ApplyPatches") or _body(s, "cJSONUtils_ApplyPatchesCaseSensitive")
    if apply_one and apply_many:
        pos, ab = apply_one
        mb = apply_many[1]
        bounded = bool(re.search(r"(?:depth|nest(?:ing)?_level)[^;{}]{0,120}(?:>|>=|MAX|LIMIT)", ab, re.I)
                       or re.search(r"(?:MAX|LIMIT)[A-Z0-9_]*(?:JSON|PATCH|DEPTH|NEST)", ab, re.I))
        if ("cJSON_Duplicate" in ab and re.search(r"cJSON_Duplicate\s*\([^;]*,\s*1\s*\)", ab)
                and "cJSON_Delete" in ab and "apply_patch" in mb and "while" in mb and not bounded):
            out.append(_finding(unit, pos, "ohknowncve-cjson-cve-2026-67215", "CVE-2026-67215", "JSON Patch deep-copy and cleanup path has no visible nesting bound before recursive cJSON deletion.", "CWE-674"))
    # CVE-2025-27247: the old pasteboard Binder dispatch exposed GetPasteData
    # without a service-side read permission check. A source-local match is
    # only a candidate because enforcement may live outside this file.
    dispatch = _body(s, "OnRemoteRequest")
    mapping = _body(s, "PasteboardServiceStub")
    handler = _body(s, "OnGetPasteData")
    if dispatch and mapping and handler:
        pos, db = dispatch
        mb = mapping[1]
        hb = handler[1]
        mapped = "memberFuncMap_" in mb and "OnGetPasteData" in mb and "GET_PASTE_DATA" in mb
        routed = "memberFuncMap_" in db and "memberFuncMap_.find" in db
        reads_and_returns = "GetPasteData" in hb and "WriteParcelable" in hb
        guarded = bool(re.search(r"(?:Check\w*Permission|Verify\w*Permission|Enforce\w*Permission|PermissionManager|CheckPermission)", db + hb, re.I))
        if mapped and routed and reads_and_returns and not guarded:
            out.append(_finding(unit, pos, "ohknowncve-pasteboard-cve-2025-27247", "CVE-2025-27247", "Binder GET_PASTE_DATA dispatch returns paste data without a visible permission check in the dispatch or handler.", "CWE-862"))
    return tuple(out)

class KnownDisclosedCveDetector:
    detector_id = DETECTOR_ID
    version = VERSION
    supported_languages = ("c", "cpp")
    required_facts = ()
    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        del context
        selected = tuple(sorted((u for u in units if u.language in self.supported_languages), key=lambda u: u.path))
        if not selected:
            return DetectorRun(self.detector_id, self.version, "blocked", limitations=("not_applicable: no C/C++ source supplied.",))
        if sum(len(u.text.encode("utf-8")) for u in selected) > MAX_TOTAL_BYTES:
            return DetectorRun(self.detector_id, self.version, "failed", limitations=("Selected source exceeds detector run budget.",))
        findings=[]; analyzed=[]; limitations=[]; complete=True
        for u in selected:
            if len(u.text.encode("utf-8")) > MAX_UNIT_BYTES:
                complete=False; limitations.append(f"{u.path}: source exceeds 1MiB unit budget; coverage remains unknown."); continue
            # Narrow lexical CVE signatures can still preserve evidence from a
            # partial AST. The run remains blocked and never turns the rest of
            # the unit into a negative/safe result.
            findings.extend(_scan(u))
            analyzed.append(u.path)  # inspected; blocked run maps incomplete inputs to partial coverage
            if u.parse_status != "complete":
                complete=False
                limitations.append(f"{u.path}: parse_status={u.parse_status}; lexical matches are retained but remaining coverage is unknown.")
        unique={(f.file,f.line,f.rule_id,f.source_sha256):f for f in findings}
        return DetectorRun(self.detector_id, self.version, "completed" if complete else "blocked",
            analyzed_files=tuple(analyzed), findings=tuple(sorted(unique.values(),key=lambda f:(f.file,f.line,f.rule_id))),
            limitations=tuple(sorted(set(limitations))))
