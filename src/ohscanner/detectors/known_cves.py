from __future__ import annotations
import re
from typing import List, Tuple
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .cpp.memory_safety import MAX_TOTAL_BYTES, MAX_UNIT_BYTES, line_column, mask_comments_and_literals

DETECTOR_ID = "ohscanner.known_disclosed_cves"
VERSION = "0.11.0"
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

def _finding(unit: SourceUnit, pos: int, rule: str, cve: str, detail: str, cwe: str, impact: str = "availability_or_memory_safety"):
    line, col = line_column(unit.text, pos)
    return DetectorFinding(file=unit.path, line=line, column=col, rule_id=rule,
        message=f"Candidate component-code match for {cve}: {detail} Product reachability and vulnerability status remain unconfirmed.",
        evidence_type="syntax", candidate_cwe=cwe, symbol=cve, evidence_obligations=OBLIGATIONS,
        consequence_impact=impact, consequence_cwe=cwe,
        source_sha256=unit.sha256, rule_version=VERSION, rule_lineage_id=LINEAGE,
        symbol_identity=cve, identity_quality="partial")

def _scan(unit: SourceUnit):
    t = unit.text; s = mask_comments_and_literals(t); out = []
    # CVE-2026-25850: external storage mounts must not recursively widen
    # permissions to 0777. The source identity and the affected mount methods
    # keep this rule tied to the reviewed component behavior; product build,
    # filesystem selection, and attacker reachability remain obligations.
    source_path = unit.path.replace("\\", "/")
    if source_path.endswith("services/storage_daemon/volume/src/external_volume_info.cpp"):
        for method in ("DoMount4Ext", "DoMount4Hmfs"):
            mount = _body(s, method)
            if not mount:
                continue
            start, body = mount
            mode = re.search(r"\bmode_t\s+mode\s*=\s*0777\b", body)
            chmod = re.search(r"\bTravelChmod\s*\(\s*mountPath_\s*,\s*mode\s*\)", body)
            if mode and chmod:
                out.append(_finding(
                    unit, start + 1 + chmod.start(),
                    "ohknowncve-storage-cve-2026-25850", "CVE-2026-25850",
                    f"{method} recursively assigns mode 0777 to the mounted external-volume tree; the upstream fix removes this permission widening.",
                    "CWE-732", impact="confidentiality",
                ))
    # CVE-2025-9900: only inspect the public wrapper body. The old expression
    # subtracts image height from raster height before passing a shifted raster
    # pointer to TIFFRGBAImageGet; another function's nearby bounds checks must
    # not suppress this candidate. Keep old-shape matches even when local guards
    # are present: guard/path reasoning is outside this lexical rule and belongs
    # in review.
    oriented = _body(s, "TIFFReadRGBAImageOriented")
    if oriented:
        oriented_start, oriented_body = oriented
        offset = re.search(
            r"TIFFRGBAImageGet\s*\(\s*&img\s*,\s*raster\s*\+\s*"
            r"\(\s*rheight\s*-\s*img\.height\s*\)\s*\*\s*rwidth\s*,\s*"
            r"rwidth\s*,\s*img\.height\s*\)",
            oriented_body,
            re.S,
        )
        if offset:
            out.append(_finding(
                unit, oriented_start + 1 + offset.start(),
                "ohknowncve-libtiff-cve-2025-9900", "CVE-2025-9900",
                "TIFFReadRGBAImageOriented shifts raster by (rheight - img.height) before decoding; when caller raster height is smaller than image height, this can underflow the destination pointer. Product reachability and exploitability remain unverified.",
                "CWE-787",
            ))
    # CVE-2026-67216: recursive object comparison plus repeated linear matching.
    body = _body(s, "cJSON_Compare")
    if body:
        start, b = body
        if len(re.findall(r"\bcJSON_Compare\s*\(", b)) >= 2 and "get_object_item" in b and "cJSON_ArrayForEach" in b:
            out.append(_finding(unit, start, "ohknowncve-cjson-cve-2026-67216", "CVE-2026-67216", "cJSON_Compare recursively compares object pairs and repeats linear key lookups.", "CWE-407"))
    # CVE-2025-57052: the loop's upper-bound check accidentally references
    # pointer[0] instead of pointer[position], so a digit-leading token can
    # continue consuming non-digit bytes as array-index digits.
    array_index = _body(s, "decode_array_index_from_pointer")
    if array_index:
        index_start, index_body = array_index
        loop = re.search(
            r"for\s*\(\s*position\s*=\s*0\s*;"
            r"[^;]*pointer\s*\[\s*position\s*\][^;]*&&"
            r"[^;]*pointer\s*\[\s*0\s*\][^;]*;\s*position\s*\+\+\s*\)",
            index_body,
            re.S,
        )
        accumulates_index = re.search(
            r"parsed_index\s*=\s*\([^;]*parsed_index[^;]*pointer\s*\[\s*position\s*\]",
            index_body,
            re.S,
        )
        if loop and accumulates_index:
            out.append(_finding(
                unit, index_start + 1 + loop.start(),
                "ohknowncve-cjson-cve-2025-57052", "CVE-2025-57052",
                "decode_array_index_from_pointer checks pointer[0] for every loop iteration, allowing a digit-leading JSON Pointer array index to consume non-digit bytes.",
                "CWE-129",
            ))
    # CVE-2026-9079: clearing CURLOPT_PROXYUSERPWD with NULL must clear
    # both stored credential fields even though the parsed u/p values are NULL.
    # Old code freed each field only inside its matching non-NULL component branch.
    setopt = _body(s, "setopt_cptr_proxy")
    if setopt:
        setopt_start, setopt_body = setopt
        proxy_case = re.search(
            r"case\s+CURLOPT_PROXYUSERPWD\s*:\s*\{?(.*?)(?=case\s+CURLOPT_PROXYUSERNAME\s*:)",
            setopt_body,
            re.S,
        )
        if proxy_case:
            block = proxy_case.group(1)
            stale_user = re.search(
                r"if\s*\(\s*!result\s*&&\s*u\s*\)\s*\{\s*"
                r"(?:Curl|curlx)_safefree\s*\(\s*data->set\.str\[STRING_PROXYUSERNAME\]\s*\)",
                block,
            )
            stale_password = re.search(
                r"if\s*\(\s*!result\s*&&\s*p\s*\)\s*\{\s*"
                r"(?:Curl|curlx)_safefree\s*\(\s*data->set\.str\[STRING_PROXYPASSWORD\]\s*\)",
                block,
            )
            if stale_user or stale_password:
                out.append(_finding(
                    unit, setopt_start + 1 + proxy_case.start(),
                    "ohknowncve-curl-cve-2026-9079", "CVE-2026-9079",
                    "CURLOPT_PROXYUSERPWD credential replacement clears a stored field only when its new parsed component is non-NULL; setting the option to NULL can leave a previous proxy credential available to a later transfer.",
                    "CWE-522",
                ))
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
    # CVE-2026-33636: ARM NEON palette expansion must only process full
    # vector chunks and must restore the pre-adjusted destination pointer
    # before handing the unprocessed tail to the scalar caller.
    for name, chunk, load_shape, store_shape in (
        ("png_do_expand_palette_rgba8_neon", 4, r"sp\s*-\s*3", r"vst1q_u32\s*\("),
        ("png_do_expand_palette_rgb8_neon", 8, r"sp\s*-\s*7", r"vst3_u8\s*\("),
    ):
        neon = _body(s, name)
        if not neon:
            continue
        neon_start, neon_body = neon
        chunk_size = re.search(
            rf"pixels_per_chunk\s*=\s*{chunk}\s*;", neon_body)
        tail_loop = re.search(
            r"for\s*\(\s*i\s*=\s*0\s*;\s*i\s*<\s*row_width\s*;"
            r"\s*i\s*\+=\s*pixels_per_chunk\s*\)", neon_body)
        vector_read = bool(re.search(load_shape, neon_body)
                           and re.search(r"vld[13][A-Za-z0-9_]*\s*\(", neon_body))
        vector_write = bool(re.search(store_shape, neon_body))
        preadjust = bool(re.search(
            r"\*ddp\s*=\s*\*ddp\s*-\s*\([^;]*pixels_per_chunk[^;]*\)", neon_body))
        pointer_restore = bool(re.search(
            r"\*ddp\s*=\s*\*ddp\s*\+\s*\([^;]*pixels_per_chunk[^;]*\)", neon_body))
        unsafe_tail = bool(chunk_size and tail_loop and vector_read and vector_write)
        unsafe_handoff = preadjust and not pointer_restore and vector_write
        if unsafe_tail or unsafe_handoff:
            if unsafe_tail and unsafe_handoff:
                detail = (f"{name} processes a partial {chunk}-pixel NEON chunk and fails to restore its "
                          "pre-adjusted destination pointer before scalar tail handling.")
            elif unsafe_tail:
                detail = f"{name} processes a partial {chunk}-pixel NEON chunk at the row tail."
            else:
                detail = f"{name} does not restore its pre-adjusted destination pointer before scalar tail handling."
            out.append(_finding(
                unit, neon_start,
                "ohknowncve-libpng-cve-2026-33636", "CVE-2026-33636",
                detail + " On affected ARM/AArch64 builds this can cause out-of-bounds reads/writes; product build and input reachability remain unverified.",
                "CWE-119",
            ))
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
    # CVE-2026-27648: Flowbuffer decoding must bound both the byte range in
    # shared memory and the destination vector index. A local match remains
    # candidate-only; build/version and remote input reachability are external.
    flowbuf = _body(s, "FlowbufStrAtIndex")
    result_flowbuf = _body(s, "ProcessNativeProxyResultNewFlowbuf")
    if flowbuf and result_flowbuf:
        flow_pos, flow_body = flowbuf
        result_pos, result_body = result_flowbuf
        reads_entry = ("*strLen" in flow_body and "header" in flow_body
                       and "INDEX_SIZE" in flow_body and "offset" in flow_body)
        byte_range_bounded = bool(re.search(
            r"(?:offset\s*\+\s*\*strLen|\*strLen\s*\+\s*offset)"
            r"\)?\s*>\s*MAX_FLOWBUF_DATA_SIZE", flow_body))
        sized_destination = bool(re.search(
            r"dataList\s*\([^;]*argsSize\s*\+\s*"
            r"static_cast\s*<\s*size_t\s*>\s*\(\s*flowbufSize\s*\)", result_body))
        writes_destination = bool(re.search(r"dataList\s*\[\s*curIndex\s*\]\s*=", result_body))
        unbounded_loops = list(re.finditer(
            r"while\s*\(\s*argIndex\s*==\s*curIndex\s*\)", result_body))
        unsafe_byte_range = reads_entry and not byte_range_bounded
        unsafe_destination_index = sized_destination and writes_destination and bool(unbounded_loops)
        if unsafe_byte_range or unsafe_destination_index:
            if unsafe_byte_range and unsafe_destination_index:
                detail = ("Flowbuffer decoding has an unchecked shared-memory offset/length, and result reconstruction "
                          "writes dataList[curIndex] without a destination-size loop bound.")
            elif unsafe_byte_range:
                detail = "Flowbuffer decoding has an unchecked shared-memory offset/length."
            else:
                detail = "Flowbuffer result reconstruction writes dataList[curIndex] without a destination-size loop bound."
            finding_pos = (result_pos + 1 + unbounded_loops[0].start()
                           if unsafe_destination_index else flow_pos)
            out.append(_finding(
                unit, finding_pos,
                "ohknowncve-webview-cve-2026-27648", "CVE-2026-27648",
                detail,
                "CWE-787",
            ))
    # CVE-2022-45877: the affected device-manager flow put the PIN in the
    # auth response token that is serialized and sent through SoftBus. Require
    # the same function body and the complete serialization/send sequence;
    # mere PIN key or transport references are insufficient.
    group_created = _body(s, "OnGroupCreated")
    if group_created:
        group_start, group_body = group_created
        pin_in_token = bool(re.search(
            r"jsonObj\s*\[\s*PIN_CODE_KEY\s*\]\s*=\s*pinCode\s*;",
            group_body,
        ))
        token_marker = bool(re.search(
            r"jsonObj\s*\[\s*PIN_TOKEN\s*\]\s*=\s*authResponseContext_->token\s*;",
            group_body,
        ))
        serialized_auth_token = bool(re.search(
            r"authResponseContext_->authToken\s*=\s*jsonObj\.dump\s*\(\s*\)\s*;",
            group_body,
        ))
        sent_auth_response = bool(re.search(
            r"SetResponseContext\s*\(\s*authResponseContext_\s*\)\s*;[\s\S]{0,500}?"
            r"CreateSimpleMessage\s*\(\s*MSG_TYPE_RESP_AUTH\s*\)[\s\S]{0,400}?"
            r"SendData\s*\(\s*authResponseContext_->sessionId\s*,\s*message\s*\)",
            group_body,
        ))
        if pin_in_token and token_marker and serialized_auth_token and sent_auth_response:
            pos = group_start + 1 + re.search(
                r"jsonObj\s*\[\s*PIN_CODE_KEY\s*\]\s*=\s*pinCode\s*;", group_body
            ).start()
            out.append(_finding(
                unit, pos,
                "ohknowncve-device-manager-cve-2022-45877", "CVE-2022-45877",
                "DmAuthManager::OnGroupCreated serializes PIN_CODE_KEY into authToken and sends the authentication response through SoftBus. This is a component-source candidate; product version, build inclusion, peer visibility, and impact are not established.",
                "CWE-319", impact="sensitive_data_exposure",
            ))
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
