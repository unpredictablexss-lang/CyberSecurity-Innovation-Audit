from __future__ import annotations
import re
from typing import List, Tuple
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .cpp.memory_safety import MAX_TOTAL_BYTES, MAX_UNIT_BYTES, line_column, mask_comments_and_literals

DETECTOR_ID = "ohscanner.known_disclosed_cves"
VERSION = "0.15.0"
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

def _curl_version(units):
    """Return one source-declared libcurl version; disagreement stays unknown."""
    versions = set()
    for unit in units:
        path = unit.path.replace("\\", "/")
        if not (path.endswith("include/curl/curlver.h") or path.endswith("/curlver.h")):
            continue
        match = re.search(
            r'^\s*#\s*define\s+LIBCURL_VERSION\s+"(\d+)\.(\d+)\.(\d+)(?:[-+][^" ]*)?"',
            unit.text, re.M,
        )
        if match:
            versions.add(tuple(map(int, match.groups())))
    if len(versions) == 1:
        return next(iter(versions)), False
    return None, len(versions) > 1


def _curl_92392_affected(version):
    if version is None:
        return None
    if version < (8, 12, 0) or version > (8, 22, 0):
        return False
    # curl publishes fixed backports on the 8.14.x, 8.16.x and 8.20.x lines.
    if version[:2] == (8, 14) and version >= (8, 14, 3):
        return False
    if version[:2] == (8, 16) and version >= (8, 16, 2):
        return False
    if version[:2] == (8, 20) and version >= (8, 20, 2):
        return False
    return True


def _scan(unit: SourceUnit, curl_version=None):
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
    # CVE-2026-28733: StorageDaemonStub returns an opStatistics_ map iterator
    # after GetUserStatistics releases its lock. The radar thread can clear the
    # same map in GetTempStatistics before a handler dereferences that iterator.
    # A mutex inside both helpers does not protect the iterator's lifetime.
    if source_path.endswith("services/storage_daemon/ipc/src/storage_daemon_stub.cpp"):
        getter = _body(s, "GetUserStatistics")
        snapshot = _body(s, "GetTempStatistics")
        if getter and snapshot:
            getter_start, getter_body = getter
            snapshot_start, snapshot_body = snapshot
            returns_iterator = (
                "std::map<uint32_t, RadarStatisticInfo>::iterator"
                in s[max(0, getter_start - 140):getter_start]
                and "opStatistics_.find" in getter_body
                and "return it;" in getter_body
                and "opStatistics_.insert" in getter_body
            )
            clears_shared_map = (
                "opStatistics_.begin()" in snapshot_body
                and "opStatistics_.end()" in snapshot_body
                and "opStatistics_.clear()" in snapshot_body
            )
            callers = [
                match for match in re.finditer(
                    r"\bauto\s+(\w+)\s*=\s*GetUserStatistics\s*\([^;]*\);", s
                )
                if re.search(
                    r"\b" + re.escape(match.group(1)) + r"\s*->\s*second\s*\.",
                    s[match.end():match.end() + 1600],
                )
            ]
            if returns_iterator and clears_shared_map and callers:
                clear_pos = snapshot_body.find("opStatistics_.clear()")
                out.append(_finding(
                    unit, snapshot_start + 1 + clear_pos,
                    "ohknowncve-storage-cve-2026-28733", "CVE-2026-28733",
                    "GetUserStatistics returns an opStatistics_ iterator after its internal lock is released; a caller later dereferences it while GetTempStatistics clears the same map. This iterator-lifetime gap remains in the linked upstream mutex patch and requires concurrency review.",
                    "CWE-416",
                ))
    # CVE-2026-28751: a full-length xattr result leaves a capacity-sized
    # buffer unterminated when the code accepts only len < capacity, then uses
    # it as a C string. The extra-byte allocation and <= guard are the upstream
    # repair shape; product reachability remains an evidence obligation.
    if source_path.endswith("services/storage_manager/volume/src/volume_manager_service.cpp"):
        mtp = _body(s, "NotifyMtpMounted")
        if mtp:
            mtp_start, mtp_body = mtp
            exact_capacity_alloc = re.search(
                r"malloc\s*\(\s*sizeof\s*\(\s*char\s*\)\s*\*\s*MTP_DEVICE_NAME_LEN\s*\)",
                mtp_body,
            )
            bounded_xattr = re.search(
                r"getxattr\s*\([^;]*MTP_DEVICE_NAME_LEN\s*\)", mtp_body, re.S
            )
            strict_bound = re.search(
                r"len\s*>=\s*0\s*&&\s*len\s*<\s*MTP_DEVICE_NAME_LEN", mtp_body
            )
            terminates_only_under_strict_bound = re.search(
                r"if\s*\(\s*len\s*>=\s*0\s*&&\s*len\s*<\s*MTP_DEVICE_NAME_LEN\s*\)\s*\{[^{}]*value\s*\[\s*len\s*\]\s*=",
                mtp_body,
                re.S,
            )
            c_string_use = re.search(
                r"(?:std::string\s*\(\s*value\s*\)|SetDescription\s*\(\s*std::string\s*\(\s*value\s*\)\s*\))",
                mtp_body,
            )
            if (exact_capacity_alloc and bounded_xattr and strict_bound
                    and terminates_only_under_strict_bound and c_string_use):
                out.append(_finding(
                    unit, mtp_start + 1 + c_string_use.start(),
                    "ohknowncve-storage-cve-2026-28751", "CVE-2026-28751",
                    "NotifyMtpMounted allocates MTP_DEVICE_NAME_LEN bytes but a full-capacity getxattr result skips NUL termination; the value is later consumed as a C string, allowing an out-of-bounds read.",
                    "CWE-125", impact="availability_or_memory_safety",
                ))
    # CVE-2026-92392: request cleanup must finish before connection filters
    # release their references to Curl_easy.
    if source_path.endswith("lib/multi.c"):
        multi_done = _body(s, "multi_done")
        affected = _curl_92392_affected(curl_version)
        if multi_done and affected is not False:
            multi_start, multi_body = multi_done
            req_done = re.search(r"Curl_req_done\s*\(\s*&data->req\s*,\s*data\s*,\s*premature\s*\)", multi_body)
            filter_done = re.search(r"Curl_conn_ev_data_done\s*\(\s*data\s*,\s*premature\s*\)", multi_body)
            schedule = re.search(r"multi_schedule_pending\s*\(\s*data->multi\s*\)", multi_body)
            pool_return = re.search(r"Curl_cpool_(?:return|do_locked)\s*\(", multi_body)
            if (req_done and filter_done and pool_return
                    and filter_done.start() < req_done.start()
                    and pool_return.start() > req_done.start()):
                version_note = (
                    "source-declared libcurl version is in the published affected range"
                    if affected is True else
                    "no unique source-declared libcurl version was found; version applicability remains unknown"
                )
                out.append(_finding(
                    unit, multi_start + 1 + filter_done.start(),
                    "ohknowncve-curl-cve-2026-92392", "CVE-2026-92392",
                    "multi_done notifies connection filters before Curl_req_done completes, permitting a Curl_easy lifetime violation on the affected HTTP/2 upload reset path; " + version_note + ".",
                    "CWE-416",
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
        curl_version, _curl_version_ambiguous = _curl_version(selected)
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
            findings.extend(_scan(u, curl_version))
            analyzed.append(u.path)  # inspected; blocked run maps incomplete inputs to partial coverage
            if u.parse_status != "complete":
                complete=False
                limitations.append(f"{u.path}: parse_status={u.parse_status}; lexical matches are retained but remaining coverage is unknown.")
        unique={(f.file,f.line,f.rule_id,f.source_sha256):f for f in findings}
        return DetectorRun(self.detector_id, self.version, "completed" if complete else "blocked",
            analyzed_files=tuple(analyzed), findings=tuple(sorted(unique.values(),key=lambda f:(f.file,f.line,f.rule_id))),
            limitations=tuple(sorted(set(limitations))))
