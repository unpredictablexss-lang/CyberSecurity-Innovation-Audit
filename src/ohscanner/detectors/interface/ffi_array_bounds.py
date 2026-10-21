"""Narrow parcel-count allocation-width check for the OpenHarmony Cangjie FFI.

This prototype is intentionally source/repository scoped. It requires the
MessageSequenceImpl remote-object-array reader, a parcel-derived element count,
raw count-sized allocations for typed arrays, and indexed writes driven by that
same count. A CheckReadLength guard may be present, but does not establish the
capacity of the separate output allocations. The parcel guard alone never reports.
"""

import re

import tree_sitter_cpp
from tree_sitter import Language, Parser

from src.ohscanner.contracts import DetectorFinding, EvidenceObligation, SourceUnit


DATA06_RISK_ASSESSMENT = {
    "identifier": "CVE-2025-26474 (候选映射；非根因证明)",
    "mapping_basis": (
        "T74 regression manifest associates this source root with CVE-2025-26474. "
        "The public disclosure describes an input-validation issue but does not establish "
        "this allocation-width primitive as its root cause. Treat the CVE link as provenance only."
    ),
    "cwe": ["CWE-131", "CWE-787"],
    "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-26474",
    "source_name": "NVD CVE-2025-26474 (candidate mapping provenance)",
    "source_severity": "not assigned to this source primitive",
    "severity": "unknown",
    "severity_label": "未评估",
    "severity_mapping": "No CVSS or product severity is inferred from the CVE mapping or semantic harness.",
    "affected_range": "Pinned vulnerable source: communication_ipc commit 84d681288793785e8f39f71c824f211edaed8f1e",
    "fixed_versions": ["official source fix commit de3a68cc8b7d6f18017fd261060def0e38dce54a"],
    "component_condition": (
        "CJ_ReadRemoteObjectArray reads a positive count from Parcel, allocates int32_t and "
        "int64_t outputs with malloc(count), then stores count typed elements."
    ),
    "source_location": {
        "file": "interfaces/innerkits/cj/src/message_sequence_impl.cpp",
        "symbol": "MessageSequenceImpl::CJ_ReadRemoteObjectArray",
        "lines": "1188-1218",
        "vulnerable_commit": "84d681288793785e8f39f71c824f211edaed8f1e",
        "fixed_commit": "de3a68cc8b7d6f18017fd261060def0e38dce54a",
        "url": "https://gitee.com/openharmony/communication_ipc/blob/84d681288793785e8f39f71c824f211edaed8f1e/interfaces/innerkits/cj/src/message_sequence_impl.cpp#L1188",
    },
    "poc": {
        "kind": "isolated source-semantic ASan harness; OpenHarmony component not compiled",
        "entrypoint": "MessageSequenceImpl::CJ_ReadRemoteObjectArray allocation/count/typed-store semantics; count=4",
        "record": "research/deliveries/ipc/data06_runtime_poc_20261021/README.md",
        "record_sha256": "eddf6ba05843a7888f89c138be720841790a4ee99367f7b0a433255019ae3209",
        "replay": "research/deliveries/ipc/data06_runtime_poc_20261021/run.sh",
        "replay_sha256": "7994b7e0ca6d404ba64292014df567eddd51b3fd2bd23d793a9cceacff154209",
        "raw_output": "research/deliveries/ipc/data06_runtime_poc_20261021/artifacts/vulnerable.stderr.raw.b64",
        "raw_output_sha256": "b27931bbf0ae57391ae40046f5a8c0899a8f49f357a5caeecd9e35630fd6747b",
        "raw_output_encoding": "base64; SHA-256 covers decoded ASan stderr bytes",
    },
    "remediation": "Allocate sizeof(element_type) * arrayLength; upstream fixed source is the recorded commit.",
    "upstream_fix": "https://gitee.com/openharmony/communication_ipc/commit/de3a68cc8b7d6f18017fd261060def0e38dce54a",
    "component_retest": {
        "fixed_source": "Pinned official source fix de3a68cc8b7d6f18017fd261060def0e38dce54a; detector replay expects zero DATA-06 finding.",
        "affected_poc": "ASan heap-buffer-overflow in source-semantic harness at count=4.",
        "fixed_poc": "Clean return in source-semantic harness at count=4.",
        "safe_order_control": "Zero-count and insufficient-Parcel-byte controls reject without overflow.",
        "scope": "Source-semantic harness and exact-source detector replay; no OpenHarmony binary, Binder/DBinder reachability, or product impact verified.",
    },
    "product_applicability": "unknown",
    "product_evidence": (
        "The harness does not compile the OpenHarmony component and does not establish Binder/DBinder "
        "reachability, shipped build inclusion, or product impact."
    ),
}


_PATH = "interfaces/innerkits/cj/src/message_sequence_impl.cpp"
_METHOD = re.compile(r"MessageSequenceImpl\s*::\s*CJ_ReadRemoteObjectArray\s*\(")
_COUNT_READ = re.compile(
    r"\bint32_t\s+(?P<count>[A-Za-z_]\w*)\s*=\s*"
    r"nativeParcel_\s*->\s*ReadInt32\s*\(\s*\)"
)
_ALLOC = re.compile(
    r"\b(?P<type>int(?:32|64)_t)\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*=\s*"
    r"static_cast\s*<\s*(?:int(?:32|64)_t\s*\*)\s*>\s*\(\s*malloc\s*\(\s*"
    r"(?P<count>[A-Za-z_]\w*)\s*\)\s*\)"
)
_GUARD = re.compile(
    r"\bCheckReadLength\s*\(\s*static_cast\s*<\s*size_t\s*>\s*\(\s*"
    r"(?P<count>[A-Za-z_]\w*)\s*\)\s*,\s*BYTE_SIZE_32\s*\)"
)
_POSITIVE_COUNT_GUARD = re.compile(
    r"if\s*\(\s*(?P<count>[A-Za-z_]\w*)\s*<=\s*0\s*\)\s*\{?\s*return\b"
)
_LOOP = re.compile(
    r"for\s*\(\s*(?:uint32_t|uint64_t|size_t)\s+(?P<index>[A-Za-z_]\w*)\s*=\s*0\s*;"
    r"\s*(?P=index)\s*<\s*(?:\(\s*uint32_t\s*\)\s*|"
    r"static_cast\s*<\s*uint32_t\s*>\s*\(\s*)?(?P<count>[A-Za-z_]\w*)"
    r"\s*\)?\s*;"
)


def _mask_non_code(source: bytes, start: int, end: int, root):
    """Mask comments and literals so regex checks see executable token text only.

    Keep newlines and byte offsets intact: the caller uses the original syntax
    tree for function selection and source positions for the emitted line.
    """
    masked = bytearray(source[start:end])
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in {"comment", "string_literal", "raw_string_literal", "char_literal"}:
            left = max(node.start_byte, start) - start
            right = min(node.end_byte, end) - start
            for offset in range(left, right):
                if masked[offset] not in (0x0A, 0x0D):
                    masked[offset] = 0x20
        else:
            stack.extend(node.children)
    return bytes(masked)


def find_remote_array_width_candidate(unit: SourceUnit, repository: str):
    """Return one root finding when both typed output arrays are under-sized."""
    if repository != "openharmony/communication_ipc" or unit.path != _PATH:
        return None
    source = unit.text.encode("utf-8")
    tree = Parser(Language(tree_sitter_cpp.language())).parse(source)
    if tree.root_node.has_error:
        return None

    target = None
    body = None
    for node in tree.root_node.children:
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == "function_definition":
                body_node = current.child_by_field_name("body")
                if body_node is not None:
                    header = source[current.start_byte:body_node.start_byte].decode("utf-8", "replace")
                    if _METHOD.search(header):
                        target = current
                        body = _mask_non_code(
                            source, body_node.start_byte, body_node.end_byte, body_node
                        ).decode("utf-8", "replace")
                        break
            stack.extend(reversed(current.named_children))
        if target is not None:
            break
    if target is None or body is None:
        return None

    count_match = _COUNT_READ.search(body)
    if count_match is None:
        return None
    count = count_match.group("count")
    if not any(match.group("count") == count for match in _POSITIVE_COUNT_GUARD.finditer(body)):
        return None
    loops = [match for match in _LOOP.finditer(body) if match.group("count") == count]
    if not loops:
        return None

    allocations = {}
    for match in _ALLOC.finditer(body):
        if match.group("count") == count and match.group("type") in ("int32_t", "int64_t"):
            allocations[match.group("name")] = match.group("type")
    index = loops[0].group("index")
    under_sized = [
        name for name, element_type in allocations.items()
        if re.search(r"\b" + re.escape(name) + r"\s*\[\s*" + re.escape(index)
                    + r"\s*\]\s*=", body)
    ]
    if len(under_sized) < 2:
        return None

    line = source[:target.start_byte].count(b"\n") + 1
    return DetectorFinding(
        file=unit.path,
        line=line,
        symbol="MessageSequenceImpl::CJ_ReadRemoteObjectArray",
        rule_id="ipc.parcel.array-allocation-width",
        rule_version="0.1.0",
        message=("DATA-06 candidate: parcel-derived positive element count " + count
                 + " is passed as a byte count to malloc for typed arrays "
                 + ", ".join(sorted(under_sized))
                 + ", then the same count controls indexed stores. "
                 + ("CheckReadLength establishes parcel availability, not output allocation width."
                    if any(match.group("count") == count for match in _GUARD.finditer(body))
                    else "Parcel byte availability is not checked before this output allocation.")),
        evidence_type="syntax",
        candidate_cwe="CWE-131",
        consequence_impact="out_of_bounds_write",
        consequence_cwe="CWE-787",
        risk_assessment=dict(DATA06_RISK_ASSESSMENT),
        source_sha256=unit.sha256,
        evidence_obligations=(
            EvidenceObligation("ffi_api_reachability", "Verify the Cangjie FFI caller and product build expose this method to attacker-influenced Parcel contents."),
            EvidenceObligation("parcel_object_validity", "Verify the Parcel can supply the positive count and valid remote-object entries needed to execute the indexed stores."),
            EvidenceObligation("heap_write_impact", "Confirm the out-of-bounds stores and concrete process impact in an isolated runtime."),
        ),
    )
