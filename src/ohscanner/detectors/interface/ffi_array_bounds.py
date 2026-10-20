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
        source_sha256=unit.sha256,
        evidence_obligations=(
            EvidenceObligation("ffi_api_reachability", "Verify the Cangjie FFI caller and product build expose this method to attacker-influenced Parcel contents."),
            EvidenceObligation("parcel_object_validity", "Verify the Parcel can supply the positive count and valid remote-object entries needed to execute the indexed stores."),
            EvidenceObligation("heap_write_impact", "Confirm the out-of-bounds stores and concrete process impact in an isolated runtime."),
        ),
    )
