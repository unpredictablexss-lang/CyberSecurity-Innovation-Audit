"""Exact-source candidate for TypedArray.set(arrayLike, offset) wraparound."""
import re
from hashlib import sha1, sha256

from src.parser.ast import parse_source

from .analysis import AnalysisResult, Observation


_COMMIT = 'a65a2853ccae13da167d9aa4720ab8b11ec16656'
_TARGET = 'ecmascript/builtins/builtins_typedarray.cpp'
_BUFFER = 'ecmascript/builtins/builtins_arraybuffer.cpp'
_DECL = 'ecmascript/builtins/builtins_typedarray.h'
_PINS = (
    (_COMMIT, _TARGET, '0fc27c213e1ea80d93e1e3807eec11baf2634832',
     '14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c'),
)
_DEPENDENCIES = (
    (_COMMIT, _BUFFER, '2aa22c58803df690a5a2b326451e02297dc5e2f6',
     '4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9'),
    (_COMMIT, _DECL, 'b291181c949c7038b7030a216f5bdc0e7474a1c2',
     '651d426c00c1d8bc6503c1d717decf42b28c61c57336e9418ad422604a6a1be7'),
)


def _function_snippet(text, first_line, last_line, name):
    lines = text.splitlines()
    if first_line < 1 or last_line < first_line or last_line > len(lines):
        return None
    snippet = '\n'.join(lines[first_line - 1:last_line]) + '\n'
    parsed = parse_source(snippet, 'cpp')
    if (parsed.parse_status != 'complete' or parsed.parse_issues
            or not any(fn.name == name for fn in parsed.functions)):
        return None
    return snippet


def _has_wrap_shape(function):
    """Require the range check, narrowing, loop and sensitive write in one method."""
    compact = re.sub(r'\s+', ' ', function)
    checks = (
        'if (srcLen + targetOffset > targetLength)',
        'uint64_t srcLen = static_cast<uint64_t>(tSrcLen.GetNumber());',
        'uint32_t targetByteIndex = static_cast<uint32_t>(targetOffset * targetElementSize + targetByteOffset);',
        'uint32_t limit = targetByteIndex + targetElementSize * srcLen;',
        'while (targetByteIndex < limit)',
        'BuiltinsArrayBuffer::SetValueInBuffer(thread, targetBuffer.GetTaggedValue(), targetByteIndex, targetType, kNumberHandle, true)',
    )
    if not all(item in compact for item in checks):
        return False
    # Overflow-safe subtraction form makes the subsequently retained addition safe.
    safe_guard = re.search(
        r'if\s*\(\s*targetOffset\s*>\s*targetLength\s*\|\|\s*'
        r'srcLen\s*>\s*targetLength\s*-\s*targetOffset\s*\)', function)
    if safe_guard:
        return False
    # Keep the ordinary array-like route distinct from the stable-array fast path.
    return ('if (!argArray->IsTypedArray())' in compact
            and 'if (argArray->IsStableJSArray(thread))' in compact
            and 'FastCopyFromArrayToTypedArray' in compact
            and 'return JSStableArray::FastCopyFromArrayToTypedArray' in compact)


def _bytes_match(unit, row, ast):
    _, path, expected_blob, expected_sha = row
    raw = unit.text.encode('utf-8')
    actual_blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()
    ast_entry = ast.get(path)
    return (unit.path == path and unit.language == 'cpp'
            and unit.sha256 == expected_sha == sha256(raw).hexdigest()
            and actual_blob == expected_blob
            and isinstance(ast_entry, dict)
            and ast_entry.get('parse_status') == 'complete'
            and unit.parse_status == 'complete')


def _identity_match(unit, row, ast, expected_parse_status):
    _, path, expected_blob, expected_sha = row
    raw = unit.text.encode('utf-8')
    actual_blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()
    ast_entry = ast.get(path)
    return (unit.path == path and unit.language == 'cpp'
            and unit.sha256 == expected_sha == sha256(raw).hexdigest()
            and actual_blob == expected_blob
            and isinstance(ast_entry, dict)
            and ast_entry.get('parse_status') == expected_parse_status
            and unit.parse_status == expected_parse_status)


def analyze_arraylike_set_bounds(context, model):
    """Emit one local candidate only for the exact target and complete sink evidence."""
    digest = model.digest
    if (tuple(model.arraylike_set_bounds_bindings) != _PINS
            or tuple(model.arraylike_set_bounds_dependencies) != _DEPENDENCIES):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_profile_incomplete',),
                              model_digest=digest)
    request = context.request
    if (request.repository != model.source_repository or request.commit != _COMMIT
            or request.profile_id != 'light-ast' or request.provenance != 'git_object'):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_requires_exact_git_profile',),
                              model_digest=digest)
    units = {unit.path: unit for unit in context.units}
    ast = context.shared_facts.get('ast', {})
    target_row = _PINS[0]
    target = units.get(_TARGET)
    if target is None:
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_missing_target',), model_digest=digest)
    if not _bytes_match(target, target_row, ast):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_target_identity_or_parse_mismatch',),
                              model_digest=digest)
    buffer_row = _DEPENDENCIES[0]
    buffer = units.get(_BUFFER)
    if buffer is None:
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_missing_sink_helper',), model_digest=digest)
    if not _bytes_match(buffer, buffer_row, ast):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_sink_helper_identity_or_parse_mismatch',),
                              model_digest=digest)
    declaration_row = _DEPENDENCIES[1]
    declaration = units.get(_DECL)
    if declaration is None:
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_missing_target_declaration',), model_digest=digest)
    if not _identity_match(declaration, declaration_row, ast, 'partial'):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_declaration_identity_or_status_mismatch',),
                              model_digest=digest)
    blobs = context.shared_facts.get('source_blob_oid', {})
    if (blobs.get(_TARGET) != target_row[2] or blobs.get(_BUFFER) != buffer_row[2]
            or blobs.get(_DECL) != declaration_row[2]):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_git_blob_fact_mismatch',),
                              model_digest=digest)

    # The whole target/helper TUs are complete on this pin; slice the exact
    # methods as an additional guard against relying on unrelated syntax.
    method = _function_snippet(target.text, 1134, 1379, 'Set')
    sink = _function_snippet(buffer.text, 380, 407, 'SetValueInBuffer')
    dispatch = _function_snippet(buffer.text, 722, 766, 'SetValueInBuffer')
    byte_store = _function_snippet(buffer.text, 584, 597, 'SetValueInBufferForByte')
    raw_store = _function_snippet(buffer.text, 435, 442, 'SetTypeData')
    if (not method or not sink or not dispatch or not byte_store or not raw_store
            or 'SetValueInBuffer(thread, byteIndex, block, type, val, littleEndian)' not in sink
            or 'SetValueInBufferForByte<uint8_t>(val, block, byteIndex)' not in dispatch
            or 'SetTypeData(block, res, byteIndex)' not in byte_store
            or not re.search(r'\*\s*\(\s*block\s*\+\s*index\s*\+\s*i\s*\)', raw_store)):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('arraylike_set_bounds_scoped_parser_or_sink_incomplete',),
                              model_digest=digest)
    if not _has_wrap_shape(method):
        return AnalysisResult('completed', 'complete',
                              limitations=('arraylike_set_bounds_trigger_shape_not_present',),
                              model_digest=digest)

    line = 1227
    start_byte = len('\n'.join(target.text.splitlines()[:1133]).encode('utf-8')) + 1
    end_byte = start_byte + len(method.encode('utf-8'))
    observation = Observation(
        kind='candidate', line=line, column=1,
        reason=('array-like set range sum is unchecked for uint64 wrap before byte-index narrowing'),
        target_identity='BuiltinsTypedArray::Set(arrayLike, offset)',
        token_origin='uint64_t targetOffset and uint64_t srcLen',
        token_line=1161, creation_line=1227,
        path=('ordinary array-like branch', 'srcLen + targetOffset range check',
              'uint64_t byte arithmetic', 'uint32_t byte-index narrowing',
              'SetValueInBuffer backing-store write'),
        constraints=('exact source/helper identity and complete method/sink parse required',
                     'declaration header parse is partial; exact target method and byte-store helper slices parse completely',
                     'candidate only; attacker-controlled array-like length/offset dispatch not executed',
                     'cross-view backing-store overwrite hypothesis; allocation-boundary OOB is not claimed',
                     'runtime, build profile, and product impact remain unknown/not_run'),
        symbol='BuiltinsTypedArray::Set',
        region_start_byte=start_byte, region_end_byte=end_byte,
    )
    return AnalysisResult(
        'limited', 'partial', (observation,),
        limitations=('arraylike_set_bounds_declaration_header_partial',), model_digest=digest)
