"""Exact-source, candidate-only Float32Array negative-TDouble guard check."""
import re
from hashlib import sha1, sha256

from src.parser.ast import parse_source
from .analysis import AnalysisResult, Observation


_COMMIT = 'a65a2853ccae13da167d9aa4720ab8b11ec16656'
_COMMON = 'ecmascript/compiler/common_stubs.cpp'
_HCR = 'ecmascript/compiler/typed_hcr_lowering.cpp'
_HELPER = 'ecmascript/compiler/new_object_stub_builder.cpp'


def _line_slice(text, first, last):
    lines = text.splitlines()
    if first < 1 or last < first or last > len(lines):
        return ''
    return '\n'.join(lines[first - 1:last]) + '\n'


def _focused_function(unit, first, last, expected_name):
    """Require complete syntax in the pinned function, independent of distant errors."""
    snippet = _line_slice(unit.text, first, last)
    if not snippet or expected_name not in snippet:
        return None
    parsed = parse_source(snippet, 'cpp')
    if (parsed.parse_status != 'complete' or parsed.parse_issues
            or not any(fn.name == expected_name.rsplit('::', 1)[-1]
                       for fn in parsed.functions)):
        return None
    return snippet


def _double_guard_block(snippet, conversion, boundary):
    start = snippet.find('GateRef doubleLength =')
    end = snippet.find('arrayLength =', start)
    if start < 0 or end < 0:
        return None
    block = snippet[start:end]
    if conversion not in block or boundary not in block:
        return None
    # A lower-bound predicate in the TDouble block is a fixed/safe control.
    if re.search(r'(?:GreaterThanOrEqual|GreaterThan)\s*\([^;]*doubleLength[^;]*\b0\b', block):
        return None
    if re.search(r'doubleLength\s*>=\s*0(?:\.0)?\b', block):
        return None
    return block


def analyze_negative_double_length(context, model):
    """Emit one local candidate only when all exact target/helper evidence agrees."""
    digest = model.digest
    expected = tuple(model.negative_double_length_bindings)
    expected_by_path = {row[1]: row for row in expected}
    required = {_COMMON, _HCR, _HELPER}
    if (len(expected) != len(required) or set(expected_by_path) != required
            or any(row[0] != _COMMIT for row in expected)):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('negative_double_length_profile_incomplete',),
                              model_digest=digest)
    if (context.request.repository != model.source_repository
            or context.request.commit != _COMMIT
            or context.request.profile_id != 'light-ast'
            or context.request.provenance != 'git_object'):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('negative_double_length_requires_exact_git_profile',),
                              model_digest=digest)

    units = {unit.path: unit for unit in context.units}
    ast = context.shared_facts.get('ast', {})
    for path, (_, _, expected_blob, expected_sha) in expected_by_path.items():
        unit = units.get(path)
        if unit is None:
            return AnalysisResult('limited', 'not_analyzed',
                                  limitations=('negative_double_length_missing_source:' + path,),
                                  model_digest=digest)
        raw = unit.text.encode('utf-8')
        actual_blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()
        ast_entry = ast.get(path)
        if (unit.language != 'cpp' or sha256(raw).hexdigest() != expected_sha
                or unit.sha256 != expected_sha or actual_blob != expected_blob
                or context.shared_facts.get('source_blob_oid', {}).get(path) != expected_blob):
            return AnalysisResult('limited', 'not_analyzed',
                                  limitations=('negative_double_length_source_binding_mismatch:' + path,),
                                  model_digest=digest)
        if (not isinstance(ast_entry, dict) or ast_entry.get('parse_status') != unit.parse_status
                or unit.parse_status not in ('complete', 'partial')):
            return AnalysisResult('limited', 'not_analyzed',
                                  limitations=('negative_double_length_parser_evidence_missing:' + path,),
                                  model_digest=digest)

    common = units[_COMMON]
    hcr = units[_HCR]
    helper = units[_HELPER]
    common_fn = _focused_function(common, 186, 267, 'NewFloat32ArrayStubBuilder::GenerateCircuit')
    hcr_fn = _focused_function(hcr, 2333, 2373, 'TypedHCRLowering::ConvertFloat32ArrayConstructorLength')
    hcr_call_fn = _focused_function(hcr, 2375, 2428, 'TypedHCRLowering::LowerFloat32ArrayConstructor')
    helper_size_fn = _focused_function(helper, 3042, 3077, 'NewObjectStubBuilder::NewFloat32ArrayWithSize')
    helper_alloc_fn = _focused_function(helper, 3119, 3142, 'NewObjectStubBuilder::NewByteArray')
    if not all((common_fn, hcr_fn, hcr_call_fn, helper_size_fn, helper_alloc_fn)):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('negative_double_length_scoped_parser_incomplete',),
                              model_digest=digest)

    # Translation-unit parser errors are acceptable only outside the exact
    # target function. The scoped function slices above must parse completely.
    for unit, first, last in ((common, 186, 267), (hcr, 2333, 2373), (hcr, 2375, 2428),
                              (helper, 3042, 3077), (helper, 3119, 3142)):
        if any(issue.get('start_line', 0) <= last and issue.get('end_line', 0) >= first
               for issue in ast[unit.path].get('parse_issues', ())):
            return AnalysisResult('limited', 'not_analyzed',
                                  limitations=('negative_double_length_parser_error_in_target_scope:' + unit.path,),
                                  model_digest=digest)

    common_double = _double_guard_block(
        common_fn, 'DoubleToInt(glue, doubleLength, base::INT32_BITS)',
        'DoubleLessThanOrEqual(doubleLength, Double(JSObject::MAX_GAP))')
    hcr_double = _double_guard_block(
        hcr_fn, 'TruncDoubleToInt(glue_, doubleLength, base::INT32_BITS)',
        'DoubleLessThanOrEqual(doubleLength, builder_.Double(JSObject::MAX_GAP))')
    if not common_double or not hcr_double:
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('negative_double_length_branch_semantics_unverified_or_fixed',),
                              model_digest=digest)

    # The source control is representation-specific: both int-tagged paths
    # retain a nonnegative guard while the two exact-double branches do not.
    if ('isGEZero' not in common_fn or 'isGEZero' not in hcr_fn
            or 'DoubleEqual(doubleLength, intToDouble)' not in common_double
            or 'DoubleEqual(doubleLength, intToDouble)' not in hcr_double
            or 'NewFloat32ArrayWithSize' not in common_fn
            or 'NewFloat32ArrayWithSize' not in hcr_call_fn):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('negative_double_length_tag_or_sink_control_unverified',),
                              model_digest=digest)
    if ('Int32Mul(size, elementSize)' not in helper_size_fn
            or 'NewByteArray(&buffer, &newByteArrayExit, elementSize, size)' not in helper_size_fn
            or 'ZExtInt32ToPtr(elementSize)' not in helper_alloc_fn
            or 'ZExtInt32ToPtr(length)' not in helper_alloc_fn
            or 'TruncPtrToInt32(size)' not in helper_alloc_fn):
        return AnalysisResult('limited', 'not_analyzed',
                              limitations=('negative_double_length_allocation_helper_flow_unverified',),
                              model_digest=digest)

    line = 228
    start_byte = len('\n'.join(common.text.splitlines()[:185]).encode('utf-8')) + 1
    end_byte = start_byte + len(common_fn.encode('utf-8'))
    observation = Observation(
        kind='candidate', line=line, column=1,
        reason='exact CommonStub and TypedHCR TDouble length guards round-trip and enforce only an upper bound',
        target_identity='NewFloat32ArrayStubBuilder::GenerateCircuit',
        token_origin='TDouble exact-integer branch', token_line=223, creation_line=240,
        path=('TDouble branch', 'int32 conversion', 'round-trip equality', 'upper-bound-only guard',
              'NewFloat32ArrayWithSize', 'NewByteArray'),
        constraints=('candidate only; exact source profile',
                     'tagged-int negative control retains >= 0 guard',
                     'TypedHCR independently has the same missing double lower bound',
                     'runtime dispatch, allocation success and memory impact are not proven'),
        symbol='NewFloat32ArrayStubBuilder::GenerateCircuit',
        region_start_byte=start_byte, region_end_byte=end_byte,
    )
    # The CommonStub translation unit is known to be partial. The scoped target
    # function parsed cleanly, so retain this local candidate while preserving
    # partial coverage at the file/scan level.
    outcome = 'complete' if common.parse_status == 'complete' else 'partial'
    status = 'analyzed' if outcome == 'complete' else 'limited'
    return AnalysisResult(status, outcome, (observation,), model_digest=digest)
