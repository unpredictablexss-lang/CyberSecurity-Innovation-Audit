from pathlib import Path

root = Path(__file__).resolve().parents[4]
model_path = root / "src/ohscanner/detectors/ark_runtime/model.py"
model = model_path.read_text(encoding="utf-8")
model = model.replace(
    "RECEIVER_TYPE_GUARD_RULE_ID = 'ark.runtime.typedarray-receiver-type-guard'\nVERSION = '0.6.2'",
    "RECEIVER_TYPE_GUARD_RULE_ID = 'ark.runtime.typedarray-receiver-type-guard'\n"
    "LENGTH_NARROWING_RULE_ID = 'ark.runtime.typedarray-length-signed-to-unsigned-narrowing'\n"
    "INDEX_BOUNDS_RULE_ID = 'ark.runtime.dataview-index-width-bounds'\n"
    "NATIVE_EXCEPTION_RULE_ID = 'ark.runtime.native-inline-pending-exception-propagation'\n"
    "GAP_RULE_VERSIONS = {\n"
    "    LENGTH_NARROWING_RULE_ID: '1.0.0',\n"
    "    INDEX_BOUNDS_RULE_ID: '1.0.0',\n"
    "    NATIVE_EXCEPTION_RULE_ID: '1.0.0',\n"
    "}\n"
    "VERSION = '0.6.2'",
)
model = model.replace(
    "    exception_guard_creator: tuple = ('NewTypedArray', 4)",
    "    length_narrowing_bindings: tuple = (\n"
    "        ('3c1a50cfb1206ce63afcd2d0ef2b1e81668f2e3c',\n"
    "         'ecmascript/base/typed_array_helper.cpp',\n"
    "         'c5153346369f0182e73098b8d008eca6d750b36d',\n"
    "         '4be243a68180be845defbcc01b259070db68b18da8500d245eea4929e7b9eca5'),\n"
    "        ('82c21d656880923800c94b53b035c76d219313b5',\n"
    "         'ecmascript/base/typed_array_helper.cpp',\n"
    "         '89ffed8b3ff112a271c8a074967b7b5e8ebe2f6f',\n"
    "         '373f5babdd5dd2f93d01512901d02e6b39d6b57c636e72b07b8d80d27eb509ab'),\n"
    "    )\n"
    "    index_bounds_bindings: tuple = (\n"
    "        ('d62f6de64daa7e11a7936a6153748a7c5fae9e41', 'ecmascript/base/atomic_helper.cpp',\n"
    "         '7fd67717571c6d8fe7b10bf294998e952dc61e36',\n"
    "         'f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541'),\n"
    "        ('48fcec3686e45175f95b4600b579026a65149966', 'ecmascript/base/atomic_helper.cpp',\n"
    "         '80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c',\n"
    "         '39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b'),\n"
    "        ('d62f6de64daa7e11a7936a6153748a7c5fae9e41', 'ecmascript/builtins/builtins_dataview.cpp',\n"
    "         'e6bac984354292405ae62f7728170d7be5e3760e',\n"
    "         'bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c'),\n"
    "        ('48fcec3686e45175f95b4600b579026a65149966', 'ecmascript/builtins/builtins_dataview.cpp',\n"
    "         'a2376e822e995333b2400520ca5b882de9578b5e',\n"
    "         '39b1ed79451980ad85e1176805deaf6c6315bca09d7676ea5c63f5ff1c4bd65b'),\n"
    "        ('d62f6de64daa7e11a7936a6153748a7c5fae9e41',\n"
    "         'ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp',\n"
    "         'aedb6d26681535371d1e9ed90b697b923b8100e6',\n"
    "         'bd55a638db7292305dd7b564c5767657e105a48f064c66809934f5e3e6a5f548'),\n"
    "        ('48fcec3686e45175f95b4600b579026a65149966',\n"
    "         'ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp',\n"
    "         'dce9388e8b7e33c87aec33ac4d067fe40370561b',\n"
    "         '89fd548588f59a5f0756868957ff011609264b7d10437a8636c3f3262da1d386'),\n"
    "    )\n"
    "    native_exception_bindings: tuple = (\n"
    "        ('3fc1d0b960e0b1bb5bfe1aad8066bb8c9aa99724',\n"
    "         'ecmascript/compiler/native_inline_lowering.cpp',\n"
    "         'bdafa81ac797501852f639575d3a30f48b6ff25a',\n"
    "         'fcf0b9c6371ed348f433f637130fef7ae886d7cc1d241bb072fc37e252f33463'),\n"
    "        ('18d8532a200d0c9aa64a6dfe2b146dc841b52bf8',\n"
    "         'ecmascript/compiler/native_inline_lowering.cpp',\n"
    "         'df03fdce8a37cf2245577aec23c4c26deeebf02f',\n"
    "         '6e5a248ec9b82a4955232845f08f02383d6b941caca2c80f0317f4ccba7d33ce'),\n"
    "    )\n"
    "    exception_guard_creator: tuple = ('NewTypedArray', 4)",
)
model = model.replace(
    "        + tuple((revision, path, blob) for revision, path, blob, _ in self.receiver_guard_bindings)\n",
    "        + tuple((revision, path, blob) for revision, path, blob, _ in self.receiver_guard_bindings)\n"
    "        + tuple((revision, path, blob) for revision, path, blob, _ in self.size_overflow_bindings)\n"
    "        + tuple((revision, path, blob) for revision, path, blob, _ in self.length_narrowing_bindings)\n"
    "        + tuple((revision, path, blob) for revision, path, blob, _ in self.index_bounds_bindings)\n"
    "        + tuple((revision, path, blob) for revision, path, blob, _ in self.native_exception_bindings)\n",
)
model = model.replace(
    "        receiver_guard_bindings=(),\n",
    "        receiver_guard_bindings=(),\n"
    "        size_overflow_bindings=base.size_overflow_bindings,\n"
    "        length_narrowing_bindings=base.length_narrowing_bindings,\n"
    "        index_bounds_bindings=base.index_bounds_bindings,\n"
    "        native_exception_bindings=base.native_exception_bindings,\n",
)
model_path.write_text(model, encoding="utf-8", newline="")

size_path = root / "src/ohscanner/detectors/ark_runtime/size_overflow.py"
size = size_path.read_text(encoding="utf-8")
size += r'''


def _bounded_function_regions(text):
    masked = _mask_cpp_noncode(text)
    pattern = re.compile(
        r'\b(?P<name>(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*'
        r'\((?P<params>[^;{}]*)\)\s*(?:const\s*)?\{')
    excluded = {'if', 'for', 'while', 'switch', 'catch', 'sizeof', 'alignof'}
    cursor = 0
    while True:
        match = pattern.search(masked, cursor)
        if match is None:
            return
        cursor = match.end()
        if match.group('name').split('::')[-1] in excluded:
            continue
        opening = masked.find('{', match.start(), match.end())
        closing = _balanced_delimiter(masked, opening, '{', '}')
        if closing is None:
            continue
        yield (match.group('name'), text[opening + 1:closing],
               text.count('\n', 0, opening + 1) + 1,
               len(text[:opening + 1].encode('utf-8')))
        cursor = closing + 1


def _position(text, offset, base_line, base_byte):
    local = text[:offset]
    return (base_line + local.count('\n'),
            len(local[local.rfind('\n', 0, offset) + 1:offset].encode('utf-8')) + 1,
            base_byte + len(local.encode('utf-8')))


@dataclass(frozen=True)
class LengthNarrowingCandidate:
    line: int
    column: int
    function: str
    result_name: str
    conversion_line: int
    allocation_line: int
    start_byte: int
    end_byte: int


def analyze_length_narrowing_flows(source):
    """Find signed 32-bit ToIndex results that flow into TypedArray allocation.

    This is deliberately a narrow local conversion/allocation shape. It does
    not establish that a RangeError patch is safe or that a product path has
    memory-safety impact.
    """
    text = source.decode('utf-8') if isinstance(source, bytes) else source
    candidates, limitations, applicable = [], [], False
    signed_types = r'(?:int32_t|std::int32_t|signed\s+int|int)'
    for name, body, body_line, body_byte in _bounded_function_regions(text):
        if 'ToIndex' not in body or 'AllocateTypedArray' not in body:
            continue
        applicable = True
        declarations = re.finditer(
            r'\b(?P<type>' + signed_types + r')\s+(?P<name>\w+)\s*=\s*(?:0|-1)\s*;', body)
        for declaration in declarations:
            result_name = declaration.group('name')
            conversion = re.search(
                r'\b' + re.escape(result_name) + r'\s*=\s*(?:'
                r'static_cast\s*<\s*(?:std::)?int32_t\s*>\s*\([^;]+\)|'
                r'base::NumberHelper::DoubleInRangeInt32\s*\([^;]+\))\s*;', body)
            allocation = re.search(
                r'\bAllocateTypedArray\s*\([^;]*\b' + re.escape(result_name) + r'\b[^;]*\)', body)
            if conversion is None or allocation is None:
                continue
            expression = conversion.group(0)
            offset = conversion.start()
            line, column, start_byte = _position(body, offset, body_line, body_byte)
            alloc_offset = allocation.start()
            alloc_line = body_line + body[:alloc_offset].count('\n')
            candidates.append(LengthNarrowingCandidate(
                line, column, name, result_name, line, alloc_line,
                start_byte, start_byte + len(expression.encode('utf-8'))))
        if not candidates and re.search(
                r'\bAllocateTypedArray\s*\(', body) and re.search(r'\bToIndex\s*\(', body):
            if re.search(r'(?:static_cast\s*<|DoubleInRangeInt32|unknown_[A-Za-z_]\w*\s*\()', body):
                limitations.append('typedarray_length_conversion_semantics_unmodeled:' + name)
    if not applicable:
        return (), ('not_applicable_to_typedarray_length_allocation',)
    return tuple(candidates), tuple(sorted(set(limitations)))


def length_narrowing_result(unit, model_digest):
    candidates, limitations = analyze_length_narrowing_flows(unit.text)
    observations = tuple(Observation(
        'candidate', item.line, item.column,
        'signed_32_bit_to_index_result_flows_to_typedarray_allocation',
        item.result_name, 'ToIndex', item.conversion_line, item.allocation_line,
        (item.conversion_line, item.allocation_line),
        ((item.allocation_line, 'allocation_uses_narrowed_length', True),),
        item.function, item.start_byte, item.end_byte)
        for item in candidates)
    if limitations:
        return AnalysisResult('limited', 'partial', observations, limitations,
                              steps=len(candidates) + len(limitations), model_digest=model_digest)
    if not candidates and unit.parse_status == 'complete':
        return AnalysisResult('completed', 'complete', (), ('no_local_length_narrowing_candidate',),
                              steps=0, model_digest=model_digest)
    return AnalysisResult('limited', 'partial', observations,
                          ('bounded_length_conversion_model_no_product_impact',),
                          steps=len(candidates), model_digest=model_digest)


@dataclass(frozen=True)
class IndexBoundsCandidate:
    line: int
    column: int
    function: str
    index_expression: str
    arithmetic_line: int
    start_byte: int
    end_byte: int


def analyze_index_bounds_flows(source):
    """Find 32-bit index arithmetic reaching DataView/Atomics buffer access."""
    text = source.decode('utf-8') if isinstance(source, bytes) else source
    candidates, limitations, applicable = [], [], False
    for name, body, body_line, body_byte in _bounded_function_regions(text):
        semantic_name = any(token in name for token in ('DataView', 'Atomic', 'ValidateAtomicAccess'))
        buffer_flow = any(token in body for token in (
            'GetValueFromBuffer', 'SetValueInBuffer', 'GetDataPointFromBuffer', 'ValidateAtomicAccess'))
        if not semantic_name and not buffer_flow:
            continue
        if not any(token in body for token in ('ToIndex', 'requestIndex', 'accessIndex')):
            continue
        applicable = True
        narrow = re.search(
            r'(?:DoubleInRangeInt32\s*\([^;]+\)|static_cast\s*<\s*(?:std::)?int32_t\s*>\s*\([^;]+\)|'
            r'Int32Add\s*\([^;]+\))', body)
        arithmetic = re.search(
            r'(?:Int32Add\s*\([^;]+\)|static_cast\s*<\s*uint32_t\s*>\s*\([^;]+\)\s*\+\s*\w+|'
            r'\buint32_t\s+\w+\s*=\s*[^;]*\+)', body)
        bounds = any(token in body for token in (
            'Int32GreaterThan', 'getIndex +elementSize >', 'index * elementSize + offset',
            'index + elementSize >', 'index) + elementSize >'))
        if narrow and arithmetic and bounds:
            offset = arithmetic.start()
            line, column, start_byte = _position(body, offset, body_line, body_byte)
            candidates.append(IndexBoundsCandidate(
                line, column, name, narrow.group(0), line,
                start_byte, start_byte + len(arithmetic.group(0).encode('utf-8'))))
        elif any(token in body for token in ('DoubleToUInt64', 'Int64UnsignedGreaterThan', 'uint64_t index')):
            limitations.append('index_width_bounds_arithmetic_not_fully_proven:' + name)
        else:
            limitations.append('dataview_atomic_index_bounds_semantics_unmodeled:' + name)
    if not applicable:
        return (), ('not_applicable_to_dataview_or_atomics_index_bounds',)
    return tuple(candidates), tuple(sorted(set(limitations)))


def index_bounds_result(unit, model_digest):
    candidates, limitations = analyze_index_bounds_flows(unit.text)
    observations = tuple(Observation(
        'candidate', item.line, item.column,
        'signed_32_bit_index_arithmetic_reaches_dataview_or_atomic_bounds_check',
        item.function, item.index_expression, item.line, item.line,
        (item.line,), ((item.line, 'bounds_arithmetic_width', 32),),
        item.function, item.start_byte, item.end_byte)
        for item in candidates)
    if any(not item.startswith(('index_width_bounds_arithmetic_not_fully_proven:',
                                'dataview_atomic_index_bounds_semantics_unmodeled:'))
           for item in limitations):
        return AnalysisResult('failed', 'failed', observations, limitations,
                              steps=len(candidates), model_digest=model_digest)
    if limitations:
        unknown = tuple(Observation(
            'unknown', 1, 1, item, symbol=item.rsplit(':', 1)[-1])
            for item in limitations)
        return AnalysisResult('limited', 'partial', observations + unknown, limitations,
                              steps=len(candidates) + len(limitations), model_digest=model_digest)
    if not candidates and unit.parse_status == 'complete':
        return AnalysisResult('completed', 'complete', (),
                              ('no_local_dataview_index_width_candidate',),
                              steps=0, model_digest=model_digest)
    return AnalysisResult('limited', 'partial', observations,
                          ('bounded_index_width_model_no_general_bounds_proof',),
                          steps=len(candidates), model_digest=model_digest)
'''
size_path.write_text(size, encoding="utf-8", newline="")

runtime_path = root / "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
runtime = runtime_path.read_text(encoding="utf-8")
runtime += r'''


def analyze_native_inline_exception_propagation(unit):
    """Detect Reflect.apply inlining that compares a sentinel instead of pending state."""
    if unit.parse_status not in ("complete", "partial"):
        return RuntimeExceptionResult("limited", "not_analyzed",
                                      limitations=("source_parse_unavailable",))
    text = unit.text
    masked = _mask_cpp_noncode(text) if "_mask_cpp_noncode" in globals() else text
    function_pattern = re.compile(
        r"\b(?P<name>(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{")
    regions = {}
    cursor = 0
    while True:
        match = function_pattern.search(masked, cursor)
        if match is None:
            break
        cursor = match.end()
        opening = masked.find("{", match.start(), match.end())
        depth = 0
        closing = None
        for index in range(opening, len(masked)):
            if masked[index] == "{":
                depth += 1
            elif masked[index] == "}":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing is None:
            continue
        regions[match.group("name")] = (text[opening + 1:closing],
                                        text.count("\n", 0, opening + 1) + 1,
                                        len(text[:opening + 1].encode("utf-8")))
    caller_name = next((name for name in regions if name.endswith("NativeInlineLowering::TryInlineReflectApply")), None)
    helper_name = next((name for name in regions if name.endswith("NativeInlineLowering::ReplaceGateWithPendingException")), None)
    if caller_name is None:
        return RuntimeExceptionResult("limited", "not_analyzed",
                                      limitations=("reflect_apply_inline_site_not_applicable",))
    if helper_name is None:
        return RuntimeExceptionResult("limited", "partial",
                                      limitations=("pending_exception_helper_summary_missing:" + caller_name,))
    body, body_line, body_byte = regions[helper_name]
    if re.search(r"\bHasPendingException\s*\(", body):
        return RuntimeExceptionResult("completed", "complete", (),
                                      ("fixed_pending_exception_check_control_not_security_verdict",), 1)
    sentinel = re.search(r"\b(?:ExceptionConstant|Exception)\s*\(\s*\)", body)
    equality = re.search(r"\b(?:Equal|Int32Equal|Int64Equal)\s*\([^;]*exception[^;]*\)", body, re.I)
    branch = re.search(r"\bBranch\s*\([^;]*(?:equal|condition)[^;]*\)", body, re.I)
    if sentinel and equality and branch:
        offset = equality.start()
        prefix = body[:offset]
        line = body_line + prefix.count("\n")
        column = len(prefix[prefix.rfind("\n", 0, offset) + 1:offset].encode("utf-8")) + 1
        start_byte = body_byte + len(prefix.encode("utf-8"))
        observation = Observation(
            "candidate", line, column,
            "reflect_apply_result_sentinel_comparison_may_drop_pending_exception",
            helper_name, "ExceptionConstant", line, line, (line,),
            ((line, "checks_pending_thread_exception", False),),
            helper_name, start_byte, start_byte + len(equality.group(0).encode("utf-8")))
        return RuntimeExceptionResult("limited", "partial", (observation,),
                                      ("local_sentinel_comparison_does_not_prove_exception_propagation",), 1)
    return RuntimeExceptionResult("limited", "partial", (),
                                  ("native_inline_exception_semantics_unmodeled:" + helper_name,), 1)
'''
if "import re" not in runtime.splitlines()[:30]:
    runtime = runtime.replace("from dataclasses import dataclass", "from dataclasses import dataclass\nimport re", 1)
runtime_path.write_text(runtime, encoding="utf-8", newline="")

print("patched model/analyzers")

