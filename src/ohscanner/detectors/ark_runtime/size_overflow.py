"""Bounded detection of narrowed size products that feed a copy allocation.

This is a local C++ syntax/dataflow candidate rule. It requires a typed
multiplication, a buffer allocation using that result, and a later copy loop
whose iteration bound still uses a multiplication operand. It does not prove
all C++ conversions, range checks, macro expansion, or path feasibility.
"""
from dataclasses import dataclass
import re

from .analysis import AnalysisResult, Observation


RULE_ID = 'ark.runtime.typedarray-buffer-size-multiplication-overflow'

_INTEGER_WIDTHS = {
    'uint8_t': (8, False), 'int8_t': (8, True),
    'uint16_t': (16, False), 'int16_t': (16, True),
    'uint32_t': (32, False), 'int32_t': (32, True),
    'uint64_t': (64, False), 'int64_t': (64, True),
    'std::uint8_t': (8, False), 'std::int8_t': (8, True),
    'std::uint16_t': (16, False), 'std::int16_t': (16, True),
    'std::uint32_t': (32, False), 'std::int32_t': (32, True),
    'std::uint64_t': (64, False), 'std::int64_t': (64, True),
    'size_t': (None, False), 'std::size_t': (None, False),
    'ssize_t': (None, True), 'uintptr_t': (None, False),
    'intptr_t': (None, True),
}
_ALLOCATORS = {'AllocateArrayBuffer', 'AllocateSendableArrayBuffer', 'AllocateBuffer',
               'malloc', 'calloc', 'realloc'}
_WRITERS = {'SetValueInBuffer', 'FastSetValueInBuffer', 'memcpy', 'memmove'}


@dataclass(frozen=True)
class SizeOverflowCandidate:
    line: int
    column: int
    function: str
    result_name: str
    factor_names: tuple
    allocation_line: int
    loop_line: int
    start_byte: int
    end_byte: int
    may_overflow: bool


def _width(type_text):
    normalized = re.sub(r'\b(const|volatile|typename)\b', '', type_text)
    normalized = re.sub(r'\s+', '', normalized).replace('&', '').replace('*', '')
    if normalized in _INTEGER_WIDTHS:
        return _INTEGER_WIDTHS[normalized][0]
    if normalized in ('unsigned', 'unsignedint', 'int', 'signed', 'signedint'):
        return 32
    if normalized in ('unsignedlonglong', 'longlong', 'longlongint', 'unsignedlonglongint'):
        return 64
    return None


def _loop_uses_allocated_copy(source, factor_names, allocation_names, body_line):
    # Keep offsets stable while ignoring braces and parentheses in comments and
    # literals. The production AST completeness gate is checked before this
    # lexically bounded scan; this code does not claim full C++ syntax coverage.
    masked = _mask_cpp_noncode(source)

    def matching(text, opening, left='(', right=')'):
        depth = 0
        for index in range(opening, len(text)):
            if text[index] == left:
                depth += 1
            elif text[index] == right:
                depth -= 1
                if depth == 0:
                    return index
        return None

    loop_pattern = re.compile(r'\b(?:for|while)\s*\(')
    cursor = 0
    while True:
        match = loop_pattern.search(masked, cursor)
        if match is None:
            break
        opening = masked.find('(', match.start(), match.end())
        closing = matching(masked, opening)
        if closing is None:
            break
        header = source[opening + 1:closing]
        cursor = closing + 1
        if not any(re.search(r'\b' + re.escape(name) + r'\b', header)
                   for name in factor_names):
            continue
        body_open = masked.find('{', closing + 1)
        next_loop = loop_pattern.search(masked, closing + 1)
        if body_open < 0 or (next_loop is not None and next_loop.start() < body_open):
            continue
        body_close = matching(masked, body_open, '{', '}')
        if body_close is None:
            continue
        body_mask = masked[body_open + 1:body_close]
        body_source = source[body_open + 1:body_close]
        writer_pattern = re.compile(r'\b(' + '|'.join(map(re.escape, sorted(_WRITERS))) + r')\s*\(')
        for writer in writer_pattern.finditer(body_mask):
            call_open = body_mask.find('(', writer.start(), writer.end())
            call_close = matching(body_mask, call_open)
            if call_close is None:
                continue
            args_mask = body_mask[call_open + 1:call_close]
            args_source = body_source[call_open + 1:call_close]
            arg_starts = [0]
            depth = 0
            for index, char in enumerate(args_mask):
                if char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                elif char == ',' and depth == 0:
                    arg_starts.append(index + 1)
            arg_ends = arg_starts[1:] + [len(args_source)]
            args = [args_source[start:end].strip()
                    for start, end in zip(arg_starts, arg_ends)]
            dst_index = 1 if writer.group(1) in ('SetValueInBuffer', 'FastSetValueInBuffer') else 0
            if dst_index < len(args) and any(
                    re.search(r'\b' + re.escape(name) + r'\b', args[dst_index])
                    for name in allocation_names):
                return body_line + source[:match.start()].count('\n')
    return None


def _mask_cpp_noncode(source):
    return re.sub(
        r'R"([^\s()\\]{0,16})\(.*?\)\1"|"(?:\\.|[^"\\])*"|'
        r"'(?:\\.|[^'\\])*'|//[^\n]*|/\*.*?\*/",
        lambda match: re.sub(r'[^\n]', ' ', match.group(0)),
        source, flags=re.DOTALL)


def _balanced_delimiter(source, opening, left='(', right=')'):
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_product(expression):
    masked = _mask_cpp_noncode(expression)
    depth = 0
    for index, char in enumerate(masked):
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == '*' and depth == 0:
            return expression[:index].strip(), expression[index + 1:].strip()
    return None


def _operand_width(expression, type_map):
    expression = expression.strip()
    cast = re.fullmatch(r'static_cast\s*<\s*([^>]+)\s*>\s*\(\s*(\w+)\s*\)', expression)
    if cast:
        return type_map.get(cast.group(2)), _width(cast.group(1))
    c_cast = re.fullmatch(r'\(\s*([\w:]+)\s*\)\s*(\w+)', expression)
    if c_cast:
        return type_map.get(c_cast.group(2)), _width(c_cast.group(1))
    ident = re.fullmatch(r'\w+', expression)
    if ident:
        width = type_map.get(expression)
        return width, width
    return None, None


def _text_allocations(source, size_name):
    masked = _mask_cpp_noncode(source)
    names, sites = set(), []
    for allocator in _ALLOCATORS:
        pattern = re.compile(r'\b' + re.escape(allocator) + r'\s*\(')
        for match in pattern.finditer(masked):
            opening = masked.find('(', match.start(), match.end())
            depth = 0
            closing = None
            for index in range(opening, len(masked)):
                if masked[index] == '(':
                    depth += 1
                elif masked[index] == ')':
                    depth -= 1
                    if depth == 0:
                        closing = index
                        break
            if closing is None:
                continue
            args = source[opening + 1:closing]
            if not re.search(r'\b' + re.escape(size_name) + r'\b', args):
                continue
            prefix = masked[max(masked.rfind(';', 0, match.start()),
                                masked.rfind('{', 0, match.start()),
                                masked.rfind('}', 0, match.start())) + 1:match.start()]
            assignment = re.search(r'\b(\w+)\s*=\s*[\w:]*\s*$', prefix)
            if assignment:
                names.add(assignment.group(1))
                sites.append(source.count('\n', 0, match.start()) + 1)
    changed = True
    while changed:
        changed = False
        pattern = re.compile(r'\b(\w+)\s*\.\s*(?:Update|Set)\s*\(\s*([^;()]*)\s*\)')
        for match in pattern.finditer(masked):
            receiver, args = match.group(1), source[match.start(2):match.end(2)]
            if receiver not in names and any(re.search(r'\b' + re.escape(name) + r'\b', args)
                                             for name in names):
                names.add(receiver)
                changed = True
    return names, sites


def analyze_size_flows(source, *, functions=None, parse_complete=None):
    """Return bounded textual flows within lexically delimited C++ functions.

    The production source index supplies the AST completeness gate. This rule
    uses a local token scan so its candidate pass does not retain or revisit
    Tree-sitter Node wrappers after the shared parser has completed.
    """
    data = source.encode('utf-8') if isinstance(source, str) else source
    if parse_complete is False:
        return (), ('actual_parse_is_partial',)
    text = data.decode('utf-8')
    masked = _mask_cpp_noncode(text)
    function_pattern = re.compile(
        r'\b(?P<name>(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*'
        r'\((?P<params>[^;{}]*)\)\s*(?:const\s*)?\{')
    excluded = {'if', 'for', 'while', 'switch', 'catch', 'sizeof', 'alignof'}
    candidates = []
    cursor = 0
    while True:
        function = function_pattern.search(masked, cursor)
        if function is None:
            break
        cursor = function.end()
        if function.group('name').split('::')[-1] in excluded:
            continue
        function_name = function.group('name')
        if functions is not None:
            matches = [item.qualified_name for item in functions
                       if item.qualified_name.endswith('::' + function_name)]
            if len(matches) == 1:
                function_name = matches[0]
        opening = masked.find('{', function.start(), function.end())
        closing = _balanced_delimiter(masked, opening, '{', '}')
        if closing is None:
            continue
        body_start_char, body_end_char = opening + 1, closing
        body = text[body_start_char:body_end_char]
        body_mask = masked[body_start_char:body_end_char]
        body_line = text.count('\n', 0, body_start_char) + 1
        body_start_byte = len(text[:body_start_char].encode('utf-8'))
        declarations = re.compile(
            r'(?P<type>(?:(?:std::)?(?:u?int(?:8|16|32|64)_t|size_t|ssize_t|'
            r'uintptr_t|intptr_t)|unsigned(?:\s+int)?|signed(?:\s+int)?|int|'
            r'(?:unsigned\s+)?long\s+long))\s+(?P<name>\w+)\s*=\s*(?P<expr>[^;]+);')
        type_map = {}
        type_pattern = re.compile(
            r'\b((?:(?:std::)?(?:u?int(?:8|16|32|64)_t|size_t|ssize_t|'
            r'uintptr_t|intptr_t)|unsigned(?:\s+int)?|signed(?:\s+int)?|int|'
            r'(?:unsigned\s+)?long\s+long))\s+\*?\s*(\w+)\b')
        function_region = text[function.start():closing + 1]
        for declaration in type_pattern.finditer(_mask_cpp_noncode(function_region)):
            type_map[declaration.group(2)] = _width(declaration.group(1))
        for declaration in declarations.finditer(body_mask):
            result_type = _width(declaration.group('type'))
            product = _split_product(body[declaration.start('expr'):declaration.end('expr')])
            if product is None or result_type is None:
                continue
            left, right = product
            left_source, left_op = _operand_width(left, type_map)
            right_source, right_op = _operand_width(right, type_map)
            if None in (left_source, right_source, left_op, right_op):
                continue
            factor_names = tuple(match.group(1) for operand in (left, right)
                                 if (match := re.search(r'(\w+)\s*\)?\s*$', operand)))
            if len(factor_names) != 2:
                continue
            operation_width = max(32, left_op, right_op)
            may_overflow = operation_width < left_source + right_source
            result_name = declaration.group('name')
            allocated, allocation_lines = _text_allocations(body, result_name)
            if not allocated:
                continue
            loop_line = _loop_uses_allocated_copy(body, factor_names, allocated, body_line)
            if loop_line is None:
                continue
            expression_start = declaration.start('expr')
            expression_end = declaration.end('expr')
            expression = body[expression_start:expression_end].strip()
            expression_offset = body.find(expression, expression_start, expression_end)
            line = body_line + body[:expression_offset].count('\n')
            column = (len(body[body.rfind('\n', 0, expression_offset) + 1:expression_offset].encode('utf-8')) + 1)
            local_start = len(body[:expression_offset].encode('utf-8'))
            start_byte = body_start_byte + local_start
            end_byte = start_byte + len(expression.encode('utf-8'))
            candidates.append(SizeOverflowCandidate(
                line, column, function_name, result_name, factor_names,
                body_line + min(allocation_lines) - 1, loop_line,
                start_byte, end_byte, may_overflow))
        cursor = closing + 1
    return tuple(candidates), ()


def analyze_size_overflow(source):
    """Return only candidate flows whose multiplication is narrower than its factors."""
    flows, limitations = analyze_size_flows(source)
    return tuple(flow for flow in flows if flow.may_overflow), limitations


def size_overflow_result_from_flows(unit, model_digest, flows, limitations=()):
    """Adapt already-parsed bounded syntax results to the Detector contract."""
    if limitations:
        return AnalysisResult('limited', 'not_analyzed', limitations=limitations,
                              model_digest=model_digest)
    observations = tuple(
        Observation(
            kind='candidate', line=flow.line, column=flow.column,
            reason='narrow_product_flows_to_allocation_and_copy_loop',
            target_identity=flow.result_name,
            token_origin=' * '.join(flow.factor_names),
            token_line=flow.line, creation_line=flow.allocation_line,
            path=(flow.line, flow.allocation_line, flow.loop_line),
            constraints=((flow.line, 'product_width_covers_factor_ranges', not flow.may_overflow),
                         (flow.loop_line, 'copy_loop_uses_factor_bound', True)),
            symbol=flow.function, region_start_byte=flow.start_byte,
            region_end_byte=flow.end_byte,
            effect_sites=(flow.loop_line,))
        for flow in flows if flow.may_overflow)
    # The local model recognizes only direct integer products and a bounded set
    # of allocation/copy operations. Keep file coverage partial even with a
    # complete syntax tree until general C++ range and CFG reasoning exists.
    return AnalysisResult(
        'limited', 'partial', observations,
        ('bounded_size_product_model_no_general_cpp_ranges_or_cfg',),
        steps=len(flows), model_digest=model_digest)


def analyze_size_overflow_unit(unit, model_digest):
    """Standalone adapter for a source unit; production reuses parsed flows."""
    flows, limitations = analyze_size_flows(
        unit.text, parse_complete=unit.parse_status == 'complete')
    return size_overflow_result_from_flows(unit, model_digest, flows, limitations)



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
        signed_found = False
        declarations = re.finditer(
            r'\b(?P<type>' + signed_types + r')\s+(?P<name>\w+)\s*=\s*(?:0|-1)\s*;', body)
        for declaration in declarations:
            signed_found = True
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
        if (signed_found and not candidates and re.search(
                r'\bAllocateTypedArray\s*\(', body) and re.search(r'\bToIndex\s*\(', body)
                and re.search(r'(?:static_cast\s*<|DoubleInRangeInt32|\b\w+\s*=\s*[A-Za-z_]\w*\s*\()', body)):
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
    if limitations and limitations == ('not_applicable_to_typedarray_length_allocation',):
        return AnalysisResult('limited', 'not_analyzed', (), limitations,
                              steps=0, model_digest=model_digest)
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
        if (not any(token in body for token in ('ToIndex', 'requestIndex', 'accessIndex'))
                and not re.search(r'\bindex\b', body)):
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
        elif re.search(r'UnknownIndexConversion|CheckIndexBounds', body):
            limitations.append('dataview_atomic_index_bounds_semantics_unmodeled:' + name)
        elif (re.search(r'index\s*>\s*size\s*\|\|\s*elementSize\s*>\s*size\s*-\s*index', body)
              or re.search(r'elementSize\s*>\s*size\s*-\s*index', body)):
            continue
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
    if limitations and limitations == ('not_applicable_to_dataview_or_atomics_index_bounds',):
        return AnalysisResult('limited', 'not_analyzed', (), limitations,
                              steps=0, model_digest=model_digest)
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


