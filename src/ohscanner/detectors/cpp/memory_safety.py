"""Bounded lexical C/C++ memory and integer facts shared by A detectors.

The parser deliberately models only simple function-local declarations,
braced guards and selected allocation/copy/index expressions. It does not
claim full C++ semantics; unsupported constructs remain explicit unknowns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


MAX_UNIT_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024

_TYPE_WORDS = (
    "unsigned", "signed", "const", "volatile", "static", "constexpr",
    "register", "struct", "enum", "class",
)
_INT_TYPE_RE = re.compile(
    r"\b(?P<type>(?:unsigned|signed)?\s*"
    r"(?:char|short|int|long|size_t|ssize_t|u?int(?:8|16|32|64)_t|uintptr_t|ptrdiff_t))"
    r"\s*(?:const\s*)?(?P<name>[A-Za-z_]\w*)\s*(?:=\s*(?P<init>[^;]+))?\s*;"
)
_ARRAY_DECL_RE = re.compile(
    r"\b(?P<type>(?:unsigned\s+|signed\s+)?(?:char|short|int|long|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t))"
    r"\s+(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<capacity>[^]\s][^]]*)\s*\]\s*(?:=\s*[^;]+)?;"
)
_STD_ARRAY_DECL_RE = re.compile(
    r"\bstd\s*::\s*array\s*<\s*(?P<type>[^,<>]+)\s*,\s*(?P<capacity>[^>]+)>\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=[^;]+)?;"
)
_ALLOC_CALL_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*(?:(?:std\s*::\s*)?malloc|calloc|new)\s*\(",
    re.MULTILINE,
)
_MALLOC_ASSIGN_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*(?:\([^;=]*?\)\s*)?(?P<alloc>malloc|calloc)\s*\("
)
_NEW_ARRAY_ASSIGN_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*new\s+(?:\([^)]*\)\s*)?"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_:<>]*)\s*\[\s*(?P<count>[^]]+)\s*\]"
)
_DANGEROUS_COPY_RE = re.compile(
    r"\b(?P<name>memcpy|memmove|strncpy|snprintf|sprintf|strcpy|strcat)\s*\("
)
_INDEX_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<index>[^]\[]+)\s*\]")
_ASSIGN_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);")
_CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\(")
_CONTROL_WORDS = {
    "if", "for", "while", "switch", "catch", "return", "sizeof", "do",
    "else", "new", "delete",
}


@dataclass(frozen=True)
class FunctionShape:
    name: str
    start: int
    end: int
    body_start: int
    body_end: int
    text: str
    params: str = ""


@dataclass(frozen=True)
class GuardShape:
    start: int
    end: int
    condition: str
    true_returns: bool
    true_breaks: bool
    false_returns: bool
    body_end: int


@dataclass(frozen=True)
class ArrayShape:
    name: str
    capacity_text: str
    capacity: Optional[int]
    element_size: Optional[int]
    start: int
    kind: str


@dataclass(frozen=True)
class PointerShape:
    name: str
    capacity_bytes: Optional[int]
    capacity_expression: Optional[str]
    element_size: Optional[int]
    kind: str
    start: int
    count_expression: Optional[str] = None
    element_expression: Optional[str] = None


@dataclass(frozen=True)
class GuardFact:
    symbol: str
    condition: str
    lower: Optional[int]
    upper: Optional[int]
    kind: str
    error_path: str
    position: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "symbol": self.symbol,
            "condition": self.condition,
            "lower": self.lower,
            "upper": self.upper,
            "kind": self.kind,
            "error_path": self.error_path,
            "position": self.position,
        }


@dataclass(frozen=True)
class IntegerShape:
    name: str
    type_text: str
    bits: Optional[int]
    signed: bool
    start: int
    initial_expression: Optional[str]


@dataclass(frozen=True)
class Interval:
    minimum: Optional[int]
    maximum: Optional[int]
    known: bool = True

    @staticmethod
    def unknown() -> "Interval":
        return Interval(None, None, False)

    @staticmethod
    def exact(value: int) -> "Interval":
        return Interval(value, value, True)

    @staticmethod
    def nonnegative() -> "Interval":
        return Interval(0, None, True)

    def is_nonnegative(self) -> bool:
        return self.minimum is not None and self.minimum >= 0

    def definitely_greater_than(self, value: int) -> bool:
        return self.minimum is not None and self.minimum > value

    def definitely_at_least(self, value: int) -> bool:
        return self.minimum is not None and self.minimum >= value

    def definitely_exceeds(self, other: "Interval") -> bool:
        return (
            self.minimum is not None
            and other.maximum is not None
            and self.minimum > other.maximum
        )


def mask_comments_and_literals(text: str) -> str:
    chars = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(chars):
        pair = text[index:index + 2]
        char = text[index]
        if state == "code":
            if pair == "//":
                chars[index:index + 2] = [" ", " "]
                index += 2
                state = "line_comment"
                continue
            if pair == "/*":
                chars[index:index + 2] = [" ", " "]
                index += 2
                state = "block_comment"
                continue
            if char in {'"', "'"}:
                quote = char
                chars[index] = " "
                index += 1
                state = "literal"
                continue
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                chars[index] = " "
            index += 1
            continue
        if state == "block_comment":
            if pair == "*/":
                chars[index:index + 2] = [" ", " "]
                index += 2
                state = "code"
                continue
            if char != "\n":
                chars[index] = " "
            index += 1
            continue
        if char == "\\":
            chars[index] = " "
            if index + 1 < len(chars):
                chars[index + 1] = " "
            index += 2
            continue
        if char == quote:
            chars[index] = " "
            index += 1
            state = "code"
            continue
        if char != "\n":
            chars[index] = " "
        index += 1
    return "".join(chars)


def line_column(text: str, position: int) -> Tuple[int, int]:
    line = text.count("\n", 0, position) + 1
    line_start = text.rfind("\n", 0, position) + 1
    return line, position - line_start + 1


def balanced_end(text: str, start: int, open_char: str = "{", close_char: str = "}") -> Optional[int]:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == open_char:
            depth += 1
        elif text[index] == close_char:
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def function_shapes(masked: str) -> Tuple[FunctionShape, ...]:
    result: List[FunctionShape] = []
    pattern = re.compile(
        r"\b(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)\s*"
        r"(?:->[^;{}]+)?\s*(?:const\s*)?(?:noexcept(?:\([^)]*\))?\s*)?\{",
        re.MULTILINE,
    )
    for match in pattern.finditer(masked):
        if match.group("name") in _CONTROL_WORDS:
            continue
        body_start = match.end() - 1
        body_end = balanced_end(masked, body_start)
        if body_end is None:
            continue
        start = max(0, masked.rfind("\n", 0, match.start()) + 1)
        result.append(FunctionShape(
            match.group("name"), start, body_end, body_start, body_end,
            masked[start:body_end],
            params=match.group("params"),
        ))
    return tuple(result)


def function_at(functions: Sequence[FunctionShape], position: int) -> Optional[FunctionShape]:
    for function in functions:
        if function.start <= position < function.end:
            return function
    return None


def split_top_level(text: str, separator: str = ";") -> Tuple[str, ...]:
    parts: List[str] = []
    start = 0
    depth = 0
    angle_depth = 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "<":
            angle_depth += 1
        elif char == ">":
            angle_depth = max(0, angle_depth - 1)
        elif char == separator and depth == 0 and angle_depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return tuple(item for item in parts if item)


def _constant_value(text: str, constants: Mapping[str, int]) -> Optional[int]:
    value = text.strip()
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        return int(value, 16)
    if re.fullmatch(r"\d+(?:[uUlL]*)", value):
        return int(re.sub(r"[uUlL]+$", "", value), 10)
    if value in constants:
        return constants[value]
    if value.startswith("sizeof"):
        return None
    return None


def type_shape(type_text: str) -> Tuple[Optional[int], bool]:
    normalized = re.sub(r"\s+", " ", type_text.strip().lower())
    signed = not normalized.startswith("unsigned")
    if any(token in normalized for token in ("uint8_t", "unsigned char")):
        return 8, False
    if normalized == "char" or any(token in normalized for token in ("int8_t", "signed char")):
        return 8, True
    if any(token in normalized for token in ("uint16_t", "unsigned short")):
        return 16, False
    if any(token in normalized for token in ("int16_t", "short")):
        return 16, True
    if any(token in normalized for token in ("uint32_t", "unsigned int", "unsigned long")):
        return 32, False
    if any(token in normalized for token in ("int32_t", "int", "long", "ssize_t", "ptrdiff_t")):
        return 32, True
    if any(token in normalized for token in ("uint64_t", "uintptr_t", "size_t")):
        return 64, False
    if "int64_t" in normalized:
        return 64, True
    return None, signed


def declarations(masked: str) -> Tuple[Dict[str, ArrayShape], Dict[str, IntegerShape], Dict[str, int]]:
    arrays: Dict[str, ArrayShape] = {}
    integers: Dict[str, IntegerShape] = {}
    constants: Dict[str, int] = {}
    for match in _ARRAY_DECL_RE.finditer(masked):
        capacity = _constant_value(match.group("capacity"), constants)
        bits, signed = type_shape(match.group("type"))
        arrays[match.group("name")] = ArrayShape(
            match.group("name"), match.group("capacity").strip(), capacity,
            None if bits is None else max(1, bits // 8), match.start(), "c_array",
        )
        if capacity is not None:
            constants[match.group("name")] = capacity
    for match in _STD_ARRAY_DECL_RE.finditer(masked):
        capacity = _constant_value(match.group("capacity"), constants)
        bits, signed = type_shape(match.group("type"))
        arrays[match.group("name")] = ArrayShape(
            match.group("name"), match.group("capacity").strip(), capacity,
            None if bits is None else max(1, bits // 8), match.start(), "std_array",
        )
        if capacity is not None:
            constants[match.group("name")] = capacity
    for match in _INT_TYPE_RE.finditer(masked):
        if _inside_for_header(masked, match.start()):
            continue
        bits, signed = type_shape(match.group("type"))
        initial = match.group("init").strip() if match.group("init") else None
        integers[match.group("name")] = IntegerShape(
            match.group("name"), match.group("type").strip(), bits, signed,
            match.start(), initial,
        )
        if initial is not None:
            value = _constant_value(initial, constants)
            if value is not None:
                constants[match.group("name")] = value
    return arrays, integers, constants


def _inside_for_header(masked: str, position: int) -> bool:
    boundary = max(
        masked.rfind(";", 0, position),
        masked.rfind("{", 0, position),
        masked.rfind("}", 0, position),
    )
    return bool(re.search(r"\bfor\s*\([^()]*$", masked[boundary + 1:position]))


def loop_constraints(
    masked: str,
    position: int,
    constants: Mapping[str, int],
    sizeof_values: Optional[Mapping[str, int]] = None,
) -> Dict[str, Tuple[Optional[int], Optional[int]]]:
    """Bounds for a simple counting ``for`` loop containing ``position``.

    Only ``for (init; i < bound; step)`` and ``i <= bound`` with a constant or
    named bound are modeled. Step direction, mutation inside the body and
    ``break``/``continue`` remain unknown.
    """

    result: Dict[str, Tuple[Optional[int], Optional[int]]] = {}
    for match in re.finditer(r"\bfor\s*\(", masked):
        open_paren = match.end() - 1
        close_paren = balanced_end(masked, open_paren, "(", ")")
        if close_paren is None:
            continue
        header = masked[open_paren + 1:close_paren - 1]
        parts: List[str] = []
        depth = 0
        start = 0
        for index, char in enumerate(header):
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth = max(0, depth - 1)
            elif char == ";" and depth == 0:
                parts.append(header[start:index].strip())
                start = index + 1
        parts.append(header[start:].strip())
        if len(parts) != 3:
            continue
        body_match = re.match(
            r"\s*(?P<body>\{.*?\}|[^;{}]+;)", masked[close_paren:], re.S
        )
        if not body_match:
            continue
        body_start = close_paren + body_match.start("body")
        body_end = close_paren + body_match.end("body")
        if not body_start <= position < body_end:
            continue
        condition = re.fullmatch(
            r"\s*(?P<name>[A-Za-z_]\w*)\s*(?P<op><=|<)\s*(?P<bound>[^;]+?)\s*",
            parts[1],
        )
        if not condition:
            continue
        name = condition.group("name")
        if re.search(
            r"\b" + re.escape(name) + r"\s*=(?!=)", body_match.group("body")
        ):
            continue
        bound = _comparison_value(
            condition.group("bound"), constants, sizeof_values
        )
        init = re.search(
            r"(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<value>[^,]+)", parts[0]
        )
        low = None
        if init is not None and init.group("name") == name:
            low = _constant_value(init.group("value").strip(), constants)
        high = None
        if bound is not None:
            high = bound - 1 if condition.group("op") == "<" else bound
        if low is None and high is None:
            continue
        previous_low, previous_high = result.get(name, (None, None))
        if previous_low is None:
            merged_low = low
        elif low is None:
            merged_low = previous_low
        else:
            merged_low = max(previous_low, low)
        if previous_high is None:
            merged_high = high
        elif high is None:
            merged_high = previous_high
        else:
            merged_high = min(previous_high, high)
        result[name] = (merged_low, merged_high)
    return result


def merge_constraints(
    base: Mapping[str, Tuple[Optional[int], Optional[int]]],
    extra: Mapping[str, Tuple[Optional[int], Optional[int]]],
) -> Dict[str, Tuple[Optional[int], Optional[int]]]:
    merged = dict(base)
    for name, (low, high) in extra.items():
        base_low, base_high = merged.get(name, (None, None))
        merged[name] = (
            low if base_low is None else base_low if low is None else max(base_low, low),
            high if base_high is None else base_high if high is None else min(base_high, high),
        )
    return merged


def guard_shapes(masked: str, functions: Sequence[FunctionShape]) -> Tuple[GuardShape, ...]:
    guards: List[GuardShape] = []
    for match in re.finditer(r"\bif\s*\(", masked):
        function = function_at(functions, match.start())
        if function is None:
            continue
        open_paren = match.end() - 1
        close_paren = balanced_end(masked, open_paren, "(", ")")
        if close_paren is None:
            continue
        condition = masked[open_paren + 1:close_paren - 1].strip()
        cursor = close_paren
        then_match = re.match(r"\s*(?P<then>\{.*?\}|[^;{}]+;)", masked[cursor:], re.S)
        if not then_match:
            continue
        then = then_match.group("then").strip()
        true_returns = bool(re.search(r"\breturn\b", then))
        true_breaks = bool(re.search(r"\b(?:break|continue)\b", then))
        cursor += then_match.end()
        else_match = re.match(r"\s*else\s*(?P<else>\{.*?\}|[^;{}]+;)", masked[cursor:], re.S)
        false_returns = False
        if else_match:
            false_returns = bool(re.search(r"\breturn\b", else_match.group("else")))
            cursor += else_match.end()
        guards.append(GuardShape(
            match.start(), cursor, condition,
            true_returns, true_breaks, false_returns, cursor,
        ))
    return tuple(guards)

def expression_interval(
    expression: str,
    constants: Mapping[str, int],
    constraints: Mapping[str, Tuple[Optional[int], Optional[int]]],
) -> Interval:
    text = expression.strip()
    exact = _constant_value(text, constants)
    if exact is not None:
        return Interval.exact(exact)
    if text == "sizeof" or text.startswith("sizeof("):
        return Interval.unknown()
    if re.fullmatch(r"[A-Za-z_]\w*", text):
        if text in constraints:
            low, high = constraints[text]
            return Interval(low, high, low is not None or high is not None)
        return Interval.unknown()
    offset_match = re.fullmatch(
        r"\s*(?P<name>[A-Za-z_]\w*)\s*(?P<op>[+-])\s*(?P<value>\d+)\s*", text
    )
    if offset_match:
        base = expression_interval(offset_match.group("name"), constants, constraints)
        offset = int(offset_match.group("value"))
        if base.known:
            if offset_match.group("op") == "+":
                return Interval(
                    None if base.minimum is None else base.minimum + offset,
                    None if base.maximum is None else base.maximum + offset,
                    base.known,
                )
            return Interval(
                None if base.minimum is None else base.minimum - offset,
                None if base.maximum is None else base.maximum - offset,
                base.known,
            )
    if re.search(r"[A-Za-z_]\w*", text):
        identifiers = re.findall(r"[A-Za-z_]\w*", text)
        lows: List[int] = []
        highs: List[int] = []
        known = True
        for identifier in identifiers:
            if identifier in ("sizeof", "SIZE_MAX"):
                known = False
                continue
            item = expression_interval(identifier, constants, constraints)
            if not item.known:
                known = False
                continue
            if item.minimum is not None:
                lows.append(item.minimum)
            if item.maximum is not None:
                highs.append(item.maximum)
        if "+" in text and lows and highs:
            return Interval(sum(lows), sum(highs), known)
        if "-" in text and len(identifiers) == 2:
            left = expression_interval(identifiers[0], constants, constraints)
            right = expression_interval(identifiers[1], constants, constraints)
            if left.maximum is not None and right.minimum is not None:
                return Interval(
                    None if left.minimum is None or right.maximum is None else left.minimum - right.maximum,
                    left.maximum - right.minimum,
                    left.known and right.known,
                )
        return Interval(min(lows) if lows else None, max(highs) if highs else None, known)
    return Interval.unknown()


def _comparison_value(text, constants, sizeof_values):
    value_text = text.strip()
    match = re.fullmatch(r"sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)", value_text)
    if match and sizeof_values is not None and match.group(1) in sizeof_values:
        return sizeof_values[match.group(1)]
    return _constant_value(value_text, constants)


def guard_constraints(
    guards: Sequence[GuardShape], position: int, constants: Mapping[str, int],
    sizeof_values: Optional[Mapping[str, int]] = None,
) -> Dict[str, Tuple[Optional[int], Optional[int]]]:
    constraints: Dict[str, Tuple[Optional[int], Optional[int]]] = {}
    for guard in guards:
        if not (guard.body_end <= position or guard.end <= position):
            continue
        condition = guard.condition
        if not guard.true_returns and not guard.true_breaks and not guard.false_returns:
            continue
        negated = guard.true_returns or guard.true_breaks
        patterns = (
            (r"(?P<name>[A-Za-z_]\w*)\s*>=\s*(?P<value>sizeof\s*\([^)]+\)|[A-Za-z_]\w*|\d+)", "ge"),
            (r"(?P<name>[A-Za-z_]\w*)\s*>\s*(?P<value>sizeof\s*\([^)]+\)|[A-Za-z_]\w*|\d+)", "gt"),
            (r"(?P<name>[A-Za-z_]\w*)\s*<=\s*(?P<value>sizeof\s*\([^)]+\)|[A-Za-z_]\w*|\d+)", "le"),
            (r"(?P<name>[A-Za-z_]\w*)\s*<\s*(?P<value>sizeof\s*\([^)]+\)|[A-Za-z_]\w*|\d+)", "lt"),
            (r"(?P<name>[A-Za-z_]\w*)\s*<\s*0", "lt_zero"),
            (r"(?P<name>[A-Za-z_]\w*)\s*==\s*nullptr", "null"),
        )
        for pattern, kind in patterns:
            match = re.search(pattern, condition)
            if not match:
                continue
            name = match.group("name")
            value_text = match.groupdict().get("value")
            value = _comparison_value(value_text, constants, sizeof_values) if value_text else None
            low, high = constraints.get(name, (None, None))
            if kind in {"ge", "gt", "le", "lt"} and value is not None:
                if negated:
                    if kind == "ge":
                        high = value - 1 if high is None else min(high, value - 1)
                    elif kind == "gt":
                        high = value if high is None else min(high, value)
                    elif kind == "le":
                        low = value + 1 if low is None else max(low, value + 1)
                    else:
                        low = value if low is None else max(low, value)
                else:
                    if kind == "ge":
                        low = value if low is None else max(low, value)
                    elif kind == "gt":
                        low = value + 1 if low is None else max(low, value + 1)
                    elif kind == "le":
                        high = value if high is None else min(high, value)
                    else:
                        high = value - 1 if high is None else min(high, value - 1)
            elif kind == "lt_zero":
                if negated:
                    low = 0 if low is None else max(low, 0)
                else:
                    high = -1 if high is None else min(high, -1)
            constraints[name] = (low, high)
    return constraints


def build_guard_facts(
    masked: str,
    functions: Sequence[FunctionShape],
    constants: Optional[Mapping[str, int]] = None,
    sizeof_values: Optional[Mapping[str, int]] = None,
) -> Tuple[GuardFact, ...]:
    """Produce bounded guard facts without changing the public fact schema."""
    constants = constants or {}
    sizeof_values = sizeof_values or {}
    guards = guard_shapes(masked, functions)
    facts: List[GuardFact] = []
    for guard in guards:
        before = guard_constraints(guards, guard.start, constants, sizeof_values)
        after = guard_constraints(guards, guard.body_end, constants, sizeof_values)
        if guard.true_returns:
            error_path = "return"
        elif guard.true_breaks:
            error_path = "break/continue"
        elif guard.false_returns:
            error_path = "false_return"
        else:
            error_path = "unknown"
        zero_exit = (
            guard.true_returns
            and re.fullmatch(
                r"\s*(?P<name>[A-Za-z_]\w*)\s*!=\s*0\s*", guard.condition
            )
        )
        if zero_exit:
            facts.append(GuardFact(
                symbol=zero_exit.group("name"),
                condition=guard.condition,
                lower=0,
                upper=0,
                kind="zero_check",
                error_path=error_path,
                position=guard.start,
            ))
        for symbol, (lower, upper) in sorted(after.items()):
            if before.get(symbol) == (lower, upper):
                continue
            if lower == 0 and upper == 0:
                kind = "zero_check"
            elif lower is not None and upper is not None:
                kind = "range"
            elif lower is not None:
                kind = "lower_bound"
            elif upper is not None:
                kind = "upper_bound"
            elif "nullptr" in guard.condition:
                kind = "null_check"
            else:
                kind = "unknown"
            facts.append(GuardFact(
                symbol=symbol,
                condition=guard.condition,
                lower=lower,
                upper=upper,
                kind=kind,
                error_path=error_path,
                position=guard.start,
            ))
    return tuple(sorted(facts, key=lambda item: (item.position, item.symbol)))


def contains_unsafe_unknown_macro(text: str, position: int) -> bool:
    line_start = text.rfind("\n", 0, position) + 1
    line_end = text.find("\n", position)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    return bool(re.search(r"\b(?:MIN|MAX|ARRAY_SIZE|CHECK_AND_RETURN_RET)\s*\(", line))


def split_call_arguments(text: str) -> Tuple[str, ...]:
    args: List[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        args.append(tail)
    return tuple(args)


def parameter_names(params: str) -> Tuple[str, ...]:
    names: List[str] = []
    for item in split_call_arguments(params):
        declaration = item.split("=", 1)[0].strip()
        identifiers = re.findall(r"[A-Za-z_]\w*", declaration)
        if identifiers:
            candidate = identifiers[-1]
            if candidate not in {
                "void", "const", "unsigned", "signed", "char", "short",
                "int", "long", "float", "double", "bool", "size_t",
            }:
                names.append(candidate)
    return tuple(names)


def call_argument_span(masked: str, call_start: int) -> Optional[Tuple[int, int, str]]:
    open_paren = masked.find("(", call_start)
    if open_paren < 0:
        return None
    depth = 0
    for index in range(open_paren, len(masked)):
        char = masked[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return open_paren + 1, index, masked[open_paren + 1:index]
    return None


def pointer_declarations(masked: str, constants: Mapping[str, int]) -> Dict[str, PointerShape]:
    """Collect simple malloc/calloc/new[] capacity facts for pointer destinations."""
    result: Dict[str, PointerShape] = {}
    for match in _MALLOC_ASSIGN_RE.finditer(masked):
        span = call_argument_span(masked, match.start("alloc"))
        if span is None:
            continue
        args = split_call_arguments(span[2])
        if not args:
            continue
        name = match.group("name")
        alloc = match.group("alloc")
        if alloc == "malloc":
            expression = args[0].strip()
            capacity = _constant_value(expression, constants)
            result[name] = PointerShape(
                name, capacity, expression, None, "malloc", match.start(),
                count_expression=expression,
            )
        elif len(args) >= 2:
            count, element = args[0].strip(), args[1].strip()
            count_value = _constant_value(count, constants)
            element_value = _constant_value(element, constants)
            capacity = (
                count_value * element_value
                if count_value is not None and element_value is not None
                else None
            )
            expression = f"{count} * {element}"
            result[name] = PointerShape(
                name, capacity, expression, None, "calloc", match.start(),
                count_expression=count,
                element_expression=element,
            )
    for match in _NEW_ARRAY_ASSIGN_RE.finditer(masked):
        count = match.group("count").strip()
        bits, _signed = type_shape(match.group("type"))
        element_size = None if bits is None else max(1, bits // 8)
        count_value = _constant_value(count, constants)
        capacity = (
            count_value * element_size
            if count_value is not None and element_size is not None
            else None
        )
        if element_size is None:
            expression = None
        elif element_size == 1:
            expression = count
        else:
            expression = f"{count} * {element_size}"
        name = match.group("name")
        result[name] = PointerShape(
            name, capacity, expression, element_size, "new_array", match.start(),
            count_expression=count,
            element_expression=None if element_size is None else str(element_size),
        )
    return result

