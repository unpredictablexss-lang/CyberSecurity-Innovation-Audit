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


def guard_shapes(masked: str, functions: Sequence[FunctionShape]) -> Tuple[GuardShape, ...]:
    guards: List[GuardShape] = []
    pattern = re.compile(r"\bif\s*\((?P<condition>[^{}]+?)\)\s*(?P<then>\{[^{}]*\}|[^;{}]+;)", re.S)
    for match in pattern.finditer(masked):
        function = function_at(functions, match.start())
        if function is None:
            continue
        then = match.group("then").strip()
        true_returns = bool(re.search(r"\breturn\b", then))
        true_breaks = bool(re.search(r"\b(?:break|continue)\b", then))
        body_end = match.end()
        rest = masked[body_end:]
        else_match = re.match(r"\s*else\s*(?P<else>\{[^{}]*\}|[^;{}]+;)", rest, re.S)
        false_returns = False
        if else_match:
            false_returns = bool(re.search(r"\breturn\b", else_match.group("else")))
            body_end += else_match.end()
        guards.append(GuardShape(
            match.start(), body_end, match.group("condition").strip(),
            true_returns, true_breaks, false_returns, body_end,
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


def guard_constraints(
    guards: Sequence[GuardShape], position: int, constants: Mapping[str, int]
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
            (r"(?P<name>[A-Za-z_]\w*)\s*>=\s*(?P<value>[A-Za-z_]\w*|\d+)", "ge"),
            (r"(?P<name>[A-Za-z_]\w*)\s*>\s*(?P<value>[A-Za-z_]\w*|\d+)", "gt"),
            (r"(?P<name>[A-Za-z_]\w*)\s*<\s*0", "lt_zero"),
            (r"(?P<name>[A-Za-z_]\w*)\s*==\s*nullptr", "null"),
        )
        for pattern, kind in patterns:
            match = re.search(pattern, condition)
            if not match:
                continue
            name = match.group("name")
            value_text = match.groupdict().get("value")
            value = _constant_value(value_text, constants) if value_text else None
            low, high = constraints.get(name, (None, None))
            if kind in {"ge", "gt"} and value is not None:
                if negated:
                    bound = value - 1 if kind == "ge" else value
                    high = bound if high is None else min(high, bound)
                else:
                    bound = value if kind == "ge" else value + 1
                    low = bound if low is None else max(low, bound)
            elif kind == "lt_zero":
                if negated:
                    low = 0 if low is None else max(low, 0)
                else:
                    high = -1 if high is None else min(high, -1)
            constraints[name] = (low, high)
    return constraints


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

