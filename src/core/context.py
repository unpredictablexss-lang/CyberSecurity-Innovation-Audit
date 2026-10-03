import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import List, Optional


_FUNCTION_NAME_PATTERN = re.compile(
    r"((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*$"
)
_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch"}


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class ResolvedContext:
    function: Optional[str]
    function_start_line: Optional[int]
    function_end_line: Optional[int]
    context_start_line: int
    context_end_line: int
    snippet: str
    status: str


def _strip_comments_and_literals(text: str) -> str:
    """Mask comments and quoted literals while preserving text length/newlines."""
    output: List[str] = []
    index = 0
    state = "code"

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                output.extend((" ", " "))
                index += 2
                state = "line_comment"
                continue
            if char == "/" and next_char == "*":
                output.extend((" ", " "))
                index += 2
                state = "block_comment"
                continue
            if char == '"':
                output.append(" ")
                index += 1
                state = "string"
                continue
            if char == "'":
                output.append(" ")
                index += 1
                state = "char"
                continue

            output.append(char)
            index += 1
            continue

        if state == "line_comment":
            if char == "\n":
                output.append("\n")
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue

        quote = '"' if state == "string" else "'"
        if char == "\\" and index + 1 < len(text):
            output.append(" ")
            output.append("\n" if text[index + 1] == "\n" else " ")
            index += 2
            continue
        if char == quote:
            output.append(" ")
            index += 1
            state = "code"
            continue

        output.append("\n" if char == "\n" else " ")
        index += 1

    return "".join(output)


def _line_number(newline_offsets: List[int], position: int) -> int:
    return bisect_right(newline_offsets, position) + 1


def _extract_function_name(header: str) -> Optional[str]:
    close_paren = header.rfind(")")
    if close_paren < 0:
        return None

    depth = 0
    open_paren: Optional[int] = None
    for index in range(close_paren, -1, -1):
        char = header[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                open_paren = index
                break

    if open_paren is None:
        return None

    prefix = header[:open_paren].rstrip()
    match = _FUNCTION_NAME_PATTERN.search(prefix)
    if not match:
        return None

    name = match.group(1)
    leaf_name = name.split("::")[-1].lstrip("~")
    if leaf_name in _CONTROL_KEYWORDS:
        return None

    return name


def find_top_level_function_spans(lines: List[str]) -> List[FunctionSpan]:
    """Best-effort C/C++ function spans without claiming full AST semantics.

    The resolver intentionally targets top-level function definitions, which is
    useful for C components such as cJSON. It is not a replacement for Clang
    AST: in-class C++ definitions, complex attributes/macros, and malformed
    sources may remain unresolved.
    """
    text = "\n".join(lines)
    cleaned = _strip_comments_and_literals(text)
    newline_offsets = [
        index for index, char in enumerate(cleaned) if char == "\n"
    ]

    spans: List[FunctionSpan] = []
    brace_depth = 0
    boundary = 0
    current_name: Optional[str] = None
    current_start_line: Optional[int] = None

    for index, char in enumerate(cleaned):
        if char == "{" and brace_depth == 0:
            header = cleaned[boundary:index]
            function_name = _extract_function_name(header)

            if function_name:
                first_non_space = next(
                    (
                        offset
                        for offset, header_char in enumerate(header)
                        if not header_char.isspace()
                    ),
                    0,
                )
                absolute_start = boundary + first_non_space
                current_name = function_name
                current_start_line = _line_number(
                    newline_offsets, absolute_start
                )

            brace_depth = 1
            continue

        if char == "{" and brace_depth > 0:
            brace_depth += 1
            continue

        if char == "}" and brace_depth > 0:
            brace_depth -= 1
            if brace_depth == 0:
                if current_name is not None and current_start_line is not None:
                    spans.append(
                        FunctionSpan(
                            name=current_name,
                            start_line=current_start_line,
                            end_line=_line_number(newline_offsets, index),
                        )
                    )
                current_name = None
                current_start_line = None
                boundary = index + 1
            continue

        if char == ";" and brace_depth == 0:
            boundary = index + 1

    return spans


def resolve_context(
    lines: List[str],
    line_number: int,
    radius: int = 3,
) -> ResolvedContext:
    if line_number < 1 or line_number > len(lines):
        raise ValueError(f"line_number out of range: {line_number}")
    if radius < 0:
        raise ValueError("radius must be >= 0")

    containing_span = next(
        (
            span
            for span in find_top_level_function_spans(lines)
            if span.start_line <= line_number <= span.end_line
        ),
        None,
    )

    lower_bound = containing_span.start_line if containing_span else 1
    upper_bound = containing_span.end_line if containing_span else len(lines)
    context_start = max(lower_bound, line_number - radius)
    context_end = min(upper_bound, line_number + radius)
    snippet = "\n".join(lines[context_start - 1 : context_end])

    if containing_span:
        return ResolvedContext(
            function=containing_span.name,
            function_start_line=containing_span.start_line,
            function_end_line=containing_span.end_line,
            context_start_line=context_start,
            context_end_line=context_end,
            snippet=snippet,
            status="heuristic_top_level_function",
        )

    return ResolvedContext(
        function=None,
        function_start_line=None,
        function_end_line=None,
        context_start_line=context_start,
        context_end_line=context_end,
        snippet=snippet,
        status="unresolved",
    )
