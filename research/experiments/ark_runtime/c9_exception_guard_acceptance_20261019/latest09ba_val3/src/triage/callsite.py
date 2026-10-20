import re
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class ParsedCall:
    name: str
    arguments: List[str]
    expression: str
    start_line: int
    end_line: int
    status: str


def _split_arguments(text: str) -> List[str]:
    arguments: List[str] = []
    current: List[str] = []
    paren = bracket = brace = 0
    state = "code"
    index = 0

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                current.extend((char, next_char))
                index += 2
                state = "line_comment"
                continue
            if char == "/" and next_char == "*":
                current.extend((char, next_char))
                index += 2
                state = "block_comment"
                continue
            if char == '"':
                current.append(char)
                state = "string"
                index += 1
                continue
            if char == "'":
                current.append(char)
                state = "char"
                index += 1
                continue

            if char == "(":
                paren += 1
            elif char == ")":
                paren -= 1
            elif char == "[":
                bracket += 1
            elif char == "]":
                bracket -= 1
            elif char == "{":
                brace += 1
            elif char == "}":
                brace -= 1
            elif char == "," and paren == bracket == brace == 0:
                arguments.append("".join(current).strip())
                current = []
                index += 1
                continue

            current.append(char)
            index += 1
            continue

        current.append(char)

        if state == "line_comment":
            if char == "\n":
                state = "code"
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                current.append(next_char)
                index += 2
                state = "code"
            else:
                index += 1
            continue

        quote = '"' if state == "string" else "'"
        if char == "\\" and index + 1 < len(text):
            current.append(text[index + 1])
            index += 2
            continue
        if char == quote:
            state = "code"
        index += 1

    tail = "".join(current).strip()
    if tail or text.strip():
        arguments.append(tail)

    return arguments


def parse_call_at_line(
    lines: List[str],
    line_number: int,
    call_name: str,
    max_lines: int = 20,
) -> ParsedCall:
    if line_number < 1 or line_number > len(lines):
        raise ValueError(f"line_number out of range: {line_number}")
    if max_lines < 1:
        raise ValueError("max_lines must be >= 1")

    window = "\n".join(
        lines[line_number - 1 : min(len(lines), line_number - 1 + max_lines)]
    )
    match = re.search(
        rf"(?<![A-Za-z0-9_]){re.escape(call_name)}\s*\(",
        window,
    )
    if not match:
        return ParsedCall(
            name=call_name,
            arguments=[],
            expression=lines[line_number - 1].strip(),
            start_line=line_number,
            end_line=line_number,
            status="unresolved_call_expression",
        )

    open_paren = window.find("(", match.start())
    index = open_paren + 1
    depth = 1
    state = "code"

    while index < len(window):
        char = window[index]
        next_char = window[index + 1] if index + 1 < len(window) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                index += 2
                state = "line_comment"
                continue
            if char == "/" and next_char == "*":
                index += 2
                state = "block_comment"
                continue
            if char == '"':
                index += 1
                state = "string"
                continue
            if char == "'":
                index += 1
                state = "char"
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    expression = window[match.start() : index + 1]
                    argument_text = window[open_paren + 1 : index]
                    consumed = window[: index + 1]
                    return ParsedCall(
                        name=call_name,
                        arguments=_split_arguments(argument_text),
                        expression=expression.strip(),
                        start_line=line_number,
                        end_line=line_number + consumed.count("\n"),
                        status="parsed_text_call",
                    )
            index += 1
            continue

        if state == "line_comment":
            if char == "\n":
                state = "code"
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                index += 2
                state = "code"
            else:
                index += 1
            continue

        quote = '"' if state == "string" else "'"
        if char == "\\" and index + 1 < len(window):
            index += 2
            continue
        if char == quote:
            state = "code"
        index += 1

    return ParsedCall(
        name=call_name,
        arguments=[],
        expression=window[match.start() :].strip(),
        start_line=line_number,
        end_line=line_number + window.count("\n"),
        status="unterminated_call_expression",
    )
