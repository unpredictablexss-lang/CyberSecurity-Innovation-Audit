"""Auditable lightweight JS/TS/ArkTS lexical frontend.

This frontend reports syntax coverage and structural outlines only. It does not
claim TypeScript/ArkTS type resolution, module graph, manifest semantics or
runtime reachability.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Tuple


def _mask_comments_and_literals(text: str) -> str:
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
            if char in {'"', "'", "`"}:
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


def _line(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def parse_script_text(text: str, language: str) -> Dict[str, Any]:
    masked = _mask_comments_and_literals(text)
    issues = []
    for open_char, close_char in (("{", "}"), ("(", ")"), ("[", "]")):
        if masked.count(open_char) != masked.count(close_char):
            issues.append(f"unbalanced_{open_char}{close_char}")
    functions = []
    for match in re.finditer(
        r"\b(?:function\s*|async\s+function\s*)(?P<name>[A-Za-z_$][\w$]*)\s*\(",
        masked,
    ):
        functions.append({
            "name": match.group("name"),
            "start_line": _line(text, match.start()),
            "end_line": _line(text, match.start()),
        })
    for match in re.finditer(r"\bclass\s+(?P<name>[A-Za-z_$][\w$]*)", masked):
        functions.append({
            "name": match.group("name"),
            "start_line": _line(text, match.start()),
            "end_line": _line(text, match.start()),
        })
    calls = []
    for match in re.finditer(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*\(", masked):
        if match.group("name") in {"if", "for", "while", "switch", "catch", "function"}:
            continue
        calls.append({
            "name": match.group("name"),
            "line": _line(text, match.start()),
            "arguments": (),
        })
    status = "failed" if any(item.startswith("unbalanced_{") for item in issues) else "partial" if issues else "complete"
    return {
        "parse_status": status,
        "parse_issues": issues,
        "functions": functions,
        "calls": calls,
        "variables": [],
    }
