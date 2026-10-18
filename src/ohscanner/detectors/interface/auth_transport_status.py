"""Find explicit authorization rejection paths that return transport success.

This is a bounded lexical check rather than a control-flow proof. It records a
status-channel mismatch candidate; reply-payload semantics and client behavior
must be reviewed separately before drawing a security conclusion.
"""

import re


_PERMISSION_PREDICATES = (
    "CheckPermission", "IsSystemCaller", "VerifyAccessToken",
    "VerifyPermission", "CheckCallingPermission", "IsCallerValid",
)
_SUCCESS_RETURNS = frozenset({
    "0", "EOK", "ERR_OK", "IPC_STUB_SUCCESS",
    "NETMANAGER_SUCCESS", "SOFTBUS_OK", "SUCCESS",
})
_ERROR_MARKERS = ("ERR_", "ERROR", "DENIED", "FAIL", "INVALID")
_CONTROL_NAMES = frozenset({"if", "switch", "while", "for", "catch"})


def _mask_non_code(source):
    """Blank comments and literals while preserving byte/line positions."""
    chars = list(source)
    i = 0
    state = "code"
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line"
                continue
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block"
                continue
            if ch == '"':
                chars[i] = " "
                state = "string"
            elif ch == "'":
                chars[i] = " "
                state = "char"
        elif state == "line":
            if ch == "\n":
                state = "code"
            else:
                chars[i] = " "
        elif state == "block":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
        else:
            if ch == "\\":
                chars[i] = " "
                if i + 1 < len(chars) and chars[i + 1] != "\n":
                    chars[i + 1] = " "
                    i += 2
                    continue
            elif (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                chars[i] = " "
                state = "code"
            elif ch != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def _pairs(masked, opening, closing):
    stack = []
    pairs = {}
    for index, char in enumerate(masked):
        if char == opening:
            stack.append(index)
        elif char == closing and stack:
            pairs[stack.pop()] = index
    return pairs


def _method_name(masked, brace_pairs, offset):
    pattern = re.compile(r"([A-Za-z_]\w*(?:::\w*)*)\s*\([^;{}]*\)\s*(?:const\s*)?\{")
    found = ""
    for match in pattern.finditer(masked, 0, offset + 1):
        name = match.group(1).split("::")[-1]
        brace = masked.find("{", match.start(1), match.end())
        if name not in _CONTROL_NAMES and brace in brace_pairs and brace_pairs[brace] >= offset:
            found = name
    return found


def _top_level_returns(masked, start, end):
    depth = 0
    body_start = start + 1
    returns = list(re.finditer(r"\breturn\s+([A-Za-z_]\w*(?:::\w+)*)\s*;", masked[body_start:end]))
    next_return = 0
    for index in range(start + 1, end):
        char = masked[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        while next_return < len(returns) and returns[next_return].start() + body_start == index:
            match = returns[next_return]
            expression = re.sub(r"\s+", "", match.group(1))
            if depth == 0 and expression in _SUCCESS_RETURNS:
                yield match.start() + body_start, expression
            next_return += 1


def find_permission_denial_transport_success(source):
    """Return (line, method, predicate, status) for the bounded source pattern."""
    if not any(name in source for name in _PERMISSION_PREDICATES) or "WriteInt32" not in source:
        return ()
    masked = _mask_non_code(source)
    parens = _pairs(masked, "(", ")")
    braces = _pairs(masked, "{", "}")
    findings = []
    for match in re.finditer(r"\bif\s*\(", masked):
        condition_open = masked.find("(", match.start(), match.end())
        condition_close = parens.get(condition_open)
        if condition_close is None:
            continue
        condition = masked[condition_open + 1:condition_close]
        predicate = next((name for name in _PERMISSION_PREDICATES
                          if re.search(r"!\s*(?:[A-Za-z_]\w*\s*::\s*)*" + re.escape(name) + r"\s*\(", condition)), "")
        if not predicate:
            continue
        consequence_open = condition_close + 1
        while consequence_open < len(masked) and masked[consequence_open].isspace():
            consequence_open += 1
        if consequence_open >= len(masked) or masked[consequence_open] != "{":
            continue
        consequence_close = braces.get(consequence_open)
        if consequence_close is None:
            continue
        consequence = masked[consequence_open + 1:consequence_close]
        error_write = re.search(r"\bWriteInt32\s*\([^;]*(?:ERR_|ERROR|DENIED|FAIL|INVALID)[A-Za-z_\w]*[^;]*\)", consequence)
        if error_write is None:
            continue
        for return_offset, status in _top_level_returns(masked, consequence_open, consequence_close):
            method = _method_name(masked, braces, match.start())
            line = masked.count("\n", 0, return_offset) + 1
            findings.append((line, method, predicate, status))
    return tuple(findings)
