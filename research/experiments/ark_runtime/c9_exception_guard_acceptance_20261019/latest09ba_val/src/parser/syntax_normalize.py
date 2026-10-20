"""Offset-preserving normalizations for C++ member-pointer dispatch syntax."""

import re


def normalize_member_pointer_syntax(source: bytes) -> bytes:
    """Let Tree-sitter index common ``(this->*member)(args)`` call forms.

    This is syntax recovery only: the member-pointer target remains unresolved.
    Every replacement preserves byte length and newlines, so syntax-tree offsets
    still refer to the original source. Callers must retain the original bytes.
    """
    normalized = re.sub(
        rb"\(this\s*->\s*\*\s*[A-Za-z_]\w*\)(?=\s*\()",
        lambda match: match.group(0).replace(b"*", b" ", 1),
        source,
    )
    return re.sub(
        rb"this\s*->\s*\*\s*(?=\()",
        lambda match: b" " * len(match.group(0)),
        normalized,
    )
