"""Narrow offset-preserving recovery for unsupported C++ syntax shapes."""

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


_EMPTY_LINKAGE = re.compile(
    rb'^[ \t]*#ifdef[ \t]+__cplusplus[ \t]*\r?\n'
    rb'[ \t]*(?P<opening>extern[ \t]+"C"[ \t]*\{)[ \t]*\r?\n'
    rb'[ \t]*#endif[ \t]*\r?\n'
    rb'(?:[ \t]*\r?\n)*'
    rb'[ \t]*#ifdef[ \t]+__cplusplus[ \t]*\r?\n'
    rb'[ \t]*(?P<closing>\})[ \t]*\r?\n'
    rb'[ \t]*#endif[ \t]*(?=\r?\n|$)', re.M)


def normalize_empty_cpp_linkage_wrappers(source: bytes) -> bytes:
    """Blank only a contiguous, top-level, empty split ``extern "C"`` pair.

    Tree-sitter cannot join a linkage body split over two #ifdef blocks. The
    accepted body contains whitespace only, so removing its empty braces loses
    no declarations or linkage information. Every preprocessor directive and
    original byte position remains intact. This is not general preprocessing.
    Callers must invoke this recovery only for C++ and keep original source bytes.
    """
    matches = list(_EMPTY_LINKAGE.finditer(source))
    if not matches:
        return source
    # Use the raw grammar's lexical spans to avoid matching wrapper-looking text
    # inside comments, strings, raw literals or continued macro arguments.
    from tree_sitter import Language, Parser
    import tree_sitter_cpp
    root = Parser(Language(tree_sitter_cpp.language())).parse(source).root_node
    protected = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in ('comment', 'string_literal', 'raw_string_literal', 'char_literal', 'preproc_arg'):
            protected.append((node.start_byte, node.end_byte))
        else:
            stack.extend(node.named_children)
    masked = bytearray(source)
    for start, end in protected:
        for offset in range(start, end):
            if masked[offset] not in (10, 13):
                masked[offset] = 32
    normalized = bytearray(source)
    depth = 0
    prefix_end = 0
    valid_prefix = True
    for match in matches:
        # Advance once across the input, including skipped candidates, rather
        # than rescanning a growing prefix for every wrapper in a large header.
        for byte in masked[prefix_end:match.start()]:
            if byte == ord('{'):
                depth += 1
            elif byte == ord('}'):
                depth -= 1
                if depth < 0:
                    valid_prefix = False
        prefix_end = match.start()
        first_directive = source.index(b'#', match.start(), match.end())
        probes = (first_directive, match.start('opening'), match.start('closing'))
        if any(masked[offset] == 32 for offset in probes):
            continue
        previous_end = source.rfind(b'\n', 0, match.start())
        previous_start = source.rfind(b'\n', 0, previous_end) + 1
        if previous_end >= 0 and source[previous_start:previous_end].rstrip(b'\r').endswith(b'\\'):
            continue
        # Restrict to declaration scope outside classes/functions/namespaces.
        # Braces in lexical literals and macro bodies were masked above.
        if depth != 0 or not valid_prefix:
            continue
        for name in ('opening', 'closing'):
            start, end = match.span(name)
            normalized[start:end] = b' ' * (end - start)
    return bytes(normalized)
