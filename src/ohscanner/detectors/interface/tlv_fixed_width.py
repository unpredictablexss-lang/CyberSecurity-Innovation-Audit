"""Narrow C++ TLV fixed-width read check, independent of IPC entry discovery.

This catches one parser-helper shape: a serialized TLV length is checked against
available bytes, but a fixed-width object is copied regardless of that length.
It deliberately does not claim caller reachability or exploitability.
"""

import re

from tree_sitter import Language, Parser
import tree_sitter_cpp

from .analysis import walk


def _compact(node):
    return re.sub(r"\s+", "", node.text.decode("utf-8", "replace"))


def _function_name(function):
    declarator = next((node for node in walk(function) if node.type == "function_declarator"), None)
    if declarator is None:
        return ""
    identifier = next((node for node in declarator.named_children
                       if node.type in ("identifier", "field_identifier")), None)
    return identifier.text.decode("utf-8", "replace") if identifier else ""


def _arguments(call):
    args = next((node for node in call.named_children if node.type == "argument_list"), None)
    return [_compact(child) for child in args.named_children] if args else []


def _is_rejecting_width_guard(body, copy):
    # Only a prior top-level guard in the function body is credited. A check in
    # a nested or later branch need not dominate the copy.
    for node in body.named_children:
        if node.type != "if_statement" or node.end_byte >= copy.start_byte:
            continue
        condition = next((child for child in node.named_children
                          if child.type == "condition_clause"), None)
        if condition is None or "head.len!=sizeof(T)" not in _compact(condition):
            continue
        consequence = node.named_children[-1] if node.named_children else None
        if consequence is not None and "returnfalse" in _compact(consequence):
            return True
    return False


def find_fixed_width_tlv_overreads(source):
    """Return (line, function-name) for the narrowly modelled vulnerable shape."""
    if not all(token in source for token in
               ("ReadBasicValue", "TLVHead", "HasExpectBuffer", "memcpy_s")):
        return ()
    parser = Parser(Language(tree_sitter_cpp.language()))
    tree = parser.parse(source.encode("utf-8"))
    findings = []
    for function in walk(tree.root_node, "function_definition"):
        name = _function_name(function)
        if name != "ReadBasicValue":
            continue
        declaration = function.parent
        if declaration is None or declaration.type != "template_declaration":
            continue
        if "typenameT" not in _compact(declaration):
            continue
        params = next((node for node in walk(function, "parameter_list")), None)
        if params is None:
            continue
        param_text = _compact(params)
        if "T&value" not in param_text or "TLVHead&head" not in param_text:
            continue
        body = next((node for node in function.named_children
                     if node.type == "compound_statement"), None)
        if body is None:
            continue
        body_text = _compact(body)
        if "HasExpectBuffer(buffer,head.len)" not in body_text:
            continue
        for call in walk(body, "call_expression"):
            callee = call.child_by_field_name("function")
            if callee is None or _compact(callee).split("::")[-1] != "memcpy_s":
                continue
            args = _arguments(call)
            if (len(args) == 4 and args[0] == "&value" and args[1] == "sizeof(T)"
                    and "buffer.data()+cursor_" in args[2] and args[3] == "sizeof(T)"
                    and not _is_rejecting_width_guard(body, call)):
                findings.append((call.start_point.row + 1, name))
                break
    return tuple(findings)
