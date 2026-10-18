"""Narrow guard-before-effect check for the SoftBus auth-channel callback.

The model requires source evidence for the callback, its peer-data decoder, a
state-changing handoff, and a decoded session-name whitelist helper. It does not
infer network reachability or product impact from the callback's name.
"""

import re

from tree_sitter import Language, Parser
import tree_sitter_c


def _walk(node, kind=None):
    if kind is None or node.type == kind:
        yield node
    for child in node.named_children:
        yield from _walk(child, kind)


def _compact(node):
    return re.sub(r"\s+", "", node.text.decode("utf-8", "replace"))


def _name(node):
    if node is None:
        return ""
    for current in _walk(node):
        if current.type in ("identifier", "field_identifier"):
            return current.text.decode("utf-8", "replace")
    return ""


def _function_name(function):
    declarator = function.child_by_field_name("declarator")
    for current in _walk(declarator) if declarator is not None else ():
        if current.type == "function_declarator":
            return _name(current.child_by_field_name("declarator"))
    return ""


def _calls(node):
    for call in _walk(node, "call_expression"):
        function = call.child_by_field_name("function")
        yield call, _name(function), _compact(call)


def _validated_session_name_helpers(root):
    """Require a local helper that compares decoded sessionName to a list."""
    helpers = set()
    for function in _walk(root, "function_definition"):
        name = _function_name(function)
        compact = _compact(function)
        body = function.child_by_field_name("body")
        if (not name or body is None or "sessionName" not in compact
                or "strcmp" not in compact or "WhiteList" not in compact):
            continue
        positive_match = False
        for branch in _walk(body, "if_statement"):
            condition = branch.child_by_field_name("condition")
            consequence = branch.child_by_field_name("consequence")
            if (condition is not None and consequence is not None
                    and "strcmp" in _compact(condition)
                    and "==0" in _compact(condition)
                    and "returntrue" in _compact(consequence)):
                positive_match = True
                break
        statements = body.named_children
        rejecting_fallback = bool(statements and statements[-1].type == "return_statement"
                                  and _compact(statements[-1]) == "returnfalse;")
        if positive_match and rejecting_fallback:
            helpers.add(name)
    return helpers


def _rejects_before_effect(function, helpers, effect_start):
    body = function.child_by_field_name("body")
    if body is None:
        return False
    compact_body = _compact(body)
    if "EXIT_ERR:" not in compact_body or "return;" not in body.text.decode("utf-8", "replace"):
        return False
    for branch in _walk(body, "if_statement"):
        if branch.end_byte >= effect_start:
            continue
        condition = branch.child_by_field_name("condition")
        consequence = branch.child_by_field_name("consequence")
        if condition is None or consequence is None:
            continue
        condition_text = _compact(condition)
        if not any(helper + "(&appInfo)" in condition_text for helper in helpers):
            continue
        consequence_text = _compact(consequence)
        if "gotoEXIT_ERR;" in consequence_text or "return;" in consequence_text:
            return True
    return False


def find_missing_auth_session_allowlist(source):
    """Return `(line, callback)` for peer session data used before an allowlist.

    This is deliberately limited to the reviewed SoftBus AuthChannel request
    shape. It is not a generic claim that arbitrary network callbacks are unsafe.
    """
    if not all(token in source for token in (
            "OnRecvAuthChannelRequest", "TransAuthChannelMsgUnpack",
            "OnRequsetUpdateAuthChannel", "NotifyOpenAuthChannelSuccess")):
        return ()
    parser = Parser(Language(tree_sitter_c.language()))
    root = parser.parse(source.encode("utf-8")).root_node
    helpers = _validated_session_name_helpers(root)
    results = []
    for function in _walk(root, "function_definition"):
        if _function_name(function) != "OnRecvAuthChannelRequest":
            continue
        # An error in a different file region does not erase this function's AST;
        # an error inside the target function does make the guard ordering unknown.
        if function.has_error:
            continue
        body = function.child_by_field_name("body")
        if body is None:
            continue
        calls = list(_calls(body))
        decoded = any(name == "TransAuthChannelMsgUnpack"
                      and "data" in text and "appInfo" in text
                      for _, name, text in calls)
        effect = next((call for call, name, _ in calls
                       if name == "OnRequsetUpdateAuthChannel"), None)
        success = next((call for call, name, _ in calls
                        if name == "NotifyOpenAuthChannelSuccess"), None)
        if not decoded or effect is None or success is None:
            continue
        if _rejects_before_effect(function, helpers, effect.start_byte):
            continue
        results.append((effect.start_point.row + 1, "OnRecvAuthChannelRequest"))
    return tuple(results)
