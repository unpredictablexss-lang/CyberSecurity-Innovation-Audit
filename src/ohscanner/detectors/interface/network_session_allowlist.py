"""Narrow AUTH-06 model for the SoftBus authentication callback.

This is not a CVE-name signature. It binds a callback that updates/opens an
authentication channel to the source-defined session-name allowlist check.
A prefix comparison remains a candidate: it does not prove exact membership.
"""
from dataclasses import dataclass
import tree_sitter_c
from tree_sitter import Language, Parser

AUTH_CALLBACKS = frozenset({"OnRecvAuthChannelRequest"})
VALIDATOR = "CheckAuthChannelOfPkgInfoIsValid"

@dataclass(frozen=True)
class AuthSessionObservation:
    line: int
    symbol: str
    kind: str
    message: str

def _walk(node, kind=None):
    stack = [node]
    while stack:
        current = stack.pop()
        if kind is None or current.type == kind:
            yield current
        stack.extend(reversed(current.named_children))

def _text(source, node):
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

def _function_name(source, function):
    declarator = function.child_by_field_name("declarator")
    if declarator is None:
        return ""
    candidates = list(_walk(declarator, "function_declarator"))
    if not candidates:
        return ""
    name = candidates[0].child_by_field_name("declarator")
    while name is not None and name.type not in ("identifier", "field_identifier"):
        next_node = name.child_by_field_name("declarator")
        if next_node is None:
            ids = list(_walk(name, "identifier"))
            return _text(source, ids[-1]) if ids else ""
        name = next_node
    return _text(source, name) if name is not None else ""

def _call_name(source, call):
    function = call.child_by_field_name("function")
    if function is None:
        return ""
    identifiers = list(_walk(function, "identifier")) + list(_walk(function, "field_identifier"))
    return _text(source, identifiers[-1]) if identifiers else _text(source, function).split("::")[-1]

def _args(call):
    arguments = call.child_by_field_name("arguments")
    return list(arguments.named_children) if arguments is not None else []

def _validator_is_rejecting_guard(source, body, first_effect):
    """Only credit a negative validator result that demonstrably leaves the callback."""
    import re
    body_text = _text(source, body)
    for statement in _walk(body, "if_statement"):
        condition = statement.child_by_field_name("condition")
        consequence = statement.child_by_field_name("consequence")
        if (condition is None or consequence is None or condition.type != "parenthesized_expression"
                or statement.start_byte >= first_effect.start_byte):
            continue
        if not condition.named_children:
            continue
        inner = condition.named_children[0]
        if inner.type != "unary_expression" or not _text(source, inner).lstrip().startswith("!"):
            continue
        argument = inner.child_by_field_name("argument")
        calls = list(_walk(argument, "call_expression")) if argument is not None else []
        if not any(_call_name(source, call) == VALIDATOR and "appInfo" in _text(source, call) for call in calls):
            continue
        branch = _text(source, consequence)
        if "return" in branch:
            return True
        match = re.search(r"\bgoto\s+([A-Za-z_]\w*)\s*;", branch)
        if match:
            label = match.group(1)
            label_match = re.search(r"\b" + re.escape(label) + r"\s*:", body_text)
            if label_match and "return" in body_text[label_match.end():]:
                return True
    return False
def _helper_comparison(source, root):
    for function in _walk(root, "function_definition"):
        if _function_name(source, function) != VALIDATOR:
            continue
        body = function.child_by_field_name("body")
        if body is None:
            continue
        comparisons = []
        for call in _walk(body, "call_expression"):
            name = _call_name(source, call)
            joined = " ".join(_text(source, arg) for arg in _args(call))
            if name in ("strcmp", "strncmp") and "sessionName" in joined and "WhiteList" in joined:
                comparisons.append(name)
        if comparisons and all(name == "strcmp" for name in comparisons):
            return "exact"
        if "strncmp" in comparisons:
            return "prefix"
        return "unknown"
    return "unknown"

def find_auth_session_allowlist_candidates(source_text):
    """Find source-bound C callbacks with absent, weak, or unresolved allowlist checks."""
    source = source_text.encode("utf-8")
    parser = Parser(Language(tree_sitter_c.language()))
    tree = parser.parse(source)
    root = tree.root_node
    comparison = _helper_comparison(source, root)
    observations = []
    for function in _walk(root, "function_definition"):
        name = _function_name(source, function)
        body = function.child_by_field_name("body")
        if not name or body is None:
            continue
        calls = [_call_name(source, call) for call in _walk(body, "call_expression")]
        if name not in AUTH_CALLBACKS:
            continue
        calls = list(_walk(body, "call_expression"))
        effects = [call for call in calls if _call_name(source, call) in
                   ("OnRequsetUpdateAuthChannel", "NotifyOpenAuthChannelSuccess")]
        if not effects:
            continue
        validators = [call for call in calls if _call_name(source, call) == VALIDATOR]
        first_effect = min(effects, key=lambda call: call.start_byte)
        if not validators:
            observations.append(AuthSessionObservation(function.start_point.row + 1, name, "missing",
                "auth-channel callback reaches an update/open effect without the session allowlist validator"))
        elif not _validator_is_rejecting_guard(source, body, first_effect):
            observations.append(AuthSessionObservation(function.start_point.row + 1, name, "unguarded",
                "validator call is present, but no recognized negative-result branch rejects before the callback effect"))
        elif comparison == "prefix":
            observations.append(AuthSessionObservation(function.start_point.row + 1, name, "prefix",
                "rejecting allowlist guard is present, but the helper compares only the whitelist-entry prefix length; exact session-name membership is not established"))
        elif comparison == "unknown":
            observations.append(AuthSessionObservation(function.start_point.row + 1, name, "unknown",
                "rejecting validator guard is present, but its session-name comparison semantics are unresolved"))
    return tuple(observations)
