"""Bounded, source-backed C++ permission candidate research.

AST syntax evidence only. Models must bind one repository/commit/file/hash and
explicit reviewed entry/permission obligations. Not the proposed Detector API.
"""
import hashlib
import re
from pathlib import PurePosixPath

from tree_sitter import Language, Parser
import tree_sitter_cpp

CPP_LANGUAGE = Language(tree_sitter_cpp.language())

class IncompleteAnalysis(Exception):
    pass


def analyze_cpp(source, model, max_steps=2048):
    if not isinstance(source, bytes) or len(source) > 2_000_000:
        raise ValueError("source must be bytes, at most 2 MB")
    if not isinstance(model, dict) or model.get("research_schema") != "cpp-permission-model-v0":
        raise ValueError("unsupported local model")
    for key in ("repository", "profile", "function", "model_version", "entry_evidence"):
        if not isinstance(model.get(key), str) or not model[key].strip():
            raise ValueError(f"{key} required")
    for key, size in (("commit", 40), ("source_sha256", 64)):
        if not isinstance(model.get(key), str) or not re.fullmatch(r"[0-9a-f]{%d}" % size, model[key]):
            raise ValueError(f"invalid {key}")
    path = model.get("file")
    if not isinstance(path, str) or not path or ":" in path or "\\" in path or PurePosixPath(path).is_absolute() or any(p in {"", ".", ".."} for p in path.split("/")):
        raise ValueError("repository-relative file required")
    if hashlib.sha256(source).hexdigest() != model["source_sha256"]:
        raise ValueError("model/source hash mismatch")
    if type(max_steps) is not int or not 1 <= max_steps <= 20000:
        raise ValueError("invalid analysis budget")
    if type(model.get("entry_verified")) is not bool or type(model.get("obligations_reviewed")) is not bool:
        raise ValueError("explicit entry/policy review flags required")
    guards, sinks = model.get("guards"), model.get("sinks")
    if not isinstance(guards, list) or not isinstance(sinks, list) or not sinks:
        raise ValueError("explicit guard list and nonempty sink list required")
    for item in guards + sinks:
        if not isinstance(item, dict):
            raise ValueError("invalid API model")
        for key in ("callee", "subject", "permission", "resource", "evidence"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"API {key} required")
    guard_keys = []
    for guard in guards:
        if not isinstance(guard.get("arguments"), list) or any(not isinstance(a, str) for a in guard["arguments"]):
            raise ValueError("guard requires exact argument spellings")
        if guard.get("success") != "boolean_true":
            raise ValueError("only reviewed boolean-true guard semantics supported")
        guard_keys.append((guard["callee"], tuple(guard["arguments"])))
    if len(set(guard_keys)) != len(guard_keys) or len({s["callee"] for s in sinks}) != len(sinks):
        raise ValueError("ambiguous duplicate API models")
    benign = model.get("benign_calls", [])
    if not isinstance(benign, list) or any(not isinstance(c, str) for c in benign):
        raise ValueError("invalid benign call list")
    parser = Parser(CPP_LANGUAGE)
    tree = parser.parse(source)

    def text(node):
        if node is None:
            return ""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def walk(node):
        pending = [node]
        while pending:
            current = pending.pop()
            yield current
            pending.extend(reversed(current.named_children))

    def function_name(node):
        declarator = node.child_by_field_name("declarator")
        while declarator is not None and declarator.type != "function_declarator":
            declarator = declarator.child_by_field_name("declarator")
        name = declarator.child_by_field_name("declarator") if declarator is not None else None
        return text(name) if name is not None else ""

    functions = [n for n in walk(tree.root_node) if n.type == "function_definition" and function_name(n) == model["function"]]
    result = {"repository": model["repository"], "commit": model["commit"], "profile": model["profile"],
              "file": path, "source_sha256": model["source_sha256"], "function": model["function"],
              "model_version": model["model_version"], "status": "completed", "assessment": "unknown",
              "parse_status": "partial" if tree.root_node.has_error else "complete",
              "evidence_type": "syntax", "calls": [], "guard_observations": [], "candidates": [],
              "confidence": "unassessed", "runtime_validation": "not_run", "validated_vulnerability": 0,
              "limitations": ["Syntactic path over-approximation, not path feasibility/type/IPC reachability proof.",
                              "Exact API models supplied by researcher; no inferred platform authorization policy.",
                              "Function-local subset only; no macro expansion, aliases, external CFG or cross-language flow."]}
    if len(functions) != 1:
        result.update(status="blocked")
        result["limitations"].append("Requested function missing or ambiguous.")
        return result
    function = functions[0]
    body = function.child_by_field_name("body")

    def call_key(node):
        name = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        return (text(name), tuple(text(a).strip() for a in arguments.named_children) if arguments is not None else ())

    guard_map = dict(zip(guard_keys, guards))
    sink_map = {s["callee"]: s for s in sinks}

    def obligation(item):
        return tuple(item[k] for k in ("subject", "permission", "resource"))

    def condition_guard(node):
        if node is None:
            return None
        if node.type in {"condition_clause", "parenthesized_expression"}:
            children = node.named_children
            return condition_guard(children[0]) if len(children) == 1 else None
        if node.type == "call_expression" and call_key(node) in guard_map:
            return guard_map[call_key(node)], True
        if node.type == "unary_expression" and text(node.child_by_field_name("operator")) == "!":
            child = condition_guard(node.child_by_field_name("argument"))
            return (child[0], not child[1]) if child else None
        return None

    for node in walk(body):
        if node.type == "call_expression":
            callee, arguments = call_key(node)
            result["calls"].append({"callee": callee, "arguments": list(arguments),
                                    "line": node.start_point.row + 1, "column": node.start_point.column + 1})
        if node.type == "if_statement":
            guard = condition_guard(node.child_by_field_name("condition"))
            if guard:
                result["guard_observations"].append({"line": node.start_point.row + 1,
                    "callee": guard[0]["callee"], "condition_true_means_granted": guard[1],
                    "subject": guard[0]["subject"], "permission": guard[0]["permission"],
                    "resource": guard[0]["resource"], "origin": "AST and explicit researcher API model"})
    if tree.root_node.has_error or not model["entry_verified"] or not model["obligations_reviewed"]:
        result.update(status="blocked")
        result["limitations"].append("Incomplete parse, unverified entry or unreviewed sink authorization obligation.")
        return result
    steps = 0
    candidates = {}

    def tick():
        nonlocal steps
        steps += 1
        if steps > max_steps:
            raise IncompleteAnalysis("AST path budget exceeded")

    def scan_expression(node, states):
        if node is None:
            return
        for child in walk(node):
            if child.type in {"lambda_expression", "assignment_expression", "update_expression", "conditional_expression", "new_expression", "delete_expression"}:
                raise IncompleteAnalysis(f"Unsupported expression: {child.type}")
            if child.type == "call_expression":
                callee, args = call_key(child)
                if callee in sink_map:
                    sink = sink_map[callee]
                    for grants, trace in states:
                        if obligation(sink) not in grants:
                            key = child.start_byte
                            candidates.setdefault(key, {"status": "candidate", "evidence_type": "syntax",
                                "callee": callee, "line": child.start_point.row + 1,
                                "column": child.start_point.column + 1, "trace": list(trace),
                                "missing_obligation": dict(zip(("subject", "permission", "resource"), obligation(sink))),
                                "confidence": "unassessed", "message": "Modeled syntactic path lacks matching authorization; review required."})
                elif call_key(child) not in guard_map and callee not in benign:
                    raise IncompleteAnalysis(f"Unmodeled call semantics: {callee}")

    def execute(node, states):
        tick()
        if node is None or not states:
            return states
        if node.type == "comment":
            return states
        if node.type == "compound_statement":
            for child in node.named_children:
                states = execute(child, states)
            return states
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            scan_expression(condition, states)
            guard = condition_guard(condition)
            branches = []
            for truth, field in ((True, "consequence"), (False, "alternative")):
                branch_states = []
                for grants, trace in states:
                    changed = grants
                    if guard:
                        key = obligation(guard[0])
                        granted = truth == guard[1]
                        changed = (grants | {key}) if granted else (grants - {key})
                    branch_states.append((frozenset(changed), trace + (f"if:{node.start_point.row+1}:{truth}",)))
                branches.extend(execute(node.child_by_field_name(field), branch_states))
            if len(branches) > max_steps:
                raise IncompleteAnalysis("Too many path states")
            return branches
        if node.type == "else_clause":
            children = node.named_children
            return execute(children[0], states) if len(children) == 1 else states
        if node.type == "do_statement":
            condition = node.child_by_field_name("condition")
            if text(condition).strip() not in {"(0)", "0", "(false)", "false"}:
                raise IncompleteAnalysis("General do-loop unsupported")
            return execute(node.child_by_field_name("body"), states)
        if node.type == "return_statement":
            scan_expression(node, states)
            return []
        if node.type in {"expression_statement", "declaration"}:
            scan_expression(node, states)
            if node.type == "declaration":
                declared_type = node.child_by_field_name("type")
                if declared_type is None or declared_type.type != "primitive_type":
                    raise IncompleteAnalysis("Unmodeled declaration/type or lifetime effects")
                if any(n.type == "call_expression" and call_key(n) in guard_map for n in walk(node)):
                    raise IncompleteAnalysis("Stored guard result/alias not supported")
            # A bare macro (CALL_DEBUG_ENTER;) is not a semantically known statement.
            if node.type == "expression_statement" and node.named_children and node.named_children[0].type == "identifier":
                raise IncompleteAnalysis("Bare identifier/macro semantics unknown")
            return states
        raise IncompleteAnalysis(f"Unsupported statement: {node.type}")

    try:
        execute(body, [(frozenset(), ())])
    except (IncompleteAnalysis, RecursionError) as error:
        result.update(status="blocked", assessment="unknown", candidates=[])
        result["limitations"].append(str(error))
        return result
    result["candidates"] = [candidates[k] for k in sorted(candidates)]
    result["assessment"] = "candidate" if candidates else "no_uncovered_sink_in_supported_syntax"
    result["analysis_steps"] = steps
    return result
