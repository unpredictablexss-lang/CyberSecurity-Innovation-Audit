"""Conservative exception-path check for generated TypedArray allocation results."""
from collections import deque
from dataclasses import dataclass

from .analysis import Observation
from .cross_helper import binding_matches, build_identity_helpers, unwrap_identity_expression
from .model import OWNER, AnalysisBudget
from .runtime_ir import build_graph
from .syntax import name_node, walk


@dataclass(frozen=True)
class ExceptionGuardResult:
    status: str
    file_outcome: str
    observations: tuple = ()
    limitations: tuple = ()
    steps: int = 0
    model_digest: str = ''


def _creator_assignment(fn, instruction, creator_name, creator_arity):
    for node in walk(instruction.node):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "field_expression":
            continue
        if fn.text(callee.child_by_field_name("field")) != creator_name:
            continue
        args = fn.arguments(node)
        if len(args) != creator_arity:
            continue
        receiver = callee.child_by_field_name("argument")
        if receiver is None or receiver.type != "identifier":
            continue
        builder = fn.resolve(fn.text(receiver), node)
        if builder is None or builder.type_name not in ("NewObjectStubBuilder", "panda::ecmascript::kungfu::NewObjectStubBuilder"):
            continue
        parent = node.parent
        while parent is not None and parent.type != "init_declarator":
            parent = parent.parent
        if parent is None:
            continue
        declarator = parent.child_by_field_name("declarator")
        ident = name_node(declarator)
        if ident is None or ident.type != "identifier":
            continue
        binding = fn.resolve(fn.text(ident), ident)
        if binding is not None and binding.position == ident.start_byte:
            yield binding


def _critical_use(fn, instruction, binding, sink_name, sink_arity, glue_index, object_index, identity_helpers=()):
    for node in walk(instruction.node):
        if node.type != "call_expression" or fn.call_name(node) != sink_name:
            continue
        args = fn.arguments(node)
        refers_to_object = any(binding_matches(fn, arg, binding, identity_helpers)
                               for arg in args)
        if not refers_to_object:
            continue
        valid = fn.resolve(sink_name, node) is None
        valid = valid and len(args) == sink_arity and max(glue_index, object_index) < len(args)
        if valid:
            object_arg = args[object_index]
            valid = binding_matches(fn, object_arg, binding, identity_helpers)
            glue_arg = args[glue_index]
            if glue_arg.type != "identifier":
                valid = False
            else:
                glue_binding = fn.resolve(fn.text(glue_arg), glue_arg)
                valid = (glue_binding is not None and glue_binding.name == "glue"
                         and glue_binding.parameter and glue_binding.type_name == "GateRef")
        if valid:
            # Only accept the exact reviewed wrapper chain. A surrounding or
            # argument-nested call could have effects that happen in the same IR
            # instruction, so the inter-instruction effect walk cannot see it.
            calls = [child for child in walk(instruction.node) if child.type == "call_expression"]
            semantic_calls = [call for call in calls
                              if not any(helper.matches(fn, call) for helper in identity_helpers)]
            wrappers = [call for call in semantic_calls if fn.call_name(call) == "GetObjectType"]
            sinks = [call for call in semantic_calls if fn.call_name(call) == sink_name]
            valid = (
                len(semantic_calls) == 2 and len(wrappers) == 1 and len(sinks) == 1
                and fn.arguments(wrappers[0]) == (node,)
                and fn.resolve("GetObjectType", wrappers[0]) is None
            )
        return node, valid
    return None


def _writes_binding(fn, instruction, binding):
    for node in walk(instruction.node):
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        if left is not None and left.type == "identifier":
            if fn.resolve(fn.text(left), left) == binding:
                return True
    return False


def _has_pending_exception(fn, branch, identity_helpers=()):
    if branch.kind != "BRANCH" or not branch.arguments:
        return False
    condition = branch.arguments[0]
    if condition.type != "call_expression" or fn.call_name(condition) != "HasPendingException":
        return False
    args = fn.arguments(condition)
    if fn.resolve("HasPendingException", condition) or len(args) != 1:
        return False
    root, _ = unwrap_identity_expression(fn, args[0], identity_helpers)
    if root is None or root.type != "identifier":
        return False
    binding = fn.resolve(fn.text(root), root)
    return binding is not None and binding.name == "glue" and binding.parameter and binding.type_name == "GateRef"


def _calls_in_instruction(instruction):
    return [child for child in walk(instruction.node) if child.type == "call_expression"]


def _known_exception_result_write(fn, instruction):
    calls = _calls_in_instruction(instruction)
    if len(calls) != 2:
        return False
    write = None
    exception = None
    for call in calls:
        callee = call.child_by_field_name("function")
        if callee is not None and callee.type == "field_expression":
            field = callee.child_by_field_name("field")
            if field is not None and fn.text(field) == "WriteVariable":
                write = call
        elif fn.call_name(call) == "Exception":
            exception = call
    if write is None or exception is None:
        return False
    callee = write.child_by_field_name("function")
    args = fn.arguments(write)
    receiver = callee.child_by_field_name("argument") if callee and callee.type == "field_expression" else None
    binding = fn.resolve(fn.text(receiver), receiver) if receiver else None
    return (
        len(args) == 1 and args[0] == exception and not fn.arguments(exception)
        and binding is not None and binding.name == "result" and binding.parameter
        and binding.type_name == "Variable*"
    )

def _trace_use(fn, graph, start, sink_index, budget, identity_helpers=()):
    queue = deque()
    for target, _ in graph.instructions[start].successors:
        if target is not None and target >= 0:
            queue.append((target, True, (graph.instructions[start].node.start_point[0] + 1,)))
            queue.append((target, False, (graph.instructions[start].node.start_point[0] + 1,)))
    seen, candidates, matched, unknown, steps = set(), [], [], [], 0
    while queue:
        index, pending, path = queue.popleft()
        if index < 0 or index >= len(graph.instructions):
            continue
        key = (index, pending)
        if key in seen:
            continue
        seen.add(key)
        steps += 1
        if steps > budget.max_steps:
            return "unknown", (), "exception_path_budget_exhausted", steps
        instruction = graph.instructions[index]
        line = instruction.node.start_point[0] + 1
        next_path = path + (line,)
        if index == sink_index:
            if pending:
                candidates.append(next_path)
            else:
                matched.append(next_path)
            continue
        if instruction.kind == "unknown" or instruction.problem:
            unknown.append(next_path)
            continue
        if _has_pending_exception(fn, instruction, identity_helpers):
            for target, truth in instruction.successors:
                if target is not None and target >= 0:
                    queue.append((target, bool(truth), next_path))
            continue
        if instruction.kind in ("declaration", "expression", "BRANCH"):
            calls = _calls_in_instruction(instruction)
            if calls and not _known_exception_result_write(fn, instruction):
                unknown.append(next_path)
                continue
        for target, _ in instruction.successors:
            if target is not None and target >= 0:
                queue.append((target, pending, next_path))
    if unknown:
        return "unknown", tuple(unknown), "unmodeled_effect_before_exception_guard", steps
    if candidates:
        return "candidate", tuple(candidates), "", steps
    if matched:
        return "matched", tuple(matched), "", steps
    return "unknown", (), "exception_guard_sink_path_unresolved", steps


def analyze_exception_guard(unit, *, creator_name="NewTypedArray", creator_arity=4,
                            sink_name="LoadHClass", sink_arity=2, sink_glue_arg=0,
                            sink_object_arg=1,
                            caller_names=(OWNER + "::Filter",),
                            caller_types=("GateRef", "GateRef", "GateRef", "Variable*", "Label*", "Label*"),
                            budget=None):
    budget = budget or AnalysisBudget()
    if unit.parse_status not in ("complete", "partial"):
        return ExceptionGuardResult("limited", "not_analyzed",
                                    limitations=("source_parse_unavailable",))
    try:
        from .syntax import parse_functions
        _, functions = parse_functions(unit.text.encode("utf-8"))
    except (ValueError, RuntimeError) as error:
        return ExceptionGuardResult("failed", "failed",
                                    limitations=("parser_failure:" + type(error).__name__,))
    identity_helpers = build_identity_helpers(functions)
    owner_functions = [fn for fn in functions
                       if fn.qualified_name in caller_names]
    if not owner_functions:
        return ExceptionGuardResult("limited", "not_analyzed",
                                    limitations=("runtime_owner_not_resolved",))
    findings, limitations, steps = [], [], 0
    found_callers = {fn.qualified_name for fn in owner_functions}
    for expected in caller_names:
        if expected not in found_callers:
            limitations.append("expected_exception_guard_caller_missing:" + expected.rsplit("::", 1)[-1])
    for fn in owner_functions:
        parent = fn.node.parent
        conditional = False
        while parent is not None:
            conditional |= parent.type in ("preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif")
            parent = parent.parent
        if conditional:
            limitations.append("exception_guard_caller_conditional_compilation_unresolved:" + fn.qualified_name.rsplit("::", 1)[-1])
            continue
        if fn.node.has_error:
            limitations.append("exception_guard_caller_parse_error:" + fn.qualified_name.rsplit("::", 1)[-1])
            continue
        if tuple(fn.parameter_types) != caller_types:
            limitations.append("exception_guard_caller_signature_mismatch:" + fn.qualified_name.rsplit("::", 1)[-1])
            continue
        creator_instructions = []
        try:
            graph = build_graph(fn, budget)
        except ValueError as error:
            limitations.append(str(error))
            continue
        for index, instruction in enumerate(graph.instructions):
            for binding in _creator_assignment(fn, instruction, creator_name, creator_arity):
                creator_instructions.append((index, binding, instruction.node.start_point[0] + 1))
        for start, binding, creation_line in creator_instructions:
            reassigned = any(
                index != start and _writes_binding(fn, instruction, binding)
                for index, instruction in enumerate(graph.instructions)
            )
            uses = [(index, _critical_use(fn, instruction, binding, sink_name, sink_arity, sink_glue_arg, sink_object_arg, identity_helpers))
                    for index, instruction in enumerate(graph.instructions)
                    if index > start]
            uses = [(index, result) for index, result in uses if result is not None]
            if not uses:
                continue
            # Report against the first sensitive object-header read. Control
            # flow is walked from the allocation site to that read.
            sink_index, (sink_node, signature_ok) = uses[0]
            if reassigned:
                limitation = "allocation_result_gate_ref_reassigned"
                findings.append(Observation("unknown", sink_node.start_point[0] + 1,
                                            sink_node.start_point[1] + 1, limitation,
                                            token_line=creation_line, symbol=fn.qualified_name,
                                            region_start_byte=fn.node.start_byte,
                                            region_end_byte=fn.node.end_byte))
                limitations.append(limitation)
                continue
            if not signature_ok:
                limitation = "load_hclass_signature_or_binding_mismatch"
                findings.append(Observation("unknown", sink_node.start_point[0] + 1,
                                            sink_node.start_point[1] + 1, limitation,
                                            token_line=creation_line, symbol=fn.qualified_name,
                                            region_start_byte=fn.node.start_byte,
                                            region_end_byte=fn.node.end_byte))
                limitations.append(limitation)
                continue
            status, paths, limitation, used_steps = _trace_use(
                fn, graph, start, sink_index, budget, identity_helpers)
            steps += used_steps
            line = sink_node.start_point[0] + 1
            kind = status
            reason = (
                "allocation_result_hclass_read_on_pending_exception_path"
                if status == "candidate" else
                "pending_exception_check_guards_allocation_result_use"
                if status == "matched" else limitation
            )
            findings.append(Observation(kind, line, sink_node.start_point[1] + 1,
                                        reason, token_line=creation_line,
                                        path=paths[0] if paths else (),
                                        symbol=fn.qualified_name,
                                        region_start_byte=fn.node.start_byte,
                                        region_end_byte=fn.node.end_byte))
            if limitation:
                limitations.append(limitation)
    if not findings:
        return ExceptionGuardResult("limited" if limitations else "completed",
                                    "partial" if limitations else "complete", (),
                                    tuple(sorted(set(limitations))), steps)
    if any(item.kind == "unknown" for item in findings):
        limitations.append("exception_path_not_fully_modeled")
    outcome = "partial" if limitations or unit.parse_status != "complete" else "complete"
    return ExceptionGuardResult("limited" if outcome != "complete" else "completed",
                                outcome, tuple(findings),
                                tuple(sorted(set(limitations))), steps)
