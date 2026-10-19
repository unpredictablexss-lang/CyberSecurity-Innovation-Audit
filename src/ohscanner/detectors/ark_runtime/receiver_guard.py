"""Check that TypedArray backing-buffer reads follow a receiver type guard.

This is a bounded generated-IR check. It requires a same-object
GetObjectType(LoadHClass(receiver)) -> IsFastTypeArray predicate and uses the
generated branch graph to determine whether the successful edge dominates the
backing-buffer read. Unsupported control flow remains unknown.
"""
from collections import deque
from dataclasses import dataclass

from .analysis import Observation
from .cross_helper import binding_matches, build_identity_helpers, unwrap_identity_expression
from .model import OWNER, AnalysisBudget
from .runtime_ir import build_graph
from .syntax import parse_functions, walk


@dataclass(frozen=True)
class ReceiverGuardResult:
    status: str
    file_outcome: str
    observations: tuple = ()
    limitations: tuple = ()
    steps: int = 0
    model_digest: str = ''


def _same_binding(fn, expression, binding, identity_helpers=()):
    return binding_matches(fn, expression, binding, identity_helpers)


def _typed_array_guard(fn, instruction, receiver, identity_helpers=()):
    if instruction.kind != 'BRANCH' or not instruction.arguments:
        return False
    condition = instruction.arguments[0]
    for call in walk(condition):
        if call.type != 'call_expression' or fn.call_name(call) not in ('IsFastTypeArray', 'IsTypedArray'):
            continue
        args = fn.arguments(call)
        if len(args) != 1:
            continue
        if fn.call_name(call) == 'IsTypedArray' and _same_binding(fn, args[0], receiver, identity_helpers):
            return True
        if args[0].type != 'identifier':
            continue
        type_binding = fn.resolve(fn.text(args[0]), args[0])
        if type_binding is None:
            continue
        # Bind the type predicate to the same receiver's runtime HClass.
        for node in walk(fn.body):
            if node.type != 'call_expression' or fn.call_name(node) != 'GetObjectType':
                continue
            outer_args = fn.arguments(node)
            if len(outer_args) != 1:
                continue
            load, _ = unwrap_identity_expression(fn, outer_args[0], identity_helpers)
            if load is None or load.type != 'call_expression':
                continue
            if fn.call_name(load) != 'LoadHClass':
                continue
            load_args = fn.arguments(load)
            if (len(load_args) == 1 and _same_binding(fn, load_args[0], receiver, identity_helpers)
                    and type_binding.name):
                parent = node.parent
                while parent is not None and parent.type not in ('init_declarator', 'assignment_expression'):
                    parent = parent.parent
                if parent is not None and parent.type == 'init_declarator':
                    declarator = parent.child_by_field_name('declarator')
                    identifier = declarator
                    while identifier is not None and identifier.type not in ('identifier', 'field_identifier'):
                        identifier = identifier.child_by_field_name('declarator')
                    if (identifier is not None
                            and fn.resolve(fn.text(identifier), identifier) == type_binding):
                        return True
    return False


def _sink_receiver(fn, instruction, sink_name, receiver, identity_helpers=()):
    found = []
    for node in walk(instruction.node):
        if node.type != 'call_expression' or fn.call_name(node) != sink_name:
            continue
        args = fn.arguments(node)
        if len(args) == 1 and _same_binding(fn, args[0], receiver, identity_helpers):
            found.append(node)
    return found


def _reachable_without_successful_guard(graph, sink_index, matching_guards, budget):
    queue = deque([(graph.entry, False)])
    seen, steps = set(), 0
    while queue:
        index, guarded = queue.popleft()
        if index is None or index < 0 or index >= len(graph.instructions):
            continue
        state = (index, guarded)
        if state in seen:
            continue
        seen.add(state)
        steps += 1
        if steps > budget.max_steps:
            return None, steps
        if index == sink_index:
            if not guarded:
                return True, steps
            continue
        instruction = graph.instructions[index]
        if instruction.problem or instruction.kind == 'unknown':
            return None, steps
        for target, truth in instruction.successors:
            if target is None or target < 0:
                continue
            next_guarded = guarded
            if index in matching_guards:
                if truth is True:
                    next_guarded = True
                elif truth is False:
                    next_guarded = False
            queue.append((target, next_guarded))
    return False, steps


def analyze_receiver_guard(unit, *, caller_name=None, identity_helpers=None,
                           caller_types=('GateRef', 'GateRef', 'GateRef', 'Variable*', 'Label*', 'Label*'),
                           sink_name='GetViewedArrayBuffer', budget=None):
    budget = budget or AnalysisBudget()
    if unit.parse_status not in ('complete', 'partial'):
        return ReceiverGuardResult('limited', 'not_analyzed',
                                   limitations=('source_parse_unavailable',))
    try:
        _, functions = parse_functions(unit.text.encode('utf-8'))
    except (ValueError, RuntimeError) as error:
        return ReceiverGuardResult('failed', 'failed',
                                   limitations=('parser_failure:' + type(error).__name__,))
    identity_helpers = build_identity_helpers(functions) if identity_helpers is None else tuple(identity_helpers)
    if caller_name is None:
        applicable = [fn.qualified_name for fn in functions
                      if fn.qualified_name.startswith(OWNER + '::')
                      and any(node.type == 'call_expression' and fn.call_name(node) == sink_name
                              for node in walk(fn.body))]
        if not applicable:
            return ReceiverGuardResult('completed', 'complete')
        results = [analyze_receiver_guard(unit, caller_name=name, caller_types=caller_types,
                                          sink_name=sink_name, budget=budget,
                                          identity_helpers=identity_helpers) for name in applicable]
        observations = tuple(item for result in results for item in result.observations)
        limitations = tuple(sorted({item for result in results for item in result.limitations}))
        steps = sum(result.steps for result in results)
        outcome = ('partial' if limitations or unit.parse_status != 'complete'
                   or any(result.file_outcome == 'partial' for result in results) else 'complete')
        status = 'limited' if outcome != 'complete' else 'completed'
        return ReceiverGuardResult(status, outcome, observations, limitations, steps)
    functions = [fn for fn in functions if fn.qualified_name == caller_name]
    if len(functions) != 1:
        return ReceiverGuardResult('limited', 'not_analyzed',
                                   limitations=('receiver_guard_caller_unresolved',))
    fn = functions[0]
    if fn.node.has_error or tuple(fn.parameter_types) != caller_types:
        return ReceiverGuardResult('limited', 'not_analyzed',
                                   limitations=('receiver_guard_caller_parse_or_signature_unknown',))
    # Parameter positions are declaration offsets; evaluate each GateRef
    # parameter binding and associate only same-binding queries/accessors.
    candidates = [binding for binding in fn.bindings if binding.parameter and binding.type_name == 'GateRef']
    if not candidates:
        return ReceiverGuardResult('limited', 'not_analyzed',
                                   limitations=('receiver_parameter_unresolved',))
    try:
        graph = build_graph(fn, budget)
    except ValueError as error:
        return ReceiverGuardResult('limited', 'not_analyzed', limitations=(str(error),))
    observations, limitations, total_steps = [], [], 0
    for receiver in candidates:
        sinks = [(index, node) for index, instruction in enumerate(graph.instructions)
                 for node in _sink_receiver(fn, instruction, sink_name, receiver, identity_helpers)]
        if not sinks:
            continue
        guards = {index for index, instruction in enumerate(graph.instructions)
                  if instruction.kind == 'BRANCH'
                  and _typed_array_guard(fn, instruction, receiver, identity_helpers)}
        if not guards:
            for index, node in sinks:
                observations.append(Observation('unknown', node.start_point[0] + 1,
                                                node.start_point[1] + 1,
                                                'receiver_type_guard_not_resolved',
                                                symbol=fn.qualified_name,
                                                region_start_byte=fn.node.start_byte,
                                                region_end_byte=fn.node.end_byte))
                limitations.append('receiver_type_guard_not_resolved')
            continue
        for sink_index, node in sinks:
            unsafe, steps = _reachable_without_successful_guard(graph, sink_index, guards, budget)
            total_steps += steps
            if unsafe is None:
                kind, reason = 'unknown', 'receiver_guard_path_unresolved'
                limitations.append(reason)
            elif unsafe:
                kind, reason = 'candidate', 'backing_buffer_read_not_dominated_by_receiver_type_guard'
            else:
                kind, reason = 'matched', 'receiver_type_guard_dominates_backing_buffer_read'
            observations.append(Observation(kind, node.start_point[0] + 1,
                                            node.start_point[1] + 1, reason,
                                            symbol=fn.qualified_name,
                                            path=(fn.node.start_point[0] + 1,
                                                  node.start_point[0] + 1),
                                            region_start_byte=fn.node.start_byte,
                                            region_end_byte=fn.node.end_byte))
    if not observations:
        outcome = 'partial' if graph.limitations else 'complete'
        return ReceiverGuardResult('limited' if graph.limitations else 'completed', outcome,
                                   limitations=tuple(graph.limitations), steps=total_steps)
    if graph.limitations:
        limitations.extend(graph.limitations)
    outcome = 'partial' if limitations or unit.parse_status != 'complete' else 'complete'
    return ReceiverGuardResult('limited' if outcome != 'complete' else 'completed', outcome,
                               tuple(observations), tuple(sorted(set(limitations))), total_steps)
