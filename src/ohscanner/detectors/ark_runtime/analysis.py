"""Independent local analysis engine shared by research and the strict adapter.

Partial-file inspection remains explicit and function-local. The exact-source
adapter carries that bounded result through Runner while preserving blocked
coverage and parse-contamination obligations.
"""
from collections import deque
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from time import perf_counter

from .cross_helper import build_helper_contracts, build_identity_helpers
from .model import AnalysisBudget, RuntimeTypeModel, OWNER
from .runtime_ir import build_graph
from .syntax import parse_functions, walk
from .type_origin import OriginEvaluator


@dataclass(frozen=True)
class Observation:
    kind: str
    line: int
    column: int
    reason: str
    target_identity: str = ''
    token_origin: str = ''
    token_line: int = 0
    creation_line: int = 0
    path: tuple = ()
    constraints: tuple = ()
    symbol: str = ''
    region_start_byte: int = 0
    region_end_byte: int = 0
    effect_sites: tuple = ()


@dataclass(frozen=True)
class AnalysisResult:
    status: str
    file_outcome: str
    observations: tuple = ()
    limitations: tuple = ()
    steps: int = 0
    model_digest: str = ''

    def to_dict(self):
        return asdict(self)


def has_type_origin_flow(function, model):
    """Select an owner function by a typed-array construction and element-store flow.

    Names here identify semantic operations for bounded analysis; the diagnostic
    still depends on resolving the destination object and type-token origins.
    """
    if not function.qualified_name.startswith(OWNER + '::'):
        return False
    property_name, property_arity, _, _ = model.property_store
    creates_typed_array = False
    stores_typed_array_element = False
    for node in walk(function.body):
        if node.type != 'call_expression':
            continue
        name = function.call_name(node).rsplit('.', 1)[-1].removeprefix('this->')
        args = function.arguments(node)
        if name == model.creator_name and len(args) == model.creator_arguments:
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'field_expression':
                creates_typed_array = True
        elif name == model.same_type_creator[1] and len(args) == model.same_type_creator[2]:
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'field_expression':
                creates_typed_array = True
        elif ((name == model.store_name and len(args) == len(model.store_types))
              or (name == property_name and len(args) == property_arity)):
            stores_typed_array_element = True
    return creates_typed_array and stores_typed_array_element


def _unique_observations(items):
    unique = {}
    for item in items:
        key = (item.symbol, item.kind, item.line, item.target_identity, item.token_origin, item.reason)
        unique.setdefault(key, item)
    return tuple(unique[key] for key in sorted(unique))


def analyze_unit(unit, *, model=None, budget=None, research_partial=False,
                 species_read_width_bound=False):
    model, budget = model or RuntimeTypeModel(), budget or AnalysisBudget()
    if model.build_profile != 'assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;not_product_build_verified':
        return AnalysisResult('limited', 'not_analyzed', limitations=('model_build_profile_unresolved',),
                              model_digest=model.digest)
    start = perf_counter()
    data = unit.text.encode('utf-8')
    if sha256(data).hexdigest() != unit.sha256:
        return AnalysisResult('failed', 'failed', limitations=('source_hash_mismatch',))
    if len(data) > budget.max_source_bytes:
        return AnalysisResult('limited', 'not_analyzed', limitations=('source_byte_budget_exhausted',))
    if unit.parse_status in ('failed', 'not_run'):
        return AnalysisResult('limited', 'not_analyzed', limitations=('source_parse_unavailable',))
    if unit.parse_status != 'complete' and not research_partial:
        return AnalysisResult('limited', 'not_analyzed', limitations=('production_requires_complete_ast',))
    if budget.max_seconds <= 0:
        return AnalysisResult('timed_out', 'not_analyzed', limitations=('time_budget_exhausted',))
    try:
        tree, functions = parse_functions(data)
    except (ValueError, RuntimeError) as error:
        return AnalysisResult('failed', 'failed', limitations=('parser_failure:' + type(error).__name__,))
    actual_partial = tree.root_node.has_error
    if actual_partial and not research_partial:
        return AnalysisResult('limited', 'not_analyzed', limitations=('actual_parse_is_partial',))
    helper_contracts = build_helper_contracts(functions)
    identity_helpers = build_identity_helpers(functions)
    targets = [f for f in functions if f.qualified_name in model.callers
               or has_type_origin_flow(f, model)]
    if not targets:
        return AnalysisResult('limited' if actual_partial else 'completed',
                              'not_analyzed' if actual_partial else 'complete',
                              limitations=('target_not_resolved_in_partial_ast',) if actual_partial else ('not_applicable_to_rule',),
                              model_digest=model.digest)
    observations, limitations, total_steps = [], [], 0
    model_names = {'GetObjectType', 'LoadHClass', model.store_name, model.creator_name,
                   'NewObjectStubBuilder', 'GateRef', 'BRANCH', 'Bind', 'Jump', 'LoopBegin', 'LoopEnd',
                   'Int32Equal', 'Equal', 'GetEnvironment', 'Int32', 'Int64'}
    model_names.update(name.split('::')[-1] for name, _ in model.scalar_operations)
    model_names.update(name for name, _ in model.by_value_operations + model.readonly_operations + model.type_stable_operations)
    model_names.update(name for name, _ in model.reviewed_graph_read_overloads)
    model_names.update(('BuiltinsArrayStubBuilder', 'SetParameters', 'GetTaggedValueWithElementsKind',
                        'NewTypedArraySameType', 'CallNGCRuntime', 'RTSTUB_ID', 'LogicAndBuilder', 'And', 'Done',
                        'CopyTypedArrayBuffer'))
    model_names.add(model.property_store[0])
    model_names.update(name for name, _ in model.host_constructors)
    for node in walk(tree.root_node):
        if node.type in ('preproc_def', 'preproc_function_def'):
            name = node.child_by_field_name('name')
            if name and data[name.start_byte:name.end_byte].decode() in model_names:
                return AnalysisResult('limited', 'not_analyzed', limitations=('model_symbol_macro_redefined',),
                                      model_digest=model.digest)
        if node.type in ('class_specifier', 'struct_specifier', 'alias_declaration', 'type_definition'):
            name = node.child_by_field_name('name') or node.child_by_field_name('declarator')
            if name and data[name.start_byte:name.end_byte].decode().strip() in ({'GateRef'} | {n for n, _ in model.host_constructors}):
                return AnalysisResult('limited', 'not_analyzed', limitations=('model_type_declaration_unverified',),
                                      model_digest=model.digest)
    summarized = {'GetObjectType', 'LoadHClass', 'SetParameters', 'GetTaggedValueWithElementsKind'}
    summarized.update(name for name, _ in model.scalar_operations + model.by_value_operations + model.readonly_operations)
    summarized.update(name for name, _ in model.reviewed_graph_read_overloads)
    for function in functions:
        operation = function.qualified_name.split('::')[-1]
        if operation in summarized:
            arity = dict(model.by_value_operations).get(operation)
            if (arity is not None and function.qualified_name == OWNER + '::' + operation
                    and tuple(function.parameter_types) == ('GateRef',) * arity):
                # The local definition corroborates only parameter passing;
                # effects remain unknown and still invalidate old type facts.
                continue
            reviewed_arity = dict(model.reviewed_graph_read_overloads).get(operation)
            if (reviewed_arity is not None and function.qualified_name.endswith('::' + operation)
                    and tuple(function.parameter_types) == ('GateRef',) * reviewed_arity):
                # A matching visible overload is still bounded to this exact
                # graph operation and signature; unsupported overloads remain unknown.
                continue
            return AnalysisResult('limited', 'not_analyzed', limitations=('visible_origin_operation_unverified',),
                                  model_digest=model.digest)
    if actual_partial or unit.parse_status != 'complete':
        limitations.extend(('experimental_partial_function_scope',
                            'parse_dependency_contamination_unknown',
                            'partial_scope_routed_through_semantic_selector'))
    signatures = [f for f in functions if f.qualified_name == OWNER + '::' + model.store_name]
    if signatures and any(tuple(f.parameter_types) != model.store_types for f in signatures):
        return AnalysisResult('limited', 'partial', limitations=('sink_definition_signature_mismatch',), model_digest=model.digest)
    for name, arity in model.type_stable_operations:
        if name not in ('FastGetPropertyByIndex', 'CalculatePositionWithLength'):
            continue
        definitions = [f for f in functions if f.qualified_name == OWNER + '::' + name]
        if definitions and any(len(f.parameter_types) != arity for f in definitions):
            return AnalysisResult('limited', 'partial',
                                  limitations=('type_stability_helper_signature_mismatch:' + name,),
                                  model_digest=model.digest)
    property_name, property_arity, _, _ = model.property_store
    property_definitions = [f for f in functions
                            if f.qualified_name == OWNER + '::' + property_name]
    if property_definitions and any(len(f.parameter_types) != property_arity
                                    for f in property_definitions):
        return AnalysisResult('limited', 'partial',
                              limitations=('type_origin_property_sink_signature_mismatch:' + property_name,),
                              model_digest=model.digest)
    for fn in targets:
        first_observation = len(observations)
        if any(n.type in ('class_specifier', 'struct_specifier')
               and fn.text(n.child_by_field_name('name')) == 'NewObjectStubBuilder'
               for n in walk(fn.body)):
            limitations.append('model_creator_type_shadowed')
            continue
        parent = fn.node.parent
        conditional = False
        while parent is not None:
            conditional |= parent.type in ('preproc_if', 'preproc_ifdef', 'preproc_else', 'preproc_elif')
            parent = parent.parent
        if conditional:
            limitations.append('target_conditional_compilation_unresolved')
            continue
        if tuple(fn.parameter_types) != model.caller_types:
            limitations.append('caller_signature_mismatch')
            continue
        if fn.node.has_error:
            limitations.append('target_function_parse_error')
            continue
        if sum(f.qualified_name == fn.qualified_name for f in targets) != 1:
            limitations.append('ambiguous_target_definition')
            continue
        try:
            graph = build_graph(fn, budget)
        except ValueError as error:
            retained = _unique_observations(observations[:first_observation])
            return AnalysisResult('limited', 'partial' if retained else 'not_analyzed', retained,
                                  tuple(sorted(set(limitations + [str(error)]))), total_steps, model.digest)
        limitations.extend(graph.limitations)
        evaluator = OriginEvaluator(fn, model,
            ((graph.instructions[i].node.start_byte, graph.instructions[i].node.end_byte) for i in graph.cyclic_nodes),
            identity_helpers, helper_contracts,
            species_read_width_bound=species_read_width_bound)
        host_problems = [(inst, evaluator.unsupported_cpp_effect(inst)) for inst in graph.instructions]
        host_problems = [(inst, problem) for inst, problem in host_problems if problem]
        generated_control = False
        for inst in graph.instructions:
            generated_control |= inst.kind in ('BRANCH', 'Bind', 'Jump', 'LoopBegin', 'LoopEnd')
            if generated_control and inst.node.type == 'assignment_expression':
                left = inst.node.child_by_field_name('left')
                binding = fn.resolve(fn.text(left), left) if left and left.type == 'identifier' else None
                if binding and binding.type_name != 'Variable':
                    # C++ GateRef rebinding runs while emitting the graph;
                    # it is not a runtime branch-local Variable/Phi write.
                    host_problems.append((inst, 'host_rebinding_across_generated_blocks_unmodeled'))
        if host_problems:
            for instruction, problem in host_problems:
                observations.append(Observation('unknown', instruction.node.start_point[0] + 1, 1, problem,
                    symbol=fn.qualified_name, region_start_byte=fn.node.start_byte, region_end_byte=fn.node.end_byte))
            limitations.append('unsupported_host_expression_effects')
            continue
        queue = deque([(graph.entry, evaluator.initial(), (), ())])
        seen, reached = set(), set()
        while queue:
            if perf_counter() - start > budget.max_seconds:
                # Retain completed functions; discard the incomplete function.
                return AnalysisResult('timed_out', 'partial', _unique_observations(observations[:first_observation]),
                                      limitations=tuple(sorted(set(limitations + ['time_budget_exhausted']))),
                                      steps=total_steps, model_digest=model.digest)
            if total_steps >= budget.max_steps or len(seen) >= budget.max_states:
                return AnalysisResult('limited', 'partial', _unique_observations(observations[:first_observation]),
                                      limitations=tuple(sorted(set(limitations + ['state_or_step_budget_exhausted']))),
                                      steps=total_steps, model_digest=model.digest)
            index, state, path, constraints = queue.popleft()
            if index == -1 or not graph.instructions:
                continue
            key = (index, state.key())
            if key in seen:
                continue
            seen.add(key)
            reached.add(index)
            total_steps += 1
            instruction = graph.instructions[index]
            line = instruction.node.start_point[0] + 1
            path = path + (line,)
            if instruction.kind == 'unknown' or instruction.problem:
                observations.append(Observation('unknown', line, instruction.node.start_point[1] + 1,
                                                instruction.problem or 'unmodeled_control', path=path,
                                                constraints=constraints))
                continue
            if index in graph.cyclic_nodes and any(
                    evaluator.creation_call(n, state)
                    for n in walk(instruction.node)):
                observations.append(Observation('unknown', line, 1, 'loop_allocation_identity_unmodeled', path=path))
                continue
            evaluator.prepare(instruction, state)
            hit = evaluator.store_arguments(instruction.node, state)
            if hit:
                kind, target, token, reason = hit
                observations.append(Observation(kind, line, instruction.node.start_point[1] + 1, reason,
                                                target.identity, token.origin, token.origin_line,
                                                target.creation_line, path, constraints,
                                                effect_sites=tuple(sorted(state.effects))))
            evaluator.update(instruction, state)
            for target, truth in instruction.successors:
                if target is None:
                    observations.append(Observation('unknown', line, 1, 'unresolved_generated_edge', path=path))
                    continue
                branch_state = state.copy()
                assumptions = constraints
                if truth is not None:
                    condition = instruction.arguments[0]
                    branch_state = evaluator.refine(condition, truth, branch_state)
                    if branch_state is None:
                        continue
                    assumptions += ((line, fn.text(condition), truth),)
                queue.append((target, branch_state, path, assumptions))
        for index, instruction in enumerate(graph.instructions):
            if index not in reached and instruction.node.type == 'call_expression':
                if fn.call_name(instruction.node) == model.store_name:
                    kind = 'unknown' if graph.limitations or any(o.kind == 'unknown' for o in observations) else 'unreachable'
                    observations.append(Observation(kind, instruction.node.start_point[0] + 1, 1,
                                                    'generated_predecessor_unavailable' if graph.limitations
                                                    else 'no_generated_predecessor_path'))
        observations[first_observation:] = [replace(o, symbol=fn.qualified_name,
                                                    region_start_byte=fn.node.start_byte,
                                                    region_end_byte=fn.node.end_byte)
                                            for o in observations[first_observation:]]
    observations = _unique_observations(observations)
    if any(o.kind == 'unknown' for o in observations):
        limitations.append('unresolved_local_observations')
    if not observations and any(x in limitations for x in ('target_function_parse_error', 'caller_signature_mismatch',
                                                          'target_conditional_compilation_unresolved',
                                                          'ambiguous_target_definition', 'model_creator_type_shadowed')):
        outcome = 'not_analyzed'
    else:
        outcome = 'partial' if limitations else 'complete'
    return AnalysisResult('limited' if limitations else 'completed', outcome, observations,
                          tuple(sorted(set(limitations))), total_steps, model.digest)
