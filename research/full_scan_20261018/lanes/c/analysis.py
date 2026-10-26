"""Independent local analysis engine shared by research and the strict adapter.

Only the explicit research entry point permits function-local inspection of a
partial file. It never changes SourceUnit.parse_status or invokes the Runner.
"""
from collections import deque
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from time import perf_counter

from .model import AnalysisBudget, RuntimeTypeModel, OWNER
from .runtime_ir import build_graph
from .syntax import parse_functions, parser_environment, walk
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


def _unique_observations(items):
    unique = {}
    for item in items:
        key = (item.symbol, item.kind, item.line, item.target_identity, item.token_origin, item.reason)
        unique.setdefault(key, item)
    return tuple(unique[key] for key in sorted(unique))


def analyze_unit(unit, *, model=None, budget=None, research_partial=False):
    model, budget = model or RuntimeTypeModel(), budget or AnalysisBudget()
    if model.build_profile != 'assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;not_product_build_verified':
        return AnalysisResult('limited', 'not_analyzed', limitations=('model_build_profile_unresolved',),
                              model_digest=model.digest)
    if parser_environment() != model.parser_environment:
        return AnalysisResult('limited', 'not_analyzed', limitations=('parser_environment_mismatch',),
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
    targets = [f for f in functions if f.qualified_name in model.callers]
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
    model_names.update(name for name, _ in model.by_value_operations + model.readonly_operations)
    model_names.update(('BuiltinsArrayStubBuilder', 'SetParameters', 'GetTaggedValueWithElementsKind'))
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
    for function in functions:
        operation = function.qualified_name.split('::')[-1]
        if operation in summarized:
            arity = dict(model.by_value_operations).get(operation)
            if (arity is not None and function.qualified_name == OWNER + '::' + operation
                    and tuple(function.parameter_types) == ('GateRef',) * arity):
                # The local definition corroborates only parameter passing;
                # effects remain unknown and still invalidate old type facts.
                continue
            return AnalysisResult('limited', 'not_analyzed', limitations=('visible_origin_operation_unverified',),
                                  model_digest=model.digest)
    if actual_partial or unit.parse_status != 'complete':
        limitations.extend(('research_only_partial_function_scope',
                            'parse_dependency_contamination_unknown', 'production_runner_not_admitted'))
    signatures = [f for f in functions if f.qualified_name == OWNER + '::' + model.store_name]
    if signatures and any(tuple(f.parameter_types) != model.store_types for f in signatures):
        return AnalysisResult('limited', 'partial', limitations=('sink_definition_signature_mismatch',), model_digest=model.digest)
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
            ((graph.instructions[i].node.start_byte, graph.instructions[i].node.end_byte) for i in graph.cyclic_nodes))
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
    unknown_observations = [o for o in observations if o.kind == 'unknown']
    if unknown_observations:
        limitations.append('unresolved_local_observations')
        limitations.extend('unknown_observation:' + str(item.line) + ':' + item.reason
                           for item in unknown_observations)
    if not observations and any(x in limitations for x in ('target_function_parse_error', 'caller_signature_mismatch',
                                                          'target_conditional_compilation_unresolved',
                                                          'ambiguous_target_definition', 'model_creator_type_shadowed')):
        outcome = 'not_analyzed'
    else:
        outcome = 'partial' if limitations else 'complete'
    return AnalysisResult('limited' if limitations else 'completed', outcome, observations,
                          tuple(sorted(set(limitations))), total_steps, model.digest)
