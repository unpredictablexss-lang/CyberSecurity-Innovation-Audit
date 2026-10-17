"""Independent local analysis engine shared by research and the strict adapter.

Only the explicit research entry point permits function-local inspection of a
partial file. It never changes SourceUnit.parse_status or invokes the Runner.
"""
from collections import deque
from dataclasses import asdict, dataclass
from hashlib import sha256
from time import perf_counter

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


def analyze_unit(unit, *, model=None, budget=None, research_partial=False):
    model, budget = model or RuntimeTypeModel(), budget or AnalysisBudget()
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
    targets = [f for f in functions if f.qualified_name == model.caller]
    if not targets:
        return AnalysisResult('limited' if actual_partial else 'completed',
                              'not_analyzed' if actual_partial else 'complete',
                              limitations=('target_not_resolved_in_partial_ast',) if actual_partial else ('not_applicable_to_rule',),
                              model_digest=model.digest)
    observations, limitations, total_steps = [], [], 0
    if actual_partial or unit.parse_status != 'complete':
        limitations.extend(('research_only_partial_function_scope',
                            'parse_dependency_contamination_unknown', 'production_runner_not_admitted'))
    signatures = [f for f in functions if f.qualified_name == OWNER + '::' + model.store_name]
    if signatures and any(tuple(f.parameter_types) != model.store_types for f in signatures):
        return AnalysisResult('limited', 'partial', limitations=('sink_definition_signature_mismatch',), model_digest=model.digest)
    for fn in targets:
        if tuple(fn.parameter_types) != model.caller_types:
            limitations.append('caller_signature_mismatch')
            continue
        if fn.node.has_error:
            limitations.append('target_function_parse_error')
            continue
        if len(targets) != 1:
            limitations.append('ambiguous_target_definition')
            continue
        try:
            graph = build_graph(fn, budget)
        except ValueError as error:
            return AnalysisResult('limited', 'not_analyzed', limitations=(str(error),), model_digest=model.digest)
        limitations.extend(graph.limitations)
        evaluator = OriginEvaluator(fn, model)
        queue = deque([(graph.entry, evaluator.initial(), (), ())])
        seen, reached = set(), set()
        while queue:
            if perf_counter() - start > budget.max_seconds:
                # Resource expiry does not publish a truncated candidate set.
                return AnalysisResult('timed_out', 'partial', limitations=('time_budget_exhausted',),
                                      steps=total_steps, model_digest=model.digest)
            if total_steps >= budget.max_steps or len(seen) >= budget.max_states:
                return AnalysisResult('limited', 'partial', limitations=('state_or_step_budget_exhausted',),
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
            hit = evaluator.store_arguments(instruction.node, state)
            if hit:
                kind, target, token, reason = hit
                observations.append(Observation(kind, line, instruction.node.start_point[1] + 1, reason,
                                                target.identity, token.origin, token.origin_line,
                                                target.creation_line, path, constraints))
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
                    kind = 'unknown' if graph.limitations else 'unreachable'
                    observations.append(Observation(kind, instruction.node.start_point[0] + 1, 1,
                                                    'generated_predecessor_unavailable' if graph.limitations
                                                    else 'no_generated_predecessor_path'))
    unique = {}
    for item in observations:
        key = (item.kind, item.line, item.target_identity, item.token_origin, item.reason)
        unique.setdefault(key, item)
    observations = tuple(unique[key] for key in sorted(unique))
    if any(o.kind == 'unknown' for o in observations):
        limitations.append('unresolved_local_observations')
    if not observations and any(x in limitations for x in ('target_function_parse_error', 'caller_signature_mismatch')):
        outcome = 'not_analyzed'
    else:
        outcome = 'partial' if limitations else 'complete'
    return AnalysisResult('limited' if limitations else 'completed', outcome, observations,
                          tuple(sorted(set(limitations))), total_steps, model.digest)
