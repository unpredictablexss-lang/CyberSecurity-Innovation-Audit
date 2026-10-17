"""Bounded generated-code graph. C++ nesting is not generated control flow."""
from dataclasses import dataclass, field
from .syntax import compact

CONTROL = {'BRANCH', 'Bind', 'Jump', 'LoopBegin', 'LoopEnd'}


@dataclass
class Instruction:
    node: object
    kind: str
    arguments: tuple = ()
    successors: list = field(default_factory=list)
    problem: str = ''


@dataclass
class GeneratedGraph:
    instructions: list
    entry: int
    external_labels: frozenset
    limitations: tuple


def label_identity(fn, node):
    while node is not None and node.type in ('pointer_expression', 'parenthesized_expression'):
        node = node.named_children[-1] if node.named_children else None
    if node is None or node.type != 'identifier':
        return None
    binding = fn.resolve(fn.text(node), node)
    return binding.identity if binding and binding.type_name in ('Label', 'Label*') else None


def build_graph(fn, budget):
    instructions = []
    limitations = []

    def append(node, kind, arguments=(), problem=''):
        instructions.append(Instruction(node, kind, arguments, problem=problem))

    def visit(node):
        if len(instructions) >= budget.max_instructions:
            raise ValueError('instruction_budget_exhausted')
        if node.type == 'compound_statement':
            for child in node.named_children:
                visit(child)
        elif node.type in ('if_statement', 'switch_statement', 'for_statement', 'while_statement',
                           'do_statement', 'try_statement', 'preproc_if', 'preproc_ifdef'):
            append(node, 'unknown', problem='unsupported_host_control_or_macro')
        elif node.type == 'return_statement':
            append(node, 'return')
        elif node.type == 'declaration':
            append(node, 'declaration')
        elif node.type == 'expression_statement':
            expression = node.named_children[0] if node.named_children else None
            if expression is None:
                return
            if expression.type == 'call_expression':
                name = fn.call_name(expression)
                args = fn.arguments(expression)
                shadowed = fn.resolve(name, expression)
                if name in CONTROL and shadowed is None:
                    count = 3 if name == 'BRANCH' else 1
                    if len(args) != count:
                        append(expression, 'unknown', problem='invalid_control_signature:' + name)
                    else:
                        append(expression, name, args)
                elif name != 'DEFVARIABLE' and (
                    name.isupper() or any(label_identity(fn, a) for a in args)
                ):
                    append(expression, 'unknown', problem='unmodeled_control:' + name)
                elif shadowed and name in CONTROL:
                    append(expression, 'unknown', problem='shadowed_control:' + name)
                else:
                    append(expression, 'expression')
            else:
                append(expression, 'expression')
        elif node.type not in ('comment', 'empty_statement'):
            append(node, 'unknown', problem='unsupported_statement:' + node.type)

    visit(fn.body)
    labels, duplicated = {}, set()
    external = frozenset(b.identity for b in fn.bindings if b.parameter and b.type_name == 'Label*')
    for index, inst in enumerate(instructions):
        if inst.kind in ('Bind', 'LoopBegin'):
            label = label_identity(fn, inst.arguments[0])
            if label is None:
                inst.problem = 'unresolved_label_binding'
            elif label in labels:
                duplicated.add(label)
            else:
                labels[label] = index

    def destination(arg):
        label = label_identity(fn, arg)
        if label in duplicated:
            return None
        if label in external:
            return -1
        return labels.get(label)

    for index, inst in enumerate(instructions):
        if inst.problem:
            limitations.append(inst.problem + ':' + str(inst.node.start_point[0] + 1))
            continue
        if inst.kind == 'BRANCH':
            for truth, arg in ((True, inst.arguments[1]), (False, inst.arguments[2])):
                target = destination(arg)
                if target is None:
                    limitations.append('unresolved_label_target:' + str(inst.node.start_point[0] + 1))
                inst.successors.append((target, truth))
        elif inst.kind in ('Jump', 'LoopEnd'):
            target = destination(inst.arguments[0])
            if target is None:
                limitations.append('unresolved_label_target:' + str(inst.node.start_point[0] + 1))
            inst.successors.append((target, None))
        elif inst.kind not in ('unknown', 'return') and index + 1 < len(instructions):
            # Bind does not reconnect a previously terminated block. Only a
            # predecessor edge from a branch/jump reaches a detached label.
            inst.successors.append((index + 1, None))
    return GeneratedGraph(instructions, 0, external, tuple(sorted(set(limitations))))
