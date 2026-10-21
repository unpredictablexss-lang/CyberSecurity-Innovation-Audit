"""Check that TypedArray backing-buffer reads follow a receiver type guard.

This is a bounded generated-IR check. It requires a same-object
GetObjectType(LoadHClass(receiver)) -> IsFastTypeArray predicate and uses the
generated branch graph to determine whether the successful edge dominates the
backing-buffer read. Unsupported control flow remains unknown.
"""
from collections import deque
from dataclasses import dataclass

from .analysis import Observation
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


def _same_binding(fn, expression, binding):
    return (expression is not None and expression.type == 'identifier'
            and fn.resolve(fn.text(expression), expression) == binding)


def _typed_array_guard(fn, instruction, receiver):
    if instruction.kind != 'BRANCH' or not instruction.arguments:
        return False
    condition = instruction.arguments[0]
    for call in walk(condition):
        if call.type != 'call_expression' or fn.call_name(call) not in ('IsFastTypeArray', 'IsTypedArray'):
            continue
        args = fn.arguments(call)
        if len(args) != 1:
            continue
        if fn.call_name(call) == 'IsTypedArray' and _same_binding(fn, args[0], receiver):
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
            if len(outer_args) != 1 or outer_args[0].type != 'call_expression':
                continue
            load = outer_args[0]
            if fn.call_name(load) != 'LoadHClass':
                continue
            load_args = fn.arguments(load)
            if (len(load_args) == 1 and _same_binding(fn, load_args[0], receiver)
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


def _sink_receiver(fn, instruction, sink_name, receiver):
    found = []
    for node in walk(instruction.node):
        if node.type != 'call_expression' or fn.call_name(node) != sink_name:
            continue
        args = fn.arguments(node)
        if len(args) == 1 and _same_binding(fn, args[0], receiver):
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


def analyze_receiver_guard(unit, *, caller_name=None,
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
    if caller_name is None:
        applicable = [fn.qualified_name for fn in functions
                      if fn.qualified_name.startswith(OWNER + '::')
                      and any(node.type == 'call_expression' and fn.call_name(node) == sink_name
                              for node in walk(fn.body))]
        if not applicable:
            return ReceiverGuardResult('completed', 'complete')
        results = [analyze_receiver_guard(unit, caller_name=name, caller_types=caller_types,
                                          sink_name=sink_name, budget=budget) for name in applicable]
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
                 for node in _sink_receiver(fn, instruction, sink_name, receiver)]
        if not sinks:
            continue
        guards = {index for index, instruction in enumerate(graph.instructions)
                  if instruction.kind == 'BRANCH'
                  and _typed_array_guard(fn, instruction, receiver)}
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


class OriginState:
    def __init__(self, values=None, equivalent=(), invalidated=(), predicates=(), effects=(), escaped=()):
        self.values = dict(values or {})
        self.equivalent = frozenset(equivalent)
        self.invalidated = frozenset(invalidated)
        self.predicates = frozenset(predicates)
        self.effects = frozenset(effects)
        self.escaped = frozenset(escaped)

    def copy(self):
        return OriginState(self.values, self.equivalent, self.invalidated, self.predicates,
                           self.effects, self.escaped)

    def key(self):
        return (tuple(sorted(self.values.items())), tuple(sorted(self.equivalent)),
                tuple(sorted(self.invalidated)), tuple(sorted(self.predicates)), tuple(sorted(self.effects)),
                tuple(sorted(self.escaped)))


class OriginEvaluator:
    def __init__(self, fn, model, cyclic_ranges=()):
        self.fn, self.model = fn, model
        self.cyclic_ranges = tuple(cyclic_ranges)

    @staticmethod
    def token_key(value):
        return value.identity + (':live' if value.valid else ':stale')

    def creation_call(self, node, state):
        if node.type != 'call_expression':
            return False
        callee = node.child_by_field_name('function')
        if not callee or callee.type != 'field_expression':
            return False
        builder = self.value(callee.child_by_field_name('argument'), state)
        return (builder.kind == 'builder' and builder.detail == self.model.creator_owner
                and self.fn.text(callee.child_by_field_name('field')) == self.model.creator_name
                and len(self.fn.arguments(node)) == self.model.creator_arguments)

    def same_type_creation_call(self, node, state):
        if node.type != 'call_expression':
            return False
        callee = node.child_by_field_name('function')
        if not callee or callee.type != 'field_expression':
            return False
        owner, name, arity, source_index, type_index = self.model.same_type_creator
        builder = self.value(callee.child_by_field_name('argument'), state)
        args = self.fn.arguments(node)
        if not (builder.kind == 'builder' and builder.detail == owner
                and self.fn.text(callee.child_by_field_name('field')) == name
                and len(args) == arity):
            return False
        source = self.value(args[source_index], state)
        token = self.value(args[type_index], state)
        return (source.kind == 'object' and token.kind == 'type' and token.valid
                and token.origin == source.identity)

    def _logic_and_chain(self, node):
        if node is None or node.type != 'call_expression':
            return False
        callee = node.child_by_field_name('function')
        args = self.fn.arguments(node)
        if callee and callee.type == 'identifier':
            return (self.fn.text(callee) == 'LogicAndBuilder' and len(args) == 1
                    and self.fn.resolve('LogicAndBuilder', node) is None)
        if callee and callee.type == 'field_expression':
            field = self.fn.text(callee.child_by_field_name('field'))
            receiver = callee.child_by_field_name('argument')
            if field == 'And' and len(args) == 1:
                return self._logic_and_chain(receiver)
            if field == 'Done' and not args:
                return self._logic_and_chain(receiver)
        return False

    def _copy_buffer_runtime_call(self, node):
        if node.type != 'call_expression' or self.fn.call_name(node) != self.model.copy_buffer_runtime[0]:
            return False
        _, runtime_name, arity, buffer_arity = self.model.copy_buffer_runtime
        args = self.fn.arguments(node)
        if len(args) != arity or self.fn.text(args[1]).replace(' ', '') != f'RTSTUB_ID({runtime_name})':
            return False
        buffer_args = args[2]
        return buffer_args.type == 'initializer_list' and len(buffer_args.named_children) == buffer_arity

    def _copy_buffer_runtime_id(self, node):
        args = self.fn.arguments(node)
        if self.fn.call_name(node) != 'RTSTUB_ID' or len(args) != 1 or self.fn.text(args[0]) != self.model.copy_buffer_runtime[1]:
            return False
        parent = node.parent
        while parent is not None and parent.type != 'call_expression':
            parent = parent.parent
        return parent is not None and self._copy_buffer_runtime_call(parent)

    def unsupported_cpp_effect(self, instruction):
        """Keep unmodelled host writes from masquerading as graph value copies.

        Ordinary GateRef assignments, calls and reviewed DSL declarations have
        separate handling. We do not guess C++ evaluation order, writable
        pointer/reference aliasing, implicit constructors or destructors.
        """
        if instruction.kind not in ('BRANCH', 'declaration', 'expression'):
            return ''
        fn, root = self.fn, instruction.node
        for node in walk(root):
            if node.type in ('new_expression', 'delete_expression', 'update_expression'):
                return 'unmodeled_cpp_lifetime_or_update_expression'
            if node.type == 'assignment_expression':
                if instruction.kind != 'expression' or node != root:
                    return 'unmodeled_nested_cpp_assignment'
                left = node.child_by_field_name('left')
                if left and left.type == 'identifier':
                    continue
                if left and left.type == 'field_expression':
                    receiver = left.child_by_field_name('argument')
                    binding = fn.resolve(fn.text(receiver), receiver) if receiver else None
                    if (binding and binding.type_name in ('JSCallArgs', NAMESPACE + '::JSCallArgs')
                            and fn.text(left.child_by_field_name('field')) == 'callThisArg3WithReturnArgs'):
                        continue
                return 'unmodeled_cpp_indirect_assignment'
        if instruction.kind == 'declaration':
            if any(n.type in ('reference_declarator', 'pointer_declarator') for n in walk(root)):
                return 'unmodeled_cpp_writable_alias'
            typ = compact(fn.text(root.child_by_field_name('type')))
            host = {name for name, _ in self.model.host_constructors}
            plain = {'GateRef', 'auto', 'bool', 'int', 'size_t', 'int32_t', 'int64_t'}
            short = typ.removeprefix(NAMESPACE + '::')
            if short not in host | plain:
                return 'unreviewed_cpp_constructor_or_destructor'
            if short in host:
                for child in root.named_children:
                    if child.type == 'init_declarator':
                        initializer = child.child_by_field_name('value')
                        if initializer is None or initializer.type != 'argument_list':
                            return 'unreviewed_host_constructor_form'
                        count = len(initializer.named_children)
                        if count not in dict(self.model.host_constructors)[short]:
                            return 'unreviewed_host_constructor_arity'
                    elif child.type == 'function_declarator':
                        parameters = child.child_by_field_name('parameters')
                        if parameters is None or len(parameters.named_children) not in dict(self.model.host_constructors)[short]:
                            return 'unreviewed_host_constructor_arity'
                    elif child.type == 'identifier' and 0 not in dict(self.model.host_constructors)[short]:
                        return 'unreviewed_host_constructor_arity'
        return ''

    def initial(self):
        return OriginState({b.identity: Value('object', b.identity, origin_line=self.fn.node.start_point[0] + 1)
                            for b in self.fn.bindings if b.parameter and b.type_name == 'GateRef'})

    def invalidate(self, state, call, may_rebind=True, preserve_unescaped=True,
                   preserve_fresh_type=False):
        """Forget sampled facts; preserve only local fresh results proven unescaped.

        An unmodelled call invalidates source-object observations and aliases.
        A fresh result cannot be mutated by a call until it escapes; direct and
        nested call arguments plus the modeled JSCallArgs initializer record
        those escapes. Other unsupported host writes block function analysis.
        This finite abstraction converges in loops and never revalidates a copy
        of an old token when a later read observes the same object.
        """
        from dataclasses import replace
        invalidated = set(state.invalidated)
        passed_objects = set()
        # Passing GateRef by value preserves the local variable binding, but
        # still exposes the referenced object to the call. Track those object
        # identities even when the callee cannot rebind the C++ parameter.
        for argument in self.fn.arguments(call):
            for node in walk(argument):
                if node.type == 'identifier':
                    value = self.value(node, state)
                    if value.kind == 'object':
                        passed_objects.add(value.identity)
        for value in state.values.values():
            if value.kind != 'object':
                continue
            if (preserve_unescaped and value.detail == 'fresh_local_typed_array'
                    and value.identity not in passed_objects
                    and value.identity not in state.escaped):
                continue
            invalidated.add(value.identity)
        state.invalidated = frozenset(invalidated)
        # Keep the identity of an unescaped local allocation so a distinct
        # origin can remain a candidate, but an unknown call cannot preserve
        # any sampled type fact. This avoids treating local non-escape as a
        # proof that every callback or host effect is type-stable.
        stable_fresh = {
            value.identity for value in state.values.values()
            if preserve_fresh_type and value.kind == 'object'
            and value.detail == 'fresh_local_typed_array'
            and value.identity not in passed_objects and value.identity not in state.escaped
        }
        state.values = {
            key: (replace(value, valid=False)
                  if value.kind in ('type', 'hclass')
                  and (not value.valid or value.origin not in stable_fresh)
                  else value)
            for key, value in state.values.items()
        }
        state.equivalent = frozenset()
        state.predicates = frozenset()
        state.effects |= frozenset(((call.start_point[0] + 1, self.fn.call_name(call)),))
        # Without the C++ callee declaration, GateRef arguments could be bound
        # by non-const reference. Retain aliases of the old object but forget
        # the passed lvalue's current binding; a later read cannot silently
        # equate it to a pre-call alias.
        arguments = list(self.fn.arguments(call)) if may_rebind else []
        callee = call.child_by_field_name('function')
        if may_rebind and callee and callee.type == 'field_expression':
            arguments.append(callee.child_by_field_name('argument'))
        for argument in arguments:
            while argument and argument.type in ('pointer_expression', 'parenthesized_expression'):
                argument = argument.named_children[-1] if argument.named_children else None
            if argument and argument.type == 'identifier':
                binding = self.fn.resolve(self.fn.text(argument), argument)
                if binding and state.values.get(binding.identity, UNKNOWN).kind in ('object', 'type', 'hclass'):
                    state.values[binding.identity] = UNKNOWN

    def bound_call(self, node, state):
        """Only the existing reviewed origin/creator model and scalar graph ops.

        No unknown-call purity is inferred from spelling prefixes. These scalar
        operations construct graph values, not runtime callbacks; applicability
        remains a model obligation, including macro and local shadow checks.
        """
        fn = self.fn
        name, args = fn.call_name(node), fn.arguments(node)
        base = name.removeprefix('this->')
        if self._logic_and_chain(node) or self._copy_buffer_runtime_call(node) or self._copy_buffer_runtime_id(node):
            return True
        if fn.resolve(base, node):
            return False
        callee = node.child_by_field_name('function')
        if callee and callee.type == 'field_expression':
            receiver = callee.child_by_field_name('argument')
            receiver_text = fn.text(receiver).replace(' ', '') if receiver else ''
            member = fn.text(callee.child_by_field_name('field'))
            if receiver_text not in ('this', 'this->'):
                builder = self.value(receiver, state)
                if (builder.kind == 'builder' and builder.detail == self.model.creator_owner
                        and member == 'SetParameters' and len(args) == 2):
                    return True
                if (builder.kind == 'builder' and builder.detail == NAMESPACE + '::BuiltinsArrayStubBuilder'
                        and member == 'GetTaggedValueWithElementsKind' and len(args) == 3
                        and self.model.build_profile.startswith('assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;')):
                    return True
                if (builder.kind == 'builder' and builder.detail == self.model.creator_owner
                        and member == self.model.creator_name and len(args) == self.model.creator_arguments):
                    return True
                return False
        if (base in dict(self.model.reviewed_graph_read_overloads)
                and len(args) == dict(self.model.reviewed_graph_read_overloads)[base]):
            return True
        if base in dict(self.model.type_stable_operations) and len(args) == dict(self.model.type_stable_operations)[base]:
            return True
        same_owner, same_name, same_arity, _, _ = self.model.same_type_creator
        if (name == same_name and len(args) == same_arity
                and not fn.resolve(same_name, node)):
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'field_expression':
                builder = self.value(callee.child_by_field_name('argument'), state)
                if builder.kind == 'builder' and builder.detail == same_owner:
                    return self.same_type_creation_call(node, state)
        scalar_arity = dict(self.model.scalar_operations)
        if base in scalar_arity and len(args) == scalar_arity[base]:
            return True
        if (self.model.build_profile.startswith('assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;')
                and base in dict(self.model.readonly_operations)
                and len(args) == dict(self.model.readonly_operations)[base]):
            return True
        if base == 'GetObjectType' and len(args) == 1:
            return True
        # Newer StubBuilder sources carry the runtime glue explicitly when
        # reading an object's HClass. In that reviewed overload the object is
        # the second argument; the operation still only emits a graph read.
        if base == 'LoadHClass' and len(args) in (1, 2):
            return True
        if name == 'DEFVARIABLE' and len(args) == 3:
            return True
        property_name, property_arity, _, _ = self.model.property_store
        if (name in (self.model.store_name, 'this->' + self.model.store_name,
                     OWNER + '::' + self.model.store_name)
                and len(args) == len(self.model.store_types)):
            return not fn.resolve(self.model.store_name, node)
        if name in (property_name, 'this->' + property_name, OWNER + '::' + property_name):
            return len(args) == property_arity and not fn.resolve(property_name, node)
        if callee and callee.type == 'field_expression':
            field = fn.text(callee.child_by_field_name('field'))
            builder = self.value(callee.child_by_field_name('argument'), state)
            if (builder.kind == 'builder' and builder.detail == self.model.creator_owner
                    and field == 'SetParameters' and len(args) == 2):
                return True
            if (builder.kind == 'builder' and builder.detail == NAMESPACE + '::BuiltinsArrayStubBuilder'
                    and field == 'GetTaggedValueWithElementsKind' and len(args) == 3
                    and self.model.build_profile.startswith('assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;')):
                return True
            return (field == self.model.creator_name and builder.kind == 'builder'
                    and builder.detail == self.model.creator_owner and len(args) == self.model.creator_arguments)
        return False

    def passes_by_value(self, node, state):
        name = self.fn.call_name(node).removeprefix('this->')
        if self.fn.resolve(name, node):
            return False
        arity = dict(self.model.by_value_operations).get(name)
        if arity is not None and len(self.fn.arguments(node)) == arity:
            return True
        reviewed_arity = dict(self.model.reviewed_graph_read_overloads).get(name)
        if reviewed_arity is not None and len(self.fn.arguments(node)) == reviewed_arity:
            return True
        callee = node.child_by_field_name('function')
        if callee and callee.type == 'field_expression':
            builder = self.value(callee.child_by_field_name('argument'), state)
            return (builder.kind == 'builder' and builder.detail == NAMESPACE + '::BuiltinsArrayStubBuilder'
                    and self.fn.text(callee.child_by_field_name('field')) == 'NewArray'
                    and len(self.fn.arguments(node)) == 2)
        return False

    def prepare(self, instruction, state):
        """Apply nested effects before sink inspection, guards or assignment.

        All expression locations cross this same internal seam. Unknown C++
        argument evaluation order cannot restore an old fact: invalidate first.
        """
        if instruction.kind not in ('BRANCH', 'declaration', 'expression'):
            return
        node = instruction.arguments[0] if instruction.kind == 'BRANCH' else instruction.node
        if node.type == 'assignment_expression':
            left, right = node.child_by_field_name('left'), node.child_by_field_name('right')
            if (left and left.type == 'field_expression'
                    and self.fn.text(left.child_by_field_name('field')) == 'callThisArg3WithReturnArgs'
                    and right and right.type == 'initializer_list'):
                escaped = set(state.escaped)
                for item in right.named_children:
                    value = self.value(item, state)
                    if value.kind == 'object' and value.detail == 'fresh_local_typed_array':
                        escaped.add(value.identity)
                state.escaped = frozenset(escaped)
        for call in walk(node):
            if call.type == 'call_expression':
                if self.creation_call(call, state):
                    # NewTypedArray may dispatch species code. Its four GateRef
                    # parameters are passed by value, but old runtime type
                    # observations and guards cannot survive that dispatch.
                    self.invalidate(state, call, may_rebind=False)
                elif self.same_type_creation_call(call, state):
                    # This exact helper maps the exemplar's JSType to its
                    # intrinsic constructor; it does not use species dispatch.
                    pass
                elif not self.bound_call(call, state):
                    callee = call.child_by_field_name('function')
                    unknown_member = callee is not None and callee.type == 'field_expression'
                    preserve_fresh_type = bool(self.fn.arguments(call)) and not unknown_member
                    self.invalidate(state, call, may_rebind=not self.passes_by_value(call, state),
                                    preserve_unescaped=True,
                                    preserve_fresh_type=preserve_fresh_type)

    def value(self, node, state):
        if node is None:
            return UNKNOWN
        fn = self.fn
        if node.type in ('parenthesized_expression', 'pointer_expression'):
            return self.value(node.named_children[-1], state) if node.named_children else UNKNOWN
        if node.type == 'identifier':
            binding = fn.resolve(fn.text(node), node)
            return state.values.get(binding.identity, UNKNOWN) if binding else UNKNOWN
        if node.type != 'call_expression':
            return UNKNOWN
        name, args = fn.call_name(node), fn.arguments(node)
        if fn.resolve(name, node):
            return UNKNOWN
        if name in ('GetObjectType', 'this->GetObjectType') and len(args) == 1:
            hclass = self.value(args[0], state)
            if hclass.kind == 'hclass':
                cyclic = any(start <= node.start_byte < end for start, end in self.cyclic_ranges)
                return Value('type', identity=f'token:{node.start_byte}', origin=hclass.origin,
                             origin_line=node.start_point[0] + 1, valid=hclass.valid,
                             detail='cyclic_sample' if cyclic else '')
        if name in ('LoadHClass', 'this->LoadHClass') and len(args) in (1, 2):
            obj = self.value(args[-1], state)
            if obj.kind == 'object':
                return Value('hclass', origin=obj.identity, origin_line=node.start_point[0] + 1)
        receiver = node.child_by_field_name('function')
        if receiver and receiver.type == 'field_expression':
            field = fn.text(receiver.child_by_field_name('field'))
            base = receiver.child_by_field_name('argument')
            builder = self.value(base, state)
            if (field == self.model.creator_name and builder.kind == 'builder'
                    and builder.detail == self.model.creator_owner and len(args) == self.model.creator_arguments):
                source = self.value(args[1], state)
                if source.kind == 'object':
                    return Value('object', f'new:{node.start_byte}', origin=source.identity,
                                 origin_line=source.origin_line, creation_line=node.start_point[0] + 1,
                                 may_differ=self.model.creation_may_change_runtime_type,
                                 detail='fresh_local_typed_array')
            owner, name, arity, source_index, type_index = self.model.same_type_creator
            if field == name and builder.kind == 'builder' and builder.detail == owner and len(args) == arity:
                source = self.value(args[source_index], state)
                token = self.value(args[type_index], state)
                if (source.kind == 'object' and token.kind == 'type' and token.valid
                        and token.origin == source.identity):
                    return Value('object', f'same-type:{node.start_byte}', origin=source.identity,
                                 origin_line=source.origin_line, creation_line=node.start_point[0] + 1,
                                 may_differ=False)
        return Value('unknown', identity=f'expr:{node.start_byte}')

    def update(self, instruction, state):
        fn, node = self.fn, instruction.node
        if instruction.kind not in ('declaration', 'expression'):
            return
        if instruction.kind == 'declaration':
            typ = compact(fn.text(node.child_by_field_name('type')))
            for child in node.named_children:
                if child.type not in ('init_declarator', 'function_declarator', 'identifier', 'pointer_declarator'):
                    continue
                dec = child.child_by_field_name('declarator') if child.type == 'init_declarator' else child
                ident = name_node(dec)
                if ident is None or ident.type != 'identifier':
                    continue
                binding = fn.resolve(fn.text(ident), ident)
                if binding is None:
                    continue
                if typ in ('NewObjectStubBuilder', NAMESPACE + '::NewObjectStubBuilder',
                           'BuiltinsArrayStubBuilder', NAMESPACE + '::BuiltinsArrayStubBuilder'):
                    val = Value('builder', binding.identity, detail=(typ if '::' in typ else NAMESPACE + '::' + typ))
                else:
                    val = self.value(child.child_by_field_name('value'), state)
                state.values[binding.identity] = val
        elif node.type == 'assignment_expression':
            # A graph expression at one lexical site can produce a different
            # predicate after a loop assignment; do not reuse its old truth.
            state.predicates = frozenset()
            left = node.child_by_field_name('left')
            if left and left.type == 'identifier':
                binding = fn.resolve(fn.text(left), left)
                if binding:
                    operator = node.child_by_field_name('operator')
                    state.values[binding.identity] = (self.value(node.child_by_field_name('right'), state)
                                                      if fn.text(operator) == '=' else UNKNOWN)

    def store_arguments(self, node, state):
        fn, model = self.fn, self.model
        if node.type != 'call_expression':
            return None
        name = fn.call_name(node)
        property_name, property_arity, property_target_index, property_token_index = model.property_store
        is_element_store = name in (model.store_name, 'this->' + model.store_name,
                                    OWNER + '::' + model.store_name)
        is_property_store = name in (property_name, 'this->' + property_name,
                                     OWNER + '::' + property_name)
        if not is_element_store and not is_property_store:
            callee = node.child_by_field_name('function')
            if (callee and callee.type == 'field_expression'
                    and fn.text(callee.child_by_field_name('field')) in (model.store_name, property_name)):
                return ('unknown', UNKNOWN, UNKNOWN, 'unresolved_sink_receiver')
            return None
        sink_name = property_name if is_property_store else model.store_name
        if fn.resolve(sink_name, node):
            return ('unknown', UNKNOWN, UNKNOWN, 'shadowed_sink')
        args = fn.arguments(node)
        expected_arity = property_arity if is_property_store else len(model.store_types)
        if len(args) != expected_arity:
            return ('unknown', UNKNOWN, UNKNOWN, 'sink_signature_mismatch')
        target_index = property_target_index if is_property_store else model.target_argument
        token_index = property_token_index if is_property_store else model.token_argument
        target = self.value(args[target_index], state)
        token = self.value(args[token_index], state)
        if target.kind != 'object' or token.kind != 'type':
            return ('unknown', target, token, 'unresolved_target_or_type_origin')
        guarantee = (self.token_key(token), target.identity)
        same_type_origin = (target.origin == token.origin and not target.may_differ
                            and target.origin not in state.invalidated)
        if guarantee in state.equivalent or (token.origin == target.identity and token.valid) or same_type_origin:
            return ('matched', target, token, 'target_origin_or_proved_type_equality')
        if target.identity in state.invalidated:
            return ('unknown', target, token, 'creation_relationship_invalidated_by_call')
        if target.may_differ and target.creation_line and token.origin != target.identity:
            # The captured SSA token's origin remains known even if it no
            # longer describes its source object's current type. This is only
            # a distinct-origin candidate, not a proved numeric type mismatch.
            return ('candidate', target, token, 'distinct_origin_with_type_changing_creation')
        if not token.valid:
            return ('unknown', target, token, 'type_fact_invalidated_by_call')
        return ('unknown', target, token, 'unproved_object_relationship')

    def refine(self, condition, truth, state):
        fn = self.fn
        written = compact(fn.text(condition))
        if written in ('true', 'True()', 'Boolean(true)'):
            return state if truth else None
        if written in ('false', 'False()', 'Boolean(false)'):
            return state if not truth else None
        if condition.type == 'identifier':
            value = self.value(condition, state)
            if value.identity:
                if (value.identity, not truth) in state.predicates:
                    return None
                state.predicates |= frozenset(((value.identity, truth),))
        if (condition.type == 'call_expression' and fn.call_name(condition) in ('Int32Equal', 'Equal')
                and self.bound_call(condition, state)):
            args = fn.arguments(condition)
            if len(args) == 2:
                left, right = (self.value(a, state) for a in args)
                if left.kind == right.kind == 'type':
                    if 'cyclic_sample' in (left.detail, right.detail):
                        # Repeated sampling sites need iteration-sensitive
                        # token identities before they can justify guards.
                        return state
                    known_equal = (self.token_key(left) == self.token_key(right)
                        or (left.valid and right.valid and left.origin == right.origin)
                        or (right.valid and (self.token_key(left), right.origin) in state.equivalent)
                        or (left.valid and (self.token_key(right), left.origin) in state.equivalent))
                    if known_equal and not truth:
                        return None
                    if truth:
                        guarantees = []
                        if right.valid:
                            guarantees.append((self.token_key(left), right.origin))
                        if left.valid:
                            guarantees.append((self.token_key(right), left.origin))
                        state.equivalent |= frozenset(guarantees)
        return state
