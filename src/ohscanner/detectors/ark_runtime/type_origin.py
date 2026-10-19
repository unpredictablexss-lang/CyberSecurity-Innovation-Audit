"""Local definition identities and provenance, evaluated on generated paths."""
from dataclasses import dataclass, replace
from .syntax import compact, name_node, walk
from .cross_helper import effectful_helper_problem, in_cyclic_region, unwrap_identity_expression
from .model import NAMESPACE, OWNER


@dataclass(frozen=True)
class Value:
    kind: str = 'unknown'
    identity: str = ''
    origin: str = ''
    origin_line: int = 0
    creation_line: int = 0
    may_differ: bool = False
    detail: str = ''
    valid: bool = True


UNKNOWN = Value()


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
    def __init__(self, fn, model, cyclic_ranges=(), identity_helpers=(), helper_contracts=()):
        self.fn, self.model = fn, model
        self.identity_helpers = tuple(identity_helpers)
        self.helper_contracts = tuple(helper_contracts)
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
            effect_problem = effectful_helper_problem(fn, node, self.helper_contracts)
            if effect_problem:
                return effect_problem
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

    def invalidate(self, state, call, may_rebind=True):
        """Forget sampled facts while preserving only justified local identity.

        An unmodelled call invalidates source-object observations and aliases.
        A fresh result's type can survive an unrelated by-argument callback only
        while that result is local and unescaped; global calls and unknown member
        calls invalidate every sampled type fact. The old token can still form a
        distinct-origin candidate, never a proof of current equality.
        """
        from dataclasses import replace
        args = list(self.fn.arguments(call))
        callee = call.child_by_field_name("function")
        member_call = bool(callee and callee.type == "field_expression")
        arguments = list(args)
        if member_call:
            arguments.append(callee.child_by_field_name("argument"))
        passed_objects = set()
        for argument in args:
            for node in walk(argument):
                if node.type == "identifier":
                    value = self.value(node, state)
                    if value.kind == "object":
                        passed_objects.add(value.identity)
        fresh = {
            value.identity for value in state.values.values()
            if value.kind == "object" and value.detail == "fresh_local_typed_array"
        }
        invalidated = set(state.invalidated)
        for value in state.values.values():
            if value.kind != "object":
                continue
            if (value.detail == "fresh_local_typed_array"
                    and value.identity not in passed_objects
                    and value.identity not in state.escaped):
                continue
            invalidated.add(value.identity)
        state.invalidated = frozenset(invalidated)
        preserve_fresh_type = bool(args) and not member_call
        stable_fresh = (fresh - passed_objects) if preserve_fresh_type else set()
        state.values = {
            key: (replace(value, valid=False)
                  if value.kind in ("type", "hclass")
                  and (not value.valid or value.origin not in stable_fresh)
                  else value)
            for key, value in state.values.items()
        }
        state.equivalent = frozenset()
        state.predicates = frozenset()
        state.effects |= frozenset(((call.start_point[0] + 1, self.fn.call_name(call)),))
        rebind = arguments if may_rebind else []
        for argument in rebind:
            while argument and argument.type in ("pointer_expression", "parenthesized_expression"):
                argument = argument.named_children[-1] if argument.named_children else None
            if argument and argument.type == "identifier":
                binding = self.fn.resolve(self.fn.text(argument), argument)
                if binding and state.values.get(binding.identity, UNKNOWN).kind in ("object", "type", "hclass"):
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
        if any(helper.matches(fn, node) for helper in self.identity_helpers):
            return True
        if fn.resolve(base, node):
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
        callee = node.child_by_field_name('function')
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
                    self.invalidate(state, call, may_rebind=not self.passes_by_value(call, state))

    def value(self, node, state):
        if node is None:
            return UNKNOWN
        fn = self.fn
        root, hops = unwrap_identity_expression(fn, node, self.identity_helpers)
        if root is not None and root is not node:
            value = self.value(root, state)
            if any(item.startswith('identity_helper:') for item in hops) and value.kind != 'unknown':
                detail = '+'.join(item for item in (value.detail, 'cross_helper_identity') if item)
                return replace(value, detail=detail)
            return value
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
                if (val.kind in ('object', 'type', 'hclass')
                        and in_cyclic_region(node, self.cyclic_ranges)):
                    detail = '+'.join(item for item in (val.detail, 'loop_backedge_rebinding') if item)
                    val = replace(val, may_differ=True, detail=detail)
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
                    val = (self.value(node.child_by_field_name('right'), state)
                           if fn.text(operator) == '=' else UNKNOWN)
                    if (val.kind in ('object', 'type', 'hclass')
                            and in_cyclic_region(node, self.cyclic_ranges)):
                        detail = '+'.join(item for item in (val.detail, 'loop_backedge_rebinding') if item)
                        val = replace(val, may_differ=True, detail=detail)
                    state.values[binding.identity] = val

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
                    known_equal = ((left.valid and right.valid
                                    and self.token_key(left) == self.token_key(right))
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
