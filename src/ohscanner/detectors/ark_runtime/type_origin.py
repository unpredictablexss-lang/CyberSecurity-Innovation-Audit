"""Local definition identities and provenance, evaluated on generated paths."""
from dataclasses import dataclass
from .syntax import compact, name_node
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


UNKNOWN = Value()


class OriginState:
    def __init__(self, values=None, equivalent=(), invalidated=(), predicates=()):
        self.values = dict(values or {})
        self.equivalent = frozenset(equivalent)
        self.invalidated = frozenset(invalidated)
        self.predicates = frozenset(predicates)

    def copy(self):
        return OriginState(self.values, self.equivalent, self.invalidated, self.predicates)

    def key(self):
        return (tuple(sorted(self.values.items())), tuple(sorted(self.equivalent)),
                tuple(sorted(self.invalidated)), tuple(sorted(self.predicates)))


class OriginEvaluator:
    def __init__(self, fn, model):
        self.fn, self.model = fn, model

    def initial(self):
        return OriginState({b.identity: Value('object', b.identity, origin_line=self.fn.node.start_point[0] + 1)
                            for b in self.fn.bindings if b.parameter and b.type_name == 'GateRef'})

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
                return Value('type', origin=hclass.origin, origin_line=node.start_point[0] + 1)
        if name in ('LoadHClass', 'this->LoadHClass') and len(args) == 1:
            obj = self.value(args[0], state)
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
                                 may_differ=self.model.species_may_change_type)
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
                if typ in ('NewObjectStubBuilder', NAMESPACE + '::NewObjectStubBuilder'):
                    val = Value('builder', binding.identity, detail=self.model.creator_owner)
                else:
                    val = self.value(child.child_by_field_name('value'), state)
                state.values[binding.identity] = val
        elif node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            if left and left.type == 'identifier':
                binding = fn.resolve(fn.text(left), left)
                if binding:
                    state.values[binding.identity] = self.value(node.child_by_field_name('right'), state)
        elif node.type == 'call_expression':
            name, args = fn.call_name(node), fn.arguments(node)
            # An unresolved ordinary helper may mutate a passed runtime value.
            # It cannot justify a stale same-object type token as safe.
            if (name not in ('DEFVARIABLE', 'StoreTypedArrayElement')
                    and '.' not in name and '->' not in name):
                objects = [self.value(a, state) for a in args]
                state.invalidated |= frozenset(v.identity for v in objects if v.kind == 'object')
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'field_expression':
                obj = self.value(callee.child_by_field_name('argument'), state)
                if obj.kind == 'object':
                    state.invalidated |= frozenset((obj.identity,))

    def store_arguments(self, node, state):
        fn, model = self.fn, self.model
        if node.type != 'call_expression':
            return None
        name = fn.call_name(node)
        if name not in (model.store_name, 'this->' + model.store_name, OWNER + '::' + model.store_name):
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'field_expression' and fn.text(callee.child_by_field_name('field')) == model.store_name:
                return ('unknown', UNKNOWN, UNKNOWN, 'unresolved_sink_receiver')
            return None
        if fn.resolve(model.store_name, node):
            return ('unknown', UNKNOWN, UNKNOWN, 'shadowed_sink')
        args = fn.arguments(node)
        if len(args) != len(model.store_types):
            return ('unknown', UNKNOWN, UNKNOWN, 'sink_signature_mismatch')
        target = self.value(args[model.target_argument], state)
        token = self.value(args[model.token_argument], state)
        if target.kind != 'object' or token.kind != 'type':
            return ('unknown', target, token, 'unresolved_target_or_type_origin')
        pair = tuple(sorted((target.identity, token.origin)))
        if token.origin == target.identity or pair in state.equivalent:
            if target.identity in state.invalidated or token.origin in state.invalidated:
                return ('unknown', target, token, 'type_fact_invalidated_by_call')
            return ('matched', target, token, 'target_origin_or_proved_type_equality')
        if target.may_differ and target.creation_line:
            return ('candidate', target, token, 'different_origin_with_species_creation')
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
            if value.identity and value.identity not in state.invalidated:
                if (value.identity, not truth) in state.predicates:
                    return None
                state.predicates |= frozenset(((value.identity, truth),))
        if condition.type == 'call_expression' and fn.call_name(condition) in ('Int32Equal', 'Equal'):
            args = fn.arguments(condition)
            if len(args) == 2:
                left, right = (self.value(a, state) for a in args)
                if left.kind == right.kind == 'type':
                    if left.origin in state.invalidated or right.origin in state.invalidated:
                        return state
                    pair = tuple(sorted((left.origin, right.origin)))
                    known_equal = left.origin == right.origin or pair in state.equivalent
                    if known_equal and not truth:
                        return None
                    if truth:
                        state.equivalent |= frozenset((pair,))
        return state
