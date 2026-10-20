"""Finite local helper summaries for Ark Runtime semantic passes.

Only exact C++ syntax is summarized. Casts and parenthesized/pointer wrappers
are transparent. A helper preserves source identity only when its complete
body returns one same-typed parameter or forwards it through another proven
identity helper. Any other call, update, allocation, deletion or indirect
write is retained as an explicit effect. Name similarity, macros, ownership,
range and runtime type stability are never inferred.
"""
from dataclasses import dataclass, replace
from hashlib import sha256
import re

from .syntax import walk


_CAST_CALLS = frozenset(('const_cast', 'dynamic_cast', 'reinterpret_cast', 'static_cast'))


def _normalized_type(text):
    text = re.sub(r'\b(?:const|volatile|typename)\b', '', text or '')
    return re.sub(r'\s+', '', text).replace('&&', '').replace('&', '')


class _Matches:
    def matches(self, fn, node):
        if node.type != 'call_expression':
            return False
        args = fn.arguments(node)
        if len(args) != self.arity:
            return False
        callee = node.child_by_field_name('function')
        if callee is None:
            return False
        if callee.type == 'identifier':
            written = fn.text(callee)
        elif callee.type == 'field_expression':
            written = fn.text(callee.child_by_field_name('field'))
        elif callee.type == 'template_function':
            written = fn.text(callee.child_by_field_name('name'))
        else:
            return False
        return written == self.name and fn.resolve(self.name, node) is None


@dataclass(frozen=True)
class IdentityHelper(_Matches):
    name: str
    qualified_name: str
    arity: int
    parameter_index: int
    normalized_type: str
    source_hash: str


@dataclass(frozen=True)
class HelperContract(_Matches):
    name: str
    qualified_name: str
    arity: int
    parameter_index: int
    normalized_type: str
    source_hash: str
    returns_parameter: bool = False
    effects: tuple = ()


def _call_identity(fn, node, contracts):
    matches = [item for item in contracts
               if item.returns_parameter and not item.effects and item.matches(fn, node)]
    return matches[0] if len(matches) == 1 else None


def build_helper_contracts(functions):
    """Return complete local helper contracts with bounded fixed-point identity."""
    contracts = []
    for fn in functions:
        if fn.node.has_error or fn.body is None:
            continue
        effects = []
        for node in walk(fn.body):
            if node.type in ('new_expression', 'delete_expression', 'update_expression'):
                effects.append(node.type)
            elif node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left is not None and left.type != 'identifier':
                    effects.append('indirect_assignment')
            elif node.type == 'call_expression':
                name = fn.call_name(node).split('::')[-1]
                if name not in _CAST_CALLS:
                    effects.append('call:' + name)
        parameter_bindings = [item for item in fn.bindings if item.parameter]
        parameter_types = tuple(_normalized_type(item) for item in fn.parameter_types)
        return_type = _normalized_type(fn.text(fn.node.child_by_field_name('type')))
        contracts.append(HelperContract(
            fn.qualified_name.rsplit('::', 1)[-1], fn.qualified_name,
            len(fn.parameter_types), -1, return_type,
            sha256(fn.text(fn.body).encode('utf-8')).hexdigest(),
            False, tuple(sorted(set(effects)))))
        statements = [item for item in fn.body.named_children
                      if item.type not in ('comment', 'empty_statement')]
        if len(statements) != 1 or statements[0].type != 'return_statement':
            continue
        returned = statements[0].child_by_field_name('value')
        if returned is None and statements[0].named_children:
            returned = statements[0].named_children[0]
        if returned is None:
            continue
        root = returned
        while root.type in ('parenthesized_expression', 'pointer_expression') and root.named_children:
            root = root.named_children[-1]
        parameter_index = None
        if root.type == 'identifier':
            binding = fn.resolve(fn.text(root), root)
            if binding is not None and binding.parameter:
                parameter_index = next((i for i, item in enumerate(parameter_bindings)
                                        if item.identity == binding.identity), None)
        elif root.type == 'call_expression':
            # Forwarding is resolved after direct identities are available.
            continue
        if parameter_index is None or return_type != parameter_types[parameter_index]:
            continue
        contracts[-1] = replace(contracts[-1], parameter_index=parameter_index,
                                returns_parameter=True)
    changed = True
    while changed:
        changed = False
        for index, contract in enumerate(contracts):
            if contract.returns_parameter:
                continue
            fn = next((item for item in functions if item.qualified_name == contract.qualified_name), None)
            if fn is None:
                continue
            statements = [item for item in fn.body.named_children
                          if item.type not in ('comment', 'empty_statement')]
            if len(statements) != 1 or statements[0].type != 'return_statement':
                continue
            returned = statements[0].child_by_field_name('value')
            if returned is None and statements[0].named_children:
                returned = statements[0].named_children[0]
            if returned is None:
                continue
            root = returned
            while root.type in ('parenthesized_expression', 'pointer_expression') and root.named_children:
                root = root.named_children[-1]
            if root.type != 'call_expression':
                continue
            forwarded = _call_identity(fn, root, contracts)
            residual = set(contract.effects) - {'call:' + forwarded.name} if forwarded else set(contract.effects)
            if forwarded is None or residual or contract.normalized_type != forwarded.normalized_type:
                continue
            contracts[index] = replace(contract, returns_parameter=True,
                                       parameter_index=forwarded.parameter_index,
                                       effects=())
            changed = True
    return tuple(contracts)


def build_identity_helpers(functions):
    """Index complete same-type identity helpers, including forwarding chains."""
    contracts = build_helper_contracts(functions)
    grouped = {}
    for contract in contracts:
        if not contract.returns_parameter or contract.effects:
            continue
        helper = IdentityHelper(contract.name, contract.qualified_name, contract.arity,
                                contract.parameter_index, contract.normalized_type,
                                contract.source_hash)
        grouped.setdefault((helper.name, helper.arity), []).append(helper)
    return tuple(items[0] for items in grouped.values() if len(items) == 1)


def effectful_helper_problem(fn, node, contracts=()):
    """Return an auditable effect contract, without treating it as identity."""
    if node.type != 'call_expression':
        return ''
    matches = [item for item in contracts if item.effects and item.matches(fn, node)]
    if len(matches) != 1:
        return ''
    item = matches[0]
    return 'effectful_helper_contract:' + item.qualified_name + ':' + item.source_hash[:12]


def unwrap_identity_expression(fn, node, helpers=()):
    """Return the root expression and audited identity layers, or (None, ())."""
    hops = []
    current = node
    guard = 0
    while current is not None and guard < 32:
        guard += 1
        if current.type in ('parenthesized_expression', 'pointer_expression'):
            children = current.named_children
            if not children:
                return None, tuple(hops)
            hops.append(current.type)
            current = children[-1]
            continue
        if current.type == 'cast_expression':
            value = current.child_by_field_name('value')
            if value is None and current.named_children:
                value = current.named_children[-1]
            if value is None:
                return None, tuple(hops)
            hops.append('cast_expression')
            current = value
            continue
        if current.type == 'call_expression':
            args = fn.arguments(current)
            name = fn.call_name(current)
            base = name.split('<', 1)[0].rsplit('::', 1)[-1].removeprefix('this->')
            if base in _CAST_CALLS and len(args) == 1 and not fn.resolve(base, current):
                hops.append('cpp_cast:' + base)
                current = args[0]
                continue
            matches = [helper for helper in helpers if helper.matches(fn, current)]
            if len(matches) == 1 and len(args) == matches[0].arity:
                helper = matches[0]
                hops.append('identity_helper:' + helper.qualified_name + ':' + helper.source_hash[:12])
                current = args[helper.parameter_index]
                continue
        return current, tuple(hops)
    return None, tuple(hops)


def same_binding(fn, left, right, helpers=()):
    left_root, _ = unwrap_identity_expression(fn, left, helpers)
    right_root, _ = unwrap_identity_expression(fn, right, helpers)
    if left_root is None or right_root is None:
        return False
    if left_root.type != 'identifier' or right_root.type != 'identifier':
        return left_root == right_root
    left_binding = fn.resolve(fn.text(left_root), left_root)
    right_binding = fn.resolve(fn.text(right_root), right_root)
    return left_binding is not None and left_binding == right_binding


def in_cyclic_region(node, cyclic_ranges):
    return any(start <= node.start_byte < end for start, end in cyclic_ranges)


def binding_matches(fn, node, binding, helpers=()):
    root, _ = unwrap_identity_expression(fn, node, helpers)
    if root is None or root.type != 'identifier' or binding is None:
        return False
    return fn.resolve(fn.text(root), root) == binding
