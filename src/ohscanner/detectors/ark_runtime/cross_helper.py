"""Finite function-local identity summaries for Ark Runtime semantic passes.

Only exact C++ syntax is summarized: casts and parenthesized/pointer wrappers
are transparent, and a helper is identity-preserving only when its complete
body is a return of one same-typed parameter. Name similarity, unknown macro
expansion, side effects, ownership, range, and runtime type stability are never
inferred. Unsupported helpers retain the caller's explicit unknown behavior.
"""
from dataclasses import dataclass
from hashlib import sha256
import re



_CAST_CALLS = frozenset(('const_cast', 'dynamic_cast', 'reinterpret_cast', 'static_cast'))


@dataclass(frozen=True)
class IdentityHelper:
    name: str
    qualified_name: str
    arity: int
    parameter_index: int
    normalized_type: str
    source_hash: str

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


def _normalized_type(text):
    text = re.sub(r'\b(?:const|volatile|typename)\b', '', text or '')
    return re.sub(r'\s+', '', text).replace('&&', '').replace('&', '')


def build_identity_helpers(functions):
    """Index only complete one-statement same-type identity helpers."""
    grouped = {}
    for fn in functions:
        if fn.node.has_error or fn.body is None:
            continue
        statements = [item for item in fn.body.named_children
                      if item.type not in ('comment', 'empty_statement')]
        if len(statements) != 1 or statements[0].type != 'return_statement':
            continue
        returned = statements[0].child_by_field_name('value')
        if returned is None and statements[0].named_children:
            returned = statements[0].named_children[0]
        if returned is None or returned.type != 'identifier':
            continue
        root = returned
        binding = fn.resolve(fn.text(root), root)
        if binding is None or not binding.parameter:
            continue
        if binding.identity not in {item.identity for item in fn.bindings if item.parameter}:
            continue
        return_type = _normalized_type(fn.text(fn.node.child_by_field_name('type')))
        parameter_types = tuple(_normalized_type(item) for item in fn.parameter_types)
        parameter_bindings = [item for item in fn.bindings if item.parameter]
        parameter_index = next((index for index, item in enumerate(parameter_bindings)
                                if item.identity == binding.identity), None)
        if parameter_index is None or return_type != parameter_types[parameter_index]:
            continue
        helper = IdentityHelper(
            fn.qualified_name.rsplit('::', 1)[-1], fn.qualified_name,
            len(fn.parameter_types), parameter_index, return_type,
            sha256(fn.text(fn.body).encode('utf-8')).hexdigest())
        grouped.setdefault((helper.name, helper.arity), []).append(helper)
    return tuple(items[0] for items in grouped.values() if len(items) == 1)


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
            callee = current.child_by_field_name('function')
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
    left_root, left_hops = unwrap_identity_expression(fn, left, helpers)
    right_root, right_hops = unwrap_identity_expression(fn, right, helpers)
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
