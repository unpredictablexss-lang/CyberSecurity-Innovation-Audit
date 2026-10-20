"""Narrow syntax binding for a reviewed NAPI property-name argument.

This does not classify literals or constants as public in general. The only
accepted vocabulary is "password" and the exact CERT_PRIVATE_KEY="key" pair
in argument 2 of the two read-property APIs. Other operands retain may-flow.
"""
from dataclasses import dataclass
import re

PROPERTY_READ_CALLS = frozenset({'napi_has_named_property', 'napi_get_named_property'})


@dataclass(frozen=True)
class PropertyKeyBinding:
    identity: str
    material_kind: str


def walk(node):
    yield node
    for child in node.named_children:
        yield from walk(child)


def namespace(node, flow):
    result = []
    while node is not None:
        if node.type in ('class_specifier', 'struct_specifier'):
            return None
        if node.type == 'namespace_definition':
            name = flow.text(node.child_by_field_name('name'))
            if not name or '::' in name:
                return None
            result.append(name)
        node = node.parent
    return tuple(reversed(result))


def guarded_global(node, flow):
    parent = node.parent
    while parent is not None:
        if parent.type in ('function_definition', 'compound_statement', 'lambda_expression'):
            return False
        if parent.type.startswith('preproc_'):
            # Permit a conventional whole-header include guard, not arbitrary
            # conditional definitions whose active branch is unknown.
            guard = re.match(r'#ifndef\s+(\w+)\s*\n\s*#define\s+\1\b', flow.text(parent))
            if (parent.type != 'preproc_ifdef' or parent.parent is None
                    or parent.parent.type != 'translation_unit' or not guard
                    or parent.child_by_field_name('alternative') is not None):
                return False
        parent = parent.parent
    return True


class PropertyKeyBindings:
    def __init__(self, flow):
        self.flow = flow
        self.cache = {}

    def visible_units(self):
        flow = self.flow
        units = flow.resolver.units if flow.resolver is not None else (flow.u,)
        visible = [flow]
        for node in walk(flow.tree.root_node):
            if node.type != 'preproc_include' or node.parent.type != 'translation_unit':
                continue
            include = re.fullmatch(r'"([^"\n]+)"', flow.text(node.child_by_field_name('path')))
            if not include:
                continue
            path = include.group(1)
            # Do not guess the include search order between same-basename files.
            matches = [u for u in units if u.path != flow.u.path
                       and (u.path == path or u.path.endswith('/' + path))]
            if len(matches) > 1:
                return None
            if not matches:
                continue
            other = flow.resolver.flow(matches[0]) if flow.resolver is not None else None
            if (other is None or other.u.language != 'cpp'
                    or other.u.parse_status != 'complete' or other.tree.root_node.has_error):
                return None
            visible.append(other)
        return visible

    def global_literal(self, name, scope, allow_private_key=False):
        key = (name, scope, allow_private_key)
        if key in self.cache:
            return self.cache[key]
        self.cache[key] = None
        visible = self.visible_units()
        if visible is None:
            return None
        definitions = []
        for flow in visible:
            if re.search(r'^\s*#\s*define\s+' + re.escape(name) + r'\b', flow.u.text, re.M):
                return None
            for node in walk(flow.tree.root_node):
                if node.type != 'declaration' or namespace(node, flow) != scope:
                    continue
                parent = node.parent
                local = False
                while parent is not None:
                    if parent.type in ('function_definition', 'compound_statement', 'lambda_expression'):
                        local = True
                        break
                    parent = parent.parent
                if local:
                    continue
                for declarator in node.named_children:
                    if declarator.type not in ('init_declarator', 'identifier', 'pointer_declarator', 'reference_declarator', 'array_declarator'):
                        continue
                    if flow.name(declarator) == name:
                        if not guarded_global(node, flow):
                            return None
                        definitions.append((flow, node, declarator))
        if len(definitions) != 1:
            return None
        flow, node, declaration = definitions[0]
        declarator = declaration.child_by_field_name('declarator')
        value = declaration.child_by_field_name('value')
        if (flow.text(node.child_by_field_name('type')) != 'std::string'
                or not any(child.type == 'type_qualifier' and flow.text(child) == 'const'
                           for child in node.named_children)
                or declarator is None or declarator.type != 'identifier'
                or value is None or value.type != 'string_literal'):
            return None
        try:
            literal = flow.literal(value)
        except (ValueError, SyntaxError):
            return None
        if literal == 'password':
            material_kind = 'password'
        elif allow_private_key and name == 'CERT_PRIVATE_KEY' and literal == 'key':
            material_kind = 'private-key'
        else:
            return None
        identity = (f'{flow.u.path}:{node.start_point[0]+1} '
                  f'symbol={"::".join(scope + (name,))} byte={declaration.start_byte} '
                  f'sha256={flow.u.sha256}')
        result = PropertyKeyBinding(identity, material_kind)
        self.cache[key] = result
        return result

    def bind(self, call, argument, allow_target_macro=False):
        flow = self.flow
        if (not flow.heuristic_sources or flow.u.language != 'cpp'
                or flow.u.parse_status != 'complete' or flow.tree.root_node.has_error
                or argument.type != 'call_expression'):
            return None
        api = flow.text(call.child_by_field_name('function'))
        units = flow.resolver.units if flow.resolver is not None else (flow.u,)
        tokens = ('std', 'string', 'c_str') + (() if allow_target_macro else (api,))
        modeled_tokens = '|'.join(re.escape(token) for token in tokens)
        if any(re.search(r'^\s*#\s*define\s+(?:' + modeled_tokens + r')\b', unit.text, re.M)
               for unit in units):
            return None
        function = argument.child_by_field_name('function')
        args = argument.child_by_field_name('arguments')
        if (function is None or function.type != 'field_expression'
                or flow.text(function.child_by_field_name('operator')) != '.'
                or flow.text(function.child_by_field_name('field')) != 'c_str'
                or args is None or args.named_children):
            return None
        receiver = function.child_by_field_name('argument')
        if receiver is None or receiver.type != 'identifier':
            return None
        name = flow.text(receiver)
        if name in flow.shadows:
            return None
        scope = namespace(call, flow)
        if scope is None:
            return None
        # The newly reviewed key pair is scoped to a property-read argument.
        # It does not extend the separate D89 logging-operand proof vocabulary.
        return self.global_literal(name, scope,
            allow_private_key=api in PROPERTY_READ_CALLS and not allow_target_macro)
