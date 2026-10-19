"""Immutable local syntax facts using the existing Tree-sitter dependency.

Owner recovery is deliberately source-bound and fail-closed. The parser does
not preprocess C++, resolve includes, or infer names from historical reports.
"""
from dataclasses import dataclass
from hashlib import sha256
import re
from tree_sitter import Language, Parser
import tree_sitter_cpp


def walk(node):
    pending = [node]
    while pending:
        item = pending.pop()
        yield item
        pending.extend(reversed(item.named_children))


def compact(text):
    if isinstance(text, (bytes, bytearray)):
        return re.sub(rb'\s+', b'', text)
    return re.sub(r'\s+', '', text)


def name_node(node):
    while node is not None:
        child = node.child_by_field_name('declarator')
        if child is None:
            return node
        node = child


_NAMESPACE_NAME_TYPES = {'namespace_identifier', 'identifier', 'type_identifier'}
_FUNCTION_NAME_TYPES = {
    'identifier', 'field_identifier', 'operator_name', 'destructor_name',
    'type_identifier',
}
_DECLARATOR_WRAPPERS = {
    'function_declarator', 'pointer_declarator', 'reference_declarator',
    'array_declarator', 'parenthesized_declarator', 'abstract_function_declarator',
}
_CONDITIONAL_DIRECTIVE = re.compile(
    rb'^[ \t]*\#[ \t]*(?:if|ifdef|ifndef|elif|else|endif)\b', re.MULTILINE
)
_DEFINE_DIRECTIVE = re.compile(
    rb'^[ \t]*\#[ \t]*define[ \t]+([A-Za-z_]\w*)', re.MULTILINE
)


def _text(data, node):
    return data[node.start_byte:node.end_byte] if node is not None else b''


def _digest(data):
    return sha256(data).hexdigest()


@dataclass(frozen=True)
class OwnerComponent:
    kind: str
    name: str
    start_byte: int
    end_byte: int
    source_sha256: str
    token_missing: bool = False


@dataclass(frozen=True)
class OwnerIdentity:
    components: tuple

    @property
    def spelling(self):
        return '::'.join(component.name for component in self.components
                         if component.name and not component.token_missing)

    @property
    def source_sha256(self):
        payload = '|'.join(
            f'{component.kind}:{component.name}:{component.start_byte}:'
            f'{component.end_byte}:{component.source_sha256}'
            for component in self.components
        )
        return _digest(payload.encode('utf-8'))

    @property
    def source_spans(self):
        return tuple((component.start_byte, component.end_byte)
                     for component in self.components)


def _component(kind, name_node, data, missing=False):
    if missing or name_node is None:
        return OwnerComponent(kind, '', 0, 0, _digest(b''), True)
    raw = _text(data, name_node)
    return OwnerComponent(kind, raw.decode('utf-8'), name_node.start_byte,
                          name_node.end_byte, _digest(raw), False)


def _namespace_components(data, node):
    name = node.child_by_field_name('name')
    if name is None:
        return (_component('namespace', None, data, True),)
    if name.type == 'nested_namespace_specifier':
        parts = []

        def flatten(item):
            if item.type == 'namespace_identifier':
                parts.append(item)
                return True
            if item.type != 'nested_namespace_specifier':
                return False
            children = list(item.named_children)
            return bool(children) and all(flatten(child) for child in children)

        if not flatten(name):
            return (_component('namespace', name, data, True),)
        for left, right in zip(parts, parts[1:]):
            gap = data[left.end_byte:right.start_byte]
            if compact(gap) != b'::':
                return (_component('namespace', name, data, True),)
        return tuple(_component('namespace', part, data) for part in parts)
    if name.type in _NAMESPACE_NAME_TYPES:
        return (_component('namespace', name, data),)
    return (_component('namespace', name, data, True),)


def _class_component(data, node):
    name = node.child_by_field_name('name')
    if name is None or name.type not in _NAMESPACE_NAME_TYPES:
        return _component('class', name, data, True)
    return _component('class', name, data)


def _scope_components(data, node, include_self=True):
    groups = []
    current = node if include_self else node.parent
    while current is not None:
        if current.type == 'namespace_definition':
            groups.append(_namespace_components(data, current))
        elif current.type in ('class_specifier', 'struct_specifier', 'union_specifier'):
            groups.append((_class_component(data, current),))
        current = current.parent
    return tuple(component for group in reversed(groups) for component in group)


def _symbol_records(data, root):
    records = []
    for node in walk(root):
        if node.type == 'namespace_definition':
            components = _scope_components(data, node)
            if components and all(not component.token_missing for component in components):
                records.append((tuple(component.name for component in components),
                                components, node))
        elif node.type in ('class_specifier', 'struct_specifier', 'union_specifier'):
            components = _scope_components(data, node)
            if components and all(not component.token_missing for component in components):
                records.append((tuple(component.name for component in components),
                                components, node))
    return records


def _core_declarator(node):
    current = node
    while current is not None:
        child = current.child_by_field_name('declarator')
        if child is None or current.type not in _DECLARATOR_WRAPPERS:
            return current
        current = child
    return current


def _qualified_parts(data, node):
    parts = []

    def visit(current, is_name=False):
        if current is None or current.is_missing or current.has_error:
            return False
        if current.type == 'qualified_identifier':
            name = current.child_by_field_name('name')
            named = [child for child in current.named_children if child != name]
            if name is None:
                return False
            if not named:
                if not _text(data, current).lstrip().startswith(b'::'):
                    return False
                return visit(name, is_name=True)
            if len(named) != 1:
                return False
            qualifier = named[0]
            if not visit(qualifier):
                return False
            gap = data[qualifier.end_byte:name.start_byte]
            if compact(gap) != b'::':
                return False
            return visit(name, is_name=True)
        if current.type in _FUNCTION_NAME_TYPES and is_name:
            if not _text(data, current):
                return False
            parts.append(('function', current))
            return True
        if current.type in _NAMESPACE_NAME_TYPES:
            if not _text(data, current):
                return False
            parts.append(('qualifier', current))
            return True
        return False

    if not visit(_core_declarator(node), is_name=True):
        return None, None
    if not parts or parts[-1][0] != 'function':
        return None, None
    return parts[-1][1], tuple(part[1] for part in parts[:-1])


class _OwnerContext:
    def __init__(self, data, root):
        self.data = data
        self.root = root
        self.records = _symbol_records(data, root)
        self.macro_names = {
            match.group(1).decode('ascii') for match in _DEFINE_DIRECTIVE.finditer(data)
        }
        self.conditional = bool(_CONDITIONAL_DIRECTIVE.search(data))

    def resolve_qualifier(self, function_node, qualifier_nodes):
        qualifier_names = tuple(
            self.data[node.start_byte:node.end_byte].decode('utf-8')
            for node in qualifier_nodes
        )
        if not qualifier_names:
            return None, ('owner_not_visible',)
        if any(not name for name in qualifier_names):
            return None, ('missing_owner_token',)
        declarator = function_node.child_by_field_name('declarator')
        absolute = self.data[
            declarator.start_byte:declarator.end_byte].lstrip().startswith(b'::')
        scope = tuple(
            component.name for component in
            _scope_components(self.data, function_node, include_self=False)
            if not component.token_missing
        )
        candidates = []
        for path, components, node in self.records:
            if len(path) < len(qualifier_names):
                continue
            if path[-len(qualifier_names):] != qualifier_names:
                continue
            remainder = path[:-len(qualifier_names)]
            if absolute:
                if remainder:
                    continue
            elif len(remainder) > len(scope) or scope[:len(remainder)] != remainder:
                continue
            candidates.append((components, node))
        if candidates:
            deepest = max(len(components) - len(qualifier_names)
                          for components, _ in candidates)
            candidates = [
                item for item in candidates
                if len(item[0]) - len(qualifier_names) == deepest
            ]
        unique = {}
        for components, node in candidates:
            key = tuple((component.kind, component.name) for component in components)
            unique.setdefault(key, []).append((components, node))
        if len(unique) != 1:
            return None, (('ambiguous_owner_qualifier',) if unique
                          else ('owner_not_visible_in_translation_unit',))
        variants = next(iter(unique.values()))
        if len(variants) > 1:
            definitions = [item for item in variants if item[1].child_by_field_name('body')]
            if len(definitions) != 1:
                return None, ('ambiguous_owner_qualifier',)
            variants = definitions
        return OwnerIdentity(variants[0][0]), ()

    def local_owner(self, function_node):
        components = _scope_components(self.data, function_node, include_self=False)
        if not components or any(component.token_missing for component in components):
            return None, ('missing_owner_token',)
        return OwnerIdentity(components), ()


class FunctionSyntax:
    def __init__(self, data, node, lexical_namespace=None, partial=False,
                 owner_context=None, parse_limitations=()):
        self.data, self.node = data, node
        self.body = node.child_by_field_name('body')
        declarator = node.child_by_field_name('declarator')
        self.declarator = declarator
        self.declarator_spelling = self.text(declarator)
        self.function_name_node, self.qualifier_nodes = _qualified_parts(data, declarator)
        self.qualifier_nodes = self.qualifier_nodes or ()
        self.function_name = self.text(self.function_name_node) if self.function_name_node else ''
        self.written_name = self.function_name
        self.written_declarator_name = compact(
            self.declarator_spelling.split('(', 1)[0]
        )
        self.source_span = (node.start_byte, node.end_byte)
        self.source_sha256 = _digest(_text(data, node))
        self.translation_unit_sha256 = _digest(data)
        self.function_identity = (
            f'function:{node.start_byte}:{node.end_byte}:{self.source_sha256}'
        )

        limitations = list(parse_limitations)
        if lexical_namespace is not None:
            limitations.append('lexical_owner_hint_rejected')
        owner = None
        if self.function_name_node is None:
            limitations.append('missing_function_name_token')
        if partial:
            limitations.append('partial_parse')
        if owner_context and owner_context.conditional:
            limitations.append('conditional_compilation_unknown')
        owner_tokens = {self.text(item) for item in self.qualifier_nodes}
        if self.function_name:
            owner_tokens.add(self.function_name)
        macro_owner = (
            owner_tokens & owner_context.macro_names if owner_context else set()
        )
        if macro_owner:
            limitations.append('macro_owner_expansion_unknown')

        if not partial and owner_context and self.function_name_node is not None \
                and not macro_owner and not owner_context.conditional:
            if self.qualifier_nodes:
                owner, owner_limits = owner_context.resolve_qualifier(
                    node, self.qualifier_nodes)
            else:
                owner, owner_limits = owner_context.local_owner(node)
            limitations.extend(owner_limits)
        elif not partial and self.function_name_node is not None:
            limitations.append('owner_not_visible_in_translation_unit')

        self.owner_identity = owner
        self.owner_source = 'ast' if owner is not None else 'unknown'
        self.owner_status = 'resolved' if owner is not None else (
            'limitation' if limitations else 'unknown'
        )
        self.owner_limitations = tuple(dict.fromkeys(limitations))
        self.external_context_status = 'unknown'
        self.candidate_status = 'candidate'
        self.assessment_status = 'unassessed'
        if owner is not None:
            self.qualified_name = compact(
                owner.spelling + '::' + self.function_name
            ).lstrip(':')
            self.qualified_name_status = 'resolved_owner'
        else:
            # This is an exact source lookup key built from visible scope
            # tokens, never a recovered owner identity. Analysis consumers
            # must inspect owner_identity/owner_status before treating it as
            # ownership evidence.
            if self.written_declarator_name.startswith('::'):
                self.qualified_name = self.written_declarator_name.lstrip(':')
            else:
                visible_prefix = '::'.join(
                    component.name for component in
                    _scope_components(data, node, include_self=False)
                    if component.name and not component.token_missing
                )
                self.qualified_name = compact(
                    (visible_prefix + '::' if visible_prefix else '')
                    + self.written_declarator_name
                ).lstrip(':')
            self.qualified_name_status = 'source_spelling_unverified'

        self.bindings = []
        parameters = declarator.child_by_field_name('parameters') if declarator else None
        self.parameter_types = []
        for param in parameters.named_children if parameters else ():
            if param.type not in ('parameter_declaration', 'optional_parameter_declaration'):
                continue
            dec = param.child_by_field_name('declarator')
            name = self.text(name_node(dec))
            typ = self.text(param.child_by_field_name('type'))
            pointers = self.text(dec).count('*') if dec else 0
            typ = compact(typ) + '*' * pointers
            self.parameter_types.append(typ)
            if name:
                self.add_binding(name, typ, param.start_byte, (self.body.start_byte,), True)
        for item in walk(self.body):
            if item.type == 'declaration':
                typ = compact(self.text(item.child_by_field_name('type')))
                for child in item.named_children:
                    if child.type in ('init_declarator', 'function_declarator', 'identifier', 'pointer_declarator'):
                        dec = child.child_by_field_name('declarator') if child.type == 'init_declarator' else child
                        ident = name_node(dec)
                        if ident and ident.type in ('identifier', 'field_identifier'):
                            self.add_binding(self.text(ident), typ, ident.start_byte, self.scope(item))
            elif item.type == 'call_expression' and self.call_name(item) == 'DEFVARIABLE':
                args = self.arguments(item)
                if args and args[0].type == 'identifier':
                    self.add_binding(self.text(args[0]), 'Variable', item.start_byte, self.scope(item))

    def text(self, node):
        return self.data[node.start_byte:node.end_byte].decode('utf-8') if node else ''

    def scope(self, node):
        result = []
        while node is not None:
            if node.type == 'compound_statement':
                result.append(node.start_byte)
            if node == self.body:
                break
            node = node.parent
        return tuple(reversed(result))

    def add_binding(self, name, typ, position, scope, parameter=False):
        ident = f'{self.function_identity}:{position}:{name}'
        self.bindings.append(Binding(name, ident, typ, position, scope, parameter))

    def resolve(self, name, node):
        scope = self.scope(node)
        matches = [b for b in self.bindings if b.name == name and b.position <= node.start_byte
                   and scope[:len(b.scope)] == b.scope]
        return max(matches, key=lambda b: (len(b.scope), b.position), default=None)

    def arguments(self, node):
        args = node.child_by_field_name('arguments')
        return tuple(args.named_children) if args else ()

    def call_name(self, node):
        return compact(self.text(node.child_by_field_name('function')))


@dataclass(frozen=True)
class Binding:
    name: str
    identity: str
    type_name: str
    position: int
    scope: tuple
    parameter: bool = False


def _lexical_namespace_ranges(data):
    return None


def _lexical_namespace_at(ranges, position):
    return ''


def _nested_nonmember_definition(node):
    current = node.parent
    while current is not None:
        if current.type in ('class_specifier', 'struct_specifier', 'union_specifier'):
            return False
        if current.type == 'function_definition':
            return True
        current = current.parent
    return False


def parse_functions(data):
    tree = Parser(Language(tree_sitter_cpp.language())).parse(data)
    partial = tree.root_node.has_error
    context = _OwnerContext(data, tree.root_node)
    parse_limitations = ('parse_error_or_missing_token',) if partial else ()
    functions = [
        FunctionSyntax(data, node, partial=partial, owner_context=context,
                       parse_limitations=parse_limitations)
        for node in walk(tree.root_node)
        if node.type == 'function_definition'
        and not _nested_nonmember_definition(node)
        and node.child_by_field_name('body') is not None
        and node.child_by_field_name('declarator') is not None
    ]
    for function in functions:
        function.translation_unit_status = 'partial' if partial else 'complete'
    return tree, functions