"""Immutable local syntax facts using the existing Tree-sitter dependency.

No preprocessing, full C++ type resolution, or modification of shared parsing.
"""
from dataclasses import dataclass
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
    return re.sub(r'\s+', '', text)


def name_node(node):
    while node is not None:
        child = node.child_by_field_name('declarator')
        if child is None:
            return node
        node = child


_CPP_NON_CODE = re.compile(
    rb'R"([^\s()\\]{0,16})\(.*?\)\1"'
    rb'|"(?:\\.|[^"\\])*"'
    rb"|'(?:\\.|[^'\\])*'"
    rb'|//[^\n]*'
    rb'|/\*.*?\*/'
    rb'|^[ \t]*\#(?:[^\n]|\\\n)*',
    re.MULTILINE | re.DOTALL,
)
_NAMESPACE_PREFIX = re.compile(rb'\bnamespace\s+([A-Za-z_]\w*(?:::\s*[A-Za-z_]\w*)*)\s*$')
_CONDITIONAL_DIRECTIVE = re.compile(rb'^[ \t]*\#[ \t]*(?:if|ifdef|ifndef|elif|else|endif)\b', re.MULTILINE)


def _lexical_namespace_ranges(data):
    """Return namespace byte ranges only when lexical scope is unambiguous.

    This deliberately recovers declaration ownership only. It does not expand
    macros or resolve declarations, and refuses conditional-compilation input.
    """
    if _CONDITIONAL_DIRECTIVE.search(data):
        return None

    def blank(match):
        return re.sub(rb'[^\n]', b' ', match.group(0))

    masked = _CPP_NON_CODE.sub(blank, data)
    braces = []
    ranges = []
    for index, char in enumerate(masked):
        if char == ord('{'):
            line_start = masked.rfind(b'\n', 0, index) + 1
            prefix = masked[line_start:index]
            found = _NAMESPACE_PREFIX.search(prefix)
            namespace = re.sub(rb'\s+', b'', found.group(1)).decode('ascii') if found else ''
            braces.append((namespace, index))
        elif char == ord('}'):
            if not braces:
                return None
            namespace, start = braces.pop()
            if namespace:
                ranges.append((start, index + 1, namespace))
    if braces:
        return None
    return tuple(ranges)


def _lexical_namespace_at(ranges, position):
    matches = [(start, end, name) for start, end, name in ranges
               if start < position < end]
    matches.sort()
    return '::'.join(name for _, _, name in matches)


@dataclass(frozen=True)
class Binding:
    name: str
    identity: str
    type_name: str
    position: int
    scope: tuple
    parameter: bool = False


class FunctionSyntax:
    def __init__(self, data, node, lexical_namespace=None, partial=False):
        self.data, self.node = data, node
        self.body = node.child_by_field_name('body')
        declarator = node.child_by_field_name('declarator')
        self.declarator = declarator
        written_name = self.text(name_node(declarator))
        ancestors, class_ancestors, parent = [], [], node.parent
        while parent is not None:
            if parent.type in ('namespace_definition', 'class_specifier', 'struct_specifier'):
                name = self.text(parent.child_by_field_name('name'))
                ancestors.append(name)
                if parent.type in ('class_specifier', 'struct_specifier'):
                    class_ancestors.append(name)
            parent = parent.parent
        if partial:
            prefix_parts = [part for part in (lexical_namespace or '').split('::') if part]
            prefix_parts.extend(reversed([a for a in class_ancestors if a]))
            prefix = '::'.join(prefix_parts)
            owner_source = 'lexical_scope' if prefix else 'unknown'
        else:
            prefix = '::'.join(reversed([a for a in ancestors if a]))
            owner_source = 'ast' if ancestors else 'unknown'
        self.qualified_name = compact((prefix + '::' if prefix else '') + written_name).lstrip(':')
        self.owner_source = owner_source
        # Tree-sitter parses syntax only; external macro/type declarations and
        # compiler flags are never inferred from this local owner recovery.
        self.external_context_status = 'unknown'
        self.bindings = []
        parameters = declarator.child_by_field_name('parameters')
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
        ident = f'{self.qualified_name}:{position}:{name}'
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


def parse_functions(data):
    tree = Parser(Language(tree_sitter_cpp.language())).parse(data)
    namespace_ranges = _lexical_namespace_ranges(data)
    # Tree-sitter also calls defaulted/deleted special members function_definition;
    # they have no emitted body to analyse and must not crash an unrelated caller.
    partial = tree.root_node.has_error
    functions = [FunctionSyntax(data, n,
                                _lexical_namespace_at(namespace_ranges, n.start_byte)
                                if namespace_ranges is not None else None,
                                partial=partial) for n in walk(tree.root_node)
                 if n.type == 'function_definition' and n.child_by_field_name('body') is not None
                 and n.child_by_field_name('declarator') is not None]
    for function in functions:
        function.translation_unit_status = 'partial' if tree.root_node.has_error else 'complete'
    return tree, functions
