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


@dataclass(frozen=True)
class Binding:
    name: str
    identity: str
    type_name: str
    position: int
    scope: tuple
    parameter: bool = False


class FunctionSyntax:
    def __init__(self, data, node):
        self.data, self.node = data, node
        self.body = node.child_by_field_name('body')
        declarator = node.child_by_field_name('declarator')
        self.declarator = declarator
        written_name = self.text(name_node(declarator))
        ancestors, parent = [], node.parent
        while parent is not None:
            if parent.type in ('namespace_definition', 'class_specifier', 'struct_specifier'):
                ancestors.append(self.text(parent.child_by_field_name('name')))
            parent = parent.parent
        prefix = '::'.join(reversed([a for a in ancestors if a]))
        self.qualified_name = compact((prefix + '::' if prefix else '') + written_name).lstrip(':')
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
    functions = [FunctionSyntax(data, n) for n in walk(tree.root_node)
                 if n.type == 'function_definition']
    return tree, functions
