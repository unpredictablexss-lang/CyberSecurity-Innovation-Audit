from dataclasses import dataclass, field
from typing import List, Optional

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Node, Parser


_C_LANG = Language(tree_sitter_c.language())
_CPP_LANG = Language(tree_sitter_cpp.language())
_C_PARSER = Parser(_C_LANG)
_CPP_PARSER = Parser(_CPP_LANG)


@dataclass
class FunctionDef:
    name: str
    return_type: str
    params: List[str]
    start_line: int
    end_line: int


@dataclass
class CallSite:
    name: str
    arguments: List[str]
    line: int
    start_byte: int
    end_byte: int


@dataclass
class VariableDecl:
    name: str
    type: str
    line: int


@dataclass
class AstIndex:
    language: str
    functions: List[FunctionDef] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    variables: List[VariableDecl] = field(default_factory=list)
    parse_status: str = "complete"
    parse_issues: List[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "language": self.language,
            "parse_status": self.parse_status,
            "parse_issues": self.parse_issues,
            "functions": [f.__dict__ for f in self.functions],
            "calls": [c.__dict__ for c in self.calls],
            "variables": [v.__dict__ for v in self.variables],
        }


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _field_text(node: Node, field_name: str, source: bytes) -> Optional[str]:
    child = node.child_by_field_name(field_name)
    if child is None:
        return None
    return _text(child, source)


def _descendant_text(node: Node, node_types, source: bytes) -> Optional[str]:
    for child in node.children:
        if child.type in node_types:
            return _text(child, source)
        found = _descendant_text(child, node_types, source)
        if found is not None:
            return found
    return None


def _collect(node: Node, node_type: str) -> List[Node]:
    result: List[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == node_type:
            result.append(current)
        stack.extend(reversed(current.children))
    return result


def _function_name(def_node: Node, source: bytes) -> str:
    declarator = def_node.child_by_field_name("declarator")
    if declarator is None:
        return _descendant_text(def_node, {"identifier", "field_identifier"}, source) or "<unknown>"
    # Follow the declarator itself, not identifiers in a scope or parameter type.
    while declarator.child_by_field_name("declarator") is not None:
        declarator = declarator.child_by_field_name("declarator")
    while declarator.type == "qualified_identifier":
        name = declarator.child_by_field_name("name")
        if name is None:
            return "<unknown>"
        declarator = name
    if declarator.type in {"identifier", "field_identifier", "operator_name", "destructor_name"}:
        return _text(declarator, source)
    return "<unknown>"


def _parameter_names(def_node: Node, source: bytes) -> List[str]:
    declarator = def_node.child_by_field_name("declarator")
    params: List[str] = []
    if declarator is None:
        return params
    for param in _collect(declarator, "parameter_declaration"):
        name = _descendant_text(param, {"identifier"}, source)
        params.append(name if name is not None else "<unnamed>")
    return params


def _function_return_type(def_node: Node, source: bytes) -> str:
    return _field_text(def_node, "type", source) or "<unknown>"


def _call_name(call_node: Node, source: bytes) -> str:
    func = call_node.child_by_field_name("function")
    if func is None:
        return "<unknown>"
    return _text(func, source)


def _call_arguments(call_node: Node, source: bytes) -> List[str]:
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return []
    return [_text(arg, source) for arg in args_node.named_children]


def _variable_name(decl_node: Node, source: bytes) -> str:
    return _descendant_text(decl_node, {"identifier"}, source) or "<unknown>"


def _variable_type(decl_node: Node, source: bytes) -> str:
    type_node = decl_node.child_by_field_name("type")
    if type_node is not None:
        return _text(type_node, source)
    return "<unknown>"


def parse_source(code: str, language: str = "c") -> AstIndex:
    """Parse C/C++ source into a lightweight AST index.

    ``language`` is ``c`` or ``cpp``. This is a real syntax tree (tree-sitter),
    not the heuristic span logic in src.core.context. It extracts function
    definitions, call expressions, and top-level variable declarations with
    exact line positions.
    """
    if language not in ("c", "cpp"):
        raise ValueError(f"unsupported language: {language}")
    source = code.encode("utf-8")
    parser = _C_PARSER if language == "c" else _CPP_PARSER
    tree = parser.parse(source)
    root = tree.root_node
    issues = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_error or node.is_missing:
            issues.append({
                "kind": "missing" if node.is_missing else "error",
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
            })
        stack.extend(reversed(node.children))

    functions: List[FunctionDef] = []
    for node in _collect(root, "function_definition"):
        functions.append(
            FunctionDef(
                name=_function_name(node, source),
                return_type=_function_return_type(node, source),
                params=_parameter_names(node, source),
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
            )
        )

    calls: List[CallSite] = []
    for node in _collect(root, "call_expression"):
        calls.append(
            CallSite(
                name=_call_name(node, source),
                arguments=_call_arguments(node, source),
                line=node.start_point[0] + 1,
                start_byte=node.start_byte,
                end_byte=node.end_byte,
            )
        )

    variables: List[VariableDecl] = []
    for node in _collect(root, "declaration"):
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        name = _descendant_text(declarator, {"identifier"}, source)
        if name is None:
            continue
        variables.append(
            VariableDecl(
                name=name,
                type=_variable_type(node, source),
                line=node.start_point[0] + 1,
            )
        )

    return AstIndex(language=language, functions=functions, calls=calls, variables=variables,
                    parse_status="partial" if root.has_error else "complete", parse_issues=issues)
