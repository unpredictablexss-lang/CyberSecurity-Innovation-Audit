"""Bounded AST checks for a predicate that structurally covers one call.

Recognizes an enclosing positive branch or a preceding direct early rejection
in the same block/function. It is not a compiler CFG, alias proof, origin-policy
validation, or proof that a prefix/domain test enforces the product's policy.
Comments/strings and other functions never act as guard statements.
"""
import re

FUNCTION_TYPES = {"function_declaration", "function_expression", "method_definition",
                  "arrow_function", "generator_function_declaration"}
PATH_METHODS = {"startsWith", "startsWithPath", "isValidPath"}
ORIGIN_NAMES = {"url", "origin", "src", "allowlist", "isTrusted", "isAllowed"}


def text(node, source):
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace") if node is not None else ""


def walk(node):
    stack = [node] if node is not None else []
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def unparen(node):
    while node is not None and node.type == "parenthesized_expression" and len(node.named_children) == 1:
        node = node.named_children[0]
    return node


def canonical(node, source):
    node = unparen(node)
    return re.sub(r"\s+", "", text(node, source))


def enclosing_function(node):
    parent = node.parent
    while parent is not None:
        if parent.type in FUNCTION_TYPES:
            return parent
        parent = parent.parent
    return None


def same_node(left, right):
    return left is not None and right is not None and left.id == right.id


def contained(node, container):
    return container is not None and container.start_byte <= node.start_byte and node.end_byte <= container.end_byte


def _atom(node, source, kind, subject):
    if node is None or node.has_error:
        return False
    if kind == "numeric" and node.type == "binary_expression":
        operator = text(node.child_by_field_name("operator"), source)
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        return operator in ("<", "<=", ">", ">=") and (
            canonical(left, source) == subject and unparen(right).type == "number"
            or canonical(right, source) == subject and unparen(left).type == "number")
    if kind == "origin" and node.type == "binary_expression":
        operator = text(node.child_by_field_name("operator"), source)
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        return operator in ("==", "===") and any(
            canonical(value, source).split(".")[-1] in ORIGIN_NAMES
            and unparen(literal).type == "string" for value, literal in ((left, right), (right, left)))
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    arguments = list(args.named_children) if args is not None else []
    name = canonical(function, source)
    if kind == "numeric":
        return name in ("Number.isInteger", "Number.isSafeInteger", "Number.isFinite") and len(arguments) == 1 and canonical(arguments[0], source) == subject
    if function is None or function.type != "member_expression":
        # Custom validation functions have no reviewed semantics here.
        return False
    receiver = canonical(function.child_by_field_name("object"), source)
    method = text(function.child_by_field_name("property"), source)
    if not arguments or any(item.type != "string" for item in arguments):
        return False
    if kind == "path":
        return receiver == subject and method in PATH_METHODS
    if kind == "origin":
        return receiver.split(".")[-1] in ORIGIN_NAMES and method == "startsWith"
    return False


def predicate(node, source, kind, subject, truth=True):
    node = unparen(node)
    if node is None or node.has_error:
        return False
    if node.type == "unary_expression" and text(node.child_by_field_name("operator"), source) == "!":
        return predicate(node.child_by_field_name("argument"), source, kind, subject, not truth)
    if node.type == "binary_expression":
        op = text(node.child_by_field_name("operator"), source)
        if op in ("&&", "||"):
            left = predicate(node.child_by_field_name("left"), source, kind, subject, truth)
            right = predicate(node.child_by_field_name("right"), source, kind, subject, truth)
            # true(A && B) guarantees either true fact; true(A || B) needs both
            # arms to guarantee it. The dual applies on a false branch.
            return (left or right) if (op == "&&") == truth else (left and right)
    return truth and _atom(node, source, kind, subject)


def exits(node):
    if node is None or node.has_error:
        return False
    if node.type in ("return_statement", "throw_statement"):
        return True
    if node.type == "statement_block":
        statements = [item for item in node.named_children if item.type != "comment"]
        return bool(statements) and exits(statements[-1])
    return False


def _changed_between(scope, start, end, source, subject):
    for node in walk(scope):
        if not start <= node.start_byte < end:
            continue
        if node.type in ("assignment_expression", "augmented_assignment_expression"):
            target = node.child_by_field_name("left")
        elif node.type == "update_expression":
            target = node.child_by_field_name("argument")
        elif node.type == "variable_declarator":
            target = node.child_by_field_name("name")
        else:
            continue
        value = canonical(target, source)
        if value and (value == subject or subject.startswith(value + ".") or subject.startswith(value + "[")):
            return True
    return False


def covers(call, source, kind, subjects=()):
    """Every supplied subject has a matching structural guard for this call.

    Origin checks cover registration structurally, but do not identify the
    WebView's actual loaded URL; that remains an explicit evidence obligation.
    """
    scope = enclosing_function(call)
    if scope is None:
        scope = call
        while scope.parent is not None:
            scope = scope.parent
    def one(subject):
        current = call
        while current.parent is not None:
            parent = current.parent
            if parent.type in FUNCTION_TYPES:
                break
            if parent.type == "if_statement":
                condition = parent.child_by_field_name("condition")
                yes, no = parent.child_by_field_name("consequence"), parent.child_by_field_name("alternative")
                truth = True if contained(call, yes) else False if contained(call, no) else None
                if truth is not None and predicate(condition, source, kind, subject, truth):
                    if not _changed_between(scope, condition.end_byte, call.start_byte, source, subject):
                        return True
            if parent.type in ("statement_block", "program"):
                for sibling in parent.named_children:
                    if sibling.end_byte > current.start_byte:
                        break
                    if sibling.type != "if_statement":
                        continue
                    condition = sibling.child_by_field_name("condition")
                    yes, no = sibling.child_by_field_name("consequence"), sibling.child_by_field_name("alternative")
                    accepted = (exits(yes) and no is None and predicate(condition, source, kind, subject, False))
                    accepted |= exits(no) and predicate(condition, source, kind, subject, True)
                    if accepted and not _changed_between(scope, condition.end_byte, call.start_byte, source, subject):
                        return True
            current = parent
        return False
    return all(one(subject) for subject in subjects) if subjects else one("")
