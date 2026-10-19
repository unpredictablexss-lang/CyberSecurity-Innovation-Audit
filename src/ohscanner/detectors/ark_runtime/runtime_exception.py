"""Bounded exception propagation checks for Ark Runtime callback results.

This models the completion value from a callback call and asks whether a
pending-exception early exit dominates a configured result conversion. It is
syntax based and reports candidates; it does not model all C++ effects.
"""
from dataclasses import dataclass
import re

from .analysis import Observation
from .cross_helper import build_identity_helpers, unwrap_identity_expression
from .syntax import name_node, parse_functions, walk


@dataclass(frozen=True)
class RuntimeExceptionResult:
    status: str
    file_outcome: str
    observations: tuple = ()
    limitations: tuple = ()
    steps: int = 0
    model_digest: str = ""


def _macro_contract(source_units, macro_name, arity, pending_test, exception_return):
    definitions = []
    pattern = re.compile(
        r"^\s*#\s*define\s+" + re.escape(macro_name)
        + r"\s*\(([^)]*)\)(.*)$"
    )
    for unit in source_units:
        lines = unit.text.splitlines()
        index = 0
        while index < len(lines):
            match = pattern.match(lines[index])
            if not match:
                index += 1
                continue
            params = tuple(part.strip() for part in match.group(1).split(",") if part.strip())
            body = [match.group(2)]
            while body[-1].rstrip().endswith("\\") and index + 1 < len(lines):
                body[-1] = body[-1].rstrip()[:-1]
                index += 1
                body.append(lines[index])
            definitions.append((params, " ".join(body)))
            index += 1
    if len(definitions) != 1:
        return None
    params, body = definitions[0]
    if (len(params) != arity or pending_test not in body
            or exception_return not in body):
        return None
    return params[0]


def _macro_returns_on_pending(source_units, macro_name, arity, pending_test, return_statement):
    """Prove a simple macro exits from the same-thread pending-exception branch."""
    pattern = re.compile(
        r"^\s*#\s*define\s+" + re.escape(macro_name)
        + r"\s*\(([^)]*)\)(.*)$"
    )
    definitions = []
    for unit in source_units:
        lines = unit.text.splitlines()
        index = 0
        while index < len(lines):
            match = pattern.match(lines[index])
            if not match:
                index += 1
                continue
            params = tuple(part.strip() for part in match.group(1).split(",") if part.strip())
            body = [match.group(2)]
            while body[-1].rstrip().endswith("\\") and index + 1 < len(lines):
                body[-1] = body[-1].rstrip()[:-1]
                index += 1
                body.append(lines[index])
            definitions.append((params, " ".join(body)))
            index += 1
    if len(definitions) != 1:
        return None
    params, body = definitions[0]
    if len(params) != arity:
        return None
    thread = re.escape(params[0])
    condition = re.compile(
        r"if\s*\(\s*\(\s*" + thread
        + r"\s*\)\s*->\s*" + re.escape(pending_test)
        + r"\s*\(\s*\)\s*\)\s*\{"
    )
    match = condition.search(body)
    if match is None:
        return None
    depth = 1
    cursor = match.end()
    while cursor < len(body) and depth:
        if body[cursor] == "{":
            depth += 1
        elif body[cursor] == "}":
            depth -= 1
        cursor += 1
    if depth != 0:
        return None
    branch = body[match.end():cursor - 1]
    normalized = re.sub(r"\s+", " ", branch)
    expected = re.sub(r"\s+", " ", return_statement.format(**{
        "thread": params[0], "value": params[1], "capability": params[2]
    }))
    if expected not in normalized:
        return None
    return params[0]


def _top_statement(compound, node):
    current = node
    while current is not None and current.parent != compound:
        current = current.parent
    return current if current is not None and current.parent == compound else None


def _direct_compound_pair(fn, left, right):
    left_parent = left.parent
    while left_parent is not None and left_parent.type != "compound_statement":
        left_parent = left_parent.parent
    right_parent = right.parent
    while right_parent is not None and right_parent.type != "compound_statement":
        right_parent = right_parent.parent
    if left_parent is None or left_parent != right_parent:
        return None
    left_statement = _top_statement(left_parent, left)
    right_statement = _top_statement(left_parent, right)
    if left_statement is None or right_statement is None:
        return None
    children = left_parent.named_children
    return left_parent, left_statement, right_statement, children.index(left_statement), children.index(right_statement)


def _ordered_ancestor_compound_pair(fn, left, right):
    """Find a shared compound where a straight-line statement precedes both nodes."""
    left_compounds = []
    current = left.parent
    while current is not None:
        if current.type == "compound_statement":
            left_compounds.append(current)
        current = current.parent
    right_compounds = set()
    current = right.parent
    while current is not None:
        if current.type == "compound_statement":
            right_compounds.add(current)
        current = current.parent

    for compound in left_compounds:
        if compound not in right_compounds:
            continue
        left_statement = _top_statement(compound, left)
        right_statement = _top_statement(compound, right)
        if left_statement is None or right_statement is None:
            return None
        children = compound.named_children
        left_index = children.index(left_statement)
        right_index = children.index(right_statement)
        if left_index >= right_index:
            return None
        return compound, left_statement, right_statement, left_index, right_index
    return None


def _shares_loop(left, right):
    loop_types = {"for_statement", "while_statement", "do_statement", "for_range_loop"}

    def enclosing_loops(node):
        loops = set()
        current = node.parent
        while current is not None:
            if current.type in loop_types:
                loops.add(current.id)
            current = current.parent
        return loops

    return bool(enclosing_loops(left) & enclosing_loops(right))


def _context_thread(fn, source_call):
    """Resolve the JS call-info object to the thread used to create it."""
    args = fn.arguments(source_call)
    if not args or args[0].type != "identifier":
        return None
    info = fn.resolve(fn.text(args[0]), args[0])
    if info is None:
        return None
    if info.type_name.replace(" ", "") in ("JSThread*", "JSThread"):
        return info
    if len(args) != 1:
        return None
    for node in walk(fn.body):
        if node.type != "init_declarator":
            continue
        declarator = node.child_by_field_name("declarator")
        ident = name_node(declarator)
        value = node.child_by_field_name("value")
        if ident is None or value is None or value.type != "call_expression":
            continue
        binding = fn.resolve(fn.text(ident), ident)
        if binding != info or fn.call_name(value) != "EcmaInterpreter::NewRuntimeCallInfo":
            continue
        call_args = fn.arguments(value)
        if not call_args or call_args[0].type != "identifier":
            return None
        thread = fn.resolve(fn.text(call_args[0]), call_args[0])
        return thread
    return None


def _callback_result_source(fn, node, effect_calls, identity_helpers=()):
    """Return (binding, value, direct_spec, nested_source) for bounded flows."""
    if node.type == "init_declarator":
        declarator = node.child_by_field_name("declarator")
        value = node.child_by_field_name("value")
        ident = name_node(declarator)
    elif node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        value = node.child_by_field_name("right")
        operator = node.child_by_field_name("operator")
        if (left is None or value is None or left.type != "identifier"
                or (operator is not None and fn.text(operator) != "=")):
            return None
        ident = left
    else:
        return None
    if ident is None or ident.type != "identifier" or value is None:
        return None

    raw_value = value
    value, _ = unwrap_identity_expression(fn, raw_value, identity_helpers)
    if value is None:
        value = raw_value
    source_calls = [item for item in walk(raw_value)
                    if item.type == "call_expression"
                    and any(fn.call_name(item) == spec[0]
                            and len(fn.arguments(item)) == spec[1]
                            for spec in effect_calls)]
    direct_spec = next((spec for spec in effect_calls
                        if value.type == "call_expression"
                        and fn.call_name(value) == spec[0]
                        and len(fn.arguments(value)) == spec[1]), None)
    binding = fn.resolve(fn.text(ident), ident)
    return ident, binding, value, direct_spec, bool(source_calls)


def _raw_text(data, node):
    return data[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _raw_namespace(data, node):
    parent = node.parent
    while parent is not None:
        if parent.type == "namespace_definition":
            name = parent.child_by_field_name("name")
            return _raw_text(data, name).replace(" ", "") if name is not None else ""
        parent = parent.parent
    return ""


def _class_records(source_units):
    records = {}
    for unit in source_units:
        if unit.language != "cpp" or unit.parse_status not in ("complete", "partial"):
            continue
        data = unit.text.encode("utf-8")
        try:
            tree, _ = parse_functions(data)
        except (ValueError, RuntimeError, UnicodeError):
            continue
        for node in walk(tree.root_node):
            if node.type != "class_specifier":
                continue
            name = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            if name is None or body is None:
                continue
            namespace = _raw_namespace(data, node)
            class_name = _raw_text(data, name).replace(" ", "")
            qualified = (namespace + "::" if namespace else "") + class_name
            bases = []
            for child in node.named_children:
                if child.type != "base_class_clause":
                    continue
                parts = [item for item in child.named_children
                         if item.type not in ("access_specifier", "virtual")]
                if parts:
                    base = _raw_text(data, parts[-1]).replace(" ", "")
                    bases.append(base if "::" in base
                                 else (namespace + "::" if namespace else "") + base)
            override = any(
                child.type == "function_declarator"
                and child.child_by_field_name("declarator") is not None
                and _raw_text(data, child.child_by_field_name("declarator")).split("::")[-1].startswith("Branch")
                and child.child_by_field_name("parameters") is not None
                and len([item for item in child.child_by_field_name("parameters").named_children
                         if item.type == "parameter_declaration"]) == 3
                for child in walk(body)
            )
            records[qualified] = {"bases": tuple(bases), "override": override}
    return records


def _verified_generated_branch_owners(source_units):
    """Return classes whose generated Branch alias has a checked true/false mapping."""
    contracts = set()
    for unit in source_units:
        if unit.language != "cpp" or unit.parse_status not in ("complete", "partial"):
            continue
        try:
            _, functions = parse_functions(unit.text.encode("utf-8"))
        except (ValueError, RuntimeError, UnicodeError):
            continue
        for fn in functions:
            if (fn.qualified_name.rsplit("::", 1)[-1] != "Branch"
                    or tuple(fn.parameter_types) != ("GateRef", "Label*", "Label*")):
                continue
            declarator = re.sub(r"\s+", "", fn.text(fn.declarator))
            if declarator != "StubBuilder::Branch(GateRefcondition,Label*trueLabel,Label*falseLabel)":
                continue
            body = re.sub(r"\s+", "", fn.text(fn.body))
            expected = (
                "{GateRefbranch=builder->Branch(control,condition);"
                "GateRefonTrue=builder->IfTrue(branch);"
                "trueLabel->MergeControl(onTrue);"
                "GateRefonFalse=builder->IfFalse(branch);"
                "falseLabel->MergeControl(onFalse);}"
            )
            if body == expected:
                contracts.add(fn.qualified_name.rsplit("::", 1)[0])

    records = _class_records(source_units)
    owners = set(contracts)
    changed = True
    while changed:
        changed = False
        for qualified, record in records.items():
            if qualified in owners or record["override"]:
                continue
            if any(base in owners for base in record["bases"]):
                owners.add(qualified)
                changed = True
    return frozenset(owners)


def _label_name(fn, node):
    if node is None:
        return None
    if node.type == "identifier":
        return fn.text(node)
    if node.type in ("unary_expression", "pointer_expression"):
        return _label_name(fn, node.child_by_field_name("argument") or node.named_children[-1])
    return None


def _binding_matches(fn, node, binding):
    return (node is not None and node.type == "identifier"
            and fn.resolve(fn.text(node), node) == binding)


def _generated_callback_sources(fn, effect_names=("JSCallDispatch", "JSFunction::Call")):
    for node in walk(fn.body):
        if node.type == "init_declarator":
            declarator = node.child_by_field_name("declarator")
            value = node.child_by_field_name("value")
            ident = name_node(declarator)
        elif node.type == "assignment_expression":
            ident = node.child_by_field_name("left")
            value = node.child_by_field_name("right")
        else:
            continue
        if ident is None or value is None or ident.type != "identifier":
            continue
        if value.type != "call_expression" or fn.call_name(value) not in effect_names:
            continue
        binding = fn.resolve(fn.text(ident), ident)
        if binding is not None:
            yield ident, binding, value


def _generated_sensitive_uses(fn, binding):
    for node in walk(fn.body):
        if node.type != "call_expression":
            continue
        name = fn.call_name(node)
        args = fn.arguments(node)
        if (name == "FastToBoolean" and len(args) == 1
                and binding.type_name == "GateRef"
                and _binding_matches(fn, args[0], binding)):
            yield node


def _compound_top_statement(fn, node):
    current = node
    while (current is not None and current.parent is not None
           and current.parent.type != "compound_statement"):
        current = current.parent
    if (current is not None and current.parent is not None
            and current.parent.type == "compound_statement"):
        return current
    return None


def _generated_branch_order(fn, source, sink, owners):
    source_statement = _compound_top_statement(fn, source)
    sink_statement = _compound_top_statement(fn, sink)
    if (source_statement is None or sink_statement is None
            or source_statement.parent != sink_statement.parent):
        return None, "callback_result_path_not_in_one_basic_compound"
    compound = source_statement.parent
    siblings = list(compound.named_children)
    source_index = siblings.index(source_statement)
    sink_index = siblings.index(sink_statement)
    if source_index >= sink_index:
        return None, "callback_result_use_order_unresolved"
    branches = []
    for statement in siblings[source_index + 1:sink_index]:
        for call in walk(statement):
            if call.type == "call_expression" and fn.call_name(call) in ("BRANCH", "Branch"):
                branches.append(call)
    candidate = ("candidate",
                 "callback_pending_exception_can_reach_generated_result_conversion")
    if not branches:
        return candidate, None
    if len(branches) != 1:
        return None, "unmodeled_generated_callback_exception_path"
    branch = branches[0]
    if (fn.call_name(branch) == "Branch"
            and fn.qualified_name.rsplit("::", 1)[0] not in owners):
        return None, "unmodeled_generated_callback_exception_path"
    args = fn.arguments(branch)
    if len(args) != 3:
        return None, "unmodeled_generated_callback_exception_path"
    condition, true_label, false_label = args
    true_name = _label_name(fn, true_label)
    false_name = _label_name(fn, false_label)
    if not true_name or not false_name:
        return None, "unmodeled_generated_callback_exception_path"
    condition_name = fn.call_name(condition)
    condition_args = fn.arguments(condition) if condition.type == "call_expression" else ()
    if condition_name == "HasPendingException" and len(condition_args) == 1:
        arg = condition_args[0]
        binding = fn.resolve(fn.text(arg), arg) if arg.type == "identifier" else None
        if (binding is None or not binding.parameter
                or binding.name not in ("glue", "thread")):
            return None, "unmodeled_generated_callback_exception_path"
    elif (condition_name not in ("TaggedIsException", "TaggedIsTrue")
          or len(condition_args) != 1):
        return None, "unmodeled_generated_callback_exception_path"

    binds = {}
    for item in siblings:
        for call in walk(item):
            if call.type != "call_expression" or fn.call_name(call) != "Bind":
                continue
            call_args = fn.arguments(call)
            if len(call_args) == 1:
                label = _label_name(fn, call_args[0])
                if label:
                    binds[label] = item
    exception_bind = binds.get(true_name)
    continue_bind = binds.get(false_name)
    if exception_bind is None or continue_bind is None:
        return None, "unmodeled_generated_callback_exception_path"
    exception_index = siblings.index(exception_bind)
    continue_index = siblings.index(continue_bind)
    if exception_index >= continue_index:
        return None, "unmodeled_generated_callback_exception_path"
    exception_path = siblings[exception_index + 1:continue_index]
    exits = any(
        item.type == "return_statement"
        or any(call.type == "call_expression" and fn.call_name(call) == "Jump"
               for call in walk(item))
        for item in exception_path
    )
    if not exits or condition_name != "HasPendingException":
        return candidate, None
    return ("matched",
            "pending_exception_check_precedes_generated_result_conversion"), None


def _analyze_generated_callback_paths(unit, owners):
    observations, limitations = [], []
    applicable = False
    try:
        _, functions = parse_functions(unit.text.encode("utf-8"))
    except (ValueError, RuntimeError, UnicodeError):
        return False, observations, limitations
    for fn in functions:
        for ident, binding, source in _generated_callback_sources(fn):
            uses = tuple(_generated_sensitive_uses(fn, binding))
            if not uses:
                continue
            applicable = True
            for sink in uses:
                outcome, reason = _generated_branch_order(fn, source, sink, owners)
                if outcome is None:
                    limitations.append(reason + ":" + fn.qualified_name)
                    continue
                kind, detail = outcome
                if kind == "matched":
                    continue
                observations.append(Observation(
                    kind, sink.start_point[0] + 1, sink.start_point[1] + 1, detail,
                    token_line=source.start_point[0] + 1,
                    symbol=fn.qualified_name,
                    region_start_byte=fn.node.start_byte,
                    region_end_byte=fn.node.end_byte,
                    target_identity=fn.text(ident),
                    token_origin=fn.call_name(source),
                    path=(source.start_point[0] + 1, sink.start_point[0] + 1),
                ))
    return applicable, observations, limitations


def _derived_exception_effect_calls(source_units, effect_calls, guards, macro_contracts,
                                    parsed_functions=(), parsed_path=None):
    """Infer wrapper effects from selected source bodies, never from API names alone."""
    base = tuple(effect_calls)
    parsed = list(parsed_functions)
    for unit in source_units:
        if unit.language != "cpp" or unit.parse_status not in ("complete", "partial"):
            continue
        if parsed_path is not None and unit.path == parsed_path:
            continue
        try:
            tree, functions = parse_functions(unit.text.encode("utf-8"))
        except (ValueError, RuntimeError, UnicodeError):
            continue
        if tree.root_node.has_error:
            continue
        parsed.extend(functions)

    aliases = {}
    for function in parsed:
        parts = function.qualified_name.split("::")
        if len(parts) >= 2:
            aliases.setdefault("::".join(parts[-2:]), []).append(function)
    unique_aliases = {name: values[0] for name, values in aliases.items() if len(values) == 1}

    current = base
    propagated = set()
    for _ in range(len(parsed) + 1):
        newly_propagated = set()
        for fn in parsed:
            if fn.qualified_name in propagated:
                continue
            return_type = fn.text(fn.node.child_by_field_name("type"))
            if re.sub(r"\s+", "", return_type) != "JSTaggedValue":
                continue
            for node in walk(fn.body):
                source = _callback_result_source(fn, node, current)
                if source is None:
                    continue
                _, binding, value, source_spec, _ = source
                if (source_spec is None or binding is None
                        or binding.type_name != source_spec[2]):
                    continue
                context_thread = _context_thread(fn, value)
                if context_thread is None:
                    continue
                for macro in walk(fn.body):
                    if macro.type != "call_expression":
                        continue
                    macro_name = fn.call_name(macro)
                    parameter_name = macro_contracts.get(macro_name)
                    if parameter_name is None:
                        continue
                    guard_arity = next(spec[1] for spec in guards if spec[0] == macro_name)
                    args = fn.arguments(macro)
                    if (len(args) != guard_arity or args[0].type != "identifier"
                            or fn.resolve(fn.text(args[0]), args[0]) != context_thread):
                        continue
                    relation = _direct_compound_pair(fn, value, macro)
                    if relation is not None and relation[3] < relation[4]:
                        newly_propagated.add(fn.qualified_name)
                        break
                if fn.qualified_name in newly_propagated:
                    break
        if not newly_propagated:
            break
        propagated.update(newly_propagated)
        effect_aliases = {
            alias for alias, function in unique_aliases.items()
            if function.qualified_name in propagated
        }
        derived = []
        for fn in parsed:
            for node in walk(fn.body):
                if node.type != "call_expression":
                    continue
                name = fn.call_name(node)
                if name in effect_aliases:
                    derived.append((name, len(fn.arguments(node)), "JSTaggedValue"))
        current = tuple(dict.fromkeys(base + tuple(derived)))
    return current


def _include_unit(source_units, unit):
    units = tuple(source_units)
    return units if any(item.path == unit.path and item.sha256 == unit.sha256
                        for item in units) else units + (unit,)


def _unknown_result_wrapper_sources(fn, function_nodes, effect_calls, sensitive_methods, identity_helpers=()):
    sensitive_bindings = set()
    for call in function_nodes:
        if call.type != "call_expression":
            continue
        callee = call.child_by_field_name("function")
        if callee is None or callee.type != "field_expression":
            continue
        field = callee.child_by_field_name("field")
        receiver = callee.child_by_field_name("argument")
        if (field is not None and fn.text(field) in sensitive_methods
                and receiver is not None and receiver.type == "identifier"):
            binding = fn.resolve(fn.text(receiver), receiver)
            if binding is not None:
                sensitive_bindings.add(binding)

    unknown = []
    for node in function_nodes:
        if node.type not in ("init_declarator", "assignment_expression"):
            continue
        source = _callback_result_source(fn, node, effect_calls, identity_helpers)
        if source is None:
            continue
        ident, binding, value, direct_spec, source_present = source
        if (binding is None or binding.type_name != "JSTaggedValue"
                or binding not in sensitive_bindings or value.type != "call_expression"
                or direct_spec is not None or source_present):
            continue
        args = fn.arguments(value)
        if not args or args[0].type != "identifier":
            continue
        first_arg = fn.resolve(fn.text(args[0]), args[0])
        if first_arg is None or first_arg.type_name.replace(" ", "") not in (
                "JSThread*", "JSThread", "EcmaRuntimeCallInfo*", "EcmaRuntimeCallInfo"):
            continue
        unknown.append((ident, binding, value))
    return tuple(unknown)


def _exception_result_condition(fn, condition, result_binding):
    while condition is not None and condition.type in (
            "condition_clause", "parenthesized_expression") and condition.named_children:
        condition = condition.named_children[0]
    if condition is None or condition.type != "call_expression":
        return False
    callee = condition.child_by_field_name("function")
    if callee is None or callee.type != "field_expression":
        return False
    field = callee.child_by_field_name("field")
    receiver = callee.child_by_field_name("argument")
    return (
        field is not None and fn.text(field) == "IsException"
        and _binding_matches(fn, receiver, result_binding)
    )


def _returns_pending_exception(fn, statement, result_binding):
    if statement.type == "return_statement":
        returns = [statement]
    elif statement.type == "compound_statement":
        meaningful = [item for item in statement.named_children
                      if item.type not in ("comment", "empty_statement")]
        returns = [item for item in meaningful if item.type == "return_statement"]
        if len(meaningful) != 1 or len(returns) != 1:
            return False
    else:
        return False
    value = returns[0].child_by_field_name("value")
    if value is None and returns[0].named_children:
        value = returns[0].named_children[0]
    if value is None:
        return False
    text = re.sub(r"\s+", "", fn.text(value))
    if text == "JSTaggedValue::Exception()":
        return True
    return value.type == "identifier" and _binding_matches(fn, value, result_binding)


def _guarded_by_exception_result(fn, compound, source_index, sink_index, result_binding):
    for statement in compound.named_children[source_index + 1:sink_index]:
        if statement.type != "if_statement":
            continue
        condition = statement.child_by_field_name("condition")
        consequence = statement.child_by_field_name("consequence")
        if (condition is None or consequence is None
                or not _exception_result_condition(fn, condition, result_binding)
                or not _returns_pending_exception(fn, consequence, result_binding)):
            continue
        return True
    return False


def analyze_runtime_exception_propagation(
    unit, *, source_units=(), effect_calls=(("JSFunction::Call", 1, "JSTaggedValue"),),
    sensitive_methods=("ToBoolean",),
    guards=(("RETURN_EXCEPTION_IF_ABRUPT_COMPLETION", 1,
             "HasPendingException", "JSTaggedValue::Exception"),),
    max_instructions=4096, functions=None,
):
    if unit.parse_status not in ("complete", "partial"):
        return RuntimeExceptionResult("limited", "not_analyzed",
                                      limitations=("source_parse_unavailable",))
    if functions is None:
        try:
            tree, functions = parse_functions(unit.text.encode("utf-8"))
        except (ValueError, RuntimeError, UnicodeError) as error:
            return RuntimeExceptionResult("failed", "failed",
                                          limitations=("parser_failure:" + type(error).__name__,))
        if tree.root_node.has_error:
            return RuntimeExceptionResult("limited", "partial",
                                          limitations=("runtime_translation_unit_parse_incomplete",))
    elif any(fn.translation_unit_status != "complete" for fn in functions):
        return RuntimeExceptionResult("limited", "partial",
                                      limitations=("runtime_translation_unit_parse_incomplete",))

    macro_contracts = {}
    for macro_name, arity, pending_test, exception_return in guards:
        macro_contracts[macro_name] = _macro_contract(
            source_units, macro_name, arity, pending_test, exception_return)
    effective_calls = _derived_exception_effect_calls(
        _include_unit(source_units, unit), effect_calls, guards, macro_contracts,
        parsed_functions=functions, parsed_path=unit.path)

    identity_helpers = build_identity_helpers(functions)
    owners = _verified_generated_branch_owners(_include_unit(source_units, unit))
    generated_applicable, observations, limitations = (
        _analyze_generated_callback_paths(unit, owners))
    steps = 0
    applicable = generated_applicable
    for fn in functions:
        if fn.node.has_error:
            continue
        function_nodes = tuple(walk(fn.body))
        has_source = any(
            (source := _callback_result_source(fn, node, effective_calls, identity_helpers)) is not None
            and source[4]
            for node in function_nodes
        )
        unknown_wrappers = _unknown_result_wrapper_sources(
            fn, function_nodes, effective_calls, sensitive_methods, identity_helpers)
        if not has_source and not unknown_wrappers:
            continue
        if unknown_wrappers:
            applicable = True
            limitations.append("callback_result_wrapper_summary_missing:" + fn.qualified_name)
        steps += len(function_nodes)
        if steps > max_instructions:
            return RuntimeExceptionResult("limited", "partial", tuple(observations),
                                          tuple(sorted(set(limitations + ["instruction_budget_exhausted"]))), steps)
        for node in function_nodes:
            source = _callback_result_source(fn, node, effective_calls, identity_helpers)
            if source is None:
                continue
            ident, binding, value, source_spec, nested_source = source
            if nested_source and source_spec is None:
                if binding is not None and binding.type_name == "JSTaggedValue":
                    applicable = True
                    limitations.append("callback_result_wrapper_semantics_unmodeled:" + fn.qualified_name)
                continue
            if source_spec is None:
                continue
            if binding is None or binding.type_name != source_spec[2]:
                continue
            applicable = True
            context_thread = _context_thread(fn, value)
            uses = []
            for call in walk(fn.body):
                if call.type != "call_expression":
                    continue
                callee = call.child_by_field_name("function")
                if callee is None or callee.type != "field_expression":
                    continue
                field = callee.child_by_field_name("field")
                receiver = callee.child_by_field_name("argument")
                if (field is not None and fn.text(field) in sensitive_methods
                        and receiver is not None and receiver.type == "identifier"
                        and fn.resolve(fn.text(receiver), receiver) == binding):
                    uses.append(call)
            if not uses:
                continue

            source_line = value.start_point[0] + 1
            for sink in uses:
                # A source definition cannot reach an earlier use in the same
                # straight-line invocation. A shared loop can revisit that use
                # on a later iteration, so keep that case unknown until a CFG
                # models the back edge.
                if value.start_byte > sink.start_byte:
                    if _shares_loop(value, sink):
                        limitations.append("callback_result_loop_backedge_unmodeled:" + fn.qualified_name)
                    continue
                relation = _direct_compound_pair(fn, value, sink)
                if relation is None:
                    limitations.append("callback_result_path_not_in_one_basic_compound:" + fn.qualified_name)
                    continue
                compound, source_statement, sink_statement, source_index, sink_index = relation
                if source_index >= sink_index:
                    limitations.append("callback_result_use_order_unresolved:" + fn.qualified_name)
                    continue
                if any(statement.type == "return_statement"
                       for statement in compound.named_children[source_index + 1:sink_index]):
                    continue
                reassigned = False
                for sibling in compound.named_children[source_index + 1:sink_index]:
                    for child in walk(sibling):
                        if child.type != "assignment_expression":
                            continue
                        lhs = child.child_by_field_name("left")
                        if (lhs is not None and lhs.type == "identifier"
                                and fn.resolve(fn.text(lhs), lhs) == binding):
                            reassigned = True
                if reassigned:
                    limitations.append("callback_result_reassigned_before_sensitive_use:" + fn.qualified_name)
                    continue

                protected = _guarded_by_exception_result(
                    fn, compound, source_index, sink_index, binding)
                if not protected and context_thread is not None:
                    for statement in compound.named_children[source_index + 1:sink_index]:
                        macro = next((call for call in walk(statement)
                                      if call.type == "call_expression"
                                      and fn.call_name(call) in macro_contracts), None)
                        if macro is None:
                            continue
                        macro_name = fn.call_name(macro)
                        parameter_name = macro_contracts[macro_name]
                        guard_arity = next(spec[1] for spec in guards if spec[0] == macro_name)
                        args = fn.arguments(macro)
                        if (parameter_name is not None and len(args) == guard_arity
                                and args[0].type == "identifier"
                                and fn.resolve(fn.text(args[0]), args[0]) == context_thread):
                            intervening_calls = [item for item in walk(statement)
                                                 if item.type == "call_expression"
                                                 and item != macro]
                            if not intervening_calls:
                                protected = True
                                break

                if protected:
                    continue
                sink_line = sink.start_point[0] + 1
                reason = "callback_completion_may_reach_result_conversion_without_dominating_exception_exit"
                observations.append(Observation(
                    "candidate", sink_line, sink.start_point[1] + 1, reason,
                    token_line=source_line, symbol=fn.qualified_name,
                    region_start_byte=fn.node.start_byte,
                    region_end_byte=fn.node.end_byte,
                    target_identity=fn.text(ident),
                    token_origin=fn.call_name(value),
                    path=(source_line, sink_line),
                ))

    if not applicable:
        return RuntimeExceptionResult("limited", "not_analyzed",
                                      limitations=("no_modeled_exception_result_source",), steps=steps)
    outcome = "partial" if limitations else "complete"
    return RuntimeExceptionResult("limited" if limitations else "completed", outcome,
                                  tuple(observations), tuple(sorted(set(limitations))), steps)


def _pending_exception_if_exit(fn, statement, thread_binding):
    if statement.type != "if_statement":
        return False
    condition = statement.child_by_field_name("condition")
    consequence = statement.child_by_field_name("consequence")
    if condition is None or consequence is None:
        return False
    exits = any(node.type == "return_statement" for node in walk(consequence))
    if not exits:
        return False
    condition_node = condition
    while condition_node.type in ("condition_clause", "parenthesized_expression") and condition_node.named_children:
        condition_node = condition_node.named_children[0]
    if condition_node.type != "call_expression":
        return False
    callee = condition_node.child_by_field_name("function")
    field = callee.child_by_field_name("field") if callee is not None else None
    receiver = callee.child_by_field_name("argument") if callee is not None else None
    if (field is None or fn.text(field) != "HasPendingException"
            or receiver is None or receiver.type != "identifier"
            or fn.resolve(fn.text(receiver), receiver) != thread_binding):
        return False
    for node in walk(condition):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        field = callee.child_by_field_name("field") if callee is not None else None
        receiver = callee.child_by_field_name("argument") if callee is not None else None
        if (field is not None and fn.text(field) == "HasPendingException"
                and receiver is not None and receiver.type == "identifier"
                and fn.resolve(fn.text(receiver), receiver) == thread_binding):
            return True
    return False


def analyze_call_info_construction_guard(
    unit, *, source_units=(),
    creators=(("EcmaInterpreter::NewRuntimeCallInfo", 5, "EcmaRuntimeCallInfo*"),),
    sensitive_methods=("SetCallArg",),
    guards=(("RETURN_EXCEPTION_IF_ABRUPT_COMPLETION", 1,
             "HasPendingException", "JSTaggedValue::Exception"),
            ("RETURN_VALUE_IF_ABRUPT_COMPLETION", 2,
             "HasPendingException", "return (value)"),
            ("RETURN_REJECT_PROMISE_IF_ABRUPT", 3,
             "HasPendingException", "return (capability)->GetPromise()")),
    max_instructions=4096, functions=None,
):
    """Check call-info pointer uses against the pending exception from construction."""
    if unit.parse_status not in ("complete", "partial"):
        return RuntimeExceptionResult("limited", "not_analyzed",
                                      limitations=("source_parse_unavailable",))
    if functions is None:
        try:
            tree, functions = parse_functions(unit.text.encode("utf-8"))
        except (ValueError, RuntimeError, UnicodeError) as error:
            return RuntimeExceptionResult("failed", "failed",
                                          limitations=("parser_failure:" + type(error).__name__,))
        if tree.root_node.has_error:
            return RuntimeExceptionResult("limited", "partial",
                                          limitations=("runtime_translation_unit_parse_incomplete",))
    elif any(fn.translation_unit_status != "complete" for fn in functions):
        return RuntimeExceptionResult("limited", "partial",
                                      limitations=("runtime_translation_unit_parse_incomplete",))

    macro_contracts = {}
    for name, arity, pending, exception in guards:
        if name == "RETURN_REJECT_PROMISE_IF_ABRUPT":
            macro_contracts[name] = _macro_returns_on_pending(
                source_units, name, arity, pending, exception)
        else:
            macro_contracts[name] = _macro_contract(
                source_units, name, arity, pending, exception)
    observations, limitations = [], []
    applicable = False
    steps = 0
    for fn in functions:
        if fn.node.has_error:
            continue
        nodes = tuple(walk(fn.body))
        creations = []
        for node in nodes:
            if node.type != "init_declarator":
                continue
            declaration = node.parent
            declarator = node.child_by_field_name("declarator")
            value = node.child_by_field_name("value")
            ident = name_node(declarator)
            if ident is None or value is None or value.type != "call_expression":
                continue
            spec = next((item for item in creators
                         if fn.call_name(value) == item[0]
                         and len(fn.arguments(value)) == item[1]), None)
            binding = fn.resolve(fn.text(ident), ident)
            if (spec is None or binding is None
                    or re.sub(r"[\s*]+", "", binding.type_name)
                    != re.sub(r"[\s*]+", "", spec[2])):
                continue
            creations.append((ident, binding, value, declaration))
        if not creations:
            continue

        applicable = True
        steps += len(nodes)
        if steps > max_instructions:
            return RuntimeExceptionResult("limited", "partial", tuple(observations),
                                          tuple(sorted(set(limitations + ["instruction_budget_exhausted"]))), steps)

        for ident, binding, value, _ in creations:
            context_thread = _context_thread(fn, value)
            uses = []
            for call in nodes:
                if call.type != "call_expression":
                    continue
                callee = call.child_by_field_name("function")
                if callee is None or callee.type != "field_expression":
                    continue
                field = callee.child_by_field_name("field")
                receiver = callee.child_by_field_name("argument")
                if (field is not None and fn.text(field) in sensitive_methods
                        and receiver is not None and receiver.type == "identifier"
                        and fn.resolve(fn.text(receiver), receiver) == binding):
                    uses.append(call)
            if not uses:
                continue

            for sink in uses:
                if value.start_byte > sink.start_byte:
                    if _shares_loop(value, sink):
                        limitations.append("call_info_pointer_loop_backedge_unmodeled:" + fn.qualified_name)
                    continue
                relation = _ordered_ancestor_compound_pair(fn, value, sink)
                if relation is None:
                    limitations.append("call_info_pointer_path_not_in_one_basic_compound:" + fn.qualified_name)
                    continue
                compound, _, _, source_index, sink_index = relation
                if source_index >= sink_index:
                    limitations.append("call_info_pointer_use_order_unresolved:" + fn.qualified_name)
                    continue
                between = compound.named_children[source_index + 1:sink_index]
                if any(statement.type == "return_statement" for statement in between):
                    continue
                reassigned = any(
                    child.type == "assignment_expression"
                    and (lhs := child.child_by_field_name("left")) is not None
                    and lhs.type == "identifier"
                    and fn.resolve(fn.text(lhs), lhs) == binding
                    for statement in between for child in walk(statement)
                )
                if reassigned:
                    limitations.append("call_info_pointer_reassigned_before_use:" + fn.qualified_name)
                    continue

                protected = False
                unknown_guard = False
                for statement in between:
                    if _pending_exception_if_exit(fn, statement, context_thread):
                        protected = True
                        break
                    if statement.type != "expression_statement":
                        continue
                    for macro in walk(statement):
                        if macro.type != "call_expression":
                            continue
                        macro_name = fn.call_name(macro)
                        if macro_name not in macro_contracts:
                            continue
                        contract = macro_contracts[macro_name]
                        args = fn.arguments(macro)
                        arity = next(item[1] for item in guards if item[0] == macro_name)
                        if (contract is None or context_thread is None or len(args) != arity
                                or not args or args[0].type != "identifier"
                                or fn.resolve(fn.text(args[0]), args[0]) != context_thread):
                            unknown_guard = True
                            continue
                        protected = True
                        break
                    if protected:
                        break
                if protected:
                    continue
                if unknown_guard:
                    limitations.append("call_info_exception_guard_contract_unverified:" + fn.qualified_name)
                    continue
                if context_thread is None:
                    limitations.append("call_info_constructor_thread_unresolved:" + fn.qualified_name)
                    continue

                observations.append(Observation(
                    "candidate", sink.start_point[0] + 1, sink.start_point[1] + 1,
                    "call_info_construction_may_leave_pending_exception_before_pointer_use",
                    token_line=value.start_point[0] + 1,
                    symbol=fn.qualified_name,
                    region_start_byte=fn.node.start_byte,
                    region_end_byte=fn.node.end_byte,
                    target_identity=fn.text(ident),
                    token_origin=fn.call_name(value),
                    path=(value.start_point[0] + 1, sink.start_point[0] + 1),
                ))

    if not applicable:
        return RuntimeExceptionResult("limited", "not_analyzed",
                                      limitations=("no_modeled_call_info_constructor",), steps=steps)
    outcome = "partial" if limitations else "complete"
    return RuntimeExceptionResult("limited" if limitations else "completed", outcome,
                                  tuple(observations), tuple(sorted(set(limitations))), steps)


def has_call_info_constructor(unit, creators=(("EcmaInterpreter::NewRuntimeCallInfo", 5,
                                               "EcmaRuntimeCallInfo*"),), functions=None):
    if unit.language != "cpp" or unit.parse_status not in ("complete", "partial"):
        return False
    if functions is None:
        try:
            _, functions = parse_functions(unit.text.encode("utf-8"))
        except (ValueError, RuntimeError, UnicodeError):
            return False
    for fn in functions:
        for node in walk(fn.body):
            if node.type != "init_declarator":
                continue
            declarator = node.child_by_field_name("declarator")
            value = node.child_by_field_name("value")
            ident = name_node(declarator)
            if ident is None or value is None or value.type != "call_expression":
                continue
            if any(fn.call_name(value) == spec[0]
                   and len(fn.arguments(value)) == spec[1]
                   for spec in creators):
                return True
    return False


def has_runtime_exception_source(unit, effect_calls=(("JSFunction::Call", 1, "JSTaggedValue"),),
                                 source_units=(), guards=(("RETURN_EXCEPTION_IF_ABRUPT_COMPLETION", 1,
                                 "HasPendingException", "JSTaggedValue::Exception"),), functions=None):
    if unit.language != "cpp" or unit.parse_status not in ("complete", "partial"):
        return False
    if functions is None:
        try:
            _, functions = parse_functions(unit.text.encode("utf-8"))
        except (ValueError, RuntimeError, UnicodeError):
            return False
    contracts = {name: _macro_contract(source_units, name, arity, pending, exception)
                 for name, arity, pending, exception in guards}
    effects = _derived_exception_effect_calls(
        _include_unit(source_units, unit), effect_calls, guards, contracts,
        parsed_functions=functions, parsed_path=unit.path)
    for fn in functions:
        for node in walk(fn.body):
            source = _callback_result_source(fn, node, effects)
            if source is None:
                continue
            _, binding, _, _, source_present = source
            if source_present and binding is not None and binding.type_name == "JSTaggedValue":
                return True
        if _unknown_result_wrapper_sources(fn, tuple(walk(fn.body)), effects,
                                           ("ToBoolean",)):
            return True
    return False



def analyze_native_inline_exception_propagation(unit):
    """Detect Reflect.apply inlining that compares a sentinel instead of pending state."""
    if unit.parse_status not in ("complete", "partial"):
        return RuntimeExceptionResult("limited", "not_analyzed",
                                      limitations=("source_parse_unavailable",))
    text = unit.text
    masked = _mask_cpp_noncode(text) if "_mask_cpp_noncode" in globals() else text
    function_pattern = re.compile(
        r"\b(?P<name>(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{")
    regions = {}
    cursor = 0
    while True:
        match = function_pattern.search(masked, cursor)
        if match is None:
            break
        cursor = match.end()
        opening = masked.find("{", match.start(), match.end())
        depth = 0
        closing = None
        for index in range(opening, len(masked)):
            if masked[index] == "{":
                depth += 1
            elif masked[index] == "}":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing is None:
            continue
        regions[match.group("name")] = (text[opening + 1:closing],
                                        text.count("\n", 0, opening + 1) + 1,
                                        len(text[:opening + 1].encode("utf-8")))
    def method(name):
        return name == name.rsplit("::", 1)[-1] or name.endswith("NativeInlineLowering::" + name.rsplit("::", 1)[-1])
    caller_name = next((name for name in regions
                        if name.rsplit("::", 1)[-1] == "TryInlineReflectApply"), None)
    helper_name = next((name for name in regions
                        if name.rsplit("::", 1)[-1] == "ReplaceGateWithPendingException"), None)
    if caller_name is None:
        return RuntimeExceptionResult("limited", "not_analyzed",
                                      limitations=("reflect_apply_inline_site_not_applicable",))
    if helper_name is None:
        return RuntimeExceptionResult("limited", "partial",
                                      limitations=("pending_exception_helper_summary_missing:" + caller_name,))
    body, body_line, body_byte = regions[helper_name]
    if re.search(r"\bHasPendingException\s*\(", body):
        return RuntimeExceptionResult("completed", "complete", (),
                                      ("fixed_pending_exception_check_control_not_security_verdict",), 1)
    sentinel = re.search(r"\b(?:ExceptionConstant|Exception)\s*\(\s*\)", body)
    equality = re.search(r"\b(?:Equal|Int32Equal|Int64Equal)\s*\([^;]*exception[^;]*\)", body, re.I)
    branch = re.search(r"\bBranch\s*\([^;]*(?:equal|condition)[^;]*\)", body, re.I)
    if sentinel and equality and branch:
        offset = equality.start()
        prefix = body[:offset]
        line = body_line + prefix.count("\n")
        column = len(prefix[prefix.rfind("\n", 0, offset) + 1:offset].encode("utf-8")) + 1
        start_byte = body_byte + len(prefix.encode("utf-8"))
        observation = Observation(
            "candidate", line, column,
            "reflect_apply_result_sentinel_comparison_may_drop_pending_exception",
            helper_name, "ExceptionConstant", line, line, (line,),
            ((line, "checks_pending_thread_exception", False),),
            helper_name, start_byte, start_byte + len(equality.group(0).encode("utf-8")))
        return RuntimeExceptionResult("limited", "partial", (observation,),
                                      ("local_sentinel_comparison_does_not_prove_exception_propagation",), 1)
    return RuntimeExceptionResult("limited", "partial", (),
                                  ("native_inline_exception_semantics_unmodeled:" + helper_name,), 1)
