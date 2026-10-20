import difflib
from pathlib import Path
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
source = root / "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/runtime_exception_semantics_fix_2.patch"
old = source.read_text(encoding="utf-8")
old_wrapper = '''        if first_arg is None or first_arg.type_name.replace(" ", "") not in ("JSThread*", "JSThread"):
            continue
'''
new_wrapper = '''        if first_arg is None or first_arg.type_name.replace(" ", "") not in (
                "JSThread*", "JSThread", "EcmaRuntimeCallInfo*", "EcmaRuntimeCallInfo"):
            continue
'''
assert old.count(old_wrapper) == 1
new = old.replace(old_wrapper, new_wrapper)
start = new.index("def _guarded_by_exception_result(fn, compound, source_index, sink_index, result_binding):")
end = new.index("\n\ndef analyze_runtime_exception_propagation(", start)
strict = '''def _exception_result_condition(fn, condition, result_binding):
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
    if value is None:
        return False
    text = re.sub(r"\\s+", "", fn.text(value))
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
'''
new = new[:start] + strict + new[end:]
old_obs = '''                kind, detail = outcome
                observations.append(Observation(
                    kind, sink.start_point[0] + 1, sink.start_point[1] + 1, detail,
'''
new_obs = '''                kind, detail = outcome
                if kind == "matched":
                    continue
                observations.append(Observation(
                    kind, sink.start_point[0] + 1, sink.start_point[1] + 1, detail,
'''
assert new.count(old_obs) == 1
new = new.replace(old_obs, new_obs)
path = "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch.write_text("".join(difflib.unified_diff(
    old.splitlines(keepends=True), new.splitlines(keepends=True),
    fromfile="a/" + path, tofile="b/" + path)), encoding="utf-8")
