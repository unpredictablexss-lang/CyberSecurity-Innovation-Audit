import difflib
from pathlib import Path
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
source = root / "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/runtime_exception_generated_fix_1.patch"
old = source.read_text(encoding="utf-8")
old_use = '''        if name == "FastToBoolean" and len(args) == 1 and _binding_matches(fn, args[0], binding):
            yield node
            continue
        callee = node.child_by_field_name("function")
        if callee is not None and callee.type == "field_expression":
            field = callee.child_by_field_name("field")
            receiver = callee.child_by_field_name("argument")
            if (field is not None and fn.text(field) == "ToBoolean"
                    and _binding_matches(fn, receiver, binding)):
                yield node
'''
new_use = '''        if (name == "FastToBoolean" and len(args) == 1
                and binding.type_name == "GateRef"
                and _binding_matches(fn, args[0], binding)):
            yield node
'''
assert old.count(old_use) == 1
new = old.replace(old_use, new_use)
old_owner = 'fn.qualified_name.rsplit("::", 2)[0] not in owners'
new_owner = 'fn.qualified_name.rsplit("::", 1)[0] not in owners'
assert new.count(old_owner) == 1
new = new.replace(old_owner, new_owner)
path = "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch.write_text("".join(difflib.unified_diff(
    old.splitlines(keepends=True), new.splitlines(keepends=True),
    fromfile="a/" + path, tofile="b/" + path)), encoding="utf-8")
