import difflib
from pathlib import Path
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
source = root / "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/runtime_exception_return_value_fix.patch"
old = source.read_text(encoding="utf-8")
old_line = '    value = returns[0].child_by_field_name("value")\n'
new_line = '''    value = returns[0].child_by_field_name("value")
    if value is None and returns[0].named_children:
        value = returns[0].named_children[0]
'''
assert old.count(old_line) == 1
new = old.replace(old_line, new_line)
path = "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch.write_text("".join(difflib.unified_diff(
    old.splitlines(keepends=True), new.splitlines(keepends=True),
    fromfile="a/" + path, tofile="b/" + path)), encoding="utf-8")
