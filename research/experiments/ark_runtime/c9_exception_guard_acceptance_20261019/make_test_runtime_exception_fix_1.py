import difflib
from pathlib import Path
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
source = root / "tests/detectors/ark_runtime/test_runtime_exception.py"
patch = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/test_runtime_exception_controls_fix_1.patch"
old = source.read_text(encoding="utf-8")
marker = "class C9ExceptionEffectOrderControls(unittest.TestCase):\n"
replacement = '''class C9ExceptionEffectOrderControls(unittest.TestCase):
    def analyze(self, text, macro_source=MACROS):
        return analyze_runtime_exception_propagation(
            unit(text, "ecmascript/builtins/builtins_typedarray.cpp"),
            source_units=(unit(macro_source, "ecmascript/ecma_macros.h"),))

'''
assert old.count(marker) == 1
new = old.replace(marker, replacement)
path = "tests/detectors/ark_runtime/test_runtime_exception.py"
patch.write_text("".join(difflib.unified_diff(
    old.splitlines(keepends=True), new.splitlines(keepends=True),
    fromfile="a/" + path, tofile="b/" + path)), encoding="utf-8")
