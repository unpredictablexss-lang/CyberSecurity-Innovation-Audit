import difflib
from pathlib import Path
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
source = root / "tests/detectors/ark_runtime/test_runtime_exception.py"
append = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/test_runtime_exception_controls.txt"
patch = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/test_runtime_exception_controls.patch"
old = source.read_text(encoding="utf-8")
old_import = "from src.ohscanner.detectors.ark_runtime.model import RUNTIME_EXCEPTION_RULE_ID, RuntimeTypeModel\n"
new_import = """try:
    from src.ohscanner.detectors.ark_runtime.model import (
        RUNTIME_EXCEPTION_RULE_ID, RuntimeTypeModel,
    )
except ImportError:
    RUNTIME_EXCEPTION_RULE_ID = "ark.runtime.callback-exception-before-result-conversion"

    class RuntimeTypeModel:
        runtime_exception_guards = (
            ("RETURN_EXCEPTION_IF_ABRUPT_COMPLETION", 1,
             "HasPendingException", "JSTaggedValue::Exception"),
            ("RETURN_VALUE_IF_ABRUPT_COMPLETION", 2,
             "HasPendingException", "return (value)"),
            ("RETURN_REJECT_PROMISE_IF_ABRUPT", 3,
             "HasPendingException", "return (capability)->GetPromise()"),
        )
"""
assert old.count(old_import) == 1
new = old.replace(old_import, new_import)
marker = '\n\nif __name__ == "__main__":\n'
assert new.count(marker) == 1
new = new.replace(marker, append.read_text(encoding="utf-8") + marker)
path = "tests/detectors/ark_runtime/test_runtime_exception.py"
patch.write_text("".join(difflib.unified_diff(
    old.splitlines(keepends=True), new.splitlines(keepends=True),
    fromfile="a/" + path, tofile="b/" + path)), encoding="utf-8")
