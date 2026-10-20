import difflib
from pathlib import Path
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
source = root / "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
block = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/runtime_exception_block_3.txt"
patch = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/runtime_exception_block_3.patch"
old = source.read_text(encoding="utf-8").splitlines(keepends=True)
insert = block.read_text(encoding="utf-8")
marker = "def _derived_exception_effect_calls(source_units, effect_calls, guards, macro_contracts,\n"
index = old.index(marker)
new = old[:index] + insert.splitlines(keepends=True) + old[index:]
path = "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch.write_text("".join(difflib.unified_diff(old, new, fromfile="a/" + path, tofile="b/" + path)), encoding="utf-8")
