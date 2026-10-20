import difflib
from pathlib import Path
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
source = root / "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/runtime_exception_generated_integration.patch"
old = source.read_text(encoding="utf-8")
marker = """    effective_calls = _derived_exception_effect_calls(
        _include_unit(source_units, unit), effect_calls, guards, macro_contracts,
        parsed_functions=functions, parsed_path=unit.path)

    observations, limitations = [], []
    steps = 0
    applicable = False
"""
replacement = """    effective_calls = _derived_exception_effect_calls(
        _include_unit(source_units, unit), effect_calls, guards, macro_contracts,
        parsed_functions=functions, parsed_path=unit.path)

    owners = _verified_generated_branch_owners(_include_unit(source_units, unit))
    generated_applicable, observations, limitations = (
        _analyze_generated_callback_paths(unit, owners))
    steps = 0
    applicable = generated_applicable
"""
assert old.count(marker) == 1
new = old.replace(marker, replacement)
path = "src/ohscanner/detectors/ark_runtime/runtime_exception.py"
patch.write_text("".join(difflib.unified_diff(
    old.splitlines(keepends=True), new.splitlines(keepends=True),
    fromfile="a/" + path, tofile="b/" + path)), encoding="utf-8")
