from pathlib import Path
p = Path("src/ohscanner/detectors/ark_runtime/detector.py")
s = p.read_text(encoding="utf-8")
s = s.replace(
"from .analysis import analyze_unit\nfrom .exception_guard import analyze_exception_guard\nfrom .receiver_guard import analyze_receiver_guard\nfrom .model import (AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID,\n                    EXCEPTION_GUARD_RULE_ID, RECEIVER_TYPE_GUARD_RULE_ID, VERSION)",
"from .analysis import analyze_unit\nfrom .exception_guard import analyze_exception_guard\nfrom .receiver_guard import analyze_receiver_guard\nfrom .runtime_exception import analyze_native_inline_exception_propagation\nfrom .size_overflow import (analyze_size_overflow_unit, index_bounds_result,\n                            length_narrowing_result)\nfrom .model import (AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID,\n                    EXCEPTION_GUARD_RULE_ID, RECEIVER_TYPE_GUARD_RULE_ID,\n                    SIZE_OVERFLOW_RULE_ID, LENGTH_NARROWING_RULE_ID,\n                    INDEX_BOUNDS_RULE_ID, NATIVE_EXCEPTION_RULE_ID,\n                    GAP_RULE_VERSIONS, VERSION)")
s = s.replace(
"        paths = {row[1] for row in (self.model.target_bindings + self.model.exception_guard_bindings\n                                     + self.model.receiver_guard_bindings)}",
"        paths = {row[1] for row in (\n            self.model.target_bindings + self.model.exception_guard_bindings\n            + self.model.receiver_guard_bindings + self.model.size_overflow_bindings\n            + self.model.length_narrowing_bindings + self.model.index_bounds_bindings\n            + self.model.native_exception_bindings)}")
s = s.replace(
"            receiver_binding = next((row for row in self.model.receiver_guard_bindings\n                                     if row[0] == context.request.commit and row[1] == unit.path), None)\n",
"            receiver_binding = next((row for row in self.model.receiver_guard_bindings\n                                     if row[0] == context.request.commit and row[1] == unit.path), None)\n"
"            size_binding = next((row for row in self.model.size_overflow_bindings\n                                 if row[0] == context.request.commit and row[1] == unit.path), None)\n"
"            length_binding = next((row for row in self.model.length_narrowing_bindings\n                                   if row[0] == context.request.commit and row[1] == unit.path), None)\n"
"            index_binding = next((row for row in self.model.index_bounds_bindings\n                                  if row[0] == context.request.commit and row[1] == unit.path), None)\n"
"            native_binding = next((row for row in self.model.native_exception_bindings\n                                   if row[0] == context.request.commit and row[1] == unit.path), None)\n")
s = s.replace(
"            if receiver_binding is not None:\n                rule_bindings.append((RECEIVER_TYPE_GUARD_RULE_ID, receiver_binding))\n",
"            if receiver_binding is not None:\n                rule_bindings.append((RECEIVER_TYPE_GUARD_RULE_ID, receiver_binding))\n"
"            if size_binding is not None:\n                rule_bindings.append((SIZE_OVERFLOW_RULE_ID, size_binding))\n"
"            if length_binding is not None:\n                rule_bindings.append((LENGTH_NARROWING_RULE_ID, length_binding))\n"
"            if index_binding is not None:\n                rule_bindings.append((INDEX_BOUNDS_RULE_ID, index_binding))\n"
"            if native_binding is not None:\n                rule_bindings.append((NATIVE_EXCEPTION_RULE_ID, native_binding))\n")
s = s.replace(
"                elif rule_id == EXCEPTION_GUARD_RULE_ID:",
"                elif rule_id == SIZE_OVERFLOW_RULE_ID:\n                    result = analyze_size_overflow_unit(unit, self.model.digest)\n                elif rule_id == LENGTH_NARROWING_RULE_ID:\n                    result = length_narrowing_result(unit, self.model.digest)\n                elif rule_id == INDEX_BOUNDS_RULE_ID:\n                    result = index_bounds_result(unit, self.model.digest)\n                elif rule_id == NATIVE_EXCEPTION_RULE_ID:\n                    result = analyze_native_inline_exception_propagation(unit)\n                elif rule_id == EXCEPTION_GUARD_RULE_ID:")
s = s.replace(
"                    if rule_id == EXCEPTION_GUARD_RULE_ID:",
"                    rule_version = GAP_RULE_VERSIONS.get(rule_id, 'existing-rule-v1')\n"
"                    trace += ';rule_version=' + rule_version\n"
"                    if rule_id == NATIVE_EXCEPTION_RULE_ID:\n"
"                        obligations = (\n"
"                            ('exception_propagation_semantics', 'Verify the exact pending-exception condition and generated branch return semantics.'),\n"
"                            ('runtime_path_feasibility', 'Establish that Reflect.apply inlining can reach the unguarded helper under a realistic call.'),\n"
"                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),\n"
"                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),\n"
"                        )\n"
"                    elif rule_id == LENGTH_NARROWING_RULE_ID:\n"
"                        obligations = (\n"
"                            ('integer_conversion_semantics', 'Prove the ToIndex range, signed-to-unsigned conversion and allocation length semantics.'),\n"
"                            ('memory_safety_impact', 'Establish whether the narrowed length can cause an undersized allocation or out-of-bounds access.'),\n"
"                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),\n"
"                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),\n"
"                        )\n"
"                    elif rule_id == INDEX_BOUNDS_RULE_ID:\n"
"                        obligations = (\n"
"                            ('index_width_and_bounds', 'Prove index width, overflow behavior and the exact DataView/Atomics bounds comparison.'),\n"
"                            ('memory_safety_impact', 'Establish a concrete out-of-bounds witness or retain the result as unknown.'),\n"
"                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),\n"
"                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),\n"
"                        )\n"
"                    elif rule_id == SIZE_OVERFLOW_RULE_ID:\n"
"                        obligations = (\n"
"                            ('integer_range_semantics', 'Prove multiplication width and overflow behavior for both operands.'),\n"
"                            ('allocation_and_copy_flow', 'Connect the narrowed product to the exact allocation and copy bound.'),\n"
"                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),\n"
"                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),\n"
"                        )\n"
"                    elif rule_id == EXCEPTION_GUARD_RULE_ID:")
s = s.replace(
"                        message=(\n                            'Candidate only: allocation result header is read on a path where the allocation may leave a pending exception. trace=' + trace\n                            if rule_id == EXCEPTION_GUARD_RULE_ID else\n",
"                        message=(\n                            'Candidate only: Reflect.apply native-inline result uses exception-sentinel comparison without a proven pending-exception exit. trace=' + trace\n                            if rule_id == NATIVE_EXCEPTION_RULE_ID else\n"
"                            'Candidate only: signed 32-bit ToIndex result narrows a TypedArray allocation length. trace=' + trace\n"
"                            if rule_id == LENGTH_NARROWING_RULE_ID else\n"
"                            'Candidate only: 32-bit DataView/Atomics index arithmetic reaches a local bounds check. trace=' + trace\n"
"                            if rule_id == INDEX_BOUNDS_RULE_ID else\n"
"                            'Candidate only: narrowed multiplication feeds allocation and copy bounds. trace=' + trace\n"
"                            if rule_id == SIZE_OVERFLOW_RULE_ID else\n"
"                            'Candidate only: allocation result header is read on a path where the allocation may leave a pending exception. trace=' + trace\n                            if rule_id == EXCEPTION_GUARD_RULE_ID else\n")
p.write_text(s, encoding="utf-8", newline="")
print("patched detector")
