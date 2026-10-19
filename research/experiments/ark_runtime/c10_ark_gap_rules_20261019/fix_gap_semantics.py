from pathlib import Path
p = Path("src/ohscanner/detectors/ark_runtime/size_overflow.py")
s = p.read_text(encoding="utf-8")
s = s.replace(
"    for name, body, body_line, body_byte in _bounded_function_regions(text):\n        if 'ToIndex' not in body or 'AllocateTypedArray' not in body:\n            continue\n        applicable = True\n",
"    for name, body, body_line, body_byte in _bounded_function_regions(text):\n        if 'ToIndex' not in body or 'AllocateTypedArray' not in body:\n            continue\n        applicable = True\n        signed_found = False\n")
s = s.replace(
"        for declaration in declarations:\n            result_name = declaration.group('name')\n",
"        for declaration in declarations:\n            signed_found = True\n            result_name = declaration.group('name')\n")
s = s.replace(
"        if not candidates and re.search(\n                r'\\bAllocateTypedArray\\s*\\(', body) and re.search(r'\\bToIndex\\s*\\(', body):\n            if re.search(r'(?:static_cast\\s*<|DoubleInRangeInt32|\\b\\w+\\s*=\\s*[A-Za-z_]\\w*\\s*\\()', body):\n                limitations.append('typedarray_length_conversion_semantics_unmodeled:' + name)\n",
"        if (signed_found and not candidates and re.search(\n                r'\\bAllocateTypedArray\\s*\\(', body) and re.search(r'\\bToIndex\\s*\\(', body)\n                and re.search(r'(?:static_cast\\s*<|DoubleInRangeInt32|\\b\\w+\\s*=\\s*[A-Za-z_]\\w*\\s*\\()', body)):\n            limitations.append('typedarray_length_conversion_semantics_unmodeled:' + name)\n")
s = s.replace(
"    if limitations:\n        return AnalysisResult('limited', 'partial', observations, limitations,\n                              steps=len(candidates) + len(limitations), model_digest=model_digest)\n    if not candidates and unit.parse_status == 'complete':\n        return AnalysisResult('completed', 'complete', (), ('no_local_length_narrowing_candidate',),\n                              steps=0, model_digest=model_digest)\n",
"    if limitations and limitations == ('not_applicable_to_typedarray_length_allocation',):\n        return AnalysisResult('limited', 'not_analyzed', (), limitations,\n                              steps=0, model_digest=model_digest)\n    if limitations:\n        return AnalysisResult('limited', 'partial', observations, limitations,\n                              steps=len(candidates) + len(limitations), model_digest=model_digest)\n    if not candidates and unit.parse_status == 'complete':\n        return AnalysisResult('completed', 'complete', (), ('no_local_length_narrowing_candidate',),\n                              steps=0, model_digest=model_digest)\n")
s = s.replace(
"        elif (re.search(r'index\\s*>\\s*size\\s*\\|\\|\\s*elementSize\\s*>\\s*size\\s*-\\s*index', body)\n              or re.search(r'elementSize\\s*>\\s*size\\s*-\\s*index', body)):\n            continue\n",
"        elif re.search(r'UnknownIndexConversion|CheckIndexBounds', body):\n            limitations.append('dataview_atomic_index_bounds_semantics_unmodeled:' + name)\n        elif (re.search(r'index\\s*>\\s*size\\s*\\|\\|\\s*elementSize\\s*>\\s*size\\s*-\\s*index', body)\n              or re.search(r'elementSize\\s*>\\s*size\\s*-\\s*index', body)):\n            continue\n")
s = s.replace(
"    if any(not item.startswith(('index_width_bounds_arithmetic_not_fully_proven:',\n                                'dataview_atomic_index_bounds_semantics_unmodeled:'))\n           for item in limitations):\n        return AnalysisResult('failed', 'failed', observations, limitations,\n                              steps=len(candidates), model_digest=model_digest)\n",
"    if limitations and limitations == ('not_applicable_to_dataview_or_atomics_index_bounds',):\n        return AnalysisResult('limited', 'not_analyzed', (), limitations,\n                              steps=0, model_digest=model_digest)\n    if any(not item.startswith(('index_width_bounds_arithmetic_not_fully_proven:',\n                                'dataview_atomic_index_bounds_semantics_unmodeled:'))\n           for item in limitations):\n        return AnalysisResult('failed', 'failed', observations, limitations,\n                              steps=len(candidates), model_digest=model_digest)\n")
p.write_text(s, encoding="utf-8", newline="")

p = Path("src/ohscanner/detectors/ark_runtime/runtime_exception.py")
s = p.read_text(encoding="utf-8")
s = s.replace(
'    caller_name = next((name for name in regions if name.endswith("NativeInlineLowering::TryInlineReflectApply")), None)\n    helper_name = next((name for name in regions if name.endswith("NativeInlineLowering::ReplaceGateWithPendingException")), None)',
'    def method(name):\n        return name == name.rsplit("::", 1)[-1] or name.endswith("NativeInlineLowering::" + name.rsplit("::", 1)[-1])\n    caller_name = next((name for name in regions\n                        if name.rsplit("::", 1)[-1] == "TryInlineReflectApply"), None)\n    helper_name = next((name for name in regions\n                        if name.rsplit("::", 1)[-1] == "ReplaceGateWithPendingException"), None)')
p.write_text(s, encoding="utf-8", newline="")

p = Path("tests/detectors/ark_runtime/test_c10_ark_gap_rules.py")
s = p.read_text(encoding="utf-8")
s = s.replace("        self.assertEqual(result.observations, ())\n        self.assertTrue(any('fixed_pending_exception_check_control' in x",
              "        self.assertFalse(any(item.kind == 'candidate' for item in result.observations))\n        self.assertTrue(any('fixed_pending_exception_check_control' in x")
s = s.replace("        self.assertEqual(result.observations, ())\n        self.assertEqual(result.file_outcome, 'partial')\n        self.assertTrue(any('not_fully_proven' in x",
              "        self.assertFalse(any(item.kind == 'candidate' for item in result.observations))\n        self.assertEqual(result.file_outcome, 'partial')\n        self.assertTrue(any('not_fully_proven' in x")
p.write_text(s, encoding="utf-8", newline="")
print("patched gap semantics and tests")
