# C-line parser environment freeze — 2026-10-19

The C-line research adapter advanced to **0.3.10** to bind parser identity into the model digest. The model pins Tree-sitter runtime `0.26.0`, the `tree-sitter-cpp` grammar package `0.23.4`, and C++ grammar ABI `14`. If the observed environment differs, analysis returns `not_analyzed` with `parser_environment_mismatch` before parsing source. The public Runner remains blocked and disabled.

The exact model SHA-256 is `c8ad85c8eb55ee3d83d44266c259b36a2d38ea56997178ad7395073ab5b1eec4`; the algorithm freeze SHA-256 is `f9b6da07aa69ea78ffc7ab89272accedec53d8db782a2f206a253cb1563b8bf9`. The normative AST contract and freeze verifier confirm those values and the nine required regressions. The new parser-drift control raises the focused suite from 37 to **38 passing tests**.

After the freeze, the blind applicability packet was rebuilt from official `openharmony/arkcompiler_ets_frontend` commit `fadba67b0bdf625d30d69e0940e26c52992669df`, tree `cae995ac693e849ac9d71bb38ec961da58aaeadb`, using the pinned parser environment. The generator reports 21 samples from 21 distinct translation units, all parse-complete, with `detector_invoked=false`. Packet integrity and freeze checks pass; labels remain blank (0/21). Coverage remains 21/99 complete translation units and 21/2,293 complete-file function definitions; this clustered applicability frame cannot estimate semantic recall or component-wide precision/recall.

The parser package versions and grammar ABI are frozen; a native parser binary digest is not separately recorded. Historical parent/fix translation units remain partial and lack matching compiler preprocessing/build profiles. The current a65 product build still proves only one ARM32 compile target, its compiler AST, macro dump, and 512-file dependency closure; it does not prove Ark VM species behavior. No `ark_js_vm` executable, ARM emulator, or HDC/ADB tool is available in this environment. Entry point, attacker control, reachable sensitive operation, and CIA impact remain unknown. No product vulnerability conclusion follows from this parser freeze.

Reproduction:

```text
python -m unittest research.tests.test_ark_runtime_type_safety_freeze research.tests.test_ark_runtime_type_safety_binding research.tests.test_ark_runtime_current_partial_replay research.tests.test_ark_runtime_exception_guard research.tests.test_ark_runtime_build_source_binding -v
python research/deliveries/cpp/verify_ark_runtime_ast_subset_contract.py
python research/experiments/ark_runtime/c1_product_gn_20261019/verify_profile_artifacts.py
```
