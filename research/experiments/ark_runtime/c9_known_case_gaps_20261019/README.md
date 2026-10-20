# C9-KNOWN-CASE-GAPS slice

Date: 2026-10-19 (Asia/Shanghai). Worktree is detached at `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`, tree `307ac8237263db793028e0bf34a82a85f60821a5`, remote `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`. The permitted pinned case source is `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`, Git blob `dbedeaa677c8dc70c1b0066c7bc52df27bcff06ea`, SHA-256 `58F37A6DFE3A518DA07C813195F47E1CB3CBD7E0825B02D28CB6B3E5D0F240EA`.

## Outcome

- `IAO7GO` is no longer silent 0-applicable. The semantic selector admits `native_inline_lowering.cpp`-shaped Reflect.apply lowering functions. The strict adapter emits a conservative abrupt-exception-propagation candidate only when an effect result reaches `Return` without a dominating pending-exception guard. The catalog/unseen path emits explicit `unknown` plus `IAO7GO:candidate_rule_routing_requires_strict_adapter` because its rule router is outside this slice's write scope.
- `I7W51D` and `IB8BCA` are explicitly auditable no-rule cases. Parent and fixed controls stay `partial/blocked` with distinct limitations; no RangeError or boundary repair is presented as a security/product vulnerability.
- Existing size-product positive/fixed/safe/unrelated controls remain positive/no-candidate/no-candidate/not-applicable. No public contracts, Runner, Catalog, research/evidence/ark_runtime/c9_integration_20261019, or pinned report were modified.

## Known-case matrix

| Case | Fixture | Selector | Result | Boundary |
|---|---|---|---|---|
| IAO7GO | `C9_IAO7GO_parent.cpp` | applicable | strict candidate; catalog unknown/limitation | abrupt completion before `Return` |
| IAO7GO | `C9_IAO7GO_fixed.cpp` | applicable | no same-root candidate | `RETURN_VALUE_IF_ABRUPT_COMPLETION` |
| IAO7GO | `C9_IAO7GO_safe.cpp` | applicable | no same-root candidate | `HasPendingException` guard |
| I7W51D | `C9_I7W51D_parent.cpp` | applicable | unknown + signed-int32 limitation | no security rule |
| I7W51D | `C9_I7W51D_fixed.cpp` | applicable | unknown + distinct boundary limitation | RangeError/boundary repair is not security |
| IB8BCA | `C9_IB8BCA_parent.cpp` | applicable | unknown + index-width/bounds limitation | no security rule |
| IB8BCA | `C9_IB8BCA_fixed.cpp` | applicable | unknown + distinct boundary limitation | boundary repair is not security |
| unrelated | `C9_unrelated.cpp` | not applicable | no finding | RangeError-only control |

Every fixture is source-bound by SHA-256 in `manifest.json`; these are synthetic controls, not claims of exact upstream parent/fixed blobs. The next slice must bind the real upstream commits/blobs before any product or CVE conclusion.

## Verification

Accepted focused gate (57 executed tests passed; 2 environment-dependent tests skipped and not counted as passes):

```text
wsl.exe -d Ubuntu-22.04 -- bash -lc 'cd "/mnt/e/网安/CyberSecurity-Innovation-Audit-c-line-latest-20261019" && python3 -m unittest tests.detectors.ark_runtime.test_known_case_gaps tests.detectors.ark_runtime.test_size_overflow tests.detectors.ark_runtime.test_runtime_exception tests.detectors.ark_runtime.test_detector_cases tests.detectors.ark_runtime.test_unseen_detector -v'
```

The new known-case gate is 7 tests, 7 passed, 0 skipped. CLI smoke passed for `python3 -m src.cli --help` and `python3 -m src.cli ohscan-run --help`. `git diff --check` passed. Exact argv and output paths are in `manifest.json`, `focused_tests.txt`, `cli_help.txt`, and `ohscan_run_help.txt`.

A broader `unittest discover -s tests/detectors/ark_runtime` run is not accepted as green in this checkout: 6 C3 mechanism failures and 1 dependency-manifest error were observed. No C3 source was changed in this slice; those baseline/toolchain failures remain a separate limitation.

## Limitations and next slice

1. The strict candidate is local syntax/IR evidence only. It does not prove generated CFG dominance, macro expansion, attacker reachability, product build binding, CIA impact, or exploitability.
2. `I7W51D`/`IB8BCA` have no security rule because the pinned evidence only supports length/index boundary behavior and a RangeError expectation. Adding a CWE/security rule without a concrete OOB or CIA witness would be unsupported.
3. Catalog/unseen rule routing for `ABRUPT_EXCEPTION_RULE_ID` needs a platform-owned change outside this write scope; until then it remains an explicit unknown limitation rather than a silently omitted file.
4. Bind exact upstream source commits/tree/blob/source hashes and the real product build/preprocessing profile, then rerun parent/fixed/safe/unrelated controls. Only after an isolated authorized dynamic witness should impact or fix status be upgraded.

Patch: `patch.diff`, SHA-256 `BD476FAE9052A74D0B05638A931DF017BE34423EE6153287A90BFA11E6CC27BB`. Hashes, exact argv, dirty-file snapshot, and the full matrix are in `manifest.json`.

