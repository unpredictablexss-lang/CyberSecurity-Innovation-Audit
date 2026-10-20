# Minimal merge gate

目标：三条 Ark Runtime 实现/证据线合流前的最小门。任何一项 fail/unknown 都不得写成整体 pass。

## A. 身份和公共边界

```text
git rev-parse <candidate>
git rev-parse <candidate>^{tree}
git diff --name-status <base> <candidate> -- src/ohscanner/contracts.py src/ohscanner/runner.py src/ohscanner/detectors/catalog.py
```

门：完整 SHA/tree 必须记录；公共 contracts/Runner/Catalog 若有差异，必须是独立提交并有兼容测试。e4e 的 Catalog factory swap 不能与算法提交混合通过。

## B. 最小本地命令组

```text
/usr/bin/python3 -B -m unittest discover -s tests/detectors/ark_runtime -t . -v
/usr/bin/python3 -B -m unittest -v tests.test_contract_v2_source_binding tests.test_ohscanner_contract tests.test_runner_applicability tests.test_ohscanner_m2 tests.test_ohscanner_m2_a_integration
/usr/bin/python3 -B -m unittest -v tests.detectors.test_cpp_runner_integration
/usr/bin/python3 -B -m py_compile <tracked .py>
/usr/bin/python3 -B research/evidence/ark_runtime/c9_integration_20261019/validate_json.py --root <repo> --files-from <tracked_json_files.txt> --output <json_validation.json>
python scripts/check_docs_context_budget.py
git diff --check
```

门：Ark 0 failed；Runner/Catalog/contract 0 failed；py_compile/JSON/docs/diff-check 通过。skip 必须保留原因，不能计 pass。当前 checkout 缺 docs validator，必须恢复到候选 tree 或明确使用独立公共工具提交。

## C. e4e focused/broad 复现

```text
<exact focused Ark argv, to be frozen>
<exact full-suite argv, to be frozen>
```

门：focused Ark 必须从当前结果 152 executed / 6 failed 重新取证；6 个 TypeOrigin failures 必须逐项 fix 或有独立裁决。full suite 必须记录 exact argv/env、collected/executed/passed/failed/skipped、manifest digest，并解释 `ACTUAL_INCLUDE_CLOSURE` 与四实际 unresolved reasons 的差异。跨 Python/Git 环境结果不能互相覆盖。

## D. schema/compatibility

```text
/usr/bin/python3 -B -m unittest -v tests.test_contract_v2_source_binding tests.test_ohscanner_contract
```

门：source-bound v2 source SHA、stable diagnostic identity、legacy v1 read-only、partial/unknown/block 状态不回写。e4e detector `0.6.2`、model `0.8.10` 与 local `0.7.0` 必须形成显式版本映射测试。

## E. fail-closed audit input

```text
/usr/bin/python3 -B research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/reconcile.py
/usr/bin/python3 -B research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/reconcile.py --strict-input
```

门：输入缺失时 default 必须 `blocked_missing_input` 且 imported entries 0；strict 必须非零。remote C-line 原文只能作为 source-bound coverage evidence，除非 canonical input identity 正式绑定，不能提升为 imported entries。

## F. 已知缺口

- `IAO7GO`：compiler NativeInlineLowering exception lowering。
- `I7W51D`：TypedArray length narrowing。
- `IB8BCA`：DataView/Atomics index-width and bounds。

门：缺口必须在 readiness matrix 显式保留；0 applicable/0 diagnostics 不是 pass。进入 product/reportable 前仍需真实入口、权限边界、可达敏感操作、触发条件、具体 CIA 影响和可审计动态证据。

## 最小合流判定

只有 A-F 全部满足，才可把三条线标为 `integration-ready`。当前状态：`blocked_for_three_line_merge`。
