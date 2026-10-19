# C7-REPLAY 历史对象审计与 replay 结果

日期：2026-10-19（Asia/Shanghai）

## 已执行事实

- 固定基线 `b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df` 已从本地 Git object 解包到 `_work/baseline/`，未 checkout、fetch 或修改上游对象库。
- Ark store `E:/网安/_oh_targets/arkcompiler_ets_runtime` 为 `blob:none` partial clone。`GIT_NO_LAZY_FETCH=1` 下确认四个历史 commit/tree 与路径 blob OID 链，但所有所需 blob 字节均不可本地读取，因此 source SHA 无法核验。
- `a65a2853ccae13da167d9aa4720ab8b11ec16656` 与 `a65a2853^` 未能解析；safe/unrelated 只保留控制角色和 fail-closed 缺口，不写 safe/miss。
- 历史测试实际执行 6 项：1 passed、4 errors、1 skipped；skip 原因是 bound commit parent 缺失。`test_exception_guard` 12 项中 10 passed、2 historical errors。C2/C3 replay 均因 `054451b1...` blob 缺失而 fail-closed。
- 本地合成控制通过：`test_detector_cases` 12/12、`test_c3_mechanisms` 29/29、`test_type_origin` 20/20、`test_ir_path` 13/13。`test_parser_owner` 7 passed、1 个源文件错误。合成控制不替代历史对象证据。

## 结论

所有历史候选仍 `candidate/unassessed`，`validated_vulnerability=0`。partial、failed、skipped、unknown 均不写 safe、miss、zero FP 或 zero FN。产品入口、权限、触发、CIA、产品构建和 CVE 映射仍未闭合。

## 可复现命令

```powershell
Set-Location 'E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ark_runtime\c7_historical_replay_20261019'
$env:OHSCANNER_ARK_REPO = 'E:\网安\_oh_targets\arkcompiler_ets_runtime'
$env:OHSCANNER_PYDEPS = 'E:\网安\_runtime\ohscanner-pydeps'
$env:GIT_NO_LAZY_FETCH = '1'
$env:GIT_ALLOW_PROTOCOL = ''
python _work\extract_baseline.py _work\baseline_b011.zip _work\baseline
python _work\run_c7_replay.py
```

随后可在 `_work/baseline/` 内运行 `tests.detectors.ark_runtime.*` 与 C2/C3 `replay.py`。完整命令、exit code 和日志见 `replay_results.json` 与 `_work/*.stderr.txt`。

## 交付文件

`object_inventory.json`、`replay_results.json`、`controls_matrix.json`、`next_object_manifest.json` 均为 JSON；本目录只读研究输出，不 commit/push/merge/PR。
