# A-EXP-01 R0/R1/R2 实验冻结与执行前门禁报告

状态：`frozen_pre_experiment`；结构 preflight 通过，执行门仍为 `blocked`。
本包没有模型调用、R0/R1/R2 运行、实验结果或 Precision/Recall。

## 已冻结且未改写
- 数据集：45 个 review item（11 plausible_unproven + 34 holdout）/ 45 个 scope occurrence /
  44 个唯一 workbench candidate。跨 scope 重复 candidate 两条记录都保留。
- 目标身份：五个固定组件的 repository/commit/git_tree/scope manifest/plan SHA。
- Detector：`ohscanner.cpp.shared_ptr_race` / `0.4.0` /
  `ohcpp-shared-ptr-race-candidate-001` / `light-ast`。
- Prompt、candidate、truth、review、历史诊断 ID、报告字节和 review 记录没有重写。

## 执行前门禁
- `model_binding.schema.json` 与 `model_binding.template.json` 完整定义 provider、model、
  exact version、API version/endpoint、data-processing、pricing 和 approval；
  当前记录仍是 `unbound_execution_blocked`，所以 R1/R2 blocked。
- `tool_adapter_authorization.schema.json` 与 `tool_adapter_authorization.json` 记录
  adapter 版本/实现 hash、授权人、范围、4 项工具白名单和只读边界。
  当前 `execution_authorized=false`，所以 R2 blocked；缺记录或越界同样 fail closed。
- `statistical_unit_contract.json` 固定 45/45/44 口径和已知跨 scope overlap。
- `canonical_input_bundle.schema.json`、`canonical.js` 和固定 test vectors 定义
  `input_bundle_sha256` 的 canonical byte serialization。
- `evidence_reference_contract.json` 与 `preflight_validator.js` 对 claim 引用做
  catalog/item/persisted-tool-result/denylist 成员校验；非法引用使 completed run 失败，
  或让非 completed 输出保持 unknown。
- `retry_accounting_contract.json` 固定 retry 的独立 attempt ID、预算影响和 append-only 规则。

## 统计与预算
- 每组 45 × 3 = 135 planned run；同时报告 45 review item 和 44 unique candidate。
- R2 每 run 最多 8 次工具调用、64 KiB 输出、300 秒 wall、1 次 retry。
- retry 占工具调用、实际 token/费用、wall 和输出/源码字节；不占新 repetition；
  不重置预算/seed/input bundle；首次失败与最终结果都保留。
- 不计算 Precision/Recall，不把 synthetic controls 当独立 holdout。

## 可执行入口
- `node preflight_validator.js --check`
- `node preflight_validator.js --require-ready`（当前应 exit 1，因为执行未授权）
- `node preflight_validator.js --validate-run <run.json>`
- `node preflight_validator.js --hash-bundle <bundle.json>`
- `node --test preflight_tests.js`
- `node verify_freeze.js`
