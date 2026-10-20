# B 线八仓规则级覆盖审计

日期：2026-10-19。检测器 `ohscanner.interface.ipc 0.12.12`，模型 `oh-ipc-2026.10-v32`。固定八仓回归包 manifest SHA-256：`d7f903f94a42d9681b804e63c594e223070a2966ac6fb6ac339c368b3eaa25d9`。

## 结果边界

- 八仓共 6,407 个源码文件；C/C++ applicable 文件 6,035 个。全局解析 complete 4,341 / partial 1,694 / not_run 372；complete 占可分析 C/C++ 文件 71.9%。这是 detector 级解析口径，不是每条规则的适用/执行率。
- 19 条已注册 rule 中，八仓命中 3 条、零候选 16 条；总诊断 30。零候选不能解释为风险低或规则覆盖充分。
- 家族 fixture matrix 定向测试：`python -m unittest discover -s tests -p test_ipc_family_matrix.py -q` → **13 tests OK**。所有 fixture 来自 `tests/fixtures/ipc/**/manifest.json`，标为设计控制，不是独立 holdout。
- fixture manifest 使用 `control_rules` 精确绑定 fixed/safe 负例；测试器验证 rule 归属，并确认负例不产生被测 rule。未映射项只算 family-level controls，不能算逐规则负例。
- Scanner 报告未提供每条 rule 的 applicable files、支持语法比例或被跳过原因。当前这些值明确列为 `not instrumented`，不能用 detector 全局解析比例冒充逐规则覆盖。

## 规则矩阵

| Rule | Family | 八仓候选 | 锚点 complete/partial | 正例 / fixed / safe 精确映射 | Family 正例 / fixed / safe | 规则级覆盖结论 |
|---|---|---:|---:|---:|---:|---|
| `ipc.auth.caller-class` | AUTH-03 | 0 | 0/0 | 1 / 1 / 1 | 6 / 6 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.auth.denial-transport-success` | AUTH-07 | 0 | 0/0 | 1 / 1 / 1 | 1 / 1 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.auth.flow` | AUTH-05 | 0 | 0/0 | 1 / 1 / 1 | 1 / 1 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.auth.guard-coverage` | AUTH-04 | 0 | 0/0 | 5 / 2 / 2 | 5 / 2 / 2 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.auth.identity-domain` | AUTH-03 | 0 | 0/0 | 1 / 1 / 0 | 6 / 6 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.auth.missing` | AUTH-02 | 12 | 12/0 | 17 / 4 / 3 | 17 / 4 / 3 | 命中；仍是候选 |
| `ipc.auth.object-owner` | AUTH-03 | 0 | 0/0 | 1 / 1 / 0 | 6 / 6 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.auth.request-identity` | AUTH-03 | 0 | 0/0 | 1 / 1 / 0 | 6 / 6 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.auth.service-identity` | AUTH-03 | 0 | 0/0 | 2 / 1 / 0 | 6 / 6 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.capability.export` | CAP-01 | 11 | 11/0 | 10 / 4 / 2 | 10 / 4 / 2 | 命中；仍是候选 |
| `ipc.data.sensitive-flow` | DATA-04 | 0 | 0/0 | 1 / 1 / 1 | 1 / 1 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.network.auth-session-whitelist` | AUTH-06 | 0 | 0/0 | 1 / 1 / 1 | 1 / 1 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.parcel.bounds` | DATA-02 | 0 | 0/0 | 1 / 1 / 1 | 2 / 2 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.parcel.copy-range` | DATA-01 | 0 | 0/0 | 2 / 1 / 0 | 3 / 2 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.parcel.lifecycle` | DATA-03 | 0 | 0/0 | 1 / 1 / 1 | 1 / 1 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.parcel.position-underflow` | DATA-01 | 0 | 0/0 | 1 / 1 / 1 | 3 / 2 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.parcel.write-bounds` | DATA-02 | 0 | 0/0 | 1 / 1 / 0 | 2 / 2 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |
| `ipc.relay.descriptor-boundary` | AUTH-01 | 7 | 5/2 | 17 / 6 / 1 | 17 / 6 / 1 | 命中；仍是候选 |
| `ipc.tlv.fixed-width-length` | DATA-05 | 0 | 0/0 | 1 / 1 / 1 | 1 / 1 / 1 | 精确 positive + negative 控制齐备；真实仓零候选仍 unknown |

## 下一步的覆盖契约

1. 继续为多规则 family 中尚未映射的 fixed/safe fixtures 补显式 `control_rules`；当前已确保每条规则至少有一个正例和一个精确负例，新增映射前仍需按具体语义复核。
2. Detector 执行结果按 rule 记录：适用文件数、进入规则评估的文件数、complete/partial/not-run、结构不支持/预算截断/语法失败原因，以及候选数。规则只有在适用范围和评估完成度可量化时才能把 0 候选展示为“已评估无命中”；否则显示“无候选，覆盖未知”。
3. 对每条规则展示 exact positive/fixed/safe 控制数和最近验证状态。任何一种控制缺失时单列缺口，不自动扩大结论。fixture 改动需继续作为设计集，不可称 holdout。
4. 对上述 16 条零候选规则，从未参与开发的组件构建 root-cause-split holdout；现有 controls 只能证明固定测试程序的预期行为。

## 重现与文件

- 每条规则、测试计数、候选锚点解析状态：`rule_coverage.csv`。
- 固定来源、总体解析口径、fixture 计数和免责声明：`manifest.json`。
- 固定八仓逐项报告：`../20261019-eight-component-member-pointer-normalization-v0.12.12/`。
- 逐条固定候选证据：`../20261019-eight-component-candidate-triage-v0.12.12/candidate_triage.csv`。
