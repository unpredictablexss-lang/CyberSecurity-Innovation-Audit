# Ark Runtime 0.7.0 pinned-artifact gap matrix

日期：2026-10-19（Asia/Shanghai）。
审查对象：`origin/codex/c-line-ark-runtime-replay-20261019` @ `a7962043cda3cbb99f79ada7418508709fc951ca`，tree `684c42e94c4797640113f0f2ffeca5a0c988a136`。
本地 base：`7af25f5ced471e5d6acc8cf5efd4c696275ce940`，tree `11f53fe00d79d477c383e7e9b49ad3b1adcae86c`。
本轮只用 `git show`/`git ls-tree`/`git cat-file` 审查 pinned objects；没有 fetch、checkout、reset、push，也没有覆盖远端 holdout packet。

## 结论

远端两个 packet 的可见内容满足“输出盲化 + 标签空白 + 禁用指标”的基本要求，但不满足 Ark Runtime 0.7.0 rule freeze 的版本、范围、实现自洽、profile/resource limit 和独立 truth 要求。当前 `eligible_for_metrics=false`，不得发布 Precision/Recall、零 FP/FN、产品 CIA/CVE 或 confirmed 结论。

## 差异矩阵

| 检查项 | 要求 | pinned artifacts 实况 | 判定 |
|---|---|---|---|
| pinned identity | full commit/tree/blob/source hash 可追溯 | ref、tree、各文件 blob/SHA-256 已固定 | pass |
| 两份 packet 存在 | runtime-core 与 ets-frontend 均有 manifest/packet/labels/prepare 脚本 | 均存在且 source SHA-256 与 packet source 文件一致 | pass |
| 可见记录盲化 | packet/manifest 不含 detector prediction、truth、expected label | 两个 packet 的可见样本记录均未发现这些键 | pass |
| 标签初始状态 | reviewer label cells 全空 | runtime-core 20/20、ets-frontend 21/21 标签字段为空 | pass |
| 指标禁用 | 无独立 truth 时不计算指标 | packet 明示不可推导 component Precision/Recall；本次矩阵强制 `eligible_for_metrics=false` | pass |
| rule version | 0.7.0 | `C_LINE_FREEZE_OBSERVED_20261019.json` 为 0.3.2 | gap |
| rule scope | type-origin + exception-guard 两规则 | 仅冻结 `ark.runtime.typedarray-store-type-origin` | gap |
| 实现哈希自洽 | freeze 中每个 implementation SHA-256 与 pinned path bytes 相同 | 6 项中仅 `runtime_ir.py`、`syntax.py` 匹配；`analysis.py`、`detector.py`、`model.py`、`type_origin.py` 不匹配 | gap |
| freeze digest 绑定 | packet 引用值可解析到 freeze manifest | packet 引用 `0b8b08...8291`；实际 manifest bytes SHA-256 为 `852d40...5cae` | gap |
| 0.7.0 source binding | 绑定 base 中 8 个 Ark source files | reviewed ref 不含 `src/ohscanner/detectors/ark_runtime/` | gap |
| profile/limits | 固定 build profile 与 AnalysisBudget | remote freeze 未给出 0.7.0 profile/limits | gap |
| 独立 holdout | 开发者/作者不是 truth authority，样本在 freeze 后未被调参 | runtime-core 明示 developer inspected before freeze、`counts_as_independent_holdout=false`；frontend 是 applicability/false-match frame | gap |
| reviewer schema | identity/confidence、active/paused timing、分歧与裁决 | 现有 CSV 均缺这些字段 | gap |
| coverage/performance | coverage/partial/unknown + wall/RSS/Token/cost | `coverage_ledger_20261019.json` 的 `lane=A_CPP` 且无 wall/RSS/Token/cost 字段 | gap |
| 历史对象完整性 | commit/tree/blob/source 可在本地 pinned store 解析 | 两个 target blobs 可用；相关 commits/trees/creator blob 缺失 | partial |

## 关键 hash 绑定

- `research/deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json`：blob `c2f3b5a582fb2ad23c1fd8af36049eec1b534535`，SHA-256 `852d403e158816ee2a9f29ac00e925f53c3d33064f929dd56ec4259c5d205cae`。
- runtime-core `blind_manifest.json`：blob `253e39b4e74344cb5ff46699f0b3d4d7913987c5`，SHA-256 `1a7c56a9d5f354391e4fcf400e53f1275732ee3ab043ded1d57b0bbd3a684557`。
- ets-frontend `blind_manifest.json`：见机器矩阵中的 `packets[].artifacts`，source SHA-256 为 `b9809fd39fe3f3b058e19008f51968b3d6f5ba56a0ed3203d4f08e7104f36847`。
- 0.7.0 当前 model digest：`d2b7e4664c228db8afcadbc81d5fd6a403abe853eb437ac883199801b5521e00`。
- 0.7.0 当前 build profile：`assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;not_product_build_verified`。
- 0.7.0 当前资源限制：1,048,576 source bytes、4,096 instructions、128 scope depth、2,048 states、8,192 steps、5.0 seconds。

## 性能与验证

完整 exact argv/env、wall、Windows working-set RSS、stdout/stderr hash 见 `research/experiments/ark_runtime/c8_holdout_20261019/verification_20261019.json`。

- pinned-artifact review：exit 0。
- Ark Runtime unittest：116 tests、8 skipped、0 failed；这是一次实际本地复跑，不沿用 sibling 文本结论。
- compileall：exit 0；因绝对 `PYTHONPYCACHEPREFIX` 在非 ASCII checkout 触发 WinError 206，最终对 223 个 byte-identical `.py` 副本运行 `compileall -b -j 1`，副本 manifest 固定源/目标 SHA-256。
- docs context budget：exit 1，唯一问题是 `status archive bytes do not match archive_sha256`；不是 Ark 算法失败，且本线不得改 docs/历史 archive。
- Token/费用未测；本地子进程不提供可靠 meter，保持 unknown，不用工作量替代。

## Evidence gate

- 新增内容均为 review/freeze requirement/verification 证据，不是 Detector verdict。
- 所有 scanner 语义保持 `candidate/unassessed`，`validated_vulnerability=0`。
- partial、缺对象、blank labels、budget failure 均不是 safe/miss。
