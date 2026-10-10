# `ohscanner.cpp.shared_ptr_race` 独立 Holdout 设计

## 0. 状态与边界

- 状态：`designed_not_executed`
- 适用 detector：`ohscanner.cpp.shared_ptr_race`
- 当前事实：仓库内只有 self-authored synthetic development fixtures 和开发期间已经看过的
  `commonlibrary_c_utils` vulnerable/fixed pair，**没有真正独立、未参与规则开发和调参的 holdout 数据**。
- 本文件只定义外部数据准入、manifest 接口、独立性流程和统计边界；不生成新的 synthetic
  样本，不把现有 fixtures 改称 holdout，也不声称 holdout 已执行。
- 当前 `tests/detectors/fixtures/cpp_shared_ptr_race/**` 全部属于 development fixtures。
  本文出现的 schema 和接口不是样本清单。

在取得并封存外部数据前，禁止填写 `prediction_sha256` 或 `label_release_sha256`，
禁止输出命中率、Precision、Recall、FPR/FNR、准确率或“零误报/零漏报”等结论。

## 1. 独立性准入

候选 vulnerable/fixed pair 必须同时满足：

1. repository、exact commit、repository-relative path、source SHA-256、snapshot SHA-256、
   analysis profile、detector/tool version 可固定并复核；
2. pair 的两个 revision 必须绑定同一 repository/path/profile/tool version，但 commit 不同；
3. vulnerable/fixed 来自真实历史修复关系或其他有书面依据的配对关系，不靠 detector 输出配对；
4. pair、source bytes、patch、issue、报告或标签未参与 detector 规则开发、阈值选择、
   词法切片调整或误候选修复；
5. 选择记录和排除审计在 detector freeze 前完成并保存 SHA-256；
6. detector 开发者在 prediction hash 封存前看不到 label、证据组、修复说明或预期观察。

明确排除：

- `tests/detectors/fixtures/cpp_shared_ptr_race/**` 的全部 synthetic fixtures；
- fixture provenance `synthetic/fixture`；
- 开发时使用过的 `openharmony/commonlibrary_c_utils` commits
  `bdfafdaafddb01ab7ae13354ce2ada9555d7935c` 和
  `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7`；
- 任何用于修改 detector、rule、method card 或 limitations 的源码、patch、issue 讨论、
  sanitizer 日志和人工判断材料。

如果无法证明排除条件，该候选只能留在 development corpus，不能进入 holdout。

## 2. 最小组成

一个可执行 holdout 至少包含以下 13 个 analysis cases。case 数可增加，但不得删除或
用 development fixture 替换。

| 设计 stratum | 数量 | 揭晓后的 evidence group | 目的 |
|---|---:|---|---|
| `pair_slot_a` | 1 | `vulnerable` | 真实历史 vulnerable/fixed pair 的一侧 |
| `pair_slot_b` | 1 | `fixed` | 同 repository/path/profile/tool 的修复 revision |
| `similar_safe_control` | 1 | `safe` | 与目标 shape 相似但有明确安全语义/边界的对照 |
| `unrelated_shared_ptr` | 1 | `unrelated` | 同样使用 shared_ptr 但根因/分析单元无关 |
| `local_shared_ptr` | 1 | `unrelated` | 局部 shared_ptr，不属于目标成员生命周期 |
| `same_name_different_class` | 1 | `unrelated` | 同名成员/函数但属于不同类或模板 |
| `atomic_helper` | 1 | `safe` | helper 或 wrapper 中通过 atomic API 访问 |
| `mutex_wrapper` | 1 | `safe` | 目标访问被 mutex wrapper/scope 保护 |
| `initialized_readonly` | 1 | `safe` | 初始化完成后只读 |
| `analysis_partial` | 1 | `unknown` | 只有 partial analysis 的边界单元 |
| `analysis_failed` | 1 | `unknown` | analysis/parse failed 的边界单元 |
| `analysis_not_run` | 1 | `unknown` | 尚未执行的边界单元 |
| `incompatible_unit` | 1 | `not_applicable` | 有证据证明分析单元不适用 |

要求：

- vulnerable/fixed 两侧数量严格相等，但统计时仍作为两个独立 revision 单元；
- safe、unrelated、unknown、not_applicable 分别保留独立 evidence bundle；
- 不得为了“提高结果”增加、删除、改写或重新解释 case；
- 非 C/C++ 单元只有在 detector contract 明确不支持该 analysis unit 时才能标记
  `not_applicable`，并绑定 incompatibility proof。

## 3. 外部 manifest 绑定

外部 JSON manifest 不提交第三方 source bytes。每个 case 至少包含：

```json
{
  "case_id": "opaque-id",
  "stratum": "one-predeclared-stratum",
  "pair_id": "external-pair-id-or-null",
  "repository": "owner/repository",
  "commit": "full-lowercase-git-sha",
  "path": "canonical/repository/relative/path.cpp",
  "source_sha256": "sha256-of-exact-source-bytes",
  "snapshot_sha256": "sha256-of-pinned-source-snapshot",
  "profile_id": "light-ast",
  "tool_id": "ohscanner.cpp.shared_ptr_race",
  "tool_version": "exact-frozen-detector-version",
  "development_participation": "not_participated",
  "label_visibility": "sealed_from_detector"
}
```

所有字段均为一等绑定，不允许只写 URL、分支名、tag、目录或“latest”：

- repository 必须是 owner/repository 形式；
- commit 必须是完整 40 或 64 位 lowercase SHA，不接受 abbreviated SHA；
- path 必须是 canonical POSIX repository-relative path，拒绝绝对路径、`..`、反斜杠；
- source hash 和 snapshot hash 必须是 lowercase SHA-256；
- profile 必须精确记录 AST/coverage/build profile；
- tool ID/version 必须与 detector freeze 一致；
- pair 两侧必须是同一 repository/path/profile/tool version，commit 必须不同；
- 同一 case 的 raw run、prediction、label 和 evidence record 必须复用同一组绑定。

manifest 顶层还必须记录：

```json
{
  "schema_version": 1,
  "holdout_id": "safe-opaque-id",
  "status": "designed_not_executed",
  "detector_freeze": {
    "detector_id": "ohscanner.cpp.shared_ptr_race",
    "detector_version": "exact-version",
    "detector_sha256": "...",
    "rule_sha256": "...",
    "method_sha256": "...",
    "frozen_at_utc": "ISO-8601 UTC"
  },
  "independence": {
    "development_fixtures_reused": false,
    "labels_visible_during_prediction": false,
    "label_adjustment_after_prediction": false,
    "selection_record_sha256": "...",
    "exclusion_audit_sha256": "..."
  },
  "prediction_sha256": null,
  "label_release_sha256": null
}
```

`designed_not_executed` 状态下 prediction/label hash 必须为 null；不允许先写占位 hash
再补结果。

## 4. Analysis status 边界

| raw status | 允许的 raw observation | 解释 |
|---|---|---|
| `complete` + candidate shape | `possible_hit` | 只是未确认候选，不是漏洞 |
| `complete` + no candidate shape | `no_observed_candidate_shape` | 当前窄规则无 shape，不是 safe verdict |
| `partial` | `unknown_incomplete_analysis` | 未覆盖内容保持 unknown |
| `failed` | `unknown_incomplete_analysis` | 失败不是 miss |
| `not_run` | `unknown_incomplete_analysis` | 未执行 scanner/detector 不是 miss |
| `not_applicable` + proof | `not_applicable` | 仅限明确不兼容分析单元 |

`not_applicable` 必须绑定：

```json
{
  "incompatibility": {
    "kind": "unsupported_language | incompatible_analysis_unit | outside_detector_contract",
    "proof_sha256": "sha256-of-explicit-incompatibility-evidence"
  }
}
```

禁止把 missing source、parse failure、timeout、not_run、未执行 scanner、缺失 symbol、
覆盖不足或 detector 无输出标记为 `not_applicable` 或 `miss`。

## 5. Detector freeze 到 label reveal

执行流程必须保持以下顺序：

1. **Eligibility and exclusion audit**
   外部数据管理员选择 pair 和 controls，记录为什么未参与开发；保存 selection record 与
   exclusion audit 的 SHA-256。此时 detector 开发者仍看不到 labels。
2. **Detector freeze**
   冻结 detector code、rule、method、parser/profile、依赖和 limitations。保存
   detector/rule/method SHA-256 与 UTC 时间。冻结后不得修改；任何修改都创建新版本和新 holdout。
3. **Unlabeled prediction**
   使用 opaque case ID 和 source bindings 执行 detector。prediction 只允许 raw
   observation、analysis status、diagnostic count、run status 和 source binding，
   不允许包含 label、evidence group、ground truth 或 expected observation。
4. **Prediction hash**
   对 canonical JSON 计算 SHA-256，保存 hash、命令、tool version、开始/结束时间和原始
   output artifact hash。该 hash 必须在 label release 前由独立数据管理员确认。
5. **Label reveal**
   数据管理员在 prediction hash 封存后发布 label release。label release 绑定同一
   prediction SHA-256，不得据 prediction 修改标签、case 范围或 evidence group。
6. **Evidence normalization**
   将 prediction 与 labels 按 exact binding 合并。vulnerable、fixed、safe、unrelated、
   unknown、not_applicable 分 bundle 保存；禁止混用不同 revision、不同 source artifact
   或不同 tool run。
7. **Raw-count reporting**
   只输出 raw observation/category counts、analysis-status counts、stratum counts 和
   unknown/not-applicable 边界说明。不得根据本小语料计算或宣称正式 Precision/Recall。

若 reveal 后发现数据错误，应保留原 prediction hash 和原始报告，另开 erratum；
不得静默重跑、替换样本或改标签后覆盖结果。

## 6. 可执行外部接口

接口实现：`E:\网安\CyberSecurity-Innovation-Audit\src\ohscanner\holdout_manifest.py`。

校验设计 manifest：

```text
python -m src.ohscanner.holdout_manifest validate-design HOLDOUT.json
```

校验外部 source bytes 与 exact commit。每个 pinned commit 必须提供一个独立 checkout：

```text
python -m src.ohscanner.holdout_manifest verify-sources HOLDOUT.json \
  --source-root COMMIT_1=/path/to/checkout-1 \
  --source-root COMMIT_2=/path/to/checkout-2
```

冻结后生成 unlabeled prediction hash：

```text
python -m src.ohscanner.holdout_manifest hash-prediction HOLDOUT.json PREDICTIONS.json
```

label reveal 后校验标签、prediction hash 和 evidence bundles：

```text
python -m src.ohscanner.holdout_manifest validate-label-release \
  HOLDOUT.json LABEL_RELEASE.json
```

接口拒绝：

- 缺少 repository/commit/path/source hash/snapshot/profile/tool version；
- development fixture 或 development participation；
- prediction 阶段出现 label/evidence-group 字段；
- partial/failed/not_run 被写成 hit/miss；
- 无 incompatibility proof 的 `not_applicable`；
- 同一 evidence bundle 混用
  `vulnerable/fixed/safe/unrelated/unknown/not_applicable` 证据组。

整体 holdout 可以同时包含多个 evidence group，但每个 bundle 只能有一个 group。
“不混用”针对 evidence record/run/package，不表示把 safe/unrelated controls 从 holdout 删除。

## 7. 允许的报告字段

允许：

- case/stratum/analysis-status raw counts；
- `possible_hit`、`no_observed_candidate_shape`、
  `unknown_incomplete_analysis`、`not_applicable` counts；
- 每组 source/tool/run/prediction/label artifact hashes；
- known limitations 和 coverage；
- vulnerable/fixed pair 的逐 revision raw observations。

禁止：

- 将 `possible_hit` 写成 confirmed vulnerability；
- 将 `no_observed_candidate_shape` 写成 safe、true negative 或 fixed proof；
- 将 `unknown`、`failed`、`not_run` 写成 miss；
- 计算或宣称正式 Precision、Recall、F1、FPR、FNR、准确率；
- 宣称 zero false positives/negatives；
- 根据 detector 输出反向修改 holdout labels 或组成。

## 8. 完成判据

只有同时满足以下条件，状态才可从 `designed_not_executed` 变更：

- [ ] 外部 pair/controls 已收集，且排除审计通过；
- [ ] detector/rule/method 已冻结并 hash；
- [ ] unlabeled predictions 已运行；
- [ ] prediction canonical SHA-256 已封存；
- [ ] 独立数据管理员已 release labels；
- [ ] source/revision/profile/tool bindings 已逐项复核；
- [ ] mixed-evidence regression 通过；
- [ ] raw-count 报告已生成；
- [ ] 未计算 Precision/Recall，也未升级 candidate 为 vulnerability。

当前结论：**接口和方法已经设计，但没有真正独立数据，故状态保持
`designed_not_executed`。**
