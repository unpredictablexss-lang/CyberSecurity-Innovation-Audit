# D82 — D55 本地 M2 执行准备 blocker matrix

- 状态：**STOP_BEFORE_FRAME_SELECTION_AND_SCAN**；M2 **NOT MET**。本清点没有建立 cohort、生成标签或计算指标。
- 核验 checkout：`D:\openHarmonyScanner\worktrees\d82-local-m2-readiness-20261020`；base commit `c86e0b0321eb38b0ff403e98b8597622c7cd556c`。
- T54 最终验收（reviewed commit `c86e0b0`）：协议设计 `READY_FOR_EXECUTION_PREREQUISITES`；执行 `NOT_READY`；M2 `NOT_MET`。
- D41 状态字段有历史差异：manifest 保留 `preregistered_not_run`，但稍后的 aggregate results / 报告记录了双轮 replay；本清点把 manifest 视为冻结预注册状态、把 results 视为执行事实。仍无标签；6 个仓库、3,820 个 eligible files、201 条候选、0 complete、2,787 partial、1,033 not analyzed、独立标签总数为 0。99-case 包是 post-scan stratified review packet，不能当准确率样本。
- D48 `distributed_screen`：方便样本、97 个文件全部 partial、扫描 blocked、0 candidate、没有独立标签；不能作准确率或安全性样本。
- D55 CVE advisory：17 个 catalog IDs 均有记录；A/B 计 9+8 项，15 份已有响应正文哈希可验证；CVE-2026-33636 和 CVE-2026-46675 的主 GHSA 原始正文仍 blocked。T55 接受报告判 `PARTIAL_NOT_READY`，其后的 B revision 仍判 `NOT_READY`。

## 必须排除的历史材料

| 样本/材料 | 决策 | 原因 |
|---|---|---|
| D41 six-repository replay and 99-case packet | exclude from D55 scoring | scanned post selection; detector 0.17.0; no independent labels; post-scan stratified 99-case packet; protocol explicitly excludes D41 |
| D48 distributed_screen snapshot | exclude from D55 scoring | convenience sample; D48 prior inspected/replayed; blocked scan; all 97 files partial; zero labels; protocol explicitly excludes D48 |
| D49-D50 component/CVE replay records | exclude from D55 scoring | protocol classifies as already reviewed component/CVE replay and rule-development examples; targeted, partial/blocked, not independent probability sample |
| D51-D53 Pasteboard records and T51-T53 acceptance | exclude from D55 scoring | protocol explicitly classifies as targeted candidate/config investigations and development material, not prevalence sample |
| D35-D50 development/regression/fixtures/PoCs/rule-tuning material | exclude overlapping source units from D55 scoring | protocol says any D-visible or tuned item is development data; exact raw blob/content overlap excludes regardless of path/commit; unresolved modified vendor derivative blocks stratum |
| D48_PANEL_SMOKE/d48-d43-positive-control | exclude from D55 scoring | explicit positive-control smoke artifact; scanner-development control rather than independent source sample |

## Blocker matrix

| Gate | 当前状态 | 本地可做 | 需要的授权人/外部输入 |
|---|---|---|---|
| approved_thresholds | blocked | can preserve proposed defaults and verify missing approval | D owner must approve/replace thresholds before frame selection and label access |
| independent_sampling_frame_and_cohort | blocked | can enumerate local Git objects and produce hashes/exclusion candidates; cannot designate an independent inventory or probability frame from scanner-team authored corpus | independent source inventory/custodian plus source-family provenance and eligibility approver |
| prior_use_overlap_and_exclusions | partial_inventory_only | can hash and compare repo/path/blob identities against specified D records and full D history once inventory is supplied | source steward resolves modified vendor derivation and signs unresolved cases before scan |
| reproducible_selection_and_seed | blocked | can implement seeded stratified selector after frame and strata are frozen | independent frame owner supplies frame; seed commitment must be frozen before scan and labels |
| planning_simulation | blocked | can run simulation after approved thresholds, independent frame/cluster distribution, plausible external prevalence/DEFF and label completion inputs are supplied | owner/reviewer approves assumptions; source steward supplies frame inputs |
| scanner_and_scope_freeze | blocked | can compute clean-checkout and component hashes once target evaluation version is designated | D scanner owner freezes exact version; independent verifier signs manifest |
| known_cve_advisory_package | partial_not_ready | can verify all captured bytes, manifest IDs, and append hashes for already captured snapshots | authorized network/source access to capture blocked primary GHSA responses; adjudicator resolves version-scope ambiguities before scoring |
| finding_matcher_and_coverage_aggregation | blocked | can implement and hash versioned matcher/aggregation after source reference and frozen scanner outputs are available | D owner approves claim-level matching rules before labels/unblinding |
| independent_labels_and_adjudication | blocked | can create blinded packets after frozen scan; cannot create human labels | two qualified independent reviewers and independent adjudicator provide frozen, source-bound labels/conflict declarations |
| sealed_prediction_custody | blocked | can hash output package and prepare manifest | independent custodian provides approved immutable access-controlled storage and access log |

## 本地可自助完成的步骤

- 对给定的只读 Git objects、样本清单和 advisory bytes 重算 commit/tree/blob/SHA-256；运行 duplicate-key 严格 JSON 检查。
- 以明确提供的独立 frame 运行 overlap/dedup 审核、可复现分层抽样、功效/区间仿真，并冻结 scanner bundle。
- 生成 blind packet 和评分工具的机械部分；人工评审之前不得生成 labels 或打开预测键。

## 需要人类或外部来源的输入

- D owner 对阈值、抽样设计、冻结 scanner 版本作有记录的批准。
- scanner 团队之外的独立来源清单和有出处的 cohort/frame；D41、D48 与 D 开发语料不满足这一条件。
- 两位互相独立且未参与开发/选样/扫描的 reviewer、一位独立 adjudicator、冲突声明，以及隔离预测键的保管员和获批不可变存储。
- 被网络访问阻断的主 advisory 原始字节和 unresolved version-scope 的权威解释。

## 结论

Do not start holdout scan or label work from repository-local development corpus. First obtain owner-approved thresholds, independent source inventory/custodian and cohort provenance, independent reviewer/adjudicator and custody assignments, exact scanner evaluation bundle, and resolve the still-missing primary advisory captures/scope. Local repo work can prepare auditable mechanics, but cannot convert existing D41/D48/development examples into a valid D55 holdout.

机器可读明细、输入 SHA-256 与每条排除记录见同目录 JSON。脚本可从任意 checkout 复跑：

```powershell
python research/evidence/cpp/d82_d55_local_m2_readiness.py --root . --advisory-a-root ..\d55-cve-advisories-a-20261021 --advisory-b-root ..\d55-cve-advisory-b-20261021
```
