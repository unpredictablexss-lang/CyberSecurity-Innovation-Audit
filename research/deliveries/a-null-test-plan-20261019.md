# A-NULL 独立测试线计划（T，2026-10-19）

## 任务范围与现状

本线独立负责 A-NULL 输入对账、抽样、盲审和验收；不修改 detector。共同状态与交接见 [A-NULL 总计划](a-null-development-test-plan-20261018.md)。cJSON 的真实根因评估另见 [A 线总计划](cpp/a-lane-development-test-plan-20261019.md)。

引用的 A memory-safety 小规模交付是历史 capability regression：5 个既有组件、4,983 文件、33 个候选、22 个词法组；其 unsafe-memory detector 为 0.1.0。4 个适用历史案例 vulnerable possible-hit 为 4/4，fixed 3/4 清零、1/4 residual。这不是 8,994 的全扫描总体、独立盲标集或全产品 Precision/Recall；不得据此代替本线的总体对账和抽样。

当前 9,323 条 unsafe-memory 原始观察与目标 8,994 相差 329；尚未找到目标 run/config。旧版 rule/callee/repo-scale pilot 为 160 条，源码 hash 160/160 匹配、人工复核 0/160；它仅代表 9,323 provisional frame。2026-10-19 已新增按 rule/function shape/repo scale 分层的替代 pilot，仍为 160 条且 0/160 待审，见下文检查点；不可把两份队列合并或相加。T1 已核实 A-UNSAFE `fprintf`/`vfprintf` 的 format 参数位缺陷：0.3.0 在旧扫描 829 个 hash 匹配源码文件上重现基线 8,504 行并得到 217 条候选。开发侧现已将同一范围重放至 0.5.0：基线仍为 8,504/8,504，候选为 456 条，829/829 hash 匹配，825 个 complete、4 个 partial；工件同时绑定 pinned/current detector 与共享 helper 的 source hash。共享实参切分器另在 235 个旧 unsafe-call 候选文件复放 662/662 基线行，当前仍为 662、无差异，235/235 源码 hash 匹配；该子集不能发现没有旧候选文件中的新增项。0.5.0 条件与 raw-string 格式重放为 18/18 观察、11/11 源码 hash，抑制 8 条纯字面量条件分支及 4 条 raw-string 格式候选，保留 6 条宏/动态分支。以上均为开发侧证据，不是 T 验收。T 下一步独立读取冻结工件与源码，复算 0.5.0 的 829 文件输入、候选结果、共享 helper 依赖和格式表达式差异。五组件 4,983 文件/33 候选历史 runner 在当前仓库快照缺失，不可声称已用 0.5.0 重跑；需先恢复或重建可重放入口并按原固定对象复验。25 项 pinned controls 的 T2a source-identities-only 独立 replay 已通过：25/25 源码 hash、origin、逐项 before/after finding 与 coverage 和冻结工件一致；测试执行未读取开发侧 `control_manifest.json`，输出在仓库外新路径。完整源码树及 Python 环境未 attested，因此该验收范围仍标 partial；合成 controls 不外推准确率。未完成 8,994 总体对账和人工盲审前，总体结论继续为 partial/block。

2026-10-19 T0a 重新枚举本机顶层 scan/report 目录下可用的候选 CSV/config：目前仅找到旧版 `openharmony-abcd-full-scan-20261018`（1,417 条 NULL）与 final run `openharmony-abcd-full-scan-20261018-final`（403,360 条 NULL、9,323 条 unsafe-memory）。没有匹配 8,994 或 546,559 的 CSV/config；这是本机产物清单的阴性结果，不能证明该轮扫描从未存在。 本次补查 `openharmony-full-scan-20261017/summary.json`（manifest `openharmony-manifest-fixed.xml`，processed 378/478）只含 lifetime、shared_ptr_race、IPC 三类 detector，不含 NULL 或 unsafe-memory 结果，因此也不能绑定目标总体。

**D4 独立复算记录（2026-10-19）：** 测试线只读原始 `candidate_results.csv` 与其中引用的 104 个 `result.json`，未读取开发构建脚本、开发计划、control manifest 或 blind key。按目标两条规则筛选得到 9,323 行；每行均由 diagnostic_id 在对应 result JSON 中唯一匹配，rule_id、source_sha256 字段、repository 全部一致，重复 ID 为 0。这里核对的是扫描工件间的来源身份字段，不是对全部 9,323 个源码文件重新计算哈希（160 个盲审样本此前单独 160/160 通过源码 hash 核对）。测试线独立按 `(rule_id, exact source_sha256)` 和跨仓库身份复算得到跨仓相同源码簇 0 个、涉及行 0。manifest v2 通过 JSON Schema；四类计数与复算一致：raw 9,323；仓内根因 `null/not_established`；跨仓 0；人工复核 0/160 pending。该子项对 schema、计数和身份字段关联判 **PASS**，整体仍 **PARTIAL**：observed 比 expected 8,994 多 329，frame 明确标 provisional；这项核验不证明漏洞真值，160 条仍需人工盲审。可重放脚本与记录见 `research/evidence/cpp/a_unsafe_memory_review_20261018/v2_independent_audit/`；冻结输入 manifest 为同目录 `sampling_manifest_v2.json`，SHA-256 `6ca2098c7051c08dd3ce4c97cfd8ec98b8850c33463dac63194e03b7e9874132`；原始扫描 CSV/result JSON 仍由固定 full-scan 目录提供。

## 测试线任务树

```text
T0 固定原始 run、源码/规则/profile、稳定行键与抽样种子
├─ T1 找回并验证 8,994 对应输入；不能找回则保留 blocked，不替换总体
├─ T2a 独立复验 25 项 pinned controls（冻结当前工件，隔离初判与开发预期）
├─ T2b 独立核验 NULL controls、源码 hash、覆盖和 before/after
├─ T3 独立盲标真实案例，保留分歧、unknown 与无法验证理由
└─ T4 独立复跑开发线冻结产物，核验四类计数、scope 与证据边界
```

## 当前测试切片与完成门

测试线与开发线同时推进，T 线不等待 D4 schema 才能处理输入对账或 controls：

| 切片 | 任务 | 完成门 |
|---|---|---|
| **T0a** | 追索 8,994 对应原始结果、过滤条件、run signature、scanner/rule/profile、repo manifest 与 checksum；逐行对照已知 9,323 并解释 329 条差异。 | 可复算身份绑定；若缺失，标记 `blocked: target_population_unbound`，9,323 只能作为具名 provisional frame。 |
| **T2a** | 冻结当前 0.6.0 的 25 项 main pinned JSON；用 source-identities-only 模式独立重放，逐项核输入哈希、覆盖、位置和输出。 | 已完成指定范围 replay：25 项逐条与冻结观察值一致，并与旧 0.4.0 快照明确区分。完整源码树/运行环境身份仍未绑定，验收只对所列直接源码及固定 controls 有效。 |
| **T1a/T3a** | 仅在目标总体绑定后锁定规则×函数形状×仓库规模分层、随机种子、纳入概率及行键，再由独立复核者盲标；若先对 9,323 演练，明确标 pilot。 | 当前 160 条仍为 0/160 人工复核；盲标隐藏 rule/message 和开发预期，双审子集、分歧、unknown/not-testable 均留记录。 |
| **T4a** | 收到 D 冻结包后，在独立 checkout 重放并核对 commit、规则版本、scope、输入 checksum、原始位置、partial 与四类计数。 | 输出 `pass / partial / block` 和复现材料；发现差异时只交最小复现给 D，不修 detector。 |

当前 T4a 已对 D4 manifest v2 完成独立 schema/count/identity 子项复算，结论为该子项 PASS、总体 PARTIAL。接下来的独立工作仍是 T0a 追索 8,994 run/config 和 T1a/T3a 准备并启动人工审阅；收到完整 D 冻结包后继续 T4a scope 与 pinned replay。不要因子项通过而解除 provisional 标记。

### 2026-10-19 NULL 总体与盲审 pilot 检查点

- 固定 NULL run `1696df82…` 的原始行数、唯一 ID 数、重复行和报告计数由独立审计复算通过；总体仍是 403,360 行，不能绑定到未提供 run/config 的 546,559 声明。
- 输出形状统计显示 parameter-may-be-null 280,127（69.45%），unknown-return 63,637（15.78%）；不得把 unknown-return 单独视为数量主因，也不得仅凭候选输出降低参数来源优先级。
- 已构建 160 条 pilot，按来源形状、sink 和仓库规模 quartile 分层，共 108 strata。抽样来源文件 hash 160/160 匹配，CSV/result JSON 的仓库、提交、规则、位置字段 160/160 对齐。人工标签 0/160，仍 pending independent review。
- 盲审协议已固定标签语义、源码/哈希核验步骤与影响范围边界；标签冻结工具检查队列哈希、全部样本 ID、证据字段不变、标签完整性和 coordinator key 映射，结果只写私有 coordinator 目录。3 项单元测试通过。
- 交付位于 `research/evidence/cpp/a_null_03_unknown_return_20261018/real_candidate_pilot_20261019_verified/`。协调员 key 与 reviewer queue 分目录保存；不得在标签冻结前向审阅者暴露 key。该 pilot 是 403,360 行 provisional frame 的人工审阅准备，不是 546,559 总体抽样结论。
- 下一步：独立审阅者依 `reviewer/review_protocol.md` 按队列填写 disposition、理由、证据、置信度和 reviewer ID，冻结 CSV SHA-256 后运行 `merge_null_candidate_review.py`；同时继续 T0a 追索 8,994/546,559 的输入绑定。标签完成前不得报告总体 Precision/Recall。

### 2026-10-19 A-UNSAFE 函数形状分层更新

- 对 9,323 行固定 provisional frame 做源码 hash 绑定后的 lexical function-shape census：9,323/9,323 hash 匹配、20 个非空 `rule × enclosing named-function shape × repository scale quartile` strata。format rule 有 8,004 条自由函数、524 条成员方法、123 条宏定义体、10 条具名函数外；unsafe-call rule 分别为 599、57、4、2。该分类是抽样特征，不是误报原因/真值判断；lambda、宏展开、模板和 CFG 仍不能据此判断。
- 新 160 条 function-stratified queue 每层至少 1 条并按总体量分配，源码 hash 160/160 匹配。它取代旧 callee-shape 队列作为当前推荐审阅队列；旧队列仍保留为历史 pilot，两份 160 样本不得合并或当作不同总体的复核。
- 最新队列位于 `research/evidence/cpp/a_unsafe_memory_review_20261018/function_stratified_pilot_20261019/`；人工复核仍 0/160。9,323 对 expected 8,994 的差异未解释，因此仍为 provisional pilot，不代表目标总体。 本轮重新核验 reviewer queue 与原始 candidate/result/source：160/160 均唯一绑定到 repository+manifest commit+file+line 的单条原观察行，源码 SHA-256 160/160 匹配，队列上下文窗口 160/160 与当前 hash 匹配文件重算一致；无失败，状态 `ready_for_reviewer`。审计脚本与结果见 `research/tests/a_null_03_unsafe_memory_review/audit_blind_queue_readiness.py`、`function_stratified_pilot_20261019/queue_readiness_audit_20261019.json`。该结果证明复核材料可交接，不提供真值标签；仍为 0/160 人工复核。

T 线报告分别列 raw observations、仓内根因、跨仓相同源码、人工复核结论；不得将 A-UNSAFE 0.3.0 重放中的 217 条解释为真阳性，也不得以该 829 文件子集替代 8,994 总体。

0.5.0 raw-string 与共享实参切分器回归仍是开发侧证据，T 线须独立验证 raw literal controls。canonical 条件/raw-string replay v4 绑定 scan commit 的 detector 与 helper 依赖：18/18 原始候选重现、11/11 源码 hash 匹配，其中 8 条 literal conditional 抑制、6 条宏/动态条件保留、4 条直接 raw-string 格式抑制。T 线须从原始 CSV/result JSON 与源码独立复算后才能验收。format argument 重放以 v8 为 canonical：T 线应使用固定的 detector 与 `memory_safety.py` 两侧 source hash，在 829 文件上复核 8,504 条旧行、456 条当前候选、239 条字面量前缀差异、4 个 partial 文件及完整表达式 census；v5/v6 的 baseline helper 未隔离，v7 未记录 after helper hash，均不作为验收输入。T 线还须独立重放 235 个旧 unsafe-memory-call 候选文件，核对 v3 工件中的 662/662 baseline、662 current、无差异与 235/235 source hashes；该子集不覆盖无旧 finding 的源码文件。所有这些均不是 TP/FP 标签。另须独立复算 v8 的 456 条表达式 census（122 调用/宏调用、79 标识符、239 字面量前缀混合、15 其他复合式、1 条件式），并核对 239 个源码 hash；对 177 个 `PRI*`、21 个 `TIFF_SSIZE_FORMAT` 和 120 个 `_()` 外层调用只验证来源与语义边界，不直接赋予安全/漏洞标签。`_()` 子集的开发侧审计记录为 120/120 hash 匹配、118 个纯字面量参数、2 个含 `PROJECT_NAME`、110 个直接 gettext header、10 个没有直接 header；T 线应使用 v3 审计材料独立复算，确认 wrapper 定义和 catalog 依赖，并对无编译/语言环境信息的项保留 unknown。源码自身检查显示 18 条直接包含 `<inttypes.h>`/`<cinttypes>`、14 条在同文件有宏定义；T 线须保持“直接包含/直接定义”与“完整展开已证实”两个口径分开，构建和 include 依赖未绑定时标记 unknown。开发侧 CSV census 覆盖 157 条 `printf/vprintf/syslog` 记录，其中 14 条条件表达式、12 条字面量格式（8 conditional + 4 raw string）；T 线应独立复算，并保留其他未 source replay 的范围限制。本地第二套旧条件审计得出 14/14、7/7、8/6，但 `external_independent_reviewer=not_performed`，不冒充独立验收。机器记录以 `literal_format_conditional_replay_20261019_v4.json` 为 canonical。

## 结构化 Vibe Coding 提示词

```text
角色：你是 A-NULL 独立测试与测量负责人。不修改 detector，不替开发线选择成功标签，不把告警下降或作者摘要当作准确率证据。

持续目标：每轮独立核验输入身份、抽样总体、标签和开发线冻结产物；raw observations、仓内根因、跨仓相同源码、人工标签四类结果始终分列。8,994 来源未对账、盲审未完成或独立复跑未通过时持续报告 partial/block。当前优先项是 T0a 总体追索、T1a/T3a 盲审队列执行，以及 T2a 环境/源码 attestation 补齐；已完成的 25 项 source-identities-only 复验不可扩写为完整环境验收。不读取或修改开发线实现。

步骤：
1. 校验原始 run、源码 repo/commit/tree、规则版本、profile、finding 稳定键和目标总体。9,323 不能静默改名为 8,994；找不到原 run/config 就记录 blocked。
2. 总体确认后冻结分层、随机种子、纳入概率、样本行键和盲审队列；保留原 finding/location，不以聚类删除样本。
3. 独立复核 NULL 的早返回、短路、别名、错误路径、同名 decoy、宏/模板和跨函数 controls，绑定源码 hash 与工具条件。
4. 按预先标签协议盲标真实案例，隐藏开发者预期；标注 confirmed、safe/fixed、known FP、not-testable、not-analyzed、unknown，并记录证据和分歧。
5. 独立复跑开发线 pinned before/after；核对 scope、版本、输入摘要、原始位置和失败项。无法重放时提供复现步骤并判 partial/block。
6. 分列四类计数和覆盖；样本不足或标签未验证时不报告 Precision/Recall，不把 not-testable 记为 FP。
7. 更新 T checkpoint，提交逐例证据、差异报告、验收结论与最小回交动作。

交付：原始总体核验、可复现抽样框、盲审协议/标签/证据、独立 controls 复核、四类分列计数、复跑日志和 pass/partial/block。

完成门：来源与抽样可复现；每个标签有独立证据；所有候选仍可追溯到原始位置；开发线没有获得隐藏留出标签；限制和未完成项明确。

边界：不改 detector/catalog/UI/schema；不使用开发者自测替代验收；不删样、改标签或混淆计数；不 push/merge/改 PR。每轮从输入与证据完整性开始。
```

## 持续目标

持续推进目标总体追索、独立抽样、盲审和 pinned 复验。无法验证时保留 unknown/partial/block 与原始证据，不通过推断填补缺口。
