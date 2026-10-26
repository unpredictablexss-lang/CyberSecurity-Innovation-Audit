# A-NULL 开发与独立测试计划（2026-10-18）

## 目标与基线

本计划围绕 NULL 弱候选与 unsafe-memory 证据质量改进。持续执行目标由当前 Codex Goal 跟踪；本文件是并行拆分、交付契约和提示词入口。基线事实、限制和本轮目标以 Goal 描述、当前仓库源码及锁定的证据清单为准。现有工作树有大量未提交文件；开始代码改动前必须建立隔离工作树并固定共同基线 SHA，不得重置、清理或覆盖原工作树。

本文件只管理 A-NULL 子任务。A 线真实漏洞根因检测（当前 cJSON 候选）的开发/独立测试分工、任务树和两条结构化提示词见 [A 线开发与独立测试并行计划](cpp/a-lane-development-test-plan-20261019.md)。

本文件保留 A-NULL 的共同状态、证据和交接；两条执行线使用分开的文档：[A-NULL 开发线计划](a-null-development-plan-20261019.md) 与 [A-NULL 测试线计划](a-null-test-plan-20261019.md)。

## 本轮任务树状态与下一批排期（2026-10-19）

远端复核：本轮重新执行 `git fetch origin` 成功。当前隔离分支 `codex/a-null-latest-20261019` 的 HEAD 为 `4593a7c9b6977eb81172d01b46cc59daf46f5d45`，`origin/main` 已前进至 `56a5d2689a5abf21e13d35397d87c9b035954197`，本分支落后 12 个提交。远端新增主要为 D 线高召回/CVE 工作；与 NULL detector、unsafe-memory detector、研究模式 UI 直接相关的 A 文件没有上游差异。未将 D 线或其他主线工作混入 dirty A 工作树。固定 final 扫描与同 run checksum 报告为 9,323 unsafe-memory 行；另一签名小扫描为 0；未找到 8,994 对应 run/config。

本轮 T0a 再枚举了本机 `candidate_results.csv`、`run_config.json`、`compact-summary.json` 和 `checksums.json` 文件。找到的 unsafe-memory run 仍只有：6 项目 run `40a9c2ac…`（0 行，candidate CSV SHA-256 `a9e2f9fa…`）以及 final ABCD run `1696df82…`（9,323 行，candidate CSV SHA-256 `e6473b91…`）。没有发现第三个 8,994 run 或能解释 329 行差额的过滤配置；T0a 继续标记 `blocked: target_population_unbound`。

NULL 计数也存在 run 身份差异：目标描述提到的一轮全规则扫描为 546,559 条，但当前可见且可机器核验的 final ABCD 工件 `openharmony-abcd-full-scan-20261018-final` 在 run signature `1696df82f39e2564e0821c0ad2e837a00c6d83f9276bf5e0c38a3bd1f511700b`、scanner commit `0d9357ea22224b72c9756864dbd14b71a4723924` 下记录 403,360 条 NULL 原始观察、403,359 个唯一 diagnostic ID（重复 ID 行 1；400 个项目、92,228 个适用文件；23,526 analyzed、68,702 partially inspected）。可重放脚本及机器结果见 [NULL 全扫描数量身份核验](../evidence/cpp/a_null_03_unknown_return_20261018/full_scan_population_audit_20261019.md)。该报告的 run config 显式包含 NULL，但不能证明它就是 546,559 那一轮；目前没有 546,559 的原始工件或身份绑定，两个数量不得混为同一结果。全规则研究 UI 将两者分别标为未绑定历史量级与可核验另一 run，避免把任一数值伪装成本次预测。

| 任务树 | 状态 | 已有事实 | 下一动作 / 交付门 |
|---|---|---|---|
| 开发 D1–D2 | 已实现，待独立验收 | NULL 默认关闭、显式研究模式、unknown-return 独立弱观察身份、来源分级；pinned 11 行对照与 controls 已记录 | D 线只修复可复现的语义缺陷；提交规则/检测器版本、开发者 controls、同源 pinned 产物和变更范围清单，交 T4 独立复验 |
| 开发 D3 | 进行中；owner 接口申请待评审，产品构建上下文仍缺 | Clang 21 控制实验通过；产品 checkout 没有匹配 `compile_commands.json` / `build.ninja`；A 线已提交 [Clang CFG owner 接口申请](cpp/a_null_clang_cfg_owner_interface_request_20261019.md) | D3a 已完成设计和边界申请；D3b 等 owner 明确可信 build profile/provider 契约并提供匹配数据库后，再做 A-owned consumer 与产品控制；当前不得声称完成 AST+CFG 接入 |
| 开发 D4–D5 | manifest v2 schema/validator 已接入抽样生成器；四类产品计数接口申请待 owner 评审 | 保留旧 v1 读取；v2 增加跨仓簇逐项证据（rule、source SHA、仓库集合、原始行数）。临时重建 9,323 frame 位于 `D:\openHarmonyScanner\tmp\a-unsafe-schema-v2-validation-20261019`；冻结副本 `research/evidence/cpp/a_unsafe_memory_review_20261018/v2_independent_audit/sampling_manifest_v2.json` 的 SHA-256 为 `6ca2098c…`。接口申请见 `research/deliveries/cpp/a_null_four_count_report_owner_interface_request_20261019.md` | T 线独立复算 v2：9,323/9,323 行唯一关联到 104 个 result JSON；schema 与四类计数一致（raw 9,323、root cause 未建立、cross-repo 0、human 0/160）。D4 对该 provisional frame 的计数/schema 检查通过；公共报告接口仍待 owner 评审，D5 每轮保留 pinned before/after、耗时、覆盖和来源身份 |
| 测试 T0 | `blocked: target_population_unbound` | 最新本地文件名盘点（`rg --files D:\openHarmonyScanner -g candidate_results.csv -g run_config.json`）仍只找到两个候选表/配置对：0 行小 run 与 9,323 行 final run。final CSV 中“8994”仅见于 74 个 diagnostic ID 子串和 4 个 source line 值，未找到 8,994 run 身份或过滤口径 | 找回 8,994 原始 run/config/过滤规则后逐行解释 329 差额；在此之前 9,323 仅作为具名替代 frame，不能静默替换 |
| 测试 T1 | 临时框已建，目标总体未验收 | 160 条样本 source hash 160/160 匹配；9,323 总体分层草案存在 | 在总体身份确认后锁定分层、种子、纳入概率与样本清单；在此之前不得把临时 160 条样本称为 8,994 总体的代表性样本 |
| 测试 T2 | 25 项 source-identities-only pinned replay 通过；完整源码/环境 attestation 仍 partial | T 线在不读取 `control_manifest.json` 的方式下独立复跑，25/25 输入哈希、origin、逐项 findings/coverage 均与冻结工件一致；5 个 direct replay source hashes 也复核通过。结果在 `D:\openHarmonyScanner\tmp\independent_a_null_25_replay_20261019_v2.json`。完整仓库和 Python 环境未绑定 | 补齐完整执行环境/源码快照身份或明确限定验收范围；合成 controls 仍只证明固定输入行为，不外推产品准确率 |
| 测试 T3 | 未开始人工盲审；独立复核者待指定 | 协议、标签词典、临时队列已具备；160 条状态为 0 已复核 | 由用户安排或指定不参与 detector 调参的复核者，按盲审协议完成 provisional pilot；记录标签、证据、分歧与无法验证理由，不用工具自标替代人工判断 |
| 测试 T4 | D4 schema/count 子项 partial-pass；整体交接仍等待 | 可重放独立审计脚本 `research/evidence/cpp/a_unsafe_memory_review_20261018/v2_independent_audit/audit_sampling_manifest_v2.py` 复算 9,323 行，并逐条核 CSV 与 104 个 result JSON 的 diagnostic_id、rule_id、source hash 字段和 repository；无重复 ID。v2 JSON Schema 通过；四类计数一致。目标总体仍 provisional，人工标签 0/160 | D4 验收范围仅限该 provisional frame 的 schema/计数/身份字段关联；不等于对全体源文件重算 hash、总体真值或整体验收通过。D 线冻结完整包后继续 T4 scope 与 pinned 复跑 |

### 下一批并行切片

| 独立并行线 | 当前执行任务 | 本线交付 | 依赖 / 完成门 |
|---|---|---|---|
| **开发线 D** | D3：整理 A-owned compile database/CFG 消费契约；D4：定义四类计数 schema 草案。保留现有 detector 行为，不扩大到 Runner/Catalog/UI 公共改动。 | source/build identity、输入字段、失败状态与 partial obligations、控制矩阵、schema 样例、开发者回归和 owner 接口申请（若需）。 | CFG 产品实现依赖 owner 提供可信 build profile/provider 契约和匹配 compile DB；此前只交契约，不声称 AST+CFG 已接入。计数草案须保留原始行及位置。D 线单独维护提示词/进度，见 [开发线计划](a-null-development-plan-20261019.md)。 |
| **测试线 T** | T0：继续追索 8,994 原始运行证据；T1/T3：将 160 条队列保持为 provisional pilot 并推进独立盲审；T2：补齐 25 项 controls 的完整源码/环境 attestation；T4：接收 D 线冻结包做 scope/pinned 复验。 | run/config 身份对账、盲审结果/分歧、control attestation、独立复跑报告和差异记录。 | 不等待 D3/D4；9,323 不能改称 8,994。不能读取 D 线未公开的真实案例预期或 holdout 标签。总体缺失时，9,323 仅为单独标记的替代总体。T 线单独维护提示词/进度，见 [测试线计划](a-null-test-plan-20261019.md)。 |

**交接只发生在冻结产物之后：** D 冻结 commit、detector/rule version、compile context、scope、输入清单、before/after 和开发者回归后，T 独立复跑并给 pass/partial/block。T 先发现的身份、覆盖或统计问题写成复现材料回交 D；T 不改 detector，D 不接触盲审答案。两线在各自计划中更新状态，本文件只维护共享基线和交接记录。

### 两条并行线的持续目标

- **开发线 D（持续目标）：** 每轮基于固定 immutable base 完成一个有源码证据的 A-owned C/C++ 检测改进；保留 unknown/partial，配套正反控制、来源绑定、开发者回归与 pinned before/after。任何公共接口需求先形成最小申请；只有 T 线独立验收后，才把该轮标为通过。当前首要任务是 compile DB/CFG 输入契约和 D4 计数 schema，不以降低候选数为目标。
- **测试线 T（持续目标）：** 每轮独立验证输入身份、抽样总体、标签和 D 线冻结产物；原始观察、仓内根因、跨仓相同源码、人工标签四类结果始终分列。8,994 来源未对账或人工盲审未完成时，持续报告 partial/block 和证据缺口，不用摘要、自评或候选下降替代复核。

## 当前推进状态（本轮续做）

- 开发线 D1 最初在 `f8e3a0ad7463f216db4be7502bd8a19eec545908` 上实施，随后迁到最新主线隔离分支 `codex/a-null-latest-20261019`，基线为 `origin/main` `4593a7c9b6977eb81172d01b46cc59daf46f5d45`。主线新增的 D sensitive-exposure Catalog 项已保留；NULL detector 与 A_CPP 约定没有上游改动。A-NULL 改动包括 unknown-return 独立弱观察身份、nullable 来源分级、显式全规则研究 UI，以及无编译上下文时 guard relation 统一为 unknown；疑似保护 sink 不作为完整负向结果，疑似不保护 sink 保留候选并标 coverage partial。此前名为 `pinned_before_after_latest_20261019.json` 的工件实际绑定 0.4.0（SHA `1caef00f…`），仅作为历史快照保留。现已从 immutable main `4593a7c9b6977eb81172d01b46cc59daf46f5d45` 重放到当前 0.6.0，最新 detector SHA `3569bdce12236a37973f7e311ad3c738ca7e05276504fdf57a0de1b77cbf09a5`；18 个 A-NULL-01 fixtures 保留 11 行（9 强候选 + 2 弱观察），19 个 A-NULL-02 controls 保留 6 行（5 强候选 + 1 弱观察），覆盖与逐行结果见 `research/evidence/cpp/a_null_03_unknown_return_20261018/pinned_before_after_main_20261019.json`。完整 25 项（19 + 6 边界）main 对照另见 `macro_object_continuation_before_after_20261019.json`，其 after hash 同样绑定当前 0.6.0。
- 开发/测试接口核对：服务端 planner 回归确认普通计划跳过 NULL（`explicit_selection_required`），显式选择后 NULL 成为 requested/suggested ID 且被 registry 接受。最新主线共 10 个研究规则 ID，符合 operation API 的 10 ID 上限。Python 本轮 27 项通过（NULL fixture/control、planner 选择和 unsafe-memory 样本工具）；Web 18 项通过，`npm run build` 通过。owner API integration 仍未运行：Windows Python 缺 `fcntl`，现有 WSL venv 缺 `tree_sitter`。
- 优先级接口边界：NULL 默认关闭；研究模式用独立 weak-return rule ID 和“弱观察/待复核”文案区分 unknown-return。Runner 当前将所有 finding 的 `severity` 与 `confidence` 固定为 `unassessed`，没有可排序的低优先级字段。因此现状实现了语义/身份隔离，不声称已提供数值或 UI 排序优先级；若验收要求该字段，D 线需单独提交 shared contract/runner/UI owner 接口申请。
- 独立控制验证器在最新基线下复核了 19 个 A-NULL-02 controls，状态 passed。全历史 18 个 A-NULL-01 fixtures 的 pinned 对照保持原始 finding 行数；unknown-return 分类变化及 coverage 降级均记录在上述报告中。
- 2026-10-19 T2 追加发现并修复一处宏边界漏建模：函数式宏体包含 `->` 时旧逻辑会把后续函数的前置 `#define`/空行并入函数头，产生 `complete/0 findings`。检测器现在识别含 `*`、`->`、下标或 DEREF 标记的宏体，并跳过前置预处理行；同一 19 项既有 controls + 3 个固定 SHA 边界 controls 对照中，该宏控制由 `complete/0` 变为 `partial/1`，其余控制保持。机器结果与可重放脚本见 `research/evidence/cpp/a_null_03_unknown_return_20261018/macro_template_cross_function_controls_before_after_20261019.json`、`replay_macro_boundary_controls.py`。NULL 专项 21/21 通过，A-NULL-02 verifier 19 项通过；全 detector 集合有一个无关 D 线测试在 Windows 因缺 POSIX `resource` 模块失败，WSL 全集又因缺 `tree_sitter_c` 等依赖未能完成，故不声称全套回归通过。
- 本轮进一步修复对象式与反斜杠续行宏的隐藏解引用：对象宏 `item->id` 和续行函数宏都由 `complete/0` 变为 `partial/1`。限定名调用曾可能错误匹配到其他作用域同名的 nullable 声明；限定名及多重同名声明现保留 unknown，并新增 SHA 固定的同名异命名空间 control。Detector 升至 0.6.0，强候选规则升至 1.4.0。19 个 A-NULL-02 controls 与 6 个边界 controls 共 25 项 main pinned 对照已重生成，结果为 9→12 finding rows、4→12 partial files，新增限定名控制从强候选变为弱观察；25 项源文件哈希匹配。NULL 专项 21/21、A-NULL-02 verifier 19 项、unsafe-memory review 工具 5/5 通过；该 pinned 对照尚待独立测试线复验。当前全 detector 集合 193 项中 192 项通过，唯一错误是无关 D5 测试未生成预期 `blocked.json`；A-NULL 专项通过。远端 fetch 当前因 GitHub 443 连接失败，基线仅按本地缓存确认。
- Clang/CFG 仍属 partial：本机 WSL Clang 21.1.8 可对控制文件生成 CFG；此前用 `core.NullDereference` checker 复核了 6 个固定控制，但无产品 compile database，不能外推为产品构建或 detector 接入。当前 0.6.0 仍保持未知 guard relation，不伪报支配或非支配；产品构建数据库接入及 CFG 驱动 source/sink/guard 判定尚未完成。详情见 `research/evidence/cpp/a_null_03_unknown_return_20261018/clang_static_analyzer_controls_20261019.json` 与 `clang_cfg_context_inventory.md`。
- 测试线 T1 建成 160 条 blind-review 临时抽样框和独立复核协议，提供明确的盲审边界、标签词典、证据字段和回交方式；冻结后合并工具及同 run 报告交叉校验共 5 项工具单测通过。全体候选的消息形状初步统计显示 `fprintf` format-string 为 8,452 条（90.66%），另有 662 条 unsafe-memory-call 消息未能由当前模式解析 callee；这描述规则输出形状，不是误报结论。代码核对确认此 format-string 规则由非字面量 format 实参触发，可信动态格式可能构成待验证 FP 假设，但尚无人工标签证实。现有可验证全扫描产物 `openharmony-abcd-full-scan-20261018-final` 为 9,323 条 unsafe-memory 原始观察（format-string 8,661、memory-call 662），与目标叙述 8,994 相差 329。其 scanner commit、manifest、run signature、detector count 与 `openharmony-scan-reports-20261018` 的 checksum 验证报告一致。160/160 个样本源码 hash 匹配；review 状态仍为 0 已复核/160 待复核。仓内根因簇因缺少验证过的根因键仍为 unknown，不能用文件/行去重冒充根因；跨仓相同源码簇为 0。材料见对应隔离 worktree 下 `research/evidence/cpp/a_unsafe_memory_review_20261018/`。
- 本轮再次核对可见的 full-scan summaries：同日目录 `openharmony-abcd-full-scan-20261018` 使用另一 run signature（`40a9c2ac81bc71b7520c7acc72ef46569e220d06ef745a409ebdd1521dc998c`），仅覆盖 6 个项目且 unsafe-memory 候选数为 0；`openharmony-abcd-full-scan-20261018-final` 与独立 `openharmony-scan-reports-20261018` 的 scanner commit、manifest、run signature、detector summary 和 checksums 相符，均为 9,323 条。较早的 `openharmony-full-scan-20261017` 使用不同 schema/manifest，总诊断 1,645 条，不能解释 8,994。可见 summary 与当前可达 Git 历史的精确数字检索均未找到 8,994 的运行或过滤口径；需找回其原始 run/config 才能按该总体抽样。
- 测试线补充了身份计数对账：9,323 行有 9,323 个唯一 diagnostic ID，重复 ID 为 0；分析状态为 partial 9,317、analyzed 6。候选行去重不能解释与目标 8,994 的 329 行差异，原始目标 run/config 仍需找回。该计数写入抽样 manifest，不改变分层与原始行。
- T1 对固定 unsafe-memory 产物发现并修复 A-UNSAFE format detector 的 API 参数位错误：旧规则将 `fprintf`/`vfprintf` 的 `FILE *` 第一个实参当作 format。对旧扫描 8,452 个 `fprintf` 与 52 个 `vfprintf` finding，在 829 个 source-hash 匹配文件上逐文件重放，旧实现完整复现 8,504 行；0.3.0 按真实 API 参数索引，并将限定/同名未解析符号保留 partial/unknown。最终 0.3.0 重放得到 217 条候选，8,287 个旧位置消失、217 个位置改为真实 format 实参，825 个文件 complete、4 个 partial；机器结果见 `research/evidence/cpp/a_unsafe_memory_review_20261018/format_argument_positions_before_after_20261019.json`。重放范围仅为旧 `fprintf`/`vfprintf` 候选所在 829 个源码文件，不覆盖 92,228 个适用文件。参数位缺陷不等于余下候选 TP/FP 标签，也不代替 8,994 总体人工盲审。9,323 原始 run 仍为历史 before，需目标 run/config 对账后再决定同范围全量重扫。
- 因此目前是有实质实现与测量进展的 partial，不是整项目标完成；8,994 来源对账、人工盲审、完整 AST+CFG 接入、完整报告集成仍在任务树内。

## 并行任务树（开发线、测试线分别排期）

两条线共享 A-NULL 的总目标和 immutable base，但各自有独立任务树、工作目录、交付物与持续目标。D 线负责实现；T 线负责独立测量和验收。除共同输入契约与最终交接外，不互相代做对方任务。

### 开发线 D：规则与分析实现

```text
D0  固定代码基线、规则版本、输入清单与 before 产物
├─ D1  梳理 NULL 触发条件、来源角色、profile、配置与报告消费路径
├─ D2  将 nullable 参数、显式 nullable/nothrow 来源、unknown-return 分开建模
├─ D3  接入可用 compile_commands.json 下的 Clang AST+CFG；缺失时保留 unknown/partial
├─ D4  提供原始行、仓内根因簇、跨仓相同源码簇、人工结论的独立计数接口
└─ D5  维护开发者 controls、性能记录及 pinned before/after 机器产物
```

### 测试线 T：独立抽样、标签与验收

```text
T0  固定原始 run、源码身份、规则/profile、稳定行键与抽样种子
├─ T1  找回并验证 8,994 条候选对应的输入；按规则、函数形状、仓库规模分层
├─ T2  独立复核 NULL controls：早返回、短路、别名重绑、错误路径、同名替身、宏/模板、跨函数
├─ T3  对真实案例盲标；维护 vulnerable/fixed/safe 与 known-FP controls
└─ T4  独立复跑 pinned 前后结果，验收统计口径、证据保全、覆盖限制与变更范围
```

### 两线交接顺序

1. D0/T0 分别锁定共同输入身份；T0 额外核实 8,994 条原始 run 与抽样框。
2. D 线独立完成实现和开发者 controls；T 线在此期间只推进输入对账、抽样框及盲审准备，不读取开发者预期标签。
3. D 线交付 pinned before/after 工件后，T4 独立复跑并给出 pass/partial/block 结论。
4. T 线发现的问题回到 D 线形成新迭代；每轮保留上一轮工件与标签，不覆盖历史结果。

**持续目标 D：** 每轮从固定基线推进一个可审查的规则/分析改进，并交付代码、开发者回归、pinned 产物、覆盖与限制记录；在 CFG 上下文不足时保持 unknown/partial，直到规则证据和验收门全部满足。

**持续目标 T：** 每轮独立核验输入与统计口径、扩充可追溯盲审标签、复跑 D 线 pinned 产物并报告分层结论；在 8,994 来源、盲审覆盖或独立复跑未解决前，持续标注 partial/block，不以候选下降代替质量结论。

## 任务边界、依赖与完成门

| 线 | 负责范围 | 依赖 | 完成门 |
|---|---|---|---|
| D1–D2 开发 | A 所有权下 C/C++ NULL detector、其专属测试/fixtures、研究说明 | 固定算法版本、规则版本、仓库/commit/profile 与现有 4,983 文件/33 候选的小规模结果 | 未知返回值不再冒充强 nullable 来源；参数、显式来源、未知返回分开建模；普通 profile 仍默认关闭 NULL；研究模式须显式启用并可见地标记弱候选/待复核及启用原因/量级提示。 |
| D3 开发 | 构建上下文可用时的 Clang AST+CFG 路径/支配分析 | 可定位的 compile database、Clang 版本和可复现编译参数 | compile context 有效时输出可审计 CFG/支配证据；缺失或解析不完整时保留 unknown/partial，不以词法结果伪装证明。记录支持范围与失败状态。 |
| D4–D5 开发 | 聚类计数/报告表达（若需公共接口变更，先提交 owner 接口申请）；开发者回归 | 定义稳定的 observation/root-cause/source-cluster/review schema | 聚类不丢弃原始位置和证据；历史 controls 每次算法修改前后 pin 同一 commit 对照；回归包括 positive、fixed、safe、unrelated、partial 及已知 FP。 |
| T1 测试 | 8,994 条 unsafe-memory 候选独立分层抽样和来源形状分析 | 固定原始 run、仓库规模、规则、函数形状、采样种子 | 交付可复现抽样框、纳入概率/分层统计、原始行键及每条人工结论；先描述主因与误报形状，未完成前不建议基于数量直接全局降权/过滤。 |
| T2–T3 测试 | 25 项 pinned controls 待独立验收；真实案例盲标未完成 | 19 个 A-NULL-02 controls 与 6 个固定哈希边界 controls；真实案例盲审仍 0/160 | 独立核对宏/模板/跨函数/限定同名控制的 before/after 与 source hash；取得可信编译上下文后核 Clang CFG；获得独立复核者后盲标真实案例，记录证据和分歧；所有 unknown 保持 unknown。 |
| T4 测试 | 独立回归、口径与范围验收 | D 线提交的 pinned before/after 产物 | 原始观察数、仓内根因簇、跨仓源码簇、人工复核数分开核对；所有原始位置仍可追溯；独立复跑、变更范围检查通过；输出 pass/partial/block 与最小后续动作。 |

## 并行接口与协作规则

- D 线只提交实现、变更说明、开发者回归和机器可读 before/after 产物；不得给 T 线预先提供真实案例盲标标签。
- T 线不修改 detector 或规则，不用 D 线 fixtures 充当真实产品证据；可独立构造测试输入与盲标协议。
- 两线使用独立工作目录、数据目录与结果目录，共同基线 SHA、规则版本、编译参数和输入清单必须写入交付。
- 如果 UI、Catalog、Runner、schema 或报告 API 必须变更，先由 D 线提出具体接口契约与兼容影响，交 owner 集成；不能把接口改动混入 detector 交付。
- 候选总数下降不是验收标准。不得因候选量大直接全局降权、静默过滤或删除源位置、原始证据、失败项及 unknown。
- 每次算法改动都固定 before/after 的源 commit、规则版本、profile、工具版本、输入清单和统计产物；历史 vulnerable/fixed/safe controls 必须保留。新增真实案例由独立人员盲标。
- 禁止在原有脏工作树执行 pull/reset/checkout/clean；不 push、merge 或更改 PR 状态。

## 分线执行文档

- 开发线 D 的独立任务树、提示词和持续目标见 [A-NULL 开发线计划](a-null-development-plan-20261019.md)。
- 测试线 T 的独立任务树、提示词和持续目标见 [A-NULL 测试线计划](a-null-test-plan-20261019.md)。
- 本总计划只维护共同事实、总体任务树、当前状态、交接门和持续检查点；D/T 分别更新自己的执行文档，避免职责、结果与验收混写。

## 持续执行检查点

当前 Codex Goal 是本任务的持续目标记录。每轮开始核对最新可用远端基线、工作树状态、进行中的开发/测试子项和阻塞依赖；每轮结束记录已完成事项、精确输入对象、实际命令和结果、unknown/partial、下一动作与责任线。D 线与 T 线独立推进，最终由 T4 对 D 线输出盲验和 pinned 对照收口。若目标尚未满足，不把阶段性结果标记为完成。
