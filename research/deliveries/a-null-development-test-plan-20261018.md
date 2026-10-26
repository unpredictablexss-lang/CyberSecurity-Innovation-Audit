# A-NULL 开发与独立测试计划（2026-10-18）

## 目标与基线

本计划围绕 NULL 弱候选与 unsafe-memory 证据质量改进。持续执行目标由当前 Codex Goal 跟踪；本文件是并行拆分、交付契约和提示词入口。基线事实、限制和本轮目标以 Goal 描述、当前仓库源码及锁定的证据清单为准。现有工作树有大量未提交文件；开始代码改动前必须建立隔离工作树并固定共同基线 SHA，不得重置、清理或覆盖原工作树。

## 当前推进状态（本轮续做）

- 开发线 D1 已在隔离 worktree `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit-a-null` 基于 A 线提交 `f8e3a0ad7463f216db4be7502bd8a19eec545908` 实施：unknown-return 单独用弱观察规则身份，明确 nullable 参数/返回与一般可空参数分开；全规则研究 UI 可显式开启，普通规则列表仍默认排除 NULL。修正纯词法 guard 的语义：无编译上下文时 guard relation 统一为 unknown；疑似保护 sink 不再作为完整负向结果，疑似不保护 sink 保留候选但 coverage 为 partial。Detector 为 0.4.0；历史 18 fixture 与 19 A-NULL-02 控制的 finding 行数不变，unknown-return 弱观察分类也保留。Pinned coverage 从 base 的 A-NULL-01 完整/partial 10/6 变为 5/11；A-NULL-02 从 18/1 变为 13/6。该 worktree 尚未合回原工作树或提交。
- 开发/测试接口核对：新增服务端 planner 回归，确认普通计划跳过 NULL（`explicit_selection_required`），显式选择后 NULL 成为 requested/suggested ID 且被 registry 接受；当前 9 个全规则研究 ID 符合 operation API 的 10 ID 上限。该回归 2 项、Web 请求测试 17 项通过，前端 TypeScript/build 通过。
- 开发者验证：Python NULL fixture/control 20 项通过；Web 17 项通过；`npm run build`（TypeScript + 前端构建）通过。owner API integration 目前未能运行：Windows Python 缺 `fcntl`，现有 WSL venv 缺 `tree_sitter`。报告在 `research/evidence/cpp/a_null_03_unknown_return_20261018/pinned_before_after.json`。
- Clang/CFG 仍属 partial：本机 WSL Clang 21.1.8 可输出 CFG；五个锁定组件与仓库 `out` 目录没有 `compile_commands.json`，且当前环境缺 `gn`、`ninja`、Python `clang.cindex`，不能从实际构建导出并执行数据库。0.4.0 已确保词法 guard relation 不再伪报支配或非支配，pinned 报告记录了 finding 数与 coverage 变化；编译数据库接入及 CFG 驱动判定尚未完成。完整盘点见 `clang_cfg_context_inventory.md`。
- 测试线 T1 建成 160 条 blind-review 临时抽样框和独立复核协议，提供明确的盲审边界、标签词典、证据字段和回交方式；冻结后合并工具及同 run 报告交叉校验共 5 项工具单测通过。全体候选的消息形状初步统计显示 `fprintf` format-string 为 8,452 条（90.66%），另有 662 条 unsafe-memory-call 消息未能由当前模式解析 callee；这描述规则输出形状，不是误报结论。代码核对确认此 format-string 规则由非字面量 format 实参触发，可信动态格式可能构成待验证 FP 假设，但尚无人工标签证实。现有可验证全扫描产物 `openharmony-abcd-full-scan-20261018-final` 为 9,323 条 unsafe-memory 原始观察（format-string 8,661、memory-call 662），与目标叙述 8,994 相差 329。其 scanner commit、manifest、run signature、detector count 与 `openharmony-scan-reports-20261018` 的 checksum 验证报告一致。160/160 个样本源码 hash 匹配；review 状态仍为 0 已复核/160 待复核。仓内根因簇因缺少验证过的根因键仍为 unknown，不能用文件/行去重冒充根因；跨仓相同源码簇为 0。材料见对应隔离 worktree 下 `research/evidence/cpp/a_unsafe_memory_review_20261018/`。
- 本轮对账核实到另一个同日目录 `openharmony-abcd-full-scan-20261018` 使用不同 run signature（`40a9c2ac81bc71b7520c7acc72ef46569e220d06ef745a409ebdd1521dc998c`），仅覆盖 6 个项目且 unsafe-memory 候选数为 0；它不能解释 8,994，也不能替代 final 运行。另找到 `openharmony-scan-reports-20261018`，其 scanner commit、manifest、run signature 和 unsafe-memory detector summary 均与 final artifact 完全匹配并通过 checksums 哈希核验，确认此运行数为 9,323；报告仍未解释 8,994 的来源。8,994 的原始 run/config 或明确过滤口径需另行找回。
- 测试线补充了身份计数对账：9,323 行有 9,323 个唯一 diagnostic ID，重复 ID 为 0；分析状态为 partial 9,317、analyzed 6。候选行去重不能解释与目标 8,994 的 329 行差异，原始目标 run/config 仍需找回。该计数写入抽样 manifest，不改变分层与原始行。
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
| T2–T3 测试 | 独立 NULL 控制验证、真实案例盲标 | 固定的 vulnerable/fixed/safe 源码对象与独立标签人 | 开发者不向盲标者泄漏预期；记录源对象、规则版本、观察结果、标签依据和分歧；所有 unknown 保持 unknown。 |
| T4 测试 | 独立回归、口径与范围验收 | D 线提交的 pinned before/after 产物 | 原始观察数、仓内根因簇、跨仓源码簇、人工复核数分开核对；所有原始位置仍可追溯；独立复跑、变更范围检查通过；输出 pass/partial/block 与最小后续动作。 |

## 并行接口与协作规则

- D 线只提交实现、变更说明、开发者回归和机器可读 before/after 产物；不得给 T 线预先提供真实案例盲标标签。
- T 线不修改 detector 或规则，不用 D 线 fixtures 充当真实产品证据；可独立构造测试输入与盲标协议。
- 两线使用独立工作目录、数据目录与结果目录，共同基线 SHA、规则版本、编译参数和输入清单必须写入交付。
- 如果 UI、Catalog、Runner、schema 或报告 API 必须变更，先由 D 线提出具体接口契约与兼容影响，交 owner 集成；不能把接口改动混入 detector 交付。
- 候选总数下降不是验收标准。不得因候选量大直接全局降权、静默过滤或删除源位置、原始证据、失败项及 unknown。
- 每次算法改动都固定 before/after 的源 commit、规则版本、profile、工具版本、输入清单和统计产物；历史 vulnerable/fixed/safe controls 必须保留。新增真实案例由独立人员盲标。
- 禁止在原有脏工作树执行 pull/reset/checkout/clean；不 push、merge 或更改 PR 状态。

## 开发线结构化 Vibe Coding 提示词

```text
角色：你负责 A 线 C/C++ NULL 检测器与证据呈现的开发。只实现规则/分析器及 A 线自有回归；独立抽样、真实产品判定和盲标属于测试线。

目标：处理 unknown-return 造成的弱候选过量，同时保留确有证据的 NULL 风险。普通扫描 profile 不默认启用 NULL；显式研究模式把结果标成“弱候选/待复核”，展示启用原因和近似候选量提示。nullable 参数、显式 nullable/nothrow 来源和未知返回值采用不同角色/证据强度。若能绑定 compile_commands.json，探索 Clang AST+CFG 的 source-to-sink 可达性与 guard dominance；没有有效编译上下文或分析失败则返回 unknown/partial。

工作步骤：
1. 阅读 AGENTS.md 指定文档与 parallel-20261017/A_CPP.md；检查 ownership、当前 diff、NULL method card、detector/catalog/UI 配置与已有测试。固定完整 base SHA、当前规则/检测器版本、profile、输入清单和已有小规模结果。
2. 建 before 基线，检查 unknown-return 的触发链和配置/UI消费点；不先依据候选量猜测根因。
3. 设计来源分类和兼容策略，先给出窄范围改动；不改历史报告、finding ID 或公共合同。涉及 Catalog、Runner、UI API、报告 schema 时形成独立 owner 接口申请。
4. 以明确证据建模来源、sink、guard、alias 和 CFG；无 compile database、宏/模板无法解析、跨函数/异常路径不支持时保留 obligation unknown，不作安全证明。
5. 加开发者 controls：早返回、短路、别名重绑、错误路径、同名 decoy、宏/模板、跨函数；同时覆盖 vulnerable/fixed/safe/unrelated/partial 和历史 known-FP。不得把开发者自测当作独立验收。
6. 对 pinned 同一源码对象生成 before/after 机器可读比较，报告诊断变化、原始位置、分析失败、时间/资源、覆盖限制；候选下降本身不是成功指标。

完成标准：规则来源语义分明；未声明研究模式时 NULL 不参与普通默认扫描；研究输出清楚说明弱候选、启用原因及近似量；编译上下文不完整时 unknown 诚实保留；历史 vulnerable/fixed/safe 控制可复现；改动仅在允许的 A 所有权范围内。交付代码、专属测试、配置/UI接口申请（如需）、规则卡更新、before/after 清单与限制说明。

约束：使用隔离工作树与共同 immutable base；保留原脏工作树；不删除原始候选或证据；不改 B IPC、owner 公共接口或历史 benchmark；不 push/merge/改 PR 状态。每次续跑先读取本文件和当前状态，更新实际进度与下一步。
```

## 测试线结构化 Vibe Coding 提示词

```text
角色：你是 A 线独立测试与测量负责人。你不修改检测器、不帮开发线定义成功标签，也不以候选数减少作为准确度改善证据。

目标：在规则调整前建立可复现、分层且可审计的独立评估。重点分析 8,994 条 unsafe-memory 候选的主来源形状与误报成因；对 NULL 早返回、短路、别名重绑、错误路径、同名替身、宏/模板、跨函数进行对照；新增真实案例由独立人员盲标。保留 vulnerable/fixed/safe 和 known-FP 控制。

工作步骤：
1. 固定原始 run、源码 repo/commit/tree、规则/检测器版本、profile、每个观察行的稳定标识、仓库规模、函数/规则类别和抽样种子。无法验证原始 run 时标为 blocked，不自行生成替代基线。
2. 为 8,994 条候选建立分层框架，按规则、函数形状和仓库规模分层；记录抽样概率、去重键、纳入/排除原因。抽样保留原始 finding/location 关联，不因聚类删除证据。
3. 依据预先写明的标签协议独立复核候选；区分 confirmed、not reproduced、not testable、safe/fixed、known FP、unknown，并记录证据和理由。not testable 不改成 FP。
4. 为 NULL 建立独立的 vulnerable/fixed/safe/unrelated controls，覆盖早返回、短路、别名重新赋值、错误分支、同名 decoy、宏/模板和跨函数调用。源对象固定到 commit/blob/hash；真实案例盲标时隐藏开发者预期和规则分支。
5. 独立复跑 D 线提供的 pinned before/after 工件；如无法复跑，记录命令、环境、差异与阻塞，不根据作者摘要补结论。
6. 分开核对四种数：raw observation rows、within-repository root-cause clusters、cross-repository identical-source clusters、human review outcomes。抽样加权估计必须说明方法和不确定性；不得将候选行下降用作验收指标。

完成标准：样本框、抽样种子、原始行键、纳入概率、标签依据和盲标流程可复现；历史 controls 完整；每条候选保留原始位置和证据引用；四类计数互不混淆；输出分层结果、主误报形状、unknown/blocked 与下一步。提供机器可读数据和人工可读报告。

约束：使用独立工作目录与测试结果目录，不修改 detector/catalog/UI/schema；不把 D 线 fixtures 当真实案例或产品证据；不为提升指标重标或删样本；不 push/merge/改 PR 状态。每次续跑先核验固定输入和证据，再更新本任务树中的状态与阻塞项。
```

## 持续执行检查点

当前 Codex Goal 是本任务的持续目标记录。每轮开始核对最新可用远端基线、工作树状态、进行中的开发/测试子项和阻塞依赖；每轮结束记录已完成事项、精确输入对象、实际命令和结果、unknown/partial、下一动作与责任线。D 线与 T 线独立推进，最终由 T4 对 D 线输出盲验和 pinned 对照收口。若目标尚未满足，不把阶段性结果标记为完成。
