# B/IPC 线开发与测试任务树（2026-10-20）

## 基线与状态

- 本轮先用 GitHub API 只读读取 `branches/main`，再成功执行 `git fetch origin --prune`。远端、tracking ref 和五棵 B 线工作树均为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`；基于该 fetch 核实的 main 完成了定向套件复跑。未把主工作区落后分支 fast-forward/rebase。
- 远端分支端点、SHA、tree、五棵工作树 HEAD、tracking ref 与 fetch 结果的机器可读记录见 [main branch verification](ipc/b-line-20261020/main-branch-api-verification-20261020.json)。
- 本轮 T7/D5 独立测试线红绿回放、精确基线与测试隔离结果见 [T7/D5 replay](ipc/b-line-20261020/t7-d5-replay-20261020.json)。
- 本轮额外运行的全仓套件在 Windows Anaconda 环境不通过；具体失败环境及范围见 [full-suite environment result](ipc/b-line-20261020/full-suite-windows-environment-20261020.json)。B/IPC 定向测试仍通过，不能据 Windows 全仓结果宣称全仓验收。
- 在完成 WSL 前端构建并移除不属于 IPC lane 的 D3 owner-only 测试副本后，全仓 WSL2 复跑 1151 项、12 skipped、0 failures/errors；`check_change_scope.py --lane ipc` 无违规，`git diff --check` 干净。详见 [最终全仓复跑记录](ipc/b-line-20261020/full-suite-final-replay-20261020.json)。
- 全仓运行后最后一次 Git fetch 重试又遇 `:443` 连接失败；随后再次读取 GitHub `branches/main`，返回 SHA 与五棵 worktree HEAD 和 `origin/main` 一致，均为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`。fetch 传输间歇性，不影响这次已核实基线；下一轮仍先重核。
- main 当前 IPC Detector 为 `0.12.12`、模型 `oh-ipc-2026.10-v32`。主线记录的最近整合验收是 2026-10-19：全仓 1016 项（5 skipped、0 failed），IPC 定向 315 项、AST 6 项通过。这些是历史基线数字，本任务未重跑。
- 原工作区 `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit` 在 `codex/a-line-scanner-regression-20261018`，相对 `origin/main` ahead 7 / behind 93 且有大量未提交改动。保留不动。本任务工作区为 `D:\openHarmonyScanner\worktrees\b-ipc-plan-20261020`，分支 `codex/b-ipc-development-test-20261020`，初始干净、基于上述 SHA。
- 旧任务树 `research/coordination/parallel-20261017/B_IPC.md` 和历史 IPC 交付记录描述的是 0.8 时代，提供问题线索，不代表 v32 现状。本树先把当下可直接核验的 DATA-01 误报机制作为第一开发/测试闭环；AUTH-01 另行设计与验证。
- 本任务的持续目标已建立在 Codex Goal 中，状态 active。未启动第二层模型的开发或外发；LLM 只负责对静态层少量候选作具体漏洞/反例复核。

## 目标和输出原则

静态 IPC 层只在源码证据足够具体时输出候选。每条候选绑定 entry、敏感操作/数据流、触发路径、实际源码位置和未决证据；分析无法判定时保留 unknown/limitation，不猜安全、不扩大规则以追求命中数。候选交给第二层模型时，要求模型逐条核源、尝试反证、说明仍缺的产品证据，不允许模型自报结论改变 `candidate` 状态。

当前生产代码已经提供 `candidate_cwe`、`consequence_cwe/impact`、源码位置和 `evidence_obligations`。本计划优先完善检测正确性与验证协议，不改公共 schema、API/Worker、模型调用链或准入语义；若发现必需的公共契约缺口，先提交集成申请。候选输出遵守五项约束：source 身份与规则/profile/scope 可核验；位置与机制证据锚真实存在于 pinned 源码；entry/授权/支配/攻击者控制/影响分项记录，无法证明的保持 unknown；只按相同来源+entry+effect/root cause 去重，不跨边界泛化；升级为 confirmed/reportable 是独立证据 gate，模型意见不能单独升级。

## 任务树与依赖

```text
B0 固定基线/运行环境/候选身份摘要
├─ D1 DATA-01 边界与容量语义（开发，优先级 P0）
│  └─ T1 DATA-01 独立正/修复/安全/未知回归（测试；向 D1 反馈）
│     └─ D1a 根据 T1 反例修正或撤回实现
├─ D2 AUTH-01 relay 谓词形态的小步候选（开发设计，P1，待 T2 证据后开工）
│  └─ T2 AUTH-01 独立守卫/不守卫反例矩阵（测试；先于 D2 实现）
│     └─ D2a 仅对能证明控制流支配的形态开放，其他保持 candidate/unknown
└─ T3 固定源码组件/holdout 对照与候选复核契约（独立测试/裁决，P1）
   └─ L1 每条静态候选的第二层大模型结构化审查提示词（只写提示词，不开发模型）

验收收口：T1/T2 对 D1/D2 的代码和测试独立复核 → T3 报告候选移动与局限 → 负责人集成前核对来源/范围/测试。
```

开发与测试各自持有结果：开发线提交实现与自测；测试线审查假设、添加/运行对照并给出 fail/FP/FN 反例。每轮开发变更后测试线先反馈，再由开发线修订或解释；不能由开发者自评替代 T 线结论。

### D1 — DATA-01 的安全长度/容量语义（P0，开发与独立复核闭环）

**已有代码事实**（固定于基线 `db77164...`）：

- `src/ohscanner/detectors/interface/analysis.py` 中 DATA-01 copy 检查位于 `action` 的约 1565–1575 行；只有已知 `capacities` 中的目标容量与 `state.upper` 匹配，且长度键在 `state.lower` 中时，才抑制 `ipc.parcel.copy-range`。
- 二元比较建模约 2146–2152 行只把 `n < 0` 的条件识别为下界谓词；`n <= 0` 会落到上界路径。fail-fast `if (n <= 0) return` 后的正常路径因此缺少非负事实。
- 局部容量仅在约 2487–2491 行数组声明时登记；`new_expression`（约 2173–2178 行）返回 `UNKNOWN`，没有为同作用域 `new T[n]` 记录容量。
- 现有 `tests/test_ipc_data_flow_rules.py` 与 `tests/fixtures/ipc/data01/manifest.json` 覆盖数组容量、无关上界及正/修复样例，但不覆盖 `<= 0` fail-fast 与 `new T[n]` 容量配对。

**候选实现边界**：只在当前函数内、同一 parcel-derived length 变量可追踪时识别 `n <= 0` 的 fail-fast；只在目标指针由同一作用域明确的 `new T[n]` 建立且长度表达式与 copy 长度键完全一致时，将容量绑定到该目标。不得从裸指针参数、变量名、注释、跨函数猜测容量；不匹配的别名/算术/分配器形态留给 unknown 并保留候选/义务。先加测试证明，再实现最小改动。若当前候选字段没法表达 unknown，写明现有 limitation 能否满足，公共契约变更另行申请。

**交付**：最小代码 diff；测试矩阵/fixture manifest；现有 IPC 全套定向命令的实测结果；候选身份 before/after；保留的 unknown 与限制；开发线对测试线反例的逐项答复。

#### 当前实现与开发侧验证（2026-10-20）

- 对 `n <= 0` 的 fail-fast 路径补充非负下界事实；精确本地 `new T[n]` 绑定容量，只在 copy 长度键完全相同时用于容量证明。
- 对请求长度重赋值、`n++/--`、相关未知函数实参及可识别的非 const 引用 helper 调用失效旧 range/allocation 事实；对无关参数保持不变，避免扩大误报。
- T1 首轮独立复核发现分配后 `n++` 会残留旧容量证明；D1 已修复并加入回归。开发审查随后发现 `n += 1` 会丢失 Parcel taint、绕过候选发射；D1 已把复合赋值改为保留 request taint 并清除旧界限/容量事实。后续复核覆盖显式地址调用、引用/指针别名、先声明后建立 proof、指针重绑定、引用写回、`*p = ...`、`p[i] = ...`、二者 compound 写回及 shadow alias；D1 以 State 路径状态跟踪 alias origins，join 时合并可能 origin，未知指针参与 mutating call 时失效所有相关 request proofs。const pointee alias 安全控制不丢容量证明。
- 开发侧最新结果：`python -m unittest discover -s tests -p test_ipc_data_flow_rules.py -q`：52 tests，OK；`python -m unittest discover -s tests -p test_ipc_*.py -q`：343 tests，47 skipped，0 failed。unknown branch、shadow alias、简单及复合 indexed/pointer 写回均经 T1 复核；开发侧回归不替代后续 AUTH-01 与候选身份验收。

#### 结构化 vibe coding 提示词 — D1 开发线

> **角色**：OHScanner B/IPC 静态检测开发 Agent；只负责 DATA-01 局部长度和容量模型。
>
> **基线**：先确认当前 checkout SHA/dirty 状态；本任务起点 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，Detector `0.12.12` / model v32。若已漂移，停止改动并报告差异。
>
> **目标**：在 `ipc.parcel.copy-range` 中仅补足有源码证明的 `if (n <= 0) return` 下界和精确 `new T[n]` 本地容量绑定，消除有正/上界/相等容量事实的误报，同时不抑制真正越界候选。
>
> **先做**：阅读 `AGENTS.md`、IPC 方法卡、`analysis.py`、DATA-01 fixtures/tests；把 AST 形态、现有 refine 行为、scope 及候选变化写成短设计记录。新增/调整测试先于实现。
>
> **必须覆盖**：`n <= 0` fail-fast 与上界检查后的正常 copy（安全）；同路径缺少下界、缺少上界、容量不等于 copy 长度（候选）；固定分支（安全）；裸指针、别名/算术分配、解析失败或跨函数目标（unknown/不得凭猜测抑制候选）。`int n`、有符号语义及早退支配关系需被验证。
>
> **禁止**：编辑其他 detector/规则家族、公共 schema/API/Worker/catalog、测试结论/历史报告；放宽 evidence gate；将 fixture 通过称为真实漏洞准确率；为了零候选推广容量到未知指针；改共享工作区或覆盖既有 dirty 文件。
>
> **交付**：实现 diff、精确 argv 和逐条真实结果、fixture 正/修复/安全/unknown 表、候选移动清单、尚未覆盖语义、对 T1 独立反馈的逐项回应。按所有权运行 scope check；若缺依赖或共享契约，记录最小集成请求，不越权改动。

### T1 — DATA-01 独立测试与反例（P0，最终复核通过）

测试线先构造独立测试，不复制 D1 的实现逻辑。至少包括：

1. 正例：parcel 长度缺少下界/上界或容量不匹配，必须产生 `ipc.parcel.copy-range`。
2. 修复例：`n <= 0` fail-fast + 与 `new T[n]` 完全相同的 `n` 上界约束，必须不产生该候选。
3. 安全反例：`n <= 0` 但之后存在可达负值路径、检查在 copy 之后、检查其他变量、copy 长度为变换表达式、目标容量来源不同，必须保留候选或 limitation。
4. Unknown：pointer 参数/跨函数别名/不同 allocator/解析不完整，不得因猜测为安全；若当前 schema只能显示 candidate+义务，应精确断言这一点。
5. 同时验证其他规则族 finding 不因 bound/refine 改动而无故消失，特别是路径分支与短路表达式。

**验收**：所有测试从仓库根目录用 Python 模块/测试发现方式运行；两侧控制均断言；将每个失败按假设、最小修复建议回馈 D1。需要独立真值的语料不可用 fixture 替代并声称 precision/recall。

#### 结构化 vibe coding 提示词 — T1 测试线

> **角色**：独立安全测试 Agent；审查 DATA-01 对 Parcel 派生 copy 长度的静态分析。与 D1 开发者分工独立。
>
> **基线**：`db77164fdc2af0da02e4d3efc056d84694fd68e8`，IPC `0.12.12` / model v32；记录 checkout、hash、命令和原始输出。先读 detector 与既有 fixtures，不读取 D1 未提交实现假设作为测试真值。
>
> **目标**：验证 D1 是否只在路径控制、长度变量、目标对象、容量表达式均有源码证据时移除候选，并能保留缺界限、错容量和不透明别名的候选/unknown。
>
> **执行**：设计独立 positive/fixed/safe/unknown matrix；先对基线跑并保存失败/通过快照，再对 D1 head 重放；源文件片段与候选逐条比对。失败时给开发线最小可复现 fixture、预期与实际、建议语义，不直接替开发线改分析器。
>
> **验收**：测试从仓库根可运行；至少正/修复/安全/unknown 四类；核对报告规则 ID、行号、path/message/obligations；运行 IPC 定向测试（`python -m unittest discover -s tests -p test_ipc_data_flow_rules.py -v`，按环境使用项目指定 Python）；交付清楚区分通过、失败、skip、未执行。不得把合成样例称为真实漏洞或 precision/recall。
>
> **约束**：不改 detector、policy/model、UI/schema/API；不对外发源码；不更改主线状态或测试真值。每轮测试结果必须给 D1 反馈，开发修订后复测直到矩阵通过或留有明确 blocker。

### D2 / T2 — AUTH-01 relay 守卫谓词（P1，开发与独立复核闭环）

固定基线的 `relay_guard`（约 1767–1834 行）只对同文件一跳、原样传入入口参数、顶层 `if` 比较已接受 descriptor、mismatch 分支退出且比较早于 switch 的形态 credit 守卫。该范围保守，形态以外保留候选。历史 2026-10-17 测量里出现过谓词守卫误报，但其来源早于当前 v32；T2 必须先在最新代码和 pinned source 上复核是否仍存在，不得照搬旧数字。

T2 先提供两侧源码对：真实受守卫的谓词 helper、相似但没有真正守卫的 helper、错误 descriptor、检查晚于 dispatch、参数被替换/跨文件/非唯一实现。只有 T2 证明一种窄表达式具有控制流支配时，D2 才实现识别；如果语义不唯一，保持现状并记录 partial/unknown。

**T2 结果（2026-10-20）**：基线 relay 定向测试 10/10 通过。现有控制包含 accepted descriptor、局部 token、无守卫、dispatch 后检查、拒绝分支不退出、嵌套检查、实参替换、错误接口。T2 发现合成窄形态 wrong-then-correct：dispatch 前先拒绝 IBar，再拒绝 IFoo；所有进入 dispatch 的执行均通过 IFoo 守卫，但现实现停在第一处比较，仍报告候选。未证明 pinned OpenHarmony 产品源存在该误报，不能称真实产品漏洞。

**D2 修订与回归**：在隔离 branch `codex/b-d2-auth01-20261020` 上仅调整 relay guard 的 top-level if 检查选择；遇错误接口先保存诊断并继续，找到当前接口且 mismatch 分支直接退出、且后续仍有 dispatch 时才 credit。加 wrong-then-correct fixed fixture；wrong-only、拒绝分支继续、dispatch 后检查仍是 candidate。开发侧 relay 11/11、全 IPC 316 passed / 47 skipped、owner IPC UTF-8 模式 12/12；`git diff --check` clean。T2 独立最终复核通过。剩余 limitation 仍限同文件一跳及 top-level 检查，不是通用 CFG dominance。

#### 结构化 vibe coding 提示词 — T2 AUTH-01 测试线

> **角色**：独立 IPC 边界测试 Agent；复核 `AUTH-01 ipc.relay.descriptor-boundary` 在最新 main 的候选和消除条件。
>
> **基线**：完整 SHA `db77164fdc2af0da02e4d3efc056d84694fd68e8`，不是旧 B worktree 的 0.8 交付。核对 `analysis.py::relay_guard` 和 `tests/test_ipc_relay_guard.py`。
>
> **目标**：判断现有一跳 relay guard 是否误报源码可证明支配的谓词 helper；构造最小成对反例供 D2 开发者，不先假定应扩规则。
>
> **矩阵**：accepted descriptor + 拒绝错误 descriptor 的正守卫；无比较、错误接口、只记录不退出、守卫晚于 dispatch、嵌套不可证形态、实参被替换、跨文件/不唯一方法的反例；对每条断言候选应有/无及理由。
>
> **验收**：从仓库根运行 `python -m unittest discover -s tests -p test_ipc_relay_guard.py -v`；记录基线与候选 head 的差异、实际源码来源/hash、调用路径限制。只有 pinned 源码和静态调用路径可复核的现象才提为开发缺陷。不得将静态候选等同产品可达/可利用。
>
> **反馈**：向 D2 提供独立 fixture 与支配证明/反证；若同一语法具有双重含义，要求保留候选并附 limitation，不建议 blanket suppress。

#### 结构化 vibe coding 提示词 — D2 AUTH-01 开发线

> **启动条件**：只有 T2 给出可复核的同文件/有限跨过程守卫谓词及对应反例后开工；若 T2 没有发现 v32 仍存在的具体漏判，本项标记 no-change，不强行开发。
>
> **目标**：仅为 T2 证明的一个形态补控制流推理，使 descriptor check 在敏感 dispatch 前实际拒绝不匹配请求时才 credit。
>
> **不变量**：错误 descriptor、检查后 dispatch、继续执行分支、替换参数、跨文件/重载不唯一或 unresolved identity 均不能让候选消失；unsupported shape 保持 candidate/limitation。
>
> **工作流**：先固定成对正/固定/反例 fixture 与最小设计，再改代码；运行 relay 定向与完整 IPC 测试；提供 source location、候选 before/after、unknown 保留情况。T2 独立复核后修订。
>
> **约束**：不扩写全局 descriptor trusted names；不弱化当前结构化守卫；不改公共契约/版本状态；不得以候选数下降宣称精度提升；未获独立测试确认不请求集成。

### T3 / L1 — 源码候选与第二层复核契约（P1，字段与准入核验完成；L1 提示词已定）

T3 对新 Detector 结果只使用固定 repo/commit/tree/blob 或 snapshot hash、detector/model/rule versions、scope、candidate source location/path、coverage/parse state、evidence obligations 和现有 controls。需区分静态候选、confirmed/reportable 与 unknown，不给零候选安全断言。建立固定 pinned 组件上候选身份 before/after 表；将规则变化、候选新增/移除、覆盖变化分开。独立标注/holdout 缺席时，不计算或宣称 precision/recall。

**T3 结果（2026-10-20）**：仓库现有身份/报告边界已核对：v2 候选要求完整 repo+commit/tree/snapshot/profile、detector/rule 版本、文件/blob/source hash 和可验证位置；hash/source mismatch 拒绝绑定；缺 identity quality 或 incomplete coverage → unknown。保留 legacy diagnostic id，身份比较添加稳定 `finding_identity_id` 和精确 observation `occurrence_id`，不能退化成 message/line 比较。第二层最多按规则取少量 source-bound 候选，需带 entry→sink 证据链、parse/coverage、obligations 和 fixed/safe controls；模型意见不升级 confirmed。holdout `research/evidence/interface/ipc/high_recall_holdout_20261018/manifest.json` 为 `not_established`、`frozen=false`、每 family independent positives 为 0，因此只报告 regression/control/replay 与候选差异，不报 precision/recall。

#### 结构化 vibe coding 提示词 — T3 候选身份与来源线

> **角色**：安全检测证据/报告契约审查 Agent；只读，不开发第二层模型。
>
> **基线**：固定仓库 SHA `db77164fdc2af0da02e4d3efc056d84694fd68e8`；同时记录 D1/D2 各自 branch、工作树状态、detector/rule 版本与测试结果，不把未提交分支当作 main。
>
> **目标**：给每条候选定义可复验的源码绑定、coverage/parse 状态、unknown 与 occurrence/stable identity；制定 before/after 对照表，使规则变化、观察变化和覆盖变化分离。
>
> **核验步骤**：阅读 contracts/identity/report/coverage 实现与现有 evidence manifest；验证 repo+commit/tree/snapshot/profile、detector/rule version、file/blob/source hash、line/byte range 的绑定关系；列出缺字段/不匹配/ambiguous/incomplete coverage 的拒绝或 unknown 行为；为 L1 每候选复核定义 source excerpt、entry→sink、trigger、obligations、控制样例与版本元数据输入。
>
> **交付**：候选身份字段映射表、拒绝/unknown 门槛、固定源码 before/after 表模板、最多每规则少量高置信候选筛选条件、holdout/独立标签状态与指标边界；每个事实给文件位置和来源。合成 fixture 只能证明规则控制，不是产品漏洞真值；holdout 未建立时不计算、不暗示 precision/recall。

#### 结构化提示词 — L1 第二层大模型逐候选复核（只写提示词，不开发模型）

> **身份**：你是 IPC 安全代码审查员。只审查给定静态候选是否存在可证的安全缺陷；不得补写不存在的源码事实，不修改代码，不运行未授权命令。
>
> **输入**：每次只含一个候选及其 pinned 源码摘录/相邻调用上下文、精确 repo+commit/tree/blob/source hash、scanner/detector/model/rule 版本、scope、parse/coverage 状态、entry/dispatch 绑定、trigger path、输入来源、敏感 sink、候选 CWE 与 consequence、evidence obligations、同规则 fixed/safe/unrelated 控制、已知测试结果。
>
> **逐步任务**：1) 核对引用行与候选位置；2) 重建 entry→guard→sink 的路径与分支支配；3) 标出不可信输入和必要前置权限；4) 尝试用实际条件、权限门、固定版本/安全控制反证；5) 说明越界/泄露/权限影响是否由代码证实；6) 分开列出事实、推断、未知及最小补证请求。
>
> **输出 JSON**：`candidate_id`, `source_binding_verified`, `mechanism_assessment` (`supported|refuted|insufficient`), `counterevidence`, `path_summary`, `attacker_control`, `guard_and_privilege`, `concrete_effect`, `product_reachability`, `impact`, `unknowns`, `confidence`（需理由）, `next_evidence`。每项事实带文件:行与原文短摘录；不能核对时写 unknown。
>
> **结论约束**：模型回复只是分诊意见，不能自行把 `candidate` 升为 confirmed/reportable，也不能以未发现反例判 safe。产品入口、真实权限边界、具体 CIA 影响、受影响版本/补丁须有各自独立证据。输出 `insufficient` 时明确最小缺证，不用泛化建议。

## 执行中的 Agent 与回馈顺序

- `/root/b_dev_review`：DATA-01 / AUTH-01 开发候选审查。
- `/root/b_test_review`：独立测试矩阵与回馈流程审查。
- `/root/b_static_candidates`：少量静态候选及第二层审查契约审查。

收到三方结果后由负责人合并到本任务树，逐条核对与固定代码证据；意见冲突保留到决策记录，不投票替代代码证明。之后先完成 T1 的独立 matrix，再决定 D1；T2 若证实当前 AUTH-01 缺口，再开 D2。此文件是计划及交付跟踪，不代表开发/测试已经通过。

## 固定源码重放（T3 验收证据，2026-10-20）

- 输入源：OpenHarmony `openharmony/communication_ipc`，本地 mirror 的 `gitcode/master` 对象解析到 commit `5903fd5f7332a427cb3f6915b0202ee5c76c63b5`、tree `0f7129fc37dcc38a0abd6c0ebdd5cbd1ff30d4ac`；两版报告 snapshot SHA-256 均为 `4a77a83643aecdef6214af80b1472ff8ebf1050eb4f48fa0b0935c4791babb9d`。源码扫描使用固定 Git index，不修改源码 checkout。
- 扫描：基线代码 `db77164fdc2af0da02e4d3efc056d84694fd68e8` vs 集成工作树 D1+D2；同一个 IPC detector `0.12.12`、同一 scope（1,389 tracked entries；697 selected source files；8,047,194 bytes）。两报告均 `completed_with_limitations`。
- 候选对照：基线/集成各 14 条，逐项 observation 精确一致：`ipc.relay.descriptor-boundary` 12 条，`ipc.auth.missing` 2 条；新增 0、移除 0；DATA-01 候选 0。此结果只表示这一个快照上没有观察移动，不证明准确率、漏洞真值或安全性，也不表示 DATA-01 修复没有价值（该源码范围未触发此规则）。
- 覆盖限制：IPC detector partial；660 applicable files 中 442 analyzed、218 partially inspected；源解析 complete 442、partial 218、not_run 37；另有 3 个非 UTF-8 JS 文件跳过、TS/JS grammar 不可用、未做宏展开、产品 manifest 未锁定。Holdout 未建立、冻结为 false、各 family 独立正例数为 0，不报告 precision/recall。
- 身份：**pre-D5** baseline/integrated 报告的 stable/occurrence identity ID 均为 null/unknown（stable 缺 AST fingerprint、rule lineage、symbol identity；occurrence 缺 rule version）。当时以 legacy diagnostic ID + 文件/行/rule/source SHA 做精确观察对照，不宣称跨版本稳定身份。D5 后同一快照的身份 metadata 重放见下文。pre-D5 原始证据见 [固定源码重放摘要](research/deliveries/ipc/b-line-20261020/fixed-source-replay-summary.json)、[基线报告](research/deliveries/ipc/b-line-20261020/communication-ipc-baseline.json)、[pre-D5 集成报告](research/deliveries/ipc/b-line-20261020/communication-ipc-integrated.json)。

## 后续并行任务（连续目标的下一轮）

| 线 | 任务 | 开始条件/反馈接口 | 验收 |
|---|---|---|---|
| D3 | SOURCE-COVERAGE-01：补齐/明确 IPC 扫描的解析缺依赖与 partial 语义，优先提供可复现依赖环境和 coverage accounting；不静默扩大扫描语义 | **D3/T4 coverage invariant 回馈闭环完成**：D3 仅增 `tests/test_ohscanner_m1.py` 合成 integration regression，不改 production/report/API/schema；T4 变异确认精确 paths、无重复、source_sha256 keys、inspected/unexamined 对应和 `status` 断言均可捕获错误。新用例 1/1；未发现 production bug。fresh fetch 两次均 GitHub 443失败，tracking ref 仍为 db77164... | 同一 pinned source 重放 coverage 字段稳定；无依赖时准确标 incomplete；不声称安全或准确率 |
| T4 | 独立覆盖与报告审查 | **独立审查通过** `/root/b_test_review`：两个 JSON coverage、source parsing、scope 和候选 observation 都逐字段相等；计数守恒，具体结果见当前状态段 | 独立复现 coverage counts 和 unknown gate，反馈 D3；修订后重放 |
| D4 | AUTH-02：多 dispatcher/helper 控制流支配建模（候选范围，不默认实现） | **本轮 no-change**：T5/T6 matrix 未发现已覆盖控制流关系中的实现缺陷；不扩通用 CFG | 仅当后续 pinned 产品源码/新对照证实新的不支配抑制问题，且 fresh fetch 核实基线后重开 |
| T5 | AUTH-02 控制流测试 | **T5/T6 matrix 闭环通过**：8 个 fixture/逐 sink tests 在固定 baseline 与 D2 两侧均 8/8；T6 独立 D2 复跑 8/8，且 relay suite 11/11。条件 mismatch return 路径保留 entry/sink candidates；无条件 mismatch return 消除 findings；wrong/correct descriptor 顺序、guard 位于多个 switch 间、branch-only 和 ambiguous helper 均按逐 sink oracle 工作。仅新增测试夹具，不改 detector。AUTH-02 caller authorization guard 与 descriptor guard 分开 | D4 后独立复跑，错误守卫和不支配守卫不丢候选 |
| L2 | 14 条候选的第二层分诊 | **AUTH-02 两条及 AUTH-01 两条 source-bound 候选已完成分诊**；AUTH-01 `ca88225a02a0fe72` 对窄主张为 `refuted`，`1831439990fdf6c8` 为 `insufficient`；另一个候选经 source-bind 后被独立测试线判定与 AUTH-02 `be13fd9ad5bb5f78` 为同 effect 重复，不另送 L2；其他未绑定候选不送审，finding identity 层仍 unknown | 回答必须 `supported/refuted/insufficient`，每个陈述引证 pinned source；模型意见只作分诊，不能自动升级 |
| T7 | Finding identity 的 fail-closed 边界 + IPC rule-version identity 集成 | **T7 完成并按本轮 API 核实的 main 复跑**：clean test worktree 仅保留身份测试；T7 定向 2/2、identity suite 21 passed / 1 skipped。D5 专项在 baseline 按预期 2 failures（缺 map 与 finding version）；通过 `PYTHONPATH` 由独立 T 文件导入集成源码后 2/2 通过。T-only 与 integration HEAD 都是 `db77164...`，测试没有拷入集成树 | missing version 不产生 occurrence/effect 结论；规则 inventory 完整；真实新 observation 使用显式版本得到 bound occurrence identity。stable cross-version identity 未由这些测试证明 |
| D5 | IPC `rule_version` 供值 | **实现与回馈闭环完成（未提交）**：`models.py` 显式登记 21 个版本 `1.0.0`（19 个 IMPACT_BY_RULE + 2 个 detector-only ID）；`detector.py` 六类 finding 构造按 rule ID 查表，未知 ID `.get()` 留 None。独立 source audit 核对所有构造路径。只变身份 metadata，不改 schema、legacy ID、检测语义；代码工作树含 D1/D2 改动且绑定本轮远端核实 SHA `db77164...` | 本轮独立 T 线先复现 baseline 红（D5 2 failures），集成源码绿（D5 2/2）；T7 identity 在 baseline 与集成均 21 passed / 1 skipped；21 项映射、未知 ID None、真实 finding bound occurrence 通过。另有历史 IPC 352 passed / 47 skipped、source binding 25、C++ runner 5、owner IPC (PYTHONUTF8=1) 12 passed；同源报告 14/14 observation 不变，stable 仍 unknown。 |

开发与测试必须保持独立工作树/结果并往返反馈。D3/T4、D4/T5、T7/D5 已在固定基线上闭环；本轮已用 GitHub API 复核 main 并启动 T7/D5 重放。L2 只在来源绑定且未与现有路径/effect 重复时并行启动。每轮记录远端 `main` SHA；若主线漂移，基于新 SHA 重建验证基线，不移动原始 dirty checkout。本轮 GitHub 443 仍阻断 Git smart transport，但 API 返回 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，与 tracking ref 一致。D5 改善 exact occurrence identity，不构成 stable identity、准确率或安全结论。

### T7/D5 结构化提示词与反馈协议

**T7 测试线提示词（独立先行）**：在固定 pinned commit 上只改身份测试。先核对 `identity.py::occurrence_identity` / compare 以及 `runner.py` source binding；测试缺失和空 `rule_version` 时 occurrence 必须 unknown，双侧缺失不能成为 compatible/安全或效果结论；精确 source mismatch 要求 runner 拒绝绑定且不改写 hash；partial/failed/blocked coverage 对 absent/added 保持 unknown；重复 identity 不得静默折叠；只改 line/message 时 stable/occurrence 和关系按契约变化；v1/v2 historical `diagnostic_id` 不得回填/改写。优先运行 `test_a_ccr_03_finding_identity.py`、`test_contract_v2_source_binding.py`、`tests/detectors/test_cpp_runner_integration.py`，必要时运行 `test_ohscanner_m1.py`。对已有通过矩阵先标“现有覆盖”，新增项只有在精确 oracle 独立于实现代码时采用。每条失败反馈给 D5，附最小复现和预期/实际；测试本身通过不等于跨版本匹配已验证。

**D5 开发线提示词（已执行，下一次基线重放仍适用）**：仅在 T7 有复现的红测且能定义 rule-version 治理时启动。仅为 IPC detector 实际发出的每个 `rule_id` 提供显式语义 `rule_version`；版本变更表示该条规则判定语义变化，不得将 detector `0.12.12` 或 model `oh-ipc-2026.10-v32` 偷换成规则版本。此次首发版本为 `1.0.0`，未来语义变化需逐规则显式 bump；未知 rule 保持 unknown/缺版本。保持 schema、legacy IDs、检测语义不变；不生成 `rule_lineage_id`、symbol identity 或 AST fingerprint，不宣称 stable ID/跨版本关联。测试线红测后开发实现，T 线独立重放，另跑 IPC 和 identity 定向套件；冲突先复现再修订。

**T7 实测反馈（2026-10-20）**：clean worktree HEAD=`db77164fdc2af0da02e4d3efc056d84694fd68e8`，仅 `tests/test_a_ccr_03_finding_identity.py` 增加 45 行。省略 `rule_version` 的 compare 结果为 `unknown_version_boundary`；空字符串由于 occurrence invalid 返回 `unknown_identity`；两者均非 persistent，`vulnerability_effect=unknown`，source binding 为 unbound。定向 identity suite `21 tests OK, 1 skipped`，`git diff --check` 通过。额外负责人复跑同一 suite 得到相同结果。

**D5 TDD/集成反馈（2026-10-20）**：第二个 T-only 文件 `tests/test_ipc_rule_versions.py` 在 baseline `db77164...` 上先红：2 failures（无 map；真实 `ipc.auth.missing` finding 的 `rule_version=None`）。D5 在 integrated worktree 通过 `models.RULE_VERSION_BY_RULE` 覆盖 21 IDs，并在六种 finding 构造路径赋值。独立静态审查确认完整、无 detector/model version fallback。T-only 测试从独立工作树经 `PYTHONPATH` 导入集成代码，2/2 pass。负责人复跑 IPC 352/47 skipped、identity 19/1 skipped、source binding 25/25、C++ runner 5/5、owner IPC 12/12（需 `PYTHONUTF8=1`）；固定源码重放 identity-only 差异如 D5 摘要。D5 只在模型/detector identity metadata，不修改规则匹配或公共 schema；未知版本仍 fail-closed。本轮按 GitHub API 核实的 main SHA 再运行 T7/D5 定向红绿测试，详情见任务树当前轮结果。

## 下一轮审查结果（2026-10-20）

- T4 独立逐对象比较 baseline/integrated：commit/tree/snapshot、scope、source parsing、完整 detector coverage、audit source、无 detector 声明文件列表均相同；14 条候选按 diagnostic/rule/file/line/symbol/hash 逐项相同。计数守恒：tracked 1389 = non_source 689 + selected 697 + non-UTF8 skipped 3；selected parsing=complete 442 + partial 218 + not_run 37；37 个 not_run 对应 JS 27/TS 8/ArkTS 2。IPC applicable=660=C/C++ 442 analyzed+218 partial；partial 与 `unexamined` 路径集合相同，not_analyzed=0。此为固定报告内部完整性复核，不是准确率结论。
- D3 只读审查确认现有来源字段足够表达上述边界；后续优先报告层展示 scope skipped、全局 parsing 和 detector applicability 的不同分母，并加守恒测试，避免把 parser not_run 误认为 IPC 漏分析。代码实现先等主线 fetch 成功。
- AUTH-02/T5 已有 6 个冻结夹具（正确 guard 前置、guard 夹在 dispatch 间、guard 后置、wrong→correct 分隔 dispatch、branch-only guard、ambiguous helper），逐 sink 行断言。作者基线与 D2 均 6/6；独立 T6 复跑 D2 6/6，且 `test_ipc_relay_guard.py` 11/11。T6 另以内存探针验证 mismatch block 中条件性 return 不能当无条件拒绝：条件版保留 entry/sink candidates，无条件 return 版抑制；已要求 T5 补一因子 fixture pair 后再独立复核。递归/跨文件/宏/复杂嵌套尚未测试。D4 不启动直到增补 matrix 通过且新主线可 fetch。
- L2 packet 已为两条 AUTH-02 候选从 pinned commit Git blob 提取源码窗口，独立校验 file SHA-256、Git blob OID、报告 byte range；位置 `be13fd9ad5bb5f78` 和 `5501bf2ba361596d`。Packet 文件见 [AUTH-02 第二层复核包](research/deliveries/ipc/b-line-20261020/auth02-second-layer-review-packets.json)。只能说 source excerpt verified；identity stable/occurrence 仍 null/unknown。尚未调用第二层模型，也未判定为漏洞。
- 本轮重试 `git fetch origin --prune` 遇 GitHub 443 网络错误；上次成功 fetch 的 tracking ref 保持 `db77164fdc2af0da02e4d3efc056d84694fd68e8`。所有新审查均绑定该基线与固定 source commit。

## AUTH-01 L2 分诊结果（2026-10-20）

- `ca88225a02a0fe72`（DBinder `GET_PROTO_INFO -> ProcessProto`）：对“该路径是缺少 caller authorization 的应用接口分发”这一窄主张为 `refuted`。源码显示它是协议/会话元数据协商，并检查 session、UID/PID、bus name 与 DATABUS 类型；更广泛的 session 混淆、产品可达性和部署仍未知。
- `1831439990fdf6c8`（Taihe JS callback）：为 `insufficient`。源码证明普通 transaction code 可转发至 JS callback，但具体 ETS handler、产品注册/调用者可达性、descriptor 契约和具体敏感效果缺证；单独的 `GetLocalInterface` descriptor 比较不支配这条 callback 路径。
- 两条结论均不改变 scanner candidate 生命周期，不构成漏洞确认或安全结论。另有一条 AUTH-01 观察完成 source-bind 后被独立测试线判为 AUTH-02 同 effect 重复，不另送 L2；其余 9 条未 source-bind、未送审。stable/occurrence identity 仍 unknown，不报告 precision/recall。详见 [AUTH-01 源码复核包](ipc/b-line-20261020/auth01-second-layer-review-packets.json) 与 [AUTH-01 L2 结构化结果](ipc/b-line-20261020/auth01-l2-review-results.json)。
- 本轮没有新 fetch 成功；最后一次成功核验的 `origin/main` 是 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，GitHub 443 连接失败仍是外部阻塞。

## 下一批 AUTH-01 候选筛选与独立验包（2026-10-20）

- 静态线为最多两条尚未复核的 AUTH-01 relay 观察筛选后，只选择 `769b6c1f4853e5f5`（`DBinderCallbackStub::ProcessProto:118`）制作待审包。候选文件 SHA-256、Git blob OID、报告 byte range/excerpt 以及包内各 source excerpt 均与 pinned commit 对应；baseline 与 integrated report 各精确匹配一次。详见 [下一批候选包及审查处置](ipc/b-line-20261020/auth01-next-l2-packets.json)。
- T4 独立验包通过 source binding，但判定它与 AUTH-02 `be13fd9ad5bb5f78` 是同一 `ProcessProto → ProcessData → DBINDER_ADD_COMMAUTH` effect 的上游调用点，因此**不作为独立 L2 候选重复送审**。另发现 `IPCObjectStub::SendRequest` 对 `GET_PROTO_INFO` 直接虚调用 `ProcessProto`；packet 原有 `OnRemoteRequest` 入口措辞不是这条 base dispatch 的已证路径。已将这两个独立反馈写入 packet。没有 scanner 状态变化。
- 开发审查未发现值得新开 L2 包的高信号不同路线：death-recipient 属协议/生命周期分支；NAPI DUMP 路径被基类分发至受 local caller/UID allowlist 约束的处理器；ANI 指向失败错误分支；Taihe callback 已是现有 AUTH-01 L2 输入。尚未 source-bind 的候选不因“有待审”而自动扩大审查数量。该筛选结论只针对 pinned snapshot 的路由多样性，不是漏洞精度/召回结论。

## 当前验收状态

- [x] 已 fetch 最新远端并固定 main SHA；已保留原工作区 dirty 状态。
- [x] 已为 B 线建立基于最新 main 的隔离 worktree。
- [x] 已建立持续 Goal（active）。
- [x] 三个只读侦察 Agent 返回并核对结论；D1 和 T1 已按审查结果进入分支工作。
- [x] D1/T1 DATA-01 反例矩阵独立闭环。T1/开发审查指出的 stale capacity、复合赋值、未知函数地址参数、引用/指针别名、先声明后赋值、重绑定、shadow、直接/索引/复合写回等反例均已修复并回归；开发侧最新 `test_ipc_data_flow_rules.py` 52 passed、`test_ipc_*.py` 343 run / 47 skipped / 0 failed；T1 对最终 pointer compound write 复核通过。候选身份 before/after 归 T3。
- [x] D2/T2：T2 确认 wrong-then-correct narrow false positive；D2 在独立 worktree `b-d2-auth01-20261020` 完成最小 descriptor identity selection 和对照；relay 11/11、全 IPC 316 passed / 47 skipped、owner IPC 12/12，T2 最终独立复核通过。多 dispatcher 同函数（guard 前后各有 switch）仍保守列为限制；helper 本身可继续产生候选。
- [x] T3 固定候选来源/版本/覆盖/unknown 准入字段，核对 stable/occurrence identity 和 L1 逐候选提示词；holdout 未建立，不宣称 precision/recall。
- [x] D1/D2 本地集成验证：在 `b-ipc-integration-20261020` 固定基线上组合 D1+D2 diff；IPC 344 passed / 47 skipped、owner IPC 12/12、`git diff --check` clean。
- [x] T5/T6 新增 IPC tests/fixtures 在集成验证树执行：IPC 定向 352 passed / 47 skipped；T5 matrix 8/8、owner IPC 12/12、`git diff --check` clean。D3 invariant 1/1 只在独立 owner worktree 验证；ownership policy 禁止将 `tests/test_ohscanner_m1.py` 纳入 IPC lane，集成树已移除该测试副本。
- [x] 固定源码 baseline/integrated replay 与逐条观察对照已完成；本快照 14 条候选无增删、coverage 不变。稳定 finding/occurrence identity 仍 unknown，已单独标明，不作为已实现的稳定身份能力。
- [x] D5 identity metadata replay（在上述 pre-D5 replay 之后）：同一 OpenHarmony commit/tree/snapshot、scope、parse 和 coverage，14/14 diagnostic observations（排除 identity metadata）逐项相同、0 added/removed；14/14 source binding bound，14 个唯一 occurrence IDs 生成，stable IDs 仍 0/14、status unknown。摘要与原始报告见 [D5 replay 摘要](ipc/b-line-20261020/d5-rule-version-replay-summary.json) 和 [D5 集成扫描报告](ipc/b-line-20261020/communication-ipc-d5-integrated.json)。不表示跨版本稳定匹配、精度/召回或安全结论。
- [x] 为既有 L2 source packets 添加 D5 身份交叉索引，不重写已审输入或结论：目前 4 条 L2 评估候选 + 1 条已排除重复观察均能在新报告中通过 legacy diagnostic ID 找到 1.0.0 occurrence ID；stable identity 仍 unknown，scanner lifecycle 未变。见 [L2 identity crosswalk](ipc/b-line-20261020/auth-l2-identity-crosswalk-d5.json)。
- [x] T4 独立重算 D5 身份完整性：14/14 Git blob OID、源码 SHA-256、UTF-8 行字节范围、occurrence ID 重算及 D5 前观察字段一致；14/14 source-bound，stable identity 14/14 仍 unknown；5 条 crosswalk 均匹配。机器可读校验见 [D5 identity integrity check](ipc/b-line-20261020/d5-identity-integrity-check.json)。该核验限于固定源码快照与单次报告，不证明跨版本语义身份。
- [x] T4 独立 coverage/report 完整性复核完成；D3 设计边界已确定，未发现生产报告缺陷；API 已复核 main SHA 与基线一致。
- [x] 两条 AUTH-02 的 Git blob/source hash/byte range 摘录核验完成并形成 L2 输入包。L2 对 `be13fd9ad5bb5f78` 结论 `insufficient`（接收侧 transport UID gate 存在，但身份字段绑定关系未知）；对 `5501bf2ba361596d` 的“缺少 caller authorization”窄主张结论 `refuted`（源码有 local caller + UID 0/2000/1212 allowlist），产品策略/具体 Dump 效果仍 unknown。结论均不修改 detector candidate 生命周期；结构化记录见 [L2 分诊结果](research/deliveries/ipc/b-line-20261020/auth02-l2-review-results.json)。
- [x] AUTH-01 12 条 candidate 只择 2 条不同路径 source-bind（DBinder `ProcessProto` 和 Taihe JS callback）；独立 reviewer 确认 ID/hash/blob/byte range/excerpts/path 均相符，可进入 L2。
- [x] AUTH-01 L2 对两条 source-bound 候选完成只读分诊：`ca88225a02a0fe72` 对窄主张 `refuted`，`1831439990fdf6c8` `insufficient`；记录见 `auth01-l2-review-results.json`。无候选生命周期变更。
- [x] AUTH-01 下一批筛选候选 `769b6c1f4853e5f5` 的 source binding 与 excerpt hash 经 T4 独立验包通过；同 effect 重复 `be13fd9ad5bb5f78`，故不重复送 L2。packet 已记录 GET_PROTO_INFO 的 base dispatch 路径修正，不改变 scanner observation。
- [ ] 其余 AUTH-01 候选当前没有不同且高信号的已复核路线；只有获得可核验的 pinned source excerpt/新产品上下文后才继续。下一轮若新增路线，先核实当时的远端 main SHA，再决定是否开启修改。
- [x] T5/T6 AUTH-02 多 dispatcher matrix 已固定并通过双侧复跑；测试源保留在独立 T worktree，IPC integration 树含同路径回归副本用于完整套件。任何后续 detector 实现仍需通过该 gate 并基于已核验 main。
- [x] D3/T4 coverage 报告不变量闭环：D3 新用例 1/1，T4 独立内存变异确认五类错路径/计数/status 都失败；生产逻辑未改。
- [x] T7 identity fail-closed 回归补测：clean pinned-base test worktree 仅改 identity test 文件，身份 suite 21 tests OK / 1 skipped，负责人复跑通过；missing/empty `rule_version` 均不能产生 persistent/effect 结论。
- [x] D5 IPC rule-version 映射在 `b-ipc-integration-20261020` 完成：21 项显式版本，六种构造路径查表，未知 ID 仍 None；identity/source-binding/runner、IPC 与全仓套件通过。D1/D2/D5 合并改动仍未提交或推送；主线 SHA 已在本轮 fetch 后复核一致，后续由负责人决定拆分/提交。
- [x] 本轮 GitHub API 对 `branches/main` 的读取与成功 `git fetch origin --prune` 均确认 `db77164fdc2af0da02e4d3efc056d84694fd68e8`；五棵 worktree HEAD 和 `origin/main` 一致。T7/D5 独立 T 线在该基线上完成红绿复跑。记录见 [branch verification](ipc/b-line-20261020/main-branch-api-verification-20261020.json)。
- [x] 本轮 `git fetch origin --prune` 成功；远端 API、tracking ref 与五棵 B 线工作树一致为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`。前几轮的 443 transport 阻塞已解除；stable identity 仍 unknown。
- [x] 全仓 WSL2 验收：最终 B/IPC integration tree 在 `npm ci && npm run build` 后用隔离 Python 3.14.7 环境运行 1151 项，0 failures/errors、12 skipped；完整记录、SHA-256、环境偏差及范围检查见 [final replay](ipc/b-line-20261020/full-suite-final-replay-20261020.json)。Windows Anaconda 的较早失败仅留作环境对照，不作为验收结果。


## 本轮持续复核（2026-10-20，UTC 19:07）

- 最新 scanner `main` 经 GitHub API 核实仍为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，与 `origin/main` 和 B 线工作树 HEAD 一致；本轮 `git fetch origin --prune` 遇 GitHub 443 连接失败，因此记录为 API 验证成功、smart transport 未成功，不宣称本轮 fetch 成功。
- 产品仓库 `openharmony/communication_ipc` 的 master 锚点为 `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`。定向路径审查中 Taihe 仅新增 JS optional presence guard；ANI 为日志前缀调整；NAPI 为静态类型/日志改动。未发现新增的 descriptor check、不同 dispatch→effect 路径或 source-bound 高信号候选。本轮不修改 scanner 规则，不新增候选，不扩大发送 L2 的数量。复核范围及产品仓库本地 object DB 限制见 [product master source review](ipc/b-line-20261020/product-master-source-review-20261020.json)。
- 当前任务树执行状态：D1/T1、D2/T2、D3/T4、D4/T5/T6、D5/T7 均已闭环；没有新的满足开工 gate 的静态修复。保持“产品 source route 侦察”与“独立 source/effect、候选去重审计”两条并行线；任何前者提出的候选都必须先由后者独立验源/去重，再判断是否形成测试用例或 L2 输入。稳定 identity、precision/recall 和真实可利用性均不由本轮结论推断。

### 本轮并行执行卡

**D6 — 产品源码静态侦察（开发/候选线，不改 detector）**

> 角色：B/IPC 静态规则与源码路由侦察 Agent。每轮先记录 scanner main SHA 与产品仓库分支/commit；若 transport 失败，用权威 API 固定 SHA 并明确失败。只检查此前未审或有行为变化的 IPC dispatch/sink 路径，最多提交 2 条候选；每条必须包含 pinned 文件/行、entry→dispatch→sink、攻击者可控字段、effect、授权/guard 路径、source blob/内容 hash、未决项，以及和现有 `diagnostic_id`/effect 的去重检查。不得开发、改 detector、把日志/类型修订升格为漏洞、或为了候选数放宽静态规则。无新证据时明确返回 0 条。

**T8 — 独立测试/证据线（测试线，反馈 D6）**

> 角色：独立安全测试与 source-bound reviewer，不复用 D6 的判断当 oracle。逐条重算 source identity/excerpt/hash/行范围；从调用边和控制流检查 dispatch 到敏感 effect 是否真实、descriptor/UID/session 等 guard 是否支配；尝试反例并检查现有候选同路径/同 effect 去重。若 D6 提候选，给最小对照测试和 pass/fail/unknown 结论并反馈 D6；若没有候选，独立检查本轮目标路径是否只是重复/无行为变更。仅在绑定和独立性均通过后才建议构造 L2 packet；不直接改规则或改变候选生命周期，不声称真实精度/召回。

**反馈闭环与 L2 gate**：D6 输出 → T8 独立验源/反例 → D6 对每条反馈给修订或保留 unknown 的答复 → 负责人决定是否形成测试/开发任务 → 只有 source-bound 且非重复候选再进入既有 L1/L2 审查模板。D6 与 T8 并行侦察，候选裁决串行依赖 T8，避免自审。

- T8 独立复核补充：Taihe 与 ANI 两个当前文件 whole-file SHA-256/Git blob OID 与 D5 integrated report 的来源绑定值完全一致，表明这两个候选来源文件在既有扫描快照后没有内容变化。Taihe binding 为 `2527026b…` / `2c2e6db…`，ANI 为 `ea3b46ff…` / `6b3b9f54…`；原候选分别为 `1831439990fdf6c8`、`1ae68a66948e0021`。Optional presence guard 属 callback 空引用防御，不加 descriptor compare；ANI 改动仅日志前缀。未建立新候选。结论**不等于**对产品 master 全树重跑 scanner 或全树“零新增”。独立审查遇 GitHub API rate limit，且旧对象重建受本地 Git 配置/旧 raw URL 限制；详细哈希和限制记在 JSON 中。
- T8 独立另选 core `DUMP_TRANSACTION`：`IPCObjectStub::SendRequest → DBinderDumpTransaction → OnRemoteDump → virtual Dump(fd,args)`，旧候选 `5501bf2ba361596d`。当前 `ipc_object_stub.cpp` SHA-256=`554a27bf…`、blob=`22c3a682…` 与 D5 report source binding 一致，sink `Dump(fd,args)` byte `[5592,5629)`；到达 dump 前要求 local caller 且 UID 为 0/2000/1212，基类 `Dump` 仅日志并返回，具体输出效果取决于 subclass override。既有 AUTH-02 L2 已 refute“无 caller authorization”窄主张；具体 subclass/output、策略、reachability/confused deputy 仍 unknown。该候选已审，不重送 L2；这不是全树扫描。D6 独立线尚在执行，T8 暂未收到 D6 新材料，因此不能声称已完成候选逐条交叉反证。
- D6 收敛：**0 条新增且已 source-bound 的候选**。DBinderCallback `ProcessProto → ProcessData → DBINDER_ADD_COMMAUTH` 与 AUTH-02 `be13fd9ad5bb5f78` 同 effect；`DBinderServiceStub::ProcessDeathRecipient` 的 ADD/REMOVE 路径已在集成报告作为 `2dc3665b93253dce` / `2f37f269ff85f764` 记录，不能冒充新观察。Death-recipient 路径看起来值得后续重新 source-bind，但本轮 GitHub tree API rate-limit、Git 443 失败，不能独立给出当前 `bbb92db...` blob/OID、SHA-256、byte range；T8 正在独立核查 D6 去重和下一步 gate。没有改代码/候选状态，也未做全树扫描。
- T8 对 D6 做完独立 source/effect 交叉核验：从 current-anchor raw 文件重算 SHA-256/Git blob，与 D5 source binding 一致。ServiceStub 文件 `6583b7b2…` / `11927a92…`；CallbackStub 文件 `167272c9…` / `05dceaa7…`。`ProcessProto → ProcessData → DBINDER_ADD_COMMAUTH` 对应旧 `769b6c1f4853e5f5`、`1c15c945a529931b`、`be13fd9ad5bb5f78` 的同操作/effect，重复。Death-recipient ADD/REMOVE 当前锚点分别是既有 `2dc3665b93253dce` 和 `2f37f269ff85f764`，entry 为 `e5c3a944e38716fd`；不是新增观察，但此前未送 L2。D6 的“零新增”只适用于已查路径对比既有观察，不可泛化全树。建议后续为 death-recipient 身份绑定/滥用影响开一个窄 L2 复核，不据缺少局部 descriptor/auth 比较直接判漏洞。T8 source binding 过关，候选去重通过；L2 结论待定。

**L2 — Death-recipient 既有候选窄复核（已完成，不开发）**

> 角色：独立第二层漏洞审查 Agent。只评估当前 pinned source 已 source-bound 的 death-recipient observations：entry `e5c3a944e38716fd`、ADD `2dc3665b93253dce`、REMOVE `2f37f269ff85f764`。来源文件 `dbinder/dbinder_service/src/dbinder_service_stub.cpp` SHA-256 `6583b7b212eb8230ae234c54666bb1c9bdcffed898a3799d096d573a0422b9f2`、Git blob `11927a9291886f56211a3c775122b2462d6f1ddd`，锚点 `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`。具体问题：parcel 中的 process type、代理身份、权限和生命周期约束是否能支持可利用的 unauthorized/mis-bound death-recipient operation？必须给出源码支持与反证、攻击者可控输入、真实 effect、caller 可达性、缺失契约。将 `candidate`、`insufficient`、`refuted` 区分清楚；局部未见 descriptor/auth check 不足以证明漏洞。不得修改 detector、candidate 状态或把结论升级为 confirmed；缺身份绑定/调用者/产品上下文时给出最小待补证据。

**闭环**：L2 回答后，由 T8 按相同 pinned excerpts/source hash 独立核对其引用和反例；D6 对测试/证据反馈做逐条答复。仅源文件/具体主张核验过后更新 packet 和状态；无论结论如何，保持当前 scanner finding 状态不变。
- L2 对既有 death-recipient 候选完成窄审：结论 **insufficient**。主张限定为“若请求者可调用 `DBINDER_OBITUARY_TRANSACTION` 并提交 remote object，本地路径未将调用者/对象绑定到当前 stub session，可能干扰 callback/death-recipient bookkeeping”。源码确有按 transaction/processType 分流、读取非空 remote object 并 Add/Remove 映射；本路径未见 descriptor/UID/PID/session 比对。反证包括正常 ADD 创建本地 callback stub、REMOVE 从当前进程 `IPCProcessSkeleton` 取回既有 stub、对象键映射/重复插入拒绝、death cleanup；`ProcessProto` 有 UID/PID/session 校验，但 obituary 分支没有复用。实际影响最多是通知/生命周期状态干扰的可能性，未证明数据泄露、越权操作或 DoS。最小缺证：谁能取得并调用该 stub、transport 是否绑定 peer/session、remote-object capability 的所有权边界、能否提交他人 callback object 并改变映射。暂不确认漏洞、不创建 scanner 开发任务、不变更现有 finding 状态。T8 正在独立核对 L2 的调用链、控制与 limitation。
- T8 独立核验 L2 反证后同意 **insufficient**。正常 ADD 在客户端按 `IPCObjectProxy*` 保存并发送本地 callback stub；REMOVE 从本地 skeleton 取回同一 proxy 对应 stub；服务端 maps 以 remote object 为键，重复插入会失败，并由 death callback/服务清理路径移除。`ProcessProto` 的 UID/PID/session check 与 obituary route 分离，所以既不能当作 obituary guard，也不足以推断任意请求者可达。补充 pinned source SHA：`ipc_object_proxy.cpp` `4d1e2412…`，`ipc_process_skeleton.cpp` `cdffaaf0…` / blob `516fd9ef…`，`dbinder_death_recipient.cpp` `343fb2d7…` / blob `aad98ab9…`。若要提升影响主张，还需证明跨 peer 提交他人 callback stub 会造成可观察的误通知、错误清理或状态破坏，并排除正常生命周期行为。T8 无异议，无候选晋级或静态开发任务。

## 当前迭代：D7 / T9 / L2 调用权限与对象能力边界（2026-10-20）

### 状态和基线

- 成功执行 `git fetch origin --prune`。scanner `origin/main`、集成工作树 HEAD、计划工作树 HEAD 均为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`；不移动含未提交工作的集成树。
- GitHub 当前 `communication_ipc/master` 页面 `refInfo.currentOid` 为 `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`，与上轮 pinned source anchor 相同。`systemabilitymgr_samgr/master` 当前页面 SHA 为 `ffeb925dc593e90e0769c5f7215f00df284d0200`。SAMGR acquisition gate 与对象传输路径仍只作调用边界证据，不替代端到端可达证明。
- D7 静态线与 T9 独立测试线均完成；death-recipient 三个旧候选继续为 `insufficient`，本轮 source-bound 新候选为 0。详细结果和已完整复核的源身份见 [产品源码审查 JSON](ipc/b-line-20261020/product-master-source-review-20261020.json)。范围限于明确列出的 DBinder / SAMGR 路径，没有跑全树扫描。

### T9 独立测试与反证反馈

- `ReadRemoteObject` 对 `QueryDBinderCallbackProxy` miss 的 non-proxy 返回原对象；obituary ADD/REMOVE 仅做 null 检查后 reinterpret cast。该局部动态类型硬化疑点有源码依据。
- 单元测试注入本地 `IPCObjectStub` 后 ADD/REMOVE 返回错误，未证明 map 被改写或产生内存破坏；正常 `IPCObjectProxy` lifecycle 用例成功。parcel 随机字节和当前 stub-service mock fuzzer 都不能构造外部可达的 Binder capability。
- Binder 接收端对本地 binder object 校验其属于当前 skeleton，handle 解析为 proxy；DBinder 入站对象翻译拒绝普通 binder/handle 类型，session PID/UID/device/token 与 stub index 在 dispatch 前校验。该校验仅支持 DBinder 入站路径，不能未经调用链证明覆盖默认 invoker 的本地 `SendLocalRequest`。
- 尚无证据证明外部 caller 能取得他人 `DBinderServiceStub`/callback proxy，或提交对象能改变他人通知/cleanup 映射。因此不升级为 confirmed，不改 scanner finding 状态，不创建 exploit/漏洞修复代码任务。可把显式 proxy 类型校验作为产品防御性硬化建议，需由产品维护方另行确认行为兼容性。

### 下一轮任务树与并行提示词

当前是证据缺口驱动的条件队列。D8 与 T10 可并行完成各自调查；只有两线发现同一条可达、新颖、可观察的 effect，才启动 D8a 实现。若未满足，结论保持 insufficient 并转向一个新的、未覆盖 dispatch 路径。

```text
D8  静态/开发线：窄化下一条候选（只读侦察，不改 detector）
 ├─ T10 独立测试线：transport / object-owner 可达性与反例复核（并行）
 │   └─ D8a 条件开发：仅修复 T10 证明的 scanner precision defect 或明确产品硬化需求
 └─ L2：仅在 D8 与 T10 都 source-bind、非重复且存在具体 effect 时启动
```

**D8 静态开发线提示词**：

> 固定 scanner `db77164fdc2af0da02e4d3efc056d84694fd68e8` 与产品锚点 `communication_ipc bbb92dbb2f52aca54ab268307c9476ac1802f3ff`。在 death-recipient 已审路径之外，选取一条此前未审或本轮确认有代码变化的 IPC dispatch→敏感 effect 路径；先比对现有 findings 的 diagnostic/rule/file/effect 去重。最多交 1 条高信号候选，必须给 pinned 行、Git blob 与 SHA-256、可控输入、调用者可达路径、所有 guard 的支配关系、具体可观察 effect 和最小缺证。不要改 scanner 或产品代码，不把 cast、日志或缺少局部检查单独当漏洞；找不到完整链时返回 0 候选及下一条建议路径。

**T10 独立测试线提示词**：

> 独立于 D8 复核同一 pinned anchor 与候选路径。重新计算 source identity/hash/行范围；从 parcel 编码、object 动态类型/owner、Binder 与 DBinder transport、caller 权限及 session/stub-index 校验还原可达链。构造或查找现有正反例，明确测试覆盖的是本地合成对象还是产品可达 capability。验证 guard 支配敏感 effect、该 effect 会否影响其他身份，并按现有 diagnostic/effect 做去重。给出 source-bound `supported/refuted/insufficient`、最小测试或缺证及复现命令；不要修改 detector/findings。T10 结论回给 D8，D8 必须逐项答复；未获得独立阳性证据前不启动实现。

**D8a 条件开发提示词**：

> 只有 T10 提供稳定、独立、source-bound 的失败 oracle 后才启动。先让 T10 测试在固定 baseline 上红；只修复对应的候选精度缺陷或经维护方确认的类型硬化行为，不泛化 CFG、不放宽候选闸门、不改变无关 finding 生命周期。修改前列出预期不变量和反例；修改后由独立 T10 工作树重放红绿、运行最小相关套件和 scope/diff 检查。若测试无法区分误报与真实 effect，停止实现并返回 unknown。

**决策回路**：D8/T10 并行 → 对相同源码范围合并 source-bound 结论 → D8 回答 T10 反例 → 条件启动 D8a → T10 独立复放 → L2 只读审具体 effect。每轮记录远端 SHA 与产品 SHA；基线漂移时重新绑定，保留 dirty integration worktree。

## D8/T10 本轮结果与 D9/T11 后续（2026-10-20）

- **D8 结论：0 条新增候选。** `DBinderSoftbusClient::DBinderGrantPermission` 会按 socketName 维护 refcount 并调用动态 Softbus grant API；已核实调用端由 DBinder 内部基于调用身份创建名称，或 listener 使用本进程 UID/PID 和固定 `OWN_SESSION_NAME`。未证明任意外部 caller 可控制 UID/PID/socketName、绕过授权或导致跨主体具体 effect。`ProcessProto` 路径与旧候选 `ca88225a02a0fe72` 重叠。SAMGR gate 来自另一个仓库，未与本产品 SHA 绑定，故未当作事实使用。
- D8 source binding：`dbinder_softbus_client.cpp` SHA-256 `01d83f57fafc2c206039d74a90e9a21cbd16bd7813a3d501b704e3642c9de87b` / blob `7b4bcd7525d01bee078d26ea80ce7ee4c1e86bef`；`dbinder_service.cpp` `ac762ad0345451a605fffcd430d933161eb20aedd7b83479753b9be8384fa1cf` / `fb7f0b92f1f842f10f35f14917c553d3bb38ee9e`；`dbinder_service_stub.cpp` `6583b7b212eb8230ae234c54666bb1c9bdcffed898a3799d096d573a0422b9f2` / `11927a9291886f56211a3c775122b2462d6f1ddd`；`dbinder_remote_listener.cpp` `787a37914ec1e1d760144803ed25a2aaddb60139651a691326bb1bd038f1df62` / `7a6240778b2e7c1b52c4d9148d849b9cef5e01e5`。锚点均为 `communication_ipc bbb92dbb2f52aca54ab268307c9476ac1802f3ff`。
- **T10 独立路径复核：**先独立选择 `DUMP_TRANSACTION → OnRemoteDump → virtual Dump`，与已审旧候选 `5501bf2ba361596d` 重叠，不产生新候选。`IPCObjectStub` 在读取 parcel/dispatch 前要求 local caller 且 UID 属于 0/2000/1212；基类 Dump 仅日志，未审具体子类 effect。Databus invoker 的 FD 编解码不支持真实 FD。source pins 见 JSON。T10 已转向独立复核 D8 grant 路径，补齐后再给最终交叉结论。
- **并行下一步已启动：D9/T11。** 两线针对 D8 建议的 Softbus 入站 `OnBytesReceived(socket,data) → AddAsynMessageTask → OnRemoteInvokerMessage`，追踪 `fromDeviceId` 与 socket peer/session 的绑定、后续 remote SA 加载和权限/effect。D9 每轮最多交一条 source-bound 候选；T11 独立还原来源和反例。两线均不得把“socket 参数未使用”直接视为 spoofing 证据。
- 若 D9/T11 仍无法证明外部可控 caller、认证绑定缺失和具体跨主体 effect，则保持 0 新候选；下一开发任务仍是侦察而非盲目改 scanner。仅当测试线提供固定基线红测且确认误报/漏报契约后，才启动条件开发和独立重放。
- 本次续跑重新尝试 `git fetch origin --prune` 遇 GitHub 443 连接失败；现存 tracking ref 与两个工作树仍为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，但本次未能证明远端仍停在该 SHA。GitHub commits 页面对此 scanner remote 返回 404，故本轮只把 `db77164...` 作为上一次成功 fetch 的 last-verified baseline。下一轮优先重试 fetch；在基线重新核实前，所有本轮静态结论明确限定在该 SHA。
- **T10 追加发现（待独立收敛）**：对 D8 grant 路径深挖后，T10 注意到 `GET_SESSION_NAME_PID_UID` 在 `IPCObjectStub::SendRequest` 基类特殊码分支直接派发；`DBinderGetSessionNameForPidUid` 的 `IsSamgrCall` 是服务端 `ProcessSkeleton` process flag，而不是 caller 身份校验；handler 从 parcel 读取远端 UID/PID 并调用 `CreateSessionName → DBinderGrantPermission`。`IPCSkeleton::GetContextObject` 与 `IPCObjectProxy::GetSessionNameForPidUid` 可能给内部 native client 一个本地 SAMGR registry 句柄及 raw 特殊请求路径，但 app 的实际链接/导出可达性、SoftBus target pair 下游是否能伪冒，以及产品权限威胁模型尚待测试线闭合。此证据推翻 D8 对“调用者只能来自内部”的初步概括；当前仅列为**待证候选**，不升级 finding。
- T10 指出下游 SoftBus `GrantPermissionInner` 会基于调用 token 的 native/SAMGR 动态权限检查，再把请求 UID/PID 存入动态 permission entry。检查目标 pair 的 identity 是否由请求端控制、以及 permission 对后续连接的具体影响，是 L2/独立复核必需证据，不能只因服务端有 SAMGR token 就推断越权。
- **D9 入站线提出一条 source-bound OOB read 候选（待 T11/L2）**：wire `DHandleEntryTxRx` 经 `OnBytesReceived` 整帧复制；总长度和 `head.len` 通过后，定长 `DeviceIdInfo::fromDeviceId[65]` 未验证 NUL，之后在 `OnRemoteInvokerMessage` 被用作 C 字符串构造 `std::string`。固定 64-bit 布局计算偏移 52、结构体大小 408；恶意非终止数据可使字符串扫描至少越过数组、并可能越过结构体边界。正常 writer 会显式追加 NUL，但这是发送端约束，不是接收端校验。候选只主张 OOB read，崩溃/泄露/可利用性待 L2，peer-device mismatch 是单独 unknown，不与此合并。
- D9 精确来源锚与候选细节见 JSON 的 `d9_softbus_inbound_candidate`。现有 listener unit test 只验证合法长度和 header；service test 零初始化 message；listener fuzzer 不填充非 NUL `fromDeviceId`。因此没有反例或 sanitizer 证据。T11 已独立复核该完整字节链；L2 同时启动窄审。若两线确认，再建一个 fixed-baseline sanitizer regression task，不先开发 detector 规则。
- 同一候选的任务树现为：

```text
D9 静态候选：定长字符串未终止 → std::string C-string 扫描越界
 ├─ T11 独立验证：结构布局、接收可控性、tests/fuzz、具体可观察内存错误
 ├─ L2 独立分诊：仅审越界读主张及缺失影响，不推断 crash/disclosure
 └─ T12 条件测试：仅在T11/L2支持后，对固定源码构造最小 ASan/UBSan regression；先红后回馈
     └─ D9a 条件开发：修正接收边界/字符串验证（先由T12 oracle证明），再由独立线复放
```

- 无论 peer mismatch 是否有安全影响，都不得将其当成 NUL-termination 候选的危害证据。只有 D9/T11/L2 三者对接收源、越界路径和可复现实验契约达成一致后才升级，并按候选优先供 L2 补充细节；scanner 远端 SHA 当前回拉失败，当前结论仍锁定上次成功 fetch 的 `db77164...`。

## 本轮验证回馈与并行提示词（2026-10-20）

- **D8 初始 0 候选已被 T10 深查修订。** `IPCSkeleton::GetContextObject()` 返回 registry object；IPC core innerkits `IPCObjectProxy::GetSessionNameForPidUid(uid,pid)` 公开方法通过 `SendRequestInner` 发送 `GET_SESSION_NAME_PID_UID` 特殊码，generic `IRemoteObject::SendRequest` 则被 `MAX_TRANSACTION_ID` 拒绝。目标服务端 `IsSamgrCall` 读取 SAMGR process flag，不绑定调用者身份；handler 根据 parcel UID/PID 创建 session name 并 grant。SoftBus 动态授权由 SAMGR native token 审核后把传入 pair 存入本进程 dynamic permission list，唯一名池最大 100，饱和后后续 grant 失败。T10 支持“可访问该 innerkits 方法的本地调用者有资源耗尽向量”，但普通三方 app 的接口导出/链接权限和产品复现仍 insufficient；独立 L2 已启动。不得沿用 D8 早期 0 候选作为最终裁决，也不声称普通 app 可利用。
- **D9/T11 汇合：一条 source-bound 字符串越界读候选进入 L2。** 接收路径的全帧长度/head.len 校验后，将定长 `DHandleEntryTxRx` 原样异步入队；`fromDeviceId[65]` 没有接收端 NUL 验证。T11 找到更早错误路径：SA-ID 检查失败时 `SendReplyMessageToRemote`/`SendDataReply` 仍会把 `fromDeviceId` 转为 `std::string`，因此不用先通过正常 SA ID/distributed gate。T11 结论为 source-level OOB read supported、网络可达需有效 Softbus端点、crash/disclosure impact insufficient。现存测试/fuzzer未提交受控非 NUL 字段，也没运行 sanitizer。本轮已启动独立 L2；没有生成正式 scanner `candidate_id` 或变更 finding lifecycle。
- T11 的 source binding 包含接收 listener、消息结构、service 调用路径和相关 unit/fuzz；完整 hashes/blobs见 JSON。peer socket 与 `fromDeviceId` 缺少显式比对是另一条待证观察，不作为该 OOB 的必要条件或危害放大依据。
- **D9 与 T11 结构化提示词**：D9 只审 pinned `communication_ipc@bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 `DHandleEntryTxRx` 入站、异步生命周期、错误回包与正常 writer 终止；逐个 C-string 用点 source-bind；候选表述严格限于非终止 wire field 导致对象/数组越界读，不推断 crash、泄露或 auth bypass。T11 从 raw pinned bytes 独立重建可达链和内存布局，区分 source-level 与实际 sanitizer测试；同时单独评估 peer identity mismatch，反馈精确现存测试/fuzz边界。两线已完成并相互反馈，本轮结论归档后再进入下轮。
- **L2 提示词**：只审 NUL termination 候选；校验错误回包是否早于正常授权 gate、transport permission 条件、`std::string(const char*)` 内存边界和实际 effect。给 `supported/refuted/insufficient`；没有 ASan/设备证据时不得升级为远程 DoS/信息泄露。回传最小安全测试 oracle 与未决条件。D8 100-entry permission-list 条件耗尽另由独立 L2 review，两个候选不得混合。
- **T12 条件测试提示词**：仅在 T11/L2 source-level OOB 结论明确且可用构建 harness 存在时开始。独立固定基线先构造经过真实被测 C-string用点的最小消息，再用 ASan/UBSan验证字段/对象边界；覆盖完整合法 ID、恰好64字节、缺NUL、错误SA ID reply。禁止对真实设备/网络做攻击性试验。不改 scanner rule；若产品修复获授权且红测成立，再由 owner开发、独立测试线复放。

### T12 本地 sanitizer 探针结果（非产品集成测试）

- T11 与 L2 都支持 source-level OOB read 后，我执行了一个最小 layout harness，源码留档于 [d9_unterminated_device_id_asan_probe.cpp](ipc/b-line-20261020/d9_unterminated_device_id_asan_probe.cpp)。它复制 pinned `DHandleEntryTxRx` 的 relevant field layout（static_assert 偏移 52、size 408）、采用 `std::make_shared` 并调用同样的 `std::string(char*)` 转换，但不编译/调用产品 listener。
- WSL Clang 21 ASan 编译成功。合法控制组在 `fromDeviceId[64]` 写 NUL，exit 0；对象字节全填 `0x41` 的未终止组，ASan 在 `strlen` 处报告 `heap-buffer-overflow`，`READ size 357`，越过 424-byte `make_shared` allocation，exit 1（预期失败）。临时 `/tmp` binary 已移除。
- 该探针验证字段/对象布局下的 C-string OOB 机理；**不等于**真实 `OnBytesReceived` 集成重放、Softbus peer 可达证明、设备崩溃或信息泄露。候选仍为 source-supported memory safety，不升级为远程 DoS/RCE/泄露。
- 当前 D9 tree 更新：D9 source-bound 候选 → T11 `supported`（source level）→ L2 `supported`（source level）→ T12 layout ASan reproducer 通过边界验证；下一步只需在可用 OpenHarmony 产品构建环境中经实际 `OnBytesReceived` / invalid-SA reply 路径复放，之后再决定是否实现接收端长度/NUL 检查。scanner detector 不动。D8 权限池资源耗尽向量另由独立 L2 审查，状态仍是普通第三方 app 可达性 insufficient。

## 本轮复核与下一轮任务树（2026-10-20）

- 本轮通过集成工作树重新执行 `git fetch origin --prune` 成功；`origin/main`、集成 HEAD、计划 HEAD 均为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`。本轮审查基线已重新核实；上文较早记录的 fetch 失败仅代表先前尝试。
- **D9 状态更新**：D9/T11/L2 均支持 source-level 越界读；T12 合成布局 ASan 探针的合法控制组通过，未终止字段组在 `strlen` 报 heap-buffer-overflow。探针只模拟 pinned layout 和 `std::string(char*)`，不调用产品 listener，因此不证明产品集成可达、远程崩溃/泄露或 exploitability。当前不创建正式 scanner finding、candidate ID 或 detector 规则。下一门槛是评估能否经真实产品测试路径复放；若不可行，记录确切依赖阻塞。
- **D8 L2 收敛**：若本地调用者能取得可命中特定 SAMGR stub 的 proxy 并调用公开 innerkits helper，则 handler 可按请求 UID/PID 创建 session name 并请求 grant；SoftBus dynamic permission list 为每进程 100 项，满额后拒绝后续 grant，已有项不会因此删除；后续检查要求精确 UID/PID pair。IsSamgrCall 是接收进程标志，不是 caller UID/token ACL。结论是**有条件的源码级资源池耗尽效果**；普通第三方 app 可达性仍为 **insufficient**，不是已证实 app 漏洞。现有单测无 100 项边界、真实 Binder→SoftBus 联动和 app reachability 覆盖；不据此改 finding 状态或重复创建共享 sink 的 detector finding。
- D8 待补证据：目标产品下无特权 app 是否能拿到 proxy 并调用 helper；真实服务 token 是否通过 SoftBus gate；隔离测试中填满池后新的合法 pair 是否产生可观察失败及 cleanup 是否恢复。T13 只调查 build/export/config 与测试接口，不写或跑攻击 PoC。

### 下一轮任务树

```text
D9：未终止 fromDeviceId 源码级 OOB read（source-supported，影响受限）
 ├─ T14：只读评估实际产品构建/测试 harness 是否可达 invalid-SA reply 的 C-string 用点
 ├─ 若可行，T15：固定 commit 的产品集成 ASan 回归，先合法控制、再无 NUL 红测
 │   └─ D9a：仅在红测成立后评估接收端边界/NUL 修正；T15 独立复放
 └─ 若不可行：记录环境依赖阻塞，不升级影响结论

D8：100-entry SoftBus pool 条件耗尽（L2 source-supported；普通 app insufficient）
 ├─ T13：独立核对普通 app 的 build/export/权限可达性
 ├─ T15b：仅在授权隔离环境定义 pool-full、新合法 grant 失败、cleanup 恢复 oracle
 └─ D8a：只有 reachability 和可观察效果闭合后，才评估限额/授权开发；测试线独立复放
```

- **T13 结构化提示词（配置/测试线）**：仅调查固定 IPC anchor `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 下，普通三方 app 在产品 build/export/install/权限策略中能否取得 registry proxy 并调用 `IPCObjectProxy::GetSessionNameForPidUid`。检查 GN target、导出头、库安装/链接可见性、策略和既有测试；每项结论绑定 source hash/blob。不得把 public 声明等同 app 可达，不写或运行攻击 PoC；不确定时给 insufficient 和所缺配置证据。结果回馈 D8/L2，不改 finding 状态。
- **T14 结构化提示词（D9 测试工程线）**：只读评估本地 OpenHarmony 构建环境能否固定产品 commit 并经真实 `OnBytesReceived → async task → invalid-SA reply` 到达 C-string 用点。提供 target、依赖、命令和最小 oracle，区分产品集成与 layout harness；无环境则列精确缺项。禁止真实网络/设备试验；不改代码、detector 或候选状态；回馈 D9/T12。
- **T15 条件测试提示词**：仅当 T14 确认目标/依赖齐备且产品 commit 固定后运行隔离本地测试：合法 64-byte ID/NUL 控制通过；定长 `MESSAGE_AS_INVOKER`、invalid-SA 且 `fromDeviceId` 与帧尾无 NUL 的消息在产品 C-string 用点触发 ASan；修复后合法组通过、恶意组无越界。逐条反馈 D9a；不触碰真实设备/网络，不改 scanner detector。
- **D8/T15b 安全测试门**：在 T13 可达性未证实或无维护方授权的隔离集成环境前，不做 pool 耗尽 PoC。之后测试需定义新合法 pair 失败与正常 cleanup 恢复 oracle，结果回馈 D8a；此前保持 conditional / ordinary-app insufficient。
- T13、T14 已并行启动，均为只读调查；本轮不启动产品修复或 detector 实现。

## T13 / T14 结果与当轮远端状态（2026-10-20）

- 本轮在集成树重新尝试 fetch 失败：GitHub 443 连接超时（约 21 秒）。因此 scanner 当前远端 tip 未验证；本地 HEAD、tracking ref 和计划仍停在上次成功 fetch 的 db77164fdc2af0da02e4d3efc056d84694fd68e8。以下调查限定于该 last-verified scanner snapshot；下一轮仍需先恢复 fetch。其他本地 source-bound 工作已继续。
- **T13 更新 D8 可达性**：针对固定 communication_ipc@bbb92dbb2f52aca54ab268307c9476ac1802f3ff 的标准 GN/export surface，普通 app 直接调用 IPCObjectProxy::GetSessionNameForPidUid 的路径为 refuted。ipc_single/BUILD.gn 采用 version script libipc_single_map；该 symbol map 未导出 helper，且 local: * 隐藏其余符号；ipc_core 使用 libipc_single.z.so。因此公开头声明和 inner-kit 头文件列表不足以证明标准 app 可动态链接此 out-of-line 方法。SendRequest 通用入口又拒绝超 MAX_TRANSACTION_ID 的特殊码。该结论不覆盖自定义 symbol map/SDK 的产品，也未验证实际第三方 app 包。
- D8 池满条件效果仍然 source-supported，但因标准 app helper 路径 refuted，本轮不按普通第三方 app 漏洞推进，不登记 finding、不写攻击 PoC。若真实产品定制 export surface，要重开 app 可达性审查；条件性池影响不与路径可达性结论混为一谈。
- **T14 更新 D9 产品测试可行性**：本地产品树 D:/openHarmonyScanner/openharmony/foundation/communication/ipc 的 HEAD 为 5903fd5f7332a427cb3f6915b0202ee5c76c63b5，并非 pinned bbb92dbb...；四个 listener/service 源及单测文件的本地 SHA/blob 与 pinned JSON 一致，但当前 Git 对象库没有目标 pin。现有 GN targets 为 DBinderRemoteListenerUnitTest、DBinderServiceUnitTest 与 listener fuzzer；listener 单测直调 OnBytesReceived，service 单测单独 mock invalid-SA reply，尚无受控 non-NUL 字段穿过异步队列到 reply 的联动用例。
- WSL 有通用 /usr/bin/clang++，仓库有 GN/Ninja prebuilts；但未找到 OHOS 专用 clang/sysroot，out/rk3568 只有 build logs，没有 build.ninja/args.gn。所以目前不可声称 pinned 产品集成 ASan 已构建或运行。T12 layout ASan 探针仍只证明合成布局/C-string 机理。
- **D9 下一测试门**：获取包含 pinned IPC commit 的产品源码对象/干净 checkout、OHOS clang 与 sysroot，并生成产品 build config 后，才在 DBinderServiceUnitTest 增加测试专用联动回归：通过 listener OnBytesReceived 送入 fixed-size invalid-SA 消息，分别跑 fromDeviceId[64]=NUL 控制与整个字段/尾部无 NUL 组，用 condition variable 等待 FFRT task，在 SendBytes hook 观察 reply。ASan 必须在真实产品 C-string 用点报告越界；控制组正常回复。测试通过后才由 D9a 评估接收边界检查，独立测试线复放。当前不改产品代码。
- **T13 source bindings**：interfaces/innerkits/ipc_single/libipc_single_map SHA-256 8e05e1b217ed5b42ad83fbf38d31ca33241302a5c2b49cf927fd66b868bd049a / blob 0bab69a423e5127f4b2e7b0d0ba87f0eb3772d9b；ipc_single/BUILD.gn 331ba3ea500d4b89216aab1c749a2b4eeade0a671701d3285f4dc4c986116227 / 797626221f2bcc113fd60c10a2410290f2ed4685；ipc_core/BUILD.gn a0215d55f3b4277dbcd62f9f0c42941e2c7cfe9b3aec34dbaf35f4ca8fcbf333 / fcc114be4923335cb09a0ea00751b2dbfcae9726；bundle.json ddb49a0b230e8f8c0101871977e427aef4465dd2745dafbf66ec83c2857c54ab / 274094d8b65f4f2f9710c4e428226f34bcba9d19。均按 pinned raw bytes 重算；真实产品 app 包编译/链接/运行仍未验证。
- **任务树反馈闭环**：T13 反证收窄 D8 漏洞主张；T14 确认 D9 真实测试入口存在，同时明确 pin/toolchain/build-config 阻塞。下一轮开发线暂只准备 D9 的 test-only 变更设计，测试线先补齐构建依赖并固定 pin；D8 回到观察态，除非发现产品定制 export surface 证据。
- **T15 独立复核**：未复用 T13 结论作 oracle，重新从 pinned raw source 绑定 GN/export、version script、proxy helper 和 transaction gate；结论再次为标准接口/export surface 下普通 app 的 helper 路径 refuted。helper 未在共享库导出表中，通用 SendRequest 也拒绝特殊码；CONFIG_IPC_SINGLE、本地/SAMGR guard 另约束 stub 特殊分支。静态链接、custom SDK、vendor wrapper 或本地修改 symbol map 不在结论范围。没有真实 app 测试/PoC。T13/T15 的关键 SHA/blob 相同且独立复核一致，D8 不再作为普通 app 漏洞推进。
- **T16 环境交叉检查纠错**：T16 最初报告称 GN/Ninja 缺失；负责人本机重新直接运行仓库二进制，gn --version 返回 2026 (47b40ef4)，ninja --version 返回 1.13.2，因此两工具当前可用。旧 build log 中的 Ninja 报错不能代表当前工具不存在。仍确认没有 OHOS clang/sysroot、没有 out/rk3568/args.gn 或 build.ninja，pinned IPC commit 在本地 object DB 不能解析；本地 HEAD 是 5903fd5f...。故 D9 pinned 产品构建依然受阻，但缺项精确收敛为 pin/object/config 与 OHOS toolchain，而非 GN/Ninja。通用 host clang 21.1.8 target 为 x86_64-pc-linux-gnu，不能替代 OHOS 工具链。
- **当前并行状态**：T13/T14/T15/T16 均已完成。D8 的下一步是仅在拿到定制产品导出 surface 时再重开；D9 的产品集成回归仍需维护环境提供目标 commit 对象/checkout、OHOS clang/sysroot 与 build config。下一轮优先尝试从集成树 fetch 最新 scanner main；若网络仍阻断，继续把结果明确锁在 last-verified db77164fdc2af0da02e4d3efc056d84694fd68e8，并在本地推进 source/test 可行工作，不把 last-verified 误称为最新。
- **当轮最后复验**：记录上面初次 443 超时后，我再次从集成工作树执行 fetch 成功；origin/main、集成 HEAD、计划 HEAD 均为 db77164fdc2af0da02e4d3efc056d84694fd68e8。故本轮基线当前已重新验证，不存在持续网络阻塞。
- 本轮再次独立 fetch 仍成功，origin/main 与两棵工作树 HEAD 保持 db77164fdc2af0da02e4d3efc056d84694fd68e8。为保持静态/测试反馈并行，已新增 D17/T18：分别独立选取一个未覆盖的 Binder transaction/Parcel 接收路径，最多一条 source-bound 候选；避开已审 D8/D9、DUMP 和 death-recipient。D17 交候选或零结果后，T18 对其逐项独立 source-bind、查 guard/测试/fuzz 和去重。没有 source-bound 有效候选则不创建开发或 detector 变更。
- **D17/T18 结果**：固定 IPC pin 下审查 BR_TRANSACTION/BR_TRANSACTION_SEC_CTX → BinderInvoker::OnTransaction/Transaction → Parcel offsets/object decode → IPCObjectStub，source-bound 新候选 0。T18 发现 UnFlattenDBinderObject 在特定 flag/长度时会解引用 buffer，但普通 MessageParcel::ReadRemoteObject 先经 Parcel::ReadObject::CheckOffsets，要求当前 cursor 命中有效 object offset 且 parcel 足够容纳对象；无 offset raw payload 因此前置失败。UnflattenObject 还有 offsets、完整对象长度、类型及本地 cookie 检查。方法级 unit/fuzz 已覆盖部分分支，但不是实际 kernel Binder integration。Parcel guard 来自 commonlibrary/c_utils，不属于 IPC pin，仓库版本尚未绑定；因此这是一个需补依赖 identity 的负面核验，不是已 refuted 的全产品 claim，也不是候选。
- **D19/T20 下一条并行验证**：D19 从固定产品 checkout/构建 manifest/GN dependency metadata 确认其选择的 commonlibrary_c_utils commit；T20 从 pinned raw/manifest 独立重算该版本和 Parcel::ReadObject/CheckOffsets 源身份并复核 guard。若依赖 commit/source mismatch，明确保持 insufficient 并索取构建 lock/manifest；若绑定一致，关闭该窄路径，不做 detector 修复。仍不得把外部 Binder driver 行为冒充 IPC 仓库证据。
- **D19 结构化提示词（依赖版本线）**：固定通信 IPC pin bbb92dbb2f52aca54ab268307c9476ac1802f3ff，只读查 bundle/build files/manifest/版本锁/组件更新配置中 commonlibrary_c_utils 的精确 revision，追到产品构建实际选用的源码根。输出 commit/tree、来源和可信度；若构建使用浮动 branch 或外部 manifest 未在工作区，标 insufficient 并给出最小需维护方提供的文件。不要改代码、fetch 大型依赖或生成候选。
- **T20 结构化提示词（独立源码与测试线）**：不复用 D19 结论作 oracle，独立检查 pinned build metadata 与 c_utils Parcel implementation 的 revision 绑定；按 pinned raw bytes 重算 parcel.cpp/h SHA/blob，核对 ReadRemoteObject→ReadObject→CheckOffsets 的 cursor/size 支配关系以及现有 unit/fuzz边界。若确切依赖 pin 未证实，则将无-offset反证保持 conditional/insufficient；禁止将通用 Binder kernel 行为当成 IPC 源码事实。只读、0/1候选、无 PoC。

## D19 / T20 依赖与负面验证结果

- D19/T20 均未发现 D17 路径的新候选。正常公开 API 的 offset guard 支配关系在本机 c_utils checkout 精确提交 7a9af76276aca8f53347fb89c07850e014905521 上复核一致：MessageParcel::ReadRemoteObject → Parcel::ReadObject → CheckOffsets；没有正确 offset 或对象尺寸不足会在 unmarshalling 前返回。其后 BinderInvoker::UnflattenObject 仍再次检查 offsets、完整对象大小、类型和 local binder cookie。
- 本地 c_utils 源绑定由负责人按原始字节重算：base/src/parcel.cpp SHA-256 f4296edd47f32475d6bb2b8c8a615ecc6f87fe3de2495cbef75cc59d326aac23、blob 097bb3b44179ee382ee9ebb65aeb8ad25a66bbdf；base/include/parcel.h SHA-256 25d5bca322bfbca84d362b6914856b2b197dea81f3212e9c135356f9c2de2c42、blob 882fac69ad5b6e2b8b680343f2bbfd8aa365019e。注意早期 T18 消息中的这两个 blob OID 有误，已用本机 Git blob 公式和 WSL git hash-object 纠正；D17 JSON 已改为正确值。
- T20 找到本地 generic c_utils 单测覆盖空 parcel/missing offset fail 与正常对象读取，c_utils fuzzer 覆盖 CheckOffsets/ReadObject；IPC binderinvoker001 fuzz 构造 transaction/offset inputs，006/007 直接 fuzz UnflattenObject/UnFlattenDBinderObject，绕过外层 guard。没有发现专门 IPC ReadRemoteObject missing-offset 单测，也没有 kernel Binder 收包到该 API 的集成覆盖。本轮没有运行测试。
- **D19/T20 精确依赖结论仍 insufficient**：活动 .repo manifest 的 ohos.xml 将 communication_ipc 与 commonlibrary_c_utils 都设为 revision=master。两个冻结清单 snapshot 的哈希分别为 openharmony-manifest-fixed.xml SHA-256 701683246a8b4393e61cdb75132d76aacc9e53f6f663d37e386bbd535511fbee / blob 9e973878fcb5164ba3f0becb0fe28ea0ed3af0a4，以及 openharmony-manifest-current-20261018.xml SHA-256 52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55 / blob a0c401b8b408a5a71795eca7dc37469b7f31e8f0。两者都将 c_utils 固定为 7a9af76276aca8f53347fb89c07850e014905521，却将 IPC 固定为 5903fd5f7332a427cb3f6915b0202ee5c76c63b5，不是目标 bbb92db...；因此不能证明该 Parcel 实现就是目标 IPC 产品构建所用版本。
- 要闭合这条 guard 反证，需要维护方提供实际包含 IPC pin bbb92db... 的产品 manifest/lock（含 c_utils revision）及已解析 GN 目标依赖/构建记录。缺这些时只保留“本地 c_utils commit 上 normal API fail-closed，目标产品依赖关系 unknown”，不据此漏洞化，也不把它写成产品端安全保证。D19/T20 已完成，0 候选；下一步继续窄静态侦察并等待 pinned product build evidence。

## D21 / T22 — REMOVE_SESSION_NAME 特殊事务闭环（2026-10-20）

```text
D21 开发侦察：限定 REMOVE_SESSION_NAME 一条事务链，候选 0
 └─ T22 独立测试/证据复核：重建身份、API/导出、SoftBus 副作用边界；发现差异后回馈 D21
     └─ D21a 负责人修订结论：IsLocalCalling 仅排除 Databus，不是 Binder caller ACL；SAMGR flag 仅为接收进程态
         └─ T22a 复核修订与条件风险，形成第二层 LLM 输入和下一轮补证项
```

- D21 交付 [D21 REMOVE_SESSION_NAME scout](ipc/b-line-20261020/d21_remove_session_scout-20261020.json)，T22 独立交付 [T22 review](ipc/b-line-20261020/t22_remove_session_review-20261020.json)。两份报告均为 0 个已确认普通应用候选；未改产品代码、未运行测试。
- T22 对 D21 的关键反馈已采纳：`BinderInvoker::IsLocalCalling()` 恒 true，只能排除 `DBinderDatabusInvoker` 的远端 databus 路径；`IsSamgrCall()` 读取 receiver 侧进程标志，该标志在 context-manager/registry 注册成功后设定。这些条件不能表述成对 Binder 原始 caller 的身份认证。
- D21/T22 汇合后的准确结论：handler 对非空 sessionName 不做原始 IPC caller 或 name-owner 校验；如普通应用能调用 `IPCObjectProxy::RemoveSessionName` 或绕过 `SendRequest` 发特殊码，存在按任意名称减少进程内 refcount/移除 SoftBus 动态权限的条件风险。当前没有证明这条调用对普通应用可达：普通 `SendRequest` 拒绝高于 `MAX_TRANSACTION_ID` 的特殊码；本地 `ipc_single` version map 未导出 helper；完整产品目标 commit 下的 sender、导出 map、SDK/build 配置尚未绑定。SoftBus 自身 token 检查只约束其直接调用上下文，不能替代 IPC stub 对原始 caller 的认证。
- 独立测试线还指出 helper 用 `TF_ASYNC`，refcount 按 sessionName 共享；若内部 raw bypass 确实可由不可信调用者触发，跨 session 删除/生命周期竞态值得做隔离测试。但在 ABI、registry proxy 获取和端到端普通 caller 可达性闭合前，不跑 PoC、不报告 app 漏洞。
- **开发/复核互反馈**：D21 原始“local + SAMGR guards”描述曾可能被误读为 caller-auth；T22 提出反证后，负责人已把裁决限定为 transport 类型 + receiver process state。T22a 只验证这一更正和目标 pin；若新证据显示 helper 暴露或 raw transaction 可达，再由开发线定义最小修复设计，测试线先给红测 oracle，修复后独立复放。
- **下一并行任务**：D23 只读绑定目标 `bbb92db...` 下 `ipc_object_proxy.cpp`、`ipc_process_skeleton.cpp`、BinderInvoker 和 `libipc_single_map` 的精确 blob/hash 及其库导出/产品构建；T24 独立从 pinned bytes 与 SDK GN/install metadata 重查 SendRequest code guard、helper ABI、registry proxy 获取条件。两者最多输出 1 条条件候选；未能绑定 target build 时维持 `insufficient`，不补跑测试或生成漏洞报告。T24 将对 D23 逐项反证并回馈，D23a 修订后 T24a 复核。

**D23 结构化提示词（开发/来源绑定线）**：只审 OpenHarmony `communication_ipc` commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 `IPCObjectProxy::RemoveSessionName`、`SendRequest`/`SendRequestInner`、`IPCProcessSkeleton` 生命周期调用、BinderInvoker 和 `interfaces/innerkits/ipc_single/libipc_single_map`。逐文件从目标 commit raw bytes 绑定 Git blob 与 SHA-256，追踪 `REMOVE_SESSION_NAME` 从内部 cleanup 到 handler 的完整路径，并记录 public code-range guard、TF_ASYNC、注册 context manager 时 receiver flag 的设置。检查产品 GN target、symlink/install/export metadata 是否能将 helper 暴露给普通三方 app。输出 0/1 条具体候选；若目标 commit 或产品 build 证据不可得，明确 `insufficient` 并列出精确缺项。只读，不改代码、不运行测试、不尝试真实设备/网络调用。

**T24 结构化提示词（独立测试/反证线）**：不采用 D23 的结论作前提，从 pinned commit 和产品 SDK/build metadata 独立重建普通 caller 可达路径。确认 `BinderInvoker::IsLocalCalling` 与 `DBinderDatabusInvoker` 语义、`IsSamgrCall` 是 receiver process flag、普通 `IPCObjectProxy::SendRequest` 对 special code 的处理、helper 符号 export，以及 app 获得 registry/SAMgr proxy 的产品权限边界。阅读 SoftBus token/refcount 路径但区分 direct token gate 与 IPC 代理转调。指出 D23 漏证、反例及任何跨 session DoS 的最小安全 oracle；目标 pin 缺失时明确不验证产品结论。只读、不运行 PoC/测试，不改 detector。

**第二层 LLM 复核包（条件候选）**：请只评估以下命题是否被证据支持：“若普通本地 app 能取得 SAMgr registry proxy 并调用 `IPCObjectProxy::RemoveSessionName`，或能将 `REMOVE_SESSION_NAME` 特殊 transaction 注入 `SendRequest` guard 之后，则 handler 仅检查非空字符串，可能按攻击者选定的 sessionName 递减进程内 refcount 并在到零时移除 SoftBus permission；这或影响另一调用者的 DBinder session。” 核验目标 commit 的 send/handler/export/build 源绑定，确认 caller 是否能触达并能否控制匹配活动 name；尝试反证 public `SendRequest` special-code rejection、`ipc_single` symbol map local wildcard、registry object 获取限制及 SoftBus 影响边界。逐项判定 `supported/refuted/insufficient`，不得把 receiver-side SAMGR 标记当作 caller ACL，也不得把 SoftBus token gate 当作 stub caller auth。无普通 app reachability 与隔离观察证据时，不称已证实漏洞；只给精确缺项和一条最小非攻击性验证建议，不自行改候选状态。

## D23 / T24 — REMOVE_SESSION_NAME 目标源码与导出边界已闭合（2026-10-20）

- D23 对 `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 proxy/process skeleton/BinderInvoker/ipc_single version map/GN/header 七个文件从 immutable raw source 绑定 SHA-256 与 Git blob；T24 独立下载并重算，报告中的关键值一致。两条线均未找到部署 SDK、库符号表或精确产品 build lock。
- D23/T24 汇合裁决：**confirmed ordinary-app candidates = 0；conditional L2 items = 1**。标准 `ipc_single` version map 未导出 `IPCObjectProxy::RemoveSessionName`；普通 `SendRequest` 会拒绝 special code。helper 在头文件虽为 public，但其内部调用 private `SendRequestInner` 并带 `TF_ASYNC`。已定位的使用是 IPCProcessSkeleton 生命周期清理，面向 SAMGR proxy。
- 仍保留的条件命题只有：若定制/已部署 ABI 额外导出 helper，或不可信方有 bypass raw transaction 的能力，且可寻址 SAMGR registry proxy，则 stub 缺少原调用者/name-owner 检查，可能请求移除匹配 session 的权限。部署、跨 caller 效果与异步完成均未验证；不报告为 app 漏洞、不运行 PoC。
- T24 对 D23 的反馈：独立 hash 与导出判断吻合；额外限定 pinned GN/install metadata 不等于已交付 SDK，SoftBus refcount/async sink 与目标 IPC 构建配对未验证；receiver `IsSamgrCall` 不是 caller auth；无本地 refcount 项时仍会调用 SoftBus backend 删除。D21/T22 的原先表述均已更正为“传输分类 + receiver process state”。
- 结构化证据见 [D23 target pin](ipc/b-line-20261020/d23_remove_session_pin-20261020.json) 和 [T24 counterreview](ipc/b-line-20261020/t24_remove_session_counterreview-20261020.json)。本轮确认 `origin/main`、计划工作树 HEAD 和集成线 HEAD 都仍为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`。

### 下一条并行路径：DBINDER_ADD_COMMAUTH

```text
D25 静态开发侦察：审 DBINDER_ADD_COMMAUTH → AddAuthInfo 身份/授权状态写入，最多 1 个具体候选
 └─ T26 独立测试/证据复核：从 databus UID 来源、输入字段控制性、AttachOrUpdateAppAuthInfo 后续使用点尝试反证
     └─ D25a 与 T26a 互馈：只有 source-bound 未授权状态写入/可观察安全影响闭合才设计修复
         └─ 后续 T26b 定义隔离 oracle；无权限/产品 harness 时保持源码结论且不跑 PoC
```

**D25 结构化提示词（静态开发线）**：只审目标 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 `DBINDER_ADD_COMMAUTH` 从特殊事务分发、`DBinderAddCommAuth` 到 `AddAuthInfo`，并追踪 `DBinderDatabusInvoker::GetCallerUid` 的实际赋值、`ALLOWED_UID` 语义、传入 remotePid/remoteUid/deviceId/stubIndex/tokenId 对 `AppAuthInfo` 的写入及后续授权消费点。优先按 immutable raw target source 绑定所有 IPC 文件 SHA/blob；外部依赖未锁定时标 unknown。尝试构造不依赖猜测的攻击者控制路径，区分低 UID 可信系统进程、普通 app 和远端 databus peer。最多 1 个候选；须写明必要权限、守卫、source-sink、影响和反证。只读、不改代码、不运行测试/PoC、不扩大成全树 claim。

**T26 结构化提示词（独立测试/反证线）**：独立检索目标 commit 和协议/测试定义，不采用 D25 候选作 oracle。核验 `DBinderAddCommAuth` 的 transport gate 与 callerUid 来源是否可伪造、`uid < ALLOWED_UID` 的产品安全含义、Parcel 字段是否有结构/身份校验、`AddAuthInfo` 更新的 AppAuthInfo 是否能被攻击者用于未授权代理/死亡通知/引用操作；检查现有 unit/fuzz 覆盖和缺少的状态矩阵。按每个因果边给 source hashes 和可反证证据，输出 0/1 候选及 `supported/refuted/insufficient`。不运行测试、不制造真实 databus 流量；产品构建/身份语义缺失时报告精确依赖并让 D25 修订，之后再次独立审查。

## D25 / T26 — DBINDER_ADD_COMMAUTH 身份写入复核（2026-10-20）

- D25 从目标 immutable raw commit 绑定 11 个 IPC 源文件；T26 独立比对其中 5 个与身份闸门直接相关文件，SHA-256 全匹配。报告见 [D25 scout](ipc/b-line-20261020/d25_add_commauth_scout-20261020.json) 与 [T26 counterreview](ipc/b-line-20261020/t26_add_commauth_counterreview-20261020.json)。
- 结果为 **0 个已确认候选**。`DBinderAddCommAuth` 的 `GetCallerUid()<10000` 检查使用 databus invoker 的会话 callerUid；每条 databus transaction 在 dispatch 前先经过 `CheckAndSetCallerInfo`，必须命中既存 caller tuple/stubIndex/socket 映射；建立新 inbound socket 时还要求已有匹配 `CommAuthInfo`。
- 实质条件风险：`AddAuthInfo` 从 parcel 读 remote PID/UID/deviceId/tokenId/stubIndex，却不与当前 caller tuple 作等值检查；插入 mapping 的 socketId 为 0，而后续 `QueryAppInfoToStubIndex` 接受 stored socketId 0 作为 wildcard。若不可信端能通过低 UID 会话/既存 CommAuthInfo 闸门并控制受害者 tuple/stubIndex，可能污染后续身份映射。当前没有证明这些前提或具体未授权操作，因此不升级为候选。
- T26 独立验证了 D25 的 dispatch 前 gate 和新 socket authorization；同时保留未知：SoftBus 的 `PeerSocketInfo.name` 是否认证并绑定远端 OS UID，普通应用/远端能否建立 UID<10000 会话，攻击者是否能取得或猜中受害者 tuple/stubIndex。IPC 解析器本身只是解析 service-name 字符串，身份真实性依赖未绑定的 SoftBus/product build。
- 现有 unit/fuzz 对 handler 和 mapping 的测试多为 mock 或直接调用，未覆盖真实 databus session→AddCommAuth→mapping→后续 tuple 身份验证链；本轮未运行测试。

### 下一并行验证

```text
D27：绑定目标产品使用的 SoftBus revision/build，与 PeerSocketInfo.name → remote UID/PID 认证映射
 └─ T28：独立核验低 UID 入站会话/CommAuth 前置条件及映射污染反例
     └─ D27a 根据 T28 反馈修订来源/信任边界；T28a 复核结论
         └─ 若外部 SoftBus 与产品 build 无法绑定，维持 insufficient 并转审另一个有闭合 IPC 路径的窄范围
```

**D27 结构化提示词（开发/依赖绑定线）**：只围绕 IPC `DBINDER_ADD_COMMAUTH` 所需的 peer identity 边界，寻找目标产品 manifest/lock、GN resolved dependency graph、SoftBus commit 和构建记录，绑定 `PeerSocketInfo.name`、Peer UID/PID 获取与授权连接建立相关 SoftBus 实现的精确源版本。检查 service-name 编码的 UID/PID 是由 SDK caller 自报、系统派生还是由 transport 认证绑定；沿 `QueryCommAuthInfo`、socket acceptance 到 IPC `DBinderSessionObject` 的来源追踪。每个结论给 SHA/blob/提交及证据限制。没有目标产品配对证据就写 insufficient，不推断不可伪造，也不生成漏洞候选。只读，不改代码、不运行测试或真实网络试验。

**T28 结构化提示词（独立测试/反证线）**：独立审查 D25/T26 发现的条件链，不把 SoftBus repository HEAD 当成产品 pin。确认 SoftBus 是否认证 peer name 与 remote OS UID、低于 10000 的 endpoint 能否建连、`QueryCommAuthInfo` 的既存授权是谁能写入、AddAuthInfo 的 socketId=0 通配是否可将攻击者记录转成受害者身份。对照 D25 target IPC raw hashes 与已解析产品构建元数据；缺项一律 insufficient。给出安全的 test-only oracle：拒绝不匹配 caller tuple 的 auth mapping，并在后续 socket/cookie 上验证身份不串用；无隔离产品 harness 时不运行测试/PoC。最多 1 条候选，须有具体可达路径和后续授权影响。

## D27 / T28 — SoftBus 身份来源独立复核（2026-10-20）

- D27/T28 均判定目标产品没有可用的 manifest/lock/build record 将 IPC `bbb92db...` 与某个不可变 SoftBus revision 配对。活动 manifest 对二者都浮动到 `master`；两份冻结快照的 IPC 都是 `5903fd5...`，分别配 SoftBus `78e7835...` 和 `7743b67...`，只能证明它们不是目标配对。
- 两线对本地未固定 SoftBus snapshot 的观察一致：`PeerSocketInfo.name` 来自 session peer name，IPC 将其解析成 UID/PID；这说明字段流向，不证明其已绑定远端 OS principal，也不证明它可以被伪造。判定为 **unknown / unproven**，不升级为 candidate。
- T28 另外确认 socketId=0 的确在 `QueryAppInfoToStubIndex` 中作为已有 tuple/stubIndex 的 socket wildcard，但它本身不能创建入站连接，也绕不过新连接的既存 `CommAuthInfo` gate 和每条事务分发前 caller tuple/stubIndex gate。攻击者控制受害者 tuple、低 UID session 可达和具体未授权效果仍缺证。
- 目标配对缺失是外部依赖阻塞；当前不能用本地 SoftBus HEAD 代替，也不能把“无 IPC 层认证”推成“SoftBus 未认证”。**候选数保持 0**。若维护方提供真实产品 build lock，则针对该确切 SoftBus revision 重开窄审；否则继续检查其他能由 IPC pinned source 自身闭合的路线。
- 证据见 [D27 dependency pin review](ipc/b-line-20261020/d27_softbus_identity_pin-20261020.json) 和 [T28 independent review](ipc/b-line-20261020/t28_softbus_identity_counterreview-20261020.json)。

### 下一条 IPC-only 路径：DBinder 引用计数事务

```text
D29：审 DBINDER_INCREFS/DECREFS 的 caller context、对象引用/授权表更新、socket close 竞态
 └─ T30：独立从 pinned raw 重建 transaction vs OnSessionClosed 并发矩阵及已有单测/fuzz边界
     └─ D29a：只在 refcount/Detach 状态不变量出现可达破坏时设计小修
         └─ T30a：由测试线给红绿 oracle，独立复核修复后引用/授权清理
```

**D29 结构化提示词**：仅审目标 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 下 `DBINDER_INCREFS_TRANSACTION` / `DBINDER_DECREFS_TRANSACTION` 的特殊码 dispatch、`DBinderBaseInvoker::ProcessTransaction → CheckAndSetCallerInfo`、caller pid/uid/token/device/socket/stubIndex 的取得、`AttachOrUpdateAppAuthInfo` / `DetachAppAuthInfo`、`DecStrongRef` 及 `OnSessionClosed` 并发清理。对 INCREFS/DECREFS 分别绑定 immutable source SHA/blob，逐条件说明守卫和状态转换；重点查重复/重排/错配事务是否能在真实可达 gate 下造成未经授权引用保活、提前释放或权限残留。最多一条高置信候选；若只能看到可能竞态而不能证明状态不变量违反，则 0/insufficient。只读，不改产品代码、不跑测试或 PoC。

**T30 结构化提示词**：独立于 D29，按目标 pinned raw bytes 重建 receive dispatch 前置 identity gate、事务 caller tuple 来源、DetachAppAuthInfo 对 socketId/stubIndex/object 的精确匹配，以及 OnSessionClosed 与 DECREFS 的锁/竞态互斥关系。搜现有 unit/fuzz 是否直接调用 helper 或使用 mock；不把直接 helper fuzz 当端到端验证。对 D29 的每条候选尝试一个守卫支配或同步反例，报告 0/1 候选和确切缺少的运行时证明；若有静态状态破坏，给出不触达真实设备的最小隔离 oracle。只读，不运行测试/PoC、不改 scanner。

## D29 / T30 — INCREFS/DECREFS 与 session-close 引用清理（2026-10-20）

- D29/T30 从目标 commit raw source 独立绑定/复核了 5–6 个 IPC 文件；目标源码的 caller-map gate、精确 detach 与 close cleanup 路径一致。报告见 [D29 scout](ipc/b-line-20261020/d29_dbinder_ref_scout-20261020.json) 和 [T30 counterreview](ipc/b-line-20261020/t30_dbinder_ref_counterreview-20261020.json)。
- T30 发现 `IPCThreadSkeleton` 是 pthread TLS，`objectMutex_` 是 invoker 实例成员；worker 与 SoftBus shutdown callback 若运行于不同线程，会有不同 invoker/锁。因此 D29 的 `objectMutex_` 不能证明它们互斥。`appAuthMutex_` 能串行化 map 删除，但 gate 成功与 handler 更新之间并未由其单次持有覆盖。
- 保留 **1 条低置信条件生命周期候选 T30-R1**：request worker 已通过 `CheckAndSetCallerInfo`，并在 `TargetStubSendRequest` 经 `QueryStubByIndex` 取得裸 stub 指针；另一个线程的 shutdown callback 可通过 TLS 下的另一 invoker 实例（不同的 `objectMutex_`）删除 socket relation 并 `DecStrongRef`，潜在与后续 `SendRequest` 并发。request 路径未在 raw lookup 后取得临时 strong ref。尚未证明 SoftBus callback 与 worker 的并发顺序、被减引用是否为最后一份，或实际 UAF/可观察安全影响，故不是确认漏洞。迟到 INCREFS 的 stale relation 是次要状态：自身不能授权新连接，后续仍有 CommAuth 与 tuple gate，不作为主漏洞机制。重复 DECREFS 由精确 tuple/stub/socket detach 阻断。
- T30 反证 D29“锁已串行化”的潜在误读，D29/T30 均保留上述竞态供后续验证。现有 handler/map tests 和 fuzz 没有覆盖 session-close 与正在执行 transaction 的交错；本轮未运行测试或 PoC。产品运行时及 SoftBus callback 语义仍是验证门槛。
- **第二层 LLM 复核提示词（仅审 T30-R1）**：请核验目标 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 中 shutdown 与 request 生命周期。攻击叙述限定为：worker 已通过 `CheckAndSetCallerInfo`，`TargetStubSendRequest` 在 `QueryStubByIndex` 取得裸 stub pointer；shutdown callback 线程通过另一 TLS invoker 的 `objectMutex_` 删除同一 socket relation 并减引用；最后一份 strong ref 若降到零，可能与该 raw pointer 的 `SendRequest` 执行并发。逐项检查目标源码 hash、是否有 callback-worker 并发、是否另有临时 `sptr`/strong ref、stub index 删除和 `objectMutex_` 是否共享、last-ref 发生后 `SendRequest` 是否仍可执行，以及真实可观察影响。对 `supported/refuted/insufficient` 分别评价源码结构、线程调度可达性、last-ref条件和安全影响。反证 stale INCREFS row 是否只能 fail-closed；不要把它当作 UAF 机制。不得将注释“race”当证明，不推断已确认 UAF。缺产品 runtime overlap 证据时不升级 finding；输出最小安全测试 oracle 和精确缺项，不改 detector 或 finding lifecycle。

### 下一轮验证任务

```text
D31：source-state graph 发现 raw stub pointer 与跨线程 close 的条件生命周期候选；stale mapping 降为次要
 ├─ T30：独立确认 transport gate / per-instance lock / exact detach 边界（已完成）
 ├─ T32：测试可行性确认 barrier 应位于 raw QueryStubByIndex 返回后、SendRequest 前；当前产品构建受阻（已完成）
 └─ T33：第二个独立源码复核，核验 raw pointer 是否有其他强引用及 last-ref destructor 时序
     └─ D31a：仅当 T33 未反证且目标 runtime overlap 可证时提出最小生命周期修复
         └─ T34：产品 test-only close-before-lookup 与 close-after-raw-lookup 控制矩阵；修复后独立复放
```

**D31 结构化提示词**：只分析 T30-R1 的 cross-thread raw pointer window：追踪 `TargetStubSendRequest → QueryStubByIndex → SendRequest` 与 `OnDatabusSessionServerSideClosed → DetachAppAuthInfoBySocketId → QueryStubByIndex → DecStrongRef`。逐个 pinned target 文件 source-bind；确认 request 的 raw pointer 在调用期间有哪些强引用保护，close 是否可使 refcount 变为零，OnLastStrongRef 是否同步 erase stub index，以及两个 mutex 是否同一个实例。区分 stale mapping 次要状态与 raw pointer 生命周期机制；不要因可能时序推断 UAF。

**T32 结构化提示词**：独立评估真实可运行验证：确认目标 `communication_ipc` 与 SoftBus/product build 配对、OHOS clang/sysroot/GN args/build.ninja 和所需 target 是否存在；测试屏障必须置于 `TargetStubSendRequest` 成功 `QueryStubByIndex` 取得裸 pointer 之后、调用 `SendRequest` 之前。关闭线程随后完成 socket detach/ref drop，再释放 request 线程；控制组是 close-before-lookup，应 fail-closed。观测 refcount、destructor、stubIndex erase 与正在运行的 SendRequest，不把 stale mapping 单独当UAF。只提供 harness/命令/oracle，不做真实网络/设备试验；缺 OHOS 环境时列具体路径和命令缺项，不用 host ASan layout 替代产品验证。


## D31 / T32 / T33 — raw stub pointer 生命周期复核收敛（2026-10-20）

- D31 的 source-state 追踪将唯一保留项从 late-INCREFS stale row 修订为 raw pointer lifetime window；T33 第二条独立 review 确认同一结论：`TargetStubSendRequest` 在 `QueryStubByIndex` 后仅持有 raw pointer，没有临时 `sptr`/strong ref；close callback 通过线程局部 skeleton 获取另一个 invoker 时，per-instance `objectMutex_` 和已删除 stubIndex 均不能撤销已返回指针。
- 保持 **1 条 low-confidence conditional candidate，0 confirmed**。真实 target 中 SoftBus close callback 是否与 worker 同时执行、被 detach 是否为最后一份 strong ref、SendRequest 期间是否发生析构与安全影响仍未在 runtime 验证。late INCREFS stale row 不会自行授权新连接，不属于候选主因。
- T32 独立确认可用 test-only barrier 确定性测试；屏障修订为 raw `QueryStubByIndex` 返回后、`SendRequest` 前。控制组 close-before-lookup 应 fail-closed；竞态组在独立 callback thread drop last ref 后观察析构/index/refcount 以及 SendRequest。禁止单凭映射或 host harness 声称 UAF。
- 当前执行条件不足：GN/Ninja 可用，但缺 OHOS clang/sysroot、`out/rk3568/args.gn`、`build.ninja`，也缺 IPC `bbb92...` 与 SoftBus 的产品锁/build graph。T32 未运行测试。该验证列为明确外部构建阻塞；不能通过本地 `5903fd5` checkout 代替目标产品。
- D31/T32/T33 报告分别在 [D31 impact analysis](ipc/b-line-20261020/d31_dbinder_race_impact-20261020.json)、[T32 test feasibility](ipc/b-line-20261020/t32_dbinder_race_test_feasibility-20261020.json)、[T33 independent counterreview](ipc/b-line-20261020/t33_raw_pointer_counterreview-20261020.json)。

### 下一条 IPC-only 路径：INVOKE_LISTEN_THREAD 会话引导

```text
D35：审 INVOKE_LISTEN_THREAD 的 caller UID gate、parcel/session 初始化与初始 strong ref/AppAuth relation 写入
 └─ T36：独立核对 direct caller 与 databus caller context、stub/session 映射先后关系、失败清理与覆盖矩阵
     └─ D35a/T36a：仅在未授权 session/refcount 状态可达时反馈修正并提出 test-only oracle
```

**D35 提示词**：限定目标 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 `INVOKE_LISTEN_THREAD → DBinderInvokeListenThread → InvokerThread → InvokerDataBusThread/DBinderDatabusInvoker` 生命周期。追踪本地调用 caller UID 取值、`uid < ALLOWED_UID`、连接/会话参数、监听 socket setup、`AttachOrUpdateAppAuthInfo` 与 `IncStrongRef` 的调用顺序、所有失败清理。逐目标文件绑定 SHA/blob，核对是否普通低 UID caller 可控制非本进程身份字段或绕过首次授权登记。最多 1 个具体候选；没有闭合路径则 0。只读，不跑测试/PoC、不改代码。

**T36 提示词**：独立从目标 raw IPC bytes 重建 INVOKE_LISTEN_THREAD 引导流程，不以 D35 结论为前提。查实际生产调用者、parcel 来源、binder caller UID 与 session peer UID 的关系、初始 stub/ref/map 关系的创建/失败回滚以及相关 unit/fuzz 是否 mock 或直接调用 helper。逐条反证 D35 候选，报告 0/1 候选与测试 oracle；若只是当前产品配置未知，标 insufficiency。只读、不跑测试/PoC、不改产品或 detector。

## D35 / T36 — INVOKE_LISTEN_THREAD 会话引导复核（2026-10-20）

- D35/T36 从目标 immutable raw commit 分别绑定相关 IPC/C caller/test 源；两线均给出 **0 个确认或可报告候选**。`DBinderInvokeListenThread` 在读 Parcel 前要求本地 Binder caller 且 UID `< ALLOWED_UID (10000)`，普通应用 UID 通常 >=10000 时不能直接触发该特殊事务；parcel 中 remote PID/UID/token 与本地 Binder caller UID 分属不同信任域。
- C++ `GetSessionForProxy` 与 C `DBinderService::OnRemoteInvokerDataBusMessage` 是两条生产上下文，最终都经特权本地 Binder 调用走同一 `INVOKE_LISTEN_THREAD` handler；成功的正常路径在同步返回给外层 remote sender 前完成 listener/index/auth/ref 登记。单测覆盖部分 UID 和错误分支；直接 helper fuzz 不具备真实 Binder caller 或 peer identity。
- D35 标记了 listener 启动或 stub index 建立后的部分失败分支没有立即 rollback。T36 复核后修正：同一 stub 的 `AddStubByIndex` 会复用 index，不会按请求累积；异步 shutdown cleanup 不一定发生在回复/对端建连前；`AttachOrUpdateAppAuthInfo` 对 socketId=0 的 duplicate 条件不同于 D35 初读。没有证据证明这些分支可由普通 app/任意远端驱动或造成持续资源耗尽。
- 另一个低优先级运行时问题：`CreateSoftbusServer` 换不同 name 时启动新 listener 并覆盖当前 socket/name，而 IPC 本身未显式关闭旧 socket。是否旧 listener 残留、SoftBus 会否自行替换关闭，以及不可信远端是否可反复触发不同名称，均依赖未绑定 SoftBus/product 语义；T36 不将其列为 L2 candidate。
- 报告：[D35 scout](ipc/b-line-20261020/d35_invoke_listen_scout-20261020.json)、[T36 counterreview](ipc/b-line-20261020/t36_invoke_listen_counterreview-20261020.json)。只读、未运行测试/PoC、未改产品或 detector。
- 下一步：保留 T30-R1 为唯一 L2 条件候选；另外选一个普通 caller 数据披露边界（GET_SESSION_NAME / GET_PID_UID）做 D37/T38，先查特殊码 public guard、helper 符号导出和本地 Binder UID/registry proxy 可达性，最多 0/1 候选。如果标准 ABI/事务 gate 明确阻断，则只记录 source-level refutation，不扩展为通用系统服务隐私报告。

**D37 结构化提示词**：目标 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 下限于 `GET_SESSION_NAME` 与 `GET_PID_UID` 两种特殊事务。对 `IPCObjectStub::SendRequest` dispatch、两 handler 的 local/UID/IsSamgr 规则、返回值实际内容、IPCObjectProxy helper/public `SendRequest` code-range guard、`ipc_single` version map export 逐文件 raw-pin；追踪普通 app 是否可取得特定 stub/registry proxy、调用哪个 API 并拿到 service session name/PID/UID。候选只有在普通 caller 既能通过产品 API 边界又能取得具有实际隐私影响的数据时才输出；不得把方法头文件 public 当作 ABI 可达，也不做泛化的 PID 信息披露。只读，不改代码、不跑测试/PoC，最多 1 条候选。

**T38 结构化提示词**：独立反证 D37：从 target raw 源/目标 SDK GN/export metadata 重建完整 app 调用链。分别判定 `GET_SESSION_NAME` 是返回当前 stub 的 databus name 还是由 SAMGR 派生内容，`GET_PID_UID` 返回本服务进程还是 caller 身份；确认 `IsLocalCalling` 是否只说明 Binder transport、`IsSamgrCall` 是 receiver state，及 `IPCObjectProxy::SendRequest` 是否拒绝 special codes。核验标准 SDK 导出映射与 registry proxy 获取边界，并检查现有测试。按数据敏感度、应用可达性和实际影响分项判 `supported/refuted/insufficient`；只在 closed chain 下留候选，不运行测试/PoC。

## D37 / T38 — GET_SESSION_NAME 与 GET_PID_UID 数据边界（2026-10-20）

- D37/T38 的目标 raw pins 对照一致；`GetSessionName()` 是公有且标准 version map 导出的 helper，内部直接 `SendRequestInner`，绕开通用 special-code guard；返回 target service 的 `DBINDER_SOCKET_NAME_PREFIX + uid + '_' + pid`。`GET_PID_UID` 返回 receiver pid/uid，但没有公开 typed helper/export，普通 generic `SendRequest` 在事务码范围检查处失败。
- T38 确认 `GetSessionName()` 是 API level 9 起的预期 DBinder 生命周期查询，`DBinderDatabusInvoker::GetSessionForProxy` 会用它来建立 peer session；拿到目标对象 proxy 即可调用，不需特定 registry proxy。返回内容只暴露数字化 service process UID/PID。未找到证据表明此信息属于受保护数据或一般服务调用者不应获得；产品 SDK 对第三方 app 的具体链接政策也没有绑定。
- 按“少而准”门槛，**D37-C1 不保留为漏洞 candidate**：数据流/公开导出事实成立，但合法用途明确，隐私影响和新增攻击能力没有闭合。可在产品/API policy 明确限制且能证明敏感性时再重开，不递交第二层漏洞复核。`GET_PID_UID` 维持 source-path refuted。
- 交付：[D37 scout](ipc/b-line-20261020/d37_session_pid_scout-20261020.json)、[T38 counterreview](ipc/b-line-20261020/t38_session_pid_counterreview-20261020.json)。未运行测试/PoC，未改产品代码。

### 下一条并行路径：GET_GRANTED_SESSION_NAME

```text
D39：审目标 SAMGR stub 的 caller gate、CreateSessionName、SoftBus grant副作用与普通本地调用可达性
 └─ T40：独立核对 GetGrantedSessionName 导出/调用、caller uid/pid来源、跨进程策略及现有测试
     └─ D39a/T40a：只在未授权 permission grant 或可观察跨caller影响闭合后，定义隔离红绿测试
```

**D39 结构化提示词**：只审 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 `GET_GRANTED_SESSION_NAME → IPCObjectStub::DBinderGetGrantedSessionName → GetGrantedSessionName → CreateSessionName → DBinderGrantPermission`。核 handler 要求的 `IsLocalCalling` 与 `IsSamgrCall` 分别表示什么，目标 SAMGR registry proxy 如何取得，`IPCObjectProxy::GetGrantedSessionName` 是否标准导出以及其正常生产调用者；追踪使用的 caller pid/uid、session key 是否来自 Binder caller 或 parcel、SoftBus grant 对目标主体的实际效果和 cleanup。按目标 raw 文件 SHA/blob 绑定。最多 1 个候选；必须证明普通应用可达并产生超出自身预期 DBinder bootstrap 的授权或跨主体影响。只读，不改代码、不跑测试/PoC。

**T40 结构化提示词**：独立反证 D39：从 pinned raw 源和标准 SDK link map/GN 重新核 helper export、registry proxy access、receiver-side SAMGR flag、Binder caller pid/uid 来源及 grant sink。确认 `GetGrantedSessionName` 是否仅允许 SAMGR receiver、SAMGR 是否根据真实 Binder caller身份授予该 caller 自己的 DBinder name、返回值是否受其他 service 访问策略约束、现有 unit/fuzz 覆盖了什么。针对任何 D39 candidate逐因果边尝试反证；若是有意的 caller-self bootstrap 且无跨主体效果，则判 0。只读不跑 PoC/测试，不改产品/detector。

## D39 / T40 — GET_GRANTED_SESSION_NAME 授权副作用与生命周期计数（2026-10-20）

- D39 以 IPC `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 immutable raw source 绑定九个文件，包括 `DBinderSoftbusClient` 与 socket shutdown 调用点；核心哈希见 [D39 报告](ipc/b-line-20261020/d39_granted_session_scout-20261020.json)。T40 确认 typed `GetGrantedSessionName` 不在标准 export map，SAMGR 收到的 nested Binder PID/UID 是请求服务自身身份；不是 parcel 可控的其他主体身份。
- D39 还闭合了一条相邻计数链：每次成功 `GET_SESSION_NAME` 都令服务对自己的固定 UID/PID session name 向 SAMGR 请求一次 grant，IPC 的 `mapSessionRefCount_` 同名计数 +1。查询本身没有对应 remove；可见的 remove 经 `ServerOnShutdown` / `ClientOnShutdown` 回调各执行一次。成功完成的 socket 生命周期可能自然配对，但重复查询、失败或未完成连接可能留下额外同名引用。
- T40 指出本地未配对 DSoftBus 对同名动态 permission 去重；这既不能证明目标产品的 backend 行为，也没有显示唯一槽耗尽。目标 SoftBus revision、第三方 SDK 可达政策以及额外引用的持续权限/可观察影响均未证明。
- 因此 **0 个确认/可报告候选**；仅记 D39-R1 为条件性生命周期观察。不得把潜在引用不平衡升级为 DoS 或跨主体权限问题，除非补齐真实产品配对、普通应用调用路径与具体影响。未运行测试/PoC，未改产品或 detector。

### 下一轮并行任务树（开发与测试往返）

```text
D41：为唯一保留的 T30-R1 找到目标产品构建/运行时来源，确认 close callback 与 request worker 的线程/锁关系；形成可注入的确定性 test seam 设计
 ├─ T42：独立审查 test seam、现有 IPC 单测/测试替身和线程模型证据；尝试反证竞态/最后引用前提，并给出通过/失败 oracle
 └─ D43：静态窄扫相邻 DBinder transaction 错误退出与 socket close cleanup；0/1 高置信候选上限，输出源 pin 和守卫支配矩阵
     └─ T44：对 D43 每个候选独立反证，检查错误分支是否可达、是否已有回滚/引用保护、是否具备实际影响
D41/T42 若闭合真实竞态且产品构建可用 → D45 实现最小修复/回归测试 → T46 独立验证红绿结果与邻近回归
否则 → 保留条件候选或关闭，并记录外部阻塞；不写猜测性产品补丁。
```

**D41 结构化 vibe coding 提示词（开发/验证准备线）**：在 IPC 固定 commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 和当前 OHScanner 最新基线下，围绕 T30-R1 查清 `QueryStubByIndex` 到 `SendRequest` 的裸指针寿命、`IPCThreadSkeleton` TLS、各 `objectMutex_` 实例及 `OnSessionClosed`/SoftBus callback 的真实线程来源。优先寻找目标产品 manifest/build lock、OHOS clang/sysroot、已生成 GN/Ninja 构建与 test target；逐一记录路径、版本和 hash。设计 test-only barrier seam：暂停 lookup 返回与 `SendRequest` 之间，另一线程执行真实 close/last-strong-ref release，观测析构次数、活动调用、stub index 与安全结果；加入 close-before-lookup fail-closed control。只在目标 harness 可配对时实现最小 test-only seam，不改生产语义；没有匹配构建环境就交付可复现步骤和明确阻塞。先不做修复，不运行 PoC，不声称动态结论。

**T42 结构化 vibe coding 提示词（独立测试/反证线）**：不依赖 D41 的结论，按目标 raw source 与现有测试重建 `TargetStubSendRequest → QueryStubByIndex → SendRequest` 和 close/DECREFS 路径；核对 `sptr`/strong ref 是否在拷贝后仍被其他局部对象持有、stub index erase 是否会析构对象、TLS invoker 是否可共享、callback 是否保证同线程串行。检查现有 unit/fuzz 是否覆盖 lookup 后 close 的交错；给 D41 barrier 测试设定红绿 oracle、调度重复次数和无竞态控制。候选最多 1 条；若强引用或线程串行化已经闭合，明确 refute；若缺产品 runtime/build 配对，结论是 insufficient。独立记录 source hashes，不运行测试/PoC、不改生产代码。

**D43 结构化 vibe coding 提示词（静态候选线）**：在同一 immutable IPC target 上只筛选相邻 DBinder transaction 的失败返回、部分状态提交与 socket-close cleanup：从 transaction dispatch 前置 caller tuple gate 到 handler 的每个状态写入、每个 early return、对应 rollback/remove/DecStrongRef，建立守卫支配表。只输出 0 或 1 条真正闭合的高置信候选，要求可达路径、状态不变量破坏和具体安全影响都由 pinned source 支持；常见错误处理缺陷、超时、理论计数增长不算候选。源文件 SHA/blob、函数/分支、已有测试覆盖和反例都要记录。只读，不改产品/detector，不运行测试/PoC。将候选 packet 交 T44，静态候选供后续第二层 LLM 复核而非自行扩写漏洞结论。

**T44 结构化 vibe coding 提示词（独立测试/反证线）**：独立对 D43 的 source pins 和每条候选重建控制流，针对 caller gate、错误回滚、socket teardown 幂等性、强引用拥有者和现有测试夹具逐项反证。对每个可行候选给最小隔离红绿 oracle；不把 mock-only helper test 当端到端覆盖，也不把本地非配对 SoftBus 当目标事实。若没有一条通过可达性+影响门槛，确认 0 并建议停止该分支。只读，不运行测试/PoC、不改产品代码。

**反馈闭环**：D41 把实际构建能力和 seam 条件发给 T42；T42 的反例用于收窄/撤销 T30-R1。D43 将每一处状态写入—退出—清理链交 T44；T44 的反证回流给 D43 只允许补证或撤回，不允许无证据放宽。只有任一线闭合可达且有影响的候选后，才由开发线拟最小变更、测试线先定义 oracle 再独立复核。

**持续验收条件**：每轮先确认 `origin/main`；任务树中每条开发线有独立测试/反证线；每个候选有 immutable source pin、信任边界、可达性、影响、反例和测试状态；静态候选保持 0–1 且足够高置信，供第二层 LLM 后续审查；产品修改必须有测试红绿结果。OHOS toolchain、product lock 或 SoftBus pairing 任一仍缺失时，明确记外部阻塞并继续可独立完成的静态/测试设计工作，直到验收满足或只剩需外部输入的阻塞。

## D41 / T42 与 D43 — 测试可行性及清理路径静态复核（2026-10-20）

- D41/T42 以目标 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 复核 T30-R1。D41 确认可测试屏障位于 `QueryStubByIndex` 成功返回 raw pointer 后、`SendRequest` 前；测试控制包括 close-before-lookup（应 fail closed）、额外 strong owner、请求先于 close。T42 未发现临时 strong ref、共享跨线程 mutex 或 map erase 可封住 lookup-first 窗口；同线程串行与额外 strong owner 是有效反证控制。
- 结论仍为 **0 confirmed / 1 conditional（T30-R1）**。尚无配对 SoftBus callback/worker 并发证据、最后引用证明、析构后调用/ASan观察或具体影响。D41 复核到本地 IPC/SoftBus revision 与目标不配对；无 OHOS clang/sysroot，`out/rk3568` 无 `args.gn`/`build.ninja`。WSL 本轮复核遇 service error，沿用 T32 已记录的环境 inventory，不声称新鲜构建检查。测试未执行。
- D43 静态窄扫覆盖 special DBinder transactions、dispatcher、`ProcessTransaction`、失败退出与 close cleanup，绑定 5 个 immutable target 文件。结果 **0 个确认、0 个新增条件候选**；复用的三项条件观察是 T30-R1、D35/T36 listener 建立后迟失败无 rollback、D39/T40 同名授权计数。它们都欠缺可达性或具体安全影响。报告由 T44 独立复核中。
- 报告：[D41 seam feasibility](ipc/b-line-20261020/d41_test_seam_feasibility-20261020.json)、[T42 counterreview](ipc/b-line-20261020/t42_lifetime_counterreview-20261020.json)、[D43 static scan](ipc/b-line-20261020/d43_dbinder_cleanup_static_scan-20261020.json)。只读，未跑测试/PoC，未改产品/detector。

**当前任务树**

```text
T44：独立反证 D43 的0新增候选结论和三个已知条件观察（进行中）
 ├─ 若发现闭合且可达的状态破坏：T44 给红绿 oracle → 开发线 D45 才可拟最小修复 → 独立验证 T46
 └─ 若无：明确0候选，继续保留 T30-R1 等待产品 runtime/build 配对；其他静态源继续按0–1候选上限

产品动态验证解阻塞：需要目标 IPC+SoftBus 产品 lock、OHOS clang/sysroot 和生成构建配置。没有这些证据就不伪造测试结果；仍可继续 immutable IPC 源静态审查与测试设计。
```

## T44 — D43 窄扫独立复核完成（2026-10-20）

- T44 独立重取目标 IPC commit 的六个重叠源文件，SHA-256 与 D43 一致。结论：**0 个新增确认候选、0 个新增条件候选**。
- R1 INCREFS/close：精确 row detach 避免同一行重复减引用；late INCREFS 仍需原有活跃 session/cookie/stub/socket gate，未发现其令已关闭 session 产生可用后效，归入 T30-R1 相邻时序观察。
- R2 INVOKE_LISTEN_THREAD：setup 后迟失败确有未即时 rollback；入口要求 local Binder 且 UID<10000，重复同 stub index 复用 index，未证明普通应用可达或有害残留。
- R3 GET_SESSION_NAME grant：IPC 同名 refcount 可增加且 grant 先于 reply，但 immediate SAMGR caller 是服务自身；缺第三方 app policy、精确配对 SoftBus、可观察权限/可用性影响。
- 报告：[D43 scan](ipc/b-line-20261020/d43_dbinder_cleanup_static_scan-20261020.json)、[T44 counterreview](ipc/b-line-20261020/t44_cleanup_counterreview-20261020.json)。未跑测试/PoC，未改产品/detector。

### 下一轮并行任务：第二层盲审现有条件候选

```text
T45：将 T30-R1 提交第二层盲审，判断其是否为真实漏洞、证据充分性、最小证明要求
 ├─ T46：独立复核 D39-R1 生命周期/授权计数观察，找普通应用可达性和具体影响的闭合或反证
 └─ D47：根据两份审查，收敛一个不依赖猜测的目标产品证据清单/继续开发门槛；不改产品代码
T45/T46 如均判 insufficient → 只保留条件观察，停止漏洞宣称；如任一发现闭合路径 → 下一轮先由测试线定义安全隔离的验证 oracle，再进入开发修复线。
```

**T45 结构化二层 LLM 提示词**：盲审以下单一候选，不接受输入中的结论为事实：在 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`，DBinder worker 通过 caller tuple gate 后，`TargetStubSendRequest` 经 `QueryStubByIndex` 取得 raw stub pointer；查询 map lock 返回后，worker 尚未取得临时 strong ref 即调用 `SendRequest`。若另一线程的 socket shutdown callback 使用不同 TLS invoker/per-instance `objectMutex_`，Detach+`DecStrongRef` 可能释放最后引用。请基于 D29/T30/T32/T33/D41/T42 immutable raw pin，分别判断（1）可达性，（2）线程调度证据，（3）最后引用，（4）释放后的实际内存安全访问，（5）攻击者控制与影响，（6）target product/SoftBus pairing，（7）现有测试是否覆盖。主动寻找 sptr 所有者、共同锁、callback 同线程保证、handler gate、调用期引用保护等反例。输出 supported/refuted/insufficient 及证据强弱；只有可达且影响闭合才判漏洞。若 insufficient，给出最小测试 oracle（barrier + 反证控制）和必须取得的产品材料。不得发明 SoftBus 行为；不运行测试/PoC，不改产品代码。

**T46 结构化独立复核提示词**：盲审 D39-R1：每次导出的 `GetSessionName` 都令 receiver service 向 SAMGR 获取自身 session name；IPC `mapSessionRefCount_` 按同名递增，源码可见 remove 经 socket shutdown callback，而不是 per-query。独立重建 exact caller身份、调用导出/SDK边界、每次 GET 是否必然建立 socket、失败路径是否可造成不配对、同名计数实际影响、target SoftBus 配对和权限策略。分别给出 source-supported / product-unbound / refuted；寻找另一处平衡 remove、唯一身份键、可触发性门限或只影响服务自身的边界。候选最多 1 条；若没有普通 app reachability 与 material effect 的闭合路径，判 0。只读，不跑测试/PoC，不改代码。

**D47 结构化开发提示词（证据门槛，不是补丁）**：将 T45/T46 的支持证据、反证与缺口整理成可执行的 target-product proof matrix，按“需提供的 manifest/build lock、SDK export policy、callback thread provenance、last-ref instrumentation、影响 oracle”列出 owner、精确 artifact、验证步骤、通过/失败判据。已有 D27/T28/T32/D41 的材料只引用其路径/hash，不重复猜测。若外部材料缺失，将其标为阻塞并保留静态结论；不得改产品语义，不得把环境失败记成漏洞成立。

**持续反馈闭环**：T45 候选审查会决定 T30-R1 是否值得申请动态证明；T46 对 D39-R1 同样给出明确 go/no-go。D47 汇总两者的具体证据请求。下一轮必须先回应 reviewer 的反例和证据门槛，再谈修复；每个路线静态候选仍限制为 0–1 条。

## T45 / T46 — 第二层盲审初步结论（2026-10-20）

- **T45 / T30-R1**：机制层 supported，漏洞确认 insufficient。源代码确有 raw pointer lookup 与 `SendRequest` 间未增临时强引用的可能窗口；但跨线程 callback overlap、socket relation 是否最后引用、析构后访问、攻击控制与实质影响均未证明。结论 **0 confirmed / 1 low-confidence conditional**；不得报告 confirmed UAF 或据此改产品。GO 门槛是目标产品配对、跨线程回调并发、最后引用和受控析构后访问四项证据。
- **T46 / D39-R1**：每次 GET 可能为服务自身同一 UID/PID 增 IPC 引用计数得到独立复核支持；`GET_SESSION_NAME` 本身不创建 socket，正常路径会另行建立 listener/session，shutdown callback 执行清理。普通第三方 SDK/proxy 可达性、配对 SoftBus 授权语义、残留 self-permission 的物质影响仍未绑定。结论 **0 candidate / 1 conditional observation**。重开条件是 shipped SDK/API policy+app route、exact SoftBus pairing、真实且可观察的安全影响与现实触发上限。
- T45 与 T46 报告均没有运行测试/PoC，也没有修改产品代码。详细证据分别见 [T45](ipc/b-line-20261020/t45_second_layer_t30_r1-20261020.json)、[T46](ipc/b-line-20261020/t46_granted_session_l2_review-20261020.json)。
- D47 正在整理两条路线的目标产品 proof matrix；矩阵完成后依照它发起下一轮可由现有证据推进的静态/测试工作。当前静态筛查没有可立即安全修复的已确认候选。

## D47 — 目标产品证据矩阵完成（2026-10-20）

- D47 已整合 T45/T46 结论，按依赖顺序列出 6 项需外部材料与验证：PM1 产品 IPC/SoftBus/c_utils/toolchain lock；PM2 已发布 SDK/export 与 service proxy policy；PM3 callback thread provenance；PM4 last-strong-ref controlled trace；PM5 T30-R1 memory-safety/impact oracle；PM6 D39-R1 同名 grant/remove/backend 语义及现实影响。
- 每项均给出当前证据、责任方、要取得的 artifact、复核步骤、pass/block 判据及依赖关系。当前缺 PM1/PM2、OHOS clang/sysroot 与生成 target build files；动态测试仍不能执行。矩阵：[D47 proof matrix](ipc/b-line-20261020/d47_target_product_proof_matrix-20261020.json)。
- 证据缺失期间继续独立源码审查，不将环境阻塞误当漏洞，也不暂停仍可进行的静态工作。

### 下一条并行源码线：death-recipient / obituary 生命周期

```text
D49：审 Binder/DBinder death-recipient 注册、移除、对象死亡通知与 obituary 回调的状态/引用生命周期
 ├─ T50：独立重建控制流、锁/引用和通知顺序，挑战D49候选并找现有反例/测试覆盖
 └─ 若0/1候选成立：测试线先定义隔离oracle → 第二层盲审 → 才考虑开发修复
```

**D49 结构化 vibe coding 提示词**：只看 `openharmony/communication_ipc` immutable commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 death-recipient/obituary 一条生命周期路由，追踪注册、移除、远端对象销毁、Binder `BR_DEAD_BINDER`/`BR_CLEAR_DEATH_NOTIFICATION` 以及 DBinder obituary 处理。检查并发 add/remove、重入回调、重复/迟到通知、锁顺序、sptr/handle/refcount 与失败清理，逐项标明 caller 可控性和信任边界。仅在 source 足以闭合时输出最多 1 个高置信候选；动态 driver/SoftBus 语义和产品配对未知必须写 unknown。绑定所有目标文件 raw SHA-256/Git blob，列出已有 unit/fuzz 覆盖而不运行。交付 JSON；只读，不改代码、不跑测试/PoC。

**T50 结构化 vibe coding 提示词**：独立于 D49，从同一 immutable target raw 重建 death-recipient/obituary 的完整生命周期。分别反证：handle/token 是否校验；注册失败是否回滚；unlink 是否幂等；callback 是否可能在锁内重入；strong reference 是否覆盖通知执行；clear notification 是否保证晚于 in-flight callback；Binder driver 是否仅作为未绑定依赖。对 D49 的每条候选给精确 source pin、最强反例、现有测试缺口及最小 test-only oracle；没有闭合路径就报0。不得推断未配对依赖行为，不运行测试/PoC，不改产品代码。

**测试反馈设计**：若存在可静态表达的竞态，T50 先定义 callback barrier + add/remove/destroy 顺序矩阵及幂等/生命周期 oracle；D49 只据此补充必要 source evidence，不先写生产修复。当前基线 `origin/main = db77164fdc2af0da02e4d3efc056d84694fd68e8`，每轮开始需再次 fetch 核验。

## D49 / T50 — death-recipient 与 obituary 生命周期复核完成（2026-10-20）

- D49/T50 检查了目标 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 的 Binder `BR_DEAD_BINDER` / `BR_CLEAR_DEATH_NOTIFICATION` 和 DBinder death-recipient ADD/REMOVE 路径。Binder death delivery 的 cookie 对象/strong-ref 保护成立；recipient vector 在锁外调用，重入路径没有显示可确认 UAF。DBinder close 通过 `QueryObject`/weak-to-strong promotion 取得对象，随后清通知与映射，未发现已确认生命周期漏洞。
- 找到一个**源码观察而非安全候选**：`AddDbinderDeathRecipient` 先 `IPCObjectProxy::AddDeathRecipient`，之后再插入 service bookkeeping；后续 attach 失败时没有 rollback。目标 proxy 对 DBINDER handle 会把 recipient 放入 `recipients_` 并返回成功。直接 helper 重复调用/失败注入可在 proxy 存活期间留下强引用和回调负担，但公共 API 对 callback stub 去重并串行，普通 `SendRequest` 拒绝 `_DOT` special code；内部入口为 private。Helper fuzzer 直调不能证明生产可达性。远端死亡或 proxy destroy 会清理；没有证明永久泄漏、跨主体效果或实质可用性影响。
- 判定 **0 确认、0 条件安全候选**；只将 D49-R1/T50-R1 保留为源码观察。未来回归 oracle：对隔离 helper 强制每个 post-registration failure，断言 proxy recipient 和两类 map 都回滚；public duplicate API 对照应最多发一次 ADD。未执行测试/PoC、未改产品代码。
- 报告：[D49 scout](ipc/b-line-20261020/d49_death_recipient_scout-20261020.json)、[T50 counterreview](ipc/b-line-20261020/t50_death_recipient_counterreview-20261020.json)。

### 下一条并行路线：DUMP_TRANSACTION

```text
D51：静态重建 DUMP_TRANSACTION 的接收 gate、caller 权限、目标选择和输出敏感度
 └─ T52：独立反证 app 可达性/权限边界/数据影响，并给最小隔离 oracle
     └─ 若候选闭合：第二层盲审 → 测试线给 oracle → 开发最小修复
        否则：0 candidate，继续下一条未覆盖 IPC 路线
```

**D51 结构化提示词**：仅审 IPC `DUMP_TRANSACTION` 特殊事务，目标 commit 固定为 `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`。从 Binder dispatcher 到接收 stub 的每层 gate，绑定 UID/PID/token、dump permission、local/remote 运输限制、目标对象选择以及 Parcel/FD 输出字段；确认普通 app 是否能通过标准 API/导出 helper 到达，而非仅头文件声明或 raw special code。只有具体敏感内容/权限影响、可达路径和现实安全后果闭合时才给最多 1 条候选。对每份源文件绑定 immutable SHA/blob，检查但不运行现有 tests/fuzz，列出最强反例和隔离 oracle。只读，不改代码、不跑测试/PoC，不推断未配对 driver/产品行为。

**T52 结构化 vibe coding 提示词**：独立重建目标 IPC DUMP_TRANSACTION 的 dispatch、调用身份、dump permission、普通 `SendRequest` special-code guard、任何 typed helper/export、目标服务的 dump policy、输出 Parcel 及应用可观察性。逐项挑战 D51 候选，检查系统服务是否重复做 permission check、通用 Binder dump ACL 是否覆盖普通 app、是否只返回公开诊断字符串，以及数据是否被权限/调用上下文过滤。源与 build/API packaging 不明处标 `unknown`。报告 0/1 候选、source hash、已有覆盖/测试缺口和最小 test-only oracle；不运行测试/PoC，不改产品代码。

**反馈闭环**：D51 交 raw evidence 和逐层 gate 后，T52 独立尝试反例；若 T52 找到缺失约束，D51 必须补源证据或撤销候选。只有两线均支持同一可达且有害路径时才送第二层审查；之后先由测试线确定红绿 oracle，再决定是否产生产品补丁。

## D51 / T52 — DUMP_TRANSACTION caller policy 与数据边界（2026-10-20）

- D51 绑定目标 commit 的 9 份源码，T52 独立核对 11 份相关源码。`IRemoteObject::Dump` 是 API 9 起公开 typed API，proxy `Dump(fd,args)` 会经 `SendRequestInner` 发起 DUMP_TRANSACTION（通用 SendRequest 也将其从 special-code 拒绝条件中豁免）。因此 API-level reachability 成立。
- 接收端在解析 FD/args、调用服务 `Dump` override 前验证 **local Binder + calling UID 为 0、2000 或 1212**；普通应用 UID 和 Databus caller 不进入 dump handler。底层默认 handler没有证明泄露敏感内容；特定服务 override 输出敏感信息属于独立服务策略问题，本轮未绑定目标产品/服务。
- T52 独立复核与 D51 一致；明确区分 public typed API 与 version-map 中覆写符号的 export，不将二者混淆。现有 tests/fuzz 覆盖 mocked gate、Dump 参数和 FD 行为，但没有跑产品级/kernel身份测试。
- 判定 **0 confirmed、0 conditional candidates**。报告：[D51](ipc/b-line-20261020/d51_dump_transaction_scout-20261020.json)、[T52](ipc/b-line-20261020/t52_dump_transaction_counterreview-20261020.json)。未跑测试/PoC，未改产品代码。

### 后续来源

D17 bounded receive review 排除的 death/obituary、DUMP_TRANSACTION 已完成；特殊 session/授权事务、DBinder close/lifetime、一般 Parcel receive boundary也已有独立审查。下一开发回合先重核可联网的 `origin/main`；若基线仍 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，则优先检查当前 B-line scanner 开发任务树/实现状态，确定是否缺少可重复的候选精度/去重门槛，并由一线设计最小 scanner change、二线独立测试候选与误报集。若 GitHub 连接仍失败，保留已核验基线标记为 stale/unknown，不声称是最新，继续基于只读源码审查推进。

## B 线当前代码任务状态核查（2026-10-20，integration worktree）

本轮直接检查了真实 B 线 task worktrees，发现当前 IPC detector 开发不是从零开始，而是已有一组以 `db77164fdc2af0da02e4d3efc056d84694fd68e8` 为基线的 dirty work。本轮后续成功执行 `git fetch origin main`：`origin/main`、`FETCH_HEAD` 与 integration worktree HEAD 均为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，`HEAD...origin/main` 为 `0 0`。该 SHA 是本轮验证的最新 main。

```text
D1 Data01: Parcel 派生 copy-range 语义与本地 pointer/reference alias invalidation
 └─ T1: IPC rule-version map / finding source identity tests
D2 AUTH-01: 避免错误 descriptor 比较掩盖实际匹配 guard
 └─ T5: per-sink multi-dispatch guard matrix（多 switch、分支、条件退出、不唯一 helper）
D3: parser/global 与 IPC detector coverage denominator 合约验证（当前改动在 owner-only shared file）
  └─ 待 scope-owner 单独处置；不可从 B lane 直接搬动 tests/test_ohscanner_m1.py 改动
```

- integration worktree 当前允许路径修改：`analysis.py`、`detector.py`、`models.py`、IPC fixtures/manifest 及 `tests/test_ipc_*.py`；我从 T1 worktree **选择性迁入**其 `test_ipc_rule_versions.py`（路径属于 IPC allowlist），不迁入其中对 `test_a_ccr_03_finding_identity.py` 的共享改动。
- D3 的 `tests/test_ohscanner_m1.py` 修改超出 IPC allowlist/属于共享 owner 内容，保留在 [D3 独立工作树](</D:/openHarmonyScanner/worktrees/b-d3-source-coverage-20261020/tests/test_ohscanner_m1.py>)。其中新增 coverage denominator 测试在 WSL venv 单项通过，但这不构成允许搬入 shared-owner 文件的授权。
- 范围检查 `python -m scripts.check_change_scope --base db77164fdc2af0da02e4d3efc056d84694fd68e8 --lane ipc` 通过，`violations=[]`；`git diff --check` 通过。
- WSL Ubuntu Python 3.12.3 (`/home/deepsleep/ohscanner-venv`) 的最新 IPC 整体定向回归：`python -m unittest discover -s tests -p "test_ipc_*.py" -q`，**385 tests, 1 skipped, 0 failed**。最新 Windows pytest data-flow/relay/multi-dispatch/rule-version/coverage 定向组合 **104 passed**；scope check `violations=[]`，`git diff --check` clean。
- WSL 全量 `python -m unittest discover -s tests -q` 的最新复跑：**1184 tests, 12 skipped, 1 failure**，唯一失败仍为 `test_ohscanner_m15.OfflineGitTests.test_promisor_clone_never_fetches_missing_blob`。用例预期 `missing_local_git_object`，但当前缺失 promisor object 时 Git 输出 `lazy fetching disabled / could not fetch ...`；与 IPC 改动无关。随后成功 `git fetch origin main` 并确认远端仍为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，HEAD 无领先/落后。Windows Anaconda Python 3.13 全量结果不作为主验证，因为缺 FastAPI/fcntl、clang/行尾差异导致额外环境失败。
- D1 首轮独立审查发现 unused pointer/reference alias 声明导致安全 exact-capacity copy 误报；开发线删除声明期事实失效并补正反回归。后续 P1 逐层发现并修复 copy 目的别名写入的 casts、括号和指针算术形式，以及等价下标/复合写入。调用解引用分析覆盖 `Mutate(*p)`/`std::swap(*p, ...)`，Parcel 值写入 API 作为只读输入消除误报。引用从 `*p`、`*(p+0)`、`p[0]`、`0[p]`、指针副本 `q=p` 与取址 `*(&n)` 的初始化和写入均通过独立复核；额外 `**pp`、`q=p+0`、`q=&(*p)` 写入探针也保留候选。最新全仓结果为 1180 项/12 skipped/1 个无关的 promisor Git 环境失败；远端仍无法连接确认，未提交/未合并。
- D2/T5 独立复核未发现 guard dominance / multi-dispatch 正确性缺陷。按建议将 relay fixture 改为缓存一次 token，并加入 relay+双 sink 回归；确认 guard 前 sink 保留候选、guard 后 sink 被保护。相关测试 **20 passed**。
- D3 将 shared-owner 的 coverage denominator 意图改写成新 IPC-only `tests/test_ipc_coverage.py`，使用正式 `M2IpcInterfaceDetector`/runner 验证完整 C++、部分 C++、无 AST 的适用 C++、JS 排除、计数互斥、hash 与具体 unexamined 原因，没有改 shared-owner 文件。T1 将 hand-built identity 测试改为实际 `DetectorRegistry`/`run_all_with_coverage`，分别验证缺 blob OID 时 unknown，以及输入 content-derived Git blob OID 时 bound/stable；fixture emission 和 detector-only 两类规则都走 production runner核对版本。独立 reviewer 反证确认 coverage denominator 非自证式；RULE_VERSION_BASELINE 固定全部21条规则后，版本 drift 探针也失败如预期。两组测试共 **6 passed**。
- 最新 scope check `python -m scripts.check_change_scope --base db77164fdc2af0da02e4d3efc056d84694fd68e8 --lane ipc` 为 `violations=[]`，`git diff --check` clean。所有当前集成更改仍是 dirty、未提交；D3 owner-only 文件未迁入。

### 开发/测试反馈任务与提示词

**B-R1 开发复核提示词（D1）**：只读对比 integration dirty `src/ohscanner/detectors/interface/analysis.py` 与 immutable base `db77164fdc2af0da02e4d3efc056d84694fd68e8`，审查 request-derived Parcel buffer 到 copy sink 的 alias-sensitive state：local nonconst reference/pointer、compound/index/member writes、分支 merge、shadowing、unknown pointer alias 和 partial parse。逐项指出任何误把候选降为 safe/refuted 的路径，或因失效规则不足而可构造的 false negative；将每个结论映射到正/负 fixture 与 `test_ipc_data_flow_rules.py`。最多列 actionable P1/P2/P3 findings；无问题说明范围与未覆盖项。不得修改代码；独立复核可运行 D1 定向测试，报告 exact command/output 和文件行号。

**B-T1 测试提示词**：针对同一实现基线，独立检查 `RULE_VERSION_BY_RULE` 是否覆盖全部当前 IPC rules 与 detector-only rules，未知 rule 是否 fail closed，finding 中 rule_version/source-bound occurrence 是否可由 identity contract 正确消费；检查 legacy diagnostics 不被静默升级。版本测试应在 integration 代码上从 repo root 运行；凡是 identity/schema 公共契约修改必须提给 owner，不能由 IPC lane 改 shared tests。当前允许的 `test_ipc_rule_versions.py` 已迁入并通过。

**B-R2 开发复核提示词（D2）**：只读审查 D2 relay descriptor-guard 逻辑，建立“每个 virtual dispatch sink 之前最近/有效的 descriptor guard + mismatch 必退出”的控制流矩阵；验证 earlier wrong-interface comparison 不会压掉 later correct guard，且 branch-only/conditional return/nonunique helper/多 dispatch 情形都保持 candidate/credit 方向保守。逐项检查规则版本和 finding evidence 是否描述真实 guarded path，不以文本 token 存在当 dominated。报告 exact counterexample、正负样本身份和行号；不改代码。

**B-T5 测试提示词**：独立于 D2 实现先定义 sink-level oracle，再核验矩阵 fixture：guard before all、dispatch→guard→dispatch、guard after all、wrong then correct、branch-local guard、条件/无条件 mismatch return、ambiguous helper。每个 case 明确预期 sink index 与 candidate 集，确保 helper ambiguity 不猜 body，执行回归并报告未覆盖 AST 形态。发现测试通过但实现仍漏 sink时给最小反例，不直接弱化 oracle。

**B-D3 scope 处理提示词**：D3 coverage 分母语义属于 shared M1 contract；IPC 线只维护允许范围内的 detector 专项测试。若需保留 IPC denominator regression，先把断言设计成 `tests/test_ipc_coverage.py` 的 IPC-scoped public API contract test，不编辑 `test_ohscanner_m1.py`、contracts、runner 或全局 coverage 代码；由 owner review 公共语义再确定接入方式。

### 当前下一步

```text
D1/T1/D2/T5/D3：实现与独立合同测试已闭环；D1 final review/T1 audit 通过，当前无需扩张规则
D53/T54 + D9/L2：peer/reply 源码边界已复核；IPC anchor bbb92db 的关键源文件 pin 已精确验证
 ├─ L2：D9 source-level missing-NUL → C-string 机制 supported；reachability/实际影响仍 insufficient
 └─ T26 build/test-feasibility 独立复审 no-go；待 exact IPC+DSoftBus lock、有效产品 source/build root 与 ASan integration target
D54/T55/L2：reply sequence correlation source review、独立 oracle 和 L2 首轮挑战均完成；0 confirmed
 ├─ L2 + D55/T56：支持 seq-only cross-wakeup/state-interference；REMOTE_ERROR 无 stub/session gate，precondition 更低，但 impact/reachability 仍 insufficient
 ├─ D54-R1 只作为低置信、条件性产品验证项；若报告门要求已证实攻击路径，归入 insufficient/parked
 └─ 产品版本、SoftBus auth/integrity/replay 语义和真实 waiter 回归齐备后，T55 oracle 再判 go/no-go；不与 D9 合并根因
D55/T56：MESSAGE_AS_REMOTE_ERROR sibling path 复核完成；同属 D54-R1 的 seq-only wake/detach root，无独立候选
 ├─ error 分支更宽松：有效固定帧/正确 code/命中活动 seq 即可，不校验 stub、deviceId、session 或 peer
 ├─ T56 A/B oracle 覆盖正确/错/未知/迟到/重复 seq、旧 session 有无两种 caller 返回行为
 └─ 并入 D54-R1 条件性 waiter-correlation 验证；跨 SoftBus peer 可达性仍 unknown，不增加候选 ID
T3：独立冻结产品 holdout 未建立之前，不计算/声称 precision 或 recall
```

**D54 结构化提示词（reply sequence correlation 静态侦察）**：只读审查 `OnRemoteReplyMessage → MakeSessionByReplyMessage → WakeupThreadByStub` 的 reply seq、stub、peer/network ID 与 pending `ThreadLockInfo` 绑定。用本地可核验源码定位 request 注册、reply 入站、session 创建、waiter 唤醒和后续消费；判断 reply 是否能将一个 peer/请求的响应关联到另一个活动 waiter，以及是否产生独立于 D9 `DeviceIdInfo` C-string 根因的具体状态改变或安全影响。逐项列出 guard 顺序、seq 唯一性/生命周期、stub 和 expected peer 约束、最强反例、源文件 SHA-256 与无法验证的产品 commit。最多输出 1 条候选；同一 D9 根因不重复开 ID；证据不足报 0/unknown。不得改代码、跑 PoC、声称任意网络可达。

**T55 结构化提示词（reply sequence 独立测试/反证）**：独立于 D54 先定义 oracle，检查两个并发 pending request A/B、peer/session 不同、reply 使用原 seq/另一个有效 seq/不存在 seq、stub 一致/不一致、重复/延迟 reply；观察 session attach、waiter 唤醒与返回值是否串线。使用生产测试入口或明确标注仅 harness 的测试，不复用 D54 的期望作为真值；若产品依赖不可构建，交付测试设计、最小数据流证据和 blocker，不把模拟通过称为产品证实。明确区分 D9 的 malformed device-id sink 与 seq correlation 是否同一 root/effect；给 D54 逐项反馈，最多保留一条独立候选。
**D55 结构化提示词（REMOTE_ERROR 静态同根审查）**：只读审查 `OnRemoteMessageTask → OnRemoteErrorMessage → WakeupThreadByStub/DetachThreadLockInfo`，以 D54-R1 的 reply seq correlation 为比较对象。核 error 分支是否仅依赖消息 type/seq、是否经 valid stub/device-id/session gate、能否唤醒或删除另一个活动 waiter、调用方可观察返回码；逐项分析 duplicate/late/unknown seq 和当前 `ThreadLockInfo` 生命周期。判断它与 `OnRemoteReplyMessage` 是同一“未验证响应关联”root cause 的第二条路径，还是有源证据支持的独立 effect。最多 0 个新增候选；除非独立 root/effect 闭合，否则合并 D54-R1。绑定本地 source SHA/行号并标明产品 commit、SoftBus transport 的 unknown。不改代码、不运行测试/PoC、不声称任意网络可达。

**T56 结构化提示词（REMOTE_ERROR 独立测试反证线）**：独立建立两个活动 waiter A/B 的 oracle，覆盖正确 error seqA、错用另一有效 seqB、未知/已 detach seq、late/duplicate error，以及成功 reply 对照；记录 waiter ready/return code、map detach 和 session 是否变化。检查现有单测/fuzz 是否覆盖完整并发生命周期而非 helper 直调；产品 target/build 环境缺失时给测试设计和具体 blocker，不把 harness 结果当产品证实。将预期效果与 D54-R1 区分，给 D55 提供反例；本轮默认不增加候选，不编辑生产或 shared 文件。
**D21 结构化提示词**：固定产品 IPC anchor `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`。避开 D8/D9、DUMP_TRANSACTION、death-recipient 与一般 Parcel receive/D17，选一条此前未覆盖的 dispatch→敏感 effect。输出 source-bound 文件 SHA-256/blob、entry/caller 可达链、可控输入、所有 guard 支配关系、具体 effect、现有 finding/effect 去重键和最强反例；最多 1 条候选，证据不足报 0/unknown。只读，不改代码、不跑 PoC。

**T22 结构化提示词**：独立从可用源码选择并复核同一未覆盖路径；按 pinned raw bytes 重算 source identity，反证 entry reachability、caller/object-owner、input control、guard dominance 和 effect；检查是否与已有 finding 重复。报告 supported/refuted/insufficient、最小 test oracle 与缺失构建/依赖证据；不改代码、不运行 PoC、不把 API public 声明等同产品 app 可达性。

**D9/T15 条件提示词**：目标 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 已从 OpenHarmony GitHub 镜像精确取回，并与本地 D9/D54 关键 raw files 的 blob/SHA-256 完全匹配。继续运行真实 `OnBytesReceived → async reply → session → C-string` ASan 前，仍须有一致的产品构建上下文：C-line rk3568 build.ninja/args.gn/compile_commands 存在，但 compile commands 指向当前不存在的 `/src`，其 IPC source directory 也缺失；manifest 锁 IPC 5903fd5（相关路径与 bbb92 文件级相同，但不是同一完整产品构建树），DSoftBus 7743 精确对象尚未从公开镜像取到。不得把错位 build output 或裸布局 harness 当作目标产品验证。

1. D1 追加独立复核发现复杂调用/拷贝目标表达式中的 false-safe：复杂参数 `Mutate(*(&n))`、多来源 `Mutate(choose ? n : m)`、条件左值赋值、条件引用、条件地址引用及 `int& alias=*q`（其中 `q=p+0`）的调用/写入。负责人扩展来源合并与 unknown propagation，并补齐上述反例；同时将直接指向已知非 request 局部量的指针与未知指针区分，避免无关 helper/memcpy 误报。指针算术/下标/取地址/引用别名/条件来源/未知 destination 反例与 `malloc/calloc/std::malloc` 新缓冲区安全控制继续通过。独立 D1 最终复核确认这些反例和安全控制均通过，未发现新增高置信 false-safe。T1 audit 未发现实质 oracle 问题，已加强 relay manifest 的文件/声明双向覆盖断言。最新聚焦测试 128 passed，IPC unittest 409 run / 1 skipped / 0 failed，scope 和 `git diff --check` 通过。全仓 unittest 1208 run / 12 skipped / 1 unrelated failure：`test_ohscanner_m15.OfflineGitTests.test_promisor_clone_never_fetches_missing_blob`，本地 promisor 缺失对象时报 Git lazy-fetch 错误，未匹配预期 `missing_local_git_object`；不在 IPC 修改范围。
2. D21/T22 选路已结束并行复核：D21 `SYNCHRONIZE_REFERENCE → DBinderSearchRefCount`，T22 `CLEAR_DBINDER_SERVICE_STATE → DBinderServiceStub`，都无足够证据形成高信号候选。D21指出普通 proxy 的特殊 code range gate；T22指出 session-close 清理 effect 属预期行为。T22 核验目标 commit object 不在本地，结论只绑定本地 IPC checkout；不送 L2、不改 detector。
3. D22/T23 并行复核 `SYSPROPS_TRANSACTION` 已完成：双方均为 0 候选。当前可见快照没有 IPC 生产 caller/专门 handler，普通 proxy 对超 `MAX_TRANSACTION_ID` 特殊码拒绝，base `OnRemoteRequest` 默认未知事务拒绝；fuzzer 的裸 base stub 代码清单不证明成功 effect。两方独立 source hash 对齐（stub cpp `554a27bf…`、ipc_types `656bb739…`、fuzzer `b31867bd…`）。受坏掉/空 `.git/config` 影响，产品 checkout 声称的 `5903fd5f…` commit 无法由 Git 验证，目标产品 pin `bbb92db…` 也不可解析；结论只绑定本地原始字节，范围外 transport 和下游 override 仍未绑定。不送 L2，不改 detector。
4. D24/T25 路径复核已收敛：标准 IPCObjectStub GET_PROTO_INFO 只回 protocol/descriptor 元数据，无敏感状态 effect。T25 的 callback ProcessData 不是 DeviceIdInfo 来源；交叉复核确认安全相关路径是固定长度 reply ingress → MakeSessionByReplyMessage（stub/serviceName/stubIndex checks）→ CopyDeviceIdInfo 原样复制 → DBinderServiceStub::ProcessProto 将 toDeviceId/fromDeviceId 传给 WriteString。独立线与 L2 将其归为 D9 同一未终止 DeviceIdInfo 根因，不新增 candidate ID。IPC 内部 expected-peer/reply binding 缺失由 D53/T54 源码追踪支持；SoftBus 部署认证及 commit provenance 未证。
5. L2 独立挑战已完成：D9 的 source-level 机制为未终止 DeviceIdInfo 字段进入 C-string/std::string sink，支持潜在字符数组越界读取候选。D53/T54 已确认 IPC 不把 reply socket/network ID 或 pending request 身份与回复字段绑定；因此能在对应 SoftBus session 发帧的 peer 可控这些字节。仍 insufficient：该 SoftBus channel 的部署认证/完整性/replay 保证、任意 app/Internet 可达性、读取是否越过 SessionInfo 分配边界及 crash/泄露等具体影响。正常 request writer 会校验长度并写 NUL，是正常 echo 的反证，不是接收端完整性校验。
6. T26 只读测试设计：使用有效注册 stub/合法 serviceName，经 listener OnBytesReceived 等待 async session 创建，再触发公开 OnRemoteRequest(GET_PROTO_INFO) WriteString；覆盖双 NUL、各单字段缺终止、双字段缺终止及 stub/serviceName/code 拒绝控制。DHandleEntryTxRx.deviceIdInfo 后接 stub 字段，单独非 NUL 可能被后续零字节终止；SessionInfo 末尾 toDeviceId 是更可靠的 allocation redzone sink，宜双字段均非 NUL。现有 008 只测复制，009 未填非 NUL ID，缺完整 listener→session→consumer ASan。目标 IPC source pin 已通过 GitHub commit/blob/SHA-256 交叉核实；C-line 有 OHOS clang 和生成 build config，但 compile DB 指向缺失的 `/src` 且 IPC source 缺失，DSoftBus pin 仍不能核验；layout harness 不能代替匹配产品集成证据。
7. D53/T54 peer/auth 与 reply/correlation 复核已完成：`OnBytesReceived` 忽略 socket 身份；reply 先 `MakeSessionByReplyMessage`，后按 reply `seqNumber` 唤醒 waiter。已校验注册 stub 和 serviceName，但复制 `DeviceIdInfo` 前不绑定 expected peer/network ID 或 pending seq；SoftBus `PeerSocketInfo.networkId` 虽在 bind 时登记，接收时未消费。结论仅支持“能在该 SoftBus session 发帧的 peer 可控回复字段”这一 IPC 层边界；SoftBus 认证、完整性和 replay protection 未证，不能称任意 app/Internet/未认证可达。reply 路径并入 D9 同一根因，不新开 candidate；产品 Git 版本仍无法由损坏 `.git/config` 验证。
8. D9 产品 ASan 门仍阻塞于匹配的产品构建上下文：IPC commit `bbb92db...` 已由 GitHub 镜像精确取回，且 D9/D54 关键文件均与当前 raw checkout 字节相同。Windows 子仓 `.git/config` 仍为 0 字节；C-line 有 rk3568 build outputs，但 compile database 指向不存在的 `/src` 且 IPC source 缺失，manifest 锁 IPC `5903fd5f...`（D9/D54 关键文件相同）；DSoftBus manifest pin `7743...` 在 GitHub/Gitee 当前可取 master 对象中不存在，原 checkout `.git/config` 也无效。源码机制的 immutable identity 已解决，SoftBus trust boundary 与真实产品 ASan 仍未证。

9. 每轮先 fetch origin main；若 SHA 前进，基于新 SHA 重绑证据并重放 scope、IPC 和全仓 WSL 套件。当前 HEAD=origin/main=db77164fdc2af0da02e4d3efc056d84694fd68e8；集成树 dirty 未提交/未合并。
10. 建立独立冻结且有标签的产品 holdout 后，按规则族报告 TP/FP/FN/unknown 与覆盖分母；fixture/regression controls 不计入 holdout。当前 `research/evidence/interface/ipc/high_recall_holdout_20261018/manifest.json` 仍为 `not_established`、`frozen=false`、各 family 独立正例 0，不得计算 precision/recall。L2 逐条挑战 source-bound 候选和反例，不能单独升级状态。
11. D54/T55 独立复核 `OnRemoteReplyMessage → MakeSessionByReplyMessage → WakeupThreadByStub`：`MakeSessionByReplyMessage` 在 waiter correlation 前，按 reply.stub 创建/替换 session；`WakeupThreadByStub` 只按 reply.seqNumber 查 map/唤醒，未对照 stub 或保存的 ThreadLockInfo.networkId。跨 seq 可能提前唤醒另一活动请求；后者按自身 stub 查询 session，可能因缺 session 返回 `DBINDER_QUERY_REPLY_SESSION_FAILED`。这是与 D9 字符串读取不同的状态/可用性 effect，但要有效本地 stub、能送入 SoftBus 回调且获知活动 seq。D54/T55 都仅保留条件性候选、0 confirmed；跨会话攻击、seq 可预测性和部署影响未证。IPC 原始文件 hash：dbinder_service.cpp `AC762AD0…8384FA1CF`、listener.cpp `787A3791…038F1DF62`、unit test `C679AB21…F96D2E50`；源文件已由 D9 source-pin artifact 绑定 target commit bbb92db；manifest 5903fd5 对比仅 4 个非候选文件变化，四个候选路径完全相同。T55 给出 A/B 并发生产 oracle，但当前缺可复用的产品构建树：C-line 有 OHOS clang 与 rk3568 `build.ninja`/`args.gn`，其 manifest 锁 IPC `5903fd5f...` 且该 source 缺失；因此未执行候选目标版本的产品测试。
12. L2 D54 challenge 与 D55 sibling-path follow-up 完成：支持无 seq/stub/network 绑定可能造成跨 seq waiter wake/detach 和协商失败；`MESSAGE_AS_REMOTE_ERROR` 路径比成功 reply 少 valid-stub/session gate，但只需固定帧、正确 code 与活动 seq。成功 reply 的 session side effect 仍受已注册 stub、合法 serviceName、非零 stubIndex、attach 成功限制。跨 peer 注入、活动 seq 时序/可获得性、SoftBus auth/integrity/replay 与产品影响仍 insufficient。仅保留一个低置信条件性候选 D54-R1 供 targeted product verification；不报确认漏洞。
13. D55/T56 MESSAGE_AS_REMOTE_ERROR sibling-path review 完成：两线均认定与 D54-R1 共用 seq-only wake/detach root；error path 不校验 stub/deviceId/session/peer，也不改 session，所需 gate 少于成功 reply。可补入同一 A/B oracle 的 error control，不另建 candidate。现有 unit 仅测 dispatcher/helper，fuzzer 使用空 waiter map/default seq，不覆盖生命周期串线。
14. 2026-10-20 本轮状态更新：scanner `git fetch origin main` 成功且 HEAD=origin/main=`db77164fdc2af0da02e4d3efc056d84694fd68e8`（0/0）。从 OpenHarmony GitHub 镜像精确 fetch IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`（tree `125ecbfa21f430f2f977f0026ab97b70cd27a726`）；本地 D9/D54 关键四文件均与该 commit blob、SHA-256 完全匹配。它与 C-line manifest IPC `5903fd5f...` 的 tree diff 仅 4 个文件，D9/D54 四个候选源文件不变。证据见 [D9 source pin verification](ipc/b-line-20261020/d9-source-pin-verification-20261020.json)。构建审计：C-line 有 rk3568 `build.ninja`/`args.gn`，但 compile DB cwd 固定为不存在的 `/src`，IPC source directory 缺失，不能直接复用。DSoftBus pin `7743b679...` 的精确 fetch及 GitHub/Gitee 当前 master 对象查找均未找到；原本地 `.git/config` 为 0 bytes。当前定向复跑 focused pytest 128 passed；IPC unittest 409/1 skipped/0 failures；scope `violations=[]`、`git diff --check` clean。
15. T26 build/test-feasibility 独立复审完成：no-go，没有可安全运行的精确产品集成 binary/build。IPC source 目录只有测试源文件，缺 `out`/`build.ninja`/`args.gn` 和 DBinder 测试/fuzzer 可执行文件；C-line compile DB cwd 为不存在的 `/src`，源码 IPC directory 缺失，DSoftBus 7743 pin 未取得。现有 fuzz/unit 源码没有 listener→async reply→session→GET_PROTO_INFO 完整链。最低解阻条件：干净产品源锁（IPC bbb92db + DSoftBus 7743）、匹配 manifest/build args 与有效 source root、OHOS clang/sysroot、带 ASan 的集成 target，并跑 terminated-ID controls、malformed-ID cases、stub/serviceName rejects。未改代码/产品树。

## 下一轮并行任务（2026-10-20）

每轮重新 fetch `origin/main` 并记录 SHA；当前仍为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，HEAD 与远端 `0/0`。并行任务以固定 IPC anchor `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 为源码输入，只读扫描，不修改 detector/产品代码，不将静态候选升级为确认漏洞。

```text
D57 开发侦察：只选一条此前未覆盖的 transaction→effect 路径，最多一个候选
 ├─ 绑定源码 SHA/blob、入口、caller/权限、输入、guards、effect、反例
 └─ 若仍有未知 reachability 或影响，标 insufficient/0，不送报告候选
T58 测试/反证：独立选路径并先写测试 oracle，不复用 D57 的预期
 ├─ 正/负/边界与生命周期矩阵，核已有 unit/fuzz 覆盖粒度
 └─ 产品环境不可用时只交可执行设计和 blocker，不把 harness 当产品证明
D57 静态选路已完成：INTERFACE_TRANSACTION → DBinderSearchDescriptor 只回对象 descriptor 元数据，0 confirmed/conditional，不送 L2
 ├─ T58 独立选中同一路径并交叉反证：request bytes 不消费、无状态/权限 effect；0 候选
 └─ 两线确认现有测试缺 proxy→真实 stub 完整生命周期 oracle，但该测试缺口本身不构成漏洞
T59 候选质量审计已完成：未发现 unknown/guard/holdout 违规；发现 rule-id set 测试 oracle 看不到 observation multiplicity
 ├─ D60/T61 独立确认：raw 双 emit 经 Interpreter.run 合并成一个 same-sink finding；distinct sink 保留两个，未见 duplicate finding bug
 ├─ T61/T63 合成双入口共用 helper 证实 coalescer 丢掉一个 root_key；v2 公共 identity contract 未要求 root 字段
 └─ D62/T63 裁决完成：是 internal provenance omission/test gap，不是已证实的 v2 contract violation；公开聚合策略待 owner 决定
反馈：D57/T58 交叉反证闭环。无新增/确认安全候选；root 归属问题不扩成代码修复，保持 owner 决策项。
```

**D57 结构化 vibe-coding 提示词（静态候选侦察）**：先读任务树和既有 D21/D22/D51 结论，固定 IPC commit `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`。避开已经审过的 D9/D54、DUMP_TRANSACTION、death-recipient、DBinder lifecycle/ref/listen/cleanup、SYSPROPS 等路径；选一条尚未覆盖的 transaction→effect 路径。逐级绑定 immutable source blob 与 SHA-256，证明入口/caller/权限、输入可控性、每个 guard 的支配关系和具体安全 effect；列出最强反例及未知项。最多 1 个候选，证据不足输出 0；不推断 SoftBus/产品可达性，不改代码、不跑 PoC。将机器可读结果写入 `d57_uncovered_route_scout-20261020.json`，供 T58 逐项挑战。

**T58 结构化 vibe-coding 提示词（独立 oracle 与反证）**：独立选择一条任务树尚未覆盖的 dispatch→effect 路径，不照搬 D57 选择或判断。先定义 A/B caller、有效/无效权限或对象、正常/畸形/边界输入、重复/延迟事件及预期状态/返回值，再核现有 unit、fuzz 和集成测试入口实际覆盖哪些层。若发现 D57 同一路径，使用最强负例挑战每个 guard/effect，并把逐项结果回传；如果没有交集，记录不同路径和原因。不得把 mock/harness 通过称为产品证实；不改代码、不运行 PoC。将 oracle、覆盖缺口、产品依赖及 go/no-go 写入 `t58_independent_test_design-20261020.json`。

**T59 结构化 vibe-coding 提示词（静态 finding 精度审计）**：只读检查 integration worktree IPC dirty diff、候选 identity/evidence schema 与现有 IPC tests。重点寻找：同一 root/effect 重复候选、unknown/insufficient 被静默降级、来源身份漂移或缺少 raw source binding、guard 证据只看 token 而非控制流、测试 oracle 未覆盖的候选降级路径。只报告最多 3 个可复现/可操作的缺口并指出最小 IPC-only regression 断言；已修复 D1 alias false-safe 和 D2 多 dispatch 问题不要重复。禁止编辑产品/shared 文件或改 holdout 数据；无问题则写明检查范围与剩余盲点到 `t59_candidate_quality_audit-20261020.json`。

**D62 结构化 vibe-coding 提示词（root provenance 去重语义审查）**：只读检查 T61 双入口共用 helper sink witness、`Interpreter.run` 的去重键、`Observation.root_key` 和 v2 finding identity contract。判断去重应保留单一 sink 并聚合多个 root，还是当前 first-root 语义已被协议定义；核对每条调用链的 root 初始化/跨函数传播及同文件/跨文件 helper 边界。给最强反例、兼容影响和最小修复设计；区分合成 witness 与真实产品形态，不报安全漏洞。输出 `d62_root_identity_review-20261020.json`，不改代码。

**T63 结构化 vibe-coding 提示词（root identity 合同测试线）**：独立于 D62 读取 Observation/finding schema 与 runner 消费方式，定义同一 source sink 经同 root 分支、两个 distinct sink、两个不同 entry roots 的最终身份预期。构造最小内存或临时测试 oracle，比较完整 `(rule,file,line,symbol,root)` 来源身份；判断现有 first-root 保留是否与合同冲突，或应使用单 sink 多-root aggregate。运行最窄相关 pytest 并记录精确输出；不改仓库代码/测试。向 D62 提供反证与兼容要求，输出 `t63_root_identity_contract_test-20261020.json`。
16. D57/T58 并行核验 `IPCObjectProxy::GetInterfaceDescriptor → INTERFACE_TRANSACTION → IPCObjectStub::DBinderSearchDescriptor → reply`。D57 固定 IPC bbb92db 源码，5 个相关文件的 blob 与 SHA-256 精确匹配；该路径忽略 request bytes，只返回本对象 `GetObjectDescriptor()` 的 UTF-16 字符串，不消费敏感状态、不改权限/状态。T58 独立给出同结论。最终 0 confirmed、0 conditional，不送 L2；未跑测试/PoC、未改代码。现有测试分别覆盖 stub handler 与 proxy cache/mock，没有端到端 proxy→真实 stub response oracle；该测试缺口不形成安全候选。D57 证据 [JSON](ipc/b-line-20261020/d57_uncovered_route_scout-20261020.json)，T58 oracle/反证 [JSON](ipc/b-line-20261020/t58_independent_test_design-20261020.json)。
17. T59 只读审计未发现 unknown 静默升级、guard 证据不足或 holdout 混入；指出多数 D1/D2 断言将 finding 压成 rule-id set，缺精确 multiplicity oracle。D60 临时内存 fixture 复现同一 DATA-01 sink 两条 branch states 各触发一次 raw `emit`，但 `Interpreter.run` 3295–3298 按 `(file,line,rule,symbol)` 合并，最终同 sink 1 个 finding、两个独立 sink各保留，故 T59 不构成 final duplicate defect，也不派发 coalescing 修复。报告 [T59 JSON](ipc/b-line-20261020/t59_candidate_quality_audit-20261020.json)、[D60 witness](ipc/b-line-20261020/d60_duplicate_emission_scout-20261020.json)。
18. T61/T63 独立 oracle 与 D62 只读契约审查确认：同 root 分支落到同 sink 得 1 条 finding、两个不同 sink 得 2 条 finding；合成双 root 共用 helper sink 时 raw 观察各带 Foo/Bar root，最终一条 finding 只保留先遍历的 Foo root。`run_all_with_coverage` 的 v2 identity 也不包含 root；现有公共契约没有规定必须暴露/聚合 root，也没有声明 first-root-only，因此行为是可复现的内部 provenance omission，但**不是已证明的 v2 contract violation**。保留 sink 去重、不把 root 加入去重键；如果 owner 决定公开多 root provenance，再设计 additive 聚合与 root-derived obligations。窄测试 `python -m pytest -q tests/test_ipc_data_flow_rules.py tests/test_ipc_multidispatch_guard_matrix.py`：111 passed（T61 0.36s；T63 0.34s）。未改代码/测试。证据：[T61](ipc/b-line-20261020/t61_exact_identity_oracle-20261020.json)、[D62](ipc/b-line-20261020/d62_root_identity_review-20261020.json)、[T63](ipc/b-line-20261020/t63_root_identity_contract_test-20261020.json)。
19. 收尾复验（2026-10-20）：本轮开始成功 `git fetch origin main`，`FETCH_HEAD=origin/main=HEAD=db77164fdc2af0da02e4d3efc056d84694fd68e8`、ahead/behind `0/0`；最终再次确认集成树 HEAD/ref 仍为该 SHA。D62/T63 后未更改 detector；重跑 WSL 全仓 unittest 得 1208 run / 12 skipped / 1 failure。唯一失败 `test_ohscanner_m15.OfflineGitTests.test_promisor_clone_never_fetches_missing_blob`：测试期待 `missing_local_git_object`，当前 Git 返回 `lazy fetching disabled / could not fetch ... from promisor remote`；与 IPC 文件无关。IPC scope check 19 paths、`violations=[]`；`git diff --check` clean。集成树保留原有 dirty IPC 修改，未提交；plan worktree 新增任务树与研究 JSON。最终 refresh 发生在本轮 fetch 成功后，尚无 SHA 前进证据。

## 2026-10-20 收尾轮：D64/T65/D66 与 D67/T68（当前增量）

### 当前基线与可信边界

- 本轮在 IPC integration worktree 重新尝试 `git fetch origin main`，因到 GitHub:443 连接失败而未更新。集成树本地 HEAD 与缓存 `origin/main` 都是 `db77164fdc2af0da02e4d3efc056d84694fd68e8`，但**本轮远端新鲜度未知**；不得称其为最新远端 main。GitHub API/connector 本轮也未能取到新端点。若网络恢复，下一轮须先 fetch 并对前进后的 SHA 重绑/复放相关证据。
- D64 在 `openharmony/.repo/project-objects/communication_dsoftbus.git` 精确恢复 DSoftBus commit `7743b679f6c3599e21bea4e4b1564422668e3643`、tree `d386e20f8074e037f330a5df11e99fc66ed155d0`。冻结 manifest `openharmony-manifest-current-20261018.xml` SHA-256 `52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55` 锁 IPC `5903fd5f7332a427cb3f6915b0202ee5c76c63b5` + DSoftBus `7743...`。D9/D54 关键 IPC 文件与分析锚点 `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 文件级相同。**这证明源码版本与相关文件来源，不证明有这些源码构建出的产品镜像/二进制。** 见 [D64](ipc/b-line-20261020/d64_dsoftbus_pin_recovery-20261020.json)、[D9 pin verification](ipc/b-line-20261020/d9-source-pin-verification-20261020.json)。
- T65 确认 source lock/provenance 可核验，但产品 build/test 仍 **NO-GO**：可复用的 C-line IPC 源码与 build root 缺失，compile database 使用不存在的 `/src` cwd，没有与 manifest 配对的测试/fuzzer 二进制，也没有 listener→session→consumer 的 ASan 集成证据。不得在错位输出树上运行或修改 C-line 产物。见 [T65](ipc/b-line-20261020/t65_product_build_gate_audit-20261020.json)。
- D66 对精确 DSoftBus `7743...` 路径复核：普通非 AUTH proxy 数据路径在传输/接收使用 `SoftBusEncryptDataWithSeq` / `SoftBusDecryptDataWithSeq` AES-GCM，认证标签校验后才向 listener 交付明文。由此不能仅凭 IPC 不核对 socket 身份而推断 off-path 未认证攻击者可改帧；持有 session key 的真实 peer 仍可形成有效认证载荷。该 receive 路径未显示 listener 前的 duplicate/freshness 拒绝，但只对已审路径作此表述。DBinder 是否走该具体 route、认证 name 与远端 OS principal 的绑定、重放规则及实际产品配置仍未知。见 [D66](ipc/b-line-20261020/d66_softbus_boundary_review-20261020.json)。
- D9 的未终止 `DeviceIdInfo` 字节到 C-string `WriteString` sink，以及 D54-R1 waiter 按 seq 唤醒而不校验网络身份，是 source-level mechanisms；真实 listener 可达性、目标对象分配边界/影响、peer 身份与通道特性仍未闭合。D9/D54-R1 状态保持 `conditional / insufficient`，confirmed=0，新候选=0。静态层不得因“有机制”扩张成“未认证网络可达”或提升严重性。

### 本轮任务树与往返反馈

```text
D64 精确恢复 source pin（开发侦察/只读） ──完成──> T65 独立 build/provenance gate（测试/审计） ──结论：source pin OK，产品运行 NO-GO
D66 固定 pair 的 trust-boundary 复核（开发侦察/只读） ──完成──> D67 L2 独立反证（完成：0 confirmed/reportable）
                                                        └──> T68 独立 A/B integration oracle（完成：仅设计，未执行）
D67 + T68 交叉反馈 ──> B 负责人更新候选与任务状态
                          └──> 若环境 gate 解除：D69 在固定源码与真实 listener 上实施最小验证 harness
                               └── T69 独立复跑/负例/ASan 与 channel controls
                                    └── D69 修正解释/测试接线，直至测试线签收或确证外部依赖阻塞
```

本轮不做产品代码或 detector 变更，因为实际产品构建依赖不满足。开发/测试当前以证据开发、oracle 设计和反证进行：D67 必须挑战来源、peer/auth/AEAD/replay 和候选效应；T68 独立给出可否证的实测矩阵，不采用 D66 的预期作为真值。二线结果冲突由负责人对照 pin 行为和证据定裁；不能用 mock/layout probe 替代产品结论。

#### D67 结构化 vibe-coding 提示词（第二层源配对挑战，完成）

> **角色/目标**：独立第二层安全审查者；挑战 D9 与 D54-R1 在精确 IPC/DSoftBus manifest pair 下是否存在可报告漏洞。优先找反例和缩小攻击者能力；静态候选总数上限 1 个合并 root，信息不足则维持 0 个可报告候选。
>
> **固定输入**：scanner 本地锚点 `db77164fdc2af0da02e4d3efc056d84694fd68e8`（本轮 origin fetch 失败，远端新鲜度 unknown）；目标 IPC `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`；冻结产品 manifest IPC `5903fd5f7332a427cb3f6915b0202ee5c76c63b5` + DSoftBus `7743b679f6c3599e21bea4e4b1564422668e3643`。先复核 D64/D66/T65/D9-pin JSON 的提交、tree/blob/hash 与 manifest binding，区分 relevant-file equality 和 full product build identity。
>
> **审查问题**：D9：完整固定字段长度、真实分配对象边界、C-string sink、成功 listener/session 路径、最强 NUL/拒绝控制及可观察影响。D54：不同 peer/session/seq waiter A/B 配对、success/error/late/duplicate reply、session 创建副作用顺序。对 SoftBus 普通 proxy AES-GCM 结论只覆盖源中该条具体路径；指出 DBinder 路由是否使用它、peer key 持有者能做什么、seq 是否是 freshness policy、auth protocol name 是否绑定远端 UID/PID。不得从 API 名称、mock 或“忽略 socket 身份”直接推断 remote exploitability。
>
> **结论纪律**：按 confirmed/refuted/conditional-insufficient 分项；“代码机制存在”与“攻击者能到达/有安全影响”分开；不因 D66 路径推断改变无证据的产品配置。最多建议一个合并根因，若缺真实产品构建则维持 insufficient。不改代码、不运行 PoC，不捏造产品测试结果。
>
> **交付/反馈**：将 source pair、逐条反证、剩余未知、候选裁决、最低解阻证据写到 `d67_l2_source_pair_challenge-20261020.json`；把最强的安全/攻击反例交给 T68 作为矩阵 controls，待完成后供负责人合并。

#### T68 结构化 vibe-coding 提示词（固定 pair 测试 oracle，完成）

> **角色/目标**：独立测试设计者；设计最小、可否证、能区分 IPC 行为与 SoftBus 边界的真实产品实验。不修改 detector/product code，不构造/运行远程 PoC，不把 unit/mock/layout ASan 说成产品证据。
>
> **固定输入**：manifest IPC `5903fd5f7332a427cb3f6915b0202ee5c76c63b5` + DSoftBus `7743b679f6c3599e21bea4e4b1564422668e3643`；审计锚点 IPC `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` 且 D9/D54 四个相关文件 file-equal。关联 D66/D64/T65 与 D67 的反例，但独立建立 expected observables。
>
> **必备矩阵**：真实启用的 DBinder listener/channel 枚举与 peer 身份绑定；有效 auth peer 发送双字段均非 NUL 的 DeviceIdInfo、正常/单字段缺 NUL/双字段缺 NUL与 allocation redzone ASan；AEAD 密文 tag 被改/无效 tag拒绝控制、精确重放同一有效帧/重排帧的 freshness结果；A/B 两个活跃 waiter 的相同/不同 seq、success 与 MESSAGE_AS_REMOTE_ERROR、错误/未知/late/duplicate seq，观测 waiter return/ready、map detach 和 session 副作用；非法 stub/serviceName/无效 session 的拒绝控制。每项写清输入通道、预置状态、观测点、预期区分、cleanup 和安全控制。
>
> **当前 gate**：明确标注本地现有环境没有 manifest 配对的有效 source/build root/test binary，compile DB `/src` 不存在；因此只能交 oracle 和阻塞清单，不宣称已执行。若 source route/API 与产品真实部署仍未知，测试列出需由目标设备/构建负责人提供的精确信息。
>
> **交付/反馈**：将矩阵、测试层级、预期输出、现有覆盖缺口和 NO-GO 写入 `t68_pinned_pair_oracle-20261020.json`。把可判别的最小 A/B case 和 negative controls 交给 D67，反馈候选哪些条件可被实验推翻。

#### D69/T69 后续执行提示词（环境具备后才开启实测）

> **D69 开发线**：只有 manifest source pair、解析完成的 dependency graph、可复现 GN/build args、匹配 OHOS toolchain/sysroot、实际构建产物 provenance 与 listener integration target 均齐备后，按 T68 矩阵实现 IPC-owner 范围内最小 test harness/必要测试 seam。先将源和测试设计交 T69 审阅，再动代码；只新增测试工具/IPC tests，不改候选 gate/schema/SoftBus 代码。命令、build ID、source hash、产物 hash 必须写入记录。缺任何 gate 即停止并报具体缺项。
>
> **T69 测试线**：从独立干净构建/设备复跑 D69 harness，挑战正常/畸形/无效身份、AEAD tag、duplicate/reordered、A/B waiter 和拒绝控制。逐项核预期、实际观察、日志/ASan trace；报告 fail/pass/inconclusive 以及所有与构建/设备配置有关的限制。将反例回传 D69，不接受开发者自测替代独立复跑；修复后重跑最小回归集。只有测试签收与产品 provenance 完整，才重新评估 D9/D54 是否可报告。

### D67/T68 实际结果与开发—测试反馈

- D67 已独立重算 IPC 相关文件 SHA-256，并按 Git blob 算法核对 DSoftBus 关键源。结论：0 confirmed、0 reportable、无新增 ID。D9 降为 `insufficient / parked` source hypothesis：AEAD 缩小 off-path 篡改面，但 DBinder route、持 key peer 的入口/权限、`WriteString` 是否越过 `sizeof(SessionInfo)`、泄露字节接收方及具体 CIA impact 均未证明。D54-R1 为单个低置信 conditional/insufficient：seq-only wake/detach 源码机制成立，但跨 session peer delivery、活动 seq targetability、实际 replay 与产品效应未闭合。见 [D67 L2 challenge](ipc/b-line-20261020/d67_l2_source_pair_challenge-20261020.json)。
- T68 独立交付五组可证伪集成 oracle：①真实 DBinder route/peer identity；②D9 双字段非 NUL、真实分配边界 ASan、GET_PROTO_INFO sink 与受控接收方；③AEAD tag 篡改、有效帧 exact duplicate/reorder；④A/B waiter 对 success 与 REMOTE_ERROR 的同/异 seq；⑤非法 stub/serviceName/session controls。每项包含预置状态、观察点、预期区分、falsifier 与限制。由于 T65 gate 仍 NO-GO，这些均未执行，不得写成测试通过。见 [T68 oracle](ipc/b-line-20261020/t68_pinned_pair_oracle-20261020.json)。
- 反馈闭环：D66 的“普通 proxy AEAD”边界被 D67 用来排除无凭据网络篡改推论；T68 将真实路由、持 key peer 与重放行为做成独立判别项。D9/D54 未被静态层升级。下一步不是盲目改 detector，而是解开 T65 的构建/产物 provenance gate；环境满足后 D69 实测、T69 独立反证，再回馈开发侧。

### 收尾轮验收与持续目标

- 本轮交付是 source pin 恢复、独立 trust-boundary 复核和可执行实验定义；不是产品漏洞确认，也不是 build acceptance。
- D67/T68 已完成源复核与 oracle 设计。D9 保持 parked hypothesis；D54-R1 仅保留一个 conditional/insufficient 研究项；confirmed/reportable 均为 0，不新增 ID。
- 每轮继续先尝试 fetch 最新 `origin/main`，记录实际返回和缓存新鲜度；若取不到远端，仍可以在锚定 SHA 上进行不依赖漂移的 source review/test-design，但不得宣称 latest-main 验收。持续推进的停止条件是：fresh main 已复核、IPC scope/定向及必要全仓测试结果可归因、保守候选经二层挑战、实际产品 build/test gate 已通过或明确外部阻塞及责任/解阻项已登记。



## 2026-10-21 持续轮：D70/T70 并行选路（执行中）

### 开轮核验与执行边界

- 新一轮 `git fetch origin main` 再次失败（GitHub:443 连接失败）。集成 worktree HEAD 与缓存 `origin/main` 仍均为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`；这只是本地可见基线，远端新鲜度 unknown。随后 GitHub API 读取也不可用。所有本轮静态事实必须标定到该本地 scanner SHA 和 immutable IPC source pin，不能称 latest remote。
- 对 T65 构建阻塞再核：记录中的 `/src` 和 `/home/deepsleep/c-line-c1-profile-20261018` 在本轮 WSL 环境均不存在；本机 `openharmony/foundation/communication/{ipc,dsoftbus}` 的 `.git/config` 不可读，不能用 checkout HEAD 证明构建版本。保留 product build NO-GO，不重建/覆盖产物。
- 集成 worktree IPC 既有 dirty 改动仍未提交，`git diff --check` clean；本轮不触碰代码。计划 worktree 当前仅有计划与证据交付未跟踪项。

### 任务树

```text
D70 开发侦察：PING_TRANSACTION → DBinderPingTransaction，固定状态回包；0 候选（完成）
 └─ T70 独立测试 oracle：独立选中同一路径，指出 liveness 信号语义，0 候选（完成）
      ├─ 若路径重合：T70 逐 guard/entry/effect 反证，并给最小可否证 oracle
      └─ 若不重合：各自报告路径/覆盖缺口；负责人比较优先级并安排下一轮交叉审查
D70/T70 feedback → 只有 caller/input/effect 都有具体证据才送一次 L2；否则 0 candidate，不改 detector
 └─ 如果发现静态实现可安全改善：另开小范围 D71/T71，先由测试线给红/负 oracle，再由开发线修复，最后测试线独立回归
```

### D70 结构化 vibe-coding 提示词（静态候选侦察，已完成）

> **任务**：在已经完成的 route inventory 中挑一条真正未覆盖的 IPC transaction/entry→effect 路径，静态源证据先行；最多一个合并根因假设，若调用者可达、攻击者可控输入或安全 effect 任一不具体则输出 0。
>
> **固定基线**：scanner 本地 `db77164fdc2af0da02e4d3efc056d84694fd68e8`（本轮 fetch 与 API 均失败，远端新鲜度未知）；IPC immutable anchor `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`。每条源边给 Git blob + SHA-256；不要把相关文件相同说成完整 build identity。
>
> **排除清单**：D9/D54、DUMP_TRANSACTION、death-recipient、DBinder lifecycle/ref/listen/cleanup、SYSPROPS、descriptor 路径、REMOVE_SESSION_NAME、ADD_COMMAUTH、binder offset/read-object、duplicate/root attribution。先从计划索引每条旧路径结论，避免换名重复。
>
> **方法**：沿 transaction dispatch/公开 IPC/回调追到 effect；列 caller/权限/transport、输入来源与可控性、守卫及控制流支配、对象所有权/生命周期、effect 与潜在安全影响；给最强反证与现有 unit/fuzz/集成实际覆盖层。产品依赖 unknown 必须明示，mock/fuzzer reaching code 不等于产品入口可达。
>
> **禁止/交付**：不改代码/测试、不运行 PoC、不扩展 schema、不新增重复候选。写 `d70_ipc_static_scout-20261020.json`；将最强可证伪点交给 T70。只有 source-bound、行为有安全意义且非重复的候选可交第二层模型。

### T70 结构化 vibe-coding 提示词（独立测试与反证线，已完成）

> **任务**：独立从覆盖清单中另选一条路径建立 oracle，不读 D70 结论作为真值；若偶然重合，尝试最强负例挑战 D70 的入口、控制、guard dominance 和 effect；若不重合，报告路径差异和为何先后不影响安全结论。
>
> **验证设计**：列 caller/权限正负矩阵，输入正常/畸形/边界、重复/延迟事件、状态前置条件，断言返回值/状态/敏感 effect；逐项核实际 unit、fuzzer、integration 路径只到哪一层。指出最小反例、已有测试空洞及可否证的产品 oracle；生产源码/build route 缺失时将测试标为 design-only/inconclusive。
>
> **固定约束**：scanner 基线 `db77164...` 且远端 freshness unknown；IPC 源锚 `bbb92dbb...`。源定位和 hash 独立重算；不得改代码、测试或 holdout，不跑 PoC/产品集成，不把 harness/mock 结果当产品证据。最多提出一个机制假设，信息不足保持 0。
>
> **交付/反馈**：写 `t70_ipc_independent_oracle-20261020.json`，输出覆盖粒度、预置状态、expected/observed（未运行时写“未执行”）、negative controls、未知依赖。将路径重叠时的强反证及时反馈给 D70；负责人据两线结果决定是否送 L2 或关闭为 0 候选。


### D70/T70 交叉结果（2026-10-20）

- 两线独立选中 `PING_TRANSACTION → IPCObjectStub::DBinderPingTransaction`。D70 绑定目标 IPC `bbb92db...` 七个文件的 blob/SHA-256：stub helper 只向 reply 写 `ERR_NONE`，或在写失败时返回 `IPC_STUB_WRITE_PARCEL_ERR`；具体 framework caller 是 `BinderInvoker::PingService`，针对 `REGISTRY_HANDLE` 发特殊事务。普通 `IPCObjectProxy::SendRequest` 的 `code > MAX_TRANSACTION_ID` gate 拦截该 packed special code。D70 检查到 unit/fuzzer 直接调用 helper，未覆盖完整 dispatch/transport。报告：[D70 scout](ipc/b-line-20261020/d70_ipc_static_scout-20261020.json)。
- T70 独立给出重要语义修正：成功回包并非抽象的“零效果”，而是向调用方报告句柄存活状态；但此信号本身不证明敏感对象泄露或未授权状态变化。普通 proxy 拒绝该 code，`PingService` 是针对 registry handle 的内部框架 caller；raw Binder driver 上持有何种 handle、低权限主体能否发包、是否把 liveness 用于安全决策都未证。unit/fuzzer 和调用者 mock 没有覆盖真实 SendRequest→driver→reply。见 [T70 oracle](ipc/b-line-20261020/t70_ipc_independent_oracle-20261020.json)。
- 两线互馈后结论为 **0 confirmed / conditional / reportable candidates**；测试缺口不转成漏洞。若后续产品威胁模型要求只向指定身份暴露对象存活状态，应由产品 owner 先定义安全策略，再构造真实 caller/handle oracle；当前不改静态规则。
- D70 报告原 `review_date` 与本轮日期上下文不一致，已由 D70 仅更正元数据为 2026-10-20；源绑定与结论未改，JSON 解析和日期断言通过。


## 2026-10-20 增量核验：live main 与产品构建材料

- 再次 `git fetch origin main` 仍因 GitHub:443 失败，但随后通过 GitHub REST `branches/main` 只读端点成功读取实时 ref：main=`db77164fdc2af0da02e4d3efc056d84694fd68e8`，tree=`8c5a296d8304d98193a29a4695aaf61ca0c0996c`。本地 HEAD、缓存 `origin/main` 与 live ref 一致，commit object 可由 `git cat-file` 读取。因此 D70/T70 所用 scanner baseline 在 API 读取时已验证为当前 main，之前对 freshness=unknown 的表述由此被新证据替代。机器记录：[live main API verification](ipc/b-line-20261020/main-live-api-verification-20261020.json)。
- 继续检查产品 build gate：Windows `openharmony/out/rk3568` 仅有历史 build log；递归工作区搜索未找到对应的 product `build.ninja`/`compile_commands.json`，检出的其他 build metadata 属不同验证项目或 third-party。WSL 查询仍找不到原 `/src` 与 C-line 路径。本机 OpenHarmony checkout 的 IPC/DSoftBus `.git/config` 无法读取，不能据它宣称产品 source pin/build provenance 已物化。故 T65 NO-GO 未解除，D69/T69 真实产品测试继续等待可复现 build root、toolchain/sysroot、目标二进制与来源证明。
- 本轮开发/测试线反馈只确认 PING 路径无候选，且独立测试提出应把正常固定响应解释为 liveness signal；仍无源证据证明未经授权 caller 可以触达或目标服务受安全策略保护。保持 detector 与候选状态不变。

## 2026-10-20 当前轮：main 复核与 B/IPC 定向回归

- 再次请求 live GitHub `branches/main`；仍返回 `db77164fdc2af0da02e4d3efc056d84694fd68e8` / tree `8c5a296d8304d98193a29a4695aaf61ca0c0996c`，与集成 worktree HEAD 和缓存 `origin/main` 一致。普通 `git fetch origin main` 仍因 GitHub:443 失败，但 live ref 已通过只读 GitHub API 核实，故本轮基线是 current as observed，不是凭缓存推断。
- 复跑实现验证：`python -m pytest -q tests/test_ipc_data_flow_rules.py tests/test_ipc_multidispatch_guard_matrix.py` 得 111 passed；`python -m unittest discover -s tests -p 'test_ipc_*.py' -q` 得 409 run / 47 skipped / 0 failures。IPC scope checker 检查 19 paths、`violations=[]`；`git diff --check` clean。结果见 [本轮回归记录](ipc/b-line-20261020/current-cycle-validation-20261020.json)。
- 这些结果复核的是现有 integration worktree 中未提交的 scanner/IPC 改动，未修改代码；它们不证明真实 OpenHarmony 产品构建、D9/D54 transport 可达性，也不构成 frozen holdout 的 precision/recall 评估。本轮没有重跑全仓套件（上次全仓唯一失败仍为独立的 M15 promisor-Git 错误）。
- D70/T70 已关闭 PING 选路为 0 候选；D1/T1 与 D2/T5 相关测试在当前 main 对齐的工作树上保持通过。下一项高价值解阻仍是有效 manifest build root；目前 WSL 不存在 `/src`/旧 C-line 路径，product build gate 维持 NO-GO。不得为了任务进度更改候选准入或把 unit test 当产品安全证明。

## 2026-10-20 持续轮：CVE-2025-26474 候选与 D72/T72/M2 并行挑战

### 本轮 B 线当前状态

- Scanner 当前 main 经本轮 Git fetch 最终核实仍为 `db77164fdc2af0da02e4d3efc056d84694fd68e8` / tree `8c5a296d8304d98193a29a4695aaf61ca0c0996c`，HEAD=`FETCH_HEAD`=`origin/main`（0/0）；更早一次 REST API 请求被限流，所以以成功 fetch 作为本轮 freshness 证据。B/IPC integration worktree 同该 SHA，但保留未提交的 1,215-line IPC analysis/model/test 修改（数据流 alias/guard、relay、multi-dispatch 测试）；本轮未覆盖或重写这些 teammate 改动。既有 focused pytest 111 passed、IPC unittest 409 run/47 skipped/0 failed、scope check 19 paths/0 violations 与 diff check clean 仍是最近可归因结果。
- 按任务树，D70/T70 的 PING 路径已关闭为 0 候选；既有 D9/D54 仍分别是 parked/conditional，0 confirmed/reportable。产品集成构建门仍 NO-GO，但 standing authorization 已移除其作为继续源码/组件任务的阻塞条件；后续可并行做源级静态探针和隔离组件 oracle，并分别标记 not_run/unknown 与已执行范围。
- D71 官方 issue 线与 T71 独立公告/提交线发现一个强 source-positive 候选：官方 2025-09 公告列出 CVE-2025-26474、communication_ipc、受影响 OpenHarmony 5.0.3.x、特定场景本地信息泄露、CVSS 3.1 3.3。源码链显示 `CJ_ReadRemoteObjectArray` 对 `type`/`id` 仅 `malloc(arrayLength)`，但循环按 `int32_t`/`int64_t` 写 N 个元素；官方 !2037 修复将大小改为 `sizeof(int32_t)*arrayLength` 与 `sizeof(int64_t)*arrayLength` 并检查 null。该机制只计一个根因/候选，源码哈希与提交链记录见 [D71 research](ipc/b-line-20261020/d71_ipc_holdout_research-20261020.json)、[D71b fix chain](ipc/b-line-20261020/d71b_security_fix_chain-20261020.json)、[T71 independent adjudication](ipc/b-line-20261020/t71_ipc_holdout_independent_adjudication-20261020.json)。M2 支持该分配/写入根因为 source-level heap bounds defect，但指出 CVE bulletin 没有指名该函数；具体 source-to-CVE 因果链是强相关但未完全证明。公告不等于当前 detector 已覆盖或命中；此项不计 TP/FN、不纳入既有冻结 holdout、不报告精度/召回。
- IC0KMG 与 IC0GMS 是同一组接口修复摘要，不当作独立漏洞标签；其中 !1837 的 parcel 长度检查仍遗漏 typed array 分配乘数，不能作为本候选的完整 fixed control。正确 fixed control 是 !2037 的修复 commit `de3a68cc8b7d6f18017fd261060def0e38dce54a`。

### 并行任务树（当前执行）

```text
D71 issue/提交侦察 ─┐
T71 公告独立裁决 ───┴─> 1 个官方 source-positive 候选
                         ├─ D72 B detector no finding / 0 dispatcher（完成）
                         ├─ A-BOF-01 / A-INT-01 cross-check no finding（完成）
                         ├─ T72 isolated ASan vulnerable/fixed controls（完成）
                         └─ M2 second-layer challenge（完成）
                                  ↓
                         D73 prototype（完成） -> D74/T74 review + challenge（comment-only FP） -> D75最小修复（完成） <-> T75独立复测（6/6） -> B/IPC集成回归（415/47 skipped/0 failures）
                                  ↓
                         D74/T74 下一轮：若小范围规则成立，集成+回归+负例质量门
                                  ↓
                         D75 final 第3或第4轮：fresh main / scope / regression / 交付收尾
```

- D72 已在当前 IPC integration worktree 复跑并补充 provenance：脆弱与修复源码均 parse 完整、0 findings、0 dispatcher。文件属于 detector 支持的 C++，但单文件输入没有 entry；不能判为安全或已修复。随后对同一精确源码 pair 运行现有 A-BOF-01 `ohscanner.cpp.bounds 0.2.0` 与 A-INT-01 `ohscanner.cpp.integer-bounds 0.2.0`，同样两版均 0 findings（完整输入/hash见 [D72b cross-detector probe](ipc/b-line-20261020/d72b_cross_detector_probe-20261020.json)）。这确认当前窄 B detector 与现有两个通用 A detector 均未命中此样本，不代表真实全仓预测或产品安全。
- T72 的独立最小 ASan oracle 在 accepted parcel-size 前提下复现了两种 typed store 越界；`N=1` 与 `N=8` vulnerable controls 触发 ASan，乘 `sizeof(T)` 的 fixed controls、`N=0` 和短输入拒绝控制通过。数组两处写越界合为一个根因；运行记录与源码位于 [T72 report](ipc/b-line-20261020/t72_cj_array_bounds_oracle-20261020.json)、[oracle source](ipc/b-line-20261020/t72_oracle.cpp) 和同目录 ASan logs。该 harness 只证明分配/写宽度机制，不是 OpenHarmony 的真实 Parcel、FFI 全链路或产品利用证明。
- M2 支持一个 source-level candidate root，将 adjacent null dereference 留作未独立归因缺陷；M2 指出旧版本的 `res.len` 未赋值影响下游数组消费判断，但越界 store 在函数 return 之前发生。`CheckReadLength(N, BYTE_SIZE_32)` 约束 parcel 字节数，却不约束两个目标 allocation 的字节数。综合反馈：**1 source-level candidate; 当前 B/IPC 0 findings; A-BOF-01/A-INT-01 0 findings; 产品调用/披露链未由本轮实测**。下一步只验证 B 的 IPC/FFI 边界规则是否应承接该模式，避免复制 A 的通用 C++ bounds。

### D72 结构化 vibe-coding 提示词（scanner 实测线）

> **目标**：在不改规则/模型/测试的前提下，比较现有 B/IPC detector 对官方脆弱版本 `84d681288793785e8f39f71c824f211edaed8f1e` 与官方修复 `de3a68cc8b7d6f18017fd261060def0e38dce54a` 的处理。先核实 source hash、`cpp` parser status、detector 支持语言、entry/symbol 识别和实际运行命令；分别记录 vulnerable/fixed 的 finding、rule id、coverage 与限制。若没有 finding，判断是 source scope 不适用还是当前 IPC 规则漏报，不得伪造 positive。候选只有一个 root key：`CJ_ReadRemoteObjectArray` 中 N 字节分配后写 N 个 int32/int64 元素。绑定 scanner SHA=`db77164...`、完整 detector/rule/model 版本和源 commit/blob/hash。只读运行，不改代码/测试/holdout；产出 `d72_b_ipc_candidate_probe-20261020.json` 并把精确结果反馈给 T72/M2。

### T72 结构化 vibe-coding 提示词（独立 oracle/反证线）

> **目标**：不要读取 D72 扫描输出作为预期；独立依据官方脆弱/修复源和公告，为同一函数建立最小可复现的源级判别矩阵：数组长度 N=1、N>1、负数/0、remaining parcel length 不足、合法 remote object、null object；分别追踪 allocation bytes、每次 typed store 的宽度/次数、error/return path。源事实应说明 `N` 对 parcel 的 4-byte 元素检查不能替代输出数组容量检查；修复控制必须检查两个 `sizeof(T)*N` 乘法。可选在独立临时目录构造 1:1 最小 C++ ASan oracle，禁止调用真实系统服务/网络。标出该 oracle 对 OpenHarmony 集成/产品调用路由证明的边界，和现有 unit/fuzz 覆盖情况；最多一个共同根因，不以不同数组拆成多个 finding。不要改 scanner、tests 或 holdout；产出 `t72_cj_array_bounds_oracle-20261020.json`，将最强反例及固定版本预期反馈给 D72/M2。

### M2 结构化 vibe-coding 提示词（第二层候选挑战）

> **目标**：作为独立模型 reviewer，仅针对候选 `CVE-2025-26474 / CJ_ReadRemoteObjectArray` 挑战漏洞机制。自己核对官方公告、前后 commit/source hash；验证 attacker-controlled count 到分配和 indexed stores 的完整数据流、正/非正/越界 guards、对象读取 null 情况、修复是否关闭缺陷；找出对候选最不利的源反例与可达性/impact 未证据。最多给一个合并根因；不得因为 CVE ID 自动声称现有 B/IPC detector 已命中。交付 source-based verdict、规则适配意见、可证伪测试和限制至 `m2_cve26474_challenge-20261020.json`，将意见回馈 D72/T72。

### D73 结构化 vibe-coding 提示词（B规则归属/小范围开发线，已完成）

> **目标**：以当前 dirty B/IPC integration worktree 为输入，调查 `CJ_ReadRemoteObjectArray` 的 C++ FFI 调用边界，判断该 count→allocation bytes→typed indexed stores 模式应由 B IPC 规则承接，还是属于 A 通用 C++ bounds；查完整 FFI wrapper/export/registration 路径，不把单文件 0 dispatcher 当作不可达结论。若适合 B 且可窄化到 IPC/Parcel reader API 的 parcel-derived count 和可证明的分配/写宽度不匹配，可提交 additive prototype：同一 root/function 至多一个 finding，保留 `CheckReadLength` 的存在而不把它解释为 destination bound，fixed `sizeof(T)*N` 不报。不得改 A detector、不得另开泛化 C++ bounds 规则、不得覆盖现有 dirty changes。若 B 边界或高精度条件不成立，停止在实现前并写 handoff/原因。T73 独占测试文件；D73 只动 detector/source 代码与必要规则登记，记录 dirty diff identity、source hashes、变更和限制至 `d73_rule_scope_and_prototype-20261020.json`。

### T73 结构化 vibe-coding 提示词（独立回归线，已完成）

> **目标**：独立绑定官方 !2037 vulnerable/fixed revision，先不参考 D73 实现，写一个新的独立测试文件而不触碰当前脏的 fixture manifest。建立一条正例根因（两个 typed output arrays 合并成一个 finding）、fixed `sizeof(T)*N`、安全的 parcel-length matched allocation、unrelated non-parcel dynamic array、N<=0、short parcel、null remote object 控制；断言 rule ID、候选唯一性、fixed/safe/unrelated 的 0 findings，以及 coverage/unknowns 诚实输出。优先通过 scanner detector test API；若现架构无 FFI entry/root，请给出可执行 test seam 和失败原因，不伪造 test pass。保留 D72/T72 oracle 与 dirty integration changes；提交独立测试文件、命令/结果至 `t73_test_oracle_and_feedback-20261020.json`，并将最强反例反馈给 D73。

### 三到四轮收尾节奏

- **第1轮（本轮，完成）**：核 main、并行源调查/公告裁决、静态差分探针、独立 ASan oracle、M2 challenge。结论为一个 source-level candidate，现有 B 与两个 A bounds 检测器对该单文件均未命中。
- **第2轮（完成）**：D73/T73 完成 B/A 归属决策、窄规则 prototype 与独立 source oracle；开发侧报告 source probe 通过，尚待 exact-overlay 独立测试。
- **第3轮（完成审查，验证反馈待齐）**：D74/T74 对 exact overlay 审查发现 comment-only false positive；此具体缺陷触发第4轮。
- **第4轮（当前执行）**：D75/T75 修复并独立重放 comment-only 反例、官方 vulnerable/fixed controls；通过后 fresh main、scope、diff provenance 与最终交付。

### 持续执行目标

- 每轮先通过 Git fetch 或可信只读 ref API 核实 scanner `origin/main` SHA，并记录当前 dirty integration SHA/diff 与实际执行 scope；若 main 变化，重绑 source evidence、重放相关回归后再合并结论。
- B/IPC 静态层以“少而准”为目标：单一根因合并、多强 guard 与负例复核、最多将少量 source-bound candidates 送 M2；M2 不替代测试线，测试线不替代正式 source/build evidence。
- 继续 D9/D54 的 source/component follow-up，但不重复追问 unchanged build blocker；使用站立授权允许的公开组件/隔离 PoC 自行寻找可用输入，未执行记 `not_run`，产物不代表产品覆盖。
- 每轮至少交付一个具体可复现的 source/test/report 结果；D72/T72/M2 与 D73/T73 已闭环，D74/T74 正并行验证。第3轮确有一个可复现的注释误报；当前只做最小修复及独立复测后收尾。若 B 专用规则不合适，则交付 source-positive 边界和 A handoff，不为了候选数新增规则。

### 第2轮增量：T73 独立反馈（2026-10-20）

- T73 独立确认官方 FFI wrapper `FfiRpcMessageSequenceImplReadRemoteObjectArray` 取回 `MessageSequenceImpl` 后直接调用 `CJ_ReadRemoteObjectArray`；这建立了导出 wrapper 到受影响 helper 的源码绑定，但未证明具体低权限 Binder caller、产品构建纳入或 CVE 精确披露路径。当前 B IPC 以 `OnRemoteRequest`/transport roots 为主，缺 count-derived allocation-size 与 typed indexed-store 宽度规则；此接口不自然落在现有 dispatcher root 中。
- T73 在 `c-line-static-pr/tests/test_t73_cj_array_bounds_oracle.py` 新增了独立 5 项 oracle；`python -m pytest -q tests/test_t73_cj_array_bounds_oracle.py`：5 passed（0.18s）。覆盖 vulnerable/fixed official source、FFI wrapper、N=1/8、N<=0、短 parcel、safe/unrelated controls 和单一 CVE label root。该文件与测试报告均未改 B integration worktree 的既有 fixture manifest。
- 当前 B detector 对 helper+wrapper 仍 0 findings；测试因此不能断言生产 rule ID、finding dedupe 或 detector TP。独立测试只验证标签侧同根因归并及 source contract，不把 no-finding 记成安全。报告：[T73 oracle and feedback](ipc/b-line-20261020/t73_test_oracle_and_feedback-20261020.json)；独立测试源位于另一条 C-line worktree，见报告路径及 SHA。
- D73 已收到 T73 的反馈，需在交付中回应其 B/A 归属、缺少 IPC root 的边界及其对 detector direct-run 无 finding 的处理。若没有精确、可分离的 B 规则，应采用 source-level handoff 而不扩写 B；若 prototype 出现，D74/T74 必须对 vulnerable/fixed/safe/unrelated 和根因去重做独立回归。

### 第2轮开发结论与第3轮启动（2026-10-20）

- D73 选择 B/IPC 承接**仓库 + 文件 + 函数**限定的 Cangjie FFI Parcel 数组宽度模式；A 仍负责跨仓通用 C/C++ allocation bounds。新规则 `ipc.parcel.array-allocation-width` / DATA-06 / 0.1.0 要求目标 `MessageSequenceImpl::CJ_ReadRemoteObjectArray`、Parcel `ReadInt32` 派生 count、正数 guard、同 count 的 `malloc(count)` typed arrays 与 typed indexed stores；两个数组共享单一 function/root。单独 `CheckReadLength` 形态不报，错仓库不报。详见 [D73 scope/prototype](ipc/b-line-20261020/d73_rule_scope_and_prototype-20261020.json)。
- D73 的 direct probe 报告在两个 vulnerable revisions 各一 root，在 !2037 fixed revision 0 finding；A-BOF/A-INT 都是 0。以上是 ad-hoc source probe，不是独立测试，也未覆盖产品路由。T73 的 oracle 与 wrapper 证据被纳入设计；截至 D73 报告，T73 5 项 oracle 尚未对 exact overlay 做 integrated replay，因此继续第3轮验证，不以开发者 probe 自验收。
- Prototype 增量 hash：tracked diff SHA256 `9d1bc3fe6c5c73e2207ba739101d8480feedf8ccb6d2115319cc47e20e90f3b4`（98,123 bytes）；新增 `ffi_array_bounds.py` SHA256 `5e1456e8a602cbd5696727382b23819a7222c866264cebaf30140d958fa7379c`、`families/data06.py` SHA256 `a277339ae772c42a9465fc3b2063f8c80326ef770ea939598769c7ae4214074b`。保留此前 teammate 的 IPC dirty diff；没有改 A、holdout 或 T73 测试文件。
- 第3轮现并行启动：D74 对规则实现做独立设计/反例审查；T74 将独立 oracle 接到 exact overlay，运行 vulnerable/fixed/safe/unrelated/wrong-repository/CheckReadLength-only controls，并只报告当前测试覆盖到的行为。若两线发现具体缺陷，才进入第4轮最小修复；否则本轮收尾并刷新 main、scope 与回归记录。

### 第3轮独立审查发现与第4轮（仅具体缺陷修复）

D74 对 exact implementation 做只读审查时，在内存中构造了 syntactically valid 的 `CJ_ReadRemoteObjectArray`，把匹配链全部放入 `//` 注释；当前 detector 因在 AST 选出方法后仍扫描原始函数体文本，错误发出 `ipc.parcel.array-allocation-width`。这是具体 FP，不是产品发现，已触发第4轮修复。D74 报告待落盘；T74 将把该控制加入 exact-overlay 独立测试。开发线仅修改自己的 `ffi_array_bounds.py` 新文件，测试线独占新测试，不改队友已有脏文件。

#### 结构化 vibe-coding 提示词 — D74/D75 最小修复线

> **角色**：B/IPC 规则开发 Agent；只修复经独立审查复现的 comment-only false positive。
>
> **输入/基线**：使用 `D:\openHarmonyScanner\worktrees\b-ipc-integration-20261020` 当前 overlay；读取 D73 报告与 D74 反例。保留既有 dirty diff、测试、fixture manifest 与 holdout。
>
> **缺陷**：正则在已通过 AST 定位的方法体后扫描含注释的原文；注释中出现 ReadInt32、positive guard、malloc(count)、loop、indexed store 即误报。
>
> **目标**：只让可执行 C++ token/AST 节点参与结构检测；可采用可靠的 AST 节点/字节范围，或注释剥离并保证字符串/字符字面量不被误改。保持 vulnerable 源一根、fixed 源零根、注释内伪代码零根；不得扩大 detector scope 或重写规则族。
>
> **验收**：先验证 D74 comment-only 反例无 finding，再验证官方两个脆弱 revision 各一 root、官方 fixed revision 0 root，并记录 parser/provenance/代码 hash。T74 负责测试文件和独立测试结论；开发侧 direct probe 不替代 T74。
>
> **约束/交付**：只改本轮自己新增的 detector 实现；不改 A detector、公共接口/holdout、队友 `analysis.py` 及既有测试。交付最小 diff、命令及原始结果、保留的限制至 `d75_comment_fp_fix-20261020.json`；若最小修复会产生不安全字符串语义，停止并报告 limitation。

#### 结构化 vibe-coding 提示词 — T74/T75 独立验收线

> **角色**：独立安全测试 Agent；不改开发 detector，不把 D73 源探针当真值。
>
> **输入**：读取官方 pinned vulnerable/fixed commits、T73 独立 oracle、D74 comment-only 反例；自行确认 integration overlay SHA/diff 与源 hashes。
>
> **矩阵**：实际调用完整 B detector，验证两个脆弱 revision 各恰好一个 DATA-06 root；fixed `sizeof(T)*N`、短 Parcel/guard-only/unrelated typed allocation/wrong repository/comment-only chain 均 0 finding；至少断言 finding 的 rule id/version、source position、CWE/impact/obligations 与 source hash。若 scanner API 无法承载旧 commit 文件，使用精确 `SourceUnit` + repo context，并把范围写明。
>
> **执行**：先复现 comment-only FP，再在开发修复后重放同一测试；另运行所需的 DATA-06/IPC focused tests。测试报告逐项列 expected/actual/pass/fail/not_run，不推断产品 reachability 或真实 TP，不改 holdout 与共享 manifest。
>
> **反馈/交付**：任何失败给最小反例与行号反馈 D75；全矩阵通过才建议关闭。写 `t75_overlay_independent_acceptance-20261020.json`，并保留独立测试源及 SHA。

D74 报告已归档：[D74 implementation review](ipc/b-line-20261020/d74_detector_design_review-20261020.json)。修复后 direct source probes 仍为 vulnerable 两版各一个 root、fixed 为 0、comment-only 为 0。该补丁只掩码 Tree-sitter comment/string/char literal span，保留换行及字节偏移；残余限制为 regex 对复杂分支支配/别名的数据流证明有限。T74/T75 已通过实际 detector 调用路径复测，完整结果见 T74/T75 报告；开发 probe 不替代独立测试。

### 第4轮收尾结果（2026-10-20，本轮根核验）

- 最后一次 `git fetch origin main` 成功；integration `HEAD`、`FETCH_HEAD`、`origin/main` 均为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`。未提交或改写工作区分支；所有先前 DATA-01/relay/multidispatch teammate 改动均保留。
- D75 修复只在新的 `ffi_array_bounds.py` 内遮蔽 AST 注释/字符串/字符字面量后再做词法匹配。T74/T75 实际 detector API 测试：`python -m pytest -q tests/test_ipc_t74_cj_array_bounds_integration_challenge.py` → **6 passed**；两 pinned vulnerable source 各一个 rule finding、去重为单一 CVE/function root；official fixed source 与 sized/nonpositive/unrelated/guard-only/wrong-repository/comment-only controls 均 0。报告：[T74/T75 overlay challenge](ipc/b-line-20261020/t74_overlay_challenge-20261020.json)。
- D75 为新 DATA-06 建立正/修复/安全 synthetic design controls，并登记家族、CWE、rule version 与当前测量声明；当前状态 `not_run`，无 holdout case ID、无 precision/recall 数字。历史 2026-10-18 holdout 文件未修改且测试核验其原始 SHA256；DATA-06 独立声明位于 `research/evidence/interface/ipc/current_rule_measurement_20261020.json`；D75 集成记录见 [D75 closeout](ipc/b-line-20261020/d75_data06_integration_closeout-20261020.json)。
- 完整 B/IPC unittest：`python -m unittest discover -s tests -p 'test_ipc_*.py' -q` → **415 run / 47 skipped / 0 failures**。IPC scope 检查以完整 baseline SHA `db77164fdc2af0da02e4d3efc056d84694fd68e8` 执行 → 0 violations；`git diff --check` clean。
- 最终代码仍是 integration overlay 上的未提交变更。source-level candidate 可供第二层 LLM 对单根机制作漏洞/反例复核；产品构建纳入、部署 FFI/Binder 路由、低权限攻击者可达性及真实进程 impact 仍未知。该候选没有加入冻结 holdout，不是 detector benchmark TP，也不支持准确率声明。
- 四轮切片到此收口：第1轮 source/ASan/M2，第2轮边界决策与 prototype，第3轮找到 comment-only FP，第4轮修复、独立反例/官方版本复测及 IPC 集成验收。后续若没有新代码或 source evidence 不重复审计；持续目标保留为每轮重核 main、候选少而源绑定、测试线独立互馈、M2 逐条挑战和 unknown 如实记录。
