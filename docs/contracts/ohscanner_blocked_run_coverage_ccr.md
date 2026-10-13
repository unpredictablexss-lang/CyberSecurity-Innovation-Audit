# Contract Change Request: a blocked detector run must not hide its own coverage and obligations

- 状态：`proposed`，其中 **(b) 已落地**（core 线 M2-A 集成提交 `022c022`，2026-10-11）；
  (a)/(c) 待负责人决定。2026-10-13 接口线并入 core 后按 §3.2 完成翻转，落地记录见 §3.3。
- 适用接口：`src/ohscanner/runner.py`（`_normalized`、`run_all_with_coverage`）、
  `src/ohscanner/execution.py`（`coverage_has_gaps`）
- 关联 detector：`ohscanner.interface.ipc`
- 处理原则：本文只提出变更，**不修改公共 contracts/runner/execution**，也不把 proposed
  字段写成已实现 API。本分支的绕过方式见 §2，它是**旁路**，不是对共享语义的改动。
- 提出人：B（接口线）。落地与否由负责人决定。

## 1. 问题（真实组件实测，不是推演）

`ohscanner.interface.ipc` 在一处做保守选择：**只要有任一 applicable 文件的 parse 不完整，
整次 run 就返回 `blocked`**（`detectors/interface/detector.py`，`status = "blocked" if
any(u.parse_status != "complete" ...)`）。共享 runner 对 `blocked` 的处理是三件事同时发生：

| 位置 | 行为 | 后果 |
|---|---|---|
| `runner.py:152-154` | `scope_files` / `scope_loc` 置 0 | 报告说「这次没读过任何文件」 |
| `runner.py:133-144` | 每个 applicable 文件 `analysis_status=not_analyzed`、`analysis_reason=blocked` | 覆盖表说「全部未分析」 |
| `runner.py:254-265` | `evidence_obligations` 仅在 `report.status == "completed"` 时生成 | **候选还在，证明义务列表空了** |

**实测**：`communication_dsoftbus` @ `652f88e0…`（生产代码 **1656 文件** / 15,243,597 B，
parse complete **729** / partial **927**），检测器 `blocked`，报告里 **4 条候选**
（`ipc.relay.descriptor-boundary` 2 + `ipc.capability.export` 2），而同一份报告的 coverage
sidecar 对这 4 条的 `evidence_obligations` **是空列表**。

（口径与复现：1656 = 3728 个 tracked entry 里按后缀取 2975 个源文件、再按**整路径段**排除
`test/tests/mock/sample/...` 后剩 1656；该数由两份独立实现得到同一结果——审计驱动的
`plan_scope`，以及一份直接按 `Path(p).parts` 过滤的临时脚本；早先记录里的「1025」是另一套
临时 SKIP 规则的产物，**已作废**。文件数下降的 1319 个来自 `tests` 段的测试树。）

这不是「保守」而是**方向相反的两处失真**：

- 0 的 `scope_files` 与「全部未分析」**低报**了实际做过的工作（检测器逐文件走的是树，partial
  文件里的候选确实产出了）；
- 空的 `evidence_obligations` **去掉了复核链**——AGENTS.md 的证据门要求每条候选带
  「还缺什么证明」，而 `blocked` 恰恰把它删掉，读报告的人会以为这些候选不需要证明。

`blocked` 这一个状态目前还混装了三种互不相同的处境：① 无可分析语言；② 缺 required
shared facts；③ 检测器自己判定覆盖不完整。②的 `limitations` 文字不同，但 run status 分不出。

## 2. 本分支当前的旁路（已实现，不改共享语义）

- 新增同解释、窄范围的 detector：`ohscanner.interface.ipc.complete-ast`，`required_facts = ("ast",)`。
  runner 于是**只把 complete 文件交给它**，其余记 `unexamined: incomplete_ast:<status>`。
  这次 run 会 `completed`：`scope_files`/`scope_loc` 是真实数字，且**义务被记录**。
- 审计驱动（`src/ohscanner/detectors/interface/audit.py`）对同一 shard **跑两遍**
  （`complete-ast` + `all-files`），按 `(file, line, rule_id, source_sha256)` 合并候选并记录
  「哪几遍看见它」；并把 blocked 那遍的 0 连同 `applicable/analyzed` 计数一起打印、附原因说明。
  驱动另有一条**兜底**：只有当 runner 确实没为某条候选记录义务时，才补上该规则的 standing
  questions（`status=unknown`、`origin=audit_driver`）。写这条旁路时它是 blocked 那遍的常态；
  (b) 落地后它退为对照路径（§3.3）。
- 测试：`tests/test_component_audit.py`（33 项）钉死上述性质，包括「blocked 那遍的 0 必须
  与真实计数同时出现」。

代价，如实列出：

1. **两倍墙钟时间**（同一 shard 跑两遍），以及**一个解释对应两个 detector ID**
   （ID 空间多出一个名字，且候选的 `diagnostic_id` 因 detector_id 不同而不同）。
2. ~~真正「只在 partial 文件里」的候选，其义务仍然只能靠人工（`complete-ast` 那遍看不见它）。~~
   **2026-10-13 由 (b) 关闭**：runner 现在为 blocked 那遍也记录义务，这类候选不再依赖人工合成。
3. 这是绕路：共享报告本身仍然是「blocked ⇒ 0 / 无义务」。

## 3. 请求的变更（未实现，三选一）

- **(a) 覆盖计数解绑 status**：`scope_files`/`scope_loc` 取检测器自报的 `analyzed_files`，
  即使 status 是 `blocked`。**单独使用会高报**（读者会把它当成「干净覆盖」），因此不建议单独采用。
- **(b) 义务不再按 status 过滤**：`evidence_obligations` 是**附着在已产出的 finding 上**的，
  与 run status 无关；只要 finding 在，义务就应该在。改动最小、语义最纯。
- **(c) 增加第三个 run status**（如 `partial` / `completed_with_gaps`），语义为「所有 eligible
  文件都做了工作，其中 N 个 AST 不完整」，并让 `execution.coverage_has_gaps` 把它计为 gap，
  使总报告仍停在 `completed_with_limitations`。

**建议**：(c) + (b)。这两个合起来既解决「低报」（scope 不再是 0、整体状态仍是带限制），
也不引入「高报」（partial 显式是一个 gap）。若只做 (b)，0 的 scope 仍在，读者仍要靠文字解释。

## 3.1 负责人已定的方向（2026-10-11，优先于上面的「建议」）

负责人接受本 CCR，但**不直接采用「加第三种 status」**，并要求按下面的顺序落地：

1. **优先保持现有公共结果格式**，先用 **coverage sidecar 表达部分覆盖**。**只有现有格式确实
   无法表达时，才增加 status。** 理由：新增一个 `partial` 状态仍可能把「部分解析、部分执行、
   部分证明」三件事混成一个词。
2. 要回答的三个问题是**相互独立**的，不要用一个字段同时回答：

   | 维度 | 要回答的问题 |
   |---|---|
   | 执行状态 | 检测器是否正常运行结束？ |
   | 覆盖情况 | 哪些文件、入口、分析步骤实际完成？ |
   | 证据与义务 | 每条候选有哪些证据，哪些条件仍未证明？ |

3. 具体语义（负责人已批准）：
   - 检测器**正常完成**了对可分析文件的处理：**执行可以是 `completed`，覆盖是 `partial`**。
   - 分析前提**完全不满足**：`blocked`。
   - **已产出的有效候选与证据义务，不得仅因为整体状态而被丢弃。**
   - 保留候选仍须**校验文件范围、源码哈希、位置与来源**；不允许「简单地删掉状态过滤」把
     全部候选一并放行。
   - **「已检查但分析未完成」与「完全未分析」必须分开记录。**

因此上面 §3 的 (a)/(b)/(c) 里，**(b) 是必须做的**；(a) 与 (c) 是否做、以什么形式做，由负责人
按「先 sidecar、后 status」的顺序决定。三条语义里，「保留候选要校验绑定」与「两种未完成要分开
记录」在现有报告格式下也可以表达，不必等新 status。

## 3.2 本分支提供的反例与回归测试

负责人改动公共平台后，下面这些断言就是必须翻转/保持的判据（都在 B 仓库，可直接跑）：

| 判据 | 位置 | 现在钉住的事实（改平台前） | 平台修好后应当是 | 2026-10-13 接口线并入 core 后的结果 |
|---|---|---|---|---|
| blocked 遍的 scope 计数是 0 | `tests/test_component_audit.py::TwoPassAuditTests::test_all_files_pass_keeps_recall_and_admits_the_zero_counter` | `scope_files == 0` 且同一遍 `applicable_files == 5`、`diagnostics > 0` | scope 不再是 0，或整体状态变成显式的 `partial` | **未变，仍是 0**（(a)/(c) 未做）。断言保留，说明文字改为「义务已随 run 一并记录」 |
| blocked 遍的候选义务为空 | 同上 + `tests/test_ohscanner_m2.py` / `tests/test_ohscanner_m15.py` 的 sidecar 断言 | `evidence_obligations` 为空列表 | 义务随 finding 一并保留 | **已翻转**：`src/broken.cpp` 那条候选现在 `obligations_recorded_by_runner == True`、`obligations_by_source == ["all-files"]`、4 条 `origin: shared_runner`。测试改名 `test_partial_candidate_keeps_the_obligations_the_runner_recorded` |
| 驱动必须自己补 unknown 义务 | `TwoPassAuditTests::test_partial_candidate_carries_driver_synthesized_unknown_obligations` | 5 条 `origin: audit_driver` 的义务被合成出来 | 若平台保留义务，这一条仍应成立（驱动只在**确实没有**义务时才补），可作为「没有重复造证据」的对照 | **保留为对照**：测试改名 `test_driver_standing_questions_appear_only_without_a_runner_record`，用 `mock.patch` 去掉 sidecar 的义务记录后断言驱动仍补出那 5 条 `origin: audit_driver`；同一套 fixture 的真实运行里 `candidates_with_driver_synthesized_obligations == 0` |
| 归因计数闭合 | `FileAccountingClosureTests`（4 项） | `files_unaccounted == 0`，「已解析/部分/失败/未被认领/被丢弃/未运行」六桶闭合 | 不因新状态而破桶；新增状态必须能落进某一桶 | **未破**：4 项全绿，`files_unaccounted == 0` |

这个反例是可复现的：`communication_dsoftbus @ 652f88e0…`，4 条候选、义务列表为空（见 §1）。

### 3.3 落地记录（2026-10-13，接口线并入 core）

- **(b) 的落地方是 core 线，不是接口线。** 负责人在 M2-A 集成提交 `022c022` 做了三件事：
  sidecar 的 `evidence_obligations` 门从 `report.status == "completed"` 放宽为
  `report.status in ("completed", "blocked")`；新增 `DetectorRun.file_outcomes`；
  报告状态不再是「只要一个文件没解析完就 `blocked`」（`"blocked" if report.status == "blocked"
  and not (analyzed or partial) else ...`）。后两条让「已检查但分析未完成」与「完全未分析」分开
  记录，正是 §3.1 第 3 条的两项要求，且按 §3.1 的「先 sidecar、后 status」落在 sidecar 上：
  sidecar 自己的 `status` 现在是 `not_applicable / failed / blocked / partial / complete` 五档，
  并带 `partially_inspected_files`。
- **接口线的动作**：把 `origin/feat/ohscanner-core`（`e365465`）并入
  `feat/interface-ipc-detector`，然后按上表逐条翻转/保留，并同步驱动里**描述旧平台行为**的文字
  ——模块 docstring、`DRIVER_STANDING_OBLIGATIONS`（原 `PARTIAL_ONLY_OBLIGATIONS`）的注释、
  合成义务的 `reason`、coverage `notes`、`limitations`、markdown 的 NOTE。
- **驱动的逻辑没有改动，也不该有**：合成门本来就是 `if not entry["obligations"]`，即 §3.2 第 3
  行要求的那条不变式在文本落地之前就已经成立。本次改的是**文字与断言**，不是行为。
- **实测（合并后的树）**：`all-files` 那遍的 detector run 状态仍是 `blocked`、`scope_files`
  仍是 `0`，但 4 条候选全部 `obligations_source == shared_runner`，
  `candidates_with_driver_synthesized_obligations == 0`；整体 report 状态是
  `completed_with_limitations`（`coverage_has_gaps` 把这次 run 计为 gap，符合 §3.1 第 1 条）。
- **一并修的项目（跨线待办）**：core 的
  `tests/detectors/test_cpp_runner_integration.py::test_maps_current_detector_run_to_toolrun_v1`
  断言 `schema_version == 1`，而本仓库的契约 v2（`PROGRAM_STATUS.md` §27）规定是 `2`。合并后的
  树只能发出一个号，所以**改测试不改契约**：测试改名为 `..._toolrun_v2` 并断言 `2`。
  **core 线自己那条分支上这个断言仍是 `1`**，需要负责人决定何时一并重基线。
- **本次合并的 merge commit 单独看是红的**（5 项），红的原因就是本节要处理的碰撞；翻转是紧跟在
  其后的一个提交。若有人按 commit 二分，请从这里读。

## 4. 对赛题计分的影响

- **完整性**：现在读报告的人无法从 `scope_files` 判断「读过多少」，只能读文字说明。
- **准确性/误报**：义务列表消失会让人**无法**在静态阶段筛掉不该上报的候选；反向地，
  把 blocked 当「无覆盖」又会让真实候选被当成噪声。两个方向都扣分。
- 该变更**不影响**任何已有 detector 的结论等级：候选仍是候选，`validated_vulnerability`
  仍是 0；它只让覆盖与义务不再自相矛盾。

## 5. 本分支明确没做的事

- 没有改 `contracts.py` / `runner.py` / `execution.py` / `catalog.py` / CLI。
- 没有新增公共 JSON 字段；没有把 `blocked` 重新解释成别的状态。
- 没有把这条 CCR 当已实现条款引用；`docs/contracts/` 下另有 v1/v2 生效文本，本文与之并列。
- 本分支改的是**自己那份审计报告格式**（`audit.py` 的 `schema_version` 1 → 2：候选带 `source_binding`
  / `rule_version` / 逐来源义务）与审计驱动本身，**不是**公共契约。它不能替负责人做平台层的改动。

## 6. 平台修好之前，本分支不做的事

- 不把「驱动补出的 5 条 unknown 义务」当成平台已保留义务的证据（那是驱动的标准问题，不是跑出来的）。
- 不用「两遍都看见」当作独立佐证（同一套解释在同一文件上跑两遍，是重复不是交叉验证）。
- 不因为修好覆盖语义就提升任何结论等级：候选仍是候选，`validated_vulnerability` 仍是 0。
