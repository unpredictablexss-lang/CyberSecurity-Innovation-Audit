# Contract Change Request: a blocked detector run must not hide its own coverage and obligations

- 状态：`proposed / not implemented`（2026-10-11）
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
  「哪几遍看见它」；blocked 那遍的候选在报告里写明「义务未被 runner 记录，不等于没有义务」，
  并把那个 0 连同 `applicable/analyzed` 计数一起打印、附原因说明。
- 测试：`tests/test_component_audit.py`（33 项）钉死上述性质，包括「blocked 那遍的 0 必须
  与真实计数同时出现」。

代价，如实列出：

1. **两倍墙钟时间**（同一 shard 跑两遍），以及**一个解释对应两个 detector ID**
   （ID 空间多出一个名字，且候选的 `diagnostic_id` 因 detector_id 不同而不同）。
2. 真正「只在 partial 文件里」的候选，其义务**仍然只能靠人工**（`complete-ast` 那遍看不见它）。
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
