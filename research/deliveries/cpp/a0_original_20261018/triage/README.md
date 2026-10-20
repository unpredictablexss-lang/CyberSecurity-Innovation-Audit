# A0 后续验证分诊队列

生成日期：2026-10-18（Asia/Shanghai）

## 分诊摘要

本队列将 A 线 30 份报告抽查中的 345 条扫描候选排成后续证据验证顺序。每项嵌入 A0 原逐条判定，保留原 candidate/diagnostic ID、review ID、repo、commit、tree、路径、Git blob、source SHA-256、Detector、版本、rule、profile 和原 status。A0 未在候选级单独记录 scope；样本运行的 `declared_scope` 为 `.`，`profile_id` 为 `light-ast`，故队列将 scope 标为“候选级未单独记录”，不推断超出原报告的信息。

A0 的 9 条 `not_reproduced` 都没有目标派生复现执行。对应扫描本身有原始 request/run_meta 和 stdout/stderr；samgr 与 Wi‑Fi 扫描均以 exit 0 完成，`build_profile=none`，`profile=light-ast`。这些是静态扫描执行记录，不是目标复现日志。原始 request 含实际扫描命令；stderr 为空，stdout 仅报告扫描完成。samgr 的 8 条同规则候选共用同一文件、blob 与 source SHA，且该 IPC 文件在 detector coverage 中标为 `partial / detector_model_incomplete`；状态不能解释成漏洞已排除。Wi‑Fi 一条有 reduced model 及控制重放，候选文件同样为 detector partial，但模型未绑定产品 IPC/build。候选源文件层面的 IPC detector coverage 中，有 56 条记录为 `partial` / `detector_model_incomplete`（其中 9 条属于 `not_reproduced`）；这表示分析模型未完成，不代表源代码语法解析失败。所有原 status 保持不变。

首批仅继续 5 条 `not_testable`：DataShare 的一条缺失授权检查候选和两条 FD capability 导出候选（同一 source file 家族），Wi‑Fi 的一条 remote-object 导出候选，以及 HUKS 一条异步取消 shared_ptr 候选。其余 331 条 `not_testable` 留在暂停队列，等待具体入口、权限策略、同步/线程、目标构建或解析证据。A0 的 9 条 `not_reproduced` 全部进入最高复核顺序；另有 47 条 `not_testable` 的目标文件 detector coverage 也是 partial，均在队列里明确标出。

评分均为 1–5 的工作队列排序值：潜在影响、边界敏感度、证据完整度、补证成本、可重放性。它们不是漏洞严重性、确认置信度或概率。证据不满足时保留 unknown；本队列不计算 Precision/Recall。

## 队列 schema

- `queue_id` / `candidate_id`：原始判定 ID 与 diagnostic ID。
- `repository`, `repo_project_path`, `commit`, `tree`, `path`, `line`, `blob`, `source_sha256`：来源键；SHA 来自 A0 provenance。
- `detector`, `detector_version`, `rule`, `scope`, `profile`：检测上下文。`scope` 明示原始字段缺失；样本 profile 来自清单。
- `original_status`, `original_record`：结论原样留存，后者包含完整原始逐条记录。
- `blocker_category`, `blocker`, `minimum_next_evidence_action`：阻塞诊断和唯一下一项最小动作。
- 五个 `*_score` 与 `priority_rank`, `priority_reason`：可行动排序及解释。
- `owner`, `dependency`, `queue_status`, `family_key`, `family_leakage`：责任、依赖、当前队列状态和家族/泄漏记录。
- `source_report_path`, `source_result_path`, `source_run_meta_path` 及其 SHA 字段：回到 A0 原始逐项报告的入口。

## 优先事项与暂停项

### 继续：第一批 5 条 `not_testable`

1. **CR-0016–CR-0018（同一源码家族，DataShare）**：`OpenFileInner` 的权限检查证据与 `CmdOpenFile` / `CmdOpenFileWithErrCode` 的 FD 导出边界需要合并阅读。先取得该 commit 的 IPC 注册/调用端和访问控制策略，绘出调用者身份、授权 guard、FD 创建及 reply 传输链；只有确认外部主体可达后才做授权/未授权隔离对照。三条记录各自保留，不视为三个独立缺陷。
2. **CR-0336（Wi‑Fi capability export）**：先追踪 remote object 的创建、owner、访问控制、导出和接收端敏感操作，再判断是否能用双主体 IPC 对照。
3. **CR-0342（HUKS async shared_ptr）**：先查 `cancelled_` 的所有读写、取消回调、任务生命周期、锁/原子保护和线程模型；有并发未同步路径后再构建目标 TSan harness。

### 继续：9 条 `not_reproduced`

- **CR-0219–CR-0226（samgr，8 条同家族）**：只执行一次源码边界分诊。最小动作是对照原始请求/运行元数据与对应源码，建立覆盖八个导出点的 transaction、输入、调用者权限、FD/敏感操作矩阵。原材料显示扫描运行成功、静态 build profile 为 none；没有候选目标动态复现或失败日志。先找可达且有安全边界意义的路径，再决定是否建 harness。
- **CR-0335（Wi‑Fi parcel copy-range）**：已有 source-derived reduced model 与 unsafe/safe 控制各三次结果；产品入口、目标编译参数和实际 parcel/buffer 语义仍未绑定。最小动作是将模型输入/长度约束映射到同 commit 的真实 IPC stub 与目标缓冲区，并确认目标构建配置，再进行隔离重放。

“not_reproduced”表示现有记录没有重现目标路径或证据链未完成；不能由此推出漏洞不存在或安全。

### 暂停

- **其余 331 条 `not_testable`**：保留在完整 CSV/JSON 队列；当前 A0 证据未建立目标入口/权限/线程模型/目标构建，或只具有 syntax candidate / descriptor 边界提示。先补候选自身的最小静态调用/数据流证据及组件契约。没有具体可达路径时暂停动态 PoC，避免把 generic TSan/auth harness 或 parser 控制结果冒充目标复现。
- 同一 repo、文件、规则或 source SHA 的重复候选按 family key 聚合安排验证，但每个原始 ID 仍占队列一行。

## 来源与家族泄漏

A0 样本来自固定 seed `20261018` 的 30 份报告抽样；30/30 commit、tree、snapshot 和 345/345 source SHA 绑定在 A0 报告中。A0 报告说明 generic `shared_ptr`、`lifetime`、`auth01` harness 只作为方法或正负控制，不能证明样本候选。它们与目标派生 PoC 不同，但这些候选曾处于同一次人工审查/调参材料语境，不能视为独立 holdout。

机器比对发现 48 个重复 family key，覆盖 291 条候选（key=`repo+rule+path+source SHA`，最大家族 25 条）。可见重复/家族重叠包括：CR-0219–CR-0226 共用 samgr 源文件/blob/SHA 与同一 rule；CR-0016–CR-0018 共用 DataShare 源文件/blob/SHA；263 条 `shared_ptr` 规则候选属于同一规则家族，其中多个记录落在同 repo/file/source SHA。对历史 benchmark 的四个 JSON 条目按 repo、vulnerable/fixed commit、affected file 做了直接比对，没有发现 repo/commit/affected-file 命中；但 `shared_ptr` concurrency 与历史 kernel concurrency 仅能判为主题相关，根因是否相同未知。PoC/fuzz/调参材料的全量 source/commit 二级碰撞没有完整索引，故标为 **unknown**。逐家族结果见 `family_audit.json`。不得将同源/同规则记录当作独立验证样本，也不据此给出准确率指标。

## 对账统计

- 抽样报告：30（有候选 20、零候选 10）。
- 原始扫描候选：345；队列 ID 去重后仍为 345。
- 原 A0 status：`not_reproduced` 9、`not_testable` 336；保持原值。目标文件 detector coverage partial：56（9 条 not_reproduced、47 条 not_testable）；其余 289 条没有候选文件级 partial obligation 记录，但仍需完成其余证明义务。
- 原风险验证优先级：high 283、normal 62；它表示复核顺序，不是漏洞定级。
- 首批 `not_testable`：5；暂停 `not_testable`：331。
- 原包 SHA 清单：97 文件、4,364,747 bytes；缺失 0、哈希/大小不匹配 0。类型计数：JSON 17、Markdown 4、XLSX 1、PDF 1（其余含 logs、scripts、PoC 源码等）。
- A0 跨 JSON/Markdown/XLSX/PDF 对账均记载 345 条候选及 346 条明细行；额外一行为相邻审计 finding，不能并入候选数。扫描候选 confirmed=0；相邻审计 finding=1；本队列不改变任何历史结论。

## 统计复核步骤与下一轮入口

在本目录运行：

```powershell
python .\verify_queue.py
```

脚本只读 A0 哈希清单所指文件，并核对全部源哈希/大小、345 个原候选与队列候选 ID、repo/commit/tree/path/blob/source SHA/Detector/rule/status/profile 来源键、唯一 ID 和原 status 计数。预期 `hash_ok=true`、`count_ok=true`、345 unique IDs、9/336 status。

下一轮从 `queue.csv` 按 `priority_rank` 处理，先完成 CR-0219–CR-0226 的 samgr 共用边界矩阵和 CR-0335 的 Wi‑Fi 输入约束映射，再处理 5 条首批 `not_testable`。每项完成后只追加新证据、证据 SHA、执行环境和复核者；只有满足真实入口、边界、可控触发、敏感操作与 CIA 影响证据门时，才提出状态变更并记录证据依据。
