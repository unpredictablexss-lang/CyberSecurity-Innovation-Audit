# A 线 T2 候选分诊状态（2026-10-19）

## 基线与结论

本记录基于 A0 固定交付 `research/deliveries/a-line-sample30/20261018/`，在仓库基线 `origin/main` / `db77164fdc2af0da02e4d3efc056d84694fd68e8` 上整理。A0 抽取 30 份报告，包含 345 条扫描候选；逐条原结论为 `not_reproduced` 9 条、`not_testable` 336 条。候选级 confirmed 为 0；样本 2 的相邻上下文审计另有 1 条独立 finding，不计入 345 条候选。

本队列只安排补证工作，保留每条 A0 的原始 review ID、diagnostic ID 和 status。队列先后顺序表示验证工作的可行动优先级，不表示漏洞严重性、置信度或概率；`not_testable` 与 `not_reproduced` 均不等价于安全或误报。

## 首轮补证队列

### 全部 9 条 `not_reproduced`

| 原 review ID | 候选家族 | 最小补证动作 | 阻塞 / 依赖 | 建议 owner |
|---|---|---|---|---|
| CR-0219–CR-0226 | samgr，8 条同一源码文件家族；`ipc.capability.export` | 对照原始 request/run metadata 与对应源码，建立覆盖 8 个导出点的 transaction、输入、调用者权限、FD/敏感操作矩阵；确认外部主体可达后再决定是否建目标 harness。 | A0 的目标文件 coverage 为 `partial / detector_model_incomplete`；缺目标派生动态复现、调用者/权限证明。需要组件维护者提供 IPC 约束、权限策略和目标构建选项。 | A 线 IPC 验证负责人；依赖 samgr 组件维护者及隔离构建环境。 |
| CR-0335 | Wi‑Fi，`ipc.parcel.copy-range` | 将已有 source-derived reduced model 的长度/边界输入映射到同 commit 的真实 IPC stub、Parcel 与目标 buffer，核对目标编译配置后再做隔离重放。 | 有模型与 unsafe/safe 控制结果，但没有绑定产品 IPC/buffer 语义及目标构建；文件 detector coverage partial。需要 Wi‑Fi 组件维护者提供构建和调用约束。 | A 线 IPC 验证负责人；依赖 Wi‑Fi 组件维护者及隔离构建环境。 |

A0 原始扫描命令成功退出（`exit 0`、`build_profile=none`、`profile=light-ast`），但这只证明静态扫描运行完成，不是对目标候选的动态复现。samgr 的 8 条共享同一源文件/blob/SHA；先做一次家族级边界分诊，同时保留每个候选 ID 和结论。`not_reproduced` 不因缺少复现而升级为安全结论。

### 首批 5 条高风险 `not_testable`

| 原 review ID | 候选 | 最小补证动作 | 阻塞 / 依赖 | 建议 owner |
|---|---|---|---|---|
| CR-0016 | DataShare `ipc.auth.missing`，`datashare_stub.cpp:204` | 补齐该文件 detector obligation；追踪 IPC 调用端、身份及授权 guard，确认外部主体可达后再设计授权/未授权隔离对照。 | 授权契约、调用路径和 guard dominance 未建立；依赖访问控制/IPC 维护者与目标构建负责人。 | A 线 IPC 验证负责人。 |
| CR-0017–CR-0018 | DataShare `ipc.capability.export`，同文件 `:221`、`:243` | 追踪 `OpenFileInner` 权限检查以及 `CmdOpenFile` / `CmdOpenFileWithErrCode` 的 FD 创建和 reply 传输，形成身份、授权、导出链证据；仅在外部可达成立后做双主体对照。 | 权限策略、对象/FD 所有权和跨 IPC 可达性未知，缺目标 PoC；与 CR-0016 同一 source file 家族但 ID 分别保留。 | A 线 IPC 验证负责人；依赖访问控制/IPC 维护者及目标构建负责人。 |
| CR-0336 | Wi‑Fi `ipc.capability.export`，`wifi_device_mgr_stub.cpp:40` | 追踪 remote object 创建、owner、访问控制、导出和接收端敏感操作，确认边界可达后再决定是否做双主体 IPC 对照。 | 权限/对象所有权与跨端可达性未知，缺目标 PoC；依赖 Wi‑Fi 组件维护者及目标构建环境。 | A 线 IPC 验证负责人。 |
| CR-0342 | HUKS `ohcpp-shared-ptr-race-candidate-001`，`hks_ukey_async_task.h:48` | 交叉引用 `cancelled_` 全部读写、取消回调和任务生命周期，列明锁/原子保护及线程模型；确认存在同一对象未同步并发访问后再构建目标 TSan harness。 | 并发/所有权、入口与 CIA 影响未证明，目标构建/线程模型未绑定；依赖 HUKS 维护者及隔离构建环境。 | A 线并发验证负责人。 |

此 5 项属于首轮有明确、有限补证路径的工作队列。源码级补证完成前不预设候选为漏洞；通用 harness 或 parser 控制不能替代目标候选证据。

## 暂停队列与覆盖情况

其余 331 条 `not_testable` 保留在 A0 完整队列中，等待候选自身的最小调用/数据流证据、组件契约、入口与权限策略、同步/线程模型或目标构建资料。当前没有足够具体且可达的路径来设计有效目标 PoC；暂停是证据排队决定，不是安全判定。A0 目标文件 detector coverage 中另有 47 条 `not_testable` 为 `partial / detector_model_incomplete`，逐项保留该限制。

总体 coverage 对账为 56 条候选文件记录 `partial`（其中 9 条 `not_reproduced`、47 条 `not_testable`）；其余 289 条没有候选文件级 partial obligation 记录，但仍有各自尚未完成的证据门。这里的 `partial` 指 detector model 覆盖不完整，不应误读为源代码语法解析失败。

## 对账与可追溯来源

复核来源：

- A0 原始交付：`research/deliveries/a-line-sample30/20261018/evidence/candidate_reviews.json`、`evidence/provenance.json`、`evidence/reconciliation.json`、`report/technical-report.md` 及 `openharmony-a-line-sample30.xlsx`。
- 已有 T2 机器可读队列与方法：`research/deliveries/a-line-triage/20261018/queue.json`、`queue.csv`、`family_audit.json`、`README.md`、`verify_queue.py`、`reconciliation.json`。
- 已执行只读复核：`python research/deliveries/a-line-triage/20261018/verify_queue.py`。结果 `overall_ok=true`、`hash_ok=true`、`count_and_keys_ok=true`；97 个哈希清单文件缺失 0、哈希/大小不匹配 0；候选源记录 345、队列 345、唯一 candidate ID 345；来源键不匹配 0；状态计数 `not_reproduced=9`、`not_testable=336`。原交付另有 30 份样本报告、20 份含候选、10 份零候选的对账。

队列的家族审计标出 48 个重复 family key、覆盖 291 条候选；重复候选按家族协同补证，但每个原始 ID 单独保留。历史 benchmark 的仓库/提交/受影响路径直接交集为 0；共享指针并发主题与历史并发样本可能相关，但根因关系未知。全量 PoC/fuzz/调参材料的 source/commit 二级碰撞没有完整索引，因此家族泄漏状态仍为 unknown，不据此计算 Precision/Recall。

## 已知限制与下一步

A0 未为每条候选单独记录 scope；样本运行清单中的 `declared_scope=.`、`profile_id=light-ast` 仅作为样本级上下文引用，不扩展解释为候选级配置。候选级原 status、源码对象绑定和优先级均沿用 A0 记录。本状态记录不构成产品级复现或新漏洞判断，也不修改 A0 旧报告或原始候选。

下一轮先完成 CR-0219–CR-0226 的 samgr 家族边界矩阵与 CR-0335 的 Wi‑Fi 输入约束映射，再按依赖推进 5 条首批 `not_testable`。新增证据应记录精确来源对象、artifact/hash、执行环境和复核人；满足真实入口、权限边界、可控触发、敏感操作及 CIA 影响证据门后，再单独评估是否提出状态变更。
