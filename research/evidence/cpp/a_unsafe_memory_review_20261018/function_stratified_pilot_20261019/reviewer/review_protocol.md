# Unsafe-memory 独立盲审协议

## 盲审边界

复核者只使用 `blind_review_queue.csv`、对应固定 commit 的源码和本协议。标签提交并冻结前，不查看 `coordinator/review_key.csv`、扫描器消息、rule ID、分层权重或开发者预期。复核者不得通过 sample ID 查询扫描器输出。协调者应在回收后记录提交文件 SHA-256，再解盲合并。

开始前验证队列记录的 `source_sha256` 与固定 commit 下源文件一致；hash 不符或仓库 commit 无法取得时，不推测结论，标为 `not_testable` 并说明原因。`source_context` 是定位辅助，判定应查看完整函数与必要的调用/定义上下文。

## 逐条检查

1. 确认固定版本中该位置实际存在相关 API 调用，并识别各实参、长度/边界、格式串或目标缓冲区的来源。
2. 沿当前函数和调用点追踪值来源、校验/约束、错误处理、早返回、短路条件、重新赋值及跨函数传参。没有编译参数、宏展开或调用者证据时，将缺失项记入理由，不能假设其安全或可控。
3. 记录能支持标签的源码路径和行号。若无法仅凭源码确认外部输入可达性，仍可报告 API 契约是否违反，但将攻击者控制/产品可达性明确写为 unknown；不要把“确认有候选”写成“确认可利用”。
4. 以一个独立标签完成每行。不要删除行、合并行或改动 sample ID；对争议项保留 `unknown`，后续可安排第二位复核者。

## 标签

| `reviewer_disposition` | 使用条件 |
|---|---|
| `confirmed` | 固定源码中存在该问题形状，且证据显示调用违反相应 API/参数约束。另在理由中说明外部输入控制和敏感路径是否已证实；此标签本身不代表漏洞可利用或产品影响已确认。 |
| `not_reproduced` | 固定 commit 与记录位置可核验，但无法复现被描述的调用/参数形状，或证据绑定存在具体不一致。说明差异。 |
| `not_testable` | 缺少必要构建宏、调用者、依赖实现、运行约束等证据，无法做有依据的判断。指出缺少的具体对象。 |
| `safe_or_fixed` | 调用形状存在，但可由可核验的校验、范围约束、常量来源或控制流证明该路径安全/修复有效。写出证明位置和控制条件。 |
| `known_false_positive` | 规则形状与真实语义不符，例如 API/参数角色不同或被误认作危险调用。写出实际语义和依据。 |
| `unknown` | 证据相互矛盾或不足以落入以上标签。说明仍未知的事实；不要用它代替 `not_testable` 的明确环境缺失。 |

`confidence` 只填 `high`、`medium`、`low`；它表示对所选标签的把握，不是漏洞严重度。`reviewer_rationale` 至少写明观察到的操作、数据来源/约束、控制路径与 remaining unknown。`evidence_reference` 使用 `path:line` 或构建/契约文档引用。

## 交回格式

保留所有原列和所有 160 个 sample ID，只填写 `reviewer_disposition`、`reviewer_rationale`、`evidence_reference`、`confidence`、`reviewer_id`。不重排、不去重、不回填协调者字段。提交时附上完成队列的 SHA-256、复核者 ID、日期和无法检查的仓库/样本清单。标签冻结后由协调者用 sample ID 与私有 review key 合并，再按抽样权重汇总；原始观察行及位置必须保留。

仓库提供 `research/tests/a_null_03_unsafe_memory_review/merge_review_labels.py` 执行合并校验。调用时必须传入冻结提交的 SHA-256；工具会核对样本 ID 集合、不可变源码字段、标签完整性、纳入概率，并把含扫描器映射的结果限制写入 coordinator 目录。该工具不验证复核者身份或标签正确性。
