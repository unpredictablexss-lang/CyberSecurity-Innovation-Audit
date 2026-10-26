# Unsafe-memory 分层复核样本框（2026-10-18）

## 当前状态

这是基于固定全扫描产物建立的**临时抽样框**，尚未完成人工复核。任务目标提供的总体数是 8,994 条；目前能核验的全扫描产物 `openharmony-abcd-full-scan-20261018-final` 含 9,323 条 `ohscanner.cpp.unsafe_memory_call` 原始观察行，差额 329 条。两者不能合并或互相替代；本样本仅用于推进 9,323 行产物的来源形状盘点，待查明 8,994 对应的扫描输入/规则版本后再锁定目标抽样总体。

该固定产物的 `run_signature` 为 `1696df82f39e2564e0821c0ad2e837a00c6d83f9276bf5e0c38a3bd1f511700b`，扫描器提交为 `0d9357ea22224b72c9756864dbd14b71a4723924`，manifest SHA-256 为 `52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55`。抽样输入 CSV 和项目规模清单的哈希见 `sampling_manifest.json`。

对账确认 9,323 行的 diagnostic ID 全部唯一，按 ID 去重减少 0 行；分析状态为 partial 9,317、analyzed 6。因此差额 329 不能由重复诊断 ID 或分析状态筛选解释，必须找回对应 8,994 的原始 run/config 或明确过滤口径。

同一 `run_signature` 的交付报告目录 `openharmony-scan-reports-20261018` 再次核对了扫描器提交、manifest SHA、run signature 和 detector 数：四项身份/数量一致，`checksums.json` 中 compact summary 和 detector summary 的哈希也匹配。该报告确认的 unsafe-memory 数同为 9,323；它没有给出 8,994 的来源。抽样生成器可通过 `--report-root` 强制执行这项交叉校验，并将结果哈希写入机器清单。

## 分层与盲审材料

从 9,323 条原始记录按 rule ID、诊断消息中的 sink callee 形状、仓库选中源码文件数四分位分层；种子为 `20261018`，固定抽取 160 条。总体按 rule 为 8,661 条 format-string 观察、662 条 unsafe memory-call 观察；样本按 rule 为 147/13。具体每层总体数、样本数、纳入概率和结果来源 hash 均在机器清单中。

全体候选的消息形状统计如下。这里的 callee 形状来自扫描器消息的结构化提取，仅用于描述触发分布，不能推导 FP/TP：

| Rule | 消息中识别的 callee 形状 | 总体 | 样本 |
|---|---|---:|---:|
| `ohcpp-format-string-candidate-002` | `fprintf` | 8,452（90.66%） | 134 |
| `ohcpp-unsafe-memory-call-candidate-001` | 消息中无法按当前模式解析 | 662（7.10%） | 13 |
| `ohcpp-format-string-candidate-002` | `printf` | 129 | 5 |
| `ohcpp-format-string-candidate-002` | `vfprintf` | 52 | 4 |
| `ohcpp-format-string-candidate-002` | `vprintf` | 23 | 3 |
| `ohcpp-format-string-candidate-002` | `syslog` | 5 | 1 |

`fprintf` 是主要候选来源形状，下一步要由盲审检查 format 参数是否动态、受控以及调用路径约束；当前仍无人工 FP 标签，不能据此收紧规则。

## 规则触发条件与待验证 FP 假设

当前实现 `src/ohscanner/detectors/cpp/unsafe_memory_call_detector.py` 对 `fprintf`、`vfprintf`、`syslog` 取第二个实参作为 format 表达式（第 154 行）；宏拼接形式会跳过（第 160 行）；其余非字面量 format 表达式会产生 CWE-134 candidate（第 168–172 行）。因此，针对 8,452 个 `fprintf` 形状的首要复核问题是：非字面量格式串是否受信任、是否来自固定配置/枚举、是否在调用前被约束，以及相关调用路径是否可由不可信输入控制。

“可信动态格式可能被报成候选”是由触发条件推导出的待验证 FP 假设；本轮尚无盲审标签证明其发生频率。不要把这个规则机理直接写成误报结论或据此全局过滤。

- `reviewer/blind_review_queue.csv`：供复核者使用；包含 repo/commit/file/line/source hash 及已校验的源码上下文，隐藏 rule、扫描消息和分析状态。
- `reviewer/review_protocol.md`：固定盲审边界、标签定义、证据记录与回交格式。
- `coordinator/review_key.csv`：协调者私有映射；包含稳定原始诊断 ID、rule、scanner message、状态和权重。人工标签冻结前不要与盲审队列一起交给复核者。
- 标签冻结后用 `research/tests/a_null_03_unsafe_memory_review/merge_review_labels.py` 校验回收 CSV 并合并私有映射；须提供回收文件 SHA-256，解盲结果只能写在 coordinator 目录下。该工具只校验完整性，不验证复核者身份或结论正确性。
- `sampling_manifest.json`：固定输入身份、分层、权重、计数口径和阻塞项。

样本 160/160 的候选源码文件 hash 与扫描诊断的 `source_sha256` 匹配。复核标签仍为空，当前人工复核数是 0；不得把 `source_bound` 当作安全/漏洞标签。

## 四类报告计数

| 计数 | 当前结果 | 口径 |
|---|---:|---|
| 原始观察行 | 9,323 | 固定 CSV 中该 detector 的逐条 diagnostics，保留每个位置。 |
| 仓内根因簇 | 未建立 | 没有经人工/程序事实验证的根因键；不能拿同文件、同规则或文本相似代替根因。 |
| 跨仓相同源码簇 | 0 | 按 rule ID + 完全相同 source SHA-256 分组，且至少跨两个仓库；这里只报告源相同簇。 |
| 人工复核结论 | 0 已复核 / 160 待复核 | 盲审结果未回收；不得以模型/扫描器输出代替人工标签。 |

源文件哈希聚类没有移除原始记录。当前产物的 9,323 行与任务目标 8,994 行总体不一致；临时样本不支持 Precision/Recall，也不授权全局过滤或降权。
