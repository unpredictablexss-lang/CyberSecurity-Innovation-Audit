# Contacts `#include` 尾随空格解析缺口复核

日期：2026-10-19。本文记录一次对 B 线八仓报告中 Contacts partial 文件的复核，并向共享 Parser 维护者提出最小修复请求。**本轮没有修改生产解析器，也没有重跑八仓扫描；不得把探针结果写成检测器已改善。**

## 固定源码身份

- Repository：`openharmony/applications_contacts_data`
- Commit：`341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`
- Tree：`2054824c04bb403eeea128a9262edfb3001efa4f`
- File：`dataBusiness/poster/src/poster_call_stub.cpp`
- Git blob：`7cf9459f8f3b360dd85ba1587afc2a792e8a79fa`
- Source SHA-256：`da61331914d7d1f92afea3b58eff862d0b1b2f98ec102258d7807cf8798a7f50`

代码由该固定 commit 的 Git object 读取。八仓 0.12.12 报告中，这个文件是 `partial`，其中 `PosterCallStub::OnRemoteRequest` 在第 44、46 行有两条 AUTH-01 观察。它们仍是候选；不能仅凭解析修复升级结论。

## 根因探针

第 21 行为 `#include "contacts_common_event.h" `：闭引号和 LF 之间有一个 ASCII 空格。当前 Tree-sitter C++ grammar 将该 `preproc_include` 节点记成 `MISSING preproc_include_token2`；`AstIndex.parse_status` 因根节点 `has_error` 返回 `partial`，但 `parse_issues` 列表为空，所以既有报告不能指出具体错误节点。

对解析副本只把该单个尾随空格替换为 CR 字节，使这一行在解析副本中成为 CRLF。探针结果：

| 检查 | 原始字节 | 解析副本 |
|---|---:|---:|
| 文件字节数 | 1,815 | 1,815 |
| Parser 状态 | partial | complete |
| 提取函数 | 3 | 3，名称与起止行相同 |
| 提取调用 | 9 | 9 |
| LF 字节位置 | — | 保持不变 |

Git 源文件、blob、source hash 均未改。该实验说明是 Tree-sitter 对该预处理行尾空白的解析兼容问题；它不是对该 IPC 候选的安全判定，也没有证明所有此类空白都可用同一变换处理。

## 给共享 Parser 维护者的最小请求

在共同 Parser 的解析副本归一化中，针对**双引号或尖括号形式的 `#include` 行，闭合路径后恰好一个水平空格、再接 LF** 的形状，把该空格转换为 CR；不改 Git source bytes，不改报告中的 source hash，不扩展到宏形式 include、多个尾随空格、普通代码行或注释。修复归属 `src/parser/**`，超出本 B lane 的允许修改范围，所以由共享 Parser 维护者落地。

验收应包括：

1. 真实固定样本从 `partial` 变为 `complete`，且长度、LF 位置、函数/调用名称与行号保持一致。
2. 无尾随空格 include、宏 include、普通代码尾随空格和注释反例保持原行为。
3. 固定八仓同 commit/tree/scope 重跑，报告每条候选身份的增删；如果仅状态变化，应明示哪些候选解除文件级 partial 义务。
4. 重新计算证据包 manifest 与 SHA-256，并保持 source hash 与 Git blob 不变。

在共享 Parser 修复合入并完成上述复跑前，Contacts 这两个锚点仍按 `partial/unknown` 处理；本记录只提供可复核的修复依据和边界。
