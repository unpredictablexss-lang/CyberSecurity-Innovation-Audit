# A 线候选独立分诊队列（2026-10-19）

## 用途

本交付把 A0 30 报告抽查中的 345 条候选转换为可执行的独立验证队列，供 T3 按优先级补证。每行是一条原始候选；原始 review ID、diagnostic/candidate ID、源码绑定、状态、规则、静态复核状态、既有动态验证和未完成义务均原样保留或逐字段引用。这里的阻塞类别是工作分派，不是新漏洞结论。

## 对账

- 候选 345 条；high 283、normal 62。
- 原状态：not_testable 336、not_reproduced 9；状态没有被重新解释成误报、安全或已修复。
- 优先级：P0 = 全部 9 条 not_reproduced；P1 = 274 条 high-priority not_testable；P2 = 62 条 normal-priority not_testable。
- 规则：shared_ptr race 263；IPC relay descriptor 62；capability export 14；IPC auth (missing/guard coverage) 5；Parcel copy-range 1。
- 每行均链接候选原记录、provenance 的精确 source_check 与 sample manifest 的精确 diagnostic；345/345 的 source SHA 与绑定、blob、行号对应关系核对通过。

## 分诊规则

按原 rule family 确定主要阻塞类别和最小补证动作；按原 final_status / risk_priority 排优先级。`not_reproduced` 表示既有有限范围测试/审查没有复现，后续需要审计覆盖边界；`not_testable` 表示证据或执行条件未闭合。两者都不意味着漏洞不存在或存在。

- **shared_ptr race (263)**：逐候选闭合成员读写、生命周期、锁/原子覆盖、目标线程模型和触发条件、入口权限与 CIA 影响。Generic TSan controls 不替代目标证据。
- **IPC relay descriptor (62)**：闭合 FD/descriptor 解码、边界、dup/close、所有权、IPC caller identity 和实际影响。
- **capability export (14)**：闭合授权 guard 支配关系、旁路分支、owner/recipient 语义、调用者边界和影响。8 条原 not_reproduced 仍然是 P0 独立复核项。
- **IPC auth (5)**：闭合 Binder 入口、caller UID/PID/token、产品策略、guard/bypass 到敏感操作的完整路径。
- **Parcel copy-range (1)**：原缩减模型未发现 ASan/UBSan 问题；只按模型覆盖范围记录 not_reproduced，核验长度类型、边界检查支配关系及产品 Parcel 语义。

## 证据与复现

输入只读根目录：`D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-sample30\20261018`。SHA-256：

- `evidence/candidate_reviews.json` — `46d35eeb05e6e30e94883b4e6464683ab22f421affcb6591d0d2ff94cac890da`
- `evidence/provenance.json` — `5f50f0c9f09fdd54295fa114dc7841b1abb89cb5d4b5fe34f7b9d367c5b8746e`
- `evidence/sample_manifest.json` — `22e6f54a758684e48bc52e3acbc0e1e6ac88a74c523da42630d6fab868d38372`
- `evidence/reconciliation.json` — `2dec8af684f38a4b3c9e0c469464a13d209f8e8489dbc4aa3a65a1f69abc9cd1`
- `README.md` — `2888dcfddc86bc381211023cdeb0104f2bc5d71ae77dde6a99ef4d662fc49cda`

JSON 中的 JSON Pointer 均相对于输入文件根对象，数组下标为 0-based。CSV 为 UTF-8 with BOM，便于表格软件筛选。JSON 中 `source_binding`、`static_review_statuses`、`recorded_remaining_proof_obligations` 和 `recorded_dynamic_validation` 可供逐条复核。

本次只新增本交付目录下的队列与说明。未修改扫描器、detector、A0 JSON/Markdown/XLSX/PDF、历史 ID/verdict；未构造产品 PoC。没有独立标签集，故不报告 Precision/Recall。源绑定/引用行存在不等于漏洞确认；调用可达性、权限/所有权、并发触发和 CIA 影响仍需各行指定的独立证据。
