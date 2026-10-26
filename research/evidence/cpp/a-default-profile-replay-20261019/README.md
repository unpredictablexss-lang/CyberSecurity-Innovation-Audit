# A 线默认启用检测器集：披露 CVE 配对回放（2026-10-19）

本记录由最新 main 基线 `db77164fdc2af0da02e4d3efc056d84694fd68e8` 上的 D2 worktree 运行。`ohscan-run` CLI 要求至少一个 `--detector`，所以命令显式传入 `catalog.default_detector_ids()` 返回的全部 8 个默认启用 detector；未传 `ohscanner.known_disclosed_cves`（该规则是 opt-in）。这是真实 CLI/Runner/normalized 报告，分别复用 D2 已绑定的上游 vulnerable/fix 对象和 include 范围。

## 结果

| 样本 | Runner 总状态 | 所有 detector diagnostics | 目标规则结果 | 解析覆盖 |
|---|---|---:|---|---|
| libtiff CVE-2025-9900 vulnerable | completed_with_limitations | 1 | `integer_bounds` 1 candidate / blocked | 2/2 partial |
| libtiff exact fix | completed_with_limitations | 0 | `integer_bounds` 0 | 2/2 partial |
| curl CVE-2026-92391 vulnerable | completed_with_limitations | 16 | `resource_lifetime` 1 candidate / completed | 1/1 complete |
| curl exact fix | completed_with_limitations | 15 | `resource_lifetime` 0 | 1/1 complete |
| libpng CVE-2026-33416 vulnerable | completed_with_limitations | 2 | `resource_lifetime` 2 candidates / blocked | 4/4 partial |
| libpng exact fix | completed_with_limitations | 0 | `resource_lifetime` 0 | 4/4 partial |

curl 修复版的 15 条 diagnostics 来自其他 detector families，递归清理目标规则为 0。libpng 两侧均为 partial；修复版零候选不构成 safe 结论。libtiff 两侧也均为 partial。三组分别可用于显示候选差异，但只有 curl 对的目标规则解析完整。所有 diagnostic 均为未验证候选，未确认 OpenHarmony 产品漏洞。

## 默认启用 detector 集

`ohscanner.cpp.bounds`, `ohscanner.cpp.integer_bounds`, `ohscanner.cpp.lifetime`, `ohscanner.cpp.resource_lifetime`, `ohscanner.cpp.shared_ptr_race`, `ohscanner.cpp.unsafe_memory_call`, `ohscanner.interface.ipc`, `ohscanner.oh.arkts_js`。

完整 JSON/Markdown 每次结果保存在本目录；清单记录 JSON 报告 SHA-256、源 snapshot SHA-256、解析状态和各 detector 版本/状态。D2 具体源身份及精确 CVE 修复证据见 `../d2-disclosed-vulnerability-regression.md`。此回放证明三个规则已通过 A 线默认启用检测器选择集的 CLI 路径运行；它不把所有报告提升成完整覆盖。opt-in known-disclosed 规则与 D1 path detector 的 default admission 仍要由 shared owner 在 I1 评估。
