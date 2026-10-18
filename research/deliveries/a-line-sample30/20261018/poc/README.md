# PoC 索引

本轮 30 份抽样报告共复核 345 条候选，0 条通过 `confirmed/reportable` 完整证据门，因此确认漏洞数为 0，专用 PoC 数为 0。

`evidence\\sandbox\\method_controls` 中的 copy-range 缩约模型、ASan/UBSan 阳性/安全控制和 generic shared_ptr TSan 控制仅用于验证方法与工具链，不对应任何抽样组件的漏洞证明，也不放入 `poc\\<finding-id>\\`。

当且仅当真实入口/权限边界、可达敏感操作、可控触发条件和具体 CIA 影响同时成立时，才应创建独立 PoC 目录并加入本索引。
