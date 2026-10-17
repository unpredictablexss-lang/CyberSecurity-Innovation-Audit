# C3：局部证据准入 RFC 补充

冻结算法：`4ea5f4020884aed5860a88d50f5a926610e7b98a`；Detector/model `0.2.0`。状态：交负责人审议，未获生产 partial 准入。
保留 C2 `PARTIAL_ADMISSION_RFC.md` 原文及历史报告，不改公共 Runner/Catalog/contracts/API/DB/UI。

## 已提供的局部事实

`C3_SOURCE_EVIDENCE.json` 绑定 repo/commit/tree/blob/source SHA；`C3_CENSUS.json` 绑定每个函数的限定名、参数、字节/行区间、子树解析状态与整文件错误区间。`C3_RUN_MANIFEST.json` 绑定 detector/model/parser/build profile/预算与实现哈希。观察带实际 symbol、精确 region、符号路径、约束及未闭合副作用点。文件整体 partial 不变；这些研究数据没有私自增加公共契约字段。

## 控制与结果

- 目标函数内部错误：C11 与 IR 解析控制拒绝给出候选，保持 not_analyzed/unknown。
- 相关类型声明：同名模型类型/别名拒绝；可写引用、指针及未审查构造均阻塞证明。完整宏展开、错误声明对跨 TU 依赖的污染仍无法排除，所以真实 partial 不获生产准入。
- 模型宏与可见函数覆盖：Int32Equal 等宏重定义、creator/type homonym、可见未审查类型 helper 定义均拒绝，不靠同名匹配。
- 跨文件摘要：研究 replay 在两个固定 tree 中逐一核对 12 个摘要 blob OID，缺失/不匹配抛错，不使用旧摘要继续出结论；这项检查不是普通 SourceUnit 生产入口的跨文件绑定能力，相关公共事实仍需负责人设计。
- complete + partial 混扫：既有 `test_mixed_scope_retains_valid_complete_file_candidate` 实际保留完整文件候选，同时 partial 文件仍 not_analyzed；不把聚合 blocked 当丢弃有效证据的理由。
- 来源/版本变化：源码正文 hash 篡改被拒绝；模型 digest 覆盖版本、caller profiles、摘要 OID、按值策略和 build profile。冻结 holdout 检查实现 Git 字节一致；未知 build profile 不分析。尚无公共跨运行模型事实缓存，未声称完成此类缓存失效能力。
- 超预算：当前函数未完成观察丢弃，先前完整函数证据保留，新增回归覆盖该情形；partial/limited 状态和预算原因独立保留。
- 未知图边与局部有效路径：有效局部 candidate 可与 unknown 并存；候选路径是符号 witness，仍需可满足性与产品入口证据。

## 请求公共层后续评审

需要负责人统一定义局部准入能力：区域范围、错误/依赖污染、摘要签名和实际构建身份、有效/未知/未分析区域，以及聚合状态与局部证据保留。若新增字段，应独立协议变更并验证 v1 读取、v2 来源绑定和旧报告/ID/review 不变。

拒绝把“函数子树无错误”升级为“翻译单元完整”；拒绝按 detector ID 绕过 required facts。当前保持 `required_facts=('ast',)` / per_file，未注册 Catalog；生产真实双版本仍 blocked。更广摘要、跨过程类型/别名事实和真正的生成图 SSA 也是接口需求，不在本轮擅自接入。
