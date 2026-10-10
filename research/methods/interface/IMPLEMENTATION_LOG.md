# IPC v0.1 执行记录
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

基底：2026-10-10 fetch，B 分支 dcd9629 快进至 origin/feat/ohscanner-core 3b437e4；未改队长工作树、未推送。

1. [x] 读取用户两份 E 盘文档、AGENTS、架构、当前状态、契约和接入指南。
2. [x] 39 条公告机器索引与官方固定来源，按根因去重共用 PR。
3. [x] 12 个 S2 修复对、1 个 S1 混合补丁，98 文件源码/blob 哈希验证；余项留 S1，不伪造根因。
4. [x] Semgrep OSS native、Joern、CodeQL、Clang 安装与适用配置实验，保留未知/失败。
5. [x] 六家族有限路径解释检测器；独立插件、证据义务，不改公共 CLI/schema/catalog。
6. [x] 29 设计场景、13 冻结后生成变体、消融、218 项全项目测试；94 文件×3压力轮次完成。独立历史留出实验尚未完成。
7. [x] 逐例 JSON/CSV、MD、Excel、复现脚本与接入说明；生成工件不入提交。

方法卡：IPC_METHOD_CARD.md。完整结果：docs/research/ipc_scanner_v0_1_2026-10-10.md。
大型源码/工具/数据库/原始日志：/home/audit/openharmony-audit/ipc-research。
E 盘说明副本：实验记录/IPC_v0.1_2026-10-10。

不能声称覆盖大部分历史漏洞：12组为开发集，7组解析 partial/unknown，S3=0；13生成变体中1个安全UID场景误报。其余官方种子需要独立根因复核与锁模后盲测。

2026-10-10 补全：逐步输入/命令/输出/结论与记录缺口见 docs/research/ipc_scanner_v0_1_process_trace_2026-10-10.md。原始工件与旧交付校验保留；未进行最新社区源码扫描。
