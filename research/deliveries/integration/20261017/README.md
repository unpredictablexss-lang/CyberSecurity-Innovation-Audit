# 负责人本地联合集成交付（2026-10-17）

## 结果与入口

本地分支 `integration/owner-unified-20261017`，路径 `/home/audit/ohscanner/worktrees/owner-unified-20261017`，共同基线 `149baf74f0094ef82e2a0e715c09b9956df2b33e`。
当前运行 http://localhost:18775 ，独立 data `/home/audit/ohscanner/parallel-20261017/owner/data`。原 18773 与负责人/A/B/UI/平台工作树未覆盖。
本轮没有 push、merge 或 Draft Ready。阶段来源/变更/代码 SHA 见 source-inventory.json；不整体合并 A/B 分支。

## 集成与审查修复

- A：7 个 C++ 检测器已注册；lifetime 0.4.0、shared_ptr_race 0.5.1、NULL 0.2.0、bounds/integer 0.2.0、resource/unsafe 0.1.0。NULL 可显式选择，默认自动扫描排除。
- A shared_ptr 远端 0.5.0 在 unlock、release、move/逃逸后仍错误提供锁信用；本地 guard 反例出现 10 个失败子用例，已向前迁入本地 0.4.1 修复并以 0.5.1 区分。未改队友目录。
- A 新规则依赖可选 finding identity 字段；契约/Runner/ToolDiagnostic 增量单独提交，legacy diagnostic ID 不变，旧报告不改写。
- A 的 39 个测试材料哈希绑定了末尾 CRLF，而实际 Git blob 为 LF。逐项验证原哈希能由 LF 末行恢复 CRLF 得到，再以 Git 字节修正 fixture/矩阵清单及固定摘要；没有改变 A 控制代码或行为预期。旧 approval.json 保留为历史记录，不给本轮授权。
- B：使用本轮期间已完成的 61e6818 提交，ArkTS/JS 0.3.1 与 JS/TS grammar 已接入；ETS 只按实际 TypeScript grammar 覆盖报告，不声称完整 ArkTS 类型语义。
- B 新 fd/mmap 规则曾将“return 位于安全分支/条件子分支”、容量覆盖、未绑定 CHECK/RETURN 宏当成拒绝证明。四个直接反例原均错误输出 0；现仅在直线同 FD 容量定义、明确越界或负容量拒绝条件、唯一直接 return、之后无未知写入/调用时抑制。宏、别名与复杂控制保留候选/unknown。IPC 0.9.3，模型 v12；两个 authored fixed/safe fixture 改成可核验的直接拒绝分支，原宏形状保留在负例中。真实 fixed 产品源码不能据旧单测推断安全。
- 平台：源码 SourceManifest/plan_audit 接入 POST /api/v1/audit-plans 和自动扫描。规划放在只读子进程（30 秒 CPU、35 秒墙钟、2 GiB 地址空间）中；任务固定明确 IDs/versions、源/计划/元数据哈希。Worker 在资源限制内重验，漂移不发布。旧显式选择客户端仍兼容。
- 页面：后端自动选择、规则计划预览、输入变化清除旧预览、计划哈希校验、任务展示计划/跳过原因；能力文字与实际 JS/TS 接入一致。
- 报告：紧凑 JSON、64 MiB 预检与原子替换。没有抬高原资源上限，也不把失败任务写成成功。

## 必须保留的失败与限制

第一次真实 core 扫描默认启用 NULL，870 文件产生 15735 条候选，其中 15731 条来自 unknown-return nullability；缩进 JSON 超过原 64 MiB 文件上限，任务 5ef6c20034dc49f88b403c4fc226ec0d 失败，无已发布 report hash。失败任务/部分文件和日志仍在独立数据目录。
这暴露的是自动启用范围和输出预算问题，不能将这些候选数称为漏洞数、误报率或检出率。NULL 已从默认自动集合移出，显式能力与控制测试保留。零候选也不是安全结论。
C/D 未默认注册，精确门槛见 admission.json。没有降低 partial 门槛、没有白名单 UID 3020、没有动态验证或新产品漏洞确认。
单扫描 Worker、单仓/2000 文件/32 MiB 总源码/1 MiB blob 限制仍在。预览是受限同步子进程调用，不是多仓队列/分片规划；页面取消旧预览只丢弃响应，后台最长受 35 秒限制。

## 实际验证

- 最终 Python：792 项，787 passed、5 skipped、退出 0；未把 skipped 当作完成。前端 16 passed，TypeScript/build/compileall 通过。
- 针对性验证覆盖：API→Worker→CLI 一致性、自动/显式规则、JS eval 控制、C/D 拒绝、NULL 显式准入、计划/版本漂移、超时无任务、同源保护、报告预算预检、A/B 守卫反例。
- 浏览器实际选择真实仓库/固定 SHA/core 范围，预览 7 项适用/424 partial，提交并看到结果。不是用示例数据替代真实源码。
- real-acceptance.json 绑定真实任务 73589d1f4aad423696ffe1ab05880917：communication_dsoftbus @ 9f922677e147b939d6db899bde181d609d64711b，tree 4b114179868d96c69eedc4520037552ddc3d65dd，870 文件/8969000 字节，446 complete/424 partial。
- Worker 53.139 秒，4 条 IPC 候选，completed_with_limitations；4 条源码摘录与报告下载 SHA 核验通过；CLI 候选、覆盖与计划一致。没有确认产品漏洞，validated_vulnerability=0。
- 真实范围未含 JS/TS，因此脚本检测器按 no_matching_language 跳过；JS 路径用独立控制通过 API/Worker 测试，不冒充真实脚本仓库验收。

运行原始日志在 `/home/audit/ohscanner/records/owner-integration-20261017`，数据库/报告在独立 data，不入 Git。Windows 交付目录 `实验记录/OHScanner负责人集成验收_2026-10-17` 保存可阅读结果和真实浏览器截图。

## 收尾时远端并行更新

A 远端在本轮期间从 c60924cb 更新至 2418b3339a06fcfd97e79e2c9313380d1147cbbb。已对比 29 个变化路径：新增 holdout、镜像快照与 IPC 输入恢复研究材料；没有修改 Detector 源码。本轮仍按固定算法来源验收，未导入这批大型研究资产，也不引用其准确率/召回率作为当前系统结论。后续可独立审查，不影响本轮固定源码静态扫描接入。
