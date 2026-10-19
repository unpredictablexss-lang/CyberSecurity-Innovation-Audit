# UI 第一线交付与验收（2026-10-17）

本轮完成现有后端能力上的 V4.1 工作台与前端第一阶段验收，可以交本地集成复审。
没有重新建立仓库，没有迁入 A/B 整条分支，没有推送、合并 main 或把 Draft 标 Ready。
这不是完整 PRD 后端能力验收，也不是产品漏洞确认。

## 源码与运行位置

- 共同基线：`6a41dc9b1aa030158e09be6241e2b14341f9256d`。
- UI 自有代码：`work/ui-20261017@478123175fef6b6d0219eb8b433021c375e86cd1`，目录 `/home/audit/ohscanner/worktrees/parallel-ui-20261017`。
- 已接全局入口的代码：`integration/parallel-baseline-20261017@d23741efaa87cdfb3bb37a4a37353a80716d6ca8`，目录 `/home/audit/ohscanner/worktrees/parallel-integration-20261017`。
- `main.tsx` 的最小接线由集成人单独提交 `310976ca856ab437cd487bab4cad99ff3fc870c9`，对应 [接口申请](../integration-request.md)。UI 自有分支没有越界改公共文件。
- 实际预览：[工作台](http://localhost:18773/#/overview)，只监听 loopback；独立数据 `/home/audit/ohscanner/parallel-20261017/ui/data`。
- 当前预览直接从 integration 源码及其构建目录启动，使用 UI 隔离数据。早期曾将 integration 的 dist 复制到 UI 目录验收；最终已取消该运行依赖。
- 重启：在 WSL 执行 `bash /home/audit/ohscanner/parallel-20261017/ui/start-reviewed.sh`。重建先在 integration 的 `web/` 使用已配 Node 执行 `npm run build`。
- UI 原 `start.sh` 仍保留其分支隔离规则；只在 UI 分支重建将得到未接新全局入口的壳层，评审完整版应使用上述 integration 启动脚本。未放宽 ownership.json 或原始范围基线。

## 需求与实现对照

依据 `research/product/20261017/OHScanner_PRD.md` 的流程、HTML 的蓝白视觉与本地 MiSans 字体栈，复用现有 API；材料中的目标不作为已实现事实。

| 需求 | 实际实现及验证 | 边界 |
|---|---|---|
| 新建审计只作分组 | `WorkbenchApp` 展开菜单不导航，3 个直接表单；桌面与窄屏点击验证 | 无额外中间首页 |
| 仓库安全扫描 | `RepositoryAudit` 登记仓库/ref/scope/预算 → Worker → 固定源码报告 | 仅已登记单仓；官方身份待核验 |
| 普通用户不挑 Detector | 从 `/detectors` 的批准研究元数据自动准备规则；排除 example/unapproved，单测覆盖 | 当前提交全部已批准研究规则，不冒充按语言/范围执行计划 |
| 时间增量入口 | committer-date、明确时区、7/15/30 天快捷范围、预览、固定两端比较 | 端点扫描，非逐提交完整增量引擎；快捷时区算法单测、日期自定义浏览器提交 |
| 仓库/Ref 与日期变更 | 切仓清空 Ref 与预览，日期变化清预览，过期异步响应不覆盖当前状态 | 入队时重新解析 Ref；预览不是移动分支的冻结凭证 |
| 跨版本安全分析 | 分支/Tag/完整 SHA 比较；实际 Worker 完成并显示哈希 | 候选消失仍不自动等于修复 |
| 影响与修复 | 关联案例、2–8 唯一完整 SHA 矩阵；剥离 UI 辅助字段 | 只记录观察；补丁生成/应用/产品重验未接入 |
| 任务中心 | 扫描与操作队列、原任务深链、详情/覆盖/报告、运行取消 | 单扫描 Worker；取消的未分析内容仍 unknown |
| 风险中心 | 默认候选分组，可展开原始候选、固定源码、义务、复核/源码摘录 | 聚类不推断根因、不升级结论 |
| 候选进入后续流程 | 实际候选携带 job/candidate/repo 上下文进入调查/版本/PoC | 只预填来源；不会自动运行或认为 Harness 适用 |
| 编辑与异步刷新 | 保存源码证据保留复核草稿；旧详情不能换新选中项；后台新增报告不抢风险来源 | 复核仍用现有 expected_id 冲突检测 |
| 智能调查 | 人工案例与固定只读步骤，实际生成 trace、剩余义务 | model_called=false；真实模型未连接 |
| PoC 验证 | 已注册 AUTH-01 Harness 入口、前置目标/案例校验、不可用时禁用提交 | 本轮未运行 Docker，不是通用 PoC 或产品漏洞确认 |
| 报告中心 | 实际 scan JSON/MD/manifest 和案例 JSON/MD 下载，5 个浏览器下载核对 | 无虚构 PDF/模型评分/漏洞数 |
| 系统设置 | 已登记源码、显式同步、研究规则、真实 API/Worker/模型状态 | 没有假配置保存或扩容按钮 |
| 旧页面兼容 | `/new`、`/repositories`、`/cases`、`/capabilities` 映射；`/tasks/:id`、`/operations` 保留 | 三份旧 schema 报告只读，不改候选 ID/历史结论 |
| 窄屏 | 390×844 下总览/扫描/日期/矩阵 document 宽=scroll 宽=375（滚动条占宽） | 表格内部可横向滚动；浏览器尺寸覆盖已恢复 |

组件位于 `web/src/features/audits/` 与 `web/src/features/workbench/`，旧页面入口薄封装保留。
全局公共改动只有 integration 中的入口接线及本轮文档同步；API、Catalog、Runner、Store、协议、依赖文件未由 UI 改动。

## 浏览器实测与可追溯记录

全部写操作使用独立合成 Git 仓库与 SQLite。样例名称中包含 openharmony 不证明官方身份，更不证明产品漏洞。
固定基线 `a642c90aabddfff92227026aa11478ee6cc6cf77`，控制修订 `b7188ab04dac466620281dea8a07e649cb9ea34c`。

- 扫描 `d754c5be742c4dba928e9cdf24636c3f`：固定源码、1 条 CWE-416 candidate、4 项 unknown 义务；创建案例 `e701adadcd82455f89ece3eba15527aa`。
- 日期比较 `e698ccbded0647fca149e793e1608e91`；查看旧详情后再建 `40f219c26e3b42bdaaab727f9e633c95`，新详情不被旧响应覆盖。
- 跨分支 `ba9501bbb4434a49a068ad15d17dafef`；矩阵 `0dd656d2d6dd42a395c16c63d04201ef`，均 completed_with_limitations，影响 unknown。
- 只读调查 `0409f3a410b64b678562f2b4bd649f71` completed，model_called=false。
- 运行取消 `6666205f3a1b413b83509e4ec6d2fd1f`：先确认 running，再点取消，2.96s 后 cancelled；保留 incomplete analysis remains unknown。首次控制 `31f942f321c24871a5d4dd44f8a46563` 已在点击前完成，不计取消通过。
- 来源证据保存 2 条、追加复核 1 条；保存第二条摘录时正在填写的复核人/草稿不丢失，随后正常提交。
- 后台新增报告探针 `d39856b3d6cb47d6a978c2849cb50ac5` 由 API 创建，浏览器确认风险来源仍停留当前任务；这项不冒充浏览器表单提交。
- 实际下载 5 个文件，校验哈希/固定 commit/案例包含 2 条源码证据和 1 条复核，validated_vulnerability=0。完整哈希见 acceptance.json 及本机 download-verification.json。
- 从 UI 目录临时静态包预览切换为 integration 源码直接运行后，健康状态 ok、扫描 Worker 运行、记录仍能读取；18775 历史只读副本服务已停止。

完整本机日志、操作/任务结果、下载与保护快照：`/home/audit/ohscanner/records/ui-line-20261017`；大文件、数据库、第三方源码不入 Git。
Windows 可读截图在 `E:/读研/网络安全创新大赛/实验记录/` 的 `OHScanner_UI第一线_总览_2026-10-17.jpg` 与 `OHScanner_UI第一线_窄屏_2026-10-17.jpg`。

## 修复的问题与最终验证

本轮浏览器暴露并修复：原生日期输入显示与 Form 值不同步、多个操作 Form 的 DOM id 冲突、保存摘录清空复核草稿、
后台新任务抢走正在复核的风险来源、窄屏表格撑宽整页。操作详情异步选中保护沿用并回归。

- `cd web && npm test`：14 passed / 0 failed；`npm run build`：TypeScript 与生产打包通过。
- `.venv-web/bin/python -m unittest discover -s tests -v`：523 总计，519 passed / 4 skipped / 0 failed，41.210s。
  运行代码为 `5f2708c369a4f4b643a39330f3529a91b153f870`；之后唯一代码改动是窄屏 CSS，已重新构建并在浏览器验证，后端/测试未变。
- 4 skip：两项缺历史保留源码；两项按设计禁止宿主直接跑 AUTH-01，只允许 Docker Worker。未当作通过或漏洞证据。
- 原不可变基线的 UI scope check 及 `git diff --check` 通过；最末文档提交后再复查范围，结果写本机 final-checks。
- 本轮没有重复安装依赖；各自 npm ci/独立环境验收记录属共同基线准备阶段。本轮没有远端 CI。

## 历史兼容计数勘误与工作区保护

`records/parallel-20261017/historical-compatibility.json` 旧验收脚本的 finding_count=2 曾计算 JSON 响应对象键数，不能当候选数。
本轮逐份按 total 与 items 回读：`a4eb6e1a203a4ae6834eb7797cfebf90` 为 0；`59232be9012943d7994286718f26e134` 为 2；`d36c780d0262441c834df4c0fe4723e2` 为 0。
中间两条仍为 candidate/unassessed；历史原报告、IDs、review/source_evidence 不重写。
更正附加在 `historical-compatibility-erratum.json`，未覆盖原历史证据。

负责人原工作区 HEAD、dirty 列表、最初未提交文件哈希全部一致；原 B 的 HEAD/dirty/文件哈希也一致。
并行 cpp 线期间自行从共同基线前进到 `91e6291242c6917fdef7cf732f80b3860c836ebe`，本轮未写入、合并或回退它；其测试结论不属于本 UI 验收。
本地 main 仍为 `e510c99c67f31ec6c73365f9ab749c79ca6ff0a1`。

## 下一步的真实依赖

优先让平台线提供可审计的官方源码目录/身份与语言-范围 RuleExecutionPlan，再由集成人接公共 API、UI 替换请求准备层。
随后才是多仓编排、完整增量与真实模型工具型调查、标准 Docker Worker、补丁与产品证据闭环。
本 UI 交付不阻塞这些线并行推进；也不把占位状态当已完成能力。
validated_vulnerability 仍为 0；candidate/unknown、组件 Harness 与产品漏洞始终分开记录。
