# UI V4.1 最小公共接线申请

来源基线：6a41dc9b1aa030158e09be6241e2b14341f9256d。UI 线文件范围遵循 ownership.json。

已提供 `web/src/features/workbench/WorkbenchApp.tsx`，集中封装蓝白/MiSans 主题、V4.1 导航、旧路由适配和现有页面。
公共层只需将 web/src/main.tsx 的本地 App/ConfigProvider 替换为导入并渲染 WorkbenchApp；
不改 api.ts、components.tsx、API/SQLite、Detector Catalog、源扫描协议或旧候选身份。

接线由集成人在独立 integration worktree 落地，不在 UI 交付分支越界改 main.tsx。
新 feature 内保留 /new、/repositories、/cases、/capabilities 的兼容映射及 /tasks/:id、/operations。
只有现有实际可执行 API 参与表单；多仓/官方清单、自动按源码适用规划、真正增量与 LLM 不冒充已实现。
普通页面提交所有服务端已批准研究规则，不硬编码 ID；执行记录仍由服务端冻结。
后续平台 RuleExecutionPlan 接入时替换该请求准备层，不把目前的 UI 自动准备称为后端适用计划。

需集成验证：真实浏览器三入口、分组点击不导航、旧深链/历史报告、表单提交到 Worker/报告、
日期预览失效、仓库 Ref 切换、跨分支/版本矩阵、运行中取消、候选分组/源码/复核、导出、窄屏。
GitHub CI 尚未运行，未 push/merge/Ready。验收记录在本机 records/ui-line-20261017。
