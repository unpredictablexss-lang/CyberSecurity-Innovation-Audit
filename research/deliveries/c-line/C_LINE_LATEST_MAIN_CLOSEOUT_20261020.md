# C 线最新 Mainline 快速收尾结果（2026-10-20）

## 结果

C 线已验收的 Ark Runtime 静态集成变更已接到本轮 fetch 的最新主线。合并没有冲突；上游 D 线状态与证据文件保持为 `origin/main` 中的原始 blobs。

| 项目 | 结果 |
|---|---|
| 最新主线 | `c380a474718e8ec4497aff55b18a1dd38bafa13f` |
| 集成代码提交 | `4e1268a980fd103326c7dbaa6ca2e78d2ba43e69` |
| 集成代码 tree | `0495b0db7d05f02e2ce4e48149f7571c8bdd8023` |
| 父提交 | `c380a474718e8ec4497aff55b18a1dd38bafa13f` + `764f7698f6babdcccb2cd68eba75ed1b0afefc9e` |
| 开发验证报告提交 | `c1f34e97326a61d68bc79282d782a3df37e128c9` |
| 独立测试报告提交 | `0b7ab8baf1e09e151dd88a0694da62cb49e1f906` |

## 开发与独立测试闭环

开发线在最新 main 集成代码上执行 Ark Runtime 212 项（209 passed、3 skipped），source-binding/Catalog/Parser/Runner 回归 59 项（58 passed、1 skipped），以及排除 Windows symlink 权限用例后的契约测试 19/19。独立测试线在隔离 checkout 对精确代码提交 `4e1268a980fd103326c7dbaa6ca2e78d2ba43e69` 重放：Ark Runtime 212 项通过、3 项跳过；source-binding、Runner、Catalog、契约、audit plan、known case、parser 和 detector regressions 共 97 项通过、1 项跳过；`git diff --check` 通过。测试线未发现生产代码或测试失败，因此没有额外代码反馈需要回传。

三项 Ark Runtime skip 的原因已记录：两个依赖的 pinned 历史 Ark Git store 未提供；一个仓库绑定 parser-owner 用例未配置 `OHSCANNER_ARK_REPO`。Windows 全契约测试中的 symlink 用例因 `WinError 1314` 被系统拒绝创建符号链接；可运行的其余契约测试通过。这些状态保留为 skip/环境限制。

## 结论边界与后续触发条件

集成保持 Ark Runtime `0.6.3` / model `0.8.14`、显式选择、默认关闭和精确 source-bound 限制。Float32Array 与条件性 `TypedArray.set` 仍为源码候选。产品运行时和 Ark VM 执行 `not_run`；产品适用性、入口与影响 `unknown`；没有计算正式 Precision/Recall，也没有确认产品漏洞。

本轮 C 线代码集成/独立回归达到 `CLOSEOUT_READY_WITH_LIMITATIONS`。后续只在出现具体 source/preprocessor 配置、可用 runtime 构建、可复现测试缺陷或其他新证据时，按开发→独立测试反馈循环开启相应切片；unknown/not_run 按现有状态保留，不反复重审相同证据。

## 复验报告

- 开发与最新主线集成：[C_LINE_MAINLINE_INTEGRATION_20261020.md](../../../../c-mainline-dev-closeout-20261020/research/deliveries/c-line/C_LINE_MAINLINE_INTEGRATION_20261020.md)
- 精确 SHA 独立复验：[C_LINE_MAINLINE_TEST_20261020.md](../../../../c-mainline-test-closeout-20261020/research/deliveries/c-line/C_LINE_MAINLINE_TEST_20261020.md)
