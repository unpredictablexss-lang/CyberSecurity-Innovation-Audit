# STATUS_DELTA：纯 M-gate 收口（2026-10-10）

## 已完成

- **R1 已修复**：`shared_ptr_race_native_evidence.py` 不再接受任意本地导出文件冒充 `git_object`。它校验认可的公开 Git origin、固定 commit、tree/blob 和 source SHA-256，并要求独立固定的 binding manifest/hash。
- **R2 已修复**：`shared_ptr_race_review.py` 现在从可信 `ScanContext + DetectorRun + fixture manifest + manifest hash` 重建并验证 saved evidence；顶层 evidence class、fixture category、parse_issues、finding scope、artifact 唯一性和 stale hash 均不能被替换后绕过。
- **负向回归已补**：错误 repo、错误 commit、替换内容、vulnerable/fixed 调换、伪造 manifest、混用 evidence class、清空 analyzed scope、finding 超范围、重复 artifact 等均被拒绝。
- **CI 配置已补**：`.github/workflows/ci.yml` 对 `codex/**`、`feat/**`、`experiment/**` push 也运行测试；PR 到 main 保持原有触发。
- **main 同步已完成（本地 merge candidate）**：已 fetch `origin/main` 并合入性能基线，解决文档冲突；当前 candidate 不落后于 `origin/main`。
- **本地验证**：全量 241 tests、shared-ptr targeted 17 tests、OHScanner targeted 35 tests、`py_compile` 和 `git diff --check` 均通过。

## 仍未完成 / 不得误报

- 远端 CI 尚未在最终 push head 上执行；本地测试不能替代 GitHub Actions。
- 尚未创建 PR、未标 ready、未合并 main；push、PR 和 merge 仍由项目负责人授权。
- holdout 仍是 `designed_not_executed`，不得宣称 Precision/Recall、零误报或零漏报。
- C-gate 尚未闭合：不把候选升级为 confirmed/reportable，不把 TSan harness 观测写成产品攻击链证明。
- 当前 shared_ptr 结果仍是 `candidate/unassessed`、`syntax`；`CWE-362` 为主候选类别，`CWE-416` 只能写可能后果。

## 推荐提交单位

当前 merge candidate 包含平台 M0-M2、shared_ptr detector、来源/证据校验和 holdout 隔离。负责人审查时建议拆分为：

1. OHScanner core / M0-M2 平台底座；
2. shared_ptr detector + provenance/review hardening；
3. docs/status/CI。

若保持单一 PR，也必须在 PR 描述中明确这是“平台 + 一个 scoped candidate detector”，不得把完整比赛交付物或漏洞确认混入其中。
