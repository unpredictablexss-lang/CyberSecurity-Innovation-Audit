# AC 线并行扫描器优化与集成报告

日期：2026-10-19（Asia/Shanghai）。

## 1. 结论

- 第三次显式 `git fetch --prune origin` 成功；当前主 checkout `codex/full-runtime-performance-audit-20261014` 仍为 `0f8e6403095ea0fd8d6c8ac41a4789299915d139`，dirty/untracked 产物未覆盖。
- `源码漏洞审查记录_20261018.md` 在同步后的 checkout、全部本地提交树、父目录和 pinned objects 中仍不存在。A 线 sample30 technical report、C3/C4/C7/C8 记录只能作为 substitute evidence，不能声称已审查缺失原文。
- A 线已确认的 `ohscanner-contacts-path-traversal-001` 原先不是扫描器直接命中；远端 `ohscanner.cpp.path_traversal` 0.1.0-research 也只对 `open` 产生候选，真实删除 sink `fileUtils.DeleteFile(srcFilePath)` 仍为 unknown。
- 本轮补强精确 member sink `fileUtils.DeleteFile(path)` 后，`contacts_exact_excerpt.cpp` 直接产生 3 个 `symbol=DeleteFile` candidate；fixed basename/canonical containment/literal allowlist 为 0 finding，no-source/unrelated 不误报，unknown receiver/multi-arg/unknown static fail-closed。
- Detector 已以 `research_candidate` 注册 Catalog 并默认纳入普通扫描覆盖；这只增加 candidate 覆盖，不改变证据等级。scanner finding 仍为 `candidate/unassessed`、`validated_vulnerability=0`；不把 sample30 的人工/PoC 确认状态复制到诊断上。
- C 线 Ark Runtime 0.7.0 本地控制可运行，但历史 vulnerable/fixed replay 仍因 frozen implementation、历史 commit/tree 和 creator dependency 缺失而 blocked；两个 holdout packet 没有独立标签，`eligible_for_metrics=false`。

## 2. 代码与公共变更

集成分支：`codex/ac-path-deletefile-integration-20261019`。

- `73edbc0283f99aa6711029a61a17093f84ef091f`：算法修复，补 `DeleteFile` reviewed member sink 和 11 项 focused controls。
- `fd64eb63d6ae60814b54966d9206de83946ed2e5`：独立公共 Catalog/Runner 集成，5 项兼容性测试。
- `271565810d489e934fc426b357431158d4609f03`：EOF whitespace cleanup。
- `2e515c61669486396c5cf5740cbec24dabaa3454`：将 path traversal research candidate 纳入默认覆盖，仍保持 candidate/unassessed。

公共 contracts/schema/历史 finding ID 未修改。legacy v1 保持只读/unbound；source-bound v2 仍绑定 repo/commit/snapshot/profile/detector/rule/source SHA，partial identity 不伪造 stable ID。

## 3. 实际验证

环境：

```text
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
PYTHONPATH=.;E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps
```

- Focused path + Catalog：16 tests / 16 passed / 0 skipped / 0 failed。
- Compatibility：75 tests / 72 passed / 3 Windows environment errors。两项 symlink 创建受 WinError 1314 权限限制；一项 UTF-8 JSON 被系统 GBK 解码失败。schema v2、legacy v1、Catalog、Runner applicability 均通过。
- Target `compileall`：passed。
- `git diff --check`：passed。
- C8 Ark Runtime sibling 独立复跑：116 tests / 8 skipped / 0 failed。
- Path 11-test measured run：wall 0.1746341s，peak RSS 27,897,856 bytes。
- 完整 `tests/detectors` 广度基线仍有 4 failures/3 errors，均为 Windows CRLF/LF 导致旧 fixture byte length/SHA mismatch，另有 `A-NULL-01` manifest 和 shared_ptr source hash 偏差；本轮未重写旧哈希，不计算法通过或失败。

## 4. C 线证据状态

- C3 六个 type-origin counterexamples：source SHA 6/6 对账一致，但历史 replay `blocked_not_replayed`。
- C4 exception-guard 四条不在 pinned TypeSafety 0.3.1 replay 覆盖范围。
- C7 missing-object fail-closed 行为满足，但原始 dependency/replay ledger 缺失。
- pinned `hash-manifest.json` 有两项 declared/actual 不一致，已作为 provenance defect 保留。
- runtime-core 20 项、ets-frontend 21 项标签均为空；reviewer identity/confidence/timing/disagreement/adjudication 不完整。
- 不计算 Precision/Recall、TP/FP/FN/TN，不声称零 FP/FN、产品 CIA/CVE 或 confirmed。

## 5. 证据入口

- 总计划与结构化 vibe prompts：`research/coordination/ac-line-parallel-20261019/AC_LINE_TASK_TREE_AND_VIBE_PROMPTS.md`。
- Path acceptance：`artifacts/path/deletefile_acceptance_report.md`、`deletefile_acceptance.patch`、`acceptance_hashes.json`。
- C replay audit：`artifacts/replay/`。
- Holdout gap matrix：`artifacts/holdout/`。
- Source-audit fail-closed importer：`artifacts/audit/`。
- 三个集成 patch：`patches/`。

## 6. 下一持续任务

1. 在 Linux/无 CRLF 转换的干净 checkout 重跑 path、Catalog、全量 C++ 与 schema 兼容套件，消除 symlink/编码/换行环境偏差。
2. 补 CLI/API/profile 的默认 research candidate 执行验收，确认普通扫描实际包含 path traversal 且不改变 candidate/unassessed。
3. 恢复 `源码漏洞审查记录_20261018.md` 后运行 `reconcile.py --refresh-input-manifest --write-run-manifest`，再 strict 对账全部原文条目。
4. 补齐 Ark frozen 0.3.1/0.7.0 implementation、历史 commit/tree、creator dependency 后执行 parent/fix/safe/unrelated replay；缺对象继续 blocked/unknown。
5. 完成独立盲评、分歧裁决、active/paused timing 和可靠 truth；此前保持 `eligible_for_metrics=false`。
6. 跨文件 wrapper、宏、overload、权限支配和产品入口/CIA/PoC/修复/CVE 作为独立证据任务，不与局部 candidate 混写。
