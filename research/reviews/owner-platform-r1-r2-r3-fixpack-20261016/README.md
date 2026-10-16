# R1/R2/R3 独立修复包

本包在独立 worktree `E:\网安\CyberSecurity-Innovation-Audit-fixpack-20261016` 中准备，不覆盖原工作区、A/B 工作区，不改公共契约，不合并 `main`，不标记 Draft Ready。基线 checkout 为 `8e97f152ef747c1e1d21ae179a048910f147e07a`；负责人审查快照 `2146c229e00e63c4464da85f46fde303019fbeaa` 在本机不是 Git object，不能伪装成已针对该 SHA 重跑。

## 独立提交

| 修复 | 提交 | 范围 |
|---|---|---|
| R1 | `8620592e6250dad0a2b99139a0488dc45c8b1058` | `.github/workflows/ci.yml`、`tests/ui/test_served_ui.py` |
| R2 | `35bffbb5fa621b6286452a1a3fb7efa30aed3323` | `web/src/pages/Operations.tsx`、handler/browser 回归、`web/package.json`、独立 CI job |
| R3 | `0b8faea14325fb0c687a345127ab7444c939d8ff` | `docs/项目现状与下一步.md`、`docs/面板功能与验收.md` |

独立补丁位于 `patches/`，可单独或组合迁入。R2 使用 `0002-fix-workbench-guard-stale-operation-detail-responses-independent.patch`，不依赖 R1 的 CI job 改名；三份补丁对基线 index 的独立 `git apply --check --cached` 均通过，见 `logs/patches-apply-check.log`。

## Exact commands

### R1

干净环境失败（没有 `web/dist/index.html`）：

```text
test ! -e web/dist/index.html
/tmp/ohscanner-r123-venv/bin/python -m unittest discover -s tests/ui -p 'test_*.py' -v
```

结果：`AssertionError: 404 != 200`，日志 `logs/r1-clean-before.log`。

修复后构建和首页依赖测试：

```text
pnpm dlx npm@10 ci
pnpm dlx npm@10 run build
test -f web/dist/index.html
find web/dist -maxdepth 2 -type f -print | sort
/tmp/ohscanner-r123-venv/bin/python -m unittest discover -s tests/ui -p 'test_*.py' -v
```

CI 中展示的实际命令是 `npm ci`、`npm run build`、产物路径检查和 `python -m unittest discover -s tests/ui -p 'test_*.py' -v`；本机因 PATH 没有 `npm`，使用 `pnpm dlx npm@10` 调用 npm 10.9.9，完整日志为 `r1-npm-ci.log`、`r1-web-build.log`、`r1-artifacts.log`、`r1-after.log`。

### R2

handler 回归前（实际 `Operations.tsx` handler，mock hooks/API，不是浏览器）：

```text
node web/tests/operations-handler.test.mjs
```

结果：`selection_writes=["new-operation","old-operation"]`，断言失败，日志 `r2-handler-before.log`。

修复后：

```text
pnpm dlx npm@10 run test:operations-handler
```

结果：`selection_writes=["new-operation","new-operation"]`，旧详情响应不再覆盖新选择；日志 `r2-handler-after.log`、`r2-handler-after-npm.log`。

真实浏览器回归（Windows Edge + WSL FastAPI，真实本地 API；旧详情响应只做2500ms网络延迟，不替换响应，不是 mock 回放）：

```text
PLAYWRIGHT_CORE_PATH=C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\node_modules\playwright-core
BROWSER_EXECUTABLE=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
OHSCANNER_BROWSER_BASE_URL=http://127.0.0.1:8876
OLD_DETAIL_DELAY_MS=2500
node web/tests/operations-selection.browser.mjs
```

修复后通过：`r2-browser-after.json`、`r2-browser-after.log`、`r2-browser-after.png`。该测试真实打开旧详情、创建新任务并检查详情 ID；旧详情请求仍真实访问 FastAPI。修复前的 `r2-browser-before.json` 仅作尝试记录，因 React 批处理没有稳定呈现瞬时 setter 覆盖，不作为 R2 失败证明；可复核的失败证据是 handler 回归和既有 `research/reviews/owner-platform-review-20261016/handler-replay-result.json`。

### R3

两份文档均引用原始 unittest 输出片段 `Ran 517 tests ... OK (skipped=4)`，统一写为“总计 517，513 通过，4 跳过，0 失败”，绑定执行时间 `22.382` 秒、负责人完整 HEAD、五个 dirty 文件清单和 `manifest.json` SHA-256。原始输出片段来源为 `research/reviews/owner-platform-review-20261016/审查结论.md`；完整 stdout 未随审查包保存，不能把它扩写成新的运行结果。

## 干净回归证据

- R1 无构建首页测试：失败；构建后同一测试：通过。
- R2 handler：修复前 `new, old` 失败；修复后只写 `new`，并新增真实浏览器回归通过。
- 平台定向回归：`test_workbench.py` 40/40、`test_workbench_operations.py` 15/15、`tests/ui` 1/1，见 `platform-regression.log`。
- `git diff --check` 通过。
- `python scripts/check_docs_context_budget.py` 的原始失败输出在 `logs/r3-docs-budget.log`：既有 `status archive bytes do not match archive_sha256`。

## 未修复 / unknown

- 未运行 GitHub-hosted Actions；这里是干净 worktree 的本地构建/测试证据，不能声称远端 CI run 已通过。
- 全量 Python discover 在本独立 A 基线为 `Ran 674 tests ... FAILED (failures=6, errors=13, skipped=10)`，失败来自 A 线 pinned-source/fixture hash 等既有资产，不扩展为 R1/R2/R3 或 A 算法回归，见 `python-regression-after-r1.log`。
- `python scripts/check_docs_context_budget.py` 仍被既有 `status archive bytes do not match archive_sha256` 阻断；本包不改历史归档来掩盖它。
- 负责人旧快照的 dirty 文件摘要保留在 `research/reviews/owner-platform-review-20261016/manifest.json`，该 manifest SHA-256 为 `815e8f335ba3abcfb3b1450b508eafa79419b69af2ce811d0b4f5ba4e46f6a44`。
- 未攻击线上服务，未改公共 contracts/runner/catalog，未合并或标 Ready；产品入口、CIA、CVE 和 A/B 算法准确性不在本修复包结论内。

## 给负责人的最小集成建议

在负责人自己的 worktree 按需 `git cherry-pick 8620592`、`35bffbb`、`0b8faea`。只修 CI 取 `8620592`；只修 Operations 取独立分支 `codex/owner-platform-r2-independent-20261016` 的 `35bffbb`；只修统计取 `0b8faea`。R3 若与负责人 dirty 文档冲突，保留其原文历史段落，只迁入 R3 统计校正块和证据绑定。迁入后重新执行 `npm ci`、`npm run build`、`npm run test:operations-handler`、`tests/ui`、纯 Python 回归和文档预算检查，再决定是否合并。
