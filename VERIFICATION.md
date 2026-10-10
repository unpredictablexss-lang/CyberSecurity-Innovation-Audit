# VERIFICATION：纯 M-gate 合并技术审查

## 环境

| 环境 | 事实 |
|---|---|
| Windows / PowerShell | `E:\网安\CyberSecurity-Innovation-Audit`；`python.exe` 为应用别名，退出码 `9009`，`py` 不可用。 |
| WSL/Linux | Ubuntu 22.04，Python 3.10.12；测试命令通过 `wsl.exe -d Ubuntu-22.04` 执行。 |

## 已执行验证

### 全量回归

```text
wsl.exe -d Ubuntu-22.04 -- python3 -m unittest discover -s tests -q
```

结果：`Ran 241 tests in 18.334s`，`OK`。覆盖既有 historical benchmark、OHScanner M0/M1/M1.5/M2、shared_ptr race detector、review evidence、native Git provenance、holdout manifest 和性能基线合并后的测试。

### Shared-ptr 来源与证据回归

```text
wsl.exe -d Ubuntu-22.04 -- python3 -m unittest tests.detectors.test_cpp_shared_ptr_race_native_evidence tests.detectors.test_cpp_shared_ptr_race_review_evidence -q
```

结果：`Ran 17 tests`，`OK`。包含：

- origin identity、exact commit、exact tree/blob、raw LF/CRLF/BOM SHA-256；
- non-UTF-8、错误 origin、错误 commit、工作区漂移；
- binding manifest hash、blob/source hash 不匹配、vulnerable/fixed 调换；
- review 顶层 evidence class、fixture category、parse issues、finding scope、artifact 唯一性和 stale hash 篡改拒绝。

### OHScanner 平台回归

```text
wsl.exe -d Ubuntu-22.04 -- python3 -m unittest tests.test_ohscanner_contract tests.test_ohscanner_m15 tests.test_ohscanner_m2 -q
```

结果：`Ran 35 tests`，`OK`。

### 语法与仓库检查

```text
wsl.exe -d Ubuntu-22.04 -- python3 -m py_compile \
  src/ohscanner/git_source.py \
  src/ohscanner/detectors/cpp/shared_ptr_race_review.py \
  research/experiments/cpp/shared_ptr_race_native_evidence.py \
  research/experiments/cpp/prepare_shared_ptr_race_binding.py
git diff --check
```

结果：均通过。`git diff --check` 仅提示部分工作树文件的 LF/CRLF 转换，不产生 whitespace error。

## 合并状态

- `origin/main` 已 fetch 到 `1446e49`。
- `origin/main` 的真实组件性能基线已合入当前 merge candidate；合并冲突只涉及 `AGENTS.md`、`PROGRAM_STATUS.md` 和 `competition_deliverables_plan.md`，已按“保留政策 + 采用最新性能事实”解决。
- 当前候选相对 `origin/main` 为领先、非落后；最终 merge head 的远端 CI 仍需在 push 后核验。
- 本轮没有创建 PR、没有标 ready、没有合并 main。

## 结论边界

当前结果证明的是 **M-gate 工程条件在本地闭环**：来源绑定、证据完整性、回归、契约兼容、main 同步和 CI 配置均已补齐。它不证明任何漏洞为 `confirmed/reportable`，也不替代 C-gate 的 PoC、动态验证、CWE/CVE、影响版本、修复重验和漏洞报告。
