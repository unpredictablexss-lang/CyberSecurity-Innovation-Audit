# AC-PATH-01B DeleteFile acceptance closure

日期：2026-10-19（Asia/Shanghai）
工作目录：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\worktrees\path-traversal`
角色：AC-PATH-01B 继任子 Agent
结论：DeleteFile 验收闭环已满足；未修改公共 Catalog，未 fetch/checkout/reset/push。

## 1. Checkout and pinned facts

- 实际 HEAD：`758d22f354b4aede80d21f321761e4515ab86047`
- pinned commit：`bc27c2ca520223acec6ae6e44e1535e5e4e73404`
- pinned tree：`d7cc9d82880ff52ef6c650c9b87cbdd533c57607`
- pinned commit 已由本地 `git cat-file` 验证；当前目标文件为 untracked migrated files，未切换分支。
- remote：`https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`
- dirty/untracked：`research/experiments/ac_parallel_20261019/`、`src/ohscanner/detectors/cpp/path_traversal_detector.py`、`tests/detectors/fixtures/cpp_path_traversal/`、`tests/detectors/test_cpp_path_traversal_detector.py`。

## 2. Patch inspection and closure

前一 Agent 的 patch 在 `src\ohscanner\detectors\cpp\path_traversal_detector.py` 第 56 行发生字符串拼接损坏：

```text
_REVIEWED_FILE_DELETE_RECEIVER = re.compile(...)n_SINK_CALLS = {
```

这导致 focused tests import 阶段 `SyntaxError`。现有 member-sink 汇总还把 libc 和 `DeleteFile` 的 `sinks.append` 写成 5 元组，而声明为 4 元组。

本次最小修复：

1. 拆分 `_REVIEWED_FILE_DELETE_RECEIVER` 与 `_SINK_CALLS`，恢复可编译语法。
2. 将 `sinks` 统一为 `List[Tuple[_Function, int, str, str]]`；libc 与 reviewed member sink 都追加 `(function, absolute, symbol, path_vars)`。
3. 保留 fail-closed 边界：只接受精确 `fileUtils.DeleteFile(path)`（receiver 名大小写不敏感为 `fileutils`、恰好一个非空参数）；unknown receiver、unknown/unqualified call、multi-arg、wrapper/overload 不猜测为 sink，而是无 finding 且 `blocked`/unresolved。
4. 新增直接验收测试：`contacts_exact_excerpt.cpp` 必须直接产生 `symbol=DeleteFile` candidate，且 source binding 为 fixture SHA；另覆盖 basename、canonical containment、literal allowlist、no-source、unrelated、unknown receiver、multi-arg、unknown static call。

## 3. Exact commands and before/after tests

环境（所有 focused run）：

```text
PYTHONPATH=.;E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
```

前修复（失败）：

```text
$env:PYTHONPATH='.;E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps'
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -X utf8 -m unittest tests.detectors.test_cpp_path_traversal_detector -v
```

结果：`SyntaxError: invalid syntax`，定位第 56 行；输出：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\pre_fix_unittest_stdout_stderr.txt`。

tuple 修复后但未加 DeleteFile 验收测试（前状态）：

```text
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -X utf8 -m unittest tests.detectors.test_cpp_path_traversal_detector -v
```

结果：`Ran 7 tests ... OK`；输出：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\patch1_unittest_stdout_stderr.txt`。

最终 focused command：

```text
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -X utf8 -m unittest tests.detectors.test_cpp_path_traversal_detector -v
```

结果：`Ran 11 tests ... OK`；输出：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\final_unittest_stdout_stderr.txt`。

最终直接命中事实：

- `contacts_exact_excerpt.cpp`：`status=blocked`，但直接产生 3 个 `symbol=DeleteFile` candidate（fixture 23、24、28 行）；同时保留 2 个 `open` candidate。
- fixed basename / canonical containment / literal allowlist：`completed` 且 `findings=()`。
- no-source 与 unrelated：`completed` 且 `findings=()`。
- unknown receiver、`DeleteFile(path, true)`、unknown static `DeleteFile(path)`：`blocked`、`findings=()`，limitations 含 `unresolved external call`。
- fixture manifest test 通过，现有 12 个 fixture 的 byte_length/SHA-256 均与 manifest 相等，旧哈希未改。

`py_compile` 也通过：

```text
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m py_compile src\ohscanner\detectors\cpp\path_traversal_detector.py tests\detectors\test_cpp_path_traversal_detector.py
```

## 4. Wall time and RSS

测量器：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\measure_unittest.py`，使用 Windows `GetProcessMemoryInfo` 记录 peak working set；wall 使用 `time.perf_counter()`。manifest 保存在同目录。

7-test legacy slice（原有测试名，最终代码回归）：

```text
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -X utf8 -m unittest tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_identity_and_positive_file_operation_controls tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_fixture_manifest_hashes_and_categories tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_containment_basename_and_allowlist_controls tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_no_source_no_sink_and_unrelated_api_are_not_candidates tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_unresolved_cross_function_and_partial_parse_remain_unknown tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_candidate_requires_file_sink_not_path_concatenation_alone tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_budget_and_unexpected_analysis_failures_fail_closed -v
```

- result：`Ran 7 tests ... OK`
- wall：`0.15885619999971823 s`
- peak RSS：`27,885,568 bytes`
- manifest：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\legacy7_measured_run_manifest.json`

final 11-test slice：

```text
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -X utf8 -m unittest tests.detectors.test_cpp_path_traversal_detector -v
```

- result：`Ran 11 tests ... OK`
- wall：`0.17463409999982105 s`
- peak RSS：`27,897,856 bytes`
- manifest：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\final_measured_run_manifest.json`

## 5. Patch and source-bound hashes

详细 JSON：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\acceptance_hashes.json`。

- detector SHA-256：`79d39ef4365e638d461d2541ad0b7f4b24985a651b1a78e3e2e9accf6c96e49c`
- focused tests SHA-256：`4500b62d2a1931cb125f9ff44bf382349a24c0b8ec84bdabc456701551d8601f`
- `contacts_exact_excerpt.cpp` SHA-256：`a0ec386bcb07e2c587fba6d3ef8dff46130ae953e517269ac4abaeda0235cddf`
- acceptance patch SHA-256：`171d0c71eb0f6e9aa80269ed5a1788bef01a56b097c63a179c6baa1f407e15df`
- acceptance patch Git blob SHA-1：`517be06685ff0faf4d49a1e48e0a85e158047070`
- patch 文件：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\deletefile_acceptance.patch`

## 6. Windows CRLF/LF and legacy manifest mismatches (isolated)

focused `cpp_path_traversal/manifest.json` audit：12/12 fixtures byte_length 与 SHA-256 都匹配，当前 fixture 均为 LF（CRLF count=0），没有修改任何旧哈希。

以下广度基线（`PYTHONPATH=.;E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps`，`-m unittest discover -s tests/detectors -p "test_cpp_*.py" -v`）为独立旧 fixture 问题，单列保留，不在本补丁中重写：

- `test_cpp_memory_safety_detectors`：`116 != 111` byte_length。
- `test_cpp_null_dereference_signal_controls`：fixture SHA `f319f3368248aa52aee3658cc3c4aa738ebb30e98301869bfa2f3b8f358c9201` != manifest `272c119cd5f831e0d28423d9d8db0561ccc1bd973a4ac6cc97ecab76ff847502`。
- `test_cpp_resource_lifetime_detector`：`116 != 110` byte_length。
- `test_cpp_unsafe_memory_call_detector`：`202 != 193` byte_length。
- 另有两个 `A-NULL-01 manifest SHA-256 mismatch` setUpClass errors，以及 shared_ptr fixture `source content hash mismatch`；这是既有 fixture/manifest 限制，不改变旧 hash。

旧基线输出：`E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ac_parallel_20261019\path_traversal_20261019\baseline_with_deps_unittest_stdout_stderr.txt`，观察 `Ran 122 tests ... FAILED (failures=4, errors=3)`；RSS 未在旧 runner 捕获。

## 7. Limitations and evidence gate

- `DeleteFile` 只识别 reviewed project shape `fileUtils.DeleteFile(path)`；不是通用 `DeleteFile`/wrapper/overload 语义推断。
- `contacts_exact_excerpt` 的 source-to-flow 是同 translation-unit、有限 assignment/call/out-parameter summary；`status=blocked` 由未解析 external calls 造成，candidate 仍是 `candidate/unassessed`。
- AST/pattern 摘要不证明入口、权限边界、控制流支配、并发、attacker control、canonical filesystem resolution 或 CIA impact；满足真实边界/可达敏感操作/触发/影响/证据门槛前不得升级 `confirmed/reportable`。
- 未知 receiver、unknown static、multi-arg 等形状按 fail-closed 处理，不产生 safe verdict；`findings=()` 不是安全结论。
- 本次未改公共 Catalog、未改 legacy manifest/hash、未写 Git history、未执行外部扫描器。

## 8. Continuous slices (可继续执行)

### AC-PATH-01B-CONT-01 — reviewed sink semantics

目标：保持 `fileUtils.DeleteFile(path)` 的精确语义和 source-bound candidate，不允许未知 overload 越权。

vibe coding prompt：

```text
角色：AC-PATH detector engineer。输入：当前 path-traversal detector、contacts_exact_excerpt、focused tests。
目标：只增强 reviewed fileUtils.DeleteFile(path) 的最小语义；每条新增路径必须有 positive/fixed/safe/unrelated/unknown 控制。
不变式：candidate/unassessed；unknown/multi-arg/receiver unknown fail-closed；不改 Catalog、不改旧 manifest/hash。
完成门：focused tests 全绿，contacts fixture 至少一个 symbol=DeleteFile，patch/source hashes 与 evidence manifest 更新。
持续循环：运行测试 -> 失败定位 -> 最小修复 -> 重跑 7+11 tests -> 记录 wall/RSS/patch hash -> 若门槛不满足明确 remaining gap。
```

### AC-PATH-01B-CONT-02 — bounded flow expansion

目标：在同一 translation-unit 内扩展 alias/wrapper/out-parameter 的有限传播，同时保留 fail-closed。

vibe coding prompt：

```text
角色：AC-PATH dataflow engineer。输入：公共 contracts/runner 语义、现有 C++ path fixtures、A-PATH-01 lineage。
目标：为 DataShare ValuesBucket source 到 direct file sink 增加可审计的 bounded alias/return/out-param summary；显式标注 unsupported macros/cross-file/overloads。
完成门：positive 命中、fixed basename/canonical/allowlist 不命中、no-source/unrelated 不误报、unknown shapes blocked；输出 source-bound schema v2 evidence 和限制。
持续循环：每次只加一个传播形状；运行 focused regression 与独立 safe controls；超过预算或证据不完整即 fail-closed。
```

### AC-PATH-01B-CONT-03 — line-ending evidence isolation

目标：把 Windows CRLF/LF manifest mismatch 与算法修复分离，保留历史 hash。

vibe coding prompt：

```text
角色：AC-PATH evidence maintainer。输入：baseline_with_deps 输出、legacy manifests、current fixture bytes。
目标：只生成 byte_length/hash/line-ending audit 和差异报告；禁止重写旧 fixture、旧 manifest、旧 ID。
完成门：每个 mismatch 给出 expected/actual、fixture path、line-ending counts、影响测试；明确是否 CRLF/LF、依赖或 source-content hash 问题；不把 mismatch 解释为 detector safe/miss。
持续循环：审计 -> 生成报告 -> 由独立 integration slice 决定是否需要规范化；本地验证，不 push。
```
