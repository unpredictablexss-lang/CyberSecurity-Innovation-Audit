# OpenHarmony 全量测试检查收尾报告（2026-10-17）

## 1. 范围与结论

- A 线测试分支：`codex/a-line-openharmony-full-test-20261016`
- 分支基线：`origin/codex/teammate-a-static-module-20261013`
- 本次按要求停止继续执行全量扫描，不重跑 OHScanner 自回归，不对 OpenHarmony 525 个 project 作“全量完成”声明。
- OpenHarmony 全量扫描曾启动，但在完整完成前停止。已产生部分检查材料和报告；第三方源码、`.repo`、Git LFS 对象、原始扫描输出和测试日志均不进入 Git。
- OHScanner 自回归已验证通过；`git_source.py` 的离线对象读取修复保留。所有 finding 仍是 candidate/unassessed/unknown，本轮没有已验证漏洞。

## 2. 环境与源码准备

- D 盘评估时总容量约 953.87 GiB、可用约 259.35 GiB。最终实测 OpenHarmony 源码工作树约 56 GiB、`.repo` 约 36 GiB，空间足够，无需分批下载。
- 固定 manifest：`D:\openHarmonyScanner\openharmony-manifest-fixed.xml`
- manifest 共 525 个 project，均绑定完整 40 位 commit SHA；其中 4 条因缺少 `path` 使用 `name` 作为路径回退。
- manifest SHA-256：`701683246A8B4393E61CDB75132D76AACC9E53F6F663D37E386BBD535511FBEE`
- `repo sync -c` 与 `git lfs pull` 已完成。LFS 日志退出码为 0，日志 SHA-256 为
  `872BE4734AFBA6FEB868BF9D79966168E6D0FD10B7A3DD685C2B3FA12DC699CF`。

## 3. OHScanner 自回归

有效日志：`D:\openHarmonyScanner\linux-tests-after-ls-tree-fix-python314-20261017.log`

- 环境：WSL Ubuntu，Python 3.14.7
- 结果：`Ran 640 tests`，`OK (skipped=48)`，退出码 0
- 目标回归：`tests.test_ohscanner_m15.OfflineGitTests.test_promisor_clone_never_fetches_missing_blob` 通过
- `python -m compileall src/ohscanner` 通过
- `git -c core.autocrlf=true diff --check` 通过
- 日志 SHA-256：`B79E0E21EC8495C61FCADF7800DC48E0B5DB830F7C06457B6357215BDEB9A6A0`

这 640 项是 OHScanner 自回归，不是 OpenHarmony 525 个 project 的正式全量扫描。本次收尾没有重跑这 640 项。

## 4. 停止时的全量扫描状态

原始扫描根目录：`D:\openHarmonyScanner\openharmony-full-scan-20261017\projects`

| 项目 | 数量 |
| --- | ---: |
| manifest project | 525 |
| 扫描 project 目录 | 479 |
| `request.json` | 479 |
| `run_meta.json` | 478 |
| `stdout.log` | 478 |
| `stderr.log` | 478 |
| `result.json` | 378 |
| `report.md` | 378 |

runner 摘要记录：

- `project_count=478`
- `processed_count=378`
- `diagnostic_count_total=1645`
- `validated_vulnerability_total=0`
- `schema_version=openharmony-full-scan-runner-v1`

478 条 runner 记录均通过 `index + project_path + manifest_commit` 与 `summary.projects` 对账一致。另有 1 个已准备但未执行的 project：

- `0479-third_party_selinux-4ce9dd3ea7`
- 路径：`third_party/selinux`
- 仅有 `request.json`，不在 runner 摘要中，单独计为 `unknown`。

严格按 runner 分类口径：

| 统计范围 | completed | failed | unknown |
| --- | ---: | ---: | ---: |
| runner 已记录的 478 个 project | 0 | 100 | 378 |
| 含已准备未执行的第 479 个 project | 0 | 100 | 379 |

不得将本报告解释为 525 个 manifest project 已全部扫描。实际启动/准备范围为 479 个 project，其中 runner 纳入 478 个，生成 scanner 结果 378 个。

## 5. Scanner 完成项与分类歧义

对 378 个 `result.json` 的标量字段完成一致性比较。期望 detector 集合为：

- `ohscanner.interface.ipc`
- `ohscanner.cpp.lifetime`
- `ohscanner.cpp.shared_ptr_race`

比较结果：

- `result_count=378`
- `status_completed=10`
- `status_completed_with_limitations=368`
- `detector_runs_tool_mismatch_count=0`
- `detector_coverage_key_mismatch_count=0`
- `detector_set_mismatch_count=0`

此前出现过的 `detector_set_mismatch=10` 已由全量标量比对推翻，不应继续引用。严格原因计数为：

- `scanner_status_not_completed=368`
- `execution_state_not_completed=100`
- `detector_set_mismatch=0`

有 10 个 scanner 级结果达到 `result.status=completed`、`run_meta.execution_state=completed` 且 `exit_code=0`，但 runner 摘要仍将其分类为 `unknown`。本次不静默改写 runner 分类，也不将它们计入严格 `completed`。观察到的 run ID 为：

- `0044-applications_sample_wifi_iot-33cbeda99a`
- `0156-drivers_liteos-4fb817ede7`
- `0202-iothardware_peripheral-45ac7dae98`
- `0341-third_party_e2fsprogs-3683208ccd`
- `0350-third_party_freetype-133538172c`
- `0376-third_party_libjpeg-turbo-4d2fc8d606`
- `0379-third_party_libpng-d6baadab5f`
- `0423-third_party_pyyaml-cdda299373`
- `0431-third_party_rust_clang-sys-85ee4c7146`
- `0447-third_party_rust_link-cplusplus-f77a7954b5`

这 10 项的 `summary.failure_reason` 均为空字符串。由于没有建立成功的全 project 覆盖资格判定，它们仍按 `unknown` 报告。

## 6. 代码修复

本次保留 `src/ohscanner/git_source.py` 的离线读取修复：当 `git ls-tree` 因本地 tree/entry 对象缺失、promisor/lazy fetch 被禁用或无法获取而失败时，显式抛出 `missing_local_git_object`，绝不触发联网 fetch。

## 7. 证据与排除项

机器可读摘要：`validation/openharmony-full-test-20261017-summary.json`

进入 Git 的检查材料仅包括：

- `PROGRAM_STATUS.md`
- `src/ohscanner/git_source.py`
- `docs/openharmony-full-test-20261017.md`
- `validation/openharmony-full-test-20261017-summary.json`

明确不进入 Git：

- `D:\openHarmonyScanner\openharmony`
- 任意 `.repo/`
- Git LFS 对象或大文件
- 原始扫描目录、`result.json`、`report.md`、stdout/stderr 和运行日志
- 实验输出、缓存、构建产物
- virtualenv、依赖缓存、临时目录

## 8. 限制

- 扫描在完成前被要求停止，因此 525 个 manifest project 没有全量覆盖。
- runner 严格分类仍为 `completed=0`；10 个 scanner 级完成项保持 `unknown`，不能当成完整成功。
- `validated_vulnerability_total=0` 只表示本次部分结果中没有已验证漏洞，不等于 OpenHarmony 无漏洞。
- 本报告是停止时点的检查收尾材料，不替代完整全量测试报告。
- 不创建 PR，不标记 ready，不合并。
