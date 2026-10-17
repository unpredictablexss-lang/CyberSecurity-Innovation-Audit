# OpenHarmony 检查收尾与材料归档（2026-10-18）

## 1. 收尾结论

- 按要求已停止 OpenHarmony 下载、同步、扫描与测试，不继续扩大实验范围。
- 本次只整理、核验并归档已经生成的检查材料、聚合报告和两个有界测试日志。
- 本轮材料中不包含 OpenHarmony 源码仓库、第三方依赖库、`.repo/`、Git LFS 对象、
  `projects/`、原始 `result.json`/`request.json`/`run_meta.json`、约 277 MB 的原始
  `summary.json`、缓存、虚拟环境或构建产物。
- 当前分支为 `codex/a-line-openharmony-full-test-20261016`。本收尾仅提交材料，
  不创建 PR、不标记 ready、不合并。

## 2. 测试范围与精确状态

OpenHarmony manifest 共包含 **525 个 project**。全量测试在完成前按要求停止，因此不能
声称 525 个 project 已全部扫描完成。

| 口径 | 数量 | 说明 |
|---|---:|---|
| manifest project | 525 | 固定 manifest 中的全部 project |
| prepared | 479 | runner 已准备测试请求 |
| runner 记录 | 478 | 已进入执行状态 |
| 生成 `result.json` / `report.md` | 378 | 已产生 scanner 级输出 |
| 478 项严格分类 | `completed=0`, `failed=100`, `unknown=378` | 缺失、失败或无充分结果均保持 unknown |
| 含未执行 `third_party/selinux` 的 479 项 | `completed=0`, `failed=100`, `unknown=379` | 该 project 只准备了 `request.json`，未执行 |
| scanner 级 `completed` | 10 | 不等于 project 级全量完成；全 project 覆盖严格口径仍为 unknown |

正确解释：

- `validated_vulnerability_total=0` 不能解释为 OpenHarmony 没有漏洞。
- 所有 finding 仍为 `candidate` / `unassessed` / `unknown`，不得提升为已确认漏洞。
- 640 项 OHScanner 自回归仅验证工具自身行为，不是 OpenHarmony 525 个 project 的
  全量扫描。
- `repo forall -c 'git lfs pull'` 的退出码 0 只证明命令成功结束，不证明测试完成。
- Ability validation 中 `foundation/ability/idl_tool` 为
  `completed_with_limitations`，严格分类仍是 `unknown`；`lifetime` 为 `blocked`；
  `shared_ptr_race` 与 `interface.ipc` 为 `completed`。

## 3. 已归档检查材料

以下材料逐项核对了仓库路径、字节数和 SHA-256。详细机器可读记录见
`validation/openharmony-check-artifact-manifest.json`。

| 仓库路径 | 字节数 | SHA-256 | 用途 |
|---|---:|---|---|
| `validation/openharmony-manifest-fixed.xml` | 117625 | `45090468297C469DD821B3E6F311F47A358A7D292D7AF5D480130352FA746C96` | 固定 manifest 快照，绑定本次 525 个 project 的解析输入 |
| `validation/openharmony-project-heads.tsv` | 72600 | `083808FC299DBDE55804E78A733834E1CA83A6316A1D265FDB3DD5D605470519` | project 路径与完整 commit SHA 对照 |
| `docs/openharmony-full-scan-20261017-summary.md` | 253147 | `E6B65E8611243C04579C4DAFC0F7B6E0D712027A04E125741C6EA455AF78EFE9` | 全量扫描过程、聚合状态与项目级摘要 |
| `docs/openharmony-ability-validation-20261017-summary.md` | 1778 | `EA1588EBEC2BAA9470F32262D3A3134DB27E9614566B11FAF61005414426EF4B` | Ability 验证摘要 |
| `docs/openharmony-smoke-20261017-ability-idl-tool.md` | 111668 | `C505586FD250DC1EB8DC877107E662A38EF78A69B85A4AB231D8A9047D0CB484` | Ability IDL 工具 smoke 记录 |
| `validation/repo-lfs-pull-20261017.log` | 559 | `872BE4734AFBA6FEB868BF9D79966168E6D0FD10B7A3DD685C2B3FA12DC699CF` | Git LFS 拉取的有界退出码证据 |
| `validation/linux-tests-after-ls-tree-fix-python314-20261017.log` | 1499 | `B79E0E21EC8495C61FCADF7800DC48E0B5DB830F7C06457B6357215BDEB9A6A0` | Python 3.14 回归的有界测试证据 |

已存在于仓库中的先前收尾材料继续保留：

- `docs/openharmony-full-test-20261017.md`
- `validation/openharmony-full-test-20261017-summary.json`

## 4. 日志纳入与排除原则

本次仅例外纳入两个小型、有界日志：

- `validation/repo-lfs-pull-20261017.log`：只证明 `git lfs pull` 退出码 0，
  不证明 OpenHarmony 测试完成。
- `validation/linux-tests-after-ls-tree-fix-python314-20261017.log`：证明
  640 项测试、48 项跳过、`OK`，目标测试 1/1、`compileall` 与
  `git diff --check` 通过；这仍是 OHScanner 自回归。

其余完整 stdout/stderr、扫描运行日志、原始实验日志继续排除。既有报告中
“测试日志不进入 Git”的原则仍适用于原始和完整日志；上述两个文件仅作为收尾所需的
最小、可复核证据例外纳入。

## 5. 回归验证摘要

- Python 3.14 回归：640 tests，48 skipped，`OK`。
- 目标测试 `tests.test_ohscanner_m15.OfflineGitTests.test_promisor_clone_never_fetches_missing_blob`：
  1/1 `OK`。
- `compileall`：通过。
- `git diff --check`：通过。
- 上述结果仅支持 OHScanner 自身回归结论，不支持 OpenHarmony 全量覆盖结论。

## 6. 明确排除内容

本次归档和提交明确不包含：

- `D:\openHarmonyScanner\openharmony` 下的 OpenHarmony 源码或任一源码仓库。
- `.repo/`、Git LFS 对象、大型源文件和第三方依赖库。
- `projects/`、原始 `result.json`、`request.json`、`run_meta.json`。
- 约 277 MB 的原始聚合 `summary.json`。
- 完整 stdout/stderr、完整运行日志、缓存、虚拟环境、构建产物和临时目录。

## 7. 剩余限制

- 525 个 manifest project 未被完整扫描；378 个 project 有 scanner 输出，但严格
  project 级状态仍为 unknown。
- 尚未形成可审计的全量漏洞结论；现有 finding 均未完成证据评审。
- Ability 的 `lifetime` 仍为 blocked，`idl_tool` 受限制完成。
- 不创建 PR、不标记 ready、不合并；后续是否继续全量测试由用户决定。
