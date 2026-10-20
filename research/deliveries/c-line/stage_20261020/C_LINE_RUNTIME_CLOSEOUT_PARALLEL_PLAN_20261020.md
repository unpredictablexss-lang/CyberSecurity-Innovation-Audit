# C 线运行验证收尾并行计划（2026-10-20）

## 基线与任务树复核

- 已从 `origin` fetch；最新 `origin/main` 为 `0f53af62283dbd0f249280805e8286a04b2d43b9`，本地与远端 `codex/c-line-parallel-plan-20261020` 都为 `cfdbd21eac05f6b515d123a29640f5011733ab03`，未见该分支的新远端提交。
- 随后共享 remote-tracking ref 已推进到 `origin/main@4b0e16576a45a111b4fad7e8f82819a47ed472f5`（经 `f076b8c`、`4b0e165` 两个 D104 closeout commits）；本 worktree 新一轮 fetch 由于 GitHub 443 超时未成功，但该 SHA 已在本地 ref。C 阶段分支当前仍基于 `0f53af6`（ahead 8 / behind 2）；main 的 D104 改动包含 Catalog、source identity 与 parser 等可能交叠文件，所以暂不在两个组件运行 workstream 中途改写代码基线。组件与报告结束后，下一步应按路径冲突检查把 C 变更选择性重放到 `4b0e1657` 并重跑 Runner/Catalog/Parser 兼容集，不整体搬入平台更改。
- 本次 fetch 也核对了未合入 main 的 C topic refs：C scanner optimization `448bd1b`（相对 main 13 ahead / 128 behind）、C11 alias `3d9274b`（4/35）、C12 semantics `7bf57a8`（7/35）、C13 replay `40fd4d5`（10/35）。它们是相互分叉的独立 topic snapshots，planning task tree 没有标为进行中；本轮不整体合并这些分支，避免将 C-line 核心代码和 scope 不明的历史提交带入已选收尾线。
- 当前静态集成阶段分支 `codex/c-line-ark-stage-20261020` HEAD `79916713cf6e4b590a588c9cd4d50e115e187436`，代码提交 `e798fa77fda843ff00f3b0ac7367f4eea02eb5ac` 基于最新 main；交付报告记录构建在 WSL NTFS/P9 参数检查阶段停滞。
- 旧 C execution tree 含 42 个 workstream，静态候选、独立 same-SHA 测试和 source review 全部为完成状态；Float32Array/TypedArray.set 的运行环境盘点也已终结为 `runtime_not_run`。本计划只续接其明确的最小后续动作：把可复现源码/构建输入放在 Linux 原生文件系统，再执行一个现有 Ark Runtime 组件测试。它不重开静态规则、不把环境搜索写成漏洞结论。
- 任务树新增两条互相反馈的进行中工作流，任务编号 `C-CLOSEOUT-RUNTIME-DEV-20261020` 和 `C-CLOSEOUT-RUNTIME-TEST-20261020`。开发线完成真实构建与组件运行；测试线独立固定官方测试的语义/断言及修复版本可用性，并在开发线给出精确运行工件后复验。若无匹配修复 commit，必须明确报告 comparison `not_run`，不可用 synthetic fixture 代替。
- 测试线已提前确认：官方 `typedarrayset` target 只测常规 set 语义和 offset=2，不覆盖超大 offset/range-wrap 候选。因此它仅能作为 VM/组件 smoke；若运行条件允许，必须追加有界的候选触发/安全断言，或找到真正覆盖该边界的现有用例。不得把官方 smoke pass 写成候选运行验证。
- `typedarrayset` 的 case BUILD label 存在，但 `test/moduletest/BUILD.gn` 的 `module_test_list` 不含它；必须直接构建并执行 `//arkcompiler/ets_runtime/test/moduletest/typedarrayset:typedarrayset`，仅运行聚合 `ark_js_moduletest` 不能作为此案例通过证据。
- 开发线已在 Linux-native `/tmp` 从固定 Git objects 解包 Ark exact tree（116 MB，tree hash 重核吻合）及 OH build source snapshot（54 MB），并隔离安装 GN `2026 (47b40ef4)` 和 Ninja `1.13.2`。普通 `gn gen` 的第一次失败指出缺 `.gn`，拷贝/隔离诊断 probe 后再暴露 `parts_info/components.json` 与 product preloader config 缺失；还没有启动本轮 HB build，也没有 live build process。测试线独立 oracle/fix-provenance 报告提交 `61fa223fc5281793b8b7da494a05c483892f31bc`；独立 runtime replay 等待开发侧 binary/log。

## 持续目标和停止条件

共同持续目标：获得一份绑定 scanner commit、Ark Runtime commit/tree、测试路径、构建命令和日志的真实组件运行证据；有可取得的真实 fixed source 时才做 parent/fixed 对照。两个工作流完成各自可执行部分、通过其实际适用的检查并交换反馈后停止。若 Linux-native build 仍有外部缺项，交付精确失败步骤和最小继续条件，不重复 WSL NTFS 方案，也不扩展候选方向。

### 开发线：`C-CLOSEOUT-RUNTIME-DEV-20261020`

```yaml
role: C 线 Ark Runtime 组件构建与运行开发者
objective: 在 Linux 原生文件系统上尝试构建精确绑定 Ark Runtime 版本，并运行一个现有 TypedArray.set 组件案例；对真实修复版本可取得性作有限核验
baseline:
  scanner_branch: codex/c-line-ark-stage-20261020
  scanner_commit: 79916713cf6e4b590a588c9cd4d50e115e187436
  source_repo: openharmony/arkcompiler_ets_runtime
  source_commit: a65a2853ccae13da167d9aa4720ab8b11ec16656
  source_tree: 8781f036a3e7e04d8e0b34970d5f623b42875016
case: arkcompiler/ets_runtime/test/moduletest/typedarrayset:typedarrayset
steps:
  - 先查 Linux 原生 WSL 路径/可用磁盘和必要工具，不复用 NTFS/P9 的源或 out 目录
  - 以独立临时路径准备精确源码与产品/host 构建输入，保存 manifest、commit/tree、环境、完整命令和日志
  - 尝试最小 Ark VM/frontend 或现成可运行 artifact；直接构建/执行非聚合的 `//arkcompiler/ets_runtime/test/moduletest/typedarrayset:typedarrayset` smoke，若它未触发候选，再尝试有界小型 JS offset/range-wrap 测试并检查异常与目标视图字节
  - 与测试线交换预期、边界和偏差；只修复具体可复现的构建/测试接线问题，不改 Ark 上游源码
  - 有真实 matching fixed commit 才运行同一测试对照；否则如实记 not_run 并给最小缺失条件
  - 提交一份报告和必要的隔离脚本/结果；代码改动必须限于本任务工件
constraints:
  - 不运行线上目标，不覆盖已有源码/产物，不把 fixture 当产品运行
  - 不推断产品影响或将环境失败改写为漏洞/安全结论
  - 不重复扫描上轮已检查过的 WSL NTFS/P9 路径；源在 Linux-native copy 中验证 hash
feedback_to: C-CLOSEOUT-RUNTIME-TEST-20261020
deliverables: [source/build manifest, commands and raw logs, actual test output or exact blocker, real fixed comparison status, report commit]
stop: 一次完整的最小运行结果，或一次 Linux-native 构建路径的明确 blocker 记录
```

### 测试线：`C-CLOSEOUT-RUNTIME-TEST-20261020`

```yaml
role: C 线独立 Ark Runtime 组件测试者
objective: 在不修改生产代码的独立 checkout 中固定 typedarrayset 官方案例的语义预期、检查真实修复来源，并独立复验开发提交的运行结果
baseline:
  scanner_branch: codex/c-line-ark-stage-20261020
  scanner_commit: 79916713cf6e4b590a588c9cd4d50e115e187436
  source_repo: openharmony/arkcompiler_ets_runtime
  source_commit: a65a2853ccae13da167d9aa4720ab8b11ec16656
steps:
  - 阅读既有 typedarrayset 测试与其 runner/build target，确认 case label 不在聚合 `module_test_list` 中，记录断言并明确 smoke 与候选边界的覆盖差异（当前已知它不覆盖超大 offset/range-wrap）
  - 独立固定目标源码的 commit/tree/blob/SHA；检查当前已取得 refs 中是否有真实修复 commit，仅在路径/语义确有变化时称为 fixed
  - 对开发线提供的 test binary、脚本、commit 与原始日志独立核验并复跑同一官方测试；若无法访问则报告具体原因
  - 比对正向运行、边界/安全控制、fixed 版本（仅真实版本存在时）与静态候选触发条件，反馈遗漏或结论过度
  - 提交只含证据与复现信息的独立测试报告，不改生产 detector/model/runner
constraints:
  - runtime 未执行、fixed source 未取得时明确 not_run/unknown
  - 不用单元 fixture 或人工 patch 冒充真实版本修复对照
  - 零诊断/测试通过不等于安全或产品漏洞确认
feedback_to: C-CLOSEOUT-RUNTIME-DEV-20261020
deliverables: [official test assertion map, source/fix provenance check, independent same-run replay or exact blocker, discrepancy feedback, report commit]
stop: 一次开发提交的独立复验和反馈，或一次有明确外部缺项的独立 blocker 记录
```

## 反馈闭环

1. 测试线先把官方测试断言、触发差异和可用修复 ref 回给开发线；开发线据此确定可执行的最小测试。
2. 开发线产出固定源码和原始运行工件后，测试线只复验该提交/工件，并逐项返回差异。
3. 开发线只处理可复现的接线/测试缺陷，随后请测试线复测；无缺陷则共同交付实际结果或精确 blocker。
4. 测试未跑、fixed ref 不存在、产品效果未知等状态保持原样，不把未知改成通过。
