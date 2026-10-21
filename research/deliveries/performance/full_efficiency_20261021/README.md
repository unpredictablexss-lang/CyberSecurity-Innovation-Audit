# OHScanner 效率技术文档实施与实验记录（2026-10-21）

## 范围与结论

本交付覆盖 P0–P5 中已安全落地的最小可复核实现。源码基础 HEAD 为 `4f75a65775b202b8220a208ebdb50fdb5c8dbb4d`；工作区已有未提交 P0/P1 改动，E0/E3 原始实验记录对应这些 P0/P1 改动，早于本轮 P2–P5 实现。本轮未覆盖或重置这些改动。本报告内 E0/E3 使用同一 11 个固定组件、相同 manifest/示例 detector、同一 Python/Git/Tree-sitter 环境。此 detector 是 `ohscanner.example.cpp.copy-calls`，只表示扫描处理成本与输出一致性，不能代表 ABCD 全量漏洞扫描，也不提供准确率结论。

| 实验 | 定义 | 状态与结果 |
|---|---|---|
| E0 | 无 AST 缓存全量基线 | 已完成；原始记录 `E0_no_cache.json` 和组件 JSON/log |
| E1 | 仅扫描 Git 变更文件 | **三文件合成风险夹具已完成；固定语料计时未运行**。样本证明仅扫描变更文件会漏掉未变文件候选，因此拒绝作为完整扫描方案 |
| E2 | 变更依赖闭包 + 不可证明时全量回退 | 固定 11 组件 base→head 冷/热对照已完成。官方 commit 元数据和源码归档重建出的 11/11 base Git 对象、tree、head first-parent 和祖先关系均通过 SHA 验证；配置变化触发 full fallback。热缓存复用 AST 与允许缓存的完整单文件检测器结果，但仍扫描完整 head 清单。与同环境 E0 相比，热跑墙钟 -29.7%、CPU -62.1%，输出签名和覆盖 11/11 一致；冷缓存填充成本更高，不宣称冷跑更快。 |
| E3 | P0/P1 冷缓存/热缓存和共享事实按需机制 | 冷/热原始结果已归档；冷/热与 E0 的结果身份、状态及覆盖 11/11 一致。按需 facts provider 由单测验证，但当前示例语料没有消费 `facts_v1` 的 detector；不把它计入性能增益 |
| E4 | Agent 证据收益排序、重复只读动作复用 | 离线 helper 夹具已完成：根因键、义务动作排序、同请求 memo 命中；墙钟/CPU 仅为本地 Python helper 时间。真实 Provider 调用数为 0，模型延迟、Token、成本和质量仍 `not_run` / `unknown`。 |

## E0 / E3 对照

| 指标 | E0 无缓存 | E3 冷缓存 | E3 热缓存 | 解释 |
|---|---:|---:|---:|---|
| 总墙钟 | 63.444 s | 79.439 s | 39.724 s | 热缓存相对 E0 -37.4%；冷缓存因填充成本较慢 |
| 进程 CPU | 47.612 s | 59.631 s | 17.748 s | 热缓存相对 E0 -62.7% |
| AST 解析墙钟 | 38.678 s | 41.210 s | 1.904 s | 热缓存相对 E0 -95.1% |
| AST 解析 CPU | 37.698 s | 39.457 s | 1.738 s | 热缓存相对 E0 -95.4% |
| 解析器实际调用文件数 | 9,508 | 9,478 | 201 | 热缓存仍有其他语言/专用前端解析 |
| AST cache hit / miss | 0 / 0 | 30 / 9,277 | 9,307 / 0 | 可缓存摘要 lookup 命中率 100% |
| 组件进程峰值 RSS 最大值 | 264,392 KB | 264,960 KB | 261,952 KB | 不据此宣称内存改善 |
| 输出一致性 | — | 与 E0 一致 | 与 E0 一致 | 诊断身份/源码定位/解析状态/检测器覆盖/整体状态均一致，11/11 |

解析调用数不等于全仓解析文件数；AST 缓存仅接管 C/C++ 共享轻量大纲。CPU 配额利用率仍为 `unknown`：WSL2 没有暴露可读 cgroup quota。系统逻辑核数不用于代替配额或瞬时 CPU 占用率。

## E0 / E2 固定语料增量与热缓存对照

为解决浅 checkout 缺少 base commit 的问题，本轮从官方 GitHub commit 元数据与精确源码归档重建了临时 bare repository 中的 Git 对象。11/11 base commit object SHA、base tree SHA、head first-parent、次级 merge parent 元数据和 `merge-base --is-ancestor` 均核验通过；原有 pinned checkout 未改动。材料记录于 `E2_parent_objects/materialized_base_evidence.json`，实现校验的 helper 为 `materialize_e2_base_objects.py`。E2 manifest 固定 11 个 head/base SHA，运行两个真实 M2 detector，覆盖 9,508 个 head 文件。

对比使用同一工作区代码 revision `a87b953fac20da0c4f2e0fb8d5c7262aa6eb36fe`、WSL2/Python 3.14 和同一隔离 targets。E0 无缓存与 E2 冷/热缓存的缓存目录均按实验要求隔离；E2 最终计时使用 WSL 原生 ext4 `/tmp/ohscanner-e2-cache-ext4-20261022`。报告与日志在 `E2_fixed_corpus/`。此前缓存落在 Windows 挂载盘的探索数据也保留，但未用于性能结论，因为小文件缓存 I/O 使其明显变慢。

| 指标 | 同环境 E0 无缓存 | E2 冷缓存（ext4） | E2 热缓存（ext4） | 热缓存相对 E0 |
|---|---:|---:|---:|---:|
| 总墙钟 | 94.800 s | 164.627 s | 66.618 s | -29.7% |
| 进程 CPU | 81.636 s | 121.325 s | 30.950 s | -62.1% |
| AST 解析 CPU | 33.884 s | 36.621 s | 1.392 s | -95.9% |
| Detector 阶段墙钟 | 40.828 s | 65.119 s | 19.755 s | -51.6% |
| 最大组件 RSS | 206,476 KB | 336,376 KB | 333,552 KB | 热跑内存峰值更高，不能宣称内存改善 |
| parser 调用 / AST cache hit | 9,508 / 0 | 9,478 / 30 | 201 / 9,307 | — |
| detector 结果 cache hit / miss | 0 / 0 | 0 / 13,144 | 13,037 / 107 | — |
| 有 detector 结果复用的源码路径 | 0 | 0 | 6,571 | 其余文件及所有 head inventory 仍纳入扫描 |
| 候选诊断 / 状态 | 63 / 11 `completed_with_limitations` | 63 / 11 `completed_with_limitations` | 63 / 11 `completed_with_limitations` | 签名/覆盖 11/11 等价 |

冷跑高于无缓存基线，反映首次构建 AST 与检测器结果缓存的填充开销。热跑继续检查完整 Git head inventory；所有组件的 build/analysis 配置变化触发保守 full fallback，未缩小候选文件覆盖。热缓存只复用检测器明确声明为完整单文件结果且身份键匹配的条目，其他 miss 继续执行检测器。E0 与 E2 热缓存以及 E2 冷/热的规范化结果签名一致；均有 63 条未验证候选诊断、0 个已验证漏洞。该对照只说明两个 M2 detector 的固定源码处理成本，不是 ABCD 全量漏洞扫描或准确率实验。

复现实验的 Python 环境、目标路径、cache 路径和命令见 `experiments.json` 的 E2 `commands` 字段。由于目标仓库与 ext4 cache 位于本机临时目录，后续复跑需先按 `materialize_e2_base_objects.py` 与 `E2_parent_objects/` 的记录重新构建目标对象和空 cache 目录。

## P3 当前代码复测补充

P3 provider 初次接入后，固定 11 组件重新执行了无缓存、冷缓存、热缓存三轮。当前示例 detector 实际请求 `syntax_facts_v1`；热缓存相对本轮 E0 的 AST parse CPU 为 -96.0%、进程 CPU 为 -54.3%，但总墙钟为 +63.9%。三个阶段的结果签名 11/11 一致，partial 状态保留。单轮串行耗时存在环境波动，因此只报告实测值，不声称端到端更快。原始报告、命令和细节见 `p3_facts_current/README.md`；Excel 新增“P3 current”页。

## P2 单文件检测结果缓存验证

增加了 opt-in 的 `git_blob_single_file_v1` detector contract。缓存键绑定仓库/profile、路径、语言、经 Git blob hash 复核的 OID、源 SHA-256、Tree-sitter/grammar/parser 规范版本、detector ID/version/contract version，以及被 detector 声明的单文件事实摘要。坏条目、未知版本、非 Git Blob、解析不完整、缓存读写异常均按 miss/bypass 走正常 detector。示例 detector 消费单文件 AST 与 `facts_v1`，不消费 include/build flags/macros/跨文件符号；其他 detectors 未 opt-in，继续完整检测。完整 head inventory 和 AST indexing 仍会执行，所以此实现只复用可信的 per-file detector result，不宣称安全的全仓增量覆盖。

小型双提交 Git 夹具的缓存 head run 与无缓存 head run 候选身份、源码定位与哈希、解析、覆盖和整体状态等价；未变 Blob 命中 1 个检测器文件结果，变更 Blob 重新计算。该微型运行中缓存路径总墙钟为 0.576 秒，无缓存路径 0.305 秒；包含 diff 规划与基线索引的额外开销，未显示端到端加速。CPU/RSS 不足以支持性能结论，保留原始值/unknown。数据仅验证缓存正确性与失效，不代表 ABCD 漏洞扫描或准确率。可用以下命令复跑，输出不覆盖非空目录：

```powershell
python scripts/perf_incremental_cache_fixture.py --out-dir research/deliveries/performance/full_efficiency_20261021/p2_result_cache_fixture
```

原始冷/热/对照报告、缓存条目、结果签名和比较记录保存在 `p2_result_cache_fixture/`；Excel 新增“P2 cache”页。

随后在固定 11 组件、9,508 文件上用同一 detector 跑了 E0、E3 cold、E3 hot。三轮结果签名（候选身份/定位/源哈希/解析/覆盖/状态）均 11/11 一致且保留 11/11 `completed_with_limitations`。冷缓存命中 0 / miss 6,619，热缓存 hit 6,619 / miss 0；但 E0 / cold / hot 总墙钟分别为 56.316 / 235.892 / 270.672 秒，AST CPU 为 31.436 / 32.121 / 31.437 秒。热结果缓存较 E0 墙钟慢 380.6%、进程 CPU 增加 38.4%，没有减少 AST 解析成本；detector 阶段墙钟升至 213.834 秒。**该结果缓存仅保留 opt-in 研究状态，不建议作为效率功能启用。** 这是与现有 AST summary cache 分开的实验。逐组件原始记录、冷/热等价核对和解释见 `p2_corpus_result_cache/README.md`；Excel 的“P2 fixed corpus”页含阶段对比。

## 设计说明

- **P2 增量规划**：CLI 与 Workbench API/UI 都可提交完整 `base_commit`。服务端验证该 commit 已存在且是 head 祖先，并把基线纳入 workflow SHA；预览和任务详情显示比较基线，执行报告绑定 base/head、变更路径和 fallback。include 反向索引与 C/C++ 语法调用候选可扩展影响范围；base/head C/C++ 语法索引使用固定 Blob 版本化 AST 缓存，命中统计单独归入 base index 阶段；跨语言、重载、宏与函数指针边仍不可证明，因此索引仍标 incomplete 并保留完整 head inventory。显式 opt-in 的 per-Blob result cache 仅限声明单文件事实的 detector；固定语料证明输出等价，但成本显著增加，因此当前不作为效率收益交付。其他 detector 全量执行。新旧结果身份与覆盖不等时不验收，不将 partial 扫描升级为完成。
- **P3 按需事实**：FactProvider 声明 ID、版本、输出、输入事实、语言和成本；Planner 只构建 detector 请求的事实。失败/不适用时事实缺失，runner 对依赖它的 detector 保持 blocked/unknown。事实键/失效还需把跨文件输入和分析配置纳入；当前不把事实缓存复用在纯单文件 AST cache 中。
- **P4 资源模式与恢复**：`OHSCANNER_PERFORMANCE_MODE=low|balanced|high` 的扫描槽位默认为 1/2/4，可用 `OHSCANNER_MAX_CONCURRENT_SCANS` 下调但不能超过模式上限。已有队列硬容量 100。SQLite `BEGIN IMMEDIATE` 负责原子 claim；Worker 只在固定槽位内运行子进程，健康 API 与设置页报告并发、排队数、运行数和队列容量。CPU quota 只呈现操作系统可核实值；每个扫描任务沿用 `memory_mb` 通过 POSIX `RLIMIT_AS` 限制虚拟地址空间，这不等同 RSS 上限。取消和超时保留为非完成任务状态。Worker 将已完整验证的最终报告清单原子持久化；重启只恢复其任务身份和 JSON/Markdown 哈希均通过的最终提交检查点，待取消优先。另增加 completed detector 分片检查点：每次重试仍重新读取固定 Git 源码并重建 AST、索引和共享事实，再以 repository/commit/snapshot/profile/provenance、完整 SourceUnit 清单、共享事实摘要、detector ID/version/实现文件 SHA、required facts、支持语言和 engine SHA 验证缓存。仅 detector execution status 为 completed 的规范化结果可保存；报告覆盖侧车仍需完整匹配，partial 保持 partial，failed/blocked 不会缓存。条目是带 SHA-256 的 JSON，原子替换并 fsync，单条不超过 16 MiB；损坏、版本/身份不符或读取异常时重新运行 detector。解析状态、文件覆盖计数、诊断源哈希与证据绑定均在加载时复核。定向集成验证为 15 passed、4 subtests passed（见 `experiments.json`）；该夹具只验证续跑正确性，未测量固定语料收益。源读取和解析仍需从头执行，CPU/内存硬资源限制仍按运行环境能力如实呈现。
- **P5 Agent 调查**：候选按未解决 evidence obligation 数、严重性和固定 ID 排序；只将完全相同 report/commit/candidate/source 绑定的候选标同组并保留原始 ID。对已知 source obligation kind 确定性排序只读动作建议；未知类型不建议动作，R2 只对未解决项重排。工具结果缓存限定于一次已授权任务，并纳入 commit、report SHA、candidate、参数和 policy version；错误、超限或截断结果不缓存。重复模型 tool request 可复用原始只读结果，但不增加原工具步数上限，也不扩展授权。

## 验证

P2 结果缓存接入后的最新定向回归：

```bash
/tmp/ohscanner-a-line-ci-venv/bin/python -m pytest -q \
  tests/test_incremental_result_cache.py tests/test_incremental_scan_equivalence.py \
  tests/test_incremental_plan.py tests/test_ast.py tests/test_ast_cache.py \
  tests/test_ohscanner_m2.py tests/test_fact_providers.py tests/test_resource_profiles.py \
  tests/test_cpu_quota.py tests/test_worker_concurrency.py tests/test_agent_workflow.py
```

175 passed、24 subtests passed；完整输出在 `validation_p2_targeted_latest.log`。完整 `pytest tests` 重跑得到 1881 passed、16 skipped、5 failed（含两项 subtests）；5 项失败均为既有 CVE fixture 测试通过 Git 读取固定 Blob 时，嵌套 checkout 的 `.git` worktree 元数据指向不存在的父仓库路径 `D:/openHarmonyScanner/CyberSecurity-Innovation-Audit/.git/worktrees/...`。没有把它们当作通过，记录见 `validation_p2_result_cache_latest.log`。Windows 系统 Python 及默认 WSL Python 的依赖不完整；该全量结果使用项目已配置的 `/tmp/ohscanner-a-line-ci-venv`。

随后将结果缓存容量统计改为一次目录扫描加增量记账，以避免冷写入时逐文件遍历目录；该改动后的 P2 定向回归为 11 passed（`test_incremental_result_cache.py`、`test_incremental_scan_equivalence.py`、`test_incremental_plan.py`），`compileall` 通过。11 组件冷/热对照也在这次修正后成功完成。完整 175 项测试未在这项微优化后全部重跑。

Workbench 增量基线 API/UI 集成后的后端回归为 94 passed、1 skipped；其中固定基线预览、workflow SHA 绑定、Worker 透传和报告 fallback 的定向回归为 12 passed。前端 `tsc --noEmit && node build.mjs` 与 69 项 UI 测试通过；日志分别见 `validation_p2_api_latest.log`、`validation_p2_frontend_latest.log`。基线仍不使扫描自动缩小到变更文件；依赖不完整时完整扫描 head。

此前 P4 checkpoint 后的 221 passed / 1 skipped 是本次 P2 cache 变更前的历史回归，不代表本轮完整回归通过。

已通过：

```text
python -m pytest tests/test_workbench.py tests/test_agent_workflow.py tests/test_incremental_plan.py tests/test_incremental_scan_equivalence.py tests/test_resource_profiles.py tests/test_worker_concurrency.py tests/test_fact_providers.py tests/test_cpu_quota.py tests/test_ast.py tests/test_ast_cache.py tests/test_ohscanner_m2.py
221 passed, 1 skipped, 24 subtests passed
npm run build
tsc --noEmit && node build.mjs
npm test
68 passed
git diff --check
```

包含本轮 P5/P3 最新改动的完整集成回归为 218 passed、1 skipped、22 subtests passed，记录见 `validation_full_p3p5_latest.log`。较早的完整回归仍保留在 `validation_full_latest.log`。最新定向回归为 137 passed、19 subtests passed。前端 `npm run build`（TypeScript 检查 + 生产构建）通过，`npm test` 68 passed。Windows 下早期轻量子集为 41 passed。测试没有跳过扫描解析或关闭 detector。

## 复现与证据文件

- 固定语料 manifest：`benchmarks/perf_scale_corpus_2026-10-10.json`
- E2 增量 manifest 与 11 个 base 对象校验：`E2_parent_objects/perf_scale_corpus_with_base_20261010.json`、`E2_parent_objects/materialized_base_evidence.json`
- E2 同环境 E0 / ext4 冷 / ext4 热原始汇总、逐组件 JSON/log、Markdown 与签名等价检查：`E2_fixed_corpus/`
- E2 汇总和逐组件原始文件 SHA-256 清单：`E2_fixed_corpus/SHA256SUMS.txt`（生成后已逐项校验）
- 原环境、命令和阶段指标细节：`outputs/reports/perf_ast_cache_stagecpu_20261021/README.md`
- E0 原始汇总与 11 组件 JSON/log：`E0_no_cache.json`、`E0_components/`
- E3 冷缓存汇总与组件 JSON/log：`E3_cold_cache.json`、`E3_cold_components/`
- E3 热缓存汇总与组件 JSON/log：`E3_hot_cache.json`、`E3_hot_components/`
- E1/E2/E4 实验状态与原始元数据，以及 P4 最终报告恢复检查点：`experiments.json`
- E4 离线 Agent 调度 helper 复现记录：`scripts/perf_agent_scheduler_fixture.py` → `E4_offline_scheduler.json`；不代表真实模型实验
- 汇总表（含原始实验与 P5 设计更新、P3 当前代码复测及 P2/E2 固定语料对照页）：`OHScanner_Efficiency_E0-E4_20261021.xlsx`
- P2 双提交单文件缓存验证：`p2_result_cache_fixture/comparison.json`、`p2_result_cache_fixture/*/report.json`
- P2 固定 11 组件 detector-result cache 冷/热对照：`p2_corpus_result_cache/README.md`、E0/E3 JSON 和逐组件 `*_components/`；Excel 页“P2 fixed corpus”
- P2 Workbench API/UI 固定基线提交：`validation_p2_api_latest.log`、`validation_p2_frontend_latest.log`
- P3 当前代码三轮实验和结果等价：`p3_facts_current/README.md`、`p3_facts_current/p3_summary.json`、`p3_facts_current/E0_no_cache*.json`、`p3_facts_current/E3_cold_cache*`、`p3_facts_current/E3_hot_cache*`

重现 E0/E3 的具体命令位于上述阶段指标 README；E2 固定语料复现命令与精确 parent 来源记录位于 `experiments.json` 和 `E2_parent_objects/`。E1 只作为风险夹具，不作为可接受的完整扫描方案。


### P4 中途恢复复核

新增 detector shard checkpoint 后的定向集成回归为 15 passed、4 subtests passed；覆盖冷/热分片等价、engine SHA 变化、坏 JSON 回退、failed/blocked 不缓存、partial 状态保留以及 Workbench 固定基线边界。当时的相关 P2–P5 回归为 48 passed、9 subtests passed；该阶段结果已由下方最终综合回归更新，完整命令保存在 `experiments.json`。Windows Python 缺少 `fcntl`，验证通过项目 WSL 环境 `/tmp/ohscanner-a-line-ci-venv` 执行。未运行固定 11 组件的 detector checkpoint 性能实验，因此没有用夹具推导总体加速或资源收益。

## 最终综合回归（2026-10-21）

对 P2–P5 相关代码运行综合回归：`218 passed, 1 skipped, 22 subtests passed`，仅有一条 Starlette/httpx 弃用提示。覆盖 detector 检查点、增量规划与全量等价、事实提供器、资源模式、CPU 配额探测、Worker 并发、Workbench API 与 Agent workflow。之后还完成固定语料 E2 冷/热对照；结果与复核命令见下节。

## P2 实际 M2 detector 固定语料对照

为验证真实第一方执行成本，新增两个 M2 研究 detector 的固定语料对照：`ohscanner.cpp.lifetime@0.4.0` 与 `ohscanner.cpp.shared_ptr_race@0.5.1`，同一 manifest、同一 11 个固定 head、9,508 个源码文件。三个实验组是 E0 无缓存、AST-only 热缓存控制、E3 AST 与 detector per-file cache 冷/热。缓存目录在 WSL2 原生 ext4（`/home/kali/.cache/ohscanner/perf_m2_20261021`），报告和原始日志在 `p2_m2_fixed_corpus/`。E0、AST-only、E3 cold、E3 hot 的逐组件 result signature 均与 E0 的 11/11 组件一致；每轮都是 63 个 candidate diagnostics，整体状态 11/11 `completed_with_limitations`，已验证漏洞数为 0。

| 组 | 墙钟 | 进程 CPU | AST 解析 CPU | Detector 阶段墙钟 | Parser 调用文件数 | AST cache hit | Detector result hit / miss |
|---|---:|---:|---:|---:|---:|---:|---:|
| E0 无缓存 | 134.831 s | 100.331 s | 40.325 s | 54.314 s | 9,508 | 0 | 0 / 0 |
| AST-only 热缓存 | 76.571 s | 55.408 s | 1.444 s | 45.808 s | 201 | 9,307 | 0 / 0 |
| E3 冷缓存 | 142.546 s | 106.608 s | 37.416 s | 64.015 s | 9,478 | 30 | 0 / 13,144 |
| E3 热缓存 | 53.880 s | 19.601 s | 1.437 s | 18.907 s | 201 | 9,307 | 13,037 / 107 |

E3 热缓存相对 E0 的总墙钟为 -60.0%、进程 CPU 为 -80.5%；相对 AST-only 控制，E3 热缓存总墙钟再降 29.6%、CPU 再降 64.6%。这支持“缓存对这两个逐文件 M2 research detector 的当前实现有实测成本收益”，不代表产品全仓漏洞覆盖或准确率。冷跑因缓存写入成本，墙钟较 E0 高 5.7%。每个结果仅保存完整的单文件 adapter 执行；107 个未完成或不可安全缓存的结果仍重新运行。全部源码 inventory、head AST 和共享事实仍完整建立；E2 的依赖闭包扫描仍然未实际收窄范围。

缓存实现还纳入整个 `src/ohscanner` Python 源包的 SHA-256 指纹，并把缓存初始化/读取改为单次文件元数据检查；缓存 payload 使用原子替换但不 `fsync`，因为它是可丢弃优化数据，崩溃时丢失只会导致 miss。固定语料中所有 11 个 head commit 当前均精确匹配 manifest，但 11 个 parent commit 对象仍均不可用，所以完整 E2 base→head 对照尚未执行。之前 `/mnt/d` 上的中断 cache I/O 尝试原始分片日志保留在同目录，未纳入上述实测汇总。

### E1 变更文件风险样本

E1 已用三文件合成 Git 样本执行，只用于显示“仅扫变更文件”的漏覆盖风险，不是固定 11 组件性能数据。只改动 `src/safe.cpp` 的注释后，全量 M2 扫描保留 3 个未变文件候选；只扫描变更路径得到 0 个候选，漏掉 3 个。全量报告状态为 `completed_with_limitations`；E1 子集报告自身状态为 `completed`，但只覆盖 1 个变更文件、未检查另外 2 个文件，因此不能解释为全仓扫描完整。报告、两份原始 JSON 和命令见 `p2_m2_fixed_corpus/E1_changed_only_fixture/`。固定语料 E1 墙钟/CPU 未测，保持 unknown。
