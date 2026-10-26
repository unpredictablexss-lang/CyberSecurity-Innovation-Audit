# OHScanner AST 缓存：实施、验证与性能对照

实验日期：2026-10-21；目标分支 `main`；源码提交 `4f75a65775b202b8220a208ebdb50fdb5c8dbb4d`。固定语料定义见 [manifest.json](manifest.json)。作品报告工作簿：[OHScanner_Performance_Comparison_20261021.xlsx](../../../../outputs/01a15cb9-f7f1-7a21-abe6-0dfa31f90474/OHScanner_Performance_Comparison_20261021.xlsx)。

## 目标与验收

在固定 Git 源码重复扫描中，降低共享 C/C++ 轻量 AST 的重复解析 CPU 成本，产出阶段耗时和可复核的冷/热/无缓存对照。缓存身份需约束在可验证 Blob、语言、解析器/grammar 及 AST 规范版本。缓存失效或损坏时重新解析。缓存前后结果身份、候选与定位、解析/检测器状态和覆盖相同；不得把 partial、failed 或 blocked 伪装成完成。

## 实施前差距

- `frontend.index_sources` 原先对每个 C/C++ Blob 调用 `parse_source`，没有 AST 摘要复用。
- 执行报告未提供完整的源码读取、解析、检测器和报告阶段耗时；基准脚本缺少 CPU 阶段和缓存统计。
- 仓库有固定 11 组件语料，但旧 2026-10-14 记录绑定其它源码提交、环境指纹不完整，不能直接作为新实现的同条件前后比较。

## 设计、输入边界与改动文件

缓存单文件 `AstIndex` 摘要：语言、complete/partial、parse issues、functions、calls、variables。身份包括按源字节重算验证的真实 Git Blob OID、源码 SHA-256、语言、cache schema、Tree-sitter 与 C/C++ grammar 包版本、parser spec 和归一化规范版本。缓存 JSON 校验 identity 与摘要。

当前轻量 parser 只解析单文件语法；不缓存检测器结果、跨文件符号/仓库 facts、头文件/include、宏展开、编译参数、build profile。若未来解析使用这些输入，必须扩展缓存键或绕过。归档成员、无效 OID、未知语言/版本绕过；坏 JSON、校验失败、读取错误时重新解析；写入失败仅损失收益。partial 状态原样往返；解析失败保持 failed；没有完整适用 AST 时检测器保持 blocked。

- 新增 `src/ohscanner/ast_cache.py`。
- 修改 `src/ohscanner/frontend.py`、`src/ohscanner/indexing.py`：缓存共享 AST 大纲，记录解析计时和计数。
- 修改 `src/ohscanner/execution.py`、`src/cli/main.py`：阶段计时与可选 `--ast-cache-dir`。
- 修改 `scripts/perf_scale_scan.py`：外部墙钟、CPU/RSS、阶段统计、缓存计数和结果签名比较。报告中明确脚本不 clone/fetch。
- 新增 `tests/test_ast_cache.py`：冷/热、Blob/语言/parser 版本失效、坏数据回退、无效/归档 Blob 绕过、partial/failed/blocked 状态保留、候选/覆盖等价。

## 实施步骤与验证

1. 检查工作区，在现有 `main` checkout 直接开发；保留已有未提交改动和 `worktrees/`，未 reset/clean、未创建 worktree/功能分支/PR。
2. 先加阶段指标和基准输出，再接入可选、版本化、best-effort 的单文件 AST 缓存。
3. 运行针对性验证：

   ```bash
   python -m pytest tests/test_ast.py tests/test_ast_cache.py tests/test_ohscanner_m1.py tests/test_ohscanner_m2.py -q
   python -m compileall -q src scripts
   python -m src.cli ohscan-run --help
   git diff --check
   ```

   Ubuntu WSL2 Python 3.12.3 下：**44 passed，14 subtests passed**；compileall、CLI help、`git diff --check` 通过。缓存测试明确验证坏缓存回退后 partial-only 输入的 detector coverage 仍为 blocked。原计划中的 `tests/test_runner_applicable_units.py` 不存在，适用性断言位于 `tests/test_ohscanner_m2.py`。
4. 对 11 个 manifest commit 做无缓存、空 AST 缓存、热缓存对照；再增加三轮重复实验。逐组件核对完整结果签名、状态和覆盖。原始 JSON、Markdown、每组件报告与日志保存在 `raw_runs/`。
5. 将技术方案、逐组件记录、环境、指标分布和限制整理进 Excel 工作簿。

## 三轮重复实验结果

三轮使用同一提交、11 个固定 commit 和相同扫描顺序（无缓存→空 AST 缓存→热缓存）。每轮冷缓存目录新建且开始为空；操作系统文件页缓存未清空，因此“冷”仅指 AST 缓存冷，不代表冷磁盘。

| 指标 | 无缓存中位数（范围） | 冷缓存中位数（范围） | 热缓存中位数（范围） | 热缓存相对无缓存中位数 |
|---|---:|---:|---:|---:|
| 外部进程墙钟 | 66.198 s (65.927–67.622) | 116.283 s (116.180–116.902) | 45.835 s (43.215–46.300) | -30.8% |
| 外部进程 CPU | 47.795 s (47.595–48.894) | 60.854 s (60.546–62.029) | 15.933 s (15.505–15.983) | -66.7% |
| AST 阶段 | 39.515 s (39.504–40.417) | 41.140 s (40.759–41.761) | 1.698 s (1.676–1.918) | -95.7% |
| 实际解析调用 | 9,508 | 9,478 | 201 | -97.9% |
| 缓存 hit/miss | 0/0 | 30/9,277 | 9,307/0 | — |
| complete/partial/unexamined | 6,725/2,783/2,688 | 完全一致 | 完全一致 | 无覆盖减少 |

空 AST 缓存包含序列化/写入成本，三轮墙钟和 CPU 均高于无缓存；热缓存的改善方向三轮一致。peak RSS 中位数 264,628 KB 到 262,280 KB（约 0.9%），不据此宣称内存改善。

三轮批次环境为 Ubuntu WSL2、Python 3.12.3、Git 2.43.0；Tree-sitter 0.26.0、tree-sitter-c 0.24.2、tree-sitter-cpp 0.23.4。目标仓库副本位于 D: 挂载目录。首批单轮实验在 Kali WSL、Python 3.12.15、Git 2.53.0，目标语料在 Linux 文件系统。两批环境/存储不同，**分别呈现，不能合并统计**。三轮各条件 11/11 组件退出码为 0；结果签名与状态/coverage 一致；每组 9,508 文件、107,087,947 字节、complete=6,725、partial=2,783、unexamined=2,688，整体状态 `completed_with_limitations`。

范围限制：使用 `ohscanner.example.cpp.copy-calls` 非安全示例检测器。零诊断不是无漏洞或准确率结论，也不等于 ABCD 全量漏洞扫描。三轮样本量为 3，取中位数与范围，不是置信区间或跨机器性能保证。

## 复现与归档

`raw_runs/repeated_runs/run_replicates.sh` 是三轮执行脚本，`verify_corpus.py` 按完整 commit/tree SHA 核验本地副本。目标目录在 `D:\openHarmonyScanner\tmp\perf-corpus-repeat-20261021`（WSL 路径 `/mnt/d/openHarmonyScanner/tmp/perf-corpus-repeat-20261021`）。每轮 JSON/Markdown、组件级报告和日志、AST 缓存均归档；`replicate_summary.json` 可用同目录 `summarize_replicates.py` 重算。首批报告 JSON/Markdown 在 `raw_runs/` 根目录。历史 2026-10-14 的 109.12s/177.78s 未用于新百分比比较。

## 未实施方向、风险与回退

跨文件增量分析、并行/CPU 配额改造、跨组件共享 facts 和 Agent 调度不属于本次实现。回归时可移除 `--ast-cache-dir`，扫描恢复无缓存解析；必要时回退 `frontend.py`/`indexing.py` 缓存接线及 CLI 参数，保留报告、日志和测试证据。升级 parser/grammar/schema/规范时需更新版本或禁用缓存；增加头文件、宏、编译 profile 或跨文件依赖时，先扩展 key 或绕过。任何缓存故障都不能绕过解析或降低覆盖。

## 技术文档补充项：阶段 CPU 与缓存运维

对组长技术文档的 P0/P1 条款逐项复核后，补齐了阶段 CPU 时间和缓存容量/清理接口：

- 阶段记录包括源码读取、AST 解析、frontend、facts 构建、检测器执行、报告构建、Markdown 渲染和 JSON 序列化的墙钟/进程 CPU；源码 Git 读取另记录可用的子进程累计 CPU。平台或计时源不可用时记 `null/unknown`，不推算。
- 新增 `ast_cache_setup_seconds` / `ast_cache_setup_cpu_seconds`，显式暴露缓存目录启动检查和容量维护成本；报告构造不再第二次遍历缓存文件来统计体积，使用初始化测量及本进程的增量计数。
- JSON 报告另记录报告文件临时写入与原子替换耗时（`report_file_write_seconds`，兼容字段 `report_write_seconds`）；该值不包含极小的定宽计时字段回填。历史三轮运行没有此后补字段，不能追溯填数；新的扫描运行会写入该值。
- 峰值 RSS 由性能脚本在受支持平台采集；独立扫描进程由外部基准器计时和取峰值，阶段进程 CPU 使用 `process_time()`。子进程 CPU 只在 `resource.getrusage(RUSAGE_CHILDREN)` 可用时记录。
- AST 缓存缺省上限为 512 MiB，可由 `--ast-cache-max-bytes` 配置。超过上限时按缓存项修改时间从旧到新淘汰；超过上限的单个条目不保存。缓存统计包括字节数、上限、命中率、命中/未命中/无效/绕过、写入、淘汰、超大条目、清理数量与错误。
- 显式清理命令示例：`python -m src.cli ohscan-run ... --ast-cache-dir outputs/ast-cache --clear-ast-cache`。缺少缓存目录时 CLI 拒绝清理；清理只处理缓存目录顶层、名称符合本缓存格式的 JSON/临时文件，保留其它文件。
- 容量淘汰和清理仅影响性能，不改变解析与扫描路径；读取、校验、写入或清理异常都不能把未解析文件当作已完成。坏缓存按未命中重新解析。

注意：`parse_files` 是 frontend 实际调用解析器的文件数，包含缓存没有覆盖的 JS/TS/ArkTS 解析；AST 缓存 hit/miss 统计仅针对可缓存的 C/C++ 单文件摘要。因此热缓存的 9,307 次命中与 201 次解析调用不是同一个分母；在固定语料中其差额主要来自未由本缓存接管的其它语言前端。

验证补充：新增缓存容量淘汰、超大项不落盘、显式清理并重热身、阶段 CPU、JSON 序列化和文件发布计时报告断言。目标测试集现为 **47 passed，14 subtests passed**；`compileall` 与 CLI help 通过。Windows Git 对该 Windows worktree 内部 `.git` 指针可执行 `git diff --check`；WSL Git 无法解析 Windows worktree 的 `.git` 指针，因此 WSL 中的 `git diff --check` 未作为验证结果。

文档实施范围：P0 阶段指标和 P1 单文件版本化缓存、容量限制、清理、命中率已实现。P2 依赖感知全仓增量、P3 跨文件共享 facts、P4 并行/CPU 配额调度、P5 Agent 调度未实现，符合本任务明确的收尾范围。上方三轮性能数值来自归档原始记录；后补阶段字段没有回填成历史实测值。

## 后补阶段指标验证尝试

2026-10-21 在同一 Ubuntu WSL/D: 挂载固定语料上另起目录做一轮补采集。无缓存 11/11 组件成功；冷缓存 11/11 组件成功且与无缓存签名/覆盖对比通过。冷跑窗口墙钟远高于此前三轮（主要体现在大型组件分片和缓存文件写入）。热缓存尝试运行期间，缓存组件端到端出现约 30–54 秒/组件的异常开销，而单个 report 内可见的 AST/frontend 阶段明显更短。检查发现缓存构造时为容量校验遍历目录，报告生成时又完整遍历一次统计大小；热运行被中止以避免继续花费时间。该中止批次不构成完整冷/热对照，不能据此报告整体提速或退化比例；不完整运行日志和已生成组件 JSON 留在 `outputs/reports/perf_ast_cache_stagecpu_20261021/` 供排查。

随后移除了报告阶段的第二次目录统计、将目录遍历改为 `os.scandir` 单次文件 stat，并新增缓存初始化墙钟/CPU字段。最终补跑见 `outputs/reports/perf_ast_cache_stagecpu_20261021/README.md`：原生 Linux 缓存目录上的匹配冷/热完成了 11 组件等价性验证；D: 挂载缓存目录的异常批次仍只作诊断材料，未并入统计。
