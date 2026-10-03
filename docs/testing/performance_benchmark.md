# 性能 Benchmark（组件级）

> 日期：2026-10-04
> 环境：Ubuntu 22.04 WSL2；Python 3.10；tree-sitter 0.26 + tree-sitter-c/cpp 已接入。
> 方法：同一进程内 `time.perf_counter` 计时、`resource.getrusage(RUSAGE_SELF).ru_maxrss` 测峰值 RSS。
> 结论：文本 scanner 约 40k LOC/s、100-200 files/s；AST 解析约 90k LOC/s、400 files/s；峰值内存均低于 25 MB。

## 文本 scanner（src.core.scanner，危险 API 正则 + 启发式函数上下文）

| 目标 | 文件 | 行 | 候选 | 耗时 | 峰值 RSS | files/s | LOC/s |
|---|---|---|---|---|---|---|---|
| cJSON 全仓 | 99 | 22,377 | 49 | 0.507s | 14.4 MB | 195 | 44,133 |
| c_utils | 122 | 47,448 | 0 | 1.166s | 14.4 MB | 105 | 40,679 |

## AST 解析（src.parser.ast，tree-sitter，C 语法）

| 目标 | 文件 | 行 | 函数 | 调用 | 耗时 | 峰值 RSS | files/s | LOC/s |
|---|---|---|---|---|---|---|---|---|
| cJSON 全仓 | 99 | 22,474 | 1040 | 4315 | 0.248s | 22.8 MB | 400 | 90,702 |

## 关键观察

1. **c_utils 0 文本候选**：其 C++ 代码用 `memcpy_s` / `std::string` / `std::vector` 等安全 API，而非裸 `strcpy/memcpy/sprintf`。这印证第一方基础库代码质量较高，也说明"文本危险 API 规则"在第一方组件上召回率有限——需要 AST + 数据流 + 生命周期/并发分析才能覆盖（如 singleton.h UAF 这种并发数据竞争，文本规则完全命中不到）。
2. **AST 比文本 scanner 更快且更准**：tree-sitter 的 C 核心极高效（90k LOC/s vs 44k LOC/s），且天然排除注释/字符串误报、提供精确参数与函数/变量索引。这支持后续把 scanner 从文本正则升级到 AST 驱动的方向。
3. **内存占用低**：两者峰值均 < 25 MB，适合大规模扫描。

## 限制

- 这是**组件级** benchmark（22k-47k 行），不是 OpenHarmony 整树规模（千万行级）。整树性能需后续在真实 OpenHarmony 源码树（或更多组件）上测。
- 文本 scanner 的峰值 RSS 两个任务在同一进程内跑，`ru_maxrss` 取进程峰值，故都显示 14.4 MB。
- 尚未测数据流/污点/生命周期分析、并行/多进程、增量缓存等阶段的性能。
- 尚未测准确率/召回率（需要 ground truth 集，见 c_utils_singleton_uaf_groundtruth.md）。
