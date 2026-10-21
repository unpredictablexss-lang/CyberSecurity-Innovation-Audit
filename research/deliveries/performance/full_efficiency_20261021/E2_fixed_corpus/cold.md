# OHScanner 组件级性能与规模实测

> 由 `scripts/perf_scale_scan.py` 生成。语料清单见 `research/deliveries/performance/full_efficiency_20261021/E2_parent_objects/perf_scale_corpus_with_base_20261010.json`（固定完整 commit SHA，可复现）。
> 测量固定 Git 对象读取、AST/事实构建和所选检测器运行成本；结果不是准确率或产品安全结论。
> 使用检测器：`ohscanner.cpp.lifetime, ohscanner.cpp.shared_ptr_race`。
> **这不是漏洞检出能力评测**；候选和 `completed` 状态均不证明漏洞或安全。

## 汇总

- 组件数：**11**（共 11 条清单，失败 0）
- 扫描源文件：**9,508**
- 扫描源码字节：**107,087,947**
- 语料 C/C++ 总行数（全部源文件，非扫描子集）：**2,618,176**
- 累计墙钟：**443.77 s**（单进程串行执行）
- 单次进程峰值 RSS 上界：**328.3 MB**
- CPU 时间合计：**126.15 s**
- cgroup CPU 配额与平均配额利用率见逐组件 JSON；unknown 表示当前环境未暴露可验证限额，未用逻辑 CPU 数替代。平均利用率使用进程 CPU 核秒 /（墙钟 × 限额核数），不是瞬时系统 CPU 百分比。
- 阶段时间和解析/缓存计数见逐组件性能 JSON；计时不改变扫描覆盖状态。
- 缓存命中：**30**；实际重新解析：**9478.0**。
- AST 缓存 hit rate：**0.3%**；缓存容量与实际字节数见逐组件 JSON。
- Opt-in source-only detector result cache hit/miss：**0 / 13144**；该计数不表示增量覆盖，未启用时为 0/0。
- 解析/前端、事实构建、检测器、报告阶段 CPU 计时以及源码读取子进程 CPU（平台支持时）见逐组件 JSON；unknown 表示平台未提供可靠读数。
- 平均吞吐：**21 files/s**、**0.24 MB/s**
- 分片测量的组件：**1**（整树超出 `M1 bounded scope`，按顶层目录分片）

## 逐组件明细

| 组件 | 固定提交 | 分片 | 扫描文件 | 扫描字节 | 树内 C/C++ 行 | 墙钟 (s) | 峰值 RSS (MB) | files/s | parse 完整/部分 | 检测器 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| communication_ipc | `bbb92dbb2f52` | 1 | 697 | 8,047,192 | 145,562 | 30.12 | 128.6 | 23 | 453/244 | partial |
| inputmethod_imf | `7777cba9eb19` | 1 | 698 | 6,150,477 | 154,966 | 31.63 | 132.4 | 22 | 539/159 | partial |
| multimedia_camera_framework | `085a5d0e2dc1` | 1 | 1,696 | 17,258,181 | 409,298 | 89.19 | 301.5 | 19 | 1335/361 | partial |
| multimedia_player_framework | `9f9a285ff489` | 1 | 1,773 | 17,305,015 | 439,198 | 73.69 | 307.4 | 24 | 1087/686 | partial |
| notification_common_event_service | `aaaaf6d10aa8` | 1 | 293 | 3,305,017 | 85,467 | 14.38 | 84.4 | 20 | 221/72 | partial |
| resourceschedule_background_task_mgr | `cff2ff475e38` | 1 | 284 | 2,214,672 | 52,326 | 14.56 | 71.0 | 20 | 237/47 | partial |
| security_access_token | `17d88bfb36be` | 1 | 1,249 | 8,798,780 | 235,117 | 53.26 | 176.2 | 23 | 1048/201 | partial |
| telephony_call_manager | `6638d1b37f27` | 1 | 513 | 5,677,034 | 141,361 | 23.06 | 124.8 | 22 | 383/130 | partial |
| update_updateservice | `e4942a33cc5e` | 1 | 238 | 888,385 | 22,891 | 10.45 | 50.4 | 23 | 206/32 | partial |
| window_window_manager | `8b0d8fe1b973` | 7 | 1,944 | 35,876,163 | 884,210 | 96.39 | 328.3 | 20 | 1122/822 | partial |
| c_utils_pinned_m2 | `b807d3dadb7d` | 1 | 123 | 1,567,031 | 47,780 | 7.03 | 62.4 | 18 | 94/29 | partial |

## 语料构建与复现

语料由 manifest 中的完整 commit SHA 固定。此脚本不会 clone/fetch，也不会切换目标仓库；运行前必须确认目标目录的 commit 与所需 blobs 已在本地，否则扫描失败，不会自动联网补取：

```bash
git -C <targets-root>/<repo_dir> cat-file -e <full-sha>^{commit}
git -C <targets-root>/<repo_dir> rev-parse <full-sha>^{tree}
```

11 条组件与其完整 SHA 记录在 `research/deliveries/performance/full_efficiency_20261021/E2_parent_objects/perf_scale_corpus_with_base_20261010.json`。一键复跑：

```bash
python scripts/perf_scale_scan.py \
  --manifest research/deliveries/performance/full_efficiency_20261021/E2_parent_objects/perf_scale_corpus_with_base_20261010.json \
  --json-out outputs/reports/perf_scale_scan.json \
  --md-out benchmarks/组件性能规模实测.md
```

测量方式：每个组件在独立子进程中执行 `python -m src.cli ohscan-run`，由一个**最小的**父进程记录墙钟与 `ru_maxrss`。用最小父进程是必要的——Linux 上 fork 出的子进程在 exec 前共享父进程的常驻页，若从本脚本（它在统计行数时会缓冲整份源码）直接测量，得到的会是父进程的内存而不是扫描器的内存。CPU 与 RSS 来自平台支持时的 `resource.getrusage`；不可用时记为 unknown。

## 限制

- 语料是**组件级**（单次约 0.2k–2k 源文件），不是 OpenHarmony 千万行整树；整树规模需另行测量。
- 执行是**同进程串行**的；轻量缓存仅覆盖固定 Git Blob 的 C/C++ 共享 AST 大纲，不覆盖检测器专用解析、跨文件 facts 或编译语义；硬超时/资源隔离仍未实现。
- `-partial` 解析文件计入未分析（`unexamined`），因为当前无宏展开与完整 include 上下文。
- 峰值 RSS 为单个 CLI 进程的 `ru_maxrss`；未测多进程并发下的总内存。
- 分片组件的墙钟是各分片之和，含每片一次 Python 启动与 JSON 写出的固定开销，因此其 files/s 会低于同等规模的单次扫描，不能与单次运行的组件直接比吞吐。
- `window_window_manager` 整树的源文件总量超过 `M1 bounded scope` 上限而无法单次扫描；这是当前实现的真实边界，分片是绕过方式而非其消失。
- 上述耗时包含 Python 解释器启动与 JSON 报告写出，属于端到端口径。
