# OHScanner 组件级性能与规模实测

> 由 `scripts/perf_scale_scan.py` 生成。语料清单见 `benchmarks/perf_scale_corpus_2026-10-10.json`（固定完整 commit SHA，可复现）。
> 测量的是**平台成本**：固定 Git 对象读取 + 逐文件 tree-sitter AST 解析 + 检测器调度，
> 使用当前唯一允许登记的非安全示例插件 `ohscanner.example.cpp.copy-calls`。
> **这不是漏洞检出能力评测**；`completed` 状态不代表组件安全。

## 汇总

- 组件数：**11**（共 11 条清单，失败 0）
- 扫描源文件：**9,508**
- 扫描源码字节：**107,087,947**
- 语料 C/C++ 总行数（全部源文件，非扫描子集）：**2,618,176**
- 累计墙钟：**113.64 s**（单进程串行执行）
- 单次进程峰值 RSS 上界：**265.7 MB**
- 平均吞吐：**84 files/s**、**0.94 MB/s**
- 分片测量的组件：**1**（整树超出 `M1 bounded scope`，按顶层目录分片）

## 逐组件明细

| 组件 | 固定提交 | 分片 | 扫描文件 | 扫描字节 | 树内 C/C++ 行 | 墙钟 (s) | 峰值 RSS (MB) | files/s | parse 完整/部分 | 检测器 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| communication_ipc | `bbb92dbb2f52` | 1 | 697 | 8,047,192 | 145,562 | 6.48 | 103.0 | 108 | 442/218 | partial |
| inputmethod_imf | `7777cba9eb19` | 1 | 698 | 6,150,477 | 154,966 | 6.34 | 101.3 | 110 | 522/152 | partial |
| multimedia_camera_framework | `085a5d0e2dc1` | 1 | 1,696 | 17,258,181 | 409,298 | 16.03 | 237.6 | 106 | 1290/321 | partial |
| multimedia_player_framework | `9f9a285ff489` | 1 | 1,773 | 17,305,015 | 439,198 | 17.78 | 245.3 | 100 | 1087/686 | partial |
| notification_common_event_service | `aaaaf6d10aa8` | 1 | 293 | 3,305,017 | 85,467 | 2.83 | 61.8 | 104 | 215/69 | partial |
| resourceschedule_background_task_mgr | `cff2ff475e38` | 1 | 284 | 2,214,672 | 52,326 | 2.34 | 51.2 | 121 | 229/44 | partial |
| security_access_token | `17d88bfb36be` | 1 | 1,249 | 8,798,780 | 235,117 | 10.41 | 132.3 | 120 | 1046/198 | partial |
| telephony_call_manager | `6638d1b37f27` | 1 | 513 | 5,677,034 | 141,361 | 5.18 | 90.8 | 99 | 379/132 | partial |
| update_updateservice | `e4942a33cc5e` | 1 | 238 | 888,385 | 22,891 | 3.30 | 34.8 | 72 | 205/32 | partial |
| window_window_manager | `8b0d8fe1b973` | 7 | 1,944 | 35,876,163 | 884,210 | 41.13 | 265.7 | 47 | 1107/810 | partial |
| c_utils_pinned_m2 | `b807d3dadb7d` | 1 | 123 | 1,567,031 | 47,780 | 1.81 | 48.1 | 68 | 93/30 | partial |

## 语料构建与复现

语料是固定到完整 commit SHA 的 OpenHarmony 组件 `--depth=1` 克隆（SSH；该 commit 的全部 blob 本地齐备，因此扫描全程离线、不触发任何抓取）：

```bash
git clone --depth=1 git@github.com:openharmony/<component>.git
git -C <component> rev-parse HEAD   # 必须等于清单中的 commit
```

11 条组件与其完整 SHA 记录在 `benchmarks/perf_scale_corpus_2026-10-10.json`。一键复跑：

```bash
python scripts/perf_scale_scan.py \
  --manifest benchmarks/perf_scale_corpus_2026-10-10.json \
  --json-out outputs/reports/perf_scale_scan.json \
  --md-out docs/testing/ohscanner_performance_scale.md
```

测量方式：每个组件在独立子进程中执行 `python -m src.cli ohscan-run`，由一个**最小的**父进程记录墙钟与 `ru_maxrss`。用最小父进程是必要的——Linux 上 fork 出的子进程在 exec 前共享父进程的常驻页，若从本脚本（它在统计行数时会缓冲整份源码）直接测量，得到的会是父进程的内存而不是扫描器的内存。数值已用 GNU `time -v` 抽样交叉核对。

## 限制

- 语料是**组件级**（单次约 0.2k–2k 源文件），不是 OpenHarmony 千万行整树；整树规模需另行测量。
- 执行是**同进程串行**的；尚无并行、增量缓存或硬超时/资源隔离。
- `-partial` 解析文件计入未分析（`unexamined`），因为当前无宏展开与完整 include 上下文。
- 峰值 RSS 为单个 CLI 进程的 `ru_maxrss`；未测多进程并发下的总内存。
- 分片组件的墙钟是各分片之和，含每片一次 Python 启动与 JSON 写出的固定开销，因此其 files/s 会低于同等规模的单次扫描，不能与单次运行的组件直接比吞吐。
- `window_window_manager` 整树的源文件总量超过 `M1 bounded scope` 上限而无法单次扫描；这是当前实现的真实边界，分片是绕过方式而非其消失。
- 上述耗时包含 Python 解释器启动与 JSON 报告写出，属于端到端口径。
