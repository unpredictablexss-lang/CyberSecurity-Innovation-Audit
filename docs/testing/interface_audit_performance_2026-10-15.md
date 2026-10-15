# 接口线组件审计的性能与规模实测（2026-10-15）

- 交付件：**#7 性能数据**（`AGENTS.md`：「Publish scan time and scale on real components
  (files, LOC, wall-clock) so the tool's cost is demonstrable」）。
- 被测对象：**接口线自己的组件审计**（`src/ohscanner/detectors/interface/audit.py`），
  走 `IpcInterfaceDetector` 与 `IpcInterfaceCompleteAstDetector` 两趟解析。
- 语料：`perf-corpus/` 里 5 个固定提交的组件（与主线性能清单同一批 `--depth=1` 克隆）。
- 结果：**2,545 文件 / 29.9 MB 源码 / 137.39 s**，单组件峰值 RSS 最高 **1,886 MB**。
- **`validated_vulnerability` 仍为 0**：这是成本测量，不是检出能力评测。

## 0. 一句话结论

在这批真实组件上，接口审计的**吞吐由字节量决定而不是文件数**：逐组件 files/s 从 11.3 到 64.0
（差 5.7 倍），但 MB/s 稳定在 **0.21–0.30**；峰值内存与源码字节的比值更是稳定在 **92×–109×**。
最大的 `window_window_manager`（1,112 文件 / 20.2 MB）**单次单进程**跑了 **98.46 s、峰值 1,886 MB**，
这是当前实现真实的成本画像，也是它最需要被优化的一点。

## 1. 方法

**入口**：`python -m src.ohscanner.detectors.interface.audit`，**每个组件一个独立进程**。

**为什么必须是独立进程**：峰值内存用 `resource.getrusage(RUSAGE_SELF).ru_maxrss` 取，它是
**进程级高水位**。一个进程里连跑多个组件时，后面的组件会继承前面的峰值，报出来的就不是自己的数。
本轮 5 个组件各自单独调用，所以每个数字都是该次审计自身的成本。
（`audit.py` 的 `peak_rss_kb()` 与报告 `limitations` 都把这条口径写明；
若从库内一次性调多个组件，`ru_maxrss` 是运行最大值，这一点已写进限制而不是留给读者猜。）

**口径**：墙钟含 **Python 解释器启动 + JSON/Markdown/清单写出**，属端到端口径。
内存是进程高水位，**是测量值不是上界**。

**测量时点**：2026-10-15；Python 3.10.12、Git 2.34.1、Ubuntu 22.04 WSL2；
`environment` 块随每份 manifest 一起落盘，所以数字不会脱离环境被引用。

## 2. 结果

| 组件 | 固定提交 | 审计文件 | 源码字节 | 完整/部分解析 | 候选 | 墙钟 (s) | 峰值 RSS (MB) | files/s | MB/s |
|---|---|---:|---:|---|---:|---:|---:|---:|---:|
| `communication_ipc` | `bbb92dbb2f52` | 252 | 2,189,480 | 154/97 | 12 | 8.74 | 226.4 | 28.8 | 0.25 |
| `inputmethod_imf` | `7777cba9eb19` | 412 | 3,191,273 | 330/72 | 4 | 10.72 | 312.2 | 38.4 | 0.30 |
| `security_access_token` | `17d88bfb36be` | 550 | 3,484,891 | 489/56 | 3 | 16.05 | 307.0 | 34.3 | 0.22 |
| `update_updateservice` | `e4942a33cc5e` | 219 | 851,345 | 187/31 | 2 | 3.42 | 88.3 | 64.0 | 0.25 |
| `window_window_manager` | `8b0d8fe1b973` | 1112 | 20,206,691 | 811/268 | 14 | 98.46 | 1886.4 | 11.3 | 0.21 |

**合计**：2,545 文件 / 29,923,680 字节 / **137.39 s** / 峰值 **1,886 MB**（18.5 files/s，0.218 MB/s）。

五个组件的 `file accounting closed` 全为 `True`（`files_unaccounted = 0`），
`confirmed_vulnerabilities` 全为 `0`，候选合计 35 条（皆为未验证候选）。
`window_window_manager` 的 14 条候选与 2026-10-15 的逐条复核报告一致。

## 3. 从数字里读出的三条事实

1. **吞吐是字节受限的。** files/s 区间 11.3–64.0，跨度 5.7 倍；而 MB/s 落在 0.21–0.30 的窄带里。
   两个解析器都是逐文件建 AST，所以决定成本的是源码字节。用 files/s 互相比较组件会得出错误结论，
   用 MB/s 才稳定。**报告里两个都给，就是为了不让前一个被单独引用。**
2. **内存约为源码字节的 100 倍。** 五个组件分别是 108× / 103× / 92× / 109× / 98×。
   这个比值稳定得反常（±10%），说明内存占用主要跟着源码总量走，
   而不是跟着候选数或组件类型走——这对容量规划是可直接用的结论。
3. **`window_window_manager` 是当前的规模边界。** 20.2 MB 源码 / 1,112 文件，
   单次单进程 98.46 s、1,886 MB。它在**一个分片内**跑完（未触发 2000 文件 / 32 MiB 上限），
   也就是说这 1.9 GB 不是分片开销，而是单次整树解析本身的占用。

## 4. 与主线示例检测器实测的关系（**不可直接相减**）

主线 2026-10-10 的 `perf_scale_scan.py` 在同一批克隆上测过同一组件，但那是**另一个检测器**
（`ohscanner.example.cpp.copy-calls`）且**文件选择不同**：

| 组件 | 主线（示例检测器） | 本记录（接口检测器） |
|---|---|---|
| `inputmethod_imf` | 6.34 s / 101.3 MB / 698 文件 | 10.72 s / 312.2 MB / 412 文件 |
| `window_window_manager` | 41.13 s / 265.7 MB / 1,944 文件 | 98.46 s / 1,886.4 MB / 1,112 文件 |

两行的**分母都不一样**：主线按顶层目录分片选出文件，接口线按 `PRODUCTION_EXCLUDED_SEGMENTS`
规则只取生产文件（412 与 1,112），两者的文件选择口径不同。
所以**不能做减法说「接口线慢多少倍」**——那会把口径差异算成性能差异。
可以说的只有：接口审计在两趟 AST 解析下，内存占用比单趟示例检测器高一个量级，
这一点与 §3 第 2 条的 100× 比值自洽。

## 5. 本轮改了什么（全在 B 线自有面）

| 文件 | 改动 |
|---|---|
| `src/ohscanner/detectors/interface/audit.py` | 新增 `peak_rss_kb()` 与 `_rate()`；报告新增 `peak_rss_kb` 字段；manifest 新增 `performance` 块（墙钟、峰值 RSS、files/s、bytes/s、口径说明）；渲染首部与 CLI 输出新增成本行；`limitations` 新增一条写明墙钟/RSS 的口径 |
| `tests/test_component_audit.py` | +3 用例：manifest 的成本块与规模同文档、除零时给 `None` 而不是 `0.0`、报告与渲染都带峰值 RSS |

**为什么 manifest 里必须有这一块**：在改动前，B 的 audit manifest 只记文件数与字节数，
**完全没有任何时间或内存字段**——一份产物的「规模」可以被引用，而它的「成本」无处可查。
现在两者写在同一个文档里，规模不可能脱离成本被单独引用。

## 6. 没有证明的事

- **不是检出能力评测**：候选数、`confirmed_vulnerabilities: 0` 都与上面任何耗时数字无关。
- **不是上界**：所有数字都是单次测量（未做多次取中位数/最坏值），也未测并行、增量缓存、
  硬超时或资源隔离下的表现。
- **未测整树规模**：最大被测组件是 20.2 MB 源码。OpenHarmony 千万行整树的成本未测，
  且当前实现的分片上限（2000 文件 / 32 MiB）使整树必须分片，分片成本未在本记录中量化。
- **内存口径**：`ru_maxrss` 是进程高水位。同一进程内跑多个组件时它是运行最大值，
  本记录的 5 个数字来自 5 次独立进程调用，不能拿去解释「一个进程跑完 5 个组件」的内存。
- **未与 `-partial` 解析质量挂钩**：部分解析文件（wwm 268 个）计入未分析，
  本记录不声称部分解析的成本更低。

## 7. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
P=~/openharmony-audit/perf-corpus
cd "$B"

# 每个组件一个独立进程（峰值 RSS 才是该次审计自己的）
.venv/bin/python -m src.ohscanner.detectors.interface.audit \
  --repo-dir "$P/window_window_manager" \
  --repository openharmony/window_window_manager \
  --commit 8b0d8fe1b973d865904c942c286b3d2a3b9b08e7 \
  --out-dir outputs/reports/interface_perf
```

产物（5 组件 × JSON / Markdown / manifest 三件 = 15 个文件）落在 `outputs/reports/interface_perf/`，
**不入库**；本记录的表格由其中的 JSON 直接渲染，未手抄。
单测：`.venv/bin/python -m unittest tests.test_component_audit`。

**注意（已核实，与直觉相反）**：该目录**不被 `.gitignore` 覆盖**。`.gitignore` 的第 226–227 行是
`outputs/reports/*.json` 与 `outputs/reports/*.md`，`*` 不跨 `/`，所以只匹配 `outputs/reports/`
**顶层**的文件，子目录里的产物不会命中；`git check-ignore` 对上述 15 个文件全部返回「未忽略」，
`git status` 里该目录显示为 `??`。也就是说这批产物**只是未跟踪，不是被忽略的**——
它们靠 `git add` 时的手工选择才没进提交。若后续要在 CI 上跑同一入口，
应先把忽略规则收紧或在脚本里显式排除，**不要假定产物天然安全**。

## 8. 版本绑定

| 项 | 值 |
|---|---|
| 被测入口 | `src/ohscanner/detectors/interface/audit.py`（`audit_component` / `main`） |
| 设置 | `production_only=True`，排除规则来自 `PRODUCTION_EXCLUDED_SEGMENTS`；默认两趟 |
| 环境 | Python 3.10.12 / Git 2.34.1 / Ubuntu 22.04 WSL2（每份 manifest 的 `environment` 块） |
| 语料提交 | 见 §2 表（与 `benchmarks/perf_scale_corpus_2026-10-10.json` 同一批） |
| 产物目录 | `outputs/reports/interface_perf/`（5 组件 × 3 件，不入库） |
