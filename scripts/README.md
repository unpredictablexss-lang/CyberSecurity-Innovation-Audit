# Scripts

辅助脚本目录，例如：数据集准备、Benchmark 执行、批量扫描、实验统计和结果转换。

## semgrep_ruleset_scan.sh

历史 benchmark 用的 Semgrep 扫描入口，替代已弃用的本地通用规则（含噪音规则
`deref-after-arrow`）。规则集由三部分组成：

1. `rules/cpp/vendor/raptor/` —— 0xdea/semgrep-rules（MIT），唯一维护中的公开 C/C++ 规则集；
2. `rules/cpp/` —— OpenHarmony 专用规则（`oh_shared_ptr_uaf`、`oh_nothrow_null_deref`）；
3. `p/security-audit` —— 官方 registry（仅 C 规则；免费 registry 无 C++ 规则）。

```sh
# 联网（含官方 C registry 规则）
scripts/semgrep_ruleset_scan.sh path/to/file.cpp path/to/dir

# 完全离线（仅 vendor + OH 专用规则）
WITH_REGISTRY=0 scripts/semgrep_ruleset_scan.sh path/to/file.cpp
```

结果写入 `outputs/reports/semgrep/`（Git 忽略）。

## joern_nothrow_guard.sc

Joern CPG 查询脚本，输出 `src/providers/joern.py` 约定的 findings JSON。

对每条 `$v = new (std::nothrow) T(...)` 判定：方法内存在 `$v->...` 解引用，且方法内
**没有把 `$v` 本身与 null-ish 字面量比较**，才报为候选缺失空指针守卫（CWE-476）。
这是 v2：相比 v1 的"方法级比较计数"，它消除了安全封装（只分配并 return）的假阳性，
以及无关比较（如 `strcmp(...) != 0`）造成的假阴性。它仍是**结构性启发式**，不是数据流
证明，也不识别自定义守卫函数或调用方的判空。

```sh
joern-parse <file> -o cpg.bin
JOERN_CPG=cpg.bin JOERN_OUT=findings.json JOERN_VERSION=4.0.649 \
    joern --script scripts/joern_nothrow_guard.sc
python -m src.cli normalize-tool-output --provider joern \
    --input findings.json --target-id <id> --commit <sha> \
    --scope-files 1 --scope-loc <loc> --elapsed-seconds 1.0 \
    --json-out outputs/reports/joern.json --md-out outputs/reports/joern.md
```

详见 `PROGRAM_STATUS.md` 第 6b.11 节。

## perf_scale_scan.py

组件级性能与规模基准。对固定到完整 commit SHA 的 OpenHarmony 组件语料执行真实
`python -m src.cli ohscan-run`，逐组件测量墙钟、进程峰值 RSS、扫描文件/字节、解析
覆盖与检测器覆盖，汇总为 JSON + Markdown。

语料清单 `benchmarks/perf_scale_corpus_2026-10-10.json`（11 条组件 + 完整 SHA）；
报告见 `docs/testing/ohscanner_performance_scale.md`。

```sh
python scripts/perf_scale_scan.py \
  --manifest benchmarks/perf_scale_corpus_2026-10-10.json \
  --json-out outputs/reports/perf_scale_scan.json \
  --md-out docs/testing/ohscanner_performance_scale.md
```

- 语料用 `git clone --depth=1 git@github.com:openharmony/<component>.git` 获取并核对
  `rev-parse HEAD` 等于清单 SHA；该 commit 的全部 blob 本地齐备，因此扫描全程离线。
- 测量由一个**最小父进程**完成，避免 fork 出的子进程在 exec 前继承父进程常驻页导致
  `ru_maxrss` 虚高；数值已用 GNU `time -v` 交叉核对。
- `--include` 分片：整树超过 `M1 bounded scope` 的组件（如 `window_window_manager`）
  按顶层目录分片测量，分片数会记录在报告里。
- 原始逐次运行产物写入 `outputs/reports/perf_scale/`（Git 忽略）。

**边界**：该基准只反映平台成本（Git 对象读取 + 逐文件 AST 解析 + 检测器调度），
使用当前唯一允许登记的非安全示例插件，**不是漏洞检出能力评测**。

**分支依赖（`main` 上复跑前必读）**：本脚本调用的 `python -m src.cli ohscan-run`
目前只存在于 `feat/ohscanner-core`（Draft PR #5），尚未并入 `main`。在 `main` 上直接
运行本脚本会因缺少该子命令而失败；`main` 上保留的是脚本、语料清单与实测报告，
报告中的数字来自 `feat/ohscanner-core` 分支上的实测，可复核但不能在 `main` 上原地复跑。

## run_infer_experiments.py

研究用 Infer/Pulse 执行器。要求调用者先准备本仓库之外的隔离 checkout，脚本只通过
参数数组执行 Infer 和指定构建命令，不经过 Shell，并将版本、命令、日志、耗时和
原始 JSON 哈希写入 `outputs/reports/**/execution.json`：

```sh
python3 -m scripts.run_infer_experiments \
  --infer /path/to/infer \
  --work-root /path/to/isolated-checkout \
  --output-dir outputs/reports/infer-sample-001 \
  --target-id sample-001 \
  --commit <full-lowercase-sha> \
  --scope-files 1 --scope-loc 120 \
  --build-command make target
```

`--compile-commands compile_commands.json` 可替代 `--build-command`，此时执行
`infer capture` + `infer analyze`。没有完整构建/TU 覆盖时，空报告不能解释为 miss
或安全。生产 Detector 和 `ohscan-run` 不依赖 Infer。

## collect_build_context.py

读取 `compile_commands.json`，计算 TU 数、文件范围、编译命令哈希和宏 profile 哈希，
生成 Clang SA / CodeQL 公平比较所需的 run-context sidecar。脚本不编译、不运行扫描器，
也不把输入的 `include_status` 自动提升为完整覆盖：

```sh
python3 -m scripts.collect_build_context \
  --compile-commands /path/to/compile_commands.json \
  --source-root /path/to/pinned-snapshot \
  --analysis-mode snapshot --revision-role target \
  --analysis-unit translation_unit \
  --build-profile linux-host --include-status complete \
  --output outputs/reports/build_context_sample.json
```

## joern_queries/root_cause_queries.json

记录 `oob_write`、`integer_overflow`、`lifetime_uaf` 和 `concurrency_race`
四类 Joern 查询规格、证据边界和限制。当前状态为 `designed_not_executed`，不是已经
运行的查询或 benchmark 结果。
