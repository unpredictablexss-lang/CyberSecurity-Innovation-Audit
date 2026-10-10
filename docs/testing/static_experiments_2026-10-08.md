# Fixed-source static experiments — 2026-10-08
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

Status: experiments in progress, not final acceptance. Modules existing in the
repository do not mean that their tools have been executed or validated.

## Scope and preparation

Four manifests under benchmarks/historical, each vulnerable/fixed revision,
affected-file snapshots only. No full build, header stubbing, PoC or runtime
trigger. Three target source dependencies are now recovered: c_utils and
dsoftbus raw bytes match their pinned Git-tree blob IDs; kernel commits/blobs
were fetched from the official Gitee mirror with the original pinned SHAs.
Source target HEADs and implementation files remain unchanged.

Preparation logs: outputs/logs/prepare_*_fallback.json. The preceding GitHub
transport failures remain in outputs/logs/prepare_*.json and *_windows.json.

## Executed tools and observed results

WSL Ubuntu 22.04: Semgrep CE 1.179.0, Cppcheck 2.7, Clang 14.0.0. Semgrep
vendor profile uses the local MIT raptor mirror at
dae50da6e6e629750f1daec73a01ef9206a372ab. The OH profile uses the two unchanged
matching patterns in rules/cpp/oh_*.yaml, with the candidate limitations from
the architecture review. No online registry/pro rules are included.

| Sample | Own text / AST | Semgrep vendor | Semgrep OH | Cppcheck | Clang |
|---|---|---|---|---|---|
| c_utils | miss / miss, both revisions | miss, both | vulnerable possible_hit(1), fixed miss | unknown, symbol unresolved | not_applicable |
| dsoftbus | miss / miss, both revisions | miss, both | vulnerable possible_hit(5), fixed miss | miss, both | not_applicable |
| kernel | text miss; AST unknown, both revisions | unknown; 41 diagnostics plus PartialParsing, both | unknown; pinned AST partial | unknown; pinned AST partial | not_applicable |
| arkcompiler | miss / miss, both revisions | miss, both | miss, both | possible_hit(1), both revisions | not_applicable |

The OH rule pairs distinguish the two seed edits. They do not establish general
UAF/null-deref detection or zero false positives/negatives. Arkcompiler Cppcheck
overlaps the affected region before and after the fix, so it does not
discriminate that patch. Kernel partial parsing is a limitation, not a miss.

In the first batch, all eight Clang runs failed to form a translation unit due to absent headers
(e.g. nocopyable.h). CodeQL and Joern were not run in this experiment; their
adapter unit tests do not count as scanner execution. Dynamic verification
remains not_run; validated_vulnerability remains 0.

## Artifacts and interpretation

outputs/reports/static_baselines contains 16 own normalized runs, 32 external
tool/profile runs, native output and execution logs, inputs.json, eight tools
capability matrices and summary.json/md. Capability matrices include completed
comparable runs; failed/partial inputs are excluded from that statistic view
and remain visible in the root-cause summary. Generated artifacts are ignored
by Git; this document records the experiment, not fabricated fixture results.

The first-batch 64-cell summary has 4 possible_hit, 26 miss, 8 not_applicable, 26 unknown.
possible_hit counts cells, not vulnerabilities. Unknown includes 16 unexecuted
CodeQL/Joern cells, 8 kernel parsing/mapping cells and 2 unresolved c_utils
Cppcheck cells. No Precision/Recall/FPR or exploitability is inferred.

## Reproduction

Run from the repository root. Prepared component checkouts live outside it:

```bash
python -m scripts.prepare_historical_sources \
  --sample benchmarks/historical/c_utils_singleton_uaf.json \
  --target-root /path/to/components --raw-only --log outputs/logs/prepare_cutils.json
python -m scripts.prepare_historical_sources \
  --sample benchmarks/historical/kernel_liteos_a_getgroups_oob.json \
  --target-root /path/to/components \
  --remote-url https://gitee.com/openharmony/kernel_liteos_a.git \
  --log outputs/logs/prepare_kernel.json
python -m scripts.replay_static_baselines --target-root /path/to/components
python -m scripts.run_static_tool_experiments --semgrep-root /path/to/semgrep-python-target
python -m scripts.run_static_tool_experiments --summarize-only
python -m unittest discover -s tests -q
```

Raw-only recovery requires pinned commits/trees already present and verifies
the downloaded blob hash before writing it. Normal preparation intentionally
fetches; benchmark readers themselves disallow transport. Each fetch is bounded
and targets exact object IDs without checking out target code. The Semgrep
Python target includes its bin directory and dependencies; scanners run in
temporary snapshot directories with separate recorded environment/parameters.

First-batch local regression: 144 tests passed. Commit 4fbfef2 was subsequently
verified with successful remote Python unit tests; later commits require their own check.

## CodeQL / Joern follow-up batch

Executed CodeQL 2.27.1 with locally installed codeql/cpp-queries 1.9.0
cpp-security-and-quality.qls (183 queries), and Joern 4.0.649 with the unchanged
project nothrow structural guard query, over all eight pinned revision units.
Source SHA-256, commands, exit codes, elapsed time, query/suite hashes and native
results are retained in per-unit execution.json. Joern was repeated with INFO
logging and --log-problems because the default WARN level suppressed parser
problem messages. A parsed=yes / CPG=yes row is required for each affected file.

| Sample | CodeQL | Joern structural query |
|---|---|---|
| c_utils | both not_applicable: no-build reported 0 source files / 1 header, extraction failed | both unknown: CASTProblem |
| dsoftbus | both unknown: missing includes in SARIF telemetry despite successful command exit | vulnerable possible_hit(5), fixed miss |
| kernel | both unknown: missing includes | both unknown: parser problems |
| arkcompiler | both unknown: missing includes | both miss |

CodeQL's initial ark vulnerable run timed out after 180 seconds while writing
results on /mnt/e. Repeating with the database on the WSL filesystem and a
240-second bound completed; the original timeout log remains available. Six
CodeQL databases/queries completed but SARIF failed-include telemetry prevents
counting them as complete coverage. The header-only rejection applies to this
analysis unit/profile, not to CodeQL capability in general.

The current manifest binds 64 runs to 64 sample/revision/tool cells:
possible_hit=5, miss=29, unknown=20, not_applicable=10. There are no remaining
unexecuted tool cells in this scoped batch. This is execution coverage, not
complete parsing, build coverage, vulnerability validation or final acceptance.
Joern's dsoftbus overlap remains syntax evidence without dominance or runtime proof.

A supplemental c_utils Clang probe uses the exact pinned nocopyable.h blob,
-x c++ and -std=c++17. Both revisions compile without analyzer diagnostics.
The probe has no template instantiation or original build settings, so it is
kept outside the original comparable matrix. Kernel's Tree-sitter/Semgrep error
near USER int *status suggests a macro-context issue; no source text was edited
or macro-stripped to make coverage appear complete.

Reproduce with database/output storage on the WSL filesystem:

```bash
python -m scripts.run_graph_tool_experiments \
  --output-dir /path/on/wsl/static_baselines \
  --codeql /path/to/codeql --joern /path/to/joern-cli \
  --suite /path/to/cpp-queries/1.9.0/codeql-suites/cpp-security-and-quality.qls \
  --timeout 240
python -m scripts.run_graph_tool_experiments --output-dir /path/on/wsl/static_baselines --reconcile-only
python -m scripts.probe_clang_header --repo /path/to/commonlibrary_c_utils \
  --dependency /path/to/pinned/nocopyable.h --output-dir outputs/reports/static_baselines
```

The graph output directory must contain the previous baseline manifest and reports.
Current local regression: 149 tests passed. Remaining work includes pinned
dependency/build contexts, partial parsing and broader controls; PR #4 remains draft.
