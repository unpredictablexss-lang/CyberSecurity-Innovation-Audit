# Fixed-source static experiments — 2026-10-08

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

All eight Clang runs failed to form a translation unit due to absent headers
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

The 64-cell summary has 4 possible_hit, 26 miss, 8 not_applicable, 26 unknown.
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

Current local regression: 144 tests passed. Current pushed-head CI remains a
separate pending check. Continue CodeQL/Joern execution and compare build/source
analysis units before calling the branch complete.
