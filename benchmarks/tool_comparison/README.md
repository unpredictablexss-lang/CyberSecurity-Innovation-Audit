# Multi-tool benchmark result protocol

This directory defines the comparison protocol, not a vulnerability verdict
engine. The project will compare tools under the same pinned target, commit,
scope, machine, and measurement rules before deciding which capabilities belong
in the final pipeline.

The current research plan prioritizes four representative C/C++ tools:

| Tool | Intended evidence role |
|---|---|
| Semgrep | fast pattern candidate generation |
| CodeQL | data-flow / taint / cross-function evidence |
| Clang Static Analyzer | path-sensitive / symbolic evidence |
| Cppcheck | lightweight C/C++ baseline |

The project may later add other tools, but every adapter must emit the same
normalized ToolRunResult / ToolDiagnostic contract first.

## Required comparison fields

Each run records at minimum:

- tool and version;
- target ID and pinned commit;
- files and LOC in scope;
- run status;
- elapsed time;
- optional peak memory;
- normalized diagnostics;
- limitations.

Each diagnostic records:

- provider;
- evidence type;
- file / line / column when available;
- rule/checker ID;
- severity;
- message;
- provisional CWE when available;
- confidence (default unassessed).

## Evidence roles

Normalized evidence_type values are:

pattern, syntax, dataflow, control_flow, symbolic, historical, runtime,
permission, web_dynamic, human_review, or unknown.

These labels describe what kind of evidence a tool contributes. They are not
weights and they are not votes.

## Metrics and fairness

For historical ground-truth samples, report raw hit/miss counts first and only
compute aggregate Precision/Recall when the labeled sample set is large and
balanced enough to support those metrics.

For current OpenHarmony source, true negatives and false negatives are
incomplete. Prefer:

- candidate counts;
- top-k manual-review yield;
- unique root causes after deduplication;
- review cost/time;
- runtime and peak memory;
- coverage and failed-analysis counts.

Do not report full-project Recall on an unlabeled current tree.

## Interpretation boundary

A warning from any scanner is a Candidate/Evidence record, not a vulnerability.
Multiple tools reporting the same location do not automatically make it a
vulnerability. Zero diagnostics from one tool do not prove safety.

The next safe engineering step is to write adapters that translate existing
tool outputs into this protocol. Dynamic triggering, PoC work, or exploitability
claims are intentionally outside this part of the implementation.

## Adapter implementation

The current branch now provides four format-only adapters:

- src/providers/semgrep.py: Semgrep JSON -> ToolRunResult
- src/providers/codeql.py: CodeQL SARIF -> ToolRunResult
- src/providers/clang_sa.py: existing Clang baseline JSON -> ToolRunResult
- src/providers/cppcheck.py: Cppcheck XML -> ToolRunResult
- src/providers/registry.py: one normalize_tool_output(...) entry point

All adapters receive an AdapterContext containing the pinned target, commit,
scope, time and memory metadata.

Adapters do not execute scanners and do not perform runtime validation. Their
only responsibility is to preserve native diagnostics while translating them
into the common schema.

## Team / technical integration

The consolidated implementation plan is documented in:

- docs/strategy/team_parallel_multi_scanner_plan.md

It combines the vertical real-case workflow with the horizontal multi-scanner
benchmark line and fixes the merge point at the normalized Candidate/Evidence
protocol rather than direct code concatenation.

## Comparison command

Once two or more tool-native reports have been converted into normalized
ToolRunResult JSON files, compare them with:

```bash
python -m src.cli compare-tools \
  --report outputs/reports/semgrep.normalized.json \
  --report outputs/reports/codeql.normalized.json \
  --report outputs/reports/clang.normalized.json \
  --report outputs/reports/cppcheck.normalized.json \
  --json-out outputs/reports/tool_comparison.json \
  --md-out outputs/reports/tool_comparison.md
```

The command rejects reports whose target ID, commit, file count, or LOC scope
do not match. It reports per-tool diagnostic/evidence counts and exact
file/line overlap only.

Exact-location overlap is deliberately descriptive. It is not a vote, not a
root-cause equivalence proof, and not a vulnerability verdict.

