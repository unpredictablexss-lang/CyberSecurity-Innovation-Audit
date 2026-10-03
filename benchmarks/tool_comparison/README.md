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
