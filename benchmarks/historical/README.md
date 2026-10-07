# Historical vulnerability benchmark

This directory contains published OpenHarmony historical security-fix pairs used
as benchmark samples for evaluating the audit pipeline.

## What this benchmark measures

For each sample we pin the repository, vulnerable commit, fixed commit, affected
files and symbols, published weakness / root-cause group, and public source
references.

The runner verifies the commits locally, checks whether the fix diff touches the
expected files, materializes only the affected files from both revisions, and
runs the current candidate generator plus lightweight AST sanity checks.

The benchmark records whether each tool or scanner touches the known affected
file / symbol region. That is a root-cause coverage signal, not a vulnerability
verdict.

## Current sample set

The current PR carries four first-party OpenHarmony historical samples:

| sample_id | repository | root_cause_group | weakness |
|---|---|---|---|
| `c_utils-singleton-uaf-2026-01` | `openharmony/commonlibrary_c_utils` | `lifetime_uaf` | CWE-416 |
| `kernel_liteos_a-getgroups-oob-2025-03` | `openharmony/kernel_liteos_a` | `concurrency_race` | CWE-125 |
| `communication_dsoftbus_null_deref_001` | `openharmony/communication_dsoftbus` | `null_deref` | CWE-476 |
| `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | `openharmony/arkcompiler_ets_runtime` | `oob_write` | CWE-787 |

This gives type diversity across lifetime, concurrency, null-dereference, and
out-of-bounds write roots. It is still too small for formal Precision / Recall.

## What it does not measure

A positive-only historical set cannot honestly provide full Precision, false
positive rate, or global Recall. A candidate overlap is not a validated
vulnerability, a miss is not proof that all project layers would miss the issue,
and a fixed revision with zero candidates is not proof of safety.

Historical replay is also not new vulnerability discovery. It is a controlled
benchmark for checking whether the pipeline can point at known historical root
causes under pinned commits.

## Reporting rule

Report only raw states:

- `possible_hit`: tool touched the affected file / symbol region;
- `miss`: tool ran but did not touch that region;
- `unknown`: tool was not run;
- `not_applicable`: the tool does not apply to this analysis unit.

Do not convert those states into TP / FP / FN yet. Do not compute Precision /
Recall until the dataset contains enough labeled positives and negatives to
support those metrics.
