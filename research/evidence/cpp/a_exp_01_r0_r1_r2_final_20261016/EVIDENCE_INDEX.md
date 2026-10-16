# A-EXP-01 final R0/R1/R2 evidence index

- `FINAL_EXPERIMENT_REPORT.md`: human-readable final report.
- `final_experiment_report.json`: machine-readable comparison, ablations, budget, failures and metric eligibility.
- `r0_agent_review_summary.json`: validation summary for the 135 locked blinded non-human R0 records.
- `r2_extra_budget_actual.json`: actual R2-minus-R1 provider/tool/token/reference-cost/wall deltas and planned maxima.
- `all_failures.jsonl`: every failed run and every non-ok tool call from the main and ablation runs.
- rtifact_manifest.json: SHA-256 and byte count for the report inputs and outputs.
- alidation/: exact unit-test, documentation-budget and git diff --check outputs plus the validation summary.

The 135 R0 records and their lock are preserved at `research/experiments/cpp/r0_r1_r2_20261015/run_20261016_r0_agent_blind_nonhuman/`. They are explicitly agent, not independent human, records. The independent human R0 arm remains unexecuted and human active/paused time remains unknown.
