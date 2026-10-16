# A-EXP-01 R0 independent human assignments

Status: **awaiting three independent human reviewers**.

This directory prepares the remaining 135 frozen R0 reviews as three blinded assignments:

- `repetition_1/`: seed 20261015, 45 items.
- `repetition_2/`: seed 20261016, 45 items.
- `repetition_3/`: seed 20261017, 45 items.

Each assignment contains only truth-free current-item source context, persistent evidence/fact IDs, the frozen detector identity, review questions and blank submission wrappers. It does not contain sealed truth, historical review labels, other reviewer answers, model labels, R1/R2 outputs or R2 tool results.

## Required human execution

1. Assign exactly one independent human reviewer to each repetition; use three distinct reviewer IDs so repetitions do not share remembered answers.
2. The reviewer reads that repetition only and completes all 45 wrappers in `submission.jsonl`.
3. Every item must include real `started_at`, `ended_at`, `active_seconds`, `paused_seconds`, viewed evidence/fact IDs, all six EvidenceObligation statuses, conclusion, confidence and unknown reasons.
4. Preserve failed, abandoned, timeout and incomplete rows. Do not synthesize missing timing or references.
5. Validate with `validate_human_submission.py`; use `--peer-reviewer-ids` to reject repeated reviewer IDs across repetitions.
6. Only after all three submissions validate may R0/R1/R2 comparison be treated as complete enough for descriptive comparison. Accuracy metrics still require independent reliable truth.

The current Codex-agent blinded records are not a substitute for these human assignments and remain `agent_not_human`.
