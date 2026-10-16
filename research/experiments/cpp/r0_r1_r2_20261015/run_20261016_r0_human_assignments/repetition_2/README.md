# A-EXP-01 R0 independent human assignment: repetition 2

Status: awaiting independent human reviewer.

This package contains exactly 45 blinded review items and 45 blank submission wrappers. It is one repetition of the frozen 45-item experiment.

## Blindness

Do not open `sealed_item_key.json`, frozen truth labels, historical review labels, other reviewer answers, R1/R2 outputs, R2 tool results, or model labels before submitting. Do not modify candidate IDs, reviews, historical reports, cases, or vulnerability status.

## Execution

1. Use exactly one independent human reviewer for this repetition.
2. Review `review_items.jsonl` in the supplied order.
3. For every item, record `started_at`, `ended_at`, `active_seconds`, and `paused_seconds` from real observation. Never synthesize timing.
4. Record the exact `evidence_ids_viewed` and `fact_ids_viewed`.
5. Complete all six EvidenceObligations. Missing, partial, failed, timeout and unknown remain unknown.
6. Give a mechanism label, product assessment, confidence from 0 to 1, and explicit unknown reasons.
7. Save one completed wrapper per item as `submission.jsonl`, preserving failed, abandoned and timeout rows.
8. Run the validator from the assignment directory before sign-off.

The submission remains ineligible for accuracy metrics unless independent reliable truth is separately established. Model agreement, historical review and synthetic controls are not truth.
