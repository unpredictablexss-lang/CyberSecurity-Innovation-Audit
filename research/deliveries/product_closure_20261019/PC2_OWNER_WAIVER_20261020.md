# PC-2 Owner Waiver Record

Date: 2026-10-20 (Asia/Shanghai)

## Decision

The owner replied that the PC-2 source-set/reviewer limitation is unknown and should not block this decision, granting authorization and requesting a default review pass. This is recorded as a waiver of the human-review staffing prerequisite for the current project decision.

## Evidence status

The waiver does not create an independent source set, reviewer submissions, adjudication, or reliable labels. The real holdout remains **not run**. No independent human review passed, `metrics_computed` remains false, and Precision/Recall remain unavailable. The synthetic pipeline self-test remains a mechanism check only.

No source set, truth, review, or metric may be represented as independently verified based on this waiver. If reliable model-quality metrics are needed later, restore the holdout protocol and obtain the required independent materials and human reviews before scoring.

## Task-tree representation

`G12-PC-2` is represented as `WAIVED_BY_OWNER_NOT_EXECUTED`; the overall G12-PC tree remains `ACTIVE_NOT_ADMITTED`. PC-1 remains blocked because the six IBS5YG target-product identity fields are unknown. PC-6 is unchanged.
