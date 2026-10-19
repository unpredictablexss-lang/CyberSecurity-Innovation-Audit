# D5 independent holdout labels

No independent, blinded, real-source labels have been supplied or collected.
The existing D1–D4 cases are development controls and historical research
fixtures, not independent labels. The new D5 cases are semantic regression
tests created while changing the detector and are also not holdout evidence.

D41 froze six non-development OpenHarmony component snapshots and replayed
detector 0.17.0 twice over 3,820 C/C++ source files. It retained 201
`data.sensitive.unresolved-escape` candidates; all six scans were blocked,
with 2,787 partial and 1,033 not-analyzed files. The 99-item
`D41_BLIND_REVIEW_PACKET.json` is a post-scan, stratified manual review packet
(up to 8 candidate observations and 10 no-hit files per component). It has no
labels yet and is not a preregistered population-accuracy sample. See
`D41_HOLDOUT_PREREGISTRATION.md` and `D41_HOLDOUT_RESULTS.json`.

| Label | Independent samples | Result |
|---|---:|---|
| `supported_risk` | 0 | `pending independent review` |
| `protected_safe` | 0 | `pending independent review` |
| `unrelated` | 0 | `pending independent review` |
| `unknown` | 0 | `pending independent review` |

Precision, recall, TP, FP, FN, and TN are not estimable. No recall claim is
made. A future holdout must freeze detector and model hashes first, then be
reviewed by a person who did not tune the rule; missing or ambiguous evidence
must be labeled `unknown` rather than forced into a binary class.


## Current-version note (2026-10-19)

D41 is frozen against detector 0.17.0 and cannot be used as an independent accuracy result for 0.21.0. D47 freezes the current detector/model source hashes at code commit 1f170e0810405974d613bd43e1a5d62817d215a6 and repeats four already-used development profiles for stability/performance only. D47 does not create independent labels. The next valid holdout must use source snapshots not used in D development, keep the scanner/model frozen during review, and have an independent reviewer assign line-bound labels before the prediction key is revealed.


## D48 distributed_screen

D48 freezes distributed_screen at commit 373e2b5241c0e5dcb923642059ae83e4e9a1a64e and the 0.21.0 detector before its run. Two rounds matched with zero candidates, but coverage is partial for all 97 files and blocked. There are no independent labels; this is not an accuracy result or a clean bill of health. Keep D48 results sealed from tuning; use a new frozen source set after any model change. See the [preregistration](D48_HOLDOUT_PREREGISTRATION.md) and [replay report](D48_HOLDOUT/distributed_screen/README.md).


D48 also has a separate, reused synthetic panel control at detector 0.21.0. It is explicitly excluded from holdout scoring; see D48_PANEL_SMOKE/README.md. The distributed_screen source replay has no independent labels and is not scored.
