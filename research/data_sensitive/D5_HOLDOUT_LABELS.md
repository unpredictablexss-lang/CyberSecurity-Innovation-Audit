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
