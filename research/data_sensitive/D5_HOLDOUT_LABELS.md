# D5 independent holdout labels

No independent, blinded, real-source holdout has been supplied or collected.
The existing D1–D4 cases are development controls and historical research
fixtures, not independent labels. The new D5 cases are semantic regression
tests created while changing the detector and are also not holdout evidence.

| Label | Independent samples | Result |
|---|---:|---|
| `supported_risk` | 0 | `not_run` |
| `protected_safe` | 0 | `not_run` |
| `unrelated` | 0 | `not_run` |
| `unknown` | 0 | `not_run` |

Precision, recall, TP, FP, FN, and TN are not estimable. No recall claim is
made. A future holdout must freeze detector and model hashes first, then be
reviewed by a person who did not tune the rule; missing or ambiguous evidence
must be labeled `unknown` rather than forced into a binary class.
