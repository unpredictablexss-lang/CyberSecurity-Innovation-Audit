# T54 review of D55 holdout preregistration

- Review date: 2026-10-21 (Asia/Shanghai)
- Reviewer checkout: `D:/openHarmonyScanner/worktrees/t51-pasteboard-independent-20261020`
- D55 checkout: `D:/openHarmonyScanner/worktrees/d55-holdout-protocol-20261021`
- Reviewed D55 commit: `9d932746e361e9d7746a1fcf451284e32f3b8c5a`
- Inputs: `D55_INDEPENDENT_HOLDOUT_PREREGISTRATION.md`, `D55_HOLDOUT_EXECUTION_TASK.md`, and `D55_HOLDOUT_PROTOCOL_20261021.json` at that commit; T54 acceptance matrix at commit `0e84a622ef96098658963925b4031616569653eb`.
- Scope: read-only protocol review. D55 files were not changed. No samples, labels, scanner outputs, or expected outcomes were generated or accessed.

## Decision

**NOT READY for holdout execution under T54. M2 remains NOT MET.**

D55 has a strong protocol structure: it excludes prior development evidence, separates the two detector tracks, requires a seeded stratified source frame, freezes scanner/source identities, uses blinded independent double review, requires full-scope prediction-blind miss review for recall, retains unknown and coverage states, and defines a stop-before-scoring posture. It correctly says the current campaign has not started and has no labels or metrics.

The protocol is not yet preregistration-complete for an accuracy decision. Its explicit missing inputs appropriately stop source selection and scanning, but several evaluation choices also need to be specified before that stop can be lifted. In particular, it does not set target metric/interval decision thresholds or a sample-size rationale; `20 repositories / 1,000 files / four families` is explicitly only a workload floor. Therefore a future completed campaign could produce descriptive metrics without a predeclared criterion for whether they satisfy M2.

## T54 gate results

| T54 gate | Result | Review |
|---|---|---|
| Detector freeze | **PARTIAL / execution blocked** | D55 section 4 and JSON freeze requirements enumerate scanner/model/parser/config hashes and clean checkout, but the actual target version/hashes are explicitly missing. Correctly blocks execution until a signed freeze manifest exists. |
| Data separation | **PASS in design; evidence pending** | Sections 1 and 3 exclude D41/D48/D49-D53 and all D development/replays, require history search and content/path overlap screening, and stop if independence is unresolved. The actual overlap ledger is correctly a future required artifact. |
| Sampling frame | **PARTIAL** | Section 3 requires an external inventory, strata, seeded random selection, commitment/reveal, inclusion probabilities, and no post-scan replacement. However, no actual inventory/source families or target population boundary is frozen. More importantly, the numeric cohort floors have no precision/power rationale and no preregistered target interval width or outcome threshold. |
| Inclusion/exclusion | **PARTIAL** | Eligibility and path policy are substantially specified and failures remain visible. Before selection, freeze explicit treatment of submodules, symlinks, duplicate blobs/snapshots across repositories, vendored copies, and unsupported/ambiguous source identity. The generic “path policy” reference is not itself an operational rule. |
| Label unit and rubric | **PARTIAL** | Claim-relative positive/safe/unrelated/unknown labels and evidence fields are good. Clarify that source-level M2 labels can be adjudicated while `product_applicability=unknown`; the current `unknown` definition also mentions insufficient product/runtime evidence, which could incorrectly make source-level results depend on M3 evidence. Keep source, runtime, and product label scopes explicitly separate. |
| Blindness / independence | **PASS in design; evidence pending** | Sections 4-5 require neutral IDs, hiding candidate status and rule details, two independent reviewers, access/COI logs, and label freeze before unblinding. Reviewer identities/qualifications and custody setup are correctly listed as missing execution inputs. |
| Double review / adjudication | **PASS in design; evidence pending** | Sections 5-6 preserve two original labels, require independent adjudication, retain unresolved unknowns, and preclude forced consensus. |
| Candidate and no-hit coverage | **PASS in design; execution pending** | Section 5 requires full eligible-scope prediction-blind miss review, and section 7 disallows recall absent exhaustive review or a valid weighted probability sample. This is a sound recall path, subject to proof of completed full-scope review. |
| Coverage/status accounting | **PARTIAL** | Partial/not-run/blocking states are retained and coverage by files/bytes is required. No minimum acceptable coverage or explicit global stop threshold is set. The rule “partial or not-run prevents a specific claim” needs a frozen mapping from claim/stratum to when aggregate coverage makes the metric not estimable. |
| Estimands and denominators | **PARTIAL** | Precision/recall formulas and unknown reporting are strong. Before scoring, freeze deterministic scanner-to-reference matching, one-to-one/duplicate handling, and how a single source path with multiple findings or overlapping strata maps to units. The identity tuple alone does not resolve matching. |
| Uncertainty | **NOT READY** | A 95% interval accounting for repository clustering and design weights is required, but the interval/variance method, small-cluster handling, finite-population correction if applicable, and target interval width are not selected. The protocol says to mark inference unavailable when unsuitable, but no metric decision threshold is preregistered. |
| Stopping / claim rules | **NOT READY** | Stop conditions and minimum workload floors exist. Missing: target precision/recall or interval-width criteria for M2, a rationale/power calculation for sample size, and aggregate coverage/unknown/reviewer agreement thresholds (or an explicit rule that no such threshold is intended). Floors are expressly not statistical guarantees. |
| Audit/reproduction | **PASS in design; execution pending** | Section 10 and the execution task specify manifests, raw reports, sealed prediction key, original labels, adjudication, scripts, and hashes. Actual immutable storage and independent verification are future prerequisites and correctly listed as missing. |

## Required changes before lifting the stop decision

1. Freeze a target population and exact track scope. For `known_disclosed_cves`, identify the catalog/advisory universe and its hash/version before cohort selection; D55 says the track is limited to a prespecified universe but does not identify that universe in this protocol package.
2. Predeclare the M2 decision rule: acceptable precision/recall values or confidence-interval bounds/widths, separately by track and any primary stratum. If M2 has no numeric accuracy threshold, state what evidence is sufficient and why before labels are observed.
3. Add a sample-size rationale tied to the target estimand, strata, repository clustering, and desired interval precision. Do not treat the workload floors as inferential sufficiency.
4. Select and document the confidence-interval / variance method for the stratified repository-cluster design, including what happens with few clusters, sparse classes, or unequal weights.
5. Define aggregate coverage and unknown stopping rules, or explicitly declare them descriptive only and define precisely when each metric becomes `not estimable`.
6. Freeze source identity edge cases (submodules, symlinks, cross-repository identical blobs, vendored duplicates, unsupported files) and finding-to-reference matching/dedup rules before scan and labels.
7. Clarify that product applicability remains a separate M3 field and cannot force a source-level M2 label to `unknown` when the source claim itself is decidable.

The concrete source frame, cohort, scanner hashes, reviewer assignments, and sealed storage are absent by design and remain **execution blockers**, not evidence of an invalid protocol by themselves. Once the protocol-level gaps above are resolved and the required manifests are frozen, a new independent review can decide `READY_TO_RUN`.

## M2 status and boundary

D55 has created no labeled holdout and computed no metrics. Current status is **M2 NOT MET**; precision, recall, TP/FP/FN, and accuracy remain not estimable. D55's protocol does not establish M3 product applicability or a product vulnerability.

