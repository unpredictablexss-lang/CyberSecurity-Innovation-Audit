# T54 independent M2 holdout protocol acceptance

- Date: 2026-10-20 (Asia/Shanghai)
- Independent test checkout: `D:/openHarmonyScanner/worktrees/t51-pasteboard-independent-20261020`
- Role: protocol-only acceptance design based on current D5 readiness, D41/D48, D51/T51, and D52/T52 records.
- D55 protocol artifact: **not present in this checkout at review time**. This report is a checklist and structured handoff prompt, not a D55 pass/fail review.
- No detector, scanner, test, fixture, expected-output, or policy files were changed. No samples were generated and no future-sample labels or expected outcomes were accessed.

## Current M2 evidence state

| Record | What it establishes | Why it cannot close M2 |
|---|---|---|
| D41 | Six pinned non-development component snapshots; 3,820 files; repeat stability; 99 post-scan stratified blind-review cases | Review packet has zero independent labels. Post-scan selection supports case review/miss discovery, not population estimates. It ran detector 0.17.0; any later-tuned detector cannot be evaluated against it as an untouched holdout. |
| D48 | Preregistered distributed_screen convenience sample; 97 eligible files, two stable scans, zero candidates | All 97 files are partial; no independent labels; convenience selection is not a random population sample. Zero candidates do not establish safety or recall. It used detector 0.21.0 but supplies no ground truth. |
| D51/T51 | Narrow rule regression controls for 0.19.3; exact component source binding; independent positive/negative shape probes | Tests rule behavior and one candidate shape, not a separately sampled and independently labeled population. Product status remains unknown. |
| D52/T52 | Narrow permission-signature regression controls and source-to-sink review for 0.18.0 | Synthetic controls and one blocked/partial component replay are not population labels. The candidate line is method entry; component and product conclusions remain unassessed/unknown. |

**Protocol conclusion:** M2 remains **NOT MET**. There is no evidence here of a detector-frozen, disjoint, independently labeled holdout with a defined population denominator and uncertainty report. No accuracy, precision, recall, or false-positive rate can be computed from these records.

## D55 acceptance checklist (apply when the artifact arrives)

Mark each row `PASS`, `FAIL`, or `UNKNOWN`, cite exact D55 file/field/line or immutable object, and do not infer missing protocol details.

| Gate | PASS condition | Reject / keep unknown when |
|---|---|---|
| Detector freeze | Exact repository commit and hashes for detector, source/sink models, parser/dependencies, config, path filters, and replay driver are frozen before holdout source selection/scanning/label access. | Any component is mutable/unhashed, or holdout-derived feedback changed it after freeze. |
| Data separation | D55 names and hashes development/training/tuning corpus and demonstrates holdout disjointness at repository, commit/tree, file/blob, and known-case/fixture level. Exclusions include D1–D54 and rule-development examples; dedup uses content identity, not just path/name. | Only claims “unseen” without an auditable comparison; same source blobs or derived fixtures cross the split; holdout labels/outputs were used to tune. |
| Selection frame | Defines target population, time window, eligible repositories/components and sampling unit; pre-registers strata and a reproducible selection procedure/seed before scan. Strata cover meaningful project/language/size/risk dimensions without selection on scanner output. | Convenience or known-CVE-only selection is presented as representative; frame, seed, or inclusion probabilities are absent. |
| Inclusion/exclusion | Enumerates file and repository eligibility, generated/vendor/test exclusions, language and extension policy, symlink/submodule handling, duplicate handling, and treatment of unavailable objects. Freeze the complete eligible-unit manifest/hash before scanning. | Rules are changed after seeing results; exclusions are implicit; denominator cannot be reconstructed. |
| Label unit and rubric | Defines one label unit unambiguously (e.g. source finding/candidate identity or eligible file) and operational definitions for positive, negative, unrelated, and unknown, with evidence requirements and component-specific adjudication rules. | A label means “scanner candidate”, “CVE known”, or an unsupported semantic guess; rubric omits counterevidence or unknown. |
| Blindness / independence | Reviewers have no role in D development/tuning and do not see scanner prediction, severity, confidence, or candidate-only framing before independently recording labels and evidence. The label interface preserves blinding; assignments and access are logged. | Developer labels own examples; reviewers see predictions before their initial label; independence is asserted but not documented. |
| Label coverage / disagreement | Prespecifies independently double-reviewed units (prefer all units if feasible), immutable per-reviewer labels, disagreement handling by a third independent adjudicator, rationale/evidence capture, and treatment of nonresponse. Preserve pre-adjudication labels. | Single unreviewed labels or silent consensus erase disagreement; unknown/nonresponse is dropped from denominators. |
| Candidate and no-hit coverage | Candidate findings are sampled/reviewed for precision; no-hit eligible units are independently examined through a predeclared probability sample or exhaustive audit for misses/recall. Include the sampling probabilities/weights and unit mapping. | Only scanner hits are labeled and recall/FN is claimed; no-hit controls are handpicked or treated as representative without a sampling design. |
| Coverage and status accounting | Reports eligible, scanned, parse-complete, partial, blocked, not-analyzed, candidate, reviewed, unlabeled, and excluded counts with disjoint or explicitly overlapping definitions. Preserve blocked/partial status at file and run level. | Partial/blocked/not-analyzed units vanish or are counted as clean negatives; totals do not reconcile to the frozen manifest. |
| Denominators and estimands | Predefines estimands and denominator formulas: candidate precision among labeled candidate units; recall only where positive ground truth and sampled/exhaustive no-hit units permit it; file-level and finding-level results are not conflated. Unknowns are separately counted and sensitivity bounds are supplied where they affect metrics. | Uses total repository size as denominator for precision, candidate count as denominator for recall, or excludes unknown/partial without a stated estimand. |
| Uncertainty | Reports sample sizes and confidence intervals appropriate to stratified/clustered selection, with weights/design effect or a justified method. Gives uncertainty for unknown labels and reviewer disagreement; avoids point estimates alone. | Treats clustered files as independent without justification, omits interval/sample size, or gives a precise estimate from convenience samples. |
| Stopping / claim rules | Preregisters minimum label coverage and precision/recall interval-width or decision thresholds, handling of strata underfill, missing labels, unstable replay, and when to stop and declare inconclusive. Claims are limited to the frozen population and detector version. | Thresholds are chosen after observing labels; “zero findings” or low candidate count ends review; failed coverage is converted to PASS. |
| Reproduction / audit trail | Stores raw scan outputs, source object hashes, candidate identities, sampling frame/seed, blinded review exports, reviewer versions, adjudication log, and metric script hashes. A second reviewer can recompute counts and metrics. | Only a summary table is supplied; source/label/method identities cannot be independently recomputed. |

## Required M2 decision logic

1. A protocol can be accepted as **READY TO RUN** only when freeze, separation, sampling frame, inclusion rules, blindness, label rubric, denominator, uncertainty, stopping, and audit trail are all PASS.
2. A completed campaign can be **M2 EVIDENCE SUFFICIENT** only after the frozen scan and preregistered labeling are complete, accounting reconciles, uncertainty and unknowns are reported, and the measured criteria preregistered in D55 are met. This does not imply M3 product validation.
3. Any FAIL in separation/blinding invalidates the holdout for the claimed detector version. Any UNKNOWN in population frame, no-hit review, coverage, or denominators prevents an accuracy claim. Preserve the run as development/diagnostic evidence and commission a fresh holdout if contaminated.
4. Do not invent a universal sample-size threshold in this acceptance review. D55 must state its target precision/recall decision and derive a sample plan from that target and its population design before labels are observed.

## Structured vibe-coding prompt for D55 protocol author

```text
Role: D55 M2 holdout protocol author. Produce a preregistered protocol artifact and machine-readable companion only; do not modify scanner code, models, tests, fixtures, or expected outputs, and do not generate, inspect, or reveal holdout labels in the protocol-authoring phase.

Objective: make M2 accuracy and performance measurable for one frozen D sensitive-exposure detector version using source data disjoint from every development/tuning example and independently blinded labels.

Inputs to audit: research/data_sensitive/D5_MAIN_READINESS.md; D41 preregistration, manifest, blind packet/results; D48 preregistration and report; D51/T51 and D52/T52 records. Treat all examples and profiles named in these records as development/previously exposed unless an auditable content-level comparison proves otherwise. Do not use anticipated labels or ask development agents for expected outcomes.

Before any holdout scan or label access, specify and hash: detector commit; detector/model/parser/dependency/config/path-filter/replay-driver versions; source corpus frame and eligibility; exact repository commits/trees and eligible-unit manifest; data split and content-level exclusion/dedup checks against development artifacts; strata, sampling unit, seed, inclusion probabilities, and selection script; scan procedure; labeling rubric; reviewer qualifications and independence; blind workflow; double-label/adjudication plan; candidate and no-hit sampling; unknown/nonresponse policy; all denominators and estimands; coverage/status accounting; runtime/RSS measurement; uncertainty method; minimum coverage and stopping/inconclusive rules; claim boundaries; audit/reproduction artifacts.

Sampling must not depend on D outputs. Include enough independently reviewed no-hit units to support the preregistered recall estimand, by probability sampling or exhaustive audit. Keep candidates and no-hit units linked to the frozen eligible population and use design weights where selection probabilities differ. Do not equate partial, blocked, not-analyzed, or unlabeled files with negative labels.

Separate roles: a custodian selects and freezes sources; a scan operator runs the frozen detector; independent reviewers label evidence without predictions; an independent adjudicator resolves disagreements. Record access and timestamps. Preserve initial labels and disagreement. Use positive/negative/unrelated/unknown definitions tied to source evidence and record supporting and contradicting lines.

Deliver: (1) a human-readable D55 preregistration, (2) JSON schema/data for every protocol field, (3) a reproducible split-audit and sampling script or exact pseudocode, (4) an acceptance checklist self-review, and (5) a concise unresolved-questions list. Do not fill unknown fields with guesses. Predeclare confidence intervals and decision thresholds based on the target estimand; if the population design cannot support an estimand, mark it unavailable instead of manufacturing a metric.

Acceptance feedback loop: after D55 is frozen, an independent T54 reviewer will check exact artifact hashes and every gate above; protocol changes after label access require a fresh holdout or must be explicitly classified as exploratory. Do not claim M2 closed until the frozen campaign, independent labels, reconciled denominators, uncertainty analysis, and preregistered thresholds are all satisfied.
```

## Current unknowns pending D55

- Whether D55 freezes the actual current detector/model/parser bundle before any holdout source selection or exposure.
- Whether its candidate and no-hit populations are content-disjoint from all development profiles, including overlapping commits/blobs and derivative fixtures.
- Target population, source selection frame, stratum definitions, randomization/selection seed, and inclusion probabilities.
- Label unit, reviewer identities/independence, blind mechanics, double-review coverage, disagreement adjudication, and unknown handling.
- File-level coverage accounting and whether partial/blocked/not-analyzed units are retained in every denominator.
- Recall design for no-hit units; metrics, confidence intervals, sample-size rationale, stopping thresholds, and runtime/RSS measurement procedure.
- Whether raw artifacts are sufficient to recompute split, labels, counts, intervals, and claims independently.

Machine-readable checklist: [t54_m2_holdout_protocol_acceptance_20261020.json](t54_m2_holdout_protocol_acceptance_20261020.json).
