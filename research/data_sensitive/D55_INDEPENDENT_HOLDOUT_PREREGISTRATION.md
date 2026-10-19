# D55 independent holdout preregistration and data protocol

**Protocol ID:** D55  
**Status:** protocol drafted; source cohort, scanner freeze, reviewers, and labels are not yet supplied  
**Freeze rule:** no D detector/model, source-profile, parser, scope-filter, or candidate-postprocessing change after the scanner bundle is frozen. Any such change voids D55 as an accuracy holdout and requires a new cohort.  
**Purpose:** prepare an independently sourced and independently labeled evaluation for D5 gate M2. This document creates no labels and reports no accuracy.

## 1. Why a new holdout is required

The current readiness record says M2 is not met: no suitable independent labeled set exists, and source coverage and measured accuracy remain open (`D5_MAIN_READINESS.md`, M2 row and operating boundary). Keep the two D products as separate evaluation tracks: `ohscanner.data.sensitive_exposure` evaluates sensitive-data exposure paths; `ohscanner.known_disclosed_cves` evaluates only its declared disclosed-CVE scope. Do not pool their metrics.

The existing evidence is excluded from D55 scoring:

| Evidence | What it establishes | Why it is not D55 holdout data |
|---|---|---|
| `D41_HOLDOUT_MANIFEST.json`, `D41_HOLDOUT_PREREGISTRATION.md`, `D41_HOLDOUT_RESULTS.md`, `D41_BLIND_REVIEW_PACKET.json` | Six pinned repos, 3,820 eligible C/C++ files; two stable replay rounds; 99 post-scan stratified cases | Packet was drawn after scanning, has no independent labels, and D41 froze detector 0.17.0. Later D43 used a D41 candidate to change the detector. The packet is not a probability sample of the source population and cannot score the later detector. |
| `D48_HOLDOUT_PREREGISTRATION.md` and `D48_HOLDOUT/distributed_screen/` | Pinned `distributed_screen` convenience sample, 97 eligible files, zero hits in two stable rounds | All 97 files were partial, run was blocked, and there are no independent labels. It is a coverage/stability observation, not a clean scan or accuracy sample. |
| `D49_KNOWN_CVE_REPLAY/` and `D50_COMPONENT_CVE_REPLAY/` | Replays on already reviewed CVE/component sources, with partial/blocked coverage | These were rule-development/replay examples, not independently sampled or independently labeled cases. |
| D51/D52/D53 records and T51–T53 acceptance records | Pasteboard quota/permission candidate checks, independent rule-shape acceptance, and source/config product correlation | These were selected because of specific candidates and development questions; they are targeted diagnostics, not a prevalence sample. D53 product templates do not prove a built product. |
| D35–D50 and any synthetic controls, candidate deltas, fixed-source comparisons, PoCs, or rules used during development | Development, regression, source-pipeline, or component behavior evidence as individually documented | Any item visible to rule authors or used to adjust a detector is development data. It cannot be recycled into D55 scoring. |

Before enrollment, search all D research records and scanner history through the intended source freeze date for exact repo/commit, tree, archive/member identities, path, and candidate-family overlap. Record exclusions in the cohort manifest. If a source's independence cannot be determined, exclude it or mark the issue unresolved and stop that source from scoring.

## 2. Evaluation questions and populations

Pre-register separate primary endpoints:

1. **Sensitive exposure track:** whether the frozen detector identifies in-scope, source-supported sensitive-data exposure findings in the selected source population. Reviewers judge a concrete source-to-sink/path claim under the fixed D5 taxonomy, with runtime reachability/visibility uncertainty retained explicitly.
2. **Known-CVE track:** whether the frozen disclosed-CVE detector identifies in-scope vulnerable source instances from a prespecified advisory/CVE universe. Reviewers judge source/version correspondence and the vulnerable code condition; an advisory mention alone is not a positive label. Do not treat CVEs outside the frozen catalog as detector misses.

The sampling unit for enrollment is a repository snapshot (repository identity + commit + tree). The scoring unit is a deduplicated finding identity, defined before labels as `(track, repo, commit/tree, normalized source and sink or CVE identity, affected function/path, trigger condition)`. Store file-level coverage separately. A single path repeated at multiple source locations is deduplicated only by a deterministic rule frozen before labels. Keep track-specific metrics separate and report both per-finding and per-repository results.

## 3. Source cohort and selection

### 3.1 Eligibility

Eligible snapshots must:

- come from OpenHarmony or a declared downstream OpenHarmony source population relevant to the intended claim;
- have an immutable, locally available Git commit/tree or content-addressed source archive, without modifying the source;
- have enough provenance to bind repository, commit/tree, and every in-scope file's Git blob or archive/member hash;
- have source scope and language supported by the frozen evaluation profile;
- not appear in D development, prior D replays, regression fixtures, public issue examples explicitly used to build these rules, D41, D48, D49–D53, or other previously inspected/tuned material;
- be selected without looking at D detector outputs, candidate counts, labels, or second-layer model judgments.

Exclude generated/vendor/test/mock/fuzz paths only with a path policy frozen before selection; preserve excluded path counts and reasons. Do not silently remove parser failures or low-coverage files. Record them as coverage outcomes.

### 3.2 Sampling frame and selection method

Before scanning or viewing any holdout result, freeze a sampling-frame file listing every eligible candidate repository snapshot and its source family, component, release/date, repository URL as declared metadata, exact commit/tree, language/file counts, prior-use screening result, and inclusion probability. Build the frame from a source inventory that is not authored by the scanner team. Preserve the inventory source and collection timestamp.

Select whole repository snapshots using a reproducible seeded random procedure, stratified by source family/component and release era. Publish the seed commitment/hash before selection; reveal the seed after the frame hash is signed. Record selected and non-selected units and inclusion probabilities. If a genuine random frame is unavailable, label the campaign **convenience sample** and do not claim population precision/recall. No post-scan replacement of zero-hit, partial, inconvenient, or hard-to-label repositories is allowed.

Target a minimum of 20 independent repository snapshots and at least 1,000 eligible source files across at least four source families for an initial multi-family evaluation. These are workload floors, not guarantees of statistical precision. If the eligible frame cannot meet them, record the shortfall and treat results as descriptive pilot evidence; do not relax independence or coverage gates to hit the number. Freeze the exact cohort and scope before scanning.

### 3.3 Inclusion/exclusion log

For each considered snapshot record `selected`, `excluded`, or `pending`; exact reason; overlap checks; source availability; selector version; frame row; selection probability; and reviewer who approved eligibility. Exclusions include prior rule exposure, missing immutable identity, unsupported language/profile, duplicate snapshot, insufficient provenance, and source family outside the preregistered population. Missing or conflicting data is `pending`, never an implicit pass.

## 4. Freeze and custody before scan

Create a signed, append-only freeze manifest before opening predictions or labels. Include:

- protocol revision and SHA-256;
- source-frame file SHA-256, cohort-manifest SHA-256, selection code/version, seed commitment and later revealed seed;
- each repository's canonical identifier, declared origin, commit/tree, archive/member identities where relevant, and eligible-scope path-list hash;
- each source blob/member SHA-256 and byte count, or a deterministic manifest that can reproduce them;
- scanner repository full commit SHA and dirty status (must be clean), detector ID/version and source hash, model/profile/catalog hashes, parser and postprocessing versions, scan configuration and path policy;
- runtime environment, OS/runtime versions, command line, resource limits, and replay driver hash;
- output bundle hash, timestamps, operator, and immutable storage location;
- conflict-of-interest and access log for developers, operators, labelers, adjudicator, and analyst.

Run the frozen cohort exactly as preregistered, with no tuning between repositories. Repeat the same scan once only for stability/runtime replication; do not count repeat outputs as independent observations. Save raw reports, coverage, logs, file status, and wall time/RSS. Scanner operators do not label cases. If a technical rerun is needed, log its reason and retain both attempts; never overwrite results.

After the first output, seal the prediction key in access-controlled storage. Create a separate randomized review packet for labelers containing complete source excerpts and surrounding call/definition context, exact source identity/hash, and neutral case ID. Do not reveal hit/no-hit status, rule name, candidate text, ranking, severity, D41/D48 status, prior notes, CVE rule signature, or whether a case was selected from a hit. Reviewers need access to the full eligible source tree for exhaustive review, but the review UI/order must not mark scanner hits.

## 5. Blinded labeling

Two qualified reviewers independently label every in-scope scoring unit and perform a prediction-blind review of the full eligible source scope for missed positives. Both reviewers must be independent of detector/model/rule development, cohort selection, and scanning. They may not discuss cases until both label files are frozen. Record reviewer role and conflict declaration without exposing identity in the public result.

Each reviewer submits these fields for every case/unit:

| Field | Allowed values / requirements |
|---|---|
| `case_id` | Random opaque identifier; no candidate indicator. |
| `track` | `sensitive_exposure` or `known_cve`; never pooled. |
| `label` | `supported_risk`, `protected_safe`, `unrelated`, `unknown`. `unknown` includes insufficient context, unresolved binding, incomplete parsing, or insufficient product/runtime evidence for the stated claim. |
| `claim_scope` | Exact source-level claim being evaluated; distinguish source candidate from product vulnerability. |
| `support_evidence` | One or more exact repo/commit/tree/path/blob/source hash and line spans with short reasoning. |
| `contradicting_evidence` | Exact spans or explicit `none found after specified review`; include guards, validation, sanitization, cleanup, alternate flow, or fixed code when applicable. |
| `entry_and_control` | Caller/entry, privilege, attacker-controlled input, and each state `supported`, `refuted`, `unknown`, with evidence. |
| `source_to_sink_or_cve_condition` | Bound path and operation, or CVE-specific vulnerable condition/version mapping; status and evidence. |
| `coverage_confidence` | `complete_for_claim`, `partial`, `not_run`; state why. |
| `product_applicability` | `supported`, `refuted`, `unknown`, with product build evidence; source-only is `unknown`. |
| `review_notes` | Concise reasoning and unresolved questions. No scanner prediction. |

Label meanings are claim-relative. `supported_risk` means the stated source-level condition is evidenced; it does not itself establish a product vulnerability, impact, CVE applicability, or exploitable runtime path. `protected_safe` requires positive evidence for the relevant safety property across the reviewed path; absence of a candidate is not sufficient. `unrelated` means the finding's source/condition is not in the target claim. Use `unknown` rather than force a binary decision. Keep scanner coverage status separate from human label.

Reviewers must search the entire eligible scope for source-level positives without prediction hints. They identify each positive path independently and cite it in the same schema. This is necessary to identify false negatives. Merely labeling candidate excerpts estimates neither recall nor missed positives.

## 6. Disagreement and adjudication

Freeze both independent label sets (file hashes and timestamps) before unblinding. Compare them only after freeze. A third adjudicator, also independent from development, reviews disagreements and every `unknown` that could change a primary metric. The adjudicator sees the source evidence and the two rationales but not scanner prediction until an adjudicated label is frozen. Record original labels unchanged, adjudicated label, cited evidence, decision reason, and unresolved issues.

If disagreement persists, evidence conflicts, or the scope cannot be decided, final label remains `unknown`. Do not force consensus. Report raw agreement and a suitable agreement statistic only when its assumptions and class distribution make it interpretable; provide class counts and confidence intervals. Do not treat adjudication as replacing the independently submitted labels.

## 7. Scoring and denominators

Score only after labels, adjudications, scanner outputs, coverage, and analysis script are all frozen and hashed. Compute metrics separately by track and by preregistered strata. Deduplicate prediction and reference identities by the frozen rule.

For `supported_risk` positives in the evaluated source-level claim:

- **TP:** a frozen scanner finding matches an adjudicated `supported_risk` reference unit;
- **FP:** a frozen in-scope scanner finding is adjudicated `protected_safe` or `unrelated` for that claim;
- **FN:** an adjudicated `supported_risk` reference unit in the exhaustively reviewed scope has no matching scanner finding;
- **Unknown:** any scanner finding or reference unit whose final label/identity is `unknown`, or whose source coverage prevents a decision. Report separately; never silently count as FP, TP, or TN.

Primary candidate precision is `TP / (TP + FP)` among adjudicable frozen scanner findings. Publish its numerator/denominator and a 95% interval; if denominator is zero, report `not estimable`. Report unknown candidate count/rate alongside it. Do not remove unknowns without also showing the adjudicable fraction; provide a conservative bound treating unknown candidates as FP as a sensitivity analysis.

Primary recall is `TP / (TP + FN)` over all independently identified, adjudicated `supported_risk` reference units in the frozen evaluated scope. This denominator is valid only if reviewers completed prediction-blind, exhaustive review of that entire scope, or if a probability sample was drawn and the pre-registered inclusion probabilities and weighted estimator are applied. A post-scan hit-only packet, stratified convenience sample, candidate subset, or zero-hit sample cannot estimate recall. If no exhaustive review or defensible probability sample exists, recall is `not estimable`; do not claim `0 FN`.

Report `unknown` separately from the precision and recall denominators, plus coverage by files and bytes (`complete`, `partial`, `not_run`), scanner blocked status, scope exclusions, and all repository-level counts. Report performance as cohort wall time and peak RSS with environment and repetitions; do not omit blocked/partial sources. Do not calculate accuracy from file-level true negatives in an imbalanced, sampled corpus. For optional specificity/false-positive rate, define a defensible exhaustive negative unit universe before scoring; otherwise mark not estimable.

Use 95% confidence intervals appropriate to the sampling design (clustered at repository snapshot; use design weights for stratified probability sampling). If the number of clusters/classes is too small, report descriptive counts and mark inference unavailable. Do not treat files or repeated runs within one repository as independent clusters.

## 8. Stop rules for missing or invalid data

Stop scoring, preserve available artifacts, and report `not estimable` if any of these occur:

1. cohort/source identity, tree, eligible scope, or source-file hashes cannot be verified;
2. prior development exposure or independence cannot be resolved for any included snapshot;
3. scanner/model/profile/parser/scope hashes are missing, scanner checkout is dirty, or a rule/model change occurred after freeze;
4. frame, selection probabilities, seed procedure, or inclusion/exclusion log is missing or was influenced by scan outcomes;
5. fewer than two independent blind reviewers are available, reviewers are not independent, predictions were disclosed before label freeze, or full-scope miss review is incomplete for a recall claim;
6. reviewers cannot access enough source context to bind the claim, or adjudication/label hashes are absent;
7. partial/not-run coverage prevents a specific claim from being judged. Keep the observation and limitation; do not relabel unknown as safe or missed;
8. output is overwritten, source is mutated, or reproducibility cannot be reconstructed;
9. minimum cohort floors are not met: publish descriptive pilot status only and do not imply population representativeness.

If an interruption occurs, resume only from the immutable frozen manifest, preserve existing logs, document the gap, and keep the original cohort. Never replace missing data with D41/D48 candidates, a known-CVE seed set, synthetic controls, or a new repo selected after observing a result.

## 9. M2 exit criteria

M2 may be proposed for review only when all of the following are satisfied:

- a new source cohort met the frozen independence and provenance screen and the sampling frame/selection are auditable;
- detector/model/profile/parser/scope versions and hashes were frozen before scan and before labels;
- independent blind dual labels cover all scanner findings, and prediction-blind full-scope review (or a defensible probability sample with weights) supports a recall denominator;
- disagreements and unknowns are retained, adjudicated by an independent reviewer, and disclosed with agreement and coverage;
- TP/FP/FN, unknown, precision, recall, intervals, denominators, per-family strata, blocked/partial/not-run coverage, wall time, and peak RSS are reported; any not-estimable metric is explicitly marked;
- repeated run stability is shown without treating repeats as extra sample units;
- results are reproducible from committed manifests/scripts and source identities;
- limitations are reviewed and approved by the D owner. M2 evidence does not close M3 or prove a product vulnerability.

Do not claim M2 exit if recall is not estimable, the cohort is only a convenience sample, labels are model-generated, source overlap is unresolved, or key coverage/unknowns are hidden. If the project narrows its product claim, update this protocol and readiness gate explicitly before scoring; do not redefine the population after seeing results.

## 10. Data handling and report package

Keep source code and restricted excerpts in the approved local evidence store; publish hashes and line references rather than redistributing source unnecessarily. Store label files separately from the prediction key. Retain immutable raw outputs and a derived score table with scripts that verify all hashes before calculation. The final package must include protocol, frame and cohort manifests, selection code/seed record, freeze manifest, scan reports, blinded packet recipe, two original label files, adjudication file, analysis script, score tables, coverage/performance report, deviation log, and a concise limitations statement.

No sample labels, metrics, scanner results, or product claims are created by this protocol document.
