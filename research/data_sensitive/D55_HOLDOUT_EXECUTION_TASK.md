# D55 independent holdout execution task

> **Execution state:** not started. This is a structured handoff prompt for a future D55 data steward and independent review team. It intentionally contains no sample labels and does not authorize changing scanner rules during evaluation.

## Vibe coding prompt

You are the D55 independent holdout data steward and evaluation coordinator for OHScanner D. Your goal is to produce an auditable, source-bound, independently labeled evaluation for D5 M2 while preserving unknown and partial evidence. Follow [`D55_INDEPENDENT_HOLDOUT_PREREGISTRATION.md`](D55_INDEPENDENT_HOLDOUT_PREREGISTRATION.md) as the controlling protocol.

### Context to honor

- Read `research/data_sensitive/D5_MAIN_READINESS.md`, `D5_HOLDOUT_LABELS.md`, `D41_HOLDOUT_PREREGISTRATION.md`, `D41_HOLDOUT_MANIFEST.json`, `D41_HOLDOUT_RESULTS.md`, `D41_BLIND_REVIEW_PACKET.json`, `D48_HOLDOUT_PREREGISTRATION.md`, D49/D50 replay records, and D51/D52/D53 records before proposing a cohort.
- D41 is a post-scan stratified packet with zero independent labels; it is stale for current detector versions and is not a population holdout.
- D48 is a 97-file convenience source replay with zero candidates, all files partial, blocked run, and no labels; it is not a clean scan or accuracy sample.
- D49/D50 and D51–D53 are rule-development or targeted evidence. Exclude them and any sources/rules/paths used to tune D. The known-CVE track is limited to the fixed 17-ID catalog in `D_KNOWN_CVE_SCAN_20261019.md`; pin its Git blob/SHA and a primary advisory snapshot/hash for every ID before execution. Existing development source instances remain excluded.
- D53's product-template correlation is not proof that a built product contains the source. Do not use it to assign source or product labels.
- Evaluate `ohscanner.data.sensitive_exposure` and `ohscanner.known_disclosed_cves` as separate tracks. The latter's claim is limited to its frozen declared CVE catalog.

### Hard constraints

1. **Do not edit scanner, detector, model, parser, profile, scope policy, or candidate ranking during D55.** If a change is necessary, stop and define a new holdout generation.
2. **Do not invent, infer, auto-fill, or calculate labels.** `source_label` and `product_applicability` are separate fields; source-level unknowns must not be conflated with product-applicability unknowns. A label must come from two independent qualified human reviewers and, when needed, an independent adjudicator with source-bound evidence.
3. **Do not calculate precision, recall, TP, FP, FN, TN, accuracy, or zero-FP/FN claims before the freeze, complete blind labels, adjudication, and denominator gates in the protocol are met.**
4. Do not use a scan result to choose, replace, or exclude repositories. Do not reveal predictions to reviewers until labels are frozen.
5. Unknown, partial, not-run, missing, and conflicting evidence stays visible. Never coerce it into safe, negative, false positive, or missed.
6. Do not modify source mirrors, fetch implicit refs, or overwrite earlier evidence. Preserve every raw report and failed attempt.
7. Do not claim product applicability or M3 from source-only labels.

### Work sequence

#### A. Readiness and independence screen

1. Verify the active checkout, full base SHA, remote, clean/dirty state, and local `AGENTS.md` rules. Record them in the run log.
2. Search all D records and scanner history through the proposed cutoff for repo/commit/tree, archive/member, source path, candidate family, and tuning exposure. Produce an exclusion/overlap ledger with exact evidence paths.
   - Apply the explicit source identity rules in the protocol: pin submodule gitlinks recursively; record but do not follow unsafe/out-of-tree symlinks; exclude any raw blob shared with D development; group same blobs across cohort repos under one precomputed canonical owner/inclusion probability; identify exact and modified vendor derivatives. Unresolved identity means stop the affected stratum before scan.
3. Build a sampling frame from the separately identified source inventory. Record its origin and timestamp. Include selected and non-selected eligible snapshots, their pre-scan strata, immutable identities, prior-use result, and inclusion probabilities. For the known-CVE track, also freeze the exact 17-ID catalog, its Git blob/SHA, each primary advisory's saved bytes hash, source/version scope, and a disjoint new source-instance plan.
4. Use the preregistered random, stratified, reproducible selection procedure. Freeze and hash the frame, protocol, seed commitment, cohort, and selection code **before the scan**. Run and freeze a design-based precision-planning simulation against the fixed interval-width/lower-bound targets. The 20 repository / 1,000 file / 4 family floors are workload minimums, not a power calculation; the simulation and final effective cluster count govern sufficiency. If a suitable frame or independence evidence is unavailable, stop at `not ready`; do not substitute old D samples.

#### B. Scanner and source freeze

1. In a clean, immutable scanner checkout, record full code commit SHA, detector/model/profile/catalog/parser/postprocessing hashes, scope/path policy, config, and runtime environment. Hash all sources and eligible paths.
2. Have a second person verify the manifest and freeze it before execution. Any mismatch or untracked change stops scoring.
3. Run each selected snapshot with the exact frozen command. A second identical round is allowed for stability/performance only. Record raw outputs, partial/blocked states, wall time, peak RSS, and every retry. Never tune between runs.
4. Hash and seal predictions. Prepare random opaque reviewer IDs and prediction-blind packets with full context. Keep the mapping to candidate status outside reviewer access.

#### C. Independent blind review

1. Assign two qualified reviewers who had no role in D development, cohort selection, or scanning. Obtain conflict declarations.
2. Each reviewer independently reviews all relevant source scope without candidate indicators, marks every finding using `source_label` (`supported_risk`, `protected_safe`, `unrelated`, `unknown`), cites supporting and contradicting evidence, and records scanner coverage and `product_applicability` (`supported`, `refuted`, `unknown`) separately. Source-only input sets product applicability to `unknown` without changing the source label.
3. Freeze and hash both complete label files before revealing any scanner prediction. If either reviewer saw predictions or could not review the full scope, recall is not estimable; preserve what was reviewed and report the stop condition.
4. Let an independent adjudicator inspect disagreements and metric-relevant unknowns before unblinding. Keep both original labels and retain unresolved cases as unknown.

#### D. Score and report only after all gates

1. Freeze the adjudicated labels, raw scanner outputs, analysis code, and all hashes before unsealing the prediction key.
2. Apply the frozen finding matcher; calculate only track-specific and preregistered stratum metrics. Use the frozen stratified repository-cluster bootstrap/DEFF estimator, seed, 10,000 replicates, small-cluster rules, and coverage/unknown stop mapping from the protocol. Print every numerator and denominator, unknown count/rate, coverage table, sampling design, cluster-aware interval, runtime/RSS, and deviation.
3. Precision uses adjudicable scanner findings; recall requires all independently found positives from exhaustive review or a valid weighted probability sample. If either condition fails, mark that metric `not estimable`.
4. Write a report that distinguishes scanner coverage from label, source finding from product vulnerability, and stable replay from independent accuracy. Reconcile the result into D5 readiness only after owner review.

### Required output files

Create a new immutable evidence directory, for example `research/data_sensitive/D55_HOLDOUT/<campaign_id>/`, with:

- `README.md`: protocol revision, state, decisions, deviations, result boundary;
- `sampling_frame.csv` and `sampling_frame.sha256`;
- `cohort_manifest.json` and `exclusion_ledger.csv`;
- `freeze_manifest.json` and verified source/scope hash manifest;
- `scan_raw/` with first and repeat raw reports, logs, and file coverage;
- `review_packet_manifest.json` and a separate sealed `prediction_key` stored outside the labeler packet;
- two original blind label files, separately access-controlled and hash-frozen;
- `adjudication.json` preserving initial labels and evidence;
- a hash-verifying, deterministic `score.py` and score tables;
- `deviation_log.md`, performance/coverage summary, and final limitations statement.

Do not commit private source excerpts, restricted data, secrets, or labeler identity. Commit reproducible manifests and hashes where policy permits.

### Definition of done

D55 is ready for an accuracy readout only if the protocol's source independence, cohort, scanner freeze, blind double review, adjudication, coverage, denominator, reproducibility, and minimum cohort conditions are met. Otherwise deliver the completed evidence of the stop condition and mark the appropriate metric `not estimable`. M2 remains open until every M2 exit criterion in the preregistration is met and reviewed; this work alone cannot close M3.

Before committing or scoring, validate the JSON companion with duplicate keys rejected (not just a permissive parse):

```powershell
python -c "import json,pathlib; p=pathlib.Path('research/data_sensitive/D55_HOLDOUT_PROTOCOL_20261021.json'); json.loads(p.read_text(encoding='utf-8'), object_pairs_hook=lambda xs: dict(xs) if len(dict(xs)) == len(xs) else (_ for _ in ()).throw(ValueError('duplicate JSON key')))"
```

### Final handoff format

Report:

1. exact checkout and full base/final commit SHAs;
2. protocol/frame/cohort/scanner/label hashes and verification results;
3. counts of eligible, selected, excluded, scanned, partial, not-run, and independently adjudicated units;
4. for each metric: status, numerator, denominator, estimate/interval or `not estimable`, and why; compare the CI lower bound and half-width with the preregistered per-track threshold;
5. blinding, independence, deviations, unknowns, and unresolved limitations;
6. M2 exit checklist state and explicit statement that source-only evidence does not establish M3.

If any required input is absent, stop at the corresponding gate, preserve evidence, and request only that specific missing input. Do not fabricate substitutes.
