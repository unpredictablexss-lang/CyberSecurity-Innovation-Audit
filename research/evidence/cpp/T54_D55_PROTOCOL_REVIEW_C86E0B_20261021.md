# T54 final delta review of D55 protocol

- Review date: 2026-10-21 (Asia/Shanghai)
- Reviewer checkout: `D:/openHarmonyScanner/worktrees/t51-pasteboard-independent-20261020`
- D55 checkout: `D:/openHarmonyScanner/worktrees/d55-holdout-protocol-20261021`
- Reviewed commit: `c86e0b0321eb38b0ff403e98b8597622c7cd556c`
- Compared with prior review target: `650b2072c33bdbd24f919a61e97fc42453084cb6`
- Scope: read-only verification of the previous T54 findings and regression check of the statistical gates. No D55 files, detector, fixtures, samples, labels, or outputs were modified/accessed.

## Decision

**Protocol design: READY for execution prerequisites. Execution: NOT READY. M2: NOT MET.** The two protocol gaps from the preceding T54 review are resolved on paper: the JSON no longer has duplicate keys and explicit operational rules now cover submodules, symlinks, cross-repository duplicate blobs, vendor copies, and unresolved identity. The D55 execution gate remains closed because the D owner has not approved proposed thresholds and the source frame/cohort, planning simulation, scanner freeze, reviewer custody, and per-CVE advisory package are absent.

No accuracy run has started. The reviewed JSON still states `preregistered_protocol_only`, `accuracy_evaluation_started=false`, `labels_created=false`, `metrics_computed=false`, and `scanner_modified=false`.

## Focused recheck

| Check | Result | Evidence |
|---|---|---|
| Strict duplicate-key JSON validation | **PASS** | Ran the exact `object_pairs_hook` validation prescribed in D55 execution task. It completed with `STRICT_OBJECT_PAIRS_VALIDATION=PASS`. The duplicate `labeling` keys from the prior commit are gone; one unambiguous key for each field remains. |
| Submodule rule | **PASS** | Pin gitlink commit/tree and recursive manifest; include only exact locally available object; unavailable object is recorded and can fail coverage; never follow moving branch/URL. |
| Symlink rule | **PASS** | Record mode, link blob, literal target; do not follow unsafe targets; map in-tree aliases to canonical file once and preserve alias mapping; account for scanner link behavior. |
| Cross-repository identical blobs | **PASS** | Development overlap excludes matching raw content; within-holdout copies form one content unit, deterministic canonical owner is chosen from complete pre-scan frame, aliases are not independent sample units, and unreconstructable grouping stops the stratum. |
| Vendor copies | **PASS** | Exact copies use blob grouping; modified copies require provenance/content comparison; confirmed derivatives share overlap group; unresolved derivative status blocks scoring before scan. |
| Unresolved source identity | **PASS** | `pending` and stop affected stratum; report unavailable objects, aliases, unique content groups, exclusions, and unresolved identity separately. |

## Regression check of prior six areas

1. **Decision thresholds:** unchanged. Per track: precision point ≥0.90 and 95% lower bound ≥0.80; recall point ≥0.80 and lower bound ≥0.70; both interval half-widths ≤0.10; conservative unknown-as-error lower bounds must pass. They remain proposed pending D-owner approval before selection/labels.
2. **Workload floors and planning:** unchanged. 20 snapshots / 1,000 files / 4 families remain workload floors, not power guarantees. Formula, inputs, recall-positive planning, and pre-label design simulation remain specified; insufficient inputs or simulation keeps execution not-ready.
3. **CI estimator and clusters:** unchanged. Design-weighted Hájek ratios with stratified repository-cluster bootstrap, 10,000 PCG64 replicates, frozen seed and percentile 95% intervals; report DEFF and effective n. The <8-per-stratum / <20-per-track inference stop and 8–19 descriptive rule remain.
4. **Known-CVE scope:** 17-ID universe remains pinned; advisory hashes are still not collected. The per-ID advisory manifest hard-stop remains in place, so the known-CVE track cannot execute yet.
5. **Coverage and matching:** unchanged. Coverage gates remain 90% complete, ≤5% not-run+failed, ≤10% unknown; gate failure stops population claims and makes primary target-population metrics not estimable. Partial/not-run no-hit is not negative. Frozen root-cause matcher and `unknown_match` behavior remain specified.
6. **Source/product labels:** unchanged and unambiguous in JSON. `source_label` remains source-claim scoped; `product_applicability` is separate, source-only implies unknown product status, and product unknown does not alter source precision/recall.

## Execution boundary and validation

The reviewed commit changes only D55 protocol/task documentation. `git diff --check 650b2072c33bdbd24f919a61e97fc42453084cb6 c86e0b0321eb38b0ff403e98b8597622c7cd556c` returned exit 0. The strict JSON hook above passed. No scanner tests or accuracy calculations were run.

Before execution, record D-owner approval (or replacement) of the thresholds; freeze an independent source frame, cohort, overlap ledger, design simulation, scanner bundle, reviewer/adjudicator assignments and custody; and collect/hash primary advisory evidence for every CVE before running the known-CVE track. Until those inputs exist, D55 remains execution-blocked and M2 remains **NOT MET**. This protocol does not establish M3 or product applicability.
