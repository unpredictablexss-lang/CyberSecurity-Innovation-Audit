# Ark Runtime Detector independent holdout restart plan

Date: 2026-10-18  
Applies to: frozen v0.6.2 assessment `ark-runtime-c-independent-holdout-20261018-v2`

## Decision

The current assessment is a reproducibility/readiness package, not a performance holdout. Keep its detector lock, source roster, and replay history immutable. Do not assign labels or calculate TP/FP/FN, precision, or recall for this assessment.

Verification currently confirms the frozen scanner commit/tree, implementation and parser identities, model digest, and all 9 source identities. All 9 replay rows are `not_applicable` to v0.6.2. The prior replay was run before label freeze. Its escrow is unavailable in this checkout. Therefore none of those rows can be treated as a detector miss, safe result, or an independent label set.

## Restart protocol

A future run is a **new assessment**, with a new ID and its own immutable directory. It must not alter this assessment's lock or reinterpret its 9 rows.

1. **Freeze a generalizable detector build.** Select the implementation, rules, applicability contract, configuration, parser/runtime dependencies and model inputs before examining the new sample roster. The applicability contract must accept previously unseen source identities by declared semantics; do not add exact source revisions after seeing candidate cases. Record Git commit/tree, every relevant file SHA-256, model/config digest, dependency versions and build command. Verify the build from a clean archive.
2. **Freeze the development exclusion corpus.** Inventory all development, tuning, demos, prior experiments, synthetic controls, and any previously exposed cases available to the project. Store exact repository/revision/path/blob/SHA-256 identities and known root-cause/fix-family IDs. Mark unavailable history explicitly. If this inventory cannot support a defensible family-level exclusion audit, stop before sample selection and report the external-history limitation.
3. **Select samples by root-cause family.** Use sources not used in detector development/tuning. Group all variants and sibling fixes by underlying cause, then assign whole families to one split. Avoid patch-family leakage, not just duplicate-file leakage. Include vulnerable, fixed, safe, unrelated, and parser-incomplete examples; retain unknown/partial as explicit states. Record source origin, pinned revision, path, Git blob, raw-byte SHA-256, byte length, parser version/state and reproducible retrieval instructions for every unit.
4. **Freeze identities and eligibility before annotation.** A custodian verifies every source hash and split, completes the family leakage audit with evidence references, and records exclusions with reason. Freeze a manifest digest and a signed/dated eligibility snapshot. Exclude any family with detected overlap or incomplete scope unless a documented, conservative exclusion resolves it. Do not use detector output to select or exclude samples.
5. **Establish reviewer independence before access.** Obtain declarations from two named reviewers that they did not tune the detector, have not seen predictions for these samples, and have no disqualifying source/patch exposure. Keep reviewer identities and randomized blind IDs in the admin-only key. Provide both reviewers the same source evidence and labeling guide, without detector version-specific predictions or scores. If suitable reviewers cannot be obtained, stop with labels pending; do not self-label.
6. **Collect independent labels.** Each reviewer independently assigns vulnerable, fixed, safe, unrelated, partial, or unknown and records root-cause ID, evidence/locations, confidence, and exclusion recommendation. Preserve both snapshots unchanged and hash them. Record disagreements. An independent adjudicator resolves disagreements with cited evidence, or leaves the unit unknown/excluded; never silently overwrite a review.
7. **Freeze labels before prediction reveal.** Freeze and hash both review snapshots, the adjudication ledger, exclusions, final label set and timestamp. Confirm all required classes and at least one retained parser-incomplete unit, and report counts including partial/unknown/excluded. Only after this gate may the custodian reveal/run the frozen detector against the exact frozen input bytes and archive raw output with a digest.
8. **Score at root-cause level.** Validate detector/build and source hashes again. Join blinded labels via the admin key, deduplicate by `(sample identity, adjudicated root-cause ID)`, and calculate TP/FP/FN, precision and recall only for eligible, applicable, adjudicated observations under a predeclared matching rule. Report not-applicable, blocked, partial, unknown, excluded and parser-state counts separately. If a required class, applicability, independence or identity gate fails, report metrics as not estimable and state the failed gate.

## Stop conditions

Stop without metrics if any source identity cannot be reproduced; any family-level overlap remains unresolved; detector/config/parser changes after sample selection; applicability requires post-selection exact binding; reviewers saw predictions or tuning outputs; reviewer independence is unverified; labels or adjudication are incomplete; or labels were frozen after prediction reveal. Such failures require a new assessment cycle, not an exception added to the existing lock.

## Current action ledger

| Item | Status |
|---|---|
| Preserve v0.6.2 lock and old replay as historical evidence | Done |
| Reproduce frozen scanner/model/parser and source identities | Done: 9/9 source identities verified |
| Verify current audit-package file hashes | Done: 25 entries, no mismatches |
| Establish target applicability for current roster | Failed: 0/9 applicable |
| Establish independent two-reviewer labels and declarations | Pending: no independent reviewers supplied |
| Freeze labels before prediction reveal | Not done; prior replay explicitly says false |
| Compute root-cause metrics | Prohibited for this assessment; not estimable |
| Start a new detector build and untouched holdout | Requires a future independent sample roster and two qualified reviewers |

The user authorized the work but has not supplied reviewer identities/declarations or an independently selected unseen sample roster. Authorization cannot substitute for independent evidence, and this plan does not invent either.
