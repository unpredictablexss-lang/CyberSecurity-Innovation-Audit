# C-line Detector evaluation governance record (admin-only)

Assessment: `ark-runtime-detector-evaluation-20261018-v1`  
Disposition: **not estimable; no reviewer packet or prediction escrow created**

This directory contains administrator governance and freeze metadata. Do not distribute it to reviewers. No reviewer-only packet exists because this frozen Detector exposes no demonstrated unseen, applicable source identity. The prior nine-row roster is expressly excluded from performance use: all nine were `not_applicable`, none has independent labels, and none may be relabeled or repackaged as performance data.

## Frozen evaluation target

- Detector: `ohscanner.ark.runtime.type_safety` 0.6.2.
- Rules: `ark.runtime.typedarray-store-type-origin` and `ark.runtime.typedarray-allocation-exception-guard`, both 0.6.2.
- Model digest: computed from `RuntimeTypeModel` at the recorded scanner commit; see `freeze.json`.
- Implementation identity: scanner commit and tree plus SHA-256 for model, detector, analysis, syntax/parser, IR, type-origin and exception-guard modules in `freeze.json`.
- Parser profile: tree-sitter C++ parser; the prior verified holdout audit records Tree-sitter 0.26.0 and tree-sitter-cpp 0.23.4. That profile is a pinned evaluation dependency, not proof of the product compiler/parser configuration.
- Build profile: `assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;not_product_build_verified`. It remains an unresolved assumption and limits interpretation.

## Applicability contract and result

An input is applicable only when the repository identity is `openharmony/arkcompiler_ets_runtime`, the source is a C++ translation unit containing the modeled exact owner/signature/sink structure, all required source and dependency identities are available and match a declared binding, the parser exposes sufficient complete structure for the rule, and the modeled build assumptions are not contradicted. The type-origin and exception-guard rules have separately versioned bindings; a unit is assessed per rule. Missing or mismatched identity, incomplete dependencies, unsupported build context, or insufficient parse is `unknown`/`not_applicable`/partial, never a negative label. This target's current source bindings are exact commit/path/blob/source-SHA bindings. They do not establish generalization to unseen revisions.

The old 9 rows were all `not_applicable`. The model-input path disjointness condition in the existing scorer also rules out the currently bound target path, while selecting another revision and adding a binding changes the model digest and therefore requires a new freeze. No candidate source set was found in the available local artifacts that is both demonstrably from an unseen development/tuning family and demonstrably applicable under this frozen exact-binding contract. No sample is eligible. Coverage is therefore **0 eligible samples demonstrated**, not a miss or safe result. Do not lower applicability or independence criteria to fill the set.

## Protocol and score gate

Before any future sampling: record source commit/tree/blob/source SHA-256, per-rule applicability evidence, parser/build profile, family identity and leakage-search scope; freeze all inputs and the scoring protocol; then run the frozen Detector once and escrow predictions under admin access. Generate independent random reviewer IDs, keep the ID key and predictions admin-only, and provide reviewers only source-only randomized packets and annotation forms. Two reviewers must independently record vulnerability mechanism, reachability, impact, fix evidence, label rationale and prior exposure before seeing predictions, development samples, tuning history or each other's labels. A predesignated independent third adjudicator resolves disagreements. Log every inclusion/exclusion and family-leakage search; preserve excluded rows with reasons.

The score protocol is fixed: score root-cause observations, deduplicated by `(sample identity, adjudicated root cause)`. Report TP/FP/FN, precision/recall and any strata only after applicable samples have complete labels, both reviews, adjudication, frozen exclusions, verified source identities, and an unchanged protocol frozen before results. Unknown, partial, blocked, failed and not-applicable observations are coverage limitations, never negatives. Any Detector/rule/parser/profile or protocol change requires a new assessment and a newly sourced holdout; the same set cannot be reused after tuning.

## Current governance state

- Sample inventory: no eligible rows established; legacy nine explicitly excluded from performance evaluation.
- Randomized reviewer IDs / blinded package: not generated; no reviewer received materials.
- Prediction escrow: not generated for this assessment.
- Reviewer declarations, labels, disagreement resolution: not started; no independent reviewers have been appointed or attested.
- Family leakage ledger: not complete for external/untracked tuning history; this is independently disqualifying.
- Metrics: TP/FP/FN, precision/recall and strata **not estimable**.
- No push, merge, or tuning performed.

## Scoring-tool review

The existing `score_holdout.py` in the adjacent C-line admin package is fail-closed for absent hashes, declarations, family audit, labels/adjudication, source identity, and non-applicable/incomplete predictions. Invocation was limited to its help/entry-point and source review; no score was attempted and no escrow was opened. It is not a substitute for the missing dataset. The scorer's present gates do not themselves establish that a sample is suitable or unseen; that must be independently recorded before export. Any future use must review its implementation against the frozen protocol and preserve a pre-result protocol hash.

## Hashing and access boundary

`freeze.json` records the target implementation hashes. `SHA256SUMS` covers this admin record's files except itself. The admin directory has an explicit Windows ACL granting access only to the current owner, SYSTEM, and local Administrators; inherited access was removed and verified. Reviewer-only files are intentionally absent. Do not copy admin records, predictions, family IDs, or source identities into reviewer packets.
