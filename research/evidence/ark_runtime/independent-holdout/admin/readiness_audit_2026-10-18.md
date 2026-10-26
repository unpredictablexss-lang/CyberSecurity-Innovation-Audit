# Readiness audit: Ark Runtime independent holdout

Audit date: 2026-10-18 (Asia/Shanghai)  
Assessment: `ark-runtime-c-independent-holdout-20261018-v2`  
Disposition: **not a valid performance holdout; do not report accuracy metrics**

## Verified package state

- Frozen detector lock records `ohscanner.ark.runtime.type_safety` 0.6.2, both rule IDs, model digest `662c74d79b75b2a111f7ec0eca4cb819a8b1f092ea3e9f7e6cff63621a3d8a1a`, scanner commit/tree, implementation/parser hashes, and 18 model-input paths. A fresh `git archive` reconstruction matched the recorded scanner tree, all 7 implementation hashes, parser AST hash, detector version and model digest.
- The source manifest has 9 unique source rows with commit/tree/path/Git blob/source SHA-256/byte length and parser state; its frozen parse counts are 8 complete and 1 partial. `verify_frozen_holdout.py` freshly fetched each source from the official `raw.githubusercontent.com` endpoint at the manifest commit/path: all 9 byte lengths, SHA-256 values, recomputed Git blob SHA-1 values, parser statuses and parser issue counts match. Parser dependencies were Tree-sitter 0.26.0 and tree-sitter-cpp 0.23.4.
- The recorded blind replay has 9 `blocked`, 9 `not_applicable`, and 0 candidates. It explicitly records `labels_frozen_before_run: false`; no output is a TP, FP, FN, or safe result. The recorded prediction escrow file is absent at its path in the current workspace and was not read; only the old summary path/digest is available.
- All 25 entries in the package hash index matched the files present when this audit was prepared. The old `artifact_hashes.json` was stale and referenced files absent from the package; it has been marked superseded. `package_hashes.json` is the current index.
- A scoped family audit found no exact JSStableArray patch identity in available C1-C6 corpora, but C1/C3 discuss the related TypedArraySpeciesCreate concept; five other rows are only selection strata without adjudicated root-cause families. All family rows are explicitly incomplete because external/untracked tuning history and independent root-cause adjudication are absent. Export/scoring gates now require complete coverage of every manifest family; scoring also requires all four adjudicated classes and a retained partial-parse row. Reviewer declarations/submissions, adjudication ledger, and exclusion ledger remain templates. There are no reviewer labels, signatures, adjudications, or reasoned sample exclusions.

## Why the evaluation cannot be completed from this roster

1. Every row is outside the frozen detector's applicable source bindings; replay confirms 0/9 applicable. The detector model explicitly binds its typed-array analyses to exact source revisions and content hashes.
2. The scorer also requires holdout paths to be disjoint from all detector model-input paths. For this detector, that rule excludes the only source paths on which the frozen model is modeled. The combination leaves no demonstrated target-applicable row.
3. Adding another upstream revision of the target file to the bindings changes the model digest/configuration. That would be a new detector freeze, not an evaluation of v0.6.2 as currently locked. Do not add a sample or bind a revision after inspecting the current roster and call it an untouched evaluation.
4. The two known patch families were searched across current and sibling local C1-C6 artifacts with no exact JSStableArray patch identity. Developer records do discuss TypedArraySpeciesCreate; whether that is a related root-cause family is unresolved. The other five manifest groups are structural strata, not independently established root-cause families. External/untracked materials and complete family independence remain unresolved.
5. No qualified independent reviewers have submitted pre-access exposure declarations or double labels. The user's permission to proceed does not create independent human evidence. Do not infer labels from patch direction, issue titles, tests, the detector output, or this agent's assessment.

## Required next assessment

Retain this package as an audit trail and protocol template only. For performance evaluation, first issue a detector build whose supported scope can process unseen source identities without post-selection binding changes, and freeze its implementation, rules, configuration, parser, and applicability contract. Then select root-cause families absent from all development/tuning material; freeze all source identities and hashes; obtain two genuinely independent pre-access reviewer declarations and blind labels; adjudicate and freeze labels before opening the prediction escrow. Record vulnerable, fixed, safe, unrelated, partial/unknown and exclusions. Calculate root-cause TP/FP/FN and precision/recall only if those gates pass. Until then all such metrics are **not estimable**.

## Reproducibility caveat

The manifest makes each selected identity explicit by upstream commit, tree, path, Git blob, SHA-256 and byte length. This audit recreated the scanner archive and ran `python admin/verify_frozen_holdout.py --scanner-repo <scanner-checkout>`; it freshly fetched all 9 source files from the official raw source endpoint at their pinned commits and matched source SHA-256, Git blob SHA-1, byte length, and parse state. A complete local Git object store was unavailable, so commit tree IDs were not independently re-derived in this continuation; they remain pinned manifest fields. This validates the source identities needed for the row-level roster, while a full object-store reproduction can additionally verify the tree IDs.
