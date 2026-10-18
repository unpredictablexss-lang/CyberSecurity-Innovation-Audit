# Ark Runtime independent holdout — v3 restart status

Assessment ID: `ark-runtime-c-independent-holdout-20261018-v3`  
Recorded: 2026-10-18 (Asia/Shanghai)  
Status: **Detector frozen; stopped before sample selection; no predictions or scoring**

This is a new assessment directory, separate from `research/evidence/ark_runtime/independent-holdout/`. The v0.6.2 assessment and package files remain unchanged; its 26 indexed file hashes were rechecked with zero mismatches.

## Frozen Detector

`ohscanner.ark.runtime.type_safety` **0.7.0** is frozen at scanner commit `ff03077fd1bd963e51f22f43e4cb25f3669a0f0e` and tree `e76488731ff3410eb26bdb9b2bc3d95abbd1e467`. Model digest: `548996ced072b847e2a01d17c4f56de11b6fe4e42e3657f1434c7b8fbc9f3aca`. The freeze record fixes the rules, configuration, dependencies, implementation file hashes, semantic applicability contract, and verification evidence. Its selector accepts new commit, path, blob, and source-hash identities when the declared C++ owner and method semantics resolve. Blob and source hashes verify supplied bytes; they are not model allowlists.

The clean archive was extracted from the frozen commit and the dedicated unseen-source suite returned **6 passed, 2 skipped**; the skipped cases require the separate Ark Runtime Git object store. With the local Ark repository configured, all **8 dedicated controls passed**, including unseen fixed upstream and exception-guard parent/fix revisions. The focused Ark Runtime and runner applicability suite returned **103 passed, 10 skipped**. These are development controls. They do not establish independent holdout provenance or performance.

The detector uses Tree-sitter syntax and does not prove preprocessing, compiler configuration, complete types, whole-program flow, runtime reachability, shipped product binding, or CIA impact. The assumed `NDEBUG=1` and `ENABLE_ASM_ASSERT=0` profile remains unverified. Partial or damaged syntax remains partial/unknown rather than safe.

## Development and family exclusion inventory

`admin/development_exclusion_inventory.csv` contains **78** known source identities across upstream development inputs, model dependencies, the nine previously exposed v2 cases, synthetic fixtures and review controls, and an explicit unavailable-history row. The v2 cases are conservatively excluded; no v2 prediction values were inspected or reused.

`admin/development_artifacts_manifest.csv` hashes **232** experiment, fixture, detector, test, and evidence artifacts across three local checkouts. It includes committed, modified, untracked, and ignored worktree files. The new v3 assessment directory and generated Python bytecode are excluded from its own inventory. External or untracked development, tuning, demo, prior-exposure, and reviewer-contact history remains unavailable, so root-cause-family exclusions cannot be established completely.

The restart plan therefore requires stopping **before examining, selecting, or hashing a new sample roster**. No new sample manifest exists and no new sample hash was created.

## Review and scoring gates

No two qualified reviewers with pre-access declarations were available. The assessed evidence contains templates but no signed declarations or completed independent labels. No v3 reviewer packet, label snapshot, adjudication, or prediction reveal exists.

Coverage of vulnerable, fixed, safe, unrelated, and partial/unknown holdout samples is **not assessed**. No eligible applicable sample set is established. TP/FP/FN and Precision/Recall were **not computed**; the status is `not_estimable_not_computed`. This blocked assessment does not support a performance claim.

## Integrity

- Frozen Detector: `bf823d7281942a9b1b6b90ba2ecf0e66cd0dcdc06e6b145deed912787403a1ab`
- Applicability contract: `246c7126e112788dfa69a2eee226b1bf573e06aafcfe6c7a5cda5101c614441a`
- Dependency lock: `e7de5fd6ac25e23184bb41361f694a97dadec299a1b707191f01b8ec31aa2b47`
- Clean archive verification: `36a1e8cb26d08e227e993f61095046c9e4984ada046e2845e2a0e82e4808b5e6`
- Source inventory: 78 rows, `be57ec005f206f97eeba558cd11ae3323960b0ea1e45285d7c01d3142f7d4082`
- Artifact inventory: 232 rows, `a381a0e676cb9545a27b5c47697bc7bb9b7569633265b7e3af62a89af1f2c708`
- Machine-readable assessment state: `dbcbad03e6b5b82dd597069b5ea07ec5036e01cea0f9b8b8a3e49dd7abd5caab`
- Original v0.6.2 package: 26/26 indexed file hashes match.
