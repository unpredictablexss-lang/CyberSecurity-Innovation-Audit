# T4 Review: D2 Supplemental Verifier Follow-up (2026-10-20)

**Reviewed commit:** `c7526e871c52b70d0e41e21adcb02c3185edb8ac`
**T4 review base:** `28c03ad9e5598ebe223e3c867e169a432ac2bc35` (HEAD and clean status verified before review)
**Disposition:** Current evidence and the new recorded-value mismatch gate PASS. One failure-classification gap remains for missing/wrong-type commits/trees and ancestry outcomes when generating a fresh record.

## Scope and reproduced checks

D2 content was read from the specified commit object; current T4 source and all D2 files were left untouched. Runtime checks used a temporary materialization of the D2 script, evidence JSON, profile manifest and self-test file.

| D2 commit file | Git blob | Bytes | SHA-256 |
|---|---|---:|---|
| `research/methods/ark_runtime/build_profile_20261019/README.md` | `bd6abbf1e11cb6ea0eed5f64ffc2f1fb4b2c5baa` | 10702 | `a002978719559cb9be3621e3ad771515c9dae8df0682b6c02315225c7cd7dc1d` |
| `research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.py` | `5805ea4535a15f747063adb701d9a946214530d8` | 16707 | `f7b9fb331fb2d4b97807bc499cc85327d5562c7c1d26bd0cc4c8a47098b696dc` |
| `research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.v1.json` | `37ba27b120047df2dcb95e166cdb150b46b289ee` | 22742 | `5fb5fba277d90c4c8576f986a857a803bd7d40a35844892c2d1c298982d37fd8` |
| `research/methods/ark_runtime/build_profile_20261019/selftest/test_supplemental_source_identity_evidence.py` | `15a68c4b8e3c98ec1c1ff5b4214c5783bd27ada3` | 2298 | `dfd3e5cec4ba0e0fd41693abbd90c212f01e1191bb07bf9a6aaa1bce9b10f1e5` |

Read-only results against `D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git`:

- `python supplemental_source_identity_evidence.py --git-dir <store> --verify-only`: exit 0; output reports anchored=7, unanchored=3, MATCH=17, NOT_RECORDED=69, MISMATCH=0, missing-side=2, blocked expected paths=0, then verifies the saved artifact equals recomputation.
- `python supplemental_source_identity_evidence.py --self-test`: exit 0.
- `python -m unittest discover -s <temp-profile>\selftest -p test_supplemental_source_identity_evidence.py`: 4 tests passed.
- README's dotted-module `python -m unittest research.methods.ark_runtime.build_profile_20261019.selftest.test_supplemental_source_identity_evidence`: 4 tests passed from the temporary materialization.
- Injected CLI summary with MISMATCH=1 returned exit 2, confirming the main gate fails recorded mismatch.
- No network fetch, target build, runtime test or PoC was run.

## Counter audit

Counts are mutually exclusive across recorded comparisons: 14 tree checks plus 72 file-field comparisons (24 present blobs × three fields) = 86 comparisons; 17 MATCH + 69 NOT_RECORDED + 0 MISMATCH = 86. The two `NOT_PRESENT_IN_THIS_SIDE` paths have no recorded field comparisons, so are correctly reported in the separate missing-side count and do not overlap the three result buckets. The synthetic tests exercise one missing-side path and verify it is counted separately. NOT_RECORDED is not included in MATCH. The current JSON's totals and per-field subtotals agree.

Historical profile manifest was not changed by the follow-up: its Git blob is `aa66a987d772c5db1a664a7cdc9770fae23f3d88` in both `0795106aa054b0cda8650d670fae66470ff83a48` and `c7526e871c52b70d0e41e21adcb02c3185edb8ac`; `git diff` for that file is empty.

## Follow-up finding

`has_verification_failure()` fails on recorded-value MISMATCH or `BLOCKED_EXPECTED_PATH_*`, which covers this commit's mismatching tree/blob/SHA/length comparisons and unreadable expected paths. However, `summarize()` does not count side status `BLOCKED_OBJECT_MISSING_OR_WRONG_TYPE` or `BLOCKED_TREE_MISSING`, and does not classify `parent_is_ancestor_of_fixed` values `FAIL` / `BLOCKED_ERROR`. `has_verification_failure()` therefore ignores those outcomes. With a pinned manifest and today's object store, all 14 anchored commits resolve, all trees are present, and all seven ancestry checks pass, so this does not invalidate the current 17/69/0 result. For future robustness, count these as separate failure states and make generation fail closed (or explicitly label the produced record blocked) when any occur; add synthetic tests for missing commit, missing tree, ancestry FAIL and ancestry BLOCKED_ERROR.

## Evidence boundaries

- **Local object consistency:** PASS for the current recomputation against the configured local bare object store.
- **Acquisition custody / server authenticity:** UNKNOWN. A self-configured Gitee remote and reproducible object hashes do not authenticate acquisition, custody or server responses.
- **Product profile:** remains BLOCKED / NOT_ADMITTED, 0/16 complete; PC-1 remains `IN_PROGRESS_BLOCKED`. The follow-up does not connect source objects to a product build, preprocessing result, runtime path or shipped binary.

## Scope check

Only this report is added under `research/methods/ark_runtime/ibs5yg_profile_gap_20261020/review/**`. No D2 file, historical manifest, source object store or other T4 path is modified.
