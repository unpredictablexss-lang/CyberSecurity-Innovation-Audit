# T4 Review: D2 Fail-Closed Verifier Repair (2026-10-20)

**Reviewed commit:** `31d2a3e07d67f937fb059ab656e31a8d33dcb00b`
**T4 review base:** `63d75ff470c899878e21dc3f24f4598e4019676f` (HEAD and clean status verified before review)
**Disposition:** PASS for local object identity computation and the recorded-value/blocker failure gate on the reviewed evidence. Custody/authenticity and product-profile gates remain unresolved/blocked.

## Scope and changed-file hashes

The four D2 files were read from commit blobs. No D2 branch or file was modified. The verifier and self-tests were materialized under a temporary directory for execution.

| Path | Git blob | Bytes | SHA-256 |
|---|---|---:|---|
| `research/methods/ark_runtime/build_profile_20261019/README.md` | `4841231edb7b582733cc7071eac6218098f700ff` | 10914 | `8df0455fcd946ca64cade05c7f19324c4fe8b437f87414a4d910d1d27d83d840` |
| `research/methods/ark_runtime/build_profile_20261019/selftest/test_supplemental_source_identity_evidence.py` | `3fb100bb4de751b682e82321a84cc4e83db00b4f` | 4442 | `c73cab5a650f25217fbbc6fd79cc1c0e17f6bec9f8b62499e96a265469537642` |
| `research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.py` | `a45a2adfdd1fb256fea8afee637d7ff4ea93b5f6` | 19300 | `2b47b6b32b2f5dfd30a2d6e8bb0cfbd7d62aaf7a2d4b25d8ee5d7dd70f1363e7` |
| `research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.v1.json` | `d69b6fdcc3b032bb48d45a1ba8290fcafcbf4272` | 22961 | `93d9d65791beadb15e34f204c727d5c23bd9a902b7d1f851a8d8dcbdaa20b16a` |

## Reproduced validation

All checks used the configured local object store `D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git`; no network fetch, product build, product runtime test or PoC was run.

- `python supplemental_source_identity_evidence.py --git-dir <store> --verify-only`: exit 0. Summary: 7 anchored / 3 unanchored cases; MATCH=17, NOT_RECORDED=69, MISMATCH=0; missing-side paths=2; blocked expected paths=0; all blocker counters=0. Saved JSON exactly matched recomputation.
- `python supplemental_source_identity_evidence.py --self-test`: exit 0.
- `python -m unittest discover -s <profile>\selftest -p test_*.py`: **16 tests passed**.
- Independently injected synthetic states through the CLI main gate. Each returned exit code 2: missing/wrong-type commit object, missing tree, blocked expected path, ancestry `FAIL`, ancestry `BLOCKED_ERROR`, ancestry `UNKNOWN`, and a side with no bound commit.
- `NOT_RECORDED`-only synthetic evidence returned exit 0 with `--write`, `MATCH=0`, `NOT_RECORDED=5`, `MISMATCH=0`, and no blockers. Thus missing expectations are not promoted to matches and do not fail by themselves.

## Counter and manifest audit

For current evidence, the recorded-identity categories are mutually exclusive across 86 comparisons: 14 tree checks plus 72 present-blob field checks (24 blobs × Git blob ID/source SHA-256/length). `17 + 69 + 0 = 86`. The 2 missing-side paths are reported separately and have no value comparisons. Per-field totals in the JSON add up to the same total; NOT_RECORDED contributes only to its own bucket.

The historical profile manifest is unchanged between `c7526e871c52b70d0e41e21adcb02c3185edb8ac` and `31d2a3e07d67f937fb059ab656e31a8d33dcb00b`: both contain blob `aa66a987d772c5db1a664a7cdc9770fae23f3d88`, and the manifest path has no diff.

No counterexample to the requested fail-closed behavior was observed for the tested missing/wrong commit object, missing tree, expected-path block, ancestry failure/error/unknown, recorded mismatch, or NOT_RECORDED-only cases. The current record's actual seven ancestry checks all PASS and none of its expected identities are blocked.

## Evidence boundaries

- **Object identity computation / recorded-value gate:** PASS for the reviewed local bare object database and the verified record. This establishes internal consistency with that configured store and the recorded values only.
- **Acquisition custody / server authenticity:** UNKNOWN. Matching object IDs and a self-configured Gitee remote do not authenticate acquisition, custody or server responses.
- **Product profile:** BLOCKED / NOT_ADMITTED, 0/16 complete; PC-1 remains `IN_PROGRESS_BLOCKED`. This work does not bind the source to a product build, preprocessing output, runtime path or shipped binary.

## Scope and diff checks

Only this report is added beneath `research/methods/ark_runtime/ibs5yg_profile_gap_20261020/review/**`. The reviewed T4 base was clean. The report commit is checked for path scope, clean worktree and `git diff HEAD^ HEAD --check` before delivery.
