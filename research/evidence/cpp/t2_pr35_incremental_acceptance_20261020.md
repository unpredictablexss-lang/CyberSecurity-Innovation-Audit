# T2 independent PR #35 incremental acceptance

Date: 2026-10-20 (Asia/Shanghai)
Checkout: `a-t2-independent-pr35-20261020` (detached)
Target: `abd7d55fb0f38215d879d427664ad6a4531170be`
PR #35 development base: PR #34 owner-approved commit `2db47f7fc0860f036c53dc12bccd63d62bcc23d8`

## Decision

**PARTIAL.** I independently checked the PR #35 incremental evidence for Contacts, both cJSON cases, both libpng cases, and dSoftBus CVE-2025-26690. Source/CLI/queue verifiers passed where the bound object stores were available. None of these results is a product-level safety conclusion. The two libpng cases remain blocked by partial parsing and zero findings; cJSON lacks a trusted fixed source and one file parses partially; Contacts lacks a trusted fixed source and remains a blocked partial candidate; dSoftBus has partial semantic detector coverage and no component-specific safe/unrelated controls.

I also reran the available A0 follow-up checks D53/T59 and T55–T58. Their original A0 IDs and states remain unchanged. D51 and D52's ordinary checkouts have invalid `.git` pointers in this environment; I verified their commit/tree/blob identities through the local bare project-object stores, but their complete source-SHA/CLI cross-check remains queued.

## Priority case results

| Case | Independent result | Limit |
|---|---|---|
| Contacts `PortraitFileName` traversal | 3 source-to-file-sink candidates at lines 789, 790, 794 | Partial/blocked, `validated_vulnerability=0`, no trusted fixed source. Owner Catalog admission is default-disabled and opt-in. Windows cannot rerun Catalog/API/Worker tests because the environment lacks `fcntl`; the owner PR records WSL integration 11/11 and detector tests are 12/12. |
| cJSON CVE-2026-67216 compare cost | Candidate at `cJSON.c:3161`; source hash, CLI, safe controls and queue verifier pass | `cJSON.c` is parser-partial. No trusted fixed source; the upstream develop patch is experimental and unmerged. The T60 package's future date is not in T3's confirmed correction set, so its provenance remains BLOCK. |
| cJSON CVE-2026-67215 tree amplification | Candidates at `cJSON_Utils.c:932` and `:950`; source hash, CLI and control verifier pass | `cJSON.c` is parser-partial. No trusted merged/released fixed source. The T60 package's future date is not in T3's confirmed correction set, so its provenance remains BLOCK. |
| libpng CVE-2026-33416 | Exact vulnerable and fixed file hashes and current 0.4.2 CLI artifacts verified | Both sides have 4/4 partial files, blocked runs and zero findings. The fixed commit's parent object is missing from the local mirror; no accepted vulnerable/fixed differential. |
| libpng CVE-2026-46675 | Exact vulnerable/fixed `pngrutil.c` identities and current 0.4.2 CLI artifacts verified | Both sides are partial/blocked with zero findings; the fix parent is pre-fix ancestry, not a safe control. |
| dSoftBus CVE-2025-26690 | Exact vulnerable/fixed Git objects and CLI reports verified; vulnerable has 5 candidates and fixed has 0 same-rule candidates | Syntax parses complete, but semantic detector coverage is partial/blocked (0/1 complete). No dSoftBus-specific safe/unrelated control or signed publisher attestation. |

## A0 follow-up checks

- D53/T59, T55, T56, T57 and T58 verifier/CLI commands were actually rerun in this checkout and returned success. Their source/candidate results are preserved in the referenced packages, but those future-dated packages are outside T3's 13-file corrected set; their provenance therefore remains BLOCK and is not treated as new date-verified evidence here.
- D51 and D52: commit/tree/blob OIDs resolve in the local bare object databases. Their checked-out repository `.git` pointers fail, so the packaged `git -C` verifiers cannot run. Full hash/CLI revalidation is queued; their future-dated package provenance also remains BLOCK.
- The original A0 queue verifier passed: 345 unique IDs, 336 `not_testable`, 9 `not_reproduced`; queue states are 331 `paused_pending_evidence`, 5 `queued_first_batch`, 9 `queued_not_reproduced`.

## Metadata and remaining work

T3 confirmed and corrected dates for 13 D54/T61/T62 files; these dated source/CLI packages were independently reverified here. All other 2026-10-29/30 evidence remains provenance BLOCK because its date metadata has not been corrected. Direct object/artifact hash checks establish content identity, not when a replay ran. The machine-readable record lists the confirmed paths and limitations.

The complete 13-row matrix and its prior 3 PASS / 8 PARTIAL / 2 N/A classification are carried forward from T12's independent acceptance record; this incremental audit did not freshly replay every row. This report freshly checks the PR #35 incremental cases listed above and reruns the A0 queue verifier; historical PASS labels remain scoped to T12's bounded static regression evidence. Remaining queue: independently replay the other original matrix rows and finish D51/D52 source SHA/CLI verification through the bare object stores. Keep all partial, blocked and N/A labels as recorded; do not infer safety from zero findings.

Commands and checks: see `t2_pr35_incremental_acceptance_20261020.json` and `verify_t2_pr35_incremental_acceptance_20261020.py`. No detector, test, fixture, or A0 queue file was modified.
