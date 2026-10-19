# T12 independent A-line wave acceptance

Date: 2026-10-20 (Asia/Shanghai)
Checkout: `codex/a-t12-queue-acceptance-20261020`
Acceptance base: `54f68b995` (includes the `ff27d408a` integration plus the D13 tree wording correction)
Development ancestry: PR #30 head `8ec5f56a12e90bba56953b39eb17faa20e154da9`
Role: independent test/provenance audit; no detector, test, or fixture edits.

## Decision

**PARTIAL.** Current changed cases reproduce their reported bounded results, but neither libpng CVE-2026-46675 nor web_webview qualifies for a full-source PASS. The 13-case matrix remains **3 PASS / 8 PARTIAL / 0 BLOCK / 2 N/A** after T7's web source-ledger correction. The separate `PASS` labels cover only the scope named in their evidence (for example, detector regression), not product safety.

## Changed case outcomes

| Case | T12 disposition | Independent result and limit |
|---|---|---|
| libpng CVE-2026-46675 (D13/T11/D14) | **PARTIAL/BLOCK** | Confirmed vulnerable/fixed commits, trees, file blobs, byte counts, and SHA-256 values. Replayed `resource_lifetime` 0.4.0 on both exact files: both parse partial with 72 issues, are blocked, and return zero findings. Replayed seven function slices per variant: six complete and one partial (`png_handle_iCCP`), all zero findings. No vulnerable candidate means there is no fixed differential. |
| libpng CVE-2026-33416 (D12/D14) | **PARTIAL/BLOCK** | Replayed four target slices per variant. Both sides have zero findings; key whole-file and target-fragment coverage remains partial. This does not establish a fix differential. |
| OpenHarmony-TPC/chromium_src web_webview CVE-2026-27648 (D11/D15) | **PARTIAL** | Replayed identical five-file scopes with `bounds` 0.3.0 at pinned vulnerable/fixed commits. Vulnerable: 13 diagnostics, including six patched-root and six ordinary-loop residuals. Fixed: 7 diagnostics, including zero patched-root and the same six residuals. Renamed positive remains detected; safe/unrelated controls are quiet; one partial control keeps the run limited. Full translation units remain partial. Residuals remain unresolved candidates, not confirmed flaws or safe code. |

### Source identity and record reconciliation

For libpng CVE-2026-46675, T11's independent fetch records vulnerable `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, tree `e01f5780f93eaa6d74cca003bb39b427c8f1e910`, blob `a4eda54c8cb3d36cf1651dba159067b65030e3aa`, SHA-256 `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e`; fixed `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`, tree `4c64b5f18cef7d129adee3b403fc4be93f82e30d`, blob `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a`, SHA-256 `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`. T12 recomputed both cached file SHA-256 values and independently checked the commit trees and `pngrutil.c` blob entries against T11's Git object store (`rev-parse ...^{tree}` and `ls-tree`). All four IDs and file hashes match.

The earlier D13 statement that the tree was unavailable was subsequently corrected by integration commit `54f68b995`; D13's full-file JSON and Markdown now preserve T11's tree IDs. D14's historical full-file replay JSON still has `fixed_commit_tree: null`, and its fragment JSON predates the verified tree. Treat T11 as the later provenance correction; this stale D14 field does not conflict with the replayed blob/SHA values, but remains a record-cleanup item. The full-file replay is a direct detector invocation on exact bytes, not a pinned-source CLI run.

For D15, the independent CLI JSON reports vulnerable commit/tree/snapshot `769110ddf1c14355c89f34b974ab9e6cf58c0c6c` / `a8d7d7f9fd5d81a7cc37128ab59ce88118397890` / `d1c3f958bb100dd931fbc0efd3482319bd47098305c8d255f94b73dbce4e844d`; fixed `f550e8e59c57afe4e02b130ec3373b1011843617` / `ec7324dc445a30d96db9e9d0f753a12eef3bec12` / `4795c9a3cb8f719ae546628cead78c203ce17bed5d3ead25d281d080b4d1d30c`. Both runs use the five named files, four complete parses and one partial parse.

## All 13 case dispositions

The frozen T6 audit records the original labels; the current T3 integration updates the web_webview BLOCK to PARTIAL after T7 independently verified its source objects. No change in this wave justifies upgrading any case to a full-source security PASS.

| Case | Current disposition |
|---|---|
| libtiff CVE-2025-9900 | PARTIAL |
| libpng CVE-2026-46675 | PARTIAL/BLOCK |
| libpng CVE-2026-33416 | PARTIAL/BLOCK |
| curl CVE-2026-92391 | PASS (static vulnerable/fixed regression only) |
| cJSON CVE-2026-67216 compare cost | PARTIAL/BLOCK |
| cJSON CVE-2026-67215 tree amplification | PARTIAL/BLOCK |
| web_webview CVE-2026-27648 | PARTIAL |
| OpenHarmony CVE-2025-26690 | PARTIAL |
| OpenHarmony CVE-2025-0587 | PASS (bounded static regression only) |
| OpenHarmony CVE-2025-23420 | PASS (bounded static regression only) |
| OpenHarmony CVE-2025-20042 | N/A |
| OpenHarmony CVE-2025-21098 | N/A |
| Contacts PortraitFileName path traversal | PARTIAL/BLOCK |

## Queue and scope checks

- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py` — `overall_ok=true`; 345 unique source/queue IDs; 97 manifest entries present with matching hashes; original statuses remain 9 `not_reproduced` and 336 `not_testable`; queue states remain 9 `queued_not_reproduced`, 5 `queued_first_batch`, and 331 `paused_pending_evidence`.
- `python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp` — zero violations.
- `git diff --check` — clean before writing this acceptance package; rerun at final commit.
- `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v` — 8 passed.
- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v` — 20 passed.
- D13 full-file direct replay — both exact byte hashes match; each variant remains partial/blocked with 72 parser issues and zero findings.
- D12 fragment replay — CVE-2026-33416: four slices per side, all zero findings with partial coverage; CVE-2026-46675: seven slices per side, six complete and one partial per side, all zero findings.
- D15 pinned-source CLI replay — vulnerable/fixed totals 13/7, root-specific 6/0, ordinary residuals 6/6; no difference from the committed D15 outputs.

Original A0 candidate IDs and states remain unchanged. `not_testable`, missing product build/call-path evidence, and parser partial are still evidence gaps, not false positives or safe conclusions. No precision/recall claim is made.

Machine-readable evidence: [T12 acceptance JSON](t12_a_line_wave_acceptance_20261020.json). The raw D13/T11/D14/D15 evidence packages and T12 reproduction commands remain alongside this report.
