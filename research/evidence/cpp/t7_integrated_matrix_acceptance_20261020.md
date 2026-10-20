# T7 integrated A-line matrix acceptance

Date: 2026-10-20 (Asia/Shanghai)
Integrated evidence base: `790e353846b6c0d7926ee46290dcbc2873c8cad0`
Frozen scanner: `81dd4aea9bb51522ac912b33504ef0d2ddb79089`
Lane: independent testing/evidence only; no detector, test, fixture, A0 or owner-status changes.

## Decision

T7 independently reconciled the original 13-row matrix against source-bound CLI and fragment artifacts. The current scanner source tree at the integrated base is unchanged from the frozen scanner. The cited verifiers were run where their inputs were available; the historical matrix verifier was run against a temporary copy so it could not rewrite the checked-in historical summary. The original A0 verifier also passed: 345 unique IDs remain, with the original status and queue-state counts unchanged.

The earlier T12 **3 PASS / 8 PARTIAL / 2 N/A** labels were explicitly limited to bounded static regression; they were not product security results. After applying the current control gate, **bounded static regression** is **2 PASS / 9 PARTIAL / 2 N/A**. The separate **CVE/product disposition** is **0 PASS / 11 PARTIAL/BLOCK / 2 N/A**, because no row establishes product reachability and impact. This is a matrix-label hierarchy adjustment only; no A0 state changed.

T7 moves CVE-2025-0587's bounded static regression to PARTIAL because the exact vulnerable/fixed differential is reproducible but no reviewed source-bound control exercises the same `ValidateAtomicAccess` negative/overflow/out-of-range index semantics. CVE-2025-23420 qualifies as a bounded static regression PASS: its exact vulnerable/fixed pair is complete and 5/0, and T3 independently reviewed and scanned a same-source comparator-snapshot control with complete parse and zero bounds findings. Its CVE/product disposition remains PARTIAL/BLOCK; the static result does not establish product reachability or impact.

These counts do not assert a product vulnerability, exploitability, or safety. Any applicable row with partial parsing/semantic coverage, missing trusted fix, unresolved control, or stale execution provenance remains PARTIAL/BLOCK as detailed in the machine matrix.

## 13-row summary

| Original matrix row | Bounded static regression | CVE/product disposition | Independent finding and blocker |
|---|---|---|
| libtiff CVE-2025-9900 | PARTIAL | PARTIAL/BLOCK | Exact pair verified; current two-file CLI is 0/0, both files partial and detector blocked. A bounded function probe is not full-source coverage. |
| libpng CVE-2026-46675 | PARTIAL | PARTIAL/BLOCK | Exact pair verified; 0/0 with 72 parser issues on each full file. No root-positive/fixed differential. |
| libpng CVE-2026-33416 | PARTIAL | PARTIAL/BLOCK | Exact pair verified; 0/0 and 4/4 files partial on both sides. |
| curl CVE-2026-92391 | PASS | PARTIAL/BLOCK | T4's 2026-10-20 current CLI pair is 1/0, complete parse and complete coverage. This is a source-level regression only. Later T32-labeled future-date artifacts were not needed as execution-date proof. |
| cJSON CVE-2026-67216 compare cost | PARTIAL | PARTIAL/BLOCK | T2 exact frozen-scanner replay: candidate at `cJSON.c:3161`; file parse and semantic coverage partial; no trusted fixed source. |
| cJSON CVE-2026-67215 tree amplification | PARTIAL | PARTIAL/BLOCK | T2 exact frozen-scanner replay: candidates at `cJSON_Utils.c:932,950`; target file complete but aggregate semantic coverage partial; no trusted root-matched fix. |
| web_webview CVE-2026-27648 | PARTIAL | PARTIAL/BLOCK | Exact A0 full files are partial/blocked 0/0; source-derived fragments reproduce 6/0 patched-root candidates but retain six residuals on both sides and a blocked aggregate. |
| dSoftBus CVE-2025-26690 | PARTIAL | PARTIAL/BLOCK | T62 source pair 5/0 and syntax-complete; semantic coverage is partial (0/1) and run blocked. Reviewed guard controls are not scanner-validated. |
| CVE-2025-0587 | PARTIAL | PARTIAL/BLOCK | Exact pair 1/0, complete parse, but no same-root source control for `ValidateAtomicAccess`; DataView and legal-index test cases are adjacent only. |
| CVE-2025-23420 | PASS | PARTIAL/BLOCK | Exact pair 5/0, complete parse; T3's same-source comparator-snapshot control is complete and quiet. Product/impact evidence remains unknown. |
| CVE-2025-20042 | N/A | N/A | Original matrix has no bound source; excluded by design, not a safety result. |
| CVE-2025-21098 | N/A | N/A | Original matrix has no bound source; excluded by design, not a safety result. |
| Contacts `PortraitFileName` traversal | PARTIAL | PARTIAL/BLOCK | Current `790e353` production CLI explicitly selects the admitted, default-disabled detector and reproduces three complete-parse candidates at lines 789, 790, 794. No trusted fixed source or product impact is bound. The older T20 “not registered” statement is stale at this integrated base. |

## Reconciliation details

- **Verifier coverage:** T2, T3, T5, T6, T4, historical matrix, Webview exact A0 full-file/fragments, T61 libpng, T62 dSoftBus, T20 Contacts and the original A0 queue verifier all returned success. T7 ran the historical matrix verifier at scanner freeze against a temporary evidence copy; no tracked historical artifact was rewritten.
- **Scanner identity:** `git diff --quiet 81dd4aea9bb51522ac912b33504ef0d2ddb79089 HEAD -- src` passed. T61/T62 reports originated from different commit histories; their source implementation is identical to the frozen scanner, and their parse/semantic blockers are retained.
- **Contacts:** T7 ran `python -m src.cli ohscan-run` at integrated base `790e353` against the exact local bare source object and the production Catalog ID. It completed with three unassessed findings, complete parse, and explicit detector selection. This supersedes only the old Catalog-not-registered observation; it does not supply a fixed control.
- **Date provenance:** T5's fresh D51/D52 replay is dated 2026-10-20 and verifies source identities/CLI outputs. Older future-dated artifacts remain blocked. T32's report is labeled 2026-10-23, later than the current audit date, so T7 does not use that label as proof of execution; curl is independently backed by T4 dated 2026-10-20. D23's content verifier passes exact source/report projections; its report has no signed execution timestamp, and its directory suffix is not treated as date proof.
- **A0 invariant:** `verify_triage.py` passed; 345 unique IDs, `not_testable=336`, `not_reproduced=9`; queue state `paused_pending_evidence=331`, `queued_first_batch=5`, `queued_not_reproduced=9`. No ID/status was edited.
- **Focused mechanism regression:** on exact scanner freeze `81dd`, resource-lifetime and memory-safety detector suites passed 28/28. These are mechanism tests; they do not erase source-specific blockers above.

## Reproduction

```powershell
python research/evidence/cpp/verify_t7_integrated_matrix_acceptance_20261020.py
python -m scripts.check_change_scope --base 790e353846b6c0d7926ee46290dcbc2873c8cad0 --lane cpp
git diff --check
```

The machine-readable row-level record is [t7_integrated_matrix_acceptance_20261020.json](t7_integrated_matrix_acceptance_20261020.json). The verifier checks base/scanner identity, exact 13-row coverage, classification counts, evidence reference existence, and A0 queue hash/ID/status invariants. It does not certify product security or infer absent results.
