# A-line follow-up independent integration acceptance

Date: 2026-10-19 (Asia/Shanghai)

## Scope and frozen inputs

This independent integration review starts from T3 commit `50b2806a7df38cd1ad07f257873617fe9d6b8337` and adds D8 commit `f2ea2c8a717ca8c679b670c56fe685dc807e9447`, D7 commit `fa4b57f90b2eaa3c8ed21b005ab6ade456f96978`, and T6 commit `2ce223c511396cb01430dcf1b2f0187e6fd382c1`. The repository's observed remote refs remain `main=db77164fdc2af0da02e4d3efc056d84694fd68e8` and PR #30 head `8ec5f56a12e90bba56953b39eb17faa20e154da9`.

## Independent verification

- Resource lifetime, bounds/memory safety, and path traversal focused detector suites passed.
- Full C++ detector suite passed: 159 tests.
- `python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp` reported no violations.
- `git diff --check` passed and the integration worktree was clean after committing this record.
- Re-ran `research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: 345 unique source and queue IDs, 97/97 source-package hashes match, original status counts remain 9 `not_reproduced` and 336 `not_testable`, `overall_ok=true`.
- T6's 13-case evidence was independently JSON-parsed and its queue verifier rerun. Its separate audit retains 3 static-regression PASS, 7 PARTIAL, 1 BLOCK, and 2 N/A. These PASS labels cover static regression or inventory evidence only, not product security.

## Case dispositions after D7 and D8

| Case / change | Integration disposition | Evidence boundary |
|---|---|---|
| D7 unsigned dimension-subtraction pointer-offset candidate | **PASS for bounded detector regression only** | Exact vulnerability/fix expression identity and positive, guarded, signed, unrelated, and partial controls are recorded in `d7_bounds_followup_20261019.md`. Full libtiff source runs remain partial/not analyzed with zero findings; CVE-2025-9900 remains **PARTIAL**. |
| D7 web_webview CVE-2026-27648 | **BLOCK** | Vulnerable full translation unit and exact source object remain unavailable; the fixed-side evidence is partial. |
| D8 cJSON CVE-2026-67216 compare-cost | **PARTIAL/BLOCK** | Exact source candidate at `cJSON.c:3161` remains tied to a partial parse; the new syntax gate and indexed-lookup safe control passed tests. No trusted fixed source or complete detector analysis is available. |
| D8 cJSON CVE-2026-67215 tree amplification | **PARTIAL/BLOCK** | Exact source candidate at `cJSON_Utils.c:861` is reproduced, while parser completeness does not imply complete detector analysis; no trusted fixed source is bound. |
| D6 Contacts path traversal | **PARTIAL/BLOCK** | Exact A0 blob and complete parse yield candidates at lines 789, 790, and 794. No trusted fixed source, Catalog admission, or production CLI integration is established. |
| T6 A0 queue | **PASS for inventory integrity** | All 345 IDs/states remain reconciled. Candidate truth and full triage remain unestablished; preserve the queued source and evidence actions. |

## Follow-up task tree

### Development lane

1. **Contacts admission and semantic review:** validate the `DeleteFile(filePath)` bucket inputs; locate a trusted fixed source; request owner review and Catalog admission; then replay through the production CLI. Keep the finding candidate-level until those gates are met.
2. **Bounds:** recover complete libtiff source analysis or improve only a reproducible parser/model limitation; bind the full vulnerable and fixed functions. Recover the exact vulnerable web_webview object before any differential claim.
3. **Resource exhaustion:** find trusted fixed cJSON sources and complete analysis for both distinct roots; retain the D8 conservative sibling-iteration gate and add source-bound safe controls where available.
4. **Coverage blockers:** obtain full parser coverage and source-to-product provenance for libpng cases; retrieve the dsoftbus upstream tree identity and source-bound safe/unrelated controls.

### Independent test lane

1. **T7 regression audit:** in a clean checkout, replay D7/D8 frozen commits and verify positive, fixed-if-available, safe, unrelated, renamed, and partial controls; compare rule IDs, source hashes, locations, parse state, and detector coverage.
2. **T7 source-ledger reconciliation:** resolve the web_webview T1 matrix versus T3 wording discrepancy, retaining BLOCK until its exact vulnerable/fixed input records reconcile.
3. **T7 queue continuation:** preserve the 345 original IDs/statuses; process the first five queued `not_testable` entries only as evidence arrives, and write the next evidence action without upgrading unknown candidates.
4. Re-run `scripts.check_change_scope` and the queue verifier on the frozen integration commit. Record each item as PASS/PARTIAL/BLOCK/N/A with evidence boundaries.

## Overall decision

**PARTIAL.** D7 and D8 improve bounded static candidate coverage and their regressions pass independently. The identified upstream cases remain blocked or partial where full parsing, fixed source, detector coverage, or production integration is missing. No zero-result partial run is a safety result, and the A-line continuous goal remains active.
