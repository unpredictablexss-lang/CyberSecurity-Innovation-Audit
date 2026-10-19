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
| D7 web_webview CVE-2026-27648 | **PARTIAL** | T7 verified the 6.0 vulnerable-parent and fixed-merge source identities in a separate local audit mirror. Source-derived complete function fragments show 6 root-specific candidates on the vulnerable side and 0 at those patched loops on the fixed side, while 6 separate ordinary-loop candidates remain on both. Current full-translation-unit runs are still partial/blocked with 0 findings. |
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

## Structured Vibe Coding prompts for the next parallel wave

### D9 — Bounds source closure (development)

```text
Role: A-line C/C++ bounds-detector developer.
Continuous goal: improve disclosed bounds-root-cause candidates only where exact source and a reproducible detector gap support a narrow rule change.
Inputs: current T3 integration commit; D7 bounds evidence; T1/T3 libtiff and web_webview artifacts; exact upstream vulnerable/fixed Git objects if available.
Steps: verify repo/commit/tree/blob/source hashes; replay current CLI with identical scope and rule version; identify whether each miss is parser coverage, detector-model coverage, or absent input; change only the responsible detector pattern; add vulnerable, guarded/fixed, safe, unrelated, renamed and partial controls as applicable; record runtime and commands.
Done when: bounded positive and negative controls pass; source-level claims preserve parser/model coverage; missing web_webview vulnerable object remains BLOCK; libtiff full-source result is not promoted while parsing is partial; scope and diff checks pass.
Boundaries: C++ detector/tests/evidence only; do not change Catalog, API, shared parser, shared docs, or source acquisition policy; never infer safety from zero partial findings.
```

### D10 — Resource cases and source-bound controls (development)

```text
Role: A-line C/C++ resource-lifecycle and resource-exhaustion developer.
Continuous goal: close cJSON and libpng disclosed resource-root cases with distinct, source-bound candidate rules and quiet controls.
Inputs: current T3 integration commit; D8 resource evidence and tests; T3/T4 libpng and cJSON source identities; any trusted upstream fixes found by read-only provenance review.
Steps: replay each exact source at the current rule version; distinguish parser incompleteness from detector-model gaps; retain separate compare-cost, recursive cleanup, and cross-function lifetime identities; add only root-cause-specific candidates and hash-bound positive/safe/unrelated/partial fixtures; use fixed controls only when a trusted fix is bound.
Done when: each new rule has bounded positive and negative controls, reproducible source identity, recorded parser/detector coverage and command; missing fixes and partial analysis remain explicit PARTIAL/BLOCK; scope and diff checks pass.
Boundaries: no generic recursion/complexity alerts, no fabricated fixed version, no shared parser/API/Catalog/docs changes.
```

### T7 — Independent frozen-commit regression and queue audit (testing)

```text
Role: independent A-line static-regression and provenance auditor; do not participate in detector implementation.
Continuous goal: independently verify each frozen development commit and preserve the 345-candidate evidence queue until every row has a sourced disposition.
Inputs: separate clean checkout of the submitted D9/D10 commits; T1/T2/T3/T6 matrices; exact source refs, hashes, scopes, detector outputs, and A0 original IDs/states.
Steps: rerun focused tests and exact-source CLI; independently verify repository/commit/tree/blob/source hashes, finding rule/location, parser and detector coverage; compare positive/fixed/safe/unrelated/renamed/partial controls; reconcile web_webview matrix/report discrepancy; preserve original queue IDs and states while adding only sourced evidence actions.
Done when: every changed case has PASS/PARTIAL/BLOCK/N/A with a specific evidence boundary; queue verifier, source-hash checks, branch-scope check and diff check pass; unknown inputs remain blocked and no unsupported precision/recall claim is made.
Boundaries: no detector/test/fixture edits; no developer result accepted without independent replay; partial zero-finding is never safe; missing fix is not a fixed pass.
```

## Overall decision

**PARTIAL.** D7 and D8 improve bounded static candidate coverage and their regressions pass independently. The identified upstream cases remain blocked or partial where full parsing, fixed source, detector coverage, or production integration is missing. No zero-result partial run is a safety result, and the A-line continuous goal remains active.

## T7 source-ledger correction

T7 independently reconciled the prior web_webview discrepancy. The exact 6.0 vulnerable-parent commit `5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8` and fixed-merge commit `4cf313408de7b6d807465ea2bb22e434269b7c5e`, their target tree/blob identities, and full-file SHA-256 values are available in the local read-only Chromium source audit mirror and match the source identity ledger. This supersedes the earlier statement that the vulnerable object was unavailable; D9's narrower statement that the object was absent from its particular replay repository remains accurate.

The source-derived function-fragment evidence is complete-parse and version-bound to detector 0.3.6: it shows 12 diagnostics on each source fragment, with 6 vulnerable and 0 fixed findings at the patched Flowbuffer loops, while 6 separate ordinary-argument-loop findings remain on each side. The held-out 5.1 variant has now been consumed. T7's current-version full-file CLI replays used byte-identical synthetic full-TU snapshots; both remained partial/blocked with zero findings. A direct CLI attempt against the large upstream mirror timed out while recursively listing the repository tree, so it is not recorded as a completed upstream CLI run. The case is **PARTIAL**, not whole-file PASS or safe. The frozen T1 baseline is preserved unchanged.

T7 also independently replayed D7/D8: 2 bounds controls, 8 resource detector tests, and all 159 C++ detector tests passed; exact-source libtiff remains partial, exact-source cJSON yields both distinct candidates with partial overall coverage and no trusted fixes. The next five A0 IDs (CR-0219–CR-0223) have report/result/run-metadata hashes but no raw pinned source in the A0 package or examined local Samgr clone; retain all five in `queued_not_reproduced` until the exact object or a verifiable file export is available.
