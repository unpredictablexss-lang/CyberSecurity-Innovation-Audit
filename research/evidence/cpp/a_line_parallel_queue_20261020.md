# A-line parallel development and acceptance queue

Date: 2026-10-20 (Asia/Shanghai)

## Baseline and current task tree

- Integration baseline: T3 branch at `a374fc8` (D13 evidence integrated); PR #30 head remains `8ec5f56` as the development ancestry.
- D11 web_webview bounded-index fragment rule is implemented and independently accepted at fragment scope. Full translation units remain partial.
- D13 libpng CVE-2026-46675 exact vulnerable/fixed file blobs are ledger-bound and replayed. Full files are partial/blocked; seven function fragments yield no candidate; upstream fix tree ID remains unavailable. No detector rule change was justified.
- T10 Samgr source identity and five source-flow reviews are complete; product build/policy/reachability evidence remains missing and original queue states stay unchanged.
- A0 evidence queue still contains all 345 original IDs. Verification reports 345 unique rows, preserved source hashes and statuses.

## Parallel tracks

Development and testing work remain separate. Each development task uses its own checkout and owns only its named detector/evidence surface. Acceptance tasks use a separate checkout and do not edit detector code, tests, or fixtures.

### D14 — libpng 46675 lifecycle model assessment (development)

```text
Role: A-line C/C++ resource-lifetime detector developer.
Continuous goal: improve source-bound detection for disclosed cross-function resource lifetime roots without converting parser gaps or uncertain ownership into findings.
Inputs: integration commit a374fc8; D12 and D13 source-bound evidence; exact libpng vulnerable/fixed pngrutil.c blobs and official fix rationale.
Steps: establish source identity and current rule/profile; trace the acquire/release and stale zstream pointer lifetime across the relevant functions; classify each missed condition as parser, cross-function model, or absent evidence; implement a rule change only if a narrow, reproducible model gap exists; add hash-bound positive, fixed-if-valid, safe, unrelated, renamed, and partial controls; record rule version, coverage, locations, runtime, and commands.
Done when: an independently replayable root-cause candidate is produced with bounded controls, or a sourced no-change assessment explains why the evidence does not support a rule; all parse limitations stay explicit and change-scope passes.
Boundaries: only resource_lifetime detector and its dedicated detector tests/fixtures/evidence; no shared parser, API, Catalog, or shared status documentation; no generic pointer-clearing or UAF heuristic; no fixed PASS while source identity or target coverage is incomplete.
```

### T11 — D13 independent acceptance (testing, active)

```text
Role: independent A-line source-provenance and regression auditor.
Continuous goal: verify each new development evidence package independently and keep partial/blocked cases visibly unresolved.
Inputs: D13 commit f897dcf; exact source blobs, upstream advisory/commit, replay runner and outputs; clean checkout based on integration commit a374fc8.
Steps: independently verify file hashes/blob IDs and upstream commit/parent; determine whether the tree ID can be recovered from trusted evidence; rerun the exact full-file and function-fragment commands; inspect parse status, rule version, candidate positions, and scope; compare the conclusion to the raw outputs.
Done when: produce JSON and Markdown with PASS/PARTIAL/BLOCK/N/A, reproducible commands, source identities, coverage and any discrepancy; preserve the original case state unless evidence meets the full-source acceptance gate.
Boundaries: no detector, test, or fixture changes; do not treat zero findings under partial coverage as safety; do not infer a tree ID.
```

### D15 — web_webview residual candidate review (development)

```text
Role: A-line C/C++ bounds-detector developer.
Continuous goal: determine whether remaining ordinary-loop findings around web_webview Flowbuffer are true source-bound bounds risks or conservative candidates, while preserving the patched-root regression.
Inputs: integration commit a374fc8; D11 exact-source fragment replay and T9 independent acceptance; exact vulnerable and fixed source identities.
Steps: isolate the six residual loop candidates from the six patched root sites; trace index and container relationships in source; reproduce current behavior with identical scope; change the bounds rule only when a specific false-positive or missed-root model is demonstrated; add vulnerable/fixed/safe/unrelated/renamed/partial controls and record runtime and parse coverage.
Done when: provide independently replayable classification for each residual site and preserve 6/0 root-specific differential, or document why no safe rule change is supported; full-TU partial state remains explicit.
Boundaries: bounds detector and dedicated tests/fixtures/evidence only; no broad candidate suppression; no parser, API, Catalog, or shared docs changes; no safety claim from partial translation units.
```

### T12 — frozen A-line queue and change-scope audit (testing, next)

```text
Role: independent A-line acceptance and provenance auditor.
Continuous goal: reconcile every frozen development change against the 13 disclosed cases and preserve the 345-item source queue until each row has sourced evidence.
Inputs: D13 and later frozen development commits; T1/T3/T6/T7/T9/T10 matrices; A0 source manifest, queue IDs/statuses, scopes and commands.
Steps: in a clean independent checkout, rerun changed case commands and focused tests; verify repo/commit/tree/blob/source hashes, rule identity, locations, parse and detector coverage; check positive/fixed/safe/unrelated/renamed/partial controls; run queue and scope verifiers; record minimal next evidence action for each unresolved case.
Done when: all changed cases have an evidence-backed PASS/PARTIAL/BLOCK/N/A disposition, original queue IDs/statuses reconcile, and the integration range has zero scope violations; unknown rows remain queued.
Boundaries: no detector or test edits; no developer result accepted without independent replay; missing fixed source is not a fixed pass; partial zero-finding is never safe.
```

## Stage goal

Keep one active continuous objective across both tracks: improve root-cause candidate coverage for source-bound A-line cases on the development side; independently verify source identity, regression behavior, and the 345-row evidence queue on the test side. Complete only when applicable cases pass independent full-scope acceptance, all remaining cases carry a precise PARTIAL/BLOCK/N/A reason, and the change-scope check passes. Do not close the goal while any required evidence remains outstanding.
