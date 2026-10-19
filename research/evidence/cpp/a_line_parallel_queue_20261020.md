# A-line parallel development and acceptance queue

Date: 2026-10-20 (Asia/Shanghai)

## Baseline and current task tree

- Integration baseline: T3 branch at `a374fc8` (D13 evidence integrated); PR #30 head remains `8ec5f56` as the development ancestry.
- D11 web_webview bounded-index fragment rule is implemented and independently accepted at fragment scope. Full translation units remain partial.
- D13 libpng CVE-2026-46675 exact vulnerable/fixed file blobs are ledger-bound and replayed. Full files are partial/blocked; seven function fragments yield no candidate; upstream fix tree ID remains unavailable. No detector rule change was justified.
- T10 Samgr source identity and five source-flow reviews are complete; product build/policy/reachability evidence remains missing and original queue states stay unchanged.
- T11 independently verified the D13 upstream commit trees and replay. D14 found no safely implementable libpng rule gap under current partial parsing; D15 reviewed all six web_webview residual sites without suppressing unresolved candidates.
- A0 evidence queue still contains all 345 original IDs. Verification reports 345 unique rows, preserved source hashes and statuses.

## Latest wave results

- D14: no detector change. `pngrutil.c` full translation units remain partial with 72 issues; `png_handle_iCCP` remains partial. The stale zstream ownership transition requires cross-function state modeling; current evidence does not isolate a narrow rule gap.
- D15: no detector change. Three pairs of residual writes use shared `curIndex`; the `argsSize + flowbufSize` to `int` narrowing and cross-loop cursor invariant are not proven. Vulnerable/fixed CLI output keeps root-specific 6/0 while the six residual findings remain on both sides; safe/unrelated controls are quiet and partial controls remain limited.
- T11: independently fetched vulnerable/fixed commits and verified tree/blob/file identities. The full-file and fragment outcomes remain blocked/partial; zero findings do not establish a fixed differential.
- T12 independent acceptance is complete. The next wave below continues detector work and source-backed triage; acceptance stays in a separate lane and runs after those changes freeze.
- D16 is now implemented at `4208c3f`: recursive names containing `Delete` no longer qualify alone as a deallocator; the exact cJSON apply_patch candidate remains. T14 is independently accepting this detector change.
- D17 found no trusted merged/released cJSON fixed source: 67215 remains unpatched in checked master/develop; 67216 has an unmerged develop candidate that is not a fixed release.
- T13 verified the first five queued IDs and eight source objects. All five remain `not_testable / queued_first_batch`; no original queue IDs or states changed.
- T14 accepted the synthetic sink-name regression but marked the exact cJSON finding location PARTIAL: line 861 is an early-exit root-replace branch, while general ADD/COPY duplicate-and-attach paths occur later. Follow-up D18 owns that source-to-root association gap.
- D18 is implemented at `38dc3be`: the candidate is tied to COPY line 932 and ADD/REPLACE line 950; the early-exit root-replace line 861 is quiet. Exact-source coverage remains PARTIAL/BLOCK because `cJSON.c` parsing is incomplete and no trusted fixed source exists. T15 is independently accepting this change.
- T15 independently confirmed D18's exact source positions and controls: rule regression PASS, cJSON case PARTIAL, fixed-source comparison BLOCK; 345-row queue and 160-test C++ suite pass.
- D19 completed no-change review: the existing compare-cost rule still finds cJSON.c:3161, renamed and safe/unrelated controls behave as expected, and the upstream develop patch is only an experimental comparison. The case remains PARTIAL/BLOCK; T16 is independently accepting.
- T16 independently accepted the D19 rule regression and verified upstream cJSON commit/tree/blob/SHA via the OpenHarmony project-object mirror. The CVE case remains PARTIAL and a trusted released fixed comparison remains BLOCK.
- D18/T15 completed root-path binding and independent acceptance; D19/T16 completed compare-cost replay with no rule change. Both cJSON cases remain unresolved for full-source parser or trusted fixed-source evidence.
- D20 completed no-change source analysis for libpng CVE-2026-33416: all four vulnerable/fixed target slices remain partial, so cross-file member alias and call-order evidence is not parser-supported. No rule was changed; the case remains PARTIAL/BLOCK.
- D21 completed no-change source replay for libtiff CVE-2025-9900: the complete `_TIFFRGBAImage` function fragment reports the existing pointer-offset candidate at vulnerable line 621 and no finding for the fixed fragment; whole translation units remain partial/blocked. T17 is independently accepting both D20/D21 evidence packages.
- T17 independently accepted the D20/D21 source identities, fragment outcomes, and whole-TU limits. Both cases remain PARTIAL/BLOCK; A0 and T13 queues remain 345/345 with original states.

T12 completion note: the independent wave audit is committed as `1262d0ab9` and reports 3 PASS / 8 PARTIAL / 0 BLOCK / 2 N/A, with all 345 A0 IDs and original states retained. After that audit, D14's historical JSON/Markdown tree-null fields were reconciled to T11/T12's verified commit trees; this metadata cleanup does not change replay outcomes or case disposition.

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

### T12 — frozen A-line queue and change-scope audit (testing, completed)

```text
Role: independent A-line acceptance and provenance auditor.
Continuous goal: reconcile every frozen development change against the 13 disclosed cases and preserve the 345-item source queue until each row has sourced evidence.
Inputs: D13 and later frozen development commits; T1/T3/T6/T7/T9/T10 matrices; A0 source manifest, queue IDs/statuses, scopes and commands.
Steps: in a clean independent checkout, rerun changed case commands and focused tests; verify repo/commit/tree/blob/source hashes, rule identity, locations, parse and detector coverage; check positive/fixed/safe/unrelated/renamed/partial controls; run queue and scope verifiers; record minimal next evidence action for each unresolved case.
Done when: all changed cases have an evidence-backed PASS/PARTIAL/BLOCK/N/A disposition, original queue IDs/statuses reconcile, and the integration range has zero scope violations; unknown rows remain queued.
Boundaries: no detector or test edits; no developer result accepted without independent replay; missing fixed source is not a fixed pass; partial zero-finding is never safe.
```

### D16 — cJSON recursive tree amplification model (development)

```text
Role: A-line C/C++ resource-exhaustion detector developer.
Continuous goal: detect the disclosed JSON Patch recursive tree-amplification root at its source operation while keeping ordinary recursive tree operations quiet.
Inputs: current integration HEAD; cJSON CVE-2026-67215 exact source identity and D3/D8 evidence; existing resource detector and fixture contracts.
Steps: replay the exact source and current controls; trace add/copy expansion and subsequent recursive delete path; distinguish the source-specific root from generic recursion; implement a narrow rule only if source-bound evidence establishes a detector gap; add vulnerable, fixed-if-trusted, safe, unrelated, renamed and partial controls; record scope, rule version, parse coverage, location, runtime, and commands.
Done when: root-specific candidate behavior is independently reproducible with bounded controls, or a sourced no-change assessment states the missing parser/model/fix evidence; do not claim fixed differential without trusted fixed source.
Boundaries: resource_lifetime detector and dedicated tests/fixtures/evidence only; no parser/API/Catalog/shared docs; do not report generic recursion or suppress unresolved candidates.
```

### D17 — cJSON remediation provenance (source evidence)

```text
Role: A-line upstream-source provenance investigator, separate from detector implementation.
Continuous goal: identify whether trusted fixed source objects exist for cJSON CVE-2026-67215 and CVE-2026-67216 and bind any usable fix precisely.
Inputs: current integration HEAD; official cJSON advisory/issues/releases/PRs; existing cJSON vulnerable source identities in T1/T3 evidence.
Steps: inspect primary upstream sources and reachable Git object history; record repository, issue/advisory, exact commit/parent/tree/path/blob/size/SHA, patch-root rationale, and retrieval method; distinguish merged fix, candidate PR, unmerged proposal, and no fix; if unresolved, state smallest missing input without guessing.
Done when: each case has a reproducible trusted fixed identity or an explicit no-fix-found report with source URLs and checked refs; no scanner code or labels are altered.
Boundaries: evidence-only; do not use secondary claims as fix authority; do not treat an open issue or nearby patch as fixed source.
```

### T13 — A0 first-batch evidence triage (testing/evidence)

```text
Role: independent A-line evidence triage owner, not a detector developer.
Continuous goal: advance the 345-row A0 queue with source-backed next actions while preserving every original ID and status.
Inputs: latest T12-accepted queue, A0 original package and hash manifest, CR-0219–0223 T10 evidence, and the first five queued not_testable IDs.
Steps: verify each selected ID against its source bytes and hash; inspect only the evidence needed to answer its queued question; record exact source identity, reproducible commands, confirmed facts, unknowns, and minimum next evidence; preserve original status and add a separate evidence disposition; reconcile queue and source manifest after edits.
Done when: five rows have auditable per-ID evidence actions and provenance, or are explicitly kept queued with precise missing inputs; all 345 IDs and original states remain identical and verifiers pass.
Boundaries: no detector/tests/fixtures edits; no inferred vulnerability labels; no status promotion based on missing or partial evidence; keep testing and development ownership separate.
```

### T14 — D16 detector change acceptance (testing)

```text
Role: independent A-line C/C++ detector regression auditor.
Continuous goal: accept or reject each frozen detector change from independent source-bound behavior, while separating rule regression status from whole-case status.
Inputs: D16 commit 84e9493 (integration commit 4208c3f); exact cJSON source identities; D16 report/runner; clean independent checkout.
Steps: replay exact source and all dedicated positive, misleading Delete-name negative, safe, unrelated, and partial controls; inspect the rule's release-sink evidence; verify line, rule version, parse and detector coverage; run focused and full C++ detector suites; run A-line scope and diff checks.
Done when: JSON/Markdown records PASS/PARTIAL/BLOCK/N/A for the detector change and CVE case separately, source hashes and commands are independently confirmed, and no zero partial run is labeled safe.
Boundaries: do not edit detector/tests/fixtures; do not treat candidate presence as product vulnerability confirmation; do not upgrade CVE fixed differential without a trusted fix.
```

### D18 — cJSON apply_patch root-path binding (development)

```text
Role: A-line C/C++ resource-lifetime detector developer.
Continuous goal: bind the CVE-2026-67215 candidate to an actual JSON Patch tree-expansion path and avoid attributing the root-replace early-exit branch to the recursive add/copy sink.
Inputs: integration D16 commit 4208c3f and independent T14 report; exact cJSON_Utils.c source identity and cJSON.c release-sink identity; current resource_lifetime tests/fixtures.
Steps: trace ADD/REPLACE and COPY paths separately, including cJSON_Duplicate, array/object attach, value ownership transfer, cleanup and recursive cJSON_Delete; reproduce the current line-861 attribution; change candidate location/association only with a bounded control-flow relation that the current parser actually exposes; add positive controls for each supported path, a root-replace early-exit negative, unrelated/safe/renamed and partial controls; bind source hashes and record rule coverage.
Done when: supported positive paths are reported at source locations tied to duplicate+attach and the line-861 early-exit alone is quiet, or a no-change report identifies the missing parser/control-flow fact; whole-source partial and missing fix remain explicit.
Boundaries: only resource_lifetime detector and dedicated tests/fixtures/evidence; no generic recursive-delete alert, no shared parser/API/Catalog/docs, no candidate-to-product vulnerability claim.
```

### T15 — D18 independent cJSON root-path acceptance (testing)

```text
Role: independent A-line regression auditor.
Continuous goal: verify that any D18 change binds findings to true JSON Patch expansion paths and keeps the exceptional early-exit and unrelated controls quiet.
Inputs: frozen D18 commit, T14's D16 acceptance findings, exact upstream commit/tree/blob/hash identities, D18 commands and controls.
Steps: use an independent checkout; reverify source identities; rerun exact source and dedicated controls; compare finding locations to duplicate/attach operations; confirm parse status and detector coverage; run focused and full C++ detector suites, queue verifier, scope checker and diff check.
Done when: PASS/PARTIAL/BLOCK/N/A separately describes rule regression and full CVE case, with no claim based on partial zero findings or missing fixes.
Boundaries: no detector/test/fixture edits; reject a candidate whose location cannot be tied to supported root operation; preserve all unknown source and product questions.
```

### D19 — cJSON compare-cost root precision (development)

```text
Role: A-line C/C++ resource-exhaustion detector developer.
Continuous goal: bind CVE-2026-67216 candidates to the actual recursive member-comparison cost root and prevent unrelated recursive comparisons from being reported.
Inputs: integration D18/T15 commits; D17 upstream provenance; exact cJSON.c source identity; D8 comparison rule and safe indexed-lookup controls.
Steps: replay exact source and isolate the source function around line 3161 using current parser coverage; verify the visible same-TU sibling iteration and recursive compare arguments; compare the unmerged official develop candidate bd307ec only as an unmerged patch experiment, never as a fixed release; change the rule only for a reproduced root/model defect; add positive, indexed-lookup safe, unrelated, renamed, partial and experimental-patch controls with clear labels.
Done when: root-specific rule behavior has independent controls and exact source identities, or a no-change report identifies parser/model limitations; any develop-branch delta is labeled experimental and not fixed PASS.
Boundaries: resource_lifetime detector and dedicated controls/evidence only; no shared parser/API/Catalog; never label unmerged develop source as fixed; preserve parse partial and missing release/source status.
```

### T16 — cJSON compare-cost independent acceptance (testing)

```text
Role: independent A-line regression and provenance auditor.
Continuous goal: verify D19's root precision and distinguish experimental branch deltas from trusted fixed-source evidence.
Inputs: frozen D19 commit; exact cJSON vulnerable source and D17 upstream branch/commit identities; D19 commands and controls.
Steps: independently bind source repo/commit/tree/blob/SHA; rerun exact source, fragment, safe, unrelated, renamed, partial and any explicitly experimental branch comparison; inspect parse status, rule version, location, and source arguments; run focused and full C++ tests, queue verifier, scope and diff checks.
Done when: separate rule regression and CVE status are recorded as PASS/PARTIAL/BLOCK/N/A; no unmerged branch is described as fixed and queue IDs/states remain unchanged.
Boundaries: no detector/test/fixture edits; no unsupported precision/recall; partial zero findings are inconclusive.
```

### D20 — libpng CVE-2026-33416 local root assessment (development)

```text
Role: A-line C/C++ resource-lifetime detector developer.
Continuous goal: determine whether the libpng 33416 cross-file alias/release/use root can be represented as a bounded candidate from source-visible function slices without weakening parser status.
Inputs: current integration HEAD; exact vulnerable/fixed commits/trees and hash-bound pngset.c/png.c/pngread.c/pngrtran.c from D12/T4; existing resource lifetime detector 0.4.2 and source method card.
Steps: trace png_set_PLTE/png_set_tRNS, png_free_data, png_do_expand_palette and required field/type declarations across files; rerun exact source baseline; classify missing evidence as parser, cross-file alias, or absent control; make a detector change only if one narrow relation is source-visible and can be hash-bound; add vulnerable, exact fixed if trusted, safe, unrelated, renamed and partial controls.
Done when: an independently replayable root candidate is tied to the vulnerable operation with explicit cross-file coverage, or a no-change record explains the exact parser/model boundary; never upgrade partial TU or fixed status.
Boundaries: resource_lifetime detector and dedicated tests/fixtures/evidence only; no shared parser/API/Catalog/docs; do not infer safety from zero findings.
```

### D21 — libtiff CVE-2025-9900 bounds gap assessment (development)

```text
Role: A-line C/C++ integer/bounds detector developer.
Continuous goal: decide whether the exact libtiff 9900 unsigned dimension-subtraction/pointer-offset root can be detected on a source-bound complete local function, while preserving whole-file partial status.
Inputs: current integration HEAD; D7/D9/T1 exact vulnerable/fixed libtiff identities and reports; bounds detector 0.3.0, method card, existing positive/guarded/signed controls.
Steps: verify source commit/tree/blob/SHA for both variants; run exact current baseline; isolate the source function plus declarations with original offsets; distinguish parser incompleteness from detector-model gap; only implement a narrow rule if complete function evidence supports it; record target-file and whole-TU coverage separately and add safe/unrelated/renamed/partial controls.
Done when: exact vulnerable root is candidate and valid fixed/guarded controls are quiet at function scope, or a no-change evidence package lists the missing parse/model context; full file remains PARTIAL if so.
Boundaries: bounds detector and dedicated tests/fixtures/evidence only; no parser/API/Catalog/shared docs; never call zero findings on partial input a safe result.
```

### T17 — libpng/libtiff independent acceptance (testing)

```text
Role: independent A-line C/C++ source and regression auditor.
Continuous goal: verify any frozen D20/D21 changes from exact source identity, bounded function scope, controls, and parser status independently.
Inputs: frozen D20 and D21 commits/evidence; T1/T4/T7 matrices; exact vulnerable/fixed source manifests and commands.
Steps: clean independent checkout; verify source identities and source-range extraction; replay exact source and all submitted controls; compare candidate location, rule version, parse and detector coverage; run focused/full C++ tests, queue verifier, scope and diff checks.
Done when: report each rule regression and CVE disposition separately as PASS/PARTIAL/BLOCK/N/A, reconcile all changed source identities, and preserve 345 queue IDs/statuses.
Boundaries: no detector/test/fixture edits; no acceptance from developer statements alone; no fixed PASS without a trusted exact fix and sufficient parsing.
```

T17 completed after D20/D21 freeze. Both were evidence-only and did not modify detector, test, or fixture code; their commits are `fcbc7c7` and `60c7588`.

### T18 — Samgr remaining transaction evidence (testing/evidence)

```text
Role: independent A-line IPC provenance and source-flow auditor.
Continuous goal: complete source-bound review of the remaining Samgr queue IDs without inferring a vulnerability from neighboring transactions.
Inputs: current T10 verified Samgr commit/tree/blob/SHA; CR-0224, CR-0225, CR-0226 original records; T10 CR-0219–CR-0223 evidence.
Steps: verify each ID's source key and exact bytes; map its transaction registration to implementation; record parcel inputs, interface token, CanRequest/native token/SELinux checks, remote object/FD/sensitive-operation flow; identify product build, policy and reachability gaps; preserve original ID/status and add only sourced facts/actions.
Done when: all three IDs have independent per-ID source-flow evidence or a precise missing-input statement, with queue and source hash verification passing.
Boundaries: no detector/tests/fixtures edits; no status promotion; no bypass claim from source-only permission differences; keep test and development ownership separate.
```

## Stage goal

Keep one active continuous objective across both tracks: improve root-cause candidate coverage for source-bound A-line cases on the development side; independently verify source identity, regression behavior, and the 345-row evidence queue on the test side. Complete only when applicable cases pass independent full-scope acceptance, all remaining cases carry a precise PARTIAL/BLOCK/N/A reason, and the change-scope check passes. Do not close the goal while any required evidence remains outstanding.

T18 completed in `78d252c`; CR-0224/0225/0226 retain `PARTIAL` and their original queue states after exact source verification. See [T18 report](a_t18_samgr_0224_0226_20261020.md). The next test-line step is to continue A0 evidence triage from remaining queued IDs without promoting statuses absent new evidence.

### T19 — Samgr unit-test candidate source triage (testing/evidence)

```text
Role: Independent A-line IPC testing/evidence reviewer.
Continuous goal: source-bind the remaining CR-0227–CR-0230 candidates and establish whether the reported IPC/descriptor statements are product implementation or test-only code.
Inputs: current integration checkout; A0 queue rows CR-0227–CR-0230; exact Samgr project commit/tree/blob/SHA; production proxy/stub source at that same source commit.
Steps: fetch and verify the exact source commit/tree/blob/SHA; inspect test fixture, transaction codes, tests that invoke it, production API send paths and receiver handlers; map each queue ID to the exact statement and preserve original status; state missing build/policy/reachability/impact evidence; add source-bound evidence and a verifier.
Done when: all four IDs have independently verifiable source identities, test-vs-product classification, production API mapping and blockers, while original queue states remain unchanged; A0 verifier, source verifier, diff check and cpp change-scope check pass.
Boundaries: do not modify detector, tests, fixtures or A0 IDs/statuses; do not infer product flaws from mock code; do not call a test-only candidate a confirmed vulnerability.
```

T19 completed in branch `codex/a-t19-samgr-test-proxy-20261020`: CR-0227–CR-0230 bind to one test-only `MultiUserProxyRemoteStub::OnRemoteRequest` implementation. Lines 74/76 synthesize `IRemoteObject`/bool replies for real client proxy calls, but do not execute the product `SystemAbilityManagerStub`; no descriptor operation appears. All four remain **PARTIAL**, with original `not_testable` / `paused_pending_evidence` states. See [T19 report](a_t19_samgr_test_proxy_0227_0230_20261020.md) and run [the source verifier](verify_t19_samgr_test_proxy_0227_0230.py).
