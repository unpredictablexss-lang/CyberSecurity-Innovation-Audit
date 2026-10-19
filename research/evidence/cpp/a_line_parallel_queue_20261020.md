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
- T24 independently audited DataShare shared-pointer race candidates CR-0005–CR-0012 against eight frozen source objects. Source identity and queue preservation pass; unsynchronized concurrent access remains unproven, so all eight remain PARTIAL/BLOCK. See [T24 addendum](a_line_parallel_queue_20261020_T24_addendum.md) and [audit report](a_t24_datashare_race_source_audit_20261020.md).
- D25 replayed DataShare shared-pointer candidates CR-0013–CR-0015 through the production M2 CLI. CR-0013/0015 constructor writes are found; CR-0014 constructor initialization is not reported. No later write or justified generic rule gap was found; all three remain `not_testable / paused_pending_evidence`. See [D25 addendum](a_line_parallel_queue_20261020_D25_addendum.md), [source-bound report](d25_datashare_cr0013_15_replay_20261020.md), and [verifier](d25_datashare_cr0013_15_replay_20261020.py).
- T25 independently audited DataShare CR-0013–CR-0015 from the same pinned source object. The current CLI emits two constructor-write syntax candidates for `uvQueue_`; CR-0014's `extension_` initialization is quiet. The queue implementation source is parser-partial, and no same-object unordered cross-thread access or product impact is established. All three original rows remain `not_testable / paused_pending_evidence`; see [T25 addendum](a_line_parallel_queue_20261020_T25_addendum.md) and [audit report](a_t25_datashare_race_source_audit_20261020.md).
- D26 replayed Preferences CR-0020–CR-0021 through the production M2 CLI. Both header accesses (`SetInstance` write and `GetInstance` read) are detected, including in a bounded three-file replay; the pinned source does not establish a same-object unordered overlap. No detector change; both original rows remain `not_testable / paused_pending_evidence`. See [D26 addendum](a_line_parallel_queue_20261020_D26_addendum.md) and [source-bound replay](d26_preferences_shared_ptr_replay_20261020.md).
- T35 independently audited Preferences fuzzer-family CR-0025–CR-0040. All 16 A0 rows bind to one exact source object and map to current shared_ptr_race syntax candidates; together with T27's CR-0022–CR-0024, all 19 rows in the family map to the 19 findings. GN identifies a `DBPreferencesFuzzTest` fuzz target under `testonly = true`; its harness calls Preferences APIs, but product reachability and a race are not established. All IDs retain `not_testable / paused_pending_evidence` and PARTIAL. See [T35 addendum](a_line_parallel_queue_20261020_T35_addendum.md), [audit](t35_preferences_fuzzer_source_audit_20261020.md), and [verifier](verify_t35_preferences_fuzzer_audit.py).
- T36 independently audited Preferences BaseValue fuzzer CR-0041–CR-0065 from one exact source object. Current shared_ptr_race CLI v0.5.1 parses the complete 197-LOC file and maps all 25 A0 locations to 25 syntax candidates. GN declares `ohos_fuzztest("DBPreferencesBaseValueFuzzTest")` under a `testonly = true` fuzz group; production build inclusion, production reachability, actual concurrent overlap, and impact remain unknown. All rows stay `not_testable / paused_pending_evidence` and PARTIAL; A0 IDs/statuses are unchanged. See [T36 addendum](a_line_parallel_queue_20261020_T36_addendum.md), [audit](t36_preferences_basevalue_audit_20261024.md), and [verifier](t36_preferences_basevalue_audit.py).

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

T20 Contacts independent acceptance is recorded in [its addendum](a_line_parallel_queue_20261020_T20_addendum.md): the rule mechanism passed controls, while the case remains BLOCK for the missing trusted fix and Catalog/production CLI admission. D22 recovered and replayed the exact CVE-2025-26690 upstream pair; see [the D22 addendum](a_line_parallel_queue_20261020_D22_addendum.md) and [current case-status overlay](a_case_status_updates_20261020.json). The source differential is now reproducible, but semantic detector coverage and product-context evidence remain partial.

T21 source-audited CR-0335 against the frozen A0 queue and found an identity mismatch in the task input; the queue-bound source uses a length-guarded `memcpy_s`, and the case remains PARTIAL with its original queue states. See [the T21 addendum](a_line_parallel_queue_20261020_T21_addendum.md) and [source verifier](verify_cr0335_wifi_p2p_source_audit.py).

T22 independently source-audited CR-0001–CR-0004. CR-0001/0002 lack evidence of concurrent access during destruction; CR-0003/0004 expose plausible unsynchronized map read/write overlap but still need exact `OnDump` execution context and a target-derived harness. All four remain `not_testable / paused_pending_evidence`; see [the T22 addendum](../deliveries/cpp/a_line_parallel_queue_20261020_T22_addendum.md) and [source verifier](verify_a_t22_supervisor_race_source_audit.py).

D23 replayed the shared_ptr_race detector on the exact header and a bounded three-file scope without changing the rule; one implementation file remained parser-partial, so the zero-finding result is inconclusive. Its continuous development objective and T23 independent acceptance gate are in [the D23/T23 addendum](a_line_parallel_queue_20261020_D23_addendum.md).
T23 independently replayed D23's exact header-only and three-file scopes from the pinned project object. The existing detector mechanism regression passes its 39 focused tests and T23 outputs match D23; the A0 supervisor race case remains PARTIAL because the three-file scope contains one parser-partial callsite and no cross-thread same-object race is established. CR-0001–CR-0004 remain `not_testable / paused_pending_evidence`. See [the T23 addendum](a_line_parallel_queue_20261020_T23_addendum.md), [acceptance report](t23_supervisor_race_acceptance_20261020.md), and [verifier](verify_t23_supervisor_race_acceptance.py).

D24 assessed CR-0005–CR-0012 against the exact DataShare object and current CLI adapter. No production-path generic rule change was justified; all eight queue states remain `not_testable / paused_pending_evidence`. See the [D24 addendum](a_line_parallel_queue_20261020_D24_addendum.md), [source-bound replay report](d24_datashare_race_20261020.md), and [verifier](verify_d24_datashare_race.py).

### T26 — CR-0019 DataShare descriptor candidate

See [T26 independent audit addendum](a_line_parallel_queue_20261020_T26_addendum.md). T26 independently bound the frozen CR-0019 source and replayed the current IPC detector. A source-level interface-token mismatch candidate is present; runtime reachability, sender token, product authorization, build and impact remain unverified. Original A0 states are unchanged (`not_testable / paused_pending_evidence`).


T27 independently audited Preferences CR-0020–CR-0024. The two shared header accesses are detected on complete source; three fuzz-file candidates are test-only harness code. All five retain the original A0 states. See [T27 addendum](a_line_parallel_queue_20261020_T27_addendum.md), [per-ID report](t27_preferences_source_audit_20261020.md), and [source verifier](verify_t27_preferences_source_audit.py).

D28 replayed the exact DataShare source for CR-0016–CR-0018. The current IPC CLI reports the three source candidates at lines 204, 221 and 243; the target file remains parser-partial, and no production authorization or reachability gap was established. T28 independently reproduced the candidates and source identity. All three remain `not_testable / queued_first_batch` and PARTIAL/BLOCK. See [D28 replay](d28_cr0016_18_replay_20261020.md), [T28 audit addendum](a_line_parallel_queue_20261020_T28_addendum.md), and their verifiers.

D29 replayed HUKS CR-0342: the exact header parses completely and the shared_ptr race CLI reports no candidate; source review found distinct `shared_ptr` copies to a shared `atomic<bool>`, with unresolved product callback lifecycle evidence. T29 independently audited WiFi IPC CR-0336 and reproduced the `ipc.capability.export` candidate in a complete two-file scope; target SA policy and caller authorization remain unknown. Both cases remain `not_testable / queued_first_batch`, PARTIAL/BLOCK, with no change to the frozen A0 queue. See [D29 replay](d29_huks_cr0342_sharedptr_replay_20261020.md), [T29 audit addendum](a_line_parallel_queue_20261020_T29_addendum.md), and their verifiers.

T30 independently reran the current production IPC CLI on fixed Samgr source for CR-0219–CR-0226. All eight exact queue locations reproduce as `ipc.capability.export` candidates; the one-file parse remains partial. T10/T18 registration, authorization-context, parcel and `IRemoteObject` flow facts were checked; product flags, effective caller policy, external reachability and returned-object impact remain unknown. All original rows remain `not_reproduced / queued_not_reproduced`; see [T30 addendum](a_line_parallel_queue_20261020_T30_addendum.md), [per-ID audit](a_t30_samgr_ipc_audit_20261020.md), and [verifier](verify_t30_samgr_ipc_audit.py).

T31 independently reran the IPC CLI for CR-0335 using the exact A0 commit/tree/blob/SHA rather than T21's mismatched task-input identity. The copy-range candidate at line 385 reproduces with complete target-file parse; source guard/allocation/copy sizes match, so the result remains PARTIAL/BLOCK and A0 states remain unchanged. See [T31 addendum](a_line_parallel_queue_20261020_T31_addendum.md), [audit record](t31_cr0335_wifi_p2p_audit_20261021.json), and [verifier](verify_t31_cr0335_wifi_p2p_audit.py).

D31 replayed A0 CR-0335 with the current production IPC CLI using the exact queue-bound Wi-Fi source. The candidate reproduces at line 385 on complete 1/1 parsing; source shows early positive/maximum length guards and equal `ReadBuffer`/allocation/copy sizes, so CWE-125 is not established by this excerpt. The old task input's tree/commit and alternate-blob mismatch is traced without rewriting A0 provenance. The row remains `not_reproduced / queued_not_reproduced`. See [D31 addendum](a_line_parallel_queue_20261020_D31_addendum.md), [analysis](d31_cr0335_wifi_ipc_replay_20261022.md), and [verifier](verify_d31_cr0335_wifi_ipc_replay.py).

T32 independently reran curl CVE-2026-92391 against the exact vulnerable/fixed source objects with the current `resource_lifetime` 0.4.2 production CLI. The complete one-file static differential is 1/0 for the same recursive-cleanup rule; focused mechanism tests pass 8/8 across positive/fixed/safe/unrelated/partial controls. Product/CVE disposition remains PARTIAL/BLOCK because product build/call path, attacker reachability, runtime effect, and impact are not proven. No A0 IDs/statuses changed. See [T32 addendum](a_line_parallel_queue_20261020_T32_addendum.md), [audit](t32_curl_92391_independent_audit_20261023.md), and [verifier](verify_t32_curl_92391_audit.py).

D32 replayed curl CVE-2026-92391 using the current production `resource_lifetime` detector 0.4.2 against exact vulnerable/fixed upstream commits. Vulnerable `lib/mime.c` has one recursive-cleanup candidate at line 1118; exact fix has none, with complete target parses and the existing 8 resource-lifetime regression tests passing. This is source-level regression evidence only, not product impact confirmation; no detector change was needed. See [D32 addendum](a_line_parallel_queue_20261022_D32_addendum.md), [replay report](d32_curl92391_current_replay_20261022.md), and [verifier](verify_d32_curl92391_replay.py).


### T33 — cJSON CVE-2026-67215/67216 current M2 CLI replay

T33 independently reran the current production `ohscan-run` on the exact OpenHarmony `third_party_cJSON` commit/tree, with `cJSON.c` and `cJSON_Utils.c` in one scope. It reproduced the distinct compare-cost candidate at `cJSON.c:3161` and tree-amplification candidates at `cJSON_Utils.c:932` and `:950`. `cJSON.c` parsing is partial; `cJSON_Utils.c` parsing is complete, but detector coverage is partial and aggregate status blocked. D18/T15 and D19/T16 fragment/direct-detector results do not substitute for this whole-source CLI replay. Neither case has a trusted fixed source; both remain PARTIAL/BLOCK and fixed comparison BLOCK. A0 queue was not changed. See [T33 audit](t33_cjson_m2_independent_audit_20261023.md), [machine record](t33_cjson_m2_audit_20261023.json), and [verifier](verify_t33_cjson_m2_replay.py).

D34 and T34 independently reassessed libpng CVE-2026-46675 with the current resource-lifetime 0.4.2 CLI and exact vulnerable/fixed Git objects. Both full-file runs remain blocked/partial with 72 parse issues and zero findings; each seven-fragment set has six complete and one partial (`png_handle_iCCP`), also with zero findings. Parser output does not provide typed same-object field/alias or cross-function order facts needed to prove the disclosed stale zstream reuse, so no generic/name-based rule was added. Keep the case PARTIAL/BLOCK and do not treat the zero findings as a fixed differential. See [D34 model assessment](d34_libpng46675_model_assessment_20261024.md), [T34 audit](t34_libpng46675_independent_audit_20261023.md), and their verifiers.

D35 replayed Preferences CR-0022–CR-0040 from exact A0 source objects using the current shared_ptr_race CLI. The whole fuzz source parses completely and all 19 queued lines reproduce as syntax candidates. Exact BUILD.gn marks the source as `ohos_fuzztest` with a `testonly` fuzz group; findings are test-harness candidates, not production vulnerability evidence, and are not classified as confirmed false positives. All original rows remain `not_testable / paused_pending_evidence`. See [D35 addendum](a_line_parallel_queue_20261020_D35_addendum.md), [machine replay](d35_preferences_source_replay_20261024.json), and [verifier](verify_d35_preferences_fuzz_replay.py).
### D36 — Preferences base-value fuzz candidates CR-0041–CR-0065

D36 replayed the exact A0 `dbpreferencesbasevalue_fuzzer.cpp` source using current `shared_ptr_race` 0.5.1. The single-file parse completed and all 25 queue-bound lines reproduced as syntax candidates. The exact GN target is `ohos_fuzztest("DBPreferencesBaseValueFuzzTest")` under a `testonly = true` fuzz group; sequential fuzz harness calls do not establish concurrent product access, shipping, reachability, or impact. No detector change was justified. Keep all rows `not_testable / paused_pending_evidence` and PARTIAL. See [D36 report](d36_preferences_basevalue_20261024.md), [per-ID replay](d36_preferences_basevalue_replay_20261024.json), and [verifier](verify_d36_preferences_basevalue_20261024.py).

D37 replayed Preferences CR-0066–CR-0090 from the exact A0 `dbpreferencesget_fuzzer.cpp` source with current `shared_ptr_race` 0.5.1. Parsing completed and all 25 queue lines reproduce as syntax candidates. The exact `DBPreferencesGetFuzzTest` GN target is in a `testonly` fuzz group; sequential API calls do not establish product inclusion or concurrent same-object access. No detector change was justified. Preserve all rows as `not_testable / paused_pending_evidence` and PARTIAL. See [D37 addendum](a_line_parallel_queue_20261020_D37_addendum.md), [report](d37_preferences_get_fuzzer_20261024.md), [per-ID replay](d37_preferences_get_fuzzer_replay_20261024.json), and [verifier](verify_d37_preferences_get_fuzzer_20261024.py).

D38 replayed Preferences CR-0091–CR-0096 from the exact A0 `dbpreferencesvector_fuzzer.cpp` source with current `shared_ptr_race` 0.5.1. Parsing completed and all six queue lines reproduce as syntax candidates. The exact `DBPreferencesVectorFuzzTest` GN target is in a `testonly` fuzz group; sequential API calls do not establish product inclusion or concurrent same-object access. No detector change was justified. Preserve all six rows `not_testable / paused_pending_evidence` and PARTIAL. See [D38 addendum](a_line_parallel_queue_20261020_D38_addendum.md), [report](d38_preferences_vector_fuzzer_20261024.md), [per-ID replay](d38_preferences_vector_fuzzer_replay_20261024.json), and [verifier](verify_d38_preferences_vector_fuzzer_20261024.py).
## D39 — Preferences `preferences_fuzzer.cpp` CR-0097–CR-0115

D39 rebound all 19 A0 locations to the exact source and replayed the current `shared_ptr_race` 0.5.1 CLI. Parsing completed; all 19 locations map to syntax candidates. The fuzzer entry executes setup, seven fuzz routines and teardown sequentially. `PreferencesFuzzTest` is an `ohos_fuzztest` target under a `testonly = true` group; this establishes test-harness classification but not product inclusion/exclusion, production internals' threading behavior, or a product race. No product-labeled root miss was established, so no detector change was justified. Preserve all rows as `not_testable / paused_pending_evidence`, PARTIAL. See [D39 report](d39_preferences_fuzzer_20261024.md), [per-row source replay](d39_preferences_fuzzer_replay_20261024.json), [raw CLI](d39_preferences_fuzzer_cli_20261024.json), and [verifier](verify_d39_preferences_fuzzer_20261024.py).

## T40 — faultloggerd `shared_ptr_race` CR-0119–CR-0160

T40 independently rebound all 42 A0 rows to faultloggerd commit `50c7dffc057a32987d5eeb7626c20e1b3717c77b` / tree `8b54f17921ba15ff306bcbef280078003a7b1055`, then ran current `shared_ptr_race` 0.5.1 on the 11 queue-bound files: all parse complete, 2,498 LOC, 11 diagnostics. Only 10/42 A0 rows have an exact current finding; 32 do not, and `dfx_process.h:74` is an additional finding outside this group. CR-0124 is a source/model mismatch (empty StackPrinter Impl constructor line). LocalThreadContextMix is a singleton with production-capable `SetMaps` call sites in LiteProcessDumper and MinidumpDumper, plus Collect/Release in LocalUnwinder; the unsynchronized writes are source-confirmed, while product profile and overlapping call topology remain unproven. No same-object race is confirmed; preserve all 42 rows `not_testable / paused_pending_evidence`, PARTIAL. See [T40 addendum](a_line_parallel_queue_20261020_T40_addendum.md), [audit](t40_faultloggerd_sharedptr_audit_20261024.md), [raw CLI](t40_faultloggerd_sharedptr_cli_20261024.json), and [verifier](verify_t40_faultloggerd_sharedptr_audit_20261024.py).
- D40 在 faultloggerd 精确对象上回放 CR-0119–CR-0160：11 个 A0 源文件完整解析，当前 `shared_ptr_race` 0.5.1 给出 11 条候选，其中 10 个队列行位置精确对应；来源证明的生产级同对象未同步并发漏检尚未建立。`LocalThreadContextMix::maps_` singleton/signal 生命周期保留为未闭合补证项，不据此确认或排除 race。42 条 A0 状态保持 `not_testable / paused_pending_evidence`，无 detector 变化。见 [D40 addendum](a_line_parallel_queue_20261020_D40_addendum.md)、[逐案报告](d40_faultloggerd_sharedptr_20261024.md)、[验证器](verify_d40_faultloggerd_sharedptr_20261024.py)。
## D40 — faultloggerd `shared_ptr_race` CR-0119–CR-0160

D40 replayed 11 source files with complete parsing and 11 current candidates, matching 10 of the 42 A0 locations exactly. `LocalThreadContextMix::maps_` has production-capable `SetMaps` call sites in LiteProcessDumper and MinidumpDumper, and Collect/Release paths in LocalUnwinder. Product configuration and overlapping same-object operations remain unproved, so keep all 42 rows `not_testable / paused_pending_evidence`, PARTIAL, with no detector change. See [D40 addendum](a_line_parallel_queue_20261020_D40_addendum.md), [report](d40_faultloggerd_sharedptr_20261024.md), and [verifier](verify_d40_faultloggerd_sharedptr_20261024.py).

- T40 独立纠正 D40 的 `SetMaps` 调用方结论：`lite_process_dumper.cpp:362` 与 `minidump_dumper.cpp:514` 被 production-capable、安装型 `processdump` GN target 收录；refactor `LocalUnwinder` 也包含 `Collect/Release` 路径。具体产品配置与跨线程/重入 overlap 仍未知，保持 PARTIAL 和无 detector change。调用点及 GN 源身份已 hash-bound，见 [T40 校正](a_line_parallel_queue_20261020_D40_addendum.md) 和 [D40 follow-up JSON](d40_faultloggerd_sharedptr_replay_20261024.json)。


## D41 — faultloggerd shared_ptr_race CR-0161–CR-0173

D41 independently replayed the 13 A0 tail rows against four source files: parse complete 4/4, seven diagnostics, four exact A0 line matches, and nine rows without an exact finding. D40 covered only CR-0119–0160; CR-0161 binds the previously extra `dfx_process.h:74` finding to its own A0 source row. No same-object race is confirmed; preserve all rows as PARTIAL / `not_testable / paused_pending_evidence`. See [D41 report](d41_faultloggerd_tail_report_20261025.md) and [verifier](verify_d41_faultloggerd_tail_20261025.py).

## T41 — independent faultloggerd tail audit CR-0161–CR-0173

T41 independently confirmed the exact source set and current CLI outcome: four files parse completely, seven findings, four exact line matches, nine unhit A0 positions. The production-capable `processdump` target does not prove product manifest selection or concurrent overlap for these objects; T40's `SetMaps` evidence remains scoped to CR-0143. Keep all 13 rows PARTIAL / `not_testable / paused_pending_evidence`. See [T41 report](t41_faultloggerd_tail_audit_20261024.md) and [verifier](verify_t41_faultloggerd_tail_audit_20261024.py).

## T42 — player_framework IPC independent audit CR-0174–CR-0196

T42 independently replayed the exact A0 `player_framework` source using the current production IPC CLI. It produced 24 diagnostics, 23 matching the 23 A0 positions, and one extra out-of-group candidate; 10 of 11 files remain partial. All 23 source positions contain the interface-token read and exact Stub descriptor equality guard before dispatch, using a pinned macro that returns on a failed condition, so the specific missing-descriptor root is contradicted by source. Paired proxy token writes and service/client build, permission, and SA configuration evidence are recorded with identities. Product selection, callback-object exposure, and effective caller policy remain unknown; preserve all 23 A0 states as `not_testable / paused_pending_evidence`, overall PARTIAL/BLOCK. See [T42 addendum](a_line_parallel_queue_20261020_T42_addendum.md), [audit](t42_player_framework_audit_20261025.md), and [verifier](verify_t42_player_framework_audit_20261025.py).

### D42 — multimedia_player_framework IPC CR-0174–CR-0196

D42 rebound 23 A0 rows to `openharmony/multimedia_player_framework` commit `71ab1e0881e0a79f2b9528742677467e7bb8dde5` / tree `9cc6c53506a70424485885c4c10b29dfbfaa8d1b` across 11 C++ files. Current production IPC CLI produced exact line/rule findings for all 23 A0 positions, plus one additional line 86 finding outside the group. However, all 11 scoped Stub implementations contain a `ReadInterfaceToken()` / own `GetDescriptor()` comparison before dispatch and their headers bind each class to an `IRemoteStub<IStandard...>` interface. A second replay including the corresponding headers still emitted the same 24 candidates. This is a B-owner detector/model review item; D42 made no IPC detector/API/schema/catalog change.

The scoped finding row for Recorder permission callsites corresponds to `CheckPermission()`; source applies AccessToken checks to audio and conditional common requests and returns `MSERR_NO_PERMISSION_5400102` on denial. Service Stub creation and listener installation are visible in module code, including `AsObject()` returned by `MediaServerManager` and callback `SetListenerObject`/`SetPCMCallback` paths. This is not proof of product SA exposure, caller authorization/reachability, fixed/vulnerable differential or CIA impact. Detector analysis is partial for 10/11 C++ files (only PCM output is complete); no trusted fixed source is bound. Preserve all 23 rows as `not_testable / paused_pending_evidence`, PARTIAL/BLOCK. See [D42 source audit](d42_player_framework_ipc_source_audit_20261025.md), [machine record](d42_player_framework_ipc_source_audit_20261025.json), [raw CLI](d42_player_framework_cli_20261025.json), [header-context CLI](d42_player_framework_cli_with_headers_20261025.json), and [verifier](verify_d42_player_framework_ipc.py).

Owner follow-up: [D42 B-owner detector review request](d42_b_owner_ipc_review_request_20261025.md). No owner code was changed.

## T45 — safwk ExpireLruCache shared_ptr candidates CR-0231–CR-0240

T45 rebound all ten A0 rows to exact `systemabilitymgr_safwk` commit/tree/blob/SHA and reran `shared_ptr_race` 0.5.1 on the one target header: parse complete, zero diagnostics. `ExpireLruCache` public methods hold the same instance mutex while calling private read/write helpers; `ApiCacheManager` calls also hold the outer `cachesMutex_`. The production-capable `api_cache_manager` GN target and test-only `ExpireLruCacheTest` target were source-hash bound. This does not prove runtime product profile or scheduling behavior; keep all ten rows `not_testable / paused_pending_evidence`, PARTIAL/BLOCK. See [T45 audit](t45_safwk_expire_lru_cache_audit_20261027.md), [machine mapping](t45_safwk_expire_lru_cache_audit_20261027.json), [raw CLI JSON](d42_safwk_expire_lru_cache_20261027.json), and [verifier](verify_t45_safwk_expire_lru_cache_audit_20261027.py).

## T45 — safwk `local_ability_manager_stub.cpp` IPC CR-0244–CR-0246

The independent audit rebound all three A0 rows to exact Safwk source objects. The current IPC scanner maps all three locations, but target-file parsing is partial. Source checks the interface token and caller permission before dispatch; effective product grants, caller reachability and impact remain unknown, and no trusted fixed source is bound. Preserve all three original A0 states as PARTIAL/BLOCK. See [T45 audit](a_t45_safwk_ipc_audit_20261027.md), [CLI result](a_t45_safwk_cli_20261027.md), and [verifier](verify_t45_safwk_ipc_audit_20261027.py).

## T46 — safwk ExpireLruCache independent acceptance CR-0241–CR-0243

T46 independently reran the current `shared_ptr_race` 0.5.1 CLI on the exact one-file A0 scope (complete parse, 0 findings). The three rows map to `DoRemove` erase, `DoClear` clear, and `DoClearExpiredCache` erase; exact source confirms the public callers acquire the same per-instance mutex before reaching these helpers. The zero finding is not a safe result, and the review does not establish an unsynchronized same-object race. Preserve the three rows as `not_testable / paused_pending_evidence`, PARTIAL/BLOCK. See [T46 audit](t46_safwk_expire_lru_cache_audit_20261027.md), [machine mapping](t46_safwk_expire_lru_cache_audit_20261027.json), [raw CLI JSON](t46_safwk_expire_lru_cache_cli_20261027.json), and [verifier](verify_t46_safwk_expire_lru_cache_audit_20261027.py).

## T43 — Taihe FFI independent audit CR-0197–CR-0213

T43 independently replayed the exact Taihe source objects: both files parsed completely, 16 current `shared_ptr_race` findings mapped to 16/17 A0 rows, with CR-0213 unmapped (not a safety result). The root `BUILD.gn` is for Taihe tooling and does not reference the audited author files; product target/build inclusion and same-object cross-thread overlap remain unknown. Preserve all 17 rows as PARTIAL/BLOCK and `not_testable / paused_pending_evidence`. See [T43 addendum](a_line_parallel_queue_20261020_T43_addendum.md), [audit](t43_taihe_ffi_audit_20261026.md), [independent checkout attestation](t43_independent_checkout_attestation_20261026.md), and [verifier](verify_t43_taihe_ffi_audit_20261026.py).

## D43 — Taihe FFI generator shared_ptr family CR-0197–CR-0213

D43 rebound all 17 IDs to `openharmony/arkcompiler_taihe_ffi_gen` commit `d91f43e80d892bca694c6b0fce8ea27cd644919f` / tree `8c5eecdad09e2fe960ce5f3728959a4726f0a91d`, then ran current `ohscanner.cpp.shared_ptr_race` 0.5.1 on the two exact A0 files. Both parse complete (2/2; 316 LOC); 16 diagnostics exactly match CR-0197–CR-0212, while CR-0213's `GetIncrementalPixelMap()` accessor line has no current exact-line finding. The matched code is in author files explicitly commented as test files. The exact repo root `BUILD.gn` contains no reference to these files, and the object tree has no `BUILD.gn` under either author directory; the related async helper can call the getter, and an `imageSourceCrossThreadMutex_` declaration is unused in the inspected source. This still does not prove or exclude external build integration, product reachability, or same-object concurrent overlap. No detector change is justified. Keep all 17 A0 rows `not_testable / paused_pending_evidence`, PARTIAL. See [D43 report](d43_taihe_ffi_gen_report_20261025.md), [per-ID replay](d43_taihe_ffi_gen_replay_20261025.json), [raw CLI JSON](d43_taihe_ffi_gen_cli_20261025.json), and [verifier](verify_d43_taihe_ffi_gen_20261025.py).

### T44A — libtiff CVE-2025-9900 independent current-CLI acceptance



T44 independently replayed D current evidence from a clean checkout. Whole-file vulnerable/fixed runs both remain `completed_with_limitations`, parser partial, detector blocked, and 0 findings; that result is not a safe/fixed conclusion. The bounded exact function plus `_TIFFRGBAImage` is complete: the vulnerable slice reports the existing pointer-offset candidate at `tif_getimage.c:621`, while the fixed slice is quiet. Exact commit/tree/blob/SHA identities and all 345 A0 rows/statuses reconcile. Preserve PARTIAL/BLOCK; no detector change. See [D current replay](d_libtiff9900_current_cli_20261026.md) and [T44 independent acceptance](t_libtiff9900_independent_acceptance_20261027.md).

### T44B — Samgr callback IPC CR-0214–CR-0218 independent audit

The independent audit bound all five A0 rows to the exact Samgr source commit/tree and current IPC CLI: four files selected, 13 findings, one file complete and three partial; all five queue locations map to same-line `ipc.relay.descriptor-boundary` candidates. Source also verifies each callback Stub interface token against its descriptor before dispatch, so this is a source/model mismatch candidate, not a confirmed bypass. Build files include the callback Stubs in production-capable targets, but product profile, reachability, principal, impact, and trusted fixed source remain unknown. Preserve all five A0 states and PARTIAL/BLOCK. See [audit](a_t44_samgr_callback_audit_20261027.md), [CLI result](a_t44_samgr_callback_cli_20261027.md), and [verifier](verify_t44_samgr_callback_audit_20261027.py).

### T47 — battery statistics test candidates CR-0252–CR-0254

T47 bound all three rows to the exact battery statistics source object and replayed current `shared_ptr_race` 0.5.1: `stats_test.h` parses completely and lines 41–43 map to three candidates. The exact GN context is a `testonly` unittest group; product inclusion, concurrent trigger, attacker path, and impact remain unknown. Preserve all original states as `not_testable / paused_pending_evidence`, PARTIAL/BLOCK. See [T47 audit](t47_battery_stats_audit_20261027.md), [CLI result](t47_battery_stats_cli_20261027.md), and [verifier](verify_t47_battery_stats_audit_20261027.py).

### D47 — Camera shared_ptr race candidates CR-0257–CR-0260

D47 rebound the four A0 rows to exact camera framework commit/tree/blob/SHA and replayed the current `shared_ptr_race` 0.5.1 CLI. Both target files parse syntactically complete; the rule reports three A0 locations in `camera_auto_ref_taihe.h` plus one getter return, while `watch_dog.h:34` is quiet. The Taihe listener stores and reads/destroys the wrapper under `CallbackList::listMutex`, and the exact Taihe GN target includes its implementation source; the Watchdog shared pointer is constructor-initialized and its public methods share one mutex. This does not establish every external caller, product profile, or runtime interleaving; the rule's file analysis remains partial and no trusted fixed source/harness exists. No rule change. Keep all four A0 rows `not_testable / paused_pending_evidence`, PARTIAL. See [D47 source-bound audit](a_line_parallel_queue_20261020_D47_addendum.md), [raw CLI JSON](d47_camera_sharedptr_cli_20261027.json), and [verifier](verify_d47_camera_sharedptr_20261027.py).

### T49 — developtools_hapsigner shared_ptr candidate CR-0300

T49 independently rebound CR-0300 to the exact `developtools_hapsigner` source object. Current `shared_ptr_race` 0.5.1 parses the target header completely and emits no finding, so the historical candidate is not reproduced. The audited path constructs a stack-local signing context and passes it synchronously to the writer; GN includes the source in `binary-sign-tool`. Product profile, external callsites, runtime overlap and impact remain unknown; zero findings do not prove safety. Preserve the original A0 state as PARTIAL/BLOCK. See [T49 audit](t49_hapsigner_audit_20261028.md), [CLI result](t49_hapsigner_cli_20261028.md), and [verifier](verify_t49_hapsigner_audit_20261028.py).

### T48 — multimedia_camera_framework callback IPC candidates CR-0291–CR-0299

T48 independently replayed the exact camera-framework source objects with production `ohscanner.interface.ipc` 0.12.12. All nine camera A0 locations map to current findings across four files; three parse complete and `hcamera_service.cpp` is partial. Source review finds interface-token/descriptor checks before all three callback dispatchers, matching parcel-token writes in photo/thumbnail proxies, and GN source inclusion. The two authorization candidates are within `CreateCameraDevice`, which visibly checks CAMERA permission and foreground state before device creation, with CAMERA_SHARED as a separate privilege predicate; the partial model does not fully account for that context. Product build/profile, compiled macro semantics, caller policy/reachability and fixed source remain unknown. Preserve all nine original queue states and PARTIAL/BLOCK. CR-0300 is a separate hapsigner shared_ptr candidate and remains excluded. See [T48 report](t48_camera_callback_audit_20261027.md), [machine mapping](t48_camera_callback_audit_20261027.json), [CLI JSON](t48_camera_cli_20261027.json), and [verifier](verify_t48_camera_callback_audit_20261027.py).

## D48 — ai_intelligent_voice_framework capability export CR-0305

D48 rebound CR-0305 to `openharmony/ai_intelligent_voice_framework` commit `19188608475123695def986a399641bfa64a49f7` / tree `0ec80bfd6532b91f450d2f84517c461a4f7a18ae`, with exact target blob `79a9acae7a4bb5a6dab18b40159f2aab52fcb544` and source SHA-256 `55dc2d68954cf94eb41014010fc6696236d9839fa8246aebd2faa8d033d30fc6`. Current `ohscanner.interface.ipc` 0.12.12 / `oh-ipc-2026.10-v32` parses the target translation unit completely and reproduces `ipc.capability.export` at line 70; no specific detector miss was found. The concrete pinned `IntellVoiceService` factory checks `MANAGE_INTELLIGENT_VOICE` on the IPC caller token before creating the engine, and the Stub exits on a nonzero factory result before writing the remote object. This guard is interprocedural and absent from the one-file detector scope. Product profile/build, caller grants/reachability, returned object impact and trusted fixed source remain unknown; do not infer either exploitability or safety. Preserve CR-0305 as `not_testable / paused_pending_evidence`, PARTIAL/BLOCK. No detector/API/schema/catalog or A0 state change. See [D48 report](d48_ai_voice_cr0305_no_change_20261028.md), [JSON](d48_ai_voice_cr0305_no_change_20261028.json), and [verifier](d48_ai_voice_cr0305_no_change_20261028.py).

## T50 — ai_intelligent_voice_framework independent acceptance CR-0301–CR-0305

T50 reran exact A0 target files with current `shared_ptr_race` 0.5.1 and IPC 0.12.12 / `oh-ipc-2026.10-v32`; all five parse complete. CR-0301 at `adapter_callback_service.h:28` has no current finding. CR-0302/03/04 reproduce the three `engine_util.h` candidates at lines 77/78/86; they are three operations on one `adapter_` member, and per-caller lock dominance/runtime overlap remain unresolved. CR-0305 again reproduces the IPC export candidate at line 70; D48’s exact concrete-factory permission guard does not resolve product caller grants or reachability. A0 remains `not_testable / paused_pending_evidence` for all five, PARTIAL/BLOCK. Full A0 triage verification returned `overall_ok=true` with 345 unique rows; CPP scope check against PR #30 base returned zero violations. See [T50 report](t50_ai_voice_cr0301_cr0305_independent_20261028.md), [machine evidence](t50_ai_voice_cr0301_cr0305_independent_20261028.json), and [verifier](t50_ai_voice_cr0301_cr0305_independent_20261028.py).

## T51 — EDM test-only IPC candidate CR-0313

T51 bound CR-0313 to the exact `TestTimerCallbackStub::OnRemoteRequest` test source. The current IPC CLI emits zero findings, but the translation unit parser and detector coverage are partial, so this is not a safety result. GN places the candidate in `EdmServicesUnitTest`; the production `edmservice` target is separate and does not include the test Stub. Preserve the original A0 state as PARTIAL/BLOCK and `not_testable / paused_pending_evidence`. See [T51 audit](t51_edm_cr0313_audit_20261028.md), [CLI result](t51_edm_cr0313_cli_20261028.md), and [verifier](verify_t51_edm_cr0313_audit_20261028.py).

## D49 — Enterprise Device Manager IPC CR-0306–CR-0312

D49 rebound all seven rows to the exact EDM source object and replayed the current IPC CLI on three production translation units: all parse complete and five candidates map to CR-0307/0308/0310–0312. CR-0306 is a post-dispatch parameterless admin-state query; CR-0309 is before the IDL dispatch path's system/native principal guard. These are no exact-line findings and no specific detector gap was established. The five findings also remain unconfirmed static candidates. Preserve all seven original states as `not_testable / paused_pending_evidence`, PARTIAL/BLOCK; CR-0313's test-only candidate is audited separately in T51. See [D49 assessment](d49_edm_ipc_no_change_20261028.md), [CLI result](d49_edm_ipc_cli_20261028.md), and [verifier](d49_edm_ipc_no_change_20261028.py).


## T52 — security_certificate_manager CR-0315–CR-0316

T52 rebound both candidates to commit `5fcc0b6379567a70176307c281360be2ba281d6b` / tree `f3e078b356ac0724d8ab267d73ab85e69b9b44ad`. The exact `shared_ptr_race` 0.5.1 replay for CR-0315 parsed completely and emitted zero findings; this does not establish safety or target behavior. The exact IPC 0.12.12 replay for CR-0316 emitted one descriptor-boundary candidate at line 127, while target-file parser coverage is partial. Source review shows that callback stub reads an `int32` result and invokes a client callback; effective caller authorization, product dispatch/build conditions, and impact remain unresolved. No trusted fixed source is bound. Keep both original A0 rows `not_testable / paused_pending_evidence`, PARTIAL/BLOCK. T52 verifier reconciles all 345 A0 IDs and statuses; no detector, test, fixture, or A0 state change. See [T52 audit](t52_certmgr_audit_20261028.md), [source identities](t52_certmgr_context_identity_20261028.json), [shared_ptr replay](t52_certmgr_cr0315_shared_ptr_cli_20261028.md), [IPC replay](t52_certmgr_cr0316_ipc_cli_20261028.md), and [verifier](verify_t52_certmgr_audit_20261028.py).
