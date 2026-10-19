# T51 independent acceptance: Pasteboard observer quota candidate

- Date: 2026-10-20 (Asia/Shanghai)
- Independent checkout: `D:/openHarmonyScanner/worktrees/t51-pasteboard-independent-20261020`
- Developer checkout: `D:/openHarmonyScanner/worktrees/d51-pasteboard-quota-20261020`
- Scanner base: `842948084660207fd64399cfd598ed93e5593dcc`
- Final frozen developer commit: `2302caec9d812e70b281d195dc24f895827d373a`
- Final rule: `ohscanner.known_disclosed_cves@0.19.1`
- Role: independent source, regression, and scope audit; no detector, test, fixture, expected-output, or policy files were changed in this checkout.

## Decision

| Dimension | Result | Evidence boundary |
|---|---|---|
| Rule regression | **PASS for the reviewed observer-quota shape and controls** | Current rule emits at the exact set insertion. Direct quota and helper guards suppress only when the at-cap outcome exits before insertion. Both previously discovered no-op suppression cases retain the candidate. |
| Static source-case acceptance | **PARTIAL** | The source-bound candidate and upstream fixed mechanism are reproduced. The exact fixed revision refactors the API, so its zero hit is non-diagnostic; the full component run remains blocked with partial analysis coverage. |
| Component root cause | **CANDIDATE SUPPORTED, unassessed** | The pinned source stores distinct remote observer objects in a user-keyed set without a visible hard count bound. A later fixed mechanism adds a per-calling-process aggregate count of 10. The CVE advisory does not identify this exact source line. |
| Product/CVE status | **UNKNOWN** | No product build identity, service ACL, product caller reachability, automatic callback-lifetime proof, or controlled product impact was verified. `validated_vulnerability=0`; no safe conclusion follows from blocked/partial coverage. |

The detector location improved from D50's method opener (`pasteboard_service.cpp:222`) to the insertion statement (`pasteboard_service.cpp:241:5`). This identifies the candidate operation. The D50 `0.16.0` result is historical evidence; current rule behavior is established by the `0.19.1` full-component replay and independent controls below.

## Source identity and repeat replay

The vulnerable component objects were re-read from `D:/OpenHarmony807/repos/miscservices_pasteboard`. The exact commit, tree, target blob, and file SHA-256 match the D50 record.

| Object | Independently verified identity |
|---|---|
| Vulnerable repo / commit | `openharmony/miscservices_pasteboard` / `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` |
| Tree / full-component snapshot SHA-256 | `e374a0d61c9ec664ddd29fc17002797828c480ee` / `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648` |
| Target file | `services/core/src/pasteboard_service.cpp` |
| Target blob / bytes / SHA-256 | `c380ac266a85edd818caa811f11b99722d351788` / 17,335 / `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52` |
| Fixed-mechanism repo / commit | `openharmony/distributeddatamgr_pasteboard` / `836cf6990579451d6521e9177d749660b07ad34e` |
| Fixed tree / target blob / SHA-256 | `8db5ac5a62c018c80818c85482e4914a836a4765` / `af95e87bed596cc9f159bbf020536ea361835977` / `e8202191adf1d660a7a6c3149481013747e1a40b6bb166aa5947fb28b67ad3d4` |

The fixed object is recorded by D51 as OpenHarmony 5.0.3 merged PR !1539. I independently rechecked the commit/tree/blob and target bytes in its local Git object store. The fixed source computes observer counts for `(userId, callingPid)` and rejects at `MAX_OBSERVER_COUNT = 10` before inserting. The fixed API is renamed to `AddObserver`, so its zero finding under the old signature is not counted as proof of detector sensitivity.

Two consecutive current-version full-component CLI replays exited 0 and were identical for commit, tree, snapshot SHA, parser counts, task/run status, diagnostics, locations, and source hashes:

```powershell
python -m src.cli.main ohscan-run --repo-dir D:\OpenHarmony807\repos\miscservices_pasteboard --repository openharmony/miscservices_pasteboard --commit dd22c7cb5e5f207a6c38c50f45b7369ee8575840 --detector ohscanner.known_disclosed_cves
```

| Replay field | Result |
|---|---|
| Rule version / DetectorRun | `0.19.1` / `blocked` |
| Task status | `completed_with_limitations` |
| Component scope | 67 C/C++ files, 7,104 LOC |
| Parse counts | 59 complete, 8 partial, 1 not run |
| Candidate under review | CVE-2025-25212 at `services/core/src/pasteboard_service.cpp:241:5`, source SHA matches above |
| Other existing candidate | CVE-2025-27247 at `services/zidl/src/pasteboard_service_stub.cpp:41:1`, source SHA `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` |
| Target translation unit | Parser `complete`, analysis `partial` (`detector_model_incomplete`) |
| Product promotion | `validated_vulnerability=0` |

The method-level 27247 location remains a separate limitation and is not affected by D51's observer rule. D50's historical `0.16.0` report had 57 complete, 10 partial, and 1 not run. The `0.18.0` replay had the same two candidates but placed CVE-2025-25212 at line 222. D51's first `0.19.0` revision fixed the source location but suppressed candidates for two no-op quota shapes; the final `0.19.1` revision was frozen after that issue was reported and retains them, as independently verified below.

## Root-source review

The pinned `AddPasteboardChangedObserver` method (lines 221-246) maps the Binder calling UID to an OS `userId`, looks up or creates `observerMap_[userId]`, and inserts the callback into a `std::set` at line 241. `classcomp` compares `AsObject()` references, so re-registering the same remote object deduplicates, while distinct observer objects remain separate set entries. The visible collection is user-keyed, not per-process-keyed; the candidate premise is that it has no hard count bound, not that the old source partitions by process.

The adjacent ZIDL path maps `ADD_OBSERVER` to `OnAddPasteboardChangedObserver`, reads and casts a remote object, then calls `AddPasteboardChangedObserver`. The service exposes single-remove and remove-all-for-user methods. A repository-wide search found a death recipient for the client-side connection to the Pasteboard service itself, but did not find an observer-callback death recipient or an automatic server-side observer removal on caller death. This source review does not prove service ACLs, caller reachability, or actual memory/availability impact.

## Independent control probes

The final frozen `0.19.1` detector was exercised directly through the existing `KnownDisclosedCveTests.run_source` helper. No test or fixture file was changed by this review.

| Probe | Result |
|---|---|
| Exact vulnerable component source, supplied with conservative `parse_status=partial` | Candidate retained at line 241, column 5; run blocked |
| Direct at-cap condition followed by `return`, then insert | No CVE-2025-25212 candidate |
| Same-file boolean quota helper whose false result is consumed by an exiting caller guard | No candidate |
| At-cap condition that only logs, followed by insert | Candidate retained |
| Boolean quota helper called but return value ignored, followed by insert | Candidate retained |
| Unrelated `historyMap_` growth | No candidate |
| Exact fixed source object | No candidate; **non-diagnostic** because the function/API was renamed and restructured |

The log-only branch and ignored-helper-result probes had been false negatives in frozen D51 `0.19.0`; both remain candidates under `0.19.1`. The true hard-quota controls still suppress, so this review found no remaining version of those two specific failures. The helper analysis is local and narrow: cross-file admission bounds, more complex control flow, callbacks, and real caller lifetimes remain outside its proof.

Independent regression suite:

```powershell
python -m pytest tests/detectors/test_known_disclosed_cves.py tests/detectors/test_known_case_corpus.py -q
```

Result: **31 passed**. These tests support the rule behavior only; the disclosed source and synthetic controls are development/regression material, not independent holdout labels.

## Task state, scope, and remaining blockers

D50's pasteboard task remains `completed_with_limitations` with a blocked DetectorRun. The current product closure task tree remains `ACTIVE_NOT_ADMITTED`: G12-PC-1 `IN_PROGRESS_BLOCKED`, PC-2 `PIPELINE_IMPLEMENTED_NOT_EXECUTED`, PC-3 `BLOCKED`, PC-4/PC-5 `NOT_RUN`, PC-6 `NOT_ADMITTED`. D51 did not change that task tree or queue state.

The final D51 diff from the frozen base contains only the observer detector, its focused regression/corpus tests and fixtures, and D51 evidence under `research/data_sensitive/`. No shared runner, parser, API, Catalog, ownership policy, scope checker, or unrelated detector was changed. `git diff --check 842948084660207fd64399cfd598ed93e5593dcc 2302caec9d812e70b281d195dc24f895827d373a` passed; the developer checkout is clean. `check_change_scope` is **N/A** because the frozen `ownership.json` defines no D lane. Changed paths were manually reviewed against the explicit D51 detector/test/fixture/evidence assignment; no substitute lane or policy edit was used.

Remaining product blockers are precise: bind the component to a product build/version; establish service ability ACL and attacker entry; establish observer lifetime and caller-death cleanup behavior beyond the inspected source; reproduce the availability impact in an authorized product-compatible environment; and revalidate the fixed product. Until then, keep this as a source-supported candidate with product status unknown.

The public CVE record describes local denial of service from improper input in OpenHarmony v5.0.3 and prior, but does not identify this exact source line or establish this component snapshot's product inclusion ([NVD CVE-2025-25212](https://nvd.nist.gov/vuln/detail/CVE-2025-25212)).

Machine-readable counterpart: [t51_pasteboard_quota_acceptance_20261020.json](t51_pasteboard_quota_acceptance_20261020.json).
