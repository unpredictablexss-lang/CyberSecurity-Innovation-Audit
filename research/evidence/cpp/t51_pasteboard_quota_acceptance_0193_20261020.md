# T51 final independent acceptance: Pasteboard observer quota (0.19.3)

- Date: 2026-10-20 (Asia/Shanghai)
- Independent checkout: `D:/openHarmonyScanner/worktrees/t51-pasteboard-independent-20261020`
- Frozen developer commit: `c8f83b82291e82b3272c73b943623336a3c836c3`
- Frozen rule: `ohscanner.known_disclosed_cves@0.19.3`
- Supersedes the earlier T51 report for detector 0.19.1; this report is the final review of the 0.19.3 rule revision.
- No detector, test, fixture, expected-output, or policy files were changed in the independent checkout.

## Decision

| Dimension | Result | Evidence boundary |
|---|---|---|
| Rule regression | **PASS for the exact reviewed guard shapes and probes listed below** | Direct and helper positive controls suppress only for the reviewed ordered, bound, exiting guard shapes. All seven negative controls retain the candidate. This is not a general proof of quota semantics or arbitrary control flow. |
| Static source case | **PARTIAL** | Exact source identity and insertion location are bound; full component `DetectorRun` is blocked and the target file's analysis remains partial. |
| Component root cause | **CANDIDATE SUPPORTED, unassessed** | The pinned source inserts remote observer references into a user-keyed set without a visible hard count bound. This source evidence does not prove product reachability or impact. |
| Product/CVE status | **UNKNOWN** | `validated_vulnerability=0`; product build identity, service ACL/reachability, caller-death cleanup, and runtime impact remain unverified. Blocked or partial zero findings must not be interpreted as safe. |

The 0.19.1 PASS in the prior report is superseded and restricted to its directly tested shapes. The 0.19.2 commit added the insertion-after-guard and compound-predicate controls, but final acceptance is based on independent testing of 0.19.3. No claim is made about control-flow shapes outside the probes here.

## Frozen rule and source identity

The reviewed detector commit is `c8f83b82291e82b3272c73b943623336a3c836c3` (`0.19.3`). The final rule accepts a direct quota guard only when the at-cap condition is a single top-level predicate before insertion, the comparison receiver matches the insertion receiver, and the branch exits by `return` or `throw`. A `goto` is not accepted as an exit. The helper form is constrained to the reviewed two-return boolean structure and requires argument/receiver binding through the caller's exiting guard.

The vulnerable component source was re-read from its exact pinned Git object, not from the mutable worktree file:

| Object | Verified value |
|---|---|
| Repository / commit | `openharmony/miscservices_pasteboard` / `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` |
| Tree / snapshot SHA-256 | `e374a0d61c9ec664ddd29fc17002797828c480ee` / `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648` |
| File | `services/core/src/pasteboard_service.cpp` |
| Blob / bytes / SHA-256 | `c380ac266a85edd818caa811f11b99722d351788` / 17,335 / `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52` |
| Candidate | `CVE-2025-25212`, line 241, column 5: `observers->insert(observer)` |

The detector candidate remains at the real set insertion, rather than the method opener. The source body maps IPC caller UID to OS `userId`, uses a user-keyed observer set, and has no visible hard count bound in that registration path. Same remote references deduplicate in the set; distinct observer objects remain distinct entries. The source review does not establish the service ACL or caller reachability.

## Independent quota probes

Each probe was run against the final frozen detector with the existing `KnownDisclosedCveTests.run_source` helper. No test or fixture files were edited by this acceptance review.

| Probe | Expected | Observed | Result |
|---|---|---|---|
| Direct single at-cap guard on the same `observers` receiver, before insertion, exiting with `return` | Suppress candidate | No candidate | PASS |
| Exact two-return boolean helper; caller passes the same `observers` set and exits on true before insertion | Suppress candidate | No candidate | PASS |
| At-cap comparison only logs, then inserts | Retain candidate | Candidate retained | PASS |
| Hard-quota helper called but return ignored, then inserts | Retain candidate | Candidate retained | PASS |
| Insert occurs before the at-cap guard | Retain candidate | Candidate retained | PASS |
| Compound predicate `size >= MAX && observer != nullptr` | Retain candidate | Candidate retained | PASS |
| Guard compares unrelated `history` receiver before observer insertion | Retain candidate | Candidate retained | PASS |
| At-cap branch jumps by `goto` to insertion label | Retain candidate | Candidate retained | PASS |
| Unrelated `historyMap_` growth | No observer-quota candidate | No candidate | PASS |

These probes support the rule's narrow local pattern only. Cross-file quota state, aliases or wrappers beyond the exact helper shape, exception paths, concurrency, cleanup semantics, and callers outside the reviewed body remain unproved.

## Exact component replay

Ran the following command twice from the frozen 0.19.3 checkout; both invocations exited 0:

```powershell
python -m src.cli.main ohscan-run --repo-dir D:\OpenHarmony807\repos\miscservices_pasteboard --repository openharmony/miscservices_pasteboard --commit dd22c7cb5e5f207a6c38c50f45b7369ee8575840 --detector ohscanner.known_disclosed_cves
```

The stable evidence projection was identical across the two generated JSON reports: status, source commit/tree/snapshot hash, parse counts, detector version and run status, scope, diagnostic identities/locations, and source hashes.

| Replay field | Result |
|---|---|
| Top-level task status | `completed_with_limitations` |
| Rule / `DetectorRun` | `0.19.3` / `blocked` |
| Scope | 67 C/C++ files, 7,104 LOC |
| Parse counts | 59 complete, 8 partial, 1 not run |
| CVE-2025-25212 | `services/core/src/pasteboard_service.cpp:241:5`, source SHA matches pinned file |
| CVE-2025-27247 | `services/zidl/src/pasteboard_service_stub.cpp:41:1`, SHA `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` |
| Target translation unit | Parser complete; semantic analysis partial (`detector_model_incomplete`) |
| Validated vulnerabilities | 0 |

The second candidate is unrelated to the D51 quota rule and remains at a method-opening location. Neither candidate promotes product/CVE status.

## Tests, scope, and product status

Targeted test command:

```powershell
python -m pytest tests/detectors/test_known_disclosed_cves.py tests/detectors/test_known_case_corpus.py -q
```

Result: **31 passed**. The evidence JSON in the D51 commit parsed with `python -m json.tool`; `git diff --check` passed for the frozen developer commit.

The frozen diff paths are the D51 detector, its focused tests and known-case fixtures/manifest, and D51 evidence under `research/data_sensitive/`. Manual review found no shared runner, parser, API, Catalog, ownership policy, scope checker, or unrelated detector changes. `check_change_scope` is **N/A (baseline ownership has no D lane)**; the changed paths were manually checked against the D51 assignment. No policy or checker change was made.

The product closure task tree remains `ACTIVE_NOT_ADMITTED`: G12-PC-1 `IN_PROGRESS_BLOCKED`, PC-2 `PIPELINE_IMPLEMENTED_NOT_EXECUTED`, PC-3 `BLOCKED`, PC-4/PC-5 `NOT_RUN`, and PC-6 `NOT_ADMITTED`. Product build/component binding, service ACL and attacker path, callback cleanup on caller death, runtime impact, and fixed-product revalidation remain unknown. Keep rule regression status separate from product/CVE status.

The older D50 0.16.0 result is historical development evidence, not a holdout. The independent current-version replay and probes above are the basis for this acceptance.
