# T58 — Independent Pasteboard rule replay

Date: 2026-10-20 (Asia/Shanghai)

## Result

**`current-rule-candidate-reproduced`** for D52. I independently replayed the exact pinned Pasteboard source against the D52 baseline detector (`0.18.0`, checkout `842948084660207fd64399cfd598ed93e5593dcc`) and the D51 frozen detector (`0.19.3`, checkout `c8f83b82291e82b3272c73b943623336a3c836c3`). Both versions emit the same D52 rule ID and CVE label at `services/zidl/src/pasteboard_service_stub.cpp:41:1`, bound to the same source SHA-256. The full replay remains `blocked` with partial coverage.

The 0.19.3 D52 result is unchanged from 0.18.0. The D51 change moves the D51 observer candidate from line 222 to the insertion at line 241:5; it does not move or otherwise change the D52 finding. This is a rule-replay result on an old component snapshot. CVE causality, product applicability, the complete authorization boundary, and runtime impact remain unknown.

## Exact source and detector identities

| Item | Independently checked value |
|---|---|
| Component repository | `openharmony/miscservices_pasteboard` |
| Component commit / tree | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` / `e374a0d61c9ec664ddd29fc17002797828c480ee` |
| Snapshot SHA-256 | `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648` |
| D52 stub path / Git blob | `services/zidl/src/pasteboard_service_stub.cpp` / `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b` |
| D52 stub raw Git-blob SHA-256 | `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` |
| 0.18.0 scanner checkout / detector blob | `842948084660207fd64399cfd598ed93e5593dcc` / `1a0a01624f7e6cf8abd1755c511ab26f149b6214` |
| 0.19.3 scanner checkout / detector blob | `c8f83b82291e82b3272c73b943623336a3c836c3` / `94113fdd45b2273e6ea9dd02c7eeac886b853329` |

The component identity was verified from the local Git repository at `D:/OpenHarmony807/repos/miscservices_pasteboard`: `HEAD` equals the pinned commit; `git cat-file -p` reports the stated tree; `git ls-tree` reports the stated stub blob; reading the raw blob through `git cat-file blob` and hashing the bytes gives the stated SHA-256. The checked-out working file has different line-ending bytes and was not used for the source hash or detector replay.

## Independent replay

I reconstructed 67 C/C++ `SourceUnit` values directly from the pinned Git blobs and applied the per-file parser statuses saved in the D50 component report. The saved status distribution is 57 complete and 10 partial. Against both detector checkouts, direct `KnownDisclosedCveDetector.detect` returned `blocked`, analyzed 67 units, and produced the same two candidates:

| Version | D51 observer candidate | D52 permission candidate | Run |
|---|---|---|---|
| 0.18.0 | `services/core/src/pasteboard_service.cpp:222:1` | `services/zidl/src/pasteboard_service_stub.cpp:41:1` | blocked |
| 0.19.3 | `services/core/src/pasteboard_service.cpp:241:5` | `services/zidl/src/pasteboard_service_stub.cpp:41:1` | blocked |

The D52 rule ID is `ohknowncve-pasteboard-cve-2025-27247`; the symbol is `CVE-2025-27247`; the source SHA-256 is identical in both versions. The target stub's saved parse state is partial (D50 records a syntax error at line 58), so retaining the candidate does not mean the remainder of the file is completely analyzed. In a separate fresh-parser run through `run_reviewed_detectors`, both versions again emitted the D52 finding; that local run's parser distribution was 59 complete, 8 partial, and 1 not run across all 68 source files, and its detector coverage was partial. These freshly measured parser states are reported separately from the saved D50 states.

I also supplied only the raw pinned D52 stub as a `SourceUnit` with `parse_status=partial`. Both versions emitted the same D52 candidate at line 41:1 and returned `blocked`, with the limitation that remaining coverage is unknown. A complete synthetic input returns `completed` or `completed` with no findings when a tested signature is absent; those synthetic statuses are not evidence of full-source coverage.

## Guard and sibling controls

The exact pinned stub and D52 fixture controls were evaluated in memory against both versions. No scanner, test, fixture, or prior report was edited.

| Control shape | 0.18.0 and 0.19.3 result | What it establishes |
|---|---|---|
| Exact unguarded GET_PASTE_DATA mapping, dispatch, handler read, and parcel write | D52 candidate emitted | The exact local source signature reproduces. |
| `if (!VerifyCallingPermission(PERMISSION_READ_PASTEBOARD)) return ERR_NO_PERMISSION;` before `GetPasteData` | D52 candidate suppressed | A syntactic denial branch with early return suppresses this signature. The helper implementation is synthetic and unavailable, so this does not prove real permission enforcement. |
| Bare `VerifyCallingPermission(PERMISSION_READ_PASTEBOARD);` before `GetPasteData`, with the result unused | D52 candidate suppressed | A permission-like token alone suppresses; the rule does not require a checked result or denial branch. This is a precision risk. |
| Bare permission-like call after `GetPasteData` | D52 candidate suppressed | The matcher does not enforce check-before-read order or dominance. |
| Bare permission-like call after `reply.WriteParcelable` | D52 candidate suppressed | A post-serialization token suppresses even though it occurs after the data has been returned. This is an actionable false-suppression counterexample. |
| Permission-like call inside `if (false) { ... }` before the read | D52 candidate suppressed | The matcher does not check branch reachability. |
| Permission-like call only in a separate helper outside `OnRemoteRequest` and `OnGetPasteData` | D52 candidate remains | The matcher is limited to text within those two method bodies; helper authorization is not followed. |
| `GET_PASTE_DATA` renamed to a different selector | No D52 candidate; unrelated D51 observer candidate may remain in a combined fixture | The D52 mapping token is part of the signature. |
| Handler renamed and data read / parcel write removed | No D52 candidate | The D52 handler shape is part of the signature. |
| Existing fixture `positive.cpp` | D52 candidate emitted | Scoped positive regression input. |
| Existing fixtures `safe.cpp`, `fixed.cpp`, and `unrelated.cpp` | No D52 candidate | Scoped signature-level negative regression inputs only. |

The earlier T52 permission-guard controls therefore remain valid only as scoped regression observations: they show suppression for the tested token-bearing method shapes. They do not verify that a real authorization decision dominates data access or serialization. The demonstrated ignored-result, after-read, post-serialization, and dead-branch cases leave a rule-quality gap. D52's exact source contains no permission-like token in the two checked methods, so this gap does not change the fact that the candidate reproduces on that source.

## Source case, coverage, and product/CVE status

- **Rule regression:** D52 rule ID, symbol, path, source hash, anchor, and blocked/partial result are unchanged from 0.18.0 to 0.19.3. The detector diff changes D51 observer-quota logic; no D52 matcher change was found.
- **Source case:** The pinned stub maps `GET_PASTE_DATA` to `OnGetPasteData`; the request dispatcher routes to the handler; the handler calls `GetPasteData` and writes a parcelable. The reported line 41 is the opening brace of `OnRemoteRequest`, not the missing permission decision or the data-copy/write statement. The pinned core getter selects the caller's user clip and copies it without a visible permission decision in that getter body.
- **Coverage:** The full component scan remains blocked and partial. The exact target stub is partial. The rule does not inspect the core getter or its callers, helpers outside the two checked methods, inherited IPC/SystemAbility enforcement, service ACL, or product policy. Partial, skipped, failed, and unknown evidence is not a safe result or a miss.
- **Product/CVE:** Product build identity and component inclusion are unavailable; product vulnerability is `UNKNOWN`. The advisory association is not source-level CVE causality evidence; exact CVE root-cause mapping is `UNKNOWN`. No product reachability, runtime impact, fixed-source detector replay, or fixed-product retest was established. Preserve D57's narrow pinned-source interpretation.

## Reproduction method

Commands used for immutable source identity:

```powershell
git -C D:/OpenHarmony807/repos/miscservices_pasteboard rev-parse HEAD
git -C D:/OpenHarmony807/repos/miscservices_pasteboard cat-file -p dd22c7cb5e5f207a6c38c50f45b7369ee8575840
git -C D:/OpenHarmony807/repos/miscservices_pasteboard ls-tree dd22c7cb5e5f207a6c38c50f45b7369ee8575840 services/zidl/src/pasteboard_service_stub.cpp
git -C D:/OpenHarmony807/repos/miscservices_pasteboard cat-file blob dd22c7cb5e5f207a6c38c50f45b7369ee8575840:services/zidl/src/pasteboard_service_stub.cpp
```

The full replay imported `ScanContext`, `SourceUnit`, `KnownDisclosedCveDetector`, and `DetectorRun` consistently from each checkout's `src.ohscanner` package. Source bytes and parser states were bound by path from Git tree objects and the D50 report's `detector_runs[0].parsing` entries. The exact candidate is reproducible with this focused Python logic in each scanner checkout (use the pinned object bytes shown above for `stub_text`):

```python
unit = SourceUnit(path=stub_path, language="cpp", text=stub_text,
                  sha256=sha256(stub_bytes).hexdigest(), parse_status="partial")
request = ScanRequest(
    "T58-stub", "openharmony/miscservices_pasteboard", pinned_commit,
    d50_snapshot_sha256,
    "current-component:openharmony/miscservices_pasteboard",
    profile_id="light-ast", provenance="git_object")
run = KnownDisclosedCveDetector().detect(ScanContext(request, (unit,), {}), (unit,))
```

For full-component saved-state replay, instantiate the 67 C/C++ `SourceUnit` objects the same way, taking each `parse_status` from the matching path in `D50_COMPONENT_CVE_REPLAY/pasteboard.json` and the raw bytes/blob ID from the pinned Git tree. Running the same `detect` call on all units gives the exact two findings and `blocked` status above. Guard and sibling variants were produced in memory from the exact raw stub using the mutations named in the control table.

The T58 JSON companion records the verdict, source and rule identities, replay outputs, control outcomes, coverage limits, and product/CVE status. It is strict JSON (no comments, duplicate keys, or trailing commas).

## Comparison with frozen D58

I reviewed the frozen D58 report at commit `8eb43e33a10e88cc02341df3e9bb91f93d1dc862` after independently rebuilding the saved-state replay and controls. The D52 candidate identities, anchor, source hash, 0.18.0/0.19.3 run states, and the under-guarded matcher counterexamples agree. D58 was updated to call the early-return case a syntactic guard-shape control and to leave real permission enforcement unknown. T58 makes the same qualification. No D58 evidence mismatch remains.
