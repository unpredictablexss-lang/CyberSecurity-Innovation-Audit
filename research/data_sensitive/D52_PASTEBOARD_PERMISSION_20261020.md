# D52 Pasteboard Binder permission candidate review

Date: 2026-10-20 (Asia/Shanghai)
Scanner baseline: `842948084660207fd64399cfd598ed93e5593dcc`
Current rule: `ohscanner.known_disclosed_cves@0.18.0`
Historical D50 run: `ohscanner.known_disclosed_cves@0.16.0`

## Decision

**No rule change; retain the current finding as an unassessed component candidate and keep the authorization boundary unknown.** The fixed component source connects the Binder selector to a data-return handler, and no permission decision appears in the component's stub or service implementation. The complete inherited SystemAbility/IPC skeleton and product-side permission policy are outside this component repository. That leaves a possible external authorization layer unresolved, so this review does not claim that the full request path is unauthorized or that a vulnerability is confirmed.

The D50 location at `pasteboard_service_stub.cpp:41` is method-level: it is the opening brace of `OnRemoteRequest`. It does not identify the selector mapping (`27`), member dispatch (`54-58`), data handler (`73-87`) or parcel write (`82`). Interpret it as the beginning of the method scope only.

## Frozen source identity

The source is read from the local, pinned component repository `D:/OpenHarmony807/repos/miscservices_pasteboard`; no fetch or source modification was performed.

| Object | Value |
|---|---|
| Repository | `openharmony/miscservices_pasteboard` |
| Commit | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` |
| Tree | `e374a0d61c9ec664ddd29fc17002797828c480ee` |
| Target | `services/zidl/src/pasteboard_service_stub.cpp` |
| Git blob | `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b` |
| Source SHA-256 | `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` |
| D50 snapshot SHA-256 | `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648` |

Related exact objects and hashes are in the companion JSON.

## Source trace

1. `PasteboardServiceStub` maps the transaction selector `GET_PASTE_DATA` to `OnGetPasteData` in lines 25-37.
2. `OnRemoteRequest` checks the Binder interface descriptor at lines 43-48, records calling PID/UID at lines 49-53, then dispatches the mapped handler at lines 54-59. The descriptor token binds the expected IPC interface; this method has no explicit permission/token authorization check.
3. `OnGetPasteData` calls `GetPasteData(pasteData)` and serializes the result with `reply.WriteParcelable` at lines 73-87, including the write at line 82.
4. `PasteboardService::GetPasteData` looks up the clip for the caller's OS user. `GetUserId` maps the calling UID to a local account. This demonstrates per-user data selection, but the inspected code does not make a permission allow/deny decision on this path.
5. `i_pasteboard_service.h` declares the method without a permission annotation. The proxy writes the interface descriptor and sends the transaction code. The inner-kits client delegates to the proxy.
6. The component defines `PasteboardPermission::CheckCallingPermission`, but no call from the traced stub, core `GetPasteData`, proxy or service registration path was found. Component-wide permission search finds the helper implementation, not a use on this request path.
7. `PasteboardService::Init` calls inherited `Publish`; `PasteboardService` inherits `SystemAbility` and the stub inherits IPC framework classes. The implementation of those external classes and product-specific system ability access policy are not contained in the pinned component tree.

The code establishes a local selector → handler → data lookup → serialization route. It does not establish the behavior of every external IPC/framework gate.

## Current rule replay and coverage

The full pinned component was replayed against current scanner HEAD `842948084660207fd64399cfd598ed93e5593dcc` and rule version `0.18.0`. The report reproduced the two D50 candidate identities, including the target candidate at line 41 with the same source SHA. The run is `blocked`; the task is `completed_with_limitations`. Current parser counts are 59 complete, 8 partial and 1 not run across 68 selected source files; the target stub is partial and detector coverage is partial. D50's historical 0.16.0 report recorded 57 complete, 10 partial and 1 not run. These are separate runs and versions.

`validated_vulnerability=0`. A blocked/partial run is not a safe result or proof of a miss.

## Controls

| Control | Observed result | Interpretation |
|---|---|---|
| Pinned old D50 source | Current rule emits candidate | Historical candidate reproduction only; no exact fixed source commit was available in the shallow local history. |
| Handler with generic `CheckPermission()` | Silent | Synthetic regression control. |
| Handler with `VerifyCallingPermission(PERMISSION_READ_PASTEBOARD)` | Silent | Required-permission synthetic control. |
| Separate public-read selector and handler name | Silent | Synthetic selector/name boundary control; does not prove product API policy. |
| `HAS_PASTE_DATA` metadata-only sibling returning a boolean | Silent | Synthetic sibling handler control. |
| `SET_PASTE_DATA` different transaction | Silent | Synthetic different-transaction control. |
| Unresolved external skeleton represented as partial source | Candidate retained; run blocked and partial limitation preserved | Confirms unknown coverage is not converted into safe/miss. |
| Exact fixed upstream commit | Unavailable | Local source repo history contains only the grafted pinned commit. Synthetic controls are not an exact fix pair. |

Control tests passed, but these fixtures are not independent holdout labels.

## Commands and verification

Source object checks:

```powershell
git -C D:/OpenHarmony807/repos/miscservices_pasteboard cat-file -e 'dd22c7cb5e5f207a6c38c50f45b7369ee8575840^{tree}'
git -C D:/OpenHarmony807/repos/miscservices_pasteboard ls-tree dd22c7cb5e5f207a6c38c50f45b7369ee8575840 services/zidl/src/pasteboard_service_stub.cpp
git -C D:/OpenHarmony807/repos/miscservices_pasteboard show dd22c7cb5e5f207a6c38c50f45b7369ee8575840:services/zidl/src/pasteboard_service_stub.cpp
```

Current-version full-component replay used `run_reviewed_detectors` with the pinned commit, scope `('.')`, and an explicitly registered `KnownDisclosedCveDetector`. One-off synthetic controls used `KnownDisclosedCveTests.run_source`.

```powershell
python -m unittest tests.detectors.test_known_disclosed_cves -q
git diff --check
```

The targeted disclosed-CVE detector suite passed: **21 tests**. `git diff --check` passed. The frozen baseline `ownership.json` has no `d` lane, so `scripts.check_change_scope` is N/A for this assignment; I did not substitute a different lane or change the policy. Manual task-scope review confirms the only changed paths are the two D52 evidence files under `research/data_sensitive/`, an explicitly assigned evidence destination.

## Limits and next input

- The pinned source is an old component snapshot, not a product build manifest or binary.
- No trustworthy exact fixed commit was available locally.
- SystemAbility/IPC skeleton enforcement and product policy remain unknown.
- No product entry, attacker reachability, runtime impact, affected product version, exploit, or fix revalidation was established.
- T52 should independently repeat the exact object checks, verify the method-level location mapping, and decide whether external skeleton policy can be bound to this source scope. Keep the finding unassessed until that boundary is resolved.

Machine-readable evidence: [D52_PASTEBOARD_PERMISSION_20261020.json](D52_PASTEBOARD_PERMISSION_20261020.json).
