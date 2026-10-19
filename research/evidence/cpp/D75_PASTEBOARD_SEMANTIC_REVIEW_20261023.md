# D75 downstream semantic review: D52 Pasteboard read gate

## Reviewer judgment

**Retain as a narrow source-only missing-local-read-gate candidate.** The pinned D52 component source supports the bounded statement that no explicit caller read-permission predicate is visible in the traced `GET_PASTE_DATA` path before the core clip lookup/copy. This statement is confirmed for the reviewed repository snapshot. It does not establish that the whole platform lacks authorization, that a released product contains this exact snapshot, or that CVE-2025-27247 is caused by this path.

A System Ability Manager ACL, installed profile, Binder/platform framework enforcement, or product policy outside the component could reasonably prevent unauthorized callers even when this component path has no local check. Those sources are absent from the historical evidence package. Accordingly, system-wide authorization and product impact remain unknown. Do not promote the observation to a confirmed bypass or vulnerability.

## Confirmed from pinned D52 component source

Historical identity: `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`.

The route is source-bound across the interface, client, proxy, service stub, and core implementation:

1. `GET_PASTE_DATA` is declared as code 0 in `services/core/include/i_pasteboard_service.h`.
2. The stub constructor maps that code to `OnGetPasteData`; `OnRemoteRequest` checks the interface token and logs calling PID/UID, then dispatches. The line-41 candidate anchor is the opening brace of `OnRemoteRequest`, a method-entry anchor.
3. `OnGetPasteData` calls `GetPasteData(pasteData)` and writes the result to the reply.
4. The core `PasteboardService::GetPasteData` selects data by user and copies the clip contents. In the route and implementation reviewed, no explicit caller read-permission predicate appears before that lookup/copy.
5. The NAPI/framework client and proxy call this route; those component call sites do not add a visible caller permission predicate.

The PID/UID retrieval at the stub is logging/identity observation in the cited lines. It is not itself an authorization check.

## Old helper and true mock: bounded interpretation

The old `utils/native/src/pasteboard_permission.cpp` contains `PasteboardPermission::CheckSelfPermission`, which returns `true` unconditionally (blob `5e7bf43287374eb21a8200400cbe350e8d234368`, SHA-256 `b1241967b47b12ffbcc980c4f9514e32406d04b0652ff66fa7f88e4bd29f5761`). `CheckCallingPermission` resolves a bundle name and delegates to `MockPermission::VerifyPermission`.

The pinned `utils/mock/src/mock_permission.cpp` implementation also returns `true` unconditionally (blob `d4528b45a88c695c0381ed30d65fa551529c2f92`, SHA-256 `e21db508f8b5c0646f7b1fe5665dd9befe0584096386cce7ea5c6bda1206ec3e`). `services/BUILD.gn` lists both mock and helper source files in the `pasteboard_service` shared-library sources; `utils/BUILD.gn` also lists them in the `pasteboard_tools` source set.

This is a real source-level utility/mock fact and must not be hidden. It still does **not** show an effective read-route guard: repository-wide search at the pinned commit finds no call site for either `CheckSelfPermission` or `CheckCallingPermission` beyond their declarations/definitions. In particular, the traced `GET_PASTE_DATA` route does not invoke them. The true mock is evidence about those helper implementations, not proof that an attacker reaches a permissive helper from this read path, nor proof that external platform authorization is absent. Build-list inclusion alone does not establish how a product image packaged or invoked it.

## Current implementation is a separate snapshot

D74 pins current `openharmony/distributeddatamgr_pasteboard` at commit `e73747b227104e6743e957ce31040edf58507221`, tree `4128cdf9ad11d393c30f2839f43419e97a5a466d`. Keep it separate from D52 historical evidence.

In that current snapshot, `GetPasteDataInner` obtains the IPC caller token and checks `VerifyPermission(tokenId)` before `GetData(...)`, returning a permission error when the check fails. `VerifyPermission` checks `READ_PASTEBOARD` and `SECURE_PASTE`; it also permits native/shell token types and an eligible Ctrl+V path. If none grants access, SDK version 12 or later is denied, while older SDK versions fall through to allow for compatibility; invalid SDK version is denied. Separately, a developer-mode test-server condition exempts a request in `GetPasteDataInner` from the failed permission check.

These branches show a later component-source implementation with explicit policy and exceptions. They do not prove the behavior of D52, any released product, or AccessTokenKit/PermissionUtils internals. The D74/T74 boundary correctly treats this as a cross-version source difference only.

## Unknown and unsupported inferences

- Whether an installed historical `/system/profile/pasteboard_service.xml` or System Ability Manager ACL restricts callers.
- Whether packaging maps `profile/3701.xml` to the path referenced by `etc/init/pasteboardservice.cfg`; the component snapshot shows the source profile declares SA 3701 and `distributed=false` but does not declare a caller ACL, while init references an installed path not present in the checkout.
- Whether Binder/SAMgr/platform framework policy performs authorization outside this component path.
- Whether D52's source commit corresponds to any specific product image, version, configuration, or deployment.
- Whether a caller could reach this method and retrieve data in a product, whether an authorization bypass exists, and whether the CVE is caused by this path.

No product safety, exploitability, or CVE-causality conclusion is made.

## Minimum evidence required to resolve the open question

For effective system authorization, obtain the installed profile and its build/install mapping for the target image, SAMgr/IPC ACL enforcement code and configuration for that profile, and relevant platform AccessTokenKit/policy sources. For product applicability, add a product fingerprint/version plus manifest/build provenance binding the image to the historical component commit and those policy artifacts. A runtime authorization matrix for authorized and unauthorized caller identities on that exact image would validate the composed behavior. Generated IPC hook code/build provenance is also needed if the product uses generated hooks not represented in the checked-in component sources.

## Forwardable structured conclusion

- **Confirmed:** At pinned D52 component commit `dd22c7...`, the traced `GET_PASTE_DATA` component path has no visible in-component caller read-permission predicate before the core data lookup/copy. This is a narrow source observation.
- **Unknown:** Whether external SA ACL/profile, platform framework policy, or product configuration supplies effective authorization; whether any product ships the source; and whether a CVE is causally attributable.
- **Do not infer:** System-wide absence of protection, attacker reachability, a product bypass, or product safety from the old helper's hard-coded `true` or the mock's `true` implementation. Those helpers have no call site in the pinned component route.
- **Minimum next artifacts:** Target product fingerprint/build provenance; installed historical SA profile and mapping; SAMgr/Binder ACL enforcement; platform permission implementation/policy; and an exact-image authorized/unauthorized caller test.
