# T10 independent Samgr source-flow review — CR-0219–CR-0223

Date: 2026-10-20  
Role: independent evidence line; no detector, test, or fixture edits  
Base: T3 commit `9d10a523f1a47f6971b35cd010b24dfe3835fc05`

## Source identity

The local project-object mirror `D:/openHarmonyScanner/openharmony/.repo/project-objects/systemabilitymgr_samgr.git` resolves the pinned commit `08e2a552b839ea7727251cb9b749a5c1dd9cfeff` to tree `b7a89e95be788f2f2372258e341f7be842c7826d`. That tree resolves `services/samgr/native/source/system_ability_manager_stub.cpp` to blob `ae84d998c4d90c8c08d692b9020404593b58a0cc`; the checked-out bytes are 78,212 bytes and SHA-256 `e82aa966b6c70278c64683b3bc4c0b236cf7550da3e65aeafc12acfa5f718433`. All five queue rows use this same source key. The object types, commit-to-tree relation, tree-to-blob relation, Git blob OID, and byte hash were independently checked.

The five original IDs, candidate IDs, line keys, original `not_reproduced` status and `queued_not_reproduced` queue status are unchanged. The shared A0 scan recorded source-file `parse_status=partial`, `analysis_status=partial`, reason `detector_model_incomplete`; no target-derived harness was run. This T10 review is supplemental source-flow evidence, not an upgrade of the scanner result or a claim that the exports are exploitable.

## Per-ID mapping

| Queue ID / candidate ID | Original line; exact source range | Transaction/caller flow and guard | Data and exported object | Result |
|---|---|---|---|---|
| CR-0219 / `ohscanner.interface.ipc:04a66a31ff68330e` | 464; method `CheckRemtSystemAbilityInner`, lines 422–470 | Registered for `CHECK_REMOTE_SYSTEM_ABILITY_TRANSACTION` in `SetAbilityFuncMap` (155–156); `OnRemoteRequest` enforces the Samgr interface token and dispatches mapped codes (293–309). Checks `CanRequest()` (native AccessToken type only), validates SA ID, then `CheckGetRemoteSAPermission(systemAbilityId)` before resolving the remote service. | Reads SA ID and device ID from `MessageParcel`; transforms device ID to UUID; obtains an `IRemoteObject` for that SA/device and writes it to reply. Capability/object transfer; no FD read/write found in this path. | **PARTIAL** — sink and source-local permission order are visible; actual caller domain authorization, SELinux build/policy and device/SA exposure are not bound. |
| CR-0220 / `ohscanner.interface.ipc:d25bf1cd70fc1a15` | 551; `CheckSystemAbilityImmeInner`, lines 512–565 | Registered for `CHECK_SYSTEM_ABILITY_IMMEDIATELY_TRANSACTION` (159–160); same token gate and transaction dispatch. Checks `CanRequest()`, valid SA ID, and `CheckGetSAPermission(systemAbilityId)` before lookup. | Reads SA ID and `isExist` bool; obtains an `IRemoteObject` from `CheckSystemAbility` and writes object plus existence bool. No FD flow found. | **PARTIAL** — source-local checks precede export; product token/caller and SELinux permission mapping and the specific returned SA exposure are unknown. |
| CR-0221 / `ohscanner.interface.ipc:38dbb42209c3b6bc` | 668; `GetSystemAbilityInner`, lines 638–674 | Registered for `GET_SYSTEM_ABILITY_TRANSACTION` (143–144); same token gate and transaction dispatch. Validates SA ID and calls `CheckGetSAPermission(systemAbilityId)` before lookup. Unlike CR-0219/0220 this method has no local `CanRequest()` check in the inspected range. | Reads SA ID; obtains a local `IRemoteObject` from `GetSystemAbility` and writes it to reply. No FD flow found. | **PARTIAL** — SELinux check is the visible per-SA boundary when enabled, but helper explicitly returns true when built without `WITH_SELINUX`; product build and effective policy/caller allow rules are missing. |
| CR-0222 / `ohscanner.interface.ipc:f4b4ee6abf220a93` | 706; `CheckSystemAbilityInner`, lines 676–712 | The method follows the `CHECK_SYSTEM_ABILITY_TRANSACTION` map entry (145–146); interface-token enforcement and dispatch are in `OnRemoteRequest`. Validates SA ID and calls `CheckGetSAPermission(systemAbilityId)` before lookup; no local `CanRequest()` in the inspected range. | Reads SA ID; `CheckSystemAbility` result is returned as `IRemoteObject`. No FD flow found. | **PARTIAL** — same build-dependent SELinux limitation as CR-0221; product caller policy and target SA reachability not verified. |
| CR-0223 / `ohscanner.interface.ipc:a89d4fbb76239732` | 1485; `GetExtensionRunningSaListInner`, lines 1458–1492 | Registered for `GET_EXTERNSION_SA_LIST_TRANSCATION` (213–214); same token gate and transaction dispatch. Checks `CanRequest()` (native AccessToken type), reads extension name, calls `GetExtensionRunningSaList`, then returns every `IRemoteObject` in the result. Unlike adjacent `GetRunningSaExtensionInfoListInner` (1494–1499), this method does not call `CheckPermission(ohos.permission.ACCESS_EXT_SYSTEM_ABILITY)` in its own body. | Extension string selects running SA list; returns result, list size and each remote object. No FD flow found. | **PARTIAL** — native-token gate is present and a neighboring extension-info operation has a named permission check, but whether this export is intentionally native-only or insufficiently restricted depends on service API contract, token provisioning, extension ownership and target product policy. This is an audit lead, not a confirmed bypass. |

## Cross-cutting source observations

- `OnRemoteRequest` enforces `SAMANAGER_INTERFACE_TOKEN` before transaction dispatch; this is protocol/interface validation, not caller authorization by itself.
- `CanRequest()` admits only `TOKEN_NATIVE`; it does not establish which native callers can reach the service or what SAs they may obtain.
- `CheckGetSAPermission` and `CheckGetRemoteSAPermission` consult SELinux service checks only under `WITH_SELINUX`; each helper returns `true` in the non-SELinux build branch. Product build flags, policy rules and SA-specific service labels are therefore essential evidence.
- The reviewed five sinks transmit `IRemoteObject` capabilities. No file-descriptor flow was found in these method bodies. The returned objects' own interfaces and authorization are outside this source file and were not inferred.
- The 5 records share one source file/family; they are not independent holdout cases. The raw scan's partial detector model remains in force.

## CLI applicability and disposition

The requested production `null_dereference` CLI is **N/A** for these rows: their original detector/rule is `ohscanner.interface.ipc` / `ipc.capability.export`, and the questioned operation is remote-object capability export. Running a different C/C++ null-dereference detector would not test the original candidate and would not close the recorded partial IPC-model obligation. No CLI result is substituted.

All five row dispositions are **PARTIAL**. No PASS is claimed because caller authorization, product build configuration and affected-SA exposure are not established; no BLOCK is needed for source review because the exact source chain and code context were available; no N/A is applied to the underlying evidence rows. Original queue status remains `not_reproduced` / `queued_not_reproduced`.

## Minimal remaining evidence and next steps

**Test/evidence line:** obtain the exact product build profile (`WITH_SELINUX`, relevant feature flags), Samgr service registration/accessibility, SELinux rules for caller SIDs and target SA IDs, and AccessToken native-token provisioning. For CR-0223, establish the API contract and intended permission gate for `GET_EXTERNSION_SA_LIST_TRANSCATION`; compare it with the adjacent permission-protected info-list transaction. Map actual caller -> transaction -> parcel fields -> SA/extension selector -> returned object's exposed methods, then run a target-derived harness under the product policy. Keep each of the five original IDs linked and preserve shared-family dependence.

**Development line:** do not tune a detector based on the sink alone. First repair/complete the IPC detector's source-file model for member-function registration, `OnRemoteRequest` token gate, guards and return-object flow; report policy-dependent cases as unknown/partial. Add a focused rule only if independent evidence demonstrates an unauthorized capability export or a sound generic missing-authorization condition, with permitted/native-token, SELinux-enabled/disabled and unrelated operation controls. The owner must separately approve any Catalog/production wiring.

## Verification

- Queue verifier: `python -m research.deliveries.cpp.a0_triage_20261019.verify_triage` — `overall_ok=true`; all 345 IDs/statuses retained and source manifests match.
- No detector, tests, fixtures, or queue source files changed; only this supplemental evidence record was added.
- Worktree base: `9d10a523f1a47f6971b35cd010b24dfe3835fc05`; lane `cpp`.
