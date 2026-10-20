# T30 independent Samgr IPC audit — CR-0219–CR-0226

Date: 2026-10-20
Role: independent test/evidence line
Acceptance checkout: `3aa6acc13ab7f39b0ebaee092a3e3e5b9b83bfa2`
Source: `openharmony/systemabilitymgr_samgr`, commit `08e2a552b839ea7727251cb9b749a5c1dd9cfeff`

## Identity and independent replay

The pinned source commit resolves to tree `b7a89e95be788f2f2372258e341f7be842c7826d`; `services/samgr/native/source/system_ability_manager_stub.cpp` resolves to blob `ae84d998c4d90c8c08d692b9020404593b58a0cc`, 78,212 bytes, SHA-256 `e82aa966b6c70278c64683b3bc4c0b236cf7550da3e65aeafc12acfa5f718433`. The commit/tree/blob/hash chain was verified directly against the local Git project-object mirror and matches every queue row.

I independently ran the current production CLI (not a development-line report):

```powershell
python -m src.cli ohscan-run --repo-dir <pinned-samgr-checkout> --repository openharmony/systemabilitymgr_samgr --commit 08e2a552b839ea7727251cb9b749a5c1dd9cfeff --detector ohscanner.interface.ipc --include services/samgr/native/source/system_ability_manager_stub.cpp --json-out research/evidence/cpp/a_t30_samgr_cli_20261020.json --md-out research/evidence/cpp/a_t30_samgr_cli_20261020.md
```

The explicit scope selected exactly one source file (78,212 bytes). Parsing reported `partial: 1`; IPC detector coverage was `complete: 0, partial: 1, not_analyzed: 0, failed: 0`. The CLI emitted ten diagnostics total. Eight match the original A0 IPC capability-export rows at lines 464, 551, 668, 706, 1485, 1692, 1735, and 1784. The two descriptor-boundary diagnostics at lines 298 and 302 are outside this queue family and are not treated as matches for these IDs. The result is useful as candidate evidence only; because the target source file remains partial, it cannot establish a complete analysis.

## Per-ID current result and source-flow context

All eight original candidate IDs, locations and source hashes are unchanged. Current CLI finding IDs differ from the original A0 candidate IDs; the verifier binds each by immutable path, line, rule, and source hash.

| Queue ID | Transaction / method and source-local flow | Current CLI candidate | Audit disposition |
|---|---|---|---|
| CR-0219 | Code `CHECK_REMOTE_SYSTEM_ABILITY_TRANSACTION` (map lines 155–156), `CheckRemtSystemAbilityInner` 422–470. Reads SA/device IDs, checks native-token `CanRequest`, validates SA ID, calls `CheckGetRemoteSAPermission`, resolves service and returns `IRemoteObject`. | `ipc.capability.export`, line 464 | PARTIAL; product caller/policy and selected SA/device exposure unknown. |
| CR-0220 | Code `CHECK_SYSTEM_ABILITY_IMMEDIATELY_TRANSACTION` (159–160), `CheckSystemAbilityImmeInner` 512–565. Checks native-token type, SA ID, then `CheckGetSAPermission`; reads `isExist`, returns remote object and bool. | `ipc.capability.export`, line 551 | PARTIAL; product token/caller policy, SELinux configuration and SA exposure unknown. |
| CR-0221 | Code `GET_SYSTEM_ABILITY_TRANSACTION` (143–144), `GetSystemAbilityInner` 638–674. Validates SA ID and calls `CheckGetSAPermission`; no local `CanRequest` check in this method; returns remote object. | `ipc.capability.export`, line 668 | PARTIAL; product build and effective caller SID rules unknown. |
| CR-0222 | Code `CHECK_SYSTEM_ABILITY_TRANSACTION` (145–146), `CheckSystemAbilityInner` 676–712. Validates SA ID and calls `CheckGetSAPermission`; no local `CanRequest` check in this method; returns remote object. | `ipc.capability.export`, line 706 | PARTIAL; product build, policy and selected SA exposure unknown. |
| CR-0223 | Code `GET_EXTERNSION_SA_LIST_TRANSCATION` (213–214), `GetExtensionRunningSaListInner` 1458–1492. Native-token gate; reads extension string; returns each matching remote object. Neighboring extension-info operation has a named permission call absent here, but that difference alone does not prove bypass. | `ipc.capability.export`, line 1485 | PARTIAL; API contract, native-token provisioning and intended extension policy unknown. |
| CR-0224 | Under `SUPPORT_MULTI_INSTANCE`, code 45, `GetSystemAbilityWithUserIdInner` 1656–1695. SA ID validation, optional PengLai gate, then `CheckGetSAPermission` before reading user ID/lookup; manager checks caller `BASE_USER`, valid target user and manager existence; returns remote object. | `ipc.capability.export`, line 1692 | PARTIAL; build flags, caller identity mapping, policy and returned SA exposure unknown. |
| CR-0225 | Under `SUPPORT_MULTI_INSTANCE`, code 46, `CheckSystemAbilityWithUserIdInner` 1699–1738. Same SA/PengLai/SELinux checks before user ID lookup; manager checks `BASE_USER`, target user and manager; returns remote object. | `ipc.capability.export`, line 1735 | PARTIAL; same product-bound authorization and impact gaps; distinct transaction path. |
| CR-0226 | Under `SUPPORT_MULTI_INSTANCE`, code 47, `CheckSystemAbilityByUserIdInner` 1742–1793. Checks SA/PengLai/SELinux; then reads caller bool and user ID; manager initializes `isExist=false`, checks `BASE_USER`, user validity/manager; returns remote object and bool. | `ipc.capability.export`, line 1784 | PARTIAL; caller-controlled bool is not by itself an authorization bypass; product-bound gaps remain. |

`OnRemoteRequest` checks the `SAMANAGER_INTERFACE_TOKEN` and dispatches registered transaction codes (lines 293–309). This establishes interface/protocol validation, not caller authorization. `CanRequest()` is a native-token-type gate, not proof of which native callers reach the service. `CheckGetSAPermission` and `CheckGetRemoteSAPermission` invoke `ServiceChecker` only with `WITH_SELINUX`; the source's non-SELinux branch returns true. Product build flags, effective SELinux policy and caller SID mapping are therefore required. The reviewed paths export `IRemoteObject` capabilities; no FD read/write path was found in these methods. Permissions and impact of the returned objects' own interfaces are not established.

## Status, limitations, and next evidence

The eight records share one source file/family; they are not independent holdout cases. All remain `PARTIAL`; the original queue states remain exactly `not_reproduced / queued_not_reproduced`. A current CLI candidate is not a confirmed vulnerability, and partial parsing plus missing target context means neither positive nor zero static results settle product security.

Still missing: (1) exact product build/profile and Samgr service registration, including `WITH_SELINUX`, `SUPPORT_MULTI_INSTANCE`, `SUPPORT_PENGLAI_MODE`; (2) effective SELinux rules and caller SID/UID/native-token/user mapping; (3) actual external caller reachability and selected SA/extension exposure; (4) target-derived IPC tests with authorized and unauthorized principals and representative valid/invalid parcel values; (5) authorization and impact review for returned remote-object interfaces. No repaired source counterpart is identified for these queue cases, so this audit does not claim fixed-version regression.

## Verification artifacts

Machine evidence: [JSON audit](a_t30_samgr_ipc_audit_20261020.json). Re-run its consistency checks with `python research/evidence/cpp/verify_t30_samgr_ipc_audit.py`; then run the A0 triage verifier and `scripts/check_change_scope.py --base 3aa6acc13ab7f39b0ebaee092a3e3e5b9b83bfa2 --lane cpp`.
