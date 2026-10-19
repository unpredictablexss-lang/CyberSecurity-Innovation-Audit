# D77 adversarial review: D52 Pasteboard read path and external gates

## Verdict

**Retain the D52 candidate as narrow source-only evidence.** At `openharmony/miscservices_pasteboard@dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, the traced `GET_PASTE_DATA` route reaches the core's caller-user-scoped clip lookup/copy without a visible in-component caller read-permission predicate. No source-only finding in this review establishes a product bypass, system-wide absence of authorization, product applicability, or CVE causality.

The adversarial review found two boundary details to preserve:

1. The core maps the IPC caller UID to an OS account and selects that account's clip (`services/core/src/pasteboard_service.cpp:155-171, 211-216`). This is a real caller-identity partition and invalid-user failure control; it is not a permission predicate. Do not describe the path as “unrestricted” or imply cross-user reads.
2. The fixed SAMgr source also has `SUPPORT_PENGLAI_MODE` checks on SA retrieval/loading (`system_ability_manager_stub.cpp:650-653, 688-691, 780-783`), in addition to the conditional `WITH_SELINUX` `CheckGetSAPermission` branch. D76's SELinux-centered summary does not enumerate this alternative acquisition gate. Its product applicability remains unknown and it still is not a per-method Pasteboard authorization check.

These refinements do not overturn D74/T74, D75, or T76's central boundary: an external/product gate may affect whether the caller can obtain/load the SA, but the checked-in component source alone cannot establish effective product authorization.

## Frozen input identities

| Evidence | Commit | Identity / scope |
|---|---|---|
| D74 | `a29275f7a795da17171fd3df2c712ef3a8576cb7` | Historical D52 and separately pinned current Pasteboard source trace |
| T74 | `fb45fcc4d61d1ce3a56eff8386b83f9f3a652ec7` | Independent D74 acceptance with profile/install/policy limitations |
| D75 | `f3171a784c0e256c5d879ace3aeb78d6acfaf121` | Second-layer semantic review; retain narrow source-only candidate |
| D76 | `88b357fa0f7d4906e3baff9392c6b27126c88d40` | SAMgr/init/AccessToken source trace |
| T76 | `968ea9852bab858a8eab35ccdd6c4fcc45281cca` | Independent D76 acceptance with limitations |
| D52 source | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | `miscservices_pasteboard`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee` |
| SAMgr source | `08e2a552b839ea7727251cb9b749a5c1dd9cfeff` | `systemabilitymgr_samgr`, tree `b7a89e95be788f2f2372258e341f7be842c7826d` |
| D76 init source | `e06651300f349e728c76edda806dbf6496fd620d` | `startup_init`, tree `b77ef22dfc6fa75db5f3707970db9d908a1b6302` |
| D76 token source | `c53a55c371d88c46b0785cc4adb444876e6a9628` | `security_access_token`, tree `4942df10e6ed926dab1106e5752cf294305240d6` |

The replay output contains blob OIDs and SHA-256 for all 12 D52 files checked, plus the SAMgr stub and build file. D52 stub identity is blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`; core identity is blob `c380ac266a85edd818caa811f11b99722d351788`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`. SAMgr stub identity is blob `ae84d998c4d90c8c08d692b9020404593b58a0cc`, SHA-256 `e82aa966b6c70278c64683b3bc4c0b236cf7550da3e65aeafc12acfa5f718433`.

## Adversarial probes and controls

### D52 GET_PASTE_DATA route

- Positive route control: interface enum sets `GET_PASTE_DATA = 0` (`i_pasteboard_service.h:27-38`); stub constructor maps it to `OnGetPasteData` (`pasteboard_service_stub.cpp:25-30`); the method calls `GetPasteData(pasteData)` and serializes the result (`:73-85`). Proxy `SendRequest(GET_PASTE_DATA, ...)`, framework client, and NAPI call sites are independently pinned in D74.
- Negative transport/identity controls: a descriptor mismatch falls through to the base stub (`pasteboard_service_stub.cpp:43-47`); an unmapped user ID returns false (`pasteboard_service.cpp:211-217`); absent user clip returns false (`:165-175`). These are interface, account-mapping, and data-absence controls; none is a caller permission decision.
- Core identity scope: `GetPasteData` calls `GetUserId`, then finds `clips_[userId]` and copies that clip (`pasteboard_service.cpp:155-176`). `GetUserId` uses `IPCSkeleton::GetCallingUid()` and `OsAccountManager::GetOsAccountLocalIdFromUid` (`:211-216`). This may separate accounts, but does not check a permission grant or app entitlement.
- Whole-tree helper probe: exact-revision `git grep` finds only the `CheckSelfPermission` / `CheckCallingPermission` declarations and definitions plus the helper's delegation to `MockPermission::VerifyPermission`; no GET route call site is present. `CheckSelfPermission` and the mock return `true` (helper blob `5e7bf43287374eb21a8200400cbe350e8d234368`; mock blob `d4528b45a88c695c0381ed30d65fa551529c2f92`). These facts do not create a reachable guard or prove a bypass.
- Candidate anchor: stub line 41 is the opening brace of `OnRemoteRequest`, not a check, data access, or proven vulnerable operation.

### SAMgr / init interpretation

- In the fixed SAMgr stub, `CheckGetSAPermission` uses caller SID and `ServiceChecker::GetServiceCheck` only under `WITH_SELINUX`; otherwise the function returns true (`system_ability_manager_stub.cpp:47-59`). The fixed build file ties that define to `build_selinux` as D76 records.
- `GetSystemAbilityInner`, `CheckSystemAbilityInner`, and load routes contain this check, but SA retrieval also contains conditional `SUPPORT_PENGLAI_MODE` checks; e.g. get at `:650-653`, check at `:688-691`, load at `:780-783`. These branches are a counterexample to treating the SELinux branch as the only possible SAMgr acquisition gate. The reviewed code does not bind either macro or policy to a D52 product.
- `CheckPermission` is used at specific SAMgr operations (`:1421, 1496, 1573, 1842`); it is not shown as a universal filter on every later transaction to every returned SA object. Neither this nor the Penglai/SELinux acquisition checks proves whether D52 `GET_PASTE_DATA` was effectively authorized on a device.
- D76/T76's separation of SAMgr SA JSON profile parsing, init service config fields, and native service-token construction remains valid. The D52 profile/install mapping, product revisions/flags, effective policy, and method-level/runtime authorization remain unresolved.

## Conclusion and status

- **Retain:** one narrow source observation: no visible in-component caller read-permission predicate before the D52 user-scoped data lookup/copy.
- **Do not promote:** there is no minimal product-level unauthorized/authorized caller reproduction because product identity and its installed policy are absent. No vulnerability/CVE candidate is confirmed by this review.
- **Unknown:** whether any target image contains the D52 source and matching platform refs; which profile is installed; whether SELinux/Penglai mode is enabled; effective SA/Binder/AccessToken policy; caller reachability and runtime result.
- **Minimum additional evidence:** exact product fingerprint and manifest/build provenance; installed SA/init profile plus rename/install mapping; build flags for `WITH_SELINUX` and `SUPPORT_PENGLAI_MODE`; effective policy for SA 3701; any service-side/generated Binder authorization glue; and authorized/unauthorized caller tests on that image.

## Replay

`D77_pasteboard_adversarial_replay.py` re-reads the pinned Git objects, checks D52/SAMgr trees and source file blob/SHA identities, extracts route/control excerpts, and reruns whole-tree permission-helper and SAMgr gate searches. Prepare bare Git dirs with the exact commits, then run:

```powershell
python research/evidence/cpp/D77_pasteboard_adversarial_replay.py `
  --d52-git-dir <path-to-miscservices_pasteboard.git> `
  --samgr-git-dir <path-to-systemabilitymgr_samgr.git> `
  --output research/evidence/cpp/D77_PASTEBOARD_ADVERSARIAL_20261020.json
```

For this frozen run, the D52 exact commit was fetched from the recorded GitCode remote into a temporary bare Git dir; the SAMgr object came from the local OpenHarmony manifest checkout. Both expected tree IDs matched. The temporary clone is excluded from the committed worktree; no product binary or runtime test was executed.
