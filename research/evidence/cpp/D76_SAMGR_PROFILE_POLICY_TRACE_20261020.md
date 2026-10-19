# D76: SAMgr profile and service permission-field trace

## Scope and provenance

This is a source-only, fixed-ref trace. It describes how the selected repositories parse their own configuration and how the shown code gates operations. It does not establish which profiles or build options a D52 product installed.

The provided manifest snapshot `openharmony-manifest-current-20261018.xml` has SHA-256 `52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55`; it pins `systemabilitymgr_samgr` to `08e2a552b839ea7727251cb9b749a5c1dd9cfeff` (line 306), `startup_init` to `e06651300f349e728c76edda806dbf6496fd620d` (line 302), and `security_access_token` to `c53a55c371d88c46b0785cc4adb444876e6a9628` (line 274). The manifest repository Git commit for this supplied XML is unavailable here; the snapshot file hash and exact project entries are recorded in the JSON evidence.

| Repository | Commit | Tree | Origin evidence |
|---|---|---|---|
| `systemabilitymgr_samgr` | `08e2a552b839ea7727251cb9b749a5c1dd9cfeff` | `b7a89e95be788f2f2372258e341f7be842c7826d` | `bundle.json` declares Gitee; exact pinned commit fetched from GitCode mirror's `refs/keep-around/08e2a...` |
| `startup_init` | `e06651300f349e728c76edda806dbf6496fd620d` | `b77ef22dfc6fa75db5f3707970db9d908a1b6302` | `https://gitcode.com/openharmony/startup_init.git` |
| `security_access_token` | `c53a55c371d88c46b0785cc4adb444876e6a9628` | `4942df10e6ed926dab1106e5752cf294305240d6` | `https://gitcode.com/openharmony/security_access_token.git` |
| D52 `miscservices_pasteboard` | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | `e374a0d61c9ec664ddd29fc17002797828c480ee` | `https://gitcode.com/openharmony/miscservices_pasteboard.git` |

Every referenced source file has its blob OID, SHA-256 and matched line excerpts in [the JSON evidence](D:/openHarmonyScanner/worktrees/d76-samgr-profile-policy-20261020/research/evidence/cpp/D76_SAMGR_PROFILE_POLICY_TRACE_20261020.json). The SAMgr component metadata declares Gitee in `bundle.json`; a direct attempt to fetch the pinned hash from that endpoint returned `not our ref`, while the GitCode mirror exposed the exact hash as a keep-around ref and yielded the matching tree. This transport detail is recorded rather than treating the local `.repo` object store as the upstream URL.

## What SAMgr calls an SA profile

In this pinned SAMgr source, `SaProfile` in `interfaces/innerkits/common/include/sa_profiles.h` has process, SA ID, library path, dependency, lifecycle and related fields; it has no `permission` or `permission_acls` member. `services/common/src/parse_util.cpp` accepts `.json` in `ParseSaProfiles`, reads `process` and `systemability`, then fills a `SaProfile` through `ParseSystemAbilityGetSaBaseInfo` and `ParseSystemAbilityGetSaExtInfo`. The latter reads a fixed set of boolean, integer, array, lifecycle and extension keys. It never reads the names `permission` or `permission_acls`. Missing optional fields keep their `SaProfile` defaults. The existing `test/resource/profile/profile.json` fixture has no such fields, and `GetSaProfiles002` asserts `ParseSaProfiles(...)` succeeds; that test source is a positive valid-profile control, though the test binary was not run for this audit.

Therefore those two keys are not SAMgr SA-profile fields in this pinned parser. If extra keys with those names are added to an otherwise valid SA JSON object, the shown parser has no path that copies them into `SaProfile` or enforces them; that is a source-level inference from the struct and explicit field reads, not a runtime test. Separately, `ParseSaProfiles` rejects non-JSON profile paths. D52's `profile/3701.xml` is XML and is built by the component's `ohos_sa_profile` target, so that XML cannot be explained as input to this SAMgr JSON parser. Another system component may process it.

## `permission` and `permission_acls` belong to init service configuration

`startup_init@e0665130` parses service configuration in `services/init/init_service_manager.c`. `GetServiceArgs` requires a nonempty JSON string array when present. `ParseOneServiceArgs` reads `permission` into `Service::permArgs` and `permission_acls` into `Service::permAclsArgs`. Service records are allocated with `calloc`; absent keys leave the corresponding arrays/counts zero. The calls from `ParseOneServiceArgs` do not propagate the missing-key return, so omission is not interpreted as a denial rule.

The positive control is the pinned SAMgr process service entry in `etc/samgr_standard.cfg`: it has nonempty `permission` and `permission_acls` arrays. Init's `GetAccessToken` forwards those lists, process name, APL and UID to `NativeTokenInfoParams` in `services/init/standard/init_service.c`; it calls `GetAccessTokenId`, stores the resulting token ID, and `SetAccessToken` calls `SetSelfTokenID`. `services/init/init_common_service.c` also calls `SetPerms` to set process UID/GID/capabilities and later sets service content/security context. These are process setup and token-construction inputs.

The corresponding AccessToken `NativeTokenInfoParams` names the fields `perms` and `acls`. `AccessTokenInfoManager::GetNativePermissionList` iterates the native token's permission states; it skips a permission when the service APL is below that permission's `availableLevel` and the permission is absent from `nativeAcls`. Otherwise it includes the permission opcode and its grant-state bit. In this pinned implementation, `permission_acls` therefore allows a native process's configured permission to be included across the APL threshold. It does not enumerate client identities allowed to invoke a System Ability. The permission names in `permission` supply the native process token's permission set; the actual grant decision still depends on the AccessToken machinery/kernel integration and platform policy.

The D52 component's `etc/init/pasteboardservice.cfg` contains neither field. That is a component source config observation only; product-side merged init configuration and corresponding init/access-token revisions are unknown. In particular, the native token configuration for the service process does not prove that an IPC caller has permission to call Pasteboard or that the read method checks that permission.

## SAMgr IPC gates and their boundary

The pinned `SystemAbilityManagerStub` performs `CheckGetSAPermission(saId)` before returning a local SA object in `GetSystemAbilityInner` and `CheckSystemAbilityInner`; `LoadSACheck` applies it before the load operation. `CheckGetSAPermission` uses `IPCSkeleton::GetCallingSid()` and `ServiceChecker::GetServiceCheck(callingSid, std::to_string(saId))` when `WITH_SELINUX` is defined. If the macro is not defined, the function returns `true` without a SELinux permission check. `services/samgr/native/BUILD.gn` defines the macro only when `build_selinux` is true. The supplied D52 product build arguments and SELinux policy are unavailable, so whether this branch was compiled or which SID-to-SA policy applied is unknown.

This is a gate on obtaining or loading an SA proxy through SAMgr. It does not mediate every later Binder transaction sent to the returned SA. The separate `SystemAbilityManagerStub::CheckPermission` uses `IPCSkeleton::GetCallingTokenID()` and `AccessTokenKit::VerifyAccessToken()` for specific SAMgr operations (for example external-transaction/system-service APIs); it is not applied as a universal gate to all `GetSystemAbility` results. The actual Pasteboard method's authorization must be established in the Pasteboard method path or the product's service-side IPC policy.

The D74 historical comparison remains version-isolated: old Pasteboard interface route `GET_PASTE_DATA` is in `miscservices_pasteboard@dd22c...`; D76's SAMgr, init and AccessToken refs are the later manifest snapshot above. The old component profile `profile/3701.xml` and init config path `/system/profile/pasteboard_service.xml` have different basenames. Its GN target packages `3701.xml`, but the D52 component tree does not include the install transform proving how that filename becomes `pasteboard_service.xml`. The pinned SAMgr parser only explains JSON SA profiles, not that XML rename. Keep profile installation mapping and product-level SAMgr/init version as unknown.

## Controls and execution status

- Positive parser control: existing SAMgr `profile.json` fixture is accepted according to `GetSaProfiles002`; it omits `permission` and `permission_acls`.
- Positive init-field control: `etc/samgr_standard.cfg` contains both nonempty arrays; parser and consumer call sites are source-traced.
- Negative D52-field control: pinned Pasteboard init cfg omits both arrays; absence is not a caller deny rule.
- Format control: D52 `profile/3701.xml` is XML while `ParseSaProfiles` only dispatches `.json`; this SAMgr parser cannot account for it.
- Runtime unit tests, device init behavior and product profile loading were not executed. The report's controls are source-bound references and parser test source, not a claim of an executed system test.

## Unresolved evidence

1. Exact D52 product manifest/build tying its image to SAMgr, startup_init and AccessToken commits/macros.
2. D52 product `build_selinux` value, SAMgr `WITH_SELINUX` build result, SELinux service contexts and policy for `pasteboard_service` SID to SA 3701.
3. D52 `ohos_sa_profile` install mapping from `profile/3701.xml` to `/system/profile/pasteboard_service.xml`, plus the final installed init/system ability profiles.
4. Runtime AccessToken and kernel permission state on the target product, including service token permissions and actual caller tokens.
5. A per-method authorization check for D52 `GET_PASTE_DATA` at its service IPC boundary; SAMgr acquisition checks alone cannot establish it.

## Suggested second-model review prompt

> Independently review the D76 JSON evidence and this report. Verify the fixed manifest lines and each repository commit/tree/blob/SHA/line. Keep SAMgr `SaProfile` JSON parsing separate from `startup_init` service cfg parsing and from AccessToken native-token construction. Confirm the `permission` and `permission_acls` data flow and the scope of `CheckGetSAPermission` (proxy acquisition/loading only, conditional on `WITH_SELINUX`). Audit the positive init cfg, negative D52 cfg, and valid SA JSON/XML format controls. Do not infer that D52 product loaded the shown configs, enabled SELinux, or had caller authorization for `GET_PASTE_DATA`; list the missing build, installation, platform policy and service-method evidence. Return confirmed facts, uncertainties, and any contradiction; make no product safety or CVE verdict.
