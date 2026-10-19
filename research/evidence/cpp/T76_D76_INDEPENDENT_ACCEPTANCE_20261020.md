# T76 independent acceptance — D76 SAMgr/init/AccessToken trace

## Verdict

D76 is accepted with limitations. Independent source replay and focused source checks found no actionable mismatch in the manifest references, parser/data-flow claims, SELinux acquisition gate, D52 profile controls, or report boundary. This is a source-only framework trace. It does not establish any D52 product's installed configuration, compiled options, runtime token state, or security posture.

## Frozen identity and scope

- Frozen D76 commit: `88b357fa0f7d4906e3baff9392c6b27126c88d40`; the reviewed commit adds only the D76 Markdown report, JSON evidence, and replay script.
- The provided manifest snapshot `openharmony-manifest-current-20261018.xml` has SHA-256 `52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55`. Lines 274, 302, and 306 pin `security_access_token@c53a55c371d88c46b0785cc4adb444876e6a9628`, `startup_init@e06651300f349e728c76edda806dbf6496fd620d`, and `systemabilitymgr_samgr@08e2a552b839ea7727251cb9b749a5c1dd9cfeff` respectively. The manifest snapshot has no available Git commit in this workspace; D76 records that limitation.
- Source refs and trees replayed as recorded: SAMgr `b7a89e95be788f2f2372258e341f7be842c7826d`; startup_init `b77ef22dfc6fa75db5f3707970db9d908a1b6302`; AccessToken `4942df10e6ed926dab1106e5752cf294305240d6`; D52 Pasteboard `e374a0d61c9ec664ddd29fc17002797828c480ee`.

## Independent replay and source check

Re-ran `D76_samgr_profile_policy_trace.py` against the four pinned source checkouts and manifest snapshot. The replay JSON was structurally identical to committed D76 JSON. It contains 9 SAMgr, 4 startup_init, 5 AccessToken, and 4 D52 Pasteboard evidence entries; every entry has line hits, blob OID, and SHA-256 generated from the pinned Git object. Actual checkout origins and HEAD identities matched the recorded source refs. The manifest hash matched independently.

### SAMgr profile schema

In the pinned SAMgr tree, `SaProfile` does not define `permission` or `permission_acls`. `ParseSaProfiles` accepts JSON profiles and the base/extension readers enumerate the fields copied into `SaProfile`; the parser does not copy or enforce those two keys. The fixture `test/resource/profile/profile.json` omits them, and `GetSaProfiles002` uses the fixture as a successful parse control. That unit test source was inspected; the test binary was not run. D76 correctly presents unknown-key handling as a source-code inference, not a runtime result. The D52 `3701.xml` is XML and is not input to this pinned `.json` SAMgr parser; this does not establish which other platform component installs or consumes it.

### Init service config and native service token

In pinned `startup_init`, `ParseOneServiceArgs` requests `permission` and `permission_acls` via `GetServiceArgs`, storing them in `Service::permArgs` and `Service::permAclsArgs`. A present value must be a nonempty string array within the configured count limit. Service allocation is zero-initialized, and the parser does not propagate the missing-key return from these optional calls; for an absent field the arrays/counts remain at their initialized empty values. This is an omission/default observation, not a deny rule.

The positive control `etc/samgr_standard.cfg` contains nonempty arrays for both keys. Init passes the two lists, service name, APL, UID and capabilities into `NativeTokenInfoParams`, obtains the native token with `GetAccessTokenId`, and later calls `SetSelfTokenID`. In the pinned AccessToken source, `GetNativePermissionList` iterates the token's configured permission states and skips a permission when the native APL is below that permission's available level and the permission is absent from `nativeAcls`; otherwise it records its opcode and grant-state bit. This is service native-token construction. The ACL list affects inclusion of configured permissions across the APL threshold; it is not a list of client identities permitted to call a service. Actual token/grant behavior still depends on the AccessToken/kernel/platform setup.

### SAMgr caller and local controls

The pinned SAMgr `CheckGetSAPermission` uses the IPC caller SID and `ServiceChecker::GetServiceCheck(callingSid, SA ID)` only under `WITH_SELINUX`; without the macro it returns true. `services/samgr/native/BUILD.gn` defines `WITH_SELINUX` only when `build_selinux` is true. Calls are visible in get/check/load SA paths, so this is an acquisition/loading gate for SAMgr operations. It is not a per-method guard on later Binder calls to the returned Pasteboard object. The separate token-based `CheckPermission` is used by specific SAMgr operations and is not shown as a universal gate for `GetSystemAbility` results. No product build args, final SELinux policy, or D52 runtime were available.

### D52 profile and init mapping

The pinned D52 `profile/3701.xml` declares process, SA name `3701`, library, and `distributed=false`, with no `permission` or `permission_acls` field. Its `profile/BUILD.gn` names `3701.xml` as a profile source. The component's `etc/init/pasteboardservice.cfg` names `/system/profile/pasteboard_service.xml` and contains neither init permission array. The source component tree does not provide the install transform mapping `3701.xml` to `pasteboard_service.xml`, nor the final installed profile. The generic SAMgr/init/AccessToken refs are from a later manifest snapshot and are not bound to the old D52 product. D76 keeps these as separate facts and does not infer a historical product policy from them.

## Assessment

- `fix-correctness`: PASS — the source assertions and line/hash evidence match the pinned refs checked.
- `candidate-retention`: PASS — D76 preserves the bounded D52 missing-local-check observation and does not infer that a service token ACL authorizes callers.
- `coverage`: PASS WITH LIMITATIONS — positive, negative, omission, format, and acquisition-gate controls are present; no runtime test was executed.
- `scope`: PASS — source identities, chronology, and product-binding gaps remain explicit; no product security verdict is made.

## Downstream prompt boundary and remaining evidence

The suggested prompt requires separate treatment of SAMgr profile parsing, init service configuration, and AccessToken native-token construction; asks to verify the conditional proxy acquisition/loading gate; and prohibits claims that D52 loaded these configs, enabled SELinux, or authorized `GET_PASTE_DATA`. This boundary is appropriate.

A product-level conclusion still needs the exact D52 product manifest/build and `build_selinux` value, final installed SA/init profiles and XML-to-installed-name mapping, applicable SELinux service policy, matching platform AccessToken/kernel behavior, and an authorization check or policy at the D52 Pasteboard method boundary.
