# T78 independent acceptance — D78 conditional PengLai SAMgr gate

## Verdict

D78 passes independent acceptance with source and product-binding limits. The fixed SAMgr source supports the conditional PengLai check, allow/deny behavior, missing-checker fail-open path, and its position before SA acquisition/loading. The D78 documentation follow-up also correctly exposes the separate static initialization and stub-constructor parameter reads. No product-level inference is made.

## Frozen identity, replay, and scope

- Reviewed D78 follow-up commit: `5cc9c4c9c05ac42da280ca9d08d13cc18742028f` (based on D78 `1cea2041e0b58ababd784554e41d78c8d5b61465`), in an independent T78 worktree.
- D78 changes only the D76 Markdown evidence report, JSON evidence, and reproduction script; it changes no detector, fixture, expected output, or upstream source.
- Independently replayed `D76_samgr_profile_policy_trace.py` against the manifest and fixed repositories. Replay JSON exactly matched the committed JSON. Strict JSON parsing with duplicate-key rejection passed. `git diff --check` passed.
- Replayed refs/trees: SAMgr `08e2a552b839ea7727251cb9b749a5c1dd9cfeff` / `b7a89e95be788f2f2372258e341f7be842c7826d`; startup_init `e06651300f349e728c76edda806dbf6496fd620d` / `b77ef22dfc6fa75db5f3707970db9d908a1b6302`; AccessToken `c53a55c371d88c46b0785cc4adb444876e6a9628` / `4942df10e6ed926dab1106e5752cf294305240d6`; D52 Pasteboard `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` / `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- The replayed evidence includes 15 SAMgr source files, 4 startup_init, 5 AccessToken, and 4 D52 Pasteboard entries. Each source entry is recomputed from its pinned Git object with blob OID, SHA-256, matched line numbers, and excerpts. The manifest snapshot SHA and project-ref lines match the earlier D76/T76 review.

## PengLai gate findings

### Build macro and mode snapshot

The pinned `services/samgr/native/BUILD.gn` defines `SUPPORT_PENGLAI_MODE` only inside `if (support_penglai_mode)`. With the option false, the guarded PengLai state and checks compile out. The product's GN argument is unavailable.

When compiled in, `SystemAbilityManagerStub` construction calls `SetPengLai(SamgrUtil::CheckPengLai())`. `CheckPengLai` reads `ohos.boot.minisys.mode`, defaults a missing value to the empty string, and compares against the exact `penglai` value. This constructor snapshot controls `isPengLai_` for that stub instance.

The follow-up properly records a second read: `SamgrUtil::penglaiFunc_` is initialized by static dynamic initialization through `InitPenglaiFunc()`, which independently reads `CheckPengLai()` before attempting to load the PengLai library. The constructor later reads the parameter again. The pinned source establishes neither that these two reads are aligned nor that the parameter cannot change. If the function pointer is null while `isPengLai_` is true, the guard is entered but `CheckPengLaiPermission` returns true. If `isPengLai_` is false, the call-site condition bypasses the check even if the function pointer loaded. D78 now accurately marks this as a source-level timing/mutability uncertainty and limits its truth table to stable, aligned snapshots.

### Checker behavior and acquisition boundaries

`InitPenglaiFunc` returns null when the parameter read is not PengLai, `dlopen` fails, or `dlsym` cannot find `IsLaunchAllowedByUid`. `CheckPengLaiPermission` returns true for a null pointer. With a resolved function, it calls `IsLaunchAllowedByUid(callingUid, saId)`; false propagates as denial at the checked handlers. This is fail-open behavior of this particular pinned SAMgr gate, not a claim about other enforcement.

The three highlighted handlers are correctly traced:

- `GetSystemAbilityInner`: denial precedes `GetSystemAbility` and `WriteRemoteObject`.
- `CheckSystemAbilityInner`: denial precedes resolving and returning its remote object.
- `LoadSACheck`: denial precedes the load path continuing.

The pinned source also has related guarded variants. These checks happen in SAMgr acquisition/loading handlers; they do not run again for later Binder method calls on an already returned `IRemoteObject`. Any Pasteboard method-level authorization remains a separate question.

### Controls and execution limits

The structured controls cover macro disabled, macro enabled with runtime mode false, resolved checker allow/deny, missing library/symbol fail-open, separate parameter snapshots, unit-test source controls, and returned-object boundary. The SAMgr unit tests inspected include injected checker allow/deny expectations for the relevant handlers, but no test binary was built or run. The dynamic PengLai library was not executed. These are source-traced conditions, not observed device behavior.

## Prior conclusions and D52 limits

D78 preserves D76/T76 findings: `permission` and `permission_acls` configure the service's native token through init/AccessToken; they do not establish caller permission for Pasteboard Binder methods. SAMgr SELinux and PengLai checks gate specified SA acquisition/loading operations, not every later service transaction. D52 `profile/3701.xml` has no such fields, while its component init config names `/system/profile/pasteboard_service.xml`; the install-time mapping remains unresolved. D78 does not bind the later SAMgr source or its `support_penglai_mode`, runtime parameter, PengLai library/policy, or SELinux configuration to a D52 product.

## Assessment

- `fix-correctness`: PASS — source identities, lines, and behavior summaries agree; the independent static-initializer caveat was added and is accurate.
- `candidate-retention`: PASS — D52's bounded source observation remains separate from generic and later framework behavior.
- `coverage`: PASS WITH LIMITATIONS — build/mode/allow/deny/null-pointer controls and all three acquisition gates are covered; no runtime build/device execution was performed.
- `scope`: PASS — D78 remains source evidence only and does not claim D52 product applicability or safety.

## Remaining evidence

D52-specific conclusions need the exact product manifest and build args, including `support_penglai_mode` and `build_selinux`; the parameter lifecycle/value and loaded PengLai library/policy on that product; final installed SA/init profiles and the XML-to-installed-name mapping; applicable SELinux policy; and the actual Pasteboard service-method authorization path. Until then, D52 product applicability and authorization remain unknown.
