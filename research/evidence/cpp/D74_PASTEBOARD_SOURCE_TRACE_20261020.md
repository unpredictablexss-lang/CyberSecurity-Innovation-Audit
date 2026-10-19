# D74 pasteboard source trace

## Scope and method

This is a read-only source trace, not a product security assessment. It compares the exact D52 historical source snapshot with a separately pinned current repository snapshot. The current implementation is not evidence about the historical implementation.

| Label | Repository | Commit | Tree | Remote |
|---|---|---|---|---|
| D52 historical | `openharmony/miscservices_pasteboard` | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | `e374a0d61c9ec664ddd29fc17002797828c480ee` | `https://gitcode.com/openharmony/miscservices_pasteboard.git` |
| Current snapshot | `openharmony/distributeddatamgr_pasteboard` | `e73747b227104e6743e957ce31040edf58507221` | `4128cdf9ad11d393c30f2839f43419e97a5a466d` | `https://gitcode.com/openharmony/distributeddatamgr_pasteboard.git` |

The accompanying JSON records each source path, Git blob OID, SHA-256, and matched source lines. Line numbers below are from those pinned trees.

## D52 historical route

The old interface assigns `GET_PASTE_DATA = 0` and declares `GetPasteData(PasteData&)` in `services/core/include/i_pasteboard_service.h:27-38` (blob `1a5b83f314d6188f0b3465a13ac1668cb9933839`, SHA-256 `ffef3626d4dcd2d0757381e64e652a8a023d352dd59bc9afa20deafb2fd8e3fc`). The framework client calls its proxy from `framework/innerkits/src/pasteboard_client.cpp:113-126`; the proxy sends `GET_PASTE_DATA` in `services/zidl/src/pasteboard_service_proxy.cpp:147-156`. The stub registers that code to `OnGetPasteData` in `services/zidl/src/pasteboard_service_stub.cpp:25-30`, validates the interface token, obtains/logs calling PID and UID at `:39-57`, and calls `GetPasteData(pasteData)` at `:73-78`. The concrete SystemAbility registers and starts in `services/core/src/pasteboard_service.cpp:38,68`; its `GetPasteData` implementation begins at `:155` and proceeds into user/data lookup and copying. The NAPI entry calls the framework client at `interfaces/kits/napi/src/napi_pasteboard.cpp:630,671-674`.

Within this traced old repository path, no explicit read-permission predicate is visible in the NAPI entry, client, proxy, dispatch stub, or concrete `GetPasteData` route before the data lookup/copy. The stub's PID/UID retrieval is logging/identity observation in the shown code, not an authorization decision. Repository search found the `PasteboardPermission::CheckSelfPermission` and `CheckCallingPermission` helper definitions in `utils/native/src/pasteboard_permission.cpp:47-72`, but no call site from the traced route; notably `CheckSelfPermission` returns `true` directly at `:47-50` in this snapshot. This is a bounded source observation, not proof that no external platform policy applied.

The old repository contains `profile/3701.xml`, packaged by `profile/BUILD.gn` as a System Ability profile, and `etc/init/pasteboardservice.cfg`. The profile declares SA name `3701`, library `libpasteboard_service.z.so`, and `distributed=false`; it does not declare a caller permission/ACL. The init config points to `/system/profile/pasteboard_service.xml`, while the source package filename is `3701.xml`; the installed product's rename/packaging and any additional System Ability Manager policy are not resolved by this component checkout. Thus the checked-in SA profile itself shows no caller ACL, but platform enforcement outside this repository remains an evidence gap. No complete platform permission manager, product manifest, SELinux policy, or built image was included in this trace.

## Current repository route and permission check (separate version)

The current IDL declares `GetPasteData` as IPC code 200 in `services/IPasteboardService.idl:23,50`; `services/BUILD.gn` generates the interface from that IDL. Generated dispatcher/proxy code is build output and is not checked in, so the exact generated hook-to-method glue is not independently line-traced here. The framework NAPI `GetPasteData` calls `PasteboardClient::GetPasteData` at `interfaces/kits/napi/src/napi_systempasteboard.cpp:434-467`; the client calls the proxy at `framework/innerkits/src/pasteboard_client.cpp:289-312`, and `PasteboardServiceLoader` obtains/loads the System Ability at `framework/innerkits/src/pasteboard_service_loader.cpp:110-120`.

In current `services/core/src/pasteboard_service.cpp`, `PasteboardService::GetPasteData` at `:1316` calls `GetPasteDataInner` at `:1322`. `GetPasteDataInner` obtains the caller token via `IPCSkeleton::GetCallingTokenID()` (around `:1351-1354`), then tests `VerifyPermission(tokenId)` before the `GetData(...)` call at `:1371`; failure returns `PasteboardError::PERMISSION_VERIFICATION_ERROR` at `:1358-1364`. This is a service-side gate based on the IPC caller token, not a permission value supplied by the framework client.

`VerifyPermission` is defined at `:1020-1052`. It checks `ohos.permission.READ_PASTEBOARD` and `ohos.permission.SECURE_PASTE` via `PermissionUtils::IsPermissionGranted` at `:1029-1030`; either grant passes at `:1032`. The function also allows native/shell token types and the Ctrl+V action path (around `:1033-1048`). When none grants access, SDK version 12 or later is denied at `:1048-1050`; earlier SDK versions fall through to `true` at `:1051-1052` for compatibility. In addition, `GetPasteDataInner` permits a developer-mode test-server exception (`:1356-1358`). Thus this source check has explicit conditional exceptions and does not by itself prove every call is denied absent the named permission.

The class implements `SystemAbility` and its stub in `services/core/include/pasteboard_service.h:125-137`; registration and `Publish(this)` are in current `services/core/src/pasteboard_service.cpp:141-159,199`. `CallbackEnter` rejects non-local calls at `:5536-5541`, a transport locality condition distinct from the read permission gate. Current `etc/init/pasteboardservice.cfg:2-17` points to external `/system/profile/pasteboard_service.json` and lists service-held permissions/permission ACLs; that JSON is not in this checkout. Those service permissions do not establish an external caller ACL in the missing profile. `PermissionUtils`/AccessTokenKit implementation and the generated IPC hooks are also outside this component snapshot.

## Cross-version conclusion and unresolved evidence

The pinned D52 source route has no visible in-component read-permission check before its core read, while the separate current snapshot contains a service-side caller-token check before `GetData`. This establishes a source difference only. It does not establish that D52 lacked all higher-level System Ability Manager or operating-system access control, because the historical external SA profile and platform enforcement sources are missing. Nor does the current check establish how a particular released product was built or which repository snapshot it contains.

Open dependencies for a stronger cross-layer determination:

1. Historical installed `/system/profile/pasteboard_service.xml` and current `/system/profile/pasteboard_service.json`, with System Ability Manager enforcement source/config for the corresponding product builds.
2. Platform AccessTokenKit/PermissionUtils implementation and policy declarations for the named current permissions.
3. Generated IDL stub/proxy/hook sources and the build configuration for the exact product revision.
4. Product manifest/build provenance tying a product image to either pinned component commit.

No product applicability, exploitability, CVE causality, or complete authorization conclusion is made here.

## Suggested downstream second-model prompt

> Review `D74_PASTEBOARD_SOURCE_TRACE_20261020.json` and this report as bounded static evidence. Keep `miscservices_pasteboard@dd22c7cb5e5f207a6c38c50f45b7369ee8575840` strictly separate from `distributeddatamgr_pasteboard@e73747b227104e6743e957ce31040edf58507221`. Independently verify the GET_PASTE_DATA call chain and each cited blob/hash/line. Determine only whether the pinned historical component source shows an explicit caller authorization check before its data read. Treat missing external System Ability profile, platform ACL/AccessTokenKit sources, generated IPC glue, and product-build mapping as unresolved evidence; do not infer their behavior. Use the current source only to describe a later implementation difference, including its exceptions. Return confirmed claims, contradicted claims, missing evidence, and the minimum next artifacts required. Do not make a product safety or CVE-causality verdict.
