# CAP-01 capability surface and permission analysis, 2026-10-17

Repository: `openharmony/window_window_manager`  
Commit: `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`  
Tree: `24e60146ba2fe4af3aaef20b306a1e306df44617`

## Source-bound call path

1. `ScreenSessionManagerProxy::GetRenderSession(ScreenId)` writes the interface token and `screenId`, sends `TRANS_ID_GET_RENDER_SESSION`, then returns `reply.ReadRemoteObject()`.
2. `ScreenSessionManagerStub::OnRemoteRequestInner` validates the interface descriptor, dispatches `TRANS_ID_GET_RENDER_SESSION`, reads `screenId`, calls `GetRenderSession(screenId)` and writes the returned remote object.
3. `ScreenSessionManager::GetRenderSession` resolves the screen session and returns `ScreenSession::GetRenderSession()`.
4. `ScreenSession::GetRenderSession` returns its stored `renderSession_`, an opaque `IRemoteObject`.
5. Clients consume the object through `ScreenSessionManagerClient::GetRenderSessionToken`; `SceneSession` and `SceneSessionManager` use it to initialize RS UI/session state.

This establishes a real source path from a binder request to an opaque remote-object handoff. It does not establish that an unprivileged third-party caller can acquire the `IScreenSessionManager` proxy in a deployed product.

## Permission/identity facts

- The `TRANS_ID_GET_RENDER_SESSION` case in `screen_session_manager_stub.cpp` has no `SessionPermission` or permission call before the handoff.
- The stub-level gate visible at this boundary is interface descriptor equality.
- Nearby `ScreenSessionManager` methods use `SessionPermission::IsSystemCalling()`, `IsStartByHdcd()`, `IsShellCall()`, `VerifyCallingPermission()` and `CheckCallingPermission`.
- `SessionPermission::IsSystemCalling()` accepts:
  - native/shell token types through `IsTokenNativeOrShellType`;
  - system-app calls through `TokenIdKit::IsSystemAppByFullTokenID(GetCallingFullTokenID())`.
- The proposed minimal patch places `SessionPermission::IsSystemCalling()` immediately before `GetRenderSession(screenId)`.

Therefore the candidate is specifically: a remote object handoff path lacks the same caller-category guard that other service methods use. Whether this is a real security boundary depends on SAMGR/SELinux/API access, deployment and the actual capability surface of the returned object.

## Product build and service discovery evidence

Local product build inputs add partial deployment evidence:

- `_product_targets/build/indep_component_whitelist.json` contains `window_window_manager` and `display_manager`.
- `_product_targets/build/third_party_allow_list.json` contains `display_manager`.
- `_product_targets/manifest/ohos/ohos.xml` includes the OpenHarmony window project.
- `ScreenSessionManager` registers as `SystemAbility(DISPLAY_MANAGER_SERVICE_SA_ID, true)` through `MakeAndRegisterAbility`.
- Production/lite adapters and two project fuzzers retrieve the same SA ID through `SystemAbilityManagerClient::GetSystemAbility` or `CheckSystemAbility`, then cast it to `IScreenSessionManager`.
- Vendor `install_list_permissions.json` files under `_product_targets/vendor_hihope` contain no explicit WINDOW/SCREEN/RENDER/DISPLAY/CAPTURE permission grants in the inspected entries.

This shows the component is present in the inspected product build plan and that the service endpoint is intended for SAMGR discovery. It does not prove the final product image includes the exact blob, nor that SAMGR/SELinux permits an unprivileged third-party caller to obtain the proxy.
## Capability surface

- The returned object is typed only as `sptr<IRemoteObject>`.
- It originates from `ScreenSession::renderSession_`, configured from `SessionOption.renderSession_` and used with `RSAdapterUtil::InitRSUIDirector` / `RSUIContext`.
- The current pinned source does not expose a complete transaction list or permission model for that opaque remote object.
- Consequently confidentiality, integrity and availability effects remain `unknown`; capability exposure is a candidate consequence, not proven impact.

## Revalidation link

The isolated component replay in `validation/VALIDATION_UPDATE.md` verifies the modeled behavior:

- vulnerable: unauthorized and authorized export;
- fixed_control/patched: unauthorized denied, authorized preserved;
- wrong descriptor and unknown screen denied;
- 36/36 expected records, 0 mismatches.

## Fail-closed conclusion

Product-build plan and service-discovery evidence are now partial, but `candidate/unknown`, `validated_vulnerability=0` remains. Upgrade requires exact image artifact, deployed caller acquisition evidence, SAMGR/SELinux/API policy, the actual remote object interface/capability surface, CIA measurement and product build/release identity.
