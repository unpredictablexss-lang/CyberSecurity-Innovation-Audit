# T48: multimedia camera callback IPC candidates CR-0291–CR-0299

## Scope and replay

The frozen A0 queue binds CR-0291–CR-0299 to `openharmony/multimedia_camera_framework` commit `35445b57d739a41cb916330935e61f1e83d982ca`, tree `2907d1748b46897c49c8f8c253c49384294a6a7a`. Exact blob IDs, SHA-256 values, line text, original candidate IDs and queue states are recorded per row in [the machine audit](t48_camera_callback_audit_20261027.json). CR-0300 is `openharmony/developtools_hapsigner` and a `shared_ptr_race` candidate, so it is not part of this camera IPC audit; its frozen A0 state is untouched.

The current production CLI was run with `ohscanner.interface.ipc` 0.12.12 on four exact files: the photo callback Stub, thumbnail callback Stub, window-manager callback Stub and `hcamera_service.cpp`. The CLI emitted 9 diagnostics matching all 9 camera A0 positions. Parser coverage is 3 complete files and 1 partial file; `hcamera_service.cpp` is partial (`detector_model_incomplete`). The run used `light-ast`, build profile `none`, and completed with limitations. Raw JSON is in [the CLI record](t48_camera_cli_20261027.json).

Reproduce from this checkout, substituting the path to the full local camera-framework Git object mirror:

```powershell
python -m src.cli ohscan-run `
  --repo-dir <camera-framework-git-mirror> `
  --repository openharmony/multimedia_camera_framework `
  --commit 35445b57d739a41cb916330935e61f1e83d982ca `
  --include services/camera_service/binder/server/src/hstream_capture_photo_callback_stub.cpp `
  --include services/camera_service/binder/server/src/hstream_capture_thumbnail_callback_stub.cpp `
  --include services/camera_service/binder/server/src/window_manager_service_callback_stub_impl/hcamera_window_manager_callback_stub.cpp `
  --include services/camera_service/src/hcamera_service.cpp `
  --detector ohscanner.interface.ipc `
  --json-out research/evidence/cpp/t48_camera_cli_20261027.json
```

## Source review

The three callback dispatchers read the IPC interface token and call `CHECK_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode)` before entering the transaction switch. The photo and thumbnail callback proxy implementations write `GetDescriptor()` to their parcel before `SendRequest`. The window-manager callback is typed as an `IRemoteStub<IWindowManagerAgent>` and is registered through `CameraWindowManagerClient` as a camera-window agent. These source-level checks conflict with the detector's “missing descriptor guard” explanation. The macro definition/expansion is not present in this component snapshot, so this audit does not claim the check's compiled semantics or a confirmed bypass.

For CR-0298/0299, the modeled `CreateCameraDevice` path is in the same source file. Source visibly checks `OHOS_PERMISSION_CAMERA` through `CheckPermission`, guards foreground state, then treats `OHOS_PERMISSION_CAMERA_SHARED` as a separate privilege predicate. This conflicts with treating the reported branch as unauthenticated by itself. Since the file is parser partial, the effective control-flow model cannot be fully validated. No product authorization policy, configured permission grant, external caller reachability or runtime transaction was checked.

GN files bind the photo and thumbnail callback Stub sources into `camera_framework` shared/static source sets. `camera_service/BUILD.gn` declares an install-enabled shared library containing `hcamera_service.cpp` and the window-manager callback Stub. This establishes repository build intent only; no product build/profile or package inclusion was verified.

## Disposition

**PARTIAL/BLOCK for all nine rows.** The IPC candidates are static syntax evidence and source review reveals descriptor guards; the auth candidates have visible permission and foreground checks that the partial path model does not account for. No trusted fixed source was established, so there is no fixed differential. Do not treat a matched candidate as a confirmed vulnerability, and do not treat source guards or parser partiality as a product-level safety result. All original A0 `not_testable / paused_pending_evidence` states remain unchanged.

The T48 verifier checks the frozen A0 identities/states, exact Git objects and source lines, CLI source bindings, all nine finding keys/rules/locations, and the 345-row queue count:

```powershell
python research/evidence/cpp/verify_t48_camera_callback_audit_20261027.py --git-dir <camera-framework-git-mirror>
```
