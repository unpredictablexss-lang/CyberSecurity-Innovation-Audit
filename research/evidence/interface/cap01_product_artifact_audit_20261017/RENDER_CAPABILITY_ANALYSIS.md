# CAP-01 render-session capability surface

Source authority: `openharmony/graphic_graphic_2d` commit `8f1745527aa13624539e8b16ad31373e6b7d7087`, tree `ea54227cfb9a672090fb8215489bbb1e44dc9a0a` (the OpenHarmony 7.0 release dependency). All quoted files were fetched by exact raw URL and verified against their Git blob IDs.

## Concrete interface chain

1. `ScreenSession::renderSession_` is returned as `sptr<IRemoteObject>`.
2. `RSUIDirector::Create` -> `RSUIContextManager::CreateRSUIContext` -> `RSUIContext` -> `RSRenderInterface` -> `RSRenderPipelineClient`.
3. `RSRenderPipelineClient(connectToRenderRemote)` calls `RSRenderServiceConnectHub::GetRenderProcessTokenMaskId`.
4. That casts the object to `RSIConnectToRenderProcess`, descriptor `ohos.rosen.ConnectToRenderProcess`.
5. It creates a local empty `RSIConnectionToken`, derives a token mask from caller PID/token pointer, and calls `CreateRenderConnection(tokenMaskId, token, needRefresh)`.
6. The returned `RSIClientToRenderConnection` has descriptor `ohos.rosen.ClientToRenderConnection` and is retained for later render commands.

Thus the CAP-01 object is a **connect-to-render-process capability**, not a context-free identifier.

## Sensitive surface

`RSIClientToRenderConnection` includes:

- transaction/integrity: `CommitTransaction`, `ExecuteSynchronousTask`, `CreateNode`, `CreateNodeAndSurface`;
- confidentiality: `GetBitmap`, `GetPixelmap`, `TakeSurfaceCapture`, `TakeSurfaceCaptureSoloNode`, `TakeSelfSurfaceCapture`, `TakeSurfaceCaptureWithAllWindows`;
- state/availability: `SetHardwareEnabled`, `SetHidePrivacyContent`, `SetFocusAppInfo`, `FreezeScreen`, `DropFrameByPid`, watermark operations, `RemoveConnection`/`RemoveToken`.

The access verifier explicitly maps `TAKE_SURFACE_CAPTURE` to `CAPTURE_SCREEN` and `TAKE_SURFACE_CAPTURE_WITH_ALL_WINDOWS` to `CAPTURE_SCREEN_ALL`. Many other methods have explicit system-caller checks. However, the inspected verifier defaults to permission for cases not listed; this includes `COMMIT_TRANSACTION`, `EXECUTE_SYNCHRONOUS_TASK`, `CREATE_NODE`, `CREATE_NODE_AND_SURFACE`, `GET_BITMAP` and `GET_PIXELMAP`.

The stub allows capture calls through its generic access rejection path, but the handler then records `screenCapturePermission = accessible`, `isSystemCalling`, and `selfCapture = ExtractPid(id) == callingPid || callingPid == 0`. This supports self-capture even without general screen-capture permission and notes a temporary PID-zero allowance.

## CIA interpretation

- **Confidentiality: candidate-supported, not validated.** Pixel-producing APIs exist. Cross-window leakage requires target node IDs and successful bypass/boundary of self-capture/permission checks.
- **Integrity: candidate-supported, not validated.** Unrestricted transaction/node commands can alter render state if the acquired connection is scoped to another render process.
- **Availability: candidate-unknown.** Large transaction streams, synchronous tasks, node allocation and connection removal are plausible resource/lifecycle vectors, but no crash/hang/exhaustion was measured.

No method is promoted to a validated vulnerability. Product-runtime acquisition, cross-process scoping and concrete effects remain required.
