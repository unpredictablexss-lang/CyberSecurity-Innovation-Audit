# D50 current OpenHarmony component replay

Date: 2026-10-19. OHScanner baseline: `da1f02452d90d79834722fcff490b9560cb1e9d9`. Detector: explicitly selected `ohscanner.known_disclosed_cves@0.16.0`; parser profile `light-ast`. No product build, macro expansion, or locked product manifest was used. Inputs came from read-only local OpenHarmony Git mirrors; each report records exact commit/tree/snapshot SHA. No implicit fetch or source modification was performed.

| Repository | Pinned commit / tree | Files and parsing coverage | Detector / task | Result |
|---|---|---:|---|---|
| `openharmony/filemanagement_storage_service` | `cf373c3bf087167d946e20a1455d90132d82543c` / `c8be9450341e50059056e5abfaa5de40d860f7c2` | 857; 704 complete, 153 partial | blocked / completed_with_limitations | 0 diagnostics |
| `openharmony/miscservices_pasteboard` | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` / `e374a0d61c9ec664ddd29fc17002797828c480ee` | 68; 57 complete, 10 partial, 1 not_run | blocked / completed_with_limitations | 2 candidates |
| `openharmony/bundlemanager_app_domain_verify` | `80513aacffbbce6f227515843a14c2a19d651017` / `1e3880fa2793fcb1178497c0fea0b6972ab3d1fa` | 188; 138 complete, 49 partial, 1 not_run | blocked / completed_with_limitations | 0 diagnostics |

The pasteboard matches are bound to source-file SHA-256 values in the reports:

- `CVE-2025-25212`, `services/core/src/pasteboard_service.cpp:222`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`. The rule describes observer registration inserting into a shared collection without a visible per-process quota. Product reachability and vulnerability status remain unconfirmed.
- `CVE-2025-27247`, `services/zidl/src/pasteboard_service_stub.cpp:41`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`. The rule describes Binder `GET_PASTE_DATA` dispatch without a visible permission check in dispatch/handler. Product reachability and vulnerability status remain unconfirmed.

The storage zero-hit is not a safe result. In the pinned snapshot, the CVE-2026-28733 related implementation is under `services/storage_daemon/ipc/src/storage_daemon_provider.cpp`; the earlier replay profile expected `storage_daemon_stub.cpp`, which is absent. The visible `GetUserStatistics` caller is protected by the same `mutexStats_` around access. This local observation only explains why the earlier candidate path was not reproduced here; it does not establish component or product safety. The expected `volume_manager_service.cpp` / `NotifyMtpMounted` source for CVE-2026-28751 is absent from this snapshot, so no safe or missed conclusion follows.

All three tasks are `completed_with_limitations`, all DetectorRuns are `blocked`, and `validated_vulnerability=0`. Candidate and zero-hit results are limited by partial/not-run coverage. This run included no product build, real entry/permission validation, dynamic PoC, or fixed-product retest; it is not an independent holdout and cannot support accuracy claims or confirmed product vulnerabilities.

Machine reports and SHA-256: `storage.json` `f36cd40ad8a79839311cd399798e0b8d6b15bc94c4d4bd1d2483aa81977671a2`; `pasteboard.json` `b4279e00373c889f0c5142e2582412fc04c489dd4271167aa7b0223936edf9f4`; `appdomain.json` `ab7024503793a0805adfe4c079d9033a0a6c3db0c4f10a9b4b9a55e40740e038`.
