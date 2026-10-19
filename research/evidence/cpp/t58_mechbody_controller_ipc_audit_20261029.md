# T58 — mechbody controller IPC A0 audit (CR-0116–CR-0118)

## Disposition

All three frozen A0 rows remain `not_testable / paused_pending_evidence`. The current IPC CLI reproduces one `ipc.relay.descriptor-boundary` candidate at each original line. Source inspection confirms each dispatcher checks a transaction code and a custom `MECH_SERVICE_IPC_TOKEN`, then dispatches through a member-function pointer. The custom token is `ohos.mechservice.accessToken`; the declared interface descriptors are `ohos.mechManager.IJsMechManager` for the ANI/N-API wrappers and `OHOS.MechBodyController.IMechBodyController` for the service Stub. The token comparison is therefore not an exact declared-interface-descriptor check. This confirms the static candidate condition, but does not establish exploitability or security impact.

The cases remain PARTIAL/BLOCK: product target presence is source-visible, but product configuration/feature selection, service registration and caller reachability, caller authorization policy, and a demonstrated unauthorized effect are not established by these source objects. Do not treat them as validated vulnerabilities or as safe.

## Source binding and replay

- Repository declaration: `openharmony/distributedhardware_mechbody_controller`
- Commit: `6e875a2dc5a7748bfdcbec1ccf9f1153574fa03e`
- Tree: `d34e2a24b6e121f5a06a0b91d377c3558f803ca3`
- Source object: local project-object mirror `D:\openHarmonyScanner\openharmony\.repo\project-objects\distributedhardware_mechbody_controller.git`
- Current CLI: `ohscanner.interface.ipc` v0.12.12; profile `light-ast`; 3 explicitly selected files; parse complete for all 3; 3 candidates; 0 validated vulnerabilities.
- Replay JSON/Markdown: `D:\openHarmonyScanner\tmp\t58-mechbody-ipc-20261029.json` and `.md` (temporary raw outputs; verifier regenerates them).

| A0 ID | Source | Blob | SHA-256 | CLI result | Original A0 state |
|---|---|---|---|---|---|
| CR-0116 | `interface/ets/mech_manager/src/ani_mech_manager_stub.cpp:50` | `07ac99fc1a472821ed023e441f451b3a4565354f` | `159aa4000f4aa4424278f5ecb5463d90aa0d022208a3e8a6d337f8e155098001` | candidate `ohscanner.interface.ipc:fdc6f4998f7956be`, parse complete | `not_testable / paused_pending_evidence` |
| CR-0117 | `interface/napi/mech_manager/js_mech_manager_stub.cpp:43` | `b216ec521401e853b7abd85ccec53c88ccec6f26` | `bf3ebd48fd1457d0b2f50d1c0bf9483f6f17def869d92e7b4c664b59b3cddff6` | candidate `ohscanner.interface.ipc:2c65707d31461dbc`, parse complete | `not_testable / paused_pending_evidence` |
| CR-0118 | `services/src/mechbody_controller_stub.cpp:123` | `90538a2258427f76aea83600053a7c4168717ce6` | `484ecfa436aecb26ce1240a350ce28eb177770c88975e436d29004ecbd7ece8f` | candidate `ohscanner.interface.ipc:01ac86b01f2a7bb9`, parse complete | `not_testable / paused_pending_evidence` |

The identities above match the frozen A0 queue. The source-file hashes also match the diagnostics emitted by the replay. All three candidates are in the same source family; this is not an independent holdout or three independent vulnerability claims.

## Dispatcher, guard, and build context

- ANI and N-API `OnRemoteRequest` resolve a transaction code to a member-function pointer, read `MECH_SERVICE_IPC_TOKEN`, return on mismatch, and invoke the mapped function. The service Stub follows the same pattern and falls back to `IPCObjectStub::OnRemoteRequest` for unmapped codes.
- These custom token checks are real guards, but the literal differs from each interface's declared descriptor. This is consistent with the detector's descriptor-boundary candidate; it does not prove unauthorized access. Separate per-caller permission enforcement and service-manager registration/reachability are not established here.
- GN declares `taihe_shared_library("mechanic_manager_ani")` with the ANI Stub source, `ohos_shared_library("mechanicmanager_napi")` with the N-API Stub source, and install-enabled `ohos_shared_library("mechbody_service")` with the service Stub source under `if (!mechbody_controller_feature_L1)`. These are production-shaped targets, not test-only wrappers; the local source does not prove a particular product includes or enables them.
- Fuzz GN targets also compile some of these production Stub sources, but those harnesses are `testonly = true`. Their existence does not make the product path reachable and does not prove the reported behavior.

## Verification

Run from the repository worktree with the local mirror and CLI environment available:

```powershell
python research/evidence/cpp/t58_mechbody_controller_ipc_audit_20261029.py
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp
```

The A0 queue verifier reports 345 unique rows and preserves the original status totals. This audit does not edit the queue or source data.
