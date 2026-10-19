# T57 — systemabilitymgr_safwk test Stub and multi-instance audit (CR-0247–CR-0251)

**Disposition: PARTIAL/BLOCK.** All five A0 rows remain `not_testable / paused_pending_evidence`. Current IPC 0.12.12 scans parsed both selected C++ files completely and returned zero findings. This is not a safety result; it also does not establish why prior detector 0.5.0 emitted the candidates.

## Source identity and replay

All cases bind to commit `21c83c874a34e8d28e6a355a3b56e5167252ed27` / tree `e115202d315867371b3b7c885b4f017e10cb163f`.

| A0 ID | Source location | Blob | SHA-256 | Current replay |
|---|---|---|---|---|
| CR-0247 | `test/services/safwk/unittest/listen_ability/src/listen_ability_stub.cpp:129` | `fd8eb179e31c013603732b054aa14460b38ed75b` | `90e79b5a013f3d18a21db2bf0652f668be4ae36a21e8933e56f9ca634390a39e` | IPC 0.12.12 complete, 0 findings |
| CR-0248 | `test/services/safwk/unittest/listen_ability/src/listen_ability_stub.cpp:131` | `fd8eb179e31c013603732b054aa14460b38ed75b` | `90e79b5a013f3d18a21db2bf0652f668be4ae36a21e8933e56f9ca634390a39e` | IPC 0.12.12 complete, 0 findings |
| CR-0249 | `test/services/safwk/unittest/listen_ability/src/listen_ability_stub.cpp:177` | `fd8eb179e31c013603732b054aa14460b38ed75b` | `90e79b5a013f3d18a21db2bf0652f668be4ae36a21e8933e56f9ca634390a39e` | IPC 0.12.12 complete, 0 findings |
| CR-0250 | `test/services/safwk/unittest/listen_ability/src/listen_ability_stub.cpp:178` | `fd8eb179e31c013603732b054aa14460b38ed75b` | `90e79b5a013f3d18a21db2bf0652f668be4ae36a21e8933e56f9ca634390a39e` | IPC 0.12.12 complete, 0 findings |
| CR-0251 | `test/services/safwk/unittest/multi_instance_test_probe/src/multi_instance_test_probe.cpp:133` | `fbb8e7be8294011c6d87713d506d04dbb5aa81c0` | `40e1439c78f9b48edcf5baaa71499fcc1484d427cbb44582043b3833c451e76d` | IPC 0.12.12 complete, 0 findings |

The four ListenAbility candidates share `listen_ability_stub.cpp`; the multi-instance candidate is `Publish(this)` in the service lifecycle implementation. The two per-file CLI JSON and Markdown outputs are recorded beside this audit.

## GN and source context

`listen_test` is an `ohos_shared_library` defined under the unit-test subtree and routed through `test/BUILD.gn` deployment. Its source contains the A0 private-request cases. `OnRemoteRequest` takes the private request branch before checking the interface token; for non-private interface requests it compares descriptor and token. That later check must not be generalized to the private cases. The reviewed lines serialize results or dispatch the private handler.

`multi_instance_test_probe` is also an `ohos_shared_library` under the unit-test subtree and is pulled by the test deploy group. Its target does not directly declare `testonly = true`; therefore this is a test-named/deployed probe, but product inclusion remains unverified. CR-0251 is `Publish(this)`, not an IPC handler itself. The separate sibling Stub dispatches process ID, unload, remove, republish and on-demand policy operations; no descriptor token validation is visible in that `OnRemoteRequest`. Product image selection, service registration, caller authorization, reachable operation and impact remain unknown.

## Verification

- Reproduce both scans: `python research/evidence/cpp/t57_safwk_replay_20261029.py --source-repo <pinned project checkout> --out-dir research/evidence/cpp`
- Verify bindings, CLI outputs and A0 states: `python research/evidence/cpp/verify_t57_safwk_test_stubs_audit_20261029.py --git-dir <systemabilitymgr_safwk object DB>`
- The A0 queue contains 345 unique rows (9 `not_reproduced`, 336 `not_testable`); this audit does not rewrite it. No detector/API/Catalog/tests/fixtures are modified.
