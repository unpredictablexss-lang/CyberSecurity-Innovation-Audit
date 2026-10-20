# D49 — EDM IPC CR-0306–CR-0312 no-change assessment

> Static candidate replay and source review only. This is not a vulnerability confirmation or a safety verdict.

## Result

The exact current `ohscanner.interface.ipc` CLI replay completed on three production C++ translation units from the A0-bound source commit. All three parsed completely and the detector emitted five `ipc.relay.descriptor-boundary` candidates. The replay matched CR-0307, CR-0308, and CR-0310–CR-0312 at their exact source lines. It did not emit findings at CR-0306 (`admin_manager.cpp:240`) or CR-0309 (`enterprise_device_mgr_stub.cpp:63`). No concrete detector gap was reproduced, so D49 makes no detector change.

Source review puts the two missing locations in bounded roles: `AdminManager::IsAdminExist()` is a parameterless state query, while `OnRemoteRequestIdl` checks the system/native principal for the listed system transactions and returns `SYSTEM_API_DENIED` before delegating. These findings do not establish that the callers, effective product policy, or impact are safe. The five reproduced findings also remain static candidates. Preserve all seven A0 rows as `not_testable / paused_pending_evidence`; overall result remains **PARTIAL/BLOCK**.

## Source and A0 binding

| Item | Identity |
|---|---|
| A0 candidate ledger | `tmp_candidate_rows.csv`, SHA-256 `16d5702cfd60bc666ed8f041c48311546b190d32c9e66243b0e9dfa4e549caee` |
| A0 triage queue | `research/deliveries/cpp/a0_triage_20261019/queue.csv`, SHA-256 `a174c0a74986e8410c53f173b84bb446c59000c3867add612a14e8aab4396d27` |
| Repository and source commit | `openharmony/customization_enterprise_device_management` @ `e1e278bc85dc0277ab79cfdc029558a61492d3da` |
| Source tree | `74f22f00256d82a81ad9c1965ae0ec64ce3936a1` |
| A0 rows in scope | CR-0306–CR-0312, all originally `not_testable` |
| Test-only comparison excluded | CR-0313, `test/unittest/services/edm/src/system_timer_manager_test.cpp:70` |

The three production targets are `admin_manager.cpp`, `delay_unload_manager.cpp`, and `enterprise_device_mgr_stub.cpp`. Their exact Git blob IDs and SHA-256 values, plus the header, permission helper, GN and test-boundary support identities, are recorded in the machine-readable report. The verifier reconciles all seven A0 candidate IDs, source hashes, original `not_testable` states, and current `paused_pending_evidence` queue states. CR-0313's test-only source binding and queue state are checked separately.

The full A0 triage reconciliation also passed in this checkout: 345 candidate IDs retained, 345 unique queue rows, original states `not_reproduced=9` / `not_testable=336`, and queue states `queued_not_reproduced=9` / `queued_first_batch=5` / `paused_pending_evidence=331`.

## Current CLI replay

| Detector | Version/model | Files | Parsing | Candidates | Exact A0 line matches |
|---|---|---:|---|---:|---|
| `ohscanner.interface.ipc` | `0.12.12` / `oh-ipc-2026.10-v32` | 3 | complete 3/3 | 5 | 5/7 |

The five current findings are at `delay_unload_manager.cpp:38,42` and `enterprise_device_mgr_stub.cpp:75,76,90`. The current replay has no finding at `admin_manager.cpp:240` or `enterprise_device_mgr_stub.cpp:63`. Complete parsing describes only the three selected target translation units; it does not prove interprocedural authorization, product reachability, or runtime impact.

## Source review

1. **CR-0306:** `AdminManager::IsAdminExist()` at line 240 forwards to `AdminContainer::IsAdminExist()` without consuming request data. `EnterpriseDeviceMgrStub::OnRemoteRequest` calls `DelayUnloadManager::TryStartDelayUnload()` after the handler returns; that helper queries administrator state and manages a delayed-unload task. This is a post-dispatch state check, not a parcel descriptor relay.
2. **CR-0307–0308:** `TryStartDelayUnload()` checks administrator state, resolves an event handler, removes a prior delayed-unload task, and schedules a new one. The exact helper has no current `MessageParcel` input.
3. **CR-0309:** The IDL path checks `systemCodeList` and calls `CheckIsSystemAppOrNative()` for those codes; a denial returns `SYSTEM_API_DENIED` before the base IDL Stub dispatch. The helper delegates to the access-token manager. Effective caller grants in the reviewed product remain unknown.
4. **CR-0310–0312:** `OnRemoteRequest` calls `HandleOnRemoteRequest`, then performs the delayed-unload check. The service-flag branch delegates to the IDL wrapper. The non-IDL branch reads the request interface token, compares it to this Stub's descriptor, and then dispatches. Descriptor validation does not establish caller authorization.
5. **Build boundary:** `services/edm/BUILD.gn` always lists the Stub in `edmservice`; `AdminManager` and `DelayUnloadManager` are included under `enterprise_device_management_support_all`. The component `common.gni` default is true, but the product GN profile and built image were not bound. CR-0313's source appears under the unit-test BUILD target and was excluded from the production CLI scope.

The detector's bounded call model reports all five current candidates as unresolved boundary candidates; it does not prove the call chain, caller rights, or exploit consequence. The exact two A0 locations with no current finding remain unreproduced on this source snapshot. Neither result justifies calling the source vulnerable, fixed, safe, or a false positive.

## Remaining proof obligations

- Bind the product GN profile and built image to establish whether this feature and target are present.
- Establish the actual SA caller reachability and effective permission grants in that product.
- Establish a concrete descriptor-flow issue or security impact for any candidate.
- Bind a trusted fixed-source or product regression pair if one exists.

## Reproduction

Run from the scanner repository with the pinned source checkout and original A0 candidate CSV available:

```bash
python research/evidence/cpp/d49_edm_ipc_no_change_20261028.py \
  --source-repo /path/to/customization_enterprise_device_management \
  --a0-csv /path/to/tmp_candidate_rows.csv \
  --output research/evidence/cpp/d49_edm_ipc_no_change_20261028.json \
  --cli-json research/evidence/cpp/d49_edm_ipc_cli_20261028.json \
  --cli-md research/evidence/cpp/d49_edm_ipc_cli_20261028.md
```

See the [machine-readable assessment](d49_edm_ipc_no_change_20261028.json), [raw current CLI JSON](d49_edm_ipc_cli_20261028.json), and [verifier](d49_edm_ipc_no_change_20261028.py).
