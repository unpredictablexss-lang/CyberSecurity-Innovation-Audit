# T56 — telephony_sms_mms independent audit, CR-0343–CR-0345

**Disposition: PARTIAL/BLOCK.** The exact A0 source objects were rebound and all three candidate files were replayed with the current CLI. No A0 status was changed.

## Source identity

- Repository: `openharmony/telephony_sms_mms`
- Commit: `41cef006c6c4b7fdc9ee0bb8d9ae659ee2ebbfd8`
- Tree: `c7815e6f0b9033ca71cf4edc119a2e5b8393b85a`
- Provenance: detached worktree created from the matching local monorepo project-object database.
- The original A0 snapshot SHA-256 is retained in the machine report. Current CLI snapshot hashes are selection-specific and are recorded per replay; they are not treated as equivalent whole-repository snapshot hashes.

All three candidate blobs and SHA-256 values match the A0 ledger. The machine report also binds the handler implementation, unit-test sources and headers, relevant GN files, callback interfaces, and production callback stubs by blob and SHA-256.

## Current CLI replay

| Candidate | Current detector and version | Selected files | Parse coverage | Findings | Assessment |
|---|---|---|---|---:|---|
| CR-0343, `gsm_sms_cb_handler.h:39` | `ohscanner.cpp.shared_ptr_race` 0.5.1 | Candidate header | 1/1 complete | 0 | Historical 0.2.0-proposed candidate not reproduced; zero findings do not prove safety. |
| CR-0343 context replay | `ohscanner.cpp.shared_ptr_race` 0.5.1 | Candidate header and production implementation TU | 2/2 complete | 0 | Context does not establish handler scheduling or same-object overlap. |
| CR-0344/0345 | `ohscanner.interface.ipc` 0.12.12 | Both callback test translation units | 2/2 complete | 0 | The current CLI explicitly excludes both test entry roots from product candidate analysis. |

Commands and full raw outputs are recorded in the JSON report and the accompanying `t56_telephony_sms_*_cli_20261028.{json,md}` files.

## Case review

### CR-0343 — shared pointer member candidate

The candidate is the `SmsCbInfo`/`CbInfo` constructor initializer `header(headPtr)`. The component GN production library `ohos_shared_library("tel_sms_mms")` includes `services/sms/gsm/gsm_sms_cb_handler.cpp`. The implementation assigns a header into a local `SmsCbInfo` before adding it to `cbMsgList_`, and reads the member in multiple handler methods. The class has no explicit mutex for the list in this header, but the exact event-thread scheduling and concurrent same-object access are not established from this component source. No trusted fixed source is bound.

**Keep `not_testable / paused_pending_evidence`, PARTIAL/BLOCK.** The current detector did not reproduce the historical finding; this is not a safe or fixed verdict.

### CR-0344/0345 — callback test harness candidates

The candidate functions are `SmsDeliveryCallbackTest::OnRemoteRequest` and `SmsSendCallbackTest::OnRemoteRequest`; their bodies decode callback values without a local descriptor check. Their class headers inherit the corresponding `IRemoteStub<...>` interface. Both `.cpp` files are listed in the separate `ohos_executable("tel_sms_mms_test")` target in `test/unittest/BUILD.gn`, imported with `//build/test.gni`. The component's distinct production callback stubs read `data.ReadInterfaceToken()` and compare it to `GetDescriptor()` before decoding.

The current IPC detector records both roots as excluded test/fuzz/mock entry roots. Thus the zero-finding replay is not an analysis of these functions as product entries. The GN source supports their unit-test role, but this review did not establish product image selection or an externally reachable product callback using these implementations. No trusted vulnerability fix source is bound or necessary to classify a test harness as a product vulnerability.

**Keep both rows `not_testable / paused_pending_evidence`, PARTIAL/BLOCK.** Do not count these test harness candidates as product vulnerabilities or treat their exclusion as proof that all callback paths are safe.

## Reconciliation and verification

- The A0 ledger remains 345 unique rows: 9 `not_reproduced`, 336 `not_testable`.
- CR-0343, CR-0344, and CR-0345 remain `not_testable / paused_pending_evidence`.
- No detector, test, fixture, or A0 status was changed.
- Run the verifier with the exact local source object database:

```powershell
python research/evidence/cpp/t56_telephony_sms_mms_audit_20261028.py --git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\telephony_sms_mms.git
```

The verifier confirms commit/tree/blob/SHA bindings, CLI completion and parse coverage, and the frozen 345-row queue. Run `scripts.check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp` separately for delivery scope.

See [machine-readable audit](t56_telephony_sms_mms_audit_20261028.json) and [task-tree addendum](a_line_parallel_queue_20261020_T56_addendum.md).
