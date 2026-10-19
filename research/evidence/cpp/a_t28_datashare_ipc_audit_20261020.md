# T28 independent source audit: DataShare IPC CR-0016–CR-0018

## Summary

The three frozen A0 rows bind to the same DataShare source commit `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`, tree `f731230c116c94d7619f5514c828b33ffac69924`, and source blob `cb62502d82c0534a6b9466f7a5d0a9e122d85693` (`frameworks/native/provider/src/datashare_stub.cpp`, SHA-256 `cc742b1811c6c6ce2c351e27619a74ec1e5f472502a7a712c50d49fbaeed667a`). The frozen queue has 345 IDs; these rows remain `not_testable / queued_first_batch`.

The current production M2 CLI replay at scanner baseline `a950a2662a4e131b31ca28c0b7f8937b7140a034` emits all three candidates at their recorded lines. The one-file replay is `partial` (0 complete / 1 partial); that finding set is not a complete-file analysis and cannot close the cases.

Source evidence shows `DataShareStub` maps `CMD_OPEN_FILE`, `CMD_OPEN_FILE_WITH_ERR_CODE`, and `CMD_OPEN_RAW_FILE` to their handlers and dispatches mapped transaction codes in `OnRemoteRequest` after checking the interface token. The handlers decode URI/mode, call virtual `OpenFile`/`OpenRawFile`, and return a file descriptor or descriptor value in the reply. `VerifyPermissionAndUri` exists in the same source but the audit did not establish that it dominates these three handler paths; component `DataSharePermission` APIs and provider-specific permission behavior exist elsewhere. This is not enough to prove an authorization defect or to rule one out.

No exact product build/profile, product service registration/reachability, provider implementation contract for the pinned target, runtime caller principal, or concrete unauthorized impact was independently established. All three dispositions remain **PARTIAL/BLOCK**. No fixed source is bound; no fixed-control pass is claimed.

## Per-ID disposition

| A0 ID | Original candidate | Current CLI finding | Source observation | Status |
|---|---|---|---|---|
| CR-0016 | `ipc.auth.missing`, line 204 (`DataShareStub::OpenFileInner`) | `ohscanner.interface.ipc:c9ce14225a9f7473`, same rule/location | `OpenFileInner` unmarshals URI/mode, rejects malformed/empty mode, then calls `OpenFile`. The helper itself contains no recognized caller check; authorization may be implemented in provider-specific dispatch/callee paths, not established here. | PARTIAL/BLOCK; original A0 state unchanged |
| CR-0017 | `ipc.capability.export`, line 221 (`CmdOpenFile`) | `ohscanner.interface.ipc:e6519a0563067672`, same rule/location | Dispatch binding maps `CMD_OPEN_FILE` to this handler; successful path writes FD to reply and closes local ownership. External reachability and caller authorization are unknown. | PARTIAL/BLOCK; original A0 state unchanged |
| CR-0018 | `ipc.capability.export`, line 243 (`CmdOpenFileWithErrCode`) | `ohscanner.interface.ipc:c7071a32568a80bb`, same rule/location | Handler maps from `CMD_OPEN_FILE_WITH_ERR_CODE`; successful path writes FD to reply and closes local ownership. External reachability and caller authorization are unknown. | PARTIAL/BLOCK; original A0 state unchanged |

`CmdOpenRawFile` is also present at line 252 and returns the FD value via parcel serialization, but it is not one of these three frozen queue rows and is not relabeled as such.

## Source evidence and limitations

- `datashare_stub.cpp` constructor binds the three transaction codes to the corresponding member handlers. `OnRemoteRequest` validates `DataShareStub::GetDescriptor()`, looks up the function pointer by code, and invokes it. This is source-level dispatch evidence, not product reachability evidence.
- The helper `VerifyPermissionAndUri` performs configured read/write token checks, but this audit found no proof in the pinned source that it guards `OpenFileInner` or both FD-export handlers. Conversely, provider virtual operations may perform their own permission checks; their applicable concrete implementation and product configuration are not bound here.
- `DataSharePermission::VerifyPermission` resolves provider permissions and verifies the access token, establishing that permission mechanisms exist in the source corpus. It does not prove that these particular IPC operations invoke the check.
- Current CLI detector: `ohscanner.interface.ipc` version `0.12.12`; the three diagnostics are syntax candidates. Current replay selected one 26,370-byte source file; parse coverage is 0 complete / 1 partial, with the file marked `parser_not_complete`. No build or runtime validation occurred.
- The full original A0 module run also reports these same three locations, with module-wide IPC parse status partial (159/258 applicable files analyzed, 99 partial). Its full scan is context only; this independent audit's reproduced run is the bounded single-file CLI artifact alongside this report.
- No fixed source, PoC, exact shipped product profile, permissions manifest, or runtime caller/impact evidence is present. Zero/partial results are never treated as safety evidence.

## Reproduction and machine checks

The raw current CLI result is `a_t28_datashare_cr0016_0018_cli_20261020.json` and its Markdown companion. Reproduce from the scanner checkout:

```powershell
git clone --shared --no-checkout D:/openHarmonyScanner/openharmony/.repo/project-objects/distributeddatamgr_data_share.git research/evidence/cpp/.t28_datashare_source_repo
python -m src.cli.main ohscan-run --repo-dir research/evidence/cpp/.t28_datashare_source_repo --repository openharmony/distributeddatamgr_data_share --commit 560c5cdadf08b4beeb691e93d70ff32cc2dca8bd --include frameworks/native/provider/src/datashare_stub.cpp --detector ohscanner.interface.ipc --json-out research/evidence/cpp/a_t28_datashare_cr0016_0018_cli_20261020.json --md-out research/evidence/cpp/a_t28_datashare_cr0016_0018_cli_20261020.md
python research/evidence/cpp/verify_a_t28_datashare_ipc_audit.py --source-git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/distributeddatamgr_data_share.git
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base a950a2662a4e131b31ca28c0b7f8937b7140a034 --lane cpp
```

The verifier checks each pinned source blob and raw SHA-256 against Git objects and the frozen queue, confirms the three exact CLI finding locations/rules, confirms `partial` parsing, and ensures the original and queue statuses stay unchanged.

## Evidence needed to unblock

Bind the concrete DataShare service/provider implementation and product build/profile; prove whether each transaction is externally reachable and which caller identity/permission policy applies; trace the provider-specific authorization checks through each operation to FD creation/export; then use a reproducible target-derived IPC harness/runtime test for any remaining plausible unauthorized path. Until then, keep these rows queued and blocked.
