# Independent review: DataView API width proof (2026-10-20)

## Revision and exact source identities

Replay ran in a clean dedicated worktree at exact detector commit `40b7732e30f94dd77d15867ec69e2e026f609760`. The source replay script verified the parent target as commit `d62f6de64daa7e11a7936a6153748a7c5fae9e41`, tree `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1`, blob `e6bac984354292405ae62f7728170d7be5e3760e`, SHA-256 `bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c`; fixed target `48fcec3686e45175f95b4600b579026a65149966`, tree `6ff7f405071d29fc3ecf9bac1abd9d59a485909f`, blob `a2376e822e995333b2400520ca5b882de9578b5e`, SHA-256 `39b1ed79451980ad85e1176805deaf6c6315bca09d7676ea5c63f5ff1c4bd65b`.

## Registered replay

Command:

```powershell
python research/deliveries/c-line/dataview_api_width_proof_replay_20261020.py --git-dir D:/openHarmonyScanner/tmp/arkruntime-gitee-audit-20261023.git
```

Observed all four matrix cases parse the target completely with zero parse issues, report `blocked`/`partial`, and count only the target (`applicable_files=1`; helper units remain in the full context):

| Target | Helper context | Findings | Remaining unknowns |
|---|---|---|---|
| Parent | None | candidates at 394 and 455 | constructor arithmetic incomplete |
| Parent | Both pinned helper objects | zero findings | explicit `GetViewValue` and `SetViewValue` width-proof unknowns; constructor unknown |
| Fixed | None | zero findings | constructor, `GetViewValue`, `SetViewValue` unknown |
| Fixed | Both pinned helper objects | zero findings | same three fixed-API unknowns |

The helper pins are `ecmascript/js_dataview.cpp`, blob `5057a103a88096b5db0e39be0feca2864a2ff8eb`, SHA-256 `3782d04ee5c44504bf453b3b45f96d7431ff902fb575257c425c707890b83243`; and `ecmascript/base/number_helper.cpp`, blob `a648bf6cf36715d57c6466f0ab4bfdc00bdc8f35`, SHA-256 `94db5ecc8ff7ea79d656950abacd9c24756ccf6aa0e3b2b895d7dc9961dbc91f`.

## Dependency-binding discrepancy

The requested missing-dependency behavior is confirmed: with the parent target and only `js_dataview.cpp` present (the `number_helper.cpp` unit omitted), the registered adapter retains both candidates at lines 394/455. The exact-helper control suppresses those two findings only and preserves the explicit unknowns above. No `SetTypedValue` candidate was observed in this DataView target replay; the direct result therefore establishes only that the two observed API findings are the ones suppressed here, not a broader cross-file non-effect. `SetTypedValue`'s different source binding was not replayed in this command.

A mismatch control exposed a fail-open in the dependency evidence check at this commit. Reproduction: build a parent context with the exact target and both helper units from the pinned Git objects; for the `js_dataview.cpp` unit append `\n// independent stale-source mutation\n` to the source bytes and compute the `SourceUnit.sha256` from those altered bytes, but leave `shared_facts['source_blob_oid']['ecmascript/js_dataview.cpp']` set to the expected pinned blob `5057a103a88096b5db0e39be0feca2864a2ff8eb`. Keep its parse status complete and run the registered detector through `run_all_with_coverage`. The result was still parent zero diagnostics, with both API candidates suppressed, `applicable_files=1`, and blocked/partial status.

In `ArkRuntimeTypeSafetyDetector._dependency_error`, the altered dependency SHA is checked only for consistency with the altered bytes, while the source blob fact is compared with the expected blob. It does not compare the unit SHA with the model row's expected SHA or recompute the Git blob OID from the bytes. The resulting context is inconsistent (declared Git object does not hash to its supplied source); nevertheless, the adapter accepted it as width evidence. Developer confirmed this is a real evidence-binding gap and is preparing a fix. Therefore the exact-helper result above is valid for correctly pinned inputs, but fail-closed behavior for inconsistent/mismatched dependency evidence is **not established** at `40b7732e`.

## Validation and limits

`python -m pytest tests/detectors/ark_runtime tests/test_runner_applicable_units.py -q` passed: **195 passed, 3 skipped**. The replay's applicable-file accounting confirms that target bindings, not helper files, determine the one applicable target. This report records static registered-analyzer behavior only. All target reports remained blocked/partial; zero findings and suppression are not safety conclusions. No generated IR, runtime, buffer-mutation, or product behavior was tested.
