# Independent follow-up: dependency binding fix (2026-10-20)

## Same-commit replay

Checked out the exact developer commit `76efed37d814ec68b56ebd6a00662efa7d137a4a` in a new clean worktree. The replay command was:

```powershell
python research/deliveries/c-line/dataview_api_width_proof_replay_20261020.py --git-dir D:/openHarmonyScanner/tmp/arkruntime-gitee-audit-20261023.git
```

The script independently verified the same pinned source objects as the prior report: parent target commit/tree/blob/SHA-256 `d62f6de64daa7e11a7936a6153748a7c5fae9e41` / `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1` / `e6bac984354292405ae62f7728170d7be5e3760e` / `bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c`; fixed target `48fcec3686e45175f95b4600b579026a65149966` / `6ff7f405071d29fc3ecf9bac1abd9d59a485909f` / `a2376e822e995333b2400520ca5b882de9578b5e` / `39b1ed79451980ad85e1176805deaf6c6315bca09d7676ea5c63f5ff1c4bd65b`.

All five registered cases parsed the target completely with zero parse issues, had `applicable_files=1`, and remained `blocked` with partial coverage:

| Case | Findings | Relevant unknowns |
|---|---|---|
| Parent, dependencies absent | candidates at lines 394 and 455 | constructor arithmetic incomplete |
| Parent, exact dependencies | zero | explicit `GetViewValue`/`SetViewValue` width-proof unknowns; constructor unknown |
| Fixed, dependencies absent | zero | constructor, `GetViewValue`, and `SetViewValue` unknown |
| Fixed, exact dependencies | zero | same three fixed-API unknowns |
| Parent, first helper mutated, stale pinned OID retained | candidates at lines 394 and 455 | constructor arithmetic incomplete |

The mutation control appends bytes to the exact `js_dataview.cpp` helper and updates its `SourceUnit.sha256`, while deliberately retaining the expected pinned `source_blob_oid`. The registered result restored both parent candidates, confirming the fail-closed behavior for the mismatch that produced the previous discrepancy. The exact-helper case still suppresses only the two parent API candidates and preserves explicit unknown outcomes.

## Scope controls and validation

The replay sidecars count the bound DataView target only; the two helper translation units are available in context for evidence checks but do not raise target `applicable_files` above one. The suite `python -m pytest tests/detectors/ark_runtime tests/test_runner_applicable_units.py -q` passed: **196 passed, 3 skipped**. This includes the new stale-OID adapter regression and runner applicability tests.

To check the suppression boundary independently, I passed a synthetic `BuiltinsDataView::SetTypedValue` flow with the same exact width/conversion helper evidence to `index_bounds_result`. It retained one candidate (`BuiltinsDataView::SetTypedValue`) and returned `partial`; this confirms the function-name suppression filter does not remove that distinct flow. This is a synthetic rule-level control, not a registered source replay of a separately bound `SetTypedValue` source.

No discrepancy remains in the tested evidence-binding behavior. These results are static analyzer outputs only. Partial/blocked and zero-finding outcomes are not security or safety verdicts; generated IR, runtime, buffer mutation, product impact, and broader source coverage remain unverified.
