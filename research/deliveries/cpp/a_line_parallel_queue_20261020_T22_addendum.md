# T22 task-tree addendum — Supervisor race candidates

**Independent test/source-evidence lane; base:** `8ec5f56a12e90bba56953b39eb17faa20e154da9`.

| Queue IDs | Current source-derived status | Next action | Owner/evidence dependency |
|---|---|---|---|
| CR-0001/0002 | Source mapping PASS; race PARTIAL with weak evidence. Destructor clears owned shared-pointer vectors; a concurrent valid access during destruction was not found. | Defer TSan/harness. First establish a valid concurrent access or lifetime violation in the pinned product path. | Component owner supplies object lifetime contract/call path. |
| CR-0003 | Source mapping PASS; race PARTIAL. `GetPidsMap()` copies an unsynchronized map that event-side paths mutate. | Prioritize target-derived test feasibility; identify exact product thread routing and a source-faithful reader/writer schedule. | Build owner supplies exact target/compile definitions and runtime dependency recipe. |
| CR-0004 | Source mapping PASS; race PARTIAL. `GetUidsMap()` copies an unsynchronized map; synchronous dump code reads while event-side paths can insert/erase on FFRT. | Highest follow-up. Verify `OnDump` framework thread and whether it overlaps the FFRT event queue, then construct source-derived harness. | Component/service owner supplies execution-context evidence and buildable target. |

All four A0 rows remain `not_testable` / `paused_pending_evidence`. This addendum does not assert a confirmed race or TSan outcome. Generic TSan controls do not satisfy the target evidence obligation. See the independent [T22 source audit](../../evidence/cpp/a_t22_supervisor_race_source_audit_20261020.md) and its JSON/verifier.
