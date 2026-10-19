# T47 — Battery statistics `g_statsParser` candidate review (CR-0252–CR-0254)

## Result

**PARTIAL/BLOCK.** The exact source is in a `test/unittest` header, and the GN test group is explicitly `testonly = true`. The CLI independently replays three candidates at lines 41–43 with complete parsing. This is syntax evidence only: it does not prove concurrent invocation, an attacker-controlled path, product inclusion, or security impact. The A0 rows remain `not_testable`; their queue status remains `paused_pending_evidence`.

## Source binding

All three A0 rows bind `openharmony/powermgr_battery_statistics` commit `271a545acc0ececc746cfe0bb7c1501943df7c64`, tree `fd32c4da257effb689a86f7946f51805360fbf70`, and `test/unittest/include/stats_test.h` blob `adaadee18b512e92c3f4afd1d9a566a1fc90f4a6`, SHA-256 `c1113bea553ef18ffe9450df4b13865075bb2e54b42b44188f424e9cfb127c91`. The line identities are CR-0252:41, CR-0253:42, CR-0254:43. Exact row mappings and original statuses are in the [machine audit](t47_battery_stats_audit_20261027.json).

## CLI replay

`ohscanner.cpp.shared_ptr_race` 0.5.1 parsed the one-file scope completely and emitted three unassessed candidates at the same three source lines. It reported zero validated vulnerabilities. The [raw JSON](t47_battery_stats_cli_20261027.json) and [CLI report](t47_battery_stats_cli_20261027.md) preserve the output.

## Source and build context

`StatsTest::g_statsParser` is read for the null check (line 41), assigned a `make_shared` value (line 42), then read to invoke `Init()` (line 43). No mutex or atomic operation appears in this header. `ParserAveragePowerFile()` is called from test suite setup methods; inspected callers do not establish simultaneous invocation. The project test group sets `testonly = true`, and the client/service build files declare separate `ohos_unittest` targets. No product-build membership or real product configuration was found. These facts weaken the product-security interpretation but do not establish that the queue candidate is safe or impossible to race.

No target-derived concurrency harness was run. There is no trusted fixed-source pair for this candidate. Keep the queue rows unchanged and block product-security conclusions pending target linkage, execution/concurrency, entry-boundary, and impact evidence.

## Verification

Run `python research/evidence/cpp/verify_t47_battery_stats_audit_20261027.py --source-repo <standalone exact project checkout>`. The verifier checks commit/tree/blob/SHA bindings, the five build/caller context files, all 345 A0 queue rows and unchanged selected states, and the saved scanner output.
