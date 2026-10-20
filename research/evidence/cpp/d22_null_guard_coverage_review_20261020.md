# D22 null-dereference guard coverage review

Date: 2026-10-20
Scanner baseline: PR #35 head `81dd4aea9bb51522ac912b33504ef0d2ddb79089`
Disposition: **NO CHANGE / PARTIAL / BLOCK**

## Reproduction

At this baseline the fixed Git objects were replayed against the one-file scope using the current CLI:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-vulnerable --repository openharmony/communication_dsoftbus --commit 258662cd9840b55a31546a72d91027f6368cea84 --include core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp --detector ohscanner.cpp.null_dereference --json-out D:\openHarmonyScanner\tmp\d22-nullguard-vulnerable.json --md-out D:\openHarmonyScanner\tmp\d22-nullguard-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-fixed --repository openharmony/communication_dsoftbus --commit 192f3e11d74beeaa3d879333471deb8a24a7e1c5 --include core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp --detector ohscanner.cpp.null_dereference --json-out D:\openHarmonyScanner\tmp\d22-nullguard-fixed.json --md-out D:\openHarmonyScanner\tmp\d22-nullguard-fixed.md
```

The vulnerable file produced 5 candidates at lines 71, 82, 97, 108, and 123; fixed produced 0. Parsing is complete for each 1-file scope. Detector `ohscanner.cpp.null_dereference` 0.6.0 reports `blocked`, with `detector_coverage.status=partial` and `coverage_counts={complete:0, partial:1, not_analyzed:0, failed:0}` on both. The 0/1 figure is per-file analysis coverage, not a measured guard-control pass rate. All diagnostics remain unassessed syntax candidates; this is not a vulnerability confirmation or PASS.

Exact source identity is recorded in `research/evidence/cpp/a_static_baseline_20261019/d22_cve_2025_26690_upstream_object_replay_20261020.json` and independent source controls in `research/evidence/cpp/t62_dsoftbus_controls_20261020/README.md`:

- vulnerable `openharmony/communication_dsoftbus`, commit `258662cd9840b55a31546a72d91027f6368cea84`, tree `366a4ced9400653c9628c0b677e4ae657c0e7bd8`, blob `a82b71fb5520b02278a4af695bbe918d14c1048e`, SHA-256 `5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6`;
- fixed commit `192f3e11d74beeaa3d879333471deb8a24a7e1c5`, tree `1d58ba0ef706a6f69dd372bd496c8058810882aa`, blob `13ddbe93a7f617784dec0f3761e09f66b5c3217c`, SHA-256 `5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81`.

## Guard / dominance assessment

The detector's current guard model recognizes bounded same-function `if` predicates and lexical branch returns. T62's source-bound review independently confirmed that `ClientOnJoinLNNResult`, `ClientOnLeaveLNNResult`, `ClientNotifyHichainProofException`, and `ClientOnDataLevelChanged` have local null checks that return before their respective proxy use. The vulnerable candidates instead concern distinct `nothrow` allocation/use sites; their messages explicitly report `guard_relation=none`. Thus, the guards do not justify suppressing those vulnerable candidates.

The partial per-file outcome is conservative: limitations include `guard_dominance_unknown_without_compile_context`; coverage semantics explicitly treat any partial file as unknown. The output does not expose a per-function semantic-coverage numerator/denominator. Reclassifying the whole file complete merely because reviewed local guards are understood would overstate analysis of the other functions and CFG/build context. Altering coverage bookkeeping would not expand proven detector behavior. No generic local-guard change is supported by this evidence, and a source-only control observation cannot demonstrate the scanner validated that control.

## Verification

- `python -m unittest tests.detectors.test_cpp_null_dereference_signal_controls -q` — 12 tests passed.
- No detector, parser, API, Catalog, schema, or test files changed.
- Preserve the independent T62 control report, `5/0` differential, `PARTIAL/BLOCK`, and outstanding product/reachability evidence.
