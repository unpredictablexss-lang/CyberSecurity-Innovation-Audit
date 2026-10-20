# T36 — Preferences BaseValue fuzzer independent audit

## Result

T36 independently replayed A0 CR-0041–CR-0065 against the exact Preferences source object. All 25 IDs bind to commit `bff9efd79afc0d7d1ed22a63ff355f1600404596`, tree `7761d9e273ae7007046ae115797f255e554523ae`, file `test/native/fuzztest/dbpreferencesbasevalue_fuzzer/dbpreferencesbasevalue_fuzzer.cpp`, blob `37345f46187665a0a0de293ba31a446acb1616d3`, SHA-256 `2351f76128395a0da41b96719836465505060cf46949ac89677deae5dc316651`.

The production `ohscanner.cpp.shared_ptr_race` CLI v0.5.1 ran on a one-file scope (197 LOC), parsed it completely, and emitted 25 `ohcpp-shared-ptr-race-candidate-001` syntax candidates. Every A0 line (43, 48, 50, 65, 66, 74, 75, 83, 91, 92, 100, 108, 109, 117, 125, 126, 134, 142, 143, 151, 159, 160, 168, 176, 177) maps one-to-one to a candidate on `preferences_`.

The exact `BUILD.gn` blob is `73d07d85f4e438fcc125f2661b645d11cfc6a2d1` (SHA-256 `82db6683a383051fd7c6c61e2be5db028254162d3e140d678545227e448a3435`). It declares `ohos_fuzztest("DBPreferencesBaseValueFuzzTest")`; the `fuzztest` group is `testonly = true`. Its `LLVMFuzzerTestOneInput` invokes setup, sequential fuzz wrappers, and teardown; this shows harness calls into Preferences APIs, not a production entry path or concurrent overlap.

All 25 rows remain `not_testable / paused_pending_evidence` and `PARTIAL`. Test-only harness classification does not establish product-image exclusion, a vulnerability, or a false positive. Product manifest/build inclusion, production call reachability, a same-object unordered concurrent access and its synchronization protocol, thread lifecycle, attacker control, and CIA impact are not established. No detector, tests, fixtures, or A0 labels were changed.

## Reproduction and verification

From the scanner repository root, replay with the command recorded in the JSON artifact using the pinned source checkout. Then run:

```powershell
python research/evidence/cpp/t36_preferences_basevalue_audit.py
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp
git diff --check
```

Machine artifacts: [T36 JSON audit](t36_preferences_basevalue_audit_20261024.json), [raw CLI JSON](t36_preferences_basevalue_cli_20261024.json), and [verifier](t36_preferences_basevalue_audit.py).
