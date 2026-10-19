# C13 parallel integration delivery

Date: 2026-10-19 Asia/Shanghai

## Integrated branches

Base: `842948084660207fd64399cfd598ed93e5593dcc`

- `codex/c13-ark-real-replay-20261019` -> cherry-picked `d18fec679cbf4c551284cae295072a156d1617e4`
- `codex/c13-cross-file-facts-20261019` -> cherry-picked `929f50ce649e9c2cef1cf81b061a4709db00a9df`, `03c47241434f331968e1da26bcef9bef2ea5277f`
- `codex/c13-holdout-product-gate-20261019` -> cherry-picked `ca1310b75a7236f762631465922c7d08e499c173`
- Integration fixes: `40e84b67f8358bb2c4d1542aa952beedff6f13a5` preserves Catalog detector version; `24038152b90746d07ec8a3b64711f33bf0ecf9cb` makes holdout contract bytes deterministic.

Integration branch: `codex/c13-parallel-integration-20261019` @ `24038152b90746d07ec8a3b64711f33bf0ecf9cb`.

## Exact validation

```text
python -m unittest -q tests.detectors.ark_runtime.test_catalog tests.detectors.ark_runtime.test_c11_alias_cross_helper tests.detectors.ark_runtime.test_c12_deep_semantics tests.detectors.ark_runtime.test_c13_cross_file_facts tests.detectors.ark_runtime.test_c13_real_replay
Ran 34 tests in 0.778s
OK (skipped=2)
```

```text
python -m unittest -q tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus
Ran 29 tests in 1.683s
OK
```

```text
python -m unittest -q research.evaluation.ark_runtime_holdout_20261019.test_holdout_pipeline
Ran 7 tests in 0.961s
OK
```

`python -m compileall -q src tests` and `git diff --check` passed. The broader `unittest discover -s tests` was not counted: it remained active and changed fixture Git state, so it was stopped and its state preserved on `codex/c13-test-runtime-state-20261019` / `unrelated`; it is not a valid clean integration run.

## Scanner behavior

- Known disclosed CVE and 28-row disposition corpus: 29/29.
- Cross-file loop multiplication parent now emits a source-bound `candidate`; fixed 64-bit control emits no same-root candidate.
- Explicit `RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread)` suppresses the fixed-side callback-exception candidate while the parent remains a candidate.
- Catalog detector version remains `0.6.2`; algorithm model contracts are versioned separately.
- Holdout protocol/development ledger hashes are byte-stable across Windows/WSL and their 7-test contract passes.

## Evidence limits

- All matches remain `candidate/unassessed`.
- IBS5YG real objects are bound but production parent/fixed runs remain `blocked/partial`, `0->0`; the other eight real Ark cases still lack complete objects/profile closure.
- Real holdout is `FROZEN_NOT_EXECUTED`; no independent human truth or adjudication exists.
- Product gate is `BLOCKED / NOT_ADMITTED`; product build/source identity, entry, permission, trigger, attacker control, CIA, isolated PoC and fix replay remain unknown/not-run.
- No reliable Precision/Recall, FP/FN, product safety or reportable vulnerability claim is made.
