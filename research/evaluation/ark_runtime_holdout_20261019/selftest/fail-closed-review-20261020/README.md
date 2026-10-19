# Fail-closed governance self-test

This suite exercises synthetic negative and positive cases for the holdout pipeline. A passing run shows only that the pipeline rejects the tested malformed inputs and can traverse its synthetic flow. It is not a PC-2 review, does not use real holdout samples, and does not establish detector accuracy or produce real metrics.

## Required state invariants

- Real intake is refused unless every case has a `product_build_preprocess.status` of `COMPLETE` and all required product, build, compile, include, compiler/linker/sysroot, preprocessed translation unit, and macro evidence fields. Current D2 evidence reports no complete product profiles, so real intake remains blocked.
- Unknown labels are retained as `unknown`; missing chain links, hash mismatches, label drift, extra or missing cases, and malformed artifacts must stop scoring or return `NOT_RUN`.
- Synthetic fixtures must carry `pipeline_self_test_not_reliable`. `self-test` reports `metrics_computed: false`; `score` refuses that truth status. No test-only identity, signature, or label can establish reliable truth.
- Artifact hashes establish byte consistency only. Current reviewer/adjudicator identity and signature fields are structural claims; the pipeline does not validate PKI signatures, trusted reviewer enrollment, organizational role authority, custody, or source claims against an independent Git object database. Those require external identity, key, custody, and source provenance audits before any PC-2 result can be trusted.

## Run

```powershell
$python = 'D:\openHarmonyScanner\records\parallel-20261020\envs\t2\Scripts\python.exe'
& $python -m unittest discover -s research/evaluation/ark_runtime_holdout_20261019/selftest/fail-closed-review-20261020 -p 'test_*.py' -v
& $python research/evaluation/ark_runtime_holdout_20261019/holdout_pipeline.py self-test --work-dir research/evaluation/ark_runtime_holdout_20261019/selftest/fail-closed-review-20261020/generated
```
