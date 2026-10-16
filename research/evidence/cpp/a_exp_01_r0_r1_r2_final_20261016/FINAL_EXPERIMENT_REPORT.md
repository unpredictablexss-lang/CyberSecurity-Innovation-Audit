# A-EXP-01 R0/R1/R2 final experiment report

Generated: 2026-10-16T13:43:48.179093+00:00

## Executive conclusion

- The 45 review items, 135 planned runs per group, `fact_bundle_sha256`, six EvidenceObligations, seeds and repetition plan are fixed and identical across the main groups.
- 135 blinded R0 records were produced and locked at SHA-256 `2f2075ebc310d1c145f8a0ecc0465da0eca286be1a137956ee88b8ed9d4a443b` before R1/R2 result inspection.
- Those R0 records are explicitly `agent_not_human`; the independent human R0 arm remains 0/135. Therefore a three-arm human/model effect comparison and human-cost comparison are ineligible.
- Precision, Recall, TP/FP/FN/TN are not computed. There is no independent reliable labelled accuracy dataset and R0 complete human predictions are absent.
- R2 added real tool-derived evidence, but also used substantially more provider/tool budget. Method and budget effects cannot be separated.

## Fixed binding

- Review units: 45 review items / 45 scope occurrences / 44 unique candidates.
- Fact bundle: `c72147a4056a5c07cd4e60858b22970c784760fe53ab4c3c1f45d9751c5feb01`
- EvidenceObligation contract: `72f9a41d5392b8c6753cd8be4e95334fe3ba6a2b6a5e69adfa3df1cfaceadd1f`
- Seeds: `20261015`, `20261016`, `20261017`; repetitions: 1, 2, 3.
- Obligations: fixed target identity; realistic entry/privilege boundary; reachable sensitive operation; trigger conditions; concrete CIA impact; auditable evidence.
- Current checkout HEAD at experiment start: `8e97f152ef747c1e1d21ae179a048910f147e07a`.

## Completion, failure and cost

| Arm | Planned | Present | Completed | Failed | Missing/unexecuted | Completion | Failure | Provider attempts | Tool calls | Total tokens | Reference cost upper bound | Human active / paused |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| R0 independent human | 135 | 0 | 0 | n/a | 135 | 0.00% | n/a | 0 | 0 | 0 | n/a | unknown / unknown |
| R0 blinded agent supplement | 135 | 135 | 135 | 0 | 0 | 100.00% | 0.00% | 0 | 0 | 0 | n/a | unknown / unknown |
| R1 | 135 | 135 | 128 | 7 | 0 | 94.81% | 5.19% | 135 | 0 | 784,569 | $0.441711 | unknown / unknown |
| R2 | 135 | 135 | 123 | 12 | 0 | 91.11% | 8.89% | 270 | 540 | 1,881,807 | $0.974438 | unknown / unknown |

Human cost is unknown for every arm. Model wall time is machine runtime, not human active time. No timing was synthesized.

## Citation quality and independent facts

| Arm | Claims | Nonempty refs | Empty/missing-ref claims | Runs without claims | Illegal refs | Invalid-ref/record runs | Unique cited IDs | Tool-result new-fact claims | Tool-result evidence ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| R0 agent supplement | 405 | 405 | 0 | 0 | 0 | 0 | 90 | 0 | 0.00% |
| R1 | 996 | 996 | 0 | 7 | 0 | 1 | 51 | 0 (0.00%) | 0.00% |
| R2 | 1115 | 1115 | 0 | 7 | 3 | 5 | 548 | 557 (49.96%) | 84.49% |

R1 added no tool-result facts. R2 cited persisted tool-result IDs for 557/1,115 claims and 463/548 unique cited evidence IDs. These are independently tool-added facts under the frozen reference contract, not truth labels.

## R2 extra budget

| Extra quantity, R2 minus R1 | Total over 135 runs | Mean per run |
|---|---:|---:|
| Provider attempts | 135 | 1.00 |
| Tool calls | 540 | 4.00 |
| Input tokens | 969,817 | 7183.83 |
| Output tokens | 127,421 | 943.86 |
| Total tokens | 1,097,238 | 8127.69 |
| Reference cost upper bound | $0.532727 | $0.003946 |
| Mean wall time | 14.482 s | 14.482 s |
| Additional run failures | 5 | n/a |

R2 planned maxima were 1,080 tool calls, 1,080,000 input tokens, 216,000 output tokens and $101.25 reference cost; actual use was 540 tool calls, 1,523,527 input tokens, 358,280 output tokens and $0.974438. The planned maxima were not a prediction of actual usage. Four main-R2 tool calls failed; 20 non-ok tool calls across main and ablation runs are all retained in `all_failures.jsonl`.

## Repetition variance

| Arm / variant | Rep 1 completed / failed / hashes | Rep 2 completed / failed / hashes | Rep 3 completed / failed / hashes | Stability | Wall variance ms^2 |
|---|---|---|---|---|---:|
| R0 agent supplement | 45 / 0 / 45 | 45 / 0 / 45 | 45 / 0 / 45 | 45/45 assessment-stable, non-independent reviewer | unknown |
| R1 | 43 / 2 / 44 | 42 / 3 / 42 | 43 / 2 / 43 | 44/45 labels stable; 0/45 output hashes stable | 23989255.080 |
| R2 | 39 / 6 / 41 | 44 / 1 / 45 | 40 / 5 / 42 | 45/45 labels stable; 1/45 output hashes stable | 74781380.495 |

R1 per-repetition reference costs were $0.147294, $0.146927 and $0.147490. R2 costs were $0.326097, $0.327603 and $0.320738. R1 completed 43/42/43; R2 completed 39/44/40. R0 human repetition variance is unknown.

## Three ablations

| Ablation | Completed | Failed | Failure rate | Tool calls | Total tokens | Reference cost | New-fact claims | Invalid record runs | Rep completed R1/R2/R3 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| ABL-NO-AST | 130 | 5 | 3.70% | 410 | 1,719,931 | $0.898970 | 711/1226 (57.99%) | 1 | 45/43/42 |
| ABL-NO-HISTORY-PATCH | 113 | 22 | 16.30% | 405 | 1,831,461 | $0.952482 | 616/1197 (51.46%) | 17 | 37/38/38 |
| ABL-ONE-TURN | 135 | 0 | 0.00% | 0 | 939,318 | $0.536596 | 0/1302 (0.00%) | 0 | 45/45/45 |

Interpretation is descriptive only: removing AST reduced tool-derived new-fact share and produced 5 failures; removing historical patch access produced 22 failures and 17 invalid reference records; forcing one turn completed 135/135 but produced no tool-derived new facts. No ablation has independent truth, so none establishes accuracy improvement.

## Metrics eligibility

TP/FP/FN/TN, Precision and Recall: **ineligible / not computed**.

- Independent reliable truth: absent/ineligible.
- Complete predictions for the intended three arms: absent because R0 independent human runs are missing.
- Model agreement, historical review labels and synthetic controls are not used as truth.
- No zero FP/FN claim is made.

## Failures

`all_failures.jsonl` contains 66 failure records: 46 failed runs plus every non-ok tool call. Main R1 failures were 6 schema-invalid outputs and 1 missing-reference run. Main R2 failures were 7 agent failures and 5 missing/illegal-reference runs. Ablation failures are fully enumerated in the JSONL.

## Validation

- `PYTHONPATH=. .venv-web/bin/python -m unittest discover -s tests -q`: exit 0; 684 tests run, 676 passed, 8 skipped, 0 failed in 128.660s.
- `python scripts/check_docs_context_budget.py`: `python` is not on the Windows PowerShell PATH; the equivalent frozen interpreter `.venv-web/bin/python` exited 0 with `default=10835/13500, docs=17173/32500`.
- `git diff --check`: exact command exited 0. CRLF normalization warnings were retained in the raw validation log; `git diff --check -- docs/项目现状与下一步.md` also exited 0.

## Limitations and threats

- R0 independent human arm was not executed. The 135 locked R0 records are non-human Codex-agent blinded assessments and cannot substitute for human outcomes or human cost.
- All three R0 agent repetitions use one agent and therefore do not provide independent human repetition variance.
- The 45 review items represent 45 scope occurrences but only 44 unique candidates; one candidate appears in two scopes and creates clustering.
- Public or historical vulnerability material may be present in model training data; no contamination-clean unseen set was supplied.
- Frozen/synthetic truth, historical review labels, and model agreement are not eligible ground truth.
- R2 receives extra provider turns, tool calls, tokens and wall time. Its comparison with R1 is budget-confounded.
- Provider cost is a USD pay-as-you-go list-price upper bound. Actual Token Plan credit consumption and billing currency are unknown.
- All missing, failed, invalid, partial and unknown outcomes remain in planned denominators; no best-run selection was used.

## Reproducibility

- R0 record lock: `research/experiments/cpp/r0_r1_r2_20261015/run_20261016_r0_agent_blind_nonhuman/R0_AGENT_REVIEW_LOCK.json`.
- R1/R2 raw runs and tool results: `research/experiments/cpp/r0_r1_r2_20261015/run_20261016_unblock_attempt/`.
- Compact R1/R2 evidence: `research/evidence/cpp/a_exp_01_r1_r2_20261016/`.
- This report's machine-readable summary and hashes: `final_experiment_report.json`, `artifact_manifest.json`.
