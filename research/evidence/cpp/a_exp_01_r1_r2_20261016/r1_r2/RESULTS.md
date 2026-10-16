# A-EXP-01 R0/R1/R2 result report

Status: R1/R2 main runs collected; R0 awaits independent blinded human review. This report does not compute Precision/Recall.

- Fixed units: 45 review items / 45 scope occurrences / 44 unique candidates.
- Common fact bundle: `c72147a4056a5c07cd4e60858b22970c784760fe53ab4c3c1f45d9751c5feb01`.
- Common EvidenceObligation contract: `72f9a41d5392b8c6753cd8be4e95334fe3ba6a2b6a5e69adfa3df1cfaceadd1f`.

| Group | Planned | Present | Completed | Failed | Missing | Model attempts | Tool calls | Reference cost upper bound |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| R0 | 135 | 0 | 0 | 0 | 135 | 0 | 0 | n/a |
| R1 | 135 | 135 | 128 | 7 | 0 | 135 | 0 | $0.441711 |
| R2 | 135 | 135 | 123 | 12 | 0 | 270 | 540 | $0.974438 |

## Repetitions and variance

- R1 per repetition: [{"repetition":1,"planned":45,"present":45,"missing":0,"completed":43,"failed":2,"distinct_output_hashes":44,"cost_reference_usd_upper_bound":0.14729361},{"repetition":2,"planned":45,"present":45,"missing":0,"completed":42,"failed":3,"distinct_output_hashes":42,"cost_reference_usd_upper_bound":0.14692733999999996},{"repetition":3,"planned":45,"present":45,"missing":0,"completed":43,"failed":2,"distinct_output_hashes":43,"cost_reference_usd_upper_bound":0.14749023000000003}].
- R2 per repetition: [{"repetition":1,"planned":45,"present":45,"missing":0,"completed":39,"failed":6,"distinct_output_hashes":41,"cost_reference_usd_upper_bound":0.32609688000000003},{"repetition":2,"planned":45,"present":45,"missing":0,"completed":44,"failed":1,"distinct_output_hashes":45,"cost_reference_usd_upper_bound":0.32760285000000006},{"repetition":3,"planned":45,"present":45,"missing":0,"completed":40,"failed":5,"distinct_output_hashes":42,"cost_reference_usd_upper_bound":0.32073811499999993}].
- R1 stable mechanism labels across three present runs: 44/45.
- R2 stable mechanism labels across three present runs: 45/45.
- Wall-time variance: R1 23989255.079506166, R2 74781380.49492453 ms^2.

## References and independent facts

- R1 references: {"claims":996,"claims_with_nonempty_refs":996,"missing_or_empty_reference_claims":0,"runs_without_any_claims":7,"illegal_reference_count":0,"invalid_reference_runs":1,"total_missing_or_illegal_reference_errors":7}.
- R2 references: {"claims":1115,"claims_with_nonempty_refs":1115,"missing_or_empty_reference_claims":0,"runs_without_any_claims":7,"illegal_reference_count":3,"invalid_reference_runs":5,"total_missing_or_illegal_reference_errors":10}.
- R1 independent tool-added facts: {"definition":"A claim is independently tool-added when it cites at least one persisted R2 tool-result evidence ID not present in the initial evidence catalog.","new_fact_claims":0,"all_claims":996,"new_fact_claim_ratio":0,"unique_cited_evidence_ids":51,"unique_cited_tool_result_evidence_ids":0,"tool_result_evidence_ratio":0}.
- R2 independent tool-added facts: {"definition":"A claim is independently tool-added when it cites at least one persisted R2 tool-result evidence ID not present in the initial evidence catalog.","new_fact_claims":557,"all_claims":1115,"new_fact_claim_ratio":0.49955156950672647,"unique_cited_evidence_ids":548,"unique_cited_tool_result_evidence_ids":463,"tool_result_evidence_ratio":0.8448905109489051}.

## Failures

- R1 failure codes: {"ILLEGAL_OR_MISSING_EVIDENCE_REFERENCE":1,"none":128,"MODEL_OUTPUT_SCHEMA_INVALID":6}.
- R2 failure codes: {"none":123,"R2_AGENT_FAILED":7,"ILLEGAL_OR_MISSING_EVIDENCE_REFERENCE":5}.
- Exact raw-response recovery evidence is in `failure_recovery.json`.

## Ablations

- ABL-NO-AST: 135/135 present, 130 completed, 5 failed, 410 tool calls, 0.898970 reference cost upper bound (complete).
- ABL-NO-HISTORY-PATCH: 135/135 present, 113 completed, 22 failed, 405 tool calls, 0.952482 reference cost upper bound (complete).
- ABL-ONE-TURN: 135/135 present, 135 completed, 0 failed, 0 tool calls, 0.536596 reference cost upper bound (complete).

## Boundaries

R0 human review time is not measured. Model outputs are not truth. Actual Token Plan billing is unknown; reported USD is the official pay-as-you-go cache-miss upper bound. Precision/Recall is not computed because the frozen set is not an independent labelled accuracy dataset.
