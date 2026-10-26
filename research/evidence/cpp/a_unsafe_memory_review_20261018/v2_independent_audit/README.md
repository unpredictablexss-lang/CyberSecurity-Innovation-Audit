# A-UNSAFE sampling manifest v2 independent audit

## Result

**Audit checks: PASS. Population assessment: PARTIAL.**

An independent scan of the pinned `candidate_results.csv`, joined row by row
to the `result.json` files referenced by those rows, found 9,323 observations:

| Check | Independent result |
| --- | ---: |
| `ohcpp-format-string-candidate-002` rows | 8,661 |
| `ohcpp-unsafe-memory-call-candidate-001` rows | 662 |
| Total raw rows | 9,323 |
| Unique diagnostic IDs | 9,323 |
| Duplicate diagnostic ID rows | 0 |
| Rows matched to source-bound result diagnostics | 9,323 / 9,323 |
| Exact-source cross-repository clusters | 0 clusters, 0 rows |
| Within-repository root-cause clusters | Not established |
| Human review | 0 reviewed, 160 pending |

The v2 JSON Schema validates. Each CSV row's `diagnostic_id`, `rule_id`,
repository, and exact `source_sha256` field matches the uniquely referenced
`result.json` diagnostic. This audits the scan artifacts' identity metadata;
it does not reopen and rehash every source file in the 9,323-row frame. Its
four `report_count_dimensions` agree with the independent calculation: raw row count is counted; within-repository
root-cause clustering remains explicitly not established; cross-repository
clusters use `rule_id + exact source_sha256 + at least two repositories` and
count to zero; human review remains pending at 0/160.

The requested population is 8,994 while the observed candidate frame is 9,323,
a difference of 329. The manifest correctly marks this mismatch and the frame
as provisional. The audit does not infer root causes from matching paths,
lines, or message text, and candidate observations are not vulnerability
ground truth.

The exact v2 manifest audited here is preserved as `sampling_manifest_v2.json`
(SHA-256 `6ca2098c7051c08dd3ce4c97cfd8ec98b8850c33463dac63194e03b7e9874132`).
The captured machine result is `audit_output_20261019.json` (SHA-256
`7d398f14380820cc2cb108032dd7e29225da43d0df0f83f3a38535cadc942c99`).
The raw scan CSV and result files remain in the pinned local scan artifact and
can be supplied with `--candidate-root` when they are stored elsewhere.

## Reproduce

Run from the repository root:

```powershell
python research/evidence/cpp/a_unsafe_memory_review_20261018/v2_independent_audit/audit_sampling_manifest_v2.py
```

The script prints a JSON report to stdout and does not write files. Optional
arguments `--candidate-root`, `--manifest`, and `--schema` can point to another
frozen input set. It does not import or invoke the sampling builder. It reads
the candidate CSV, only the result JSON files referenced by target rows, the
sampling manifest's count fields, and the v2 schema. It does not read any blind
review queue or coordinator key file.

The audit requires Python and the `jsonschema` package for schema validation.
