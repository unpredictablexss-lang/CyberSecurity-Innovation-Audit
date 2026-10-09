# Architecture and rule review (2026-10-08)

The L0-L8 funnel and the multi-tool normalization strategy are appropriate for
this project. Keep them: syntax-level candidate discovery is cheap, precise
program analysis is selective, and validated/reportable conclusions require
stronger evidence than static pattern matches. The present branch implements a
historical static benchmark, not the complete target architecture.

## Constraints retained

- Providers normalize; benchmark modules bind and compare evidence; report
  modules render; the CLI orchestrates. Tool choice does not imply a verdict.
- Preserve sample/repository/commit/revision/tool/scope and artifact provenance.
- Separate completed/no overlap, not run/failed, and evidenced incompatibility.
- Keep static coverage, reachability, security impact and runtime validation
  distinct. No warning-count voting or automatic vulnerability promotion.
- Generated artifacts remain local; historical fixed snapshots are regression
  controls, not proof of safety across the repository.

## Rule limitations requiring correction

`oh_shared_ptr_uaf.yaml` currently matches `$PTR.reset()` without establishing
the receiver type, shared ownership, concurrent access or synchronization. It is
a broad reset candidate rule inspired by one historical fix. The vulnerable/fixed
pair distinguishes that edit, but does not establish general UAF detection.

`oh_nothrow_null_deref.yaml` excludes a visible `if` mentioning the allocated
pointer. That condition need not be a null check or terminate the failure path;
the query does not establish dominance, reassignment or aliasing. Joern likewise
searches the method for comparisons, including comparisons after the dereference
and substring matches on different identifiers. Both are structural heuristics.
The Joern script should label its evidence syntax, not control_flow, until it
actually analyzes control-flow paths.

Retain these rules as audit candidates, record their limits, and require a
dedicated rule-change task with safe/unsafe controls before broadening claims.
Do not infer Precision/Recall or zero false positives/negatives from four seeds.
The registry coverage statements in rules/README are dated experiment notes,
not permanent assumptions about the current external registry.

## Next implementation

Repair the evidence-to-summary boundary first: reports must consume saved runs,
isolate sample and vulnerable/fixed revision, preserve failed/not_applicable
reasons and source hashes, and default missing evidence to unknown. Do not add
PoC, new detection families or a new architecture during this repair.
