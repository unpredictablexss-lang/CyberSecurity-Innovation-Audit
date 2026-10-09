# Method card: oob_write

Status: research design for a future C/C++ detector. No OHScanner detector or
public contract implementation is included here.

## Target mechanism

Unchecked indexed element access can read or write out of bounds when the
accessed backing store changes or shrinks during a callback. The pinned
historical patch wraps direct `ElementAccessor::Get/Set` calls in
`SortElementsByObject` with stable-array and index-less-than-length guards and
uses a generic indexed fallback otherwise.

A future candidate detector may identify indexed element access whose bounds or
container stability obligation is not locally established. A subscript,
pointer arithmetic expression, file overlap or tool warning alone is not proof
of an out-of-bounds write.

## Evidence unit

| Role | sample_id | Exact commit | Scope |
|---|---|---|---|
| vulnerable | `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `ecmascript/js_array.cpp`, `SortElementsByObject` |
| fixed | `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | `1b23531531e768398682582969c2a9f17e72cafe` | same analysis unit |
| safe | `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | `1b23531531e768398682582969c2a9f17e72cafe` | separate `CheckStableArrayAndGet` / `AndSet` |

The full source/tree/blob/file hashes and line scopes are in
`research/corpus/native/oob_write.json` and the reproducible generated
`outputs/reports/static_baselines/evidence_units.json`.

## Evidence identity

The generated evidence unit binds repository, full commit, revision, sample ID,
analysis-unit scope, source artifact and source/tree/blob hashes to one
tool/version/configuration and `run_id`. Its `scan_context_identity` follows
PR #5 `ScanRequest`/`SourceUnit`/`ScanContext` field names and omits third-party
source text. Vulnerable, fixed and safe controls remain separate units and
never share evidence or counts. This historical metadata package records prior
baseline states only; no scanner was rerun in this round.

## Proposed analysis obligations

1. Bind repository, exact commit, source file hash, scope and tool run.
2. Identify index origin, accessed object/capacity and the nearest explicit
   bounds/stability guard.
3. Treat missing macro/build context, partial parsing or unresolved symbols as
   `unknown`.
4. Emit only `candidate`/`possible_hit` until evidence review and runtime
   validation establish impact.
5. Keep vulnerable, fixed and safe units separate.

Potential future features are direct element accessor use, index origin,
length/capacity comparison, backing-store stability checks and callback
re-entrancy points. Guard dominance must be checked; textual guard proximity is
not enough.

## Existing baseline observation

For the pinned pair across eight tools: `possible_hit=2`, `miss=10`,
`unknown=2`, `not_applicable=2`. Cppcheck produced one candidate in both the
vulnerable and fixed units, so it did not discriminate this patch. CodeQL was
unknown with missing includes; Clang SA was not applicable without a
translation unit/build context. Other completed tools reported no match in
these snapshots. These are cell states, not vulnerability or accuracy metrics.

## Limitations

- No comparator re-entrancy trigger, backing-store mutation reproduction,
  runtime validation or exploitability result.
- Full ArkCompiler build, macro and dependency context is missing.
- The safe guard helpers are shape-based; dominance, call-site coverage and
  universal safety are not proven.
- The Cppcheck overlap is not a fixed-pair miss and is not confirmation of an
  out-of-bounds write.
- The sample informed family selection and therefore belongs to the design set,
  not an independent holdout.

## Holdout and acceptance

A future holdout must use an unseen bounds root-cause instance, preferably from
another repository, with fixed vulnerable/fixed hashes and unrelated safe
controls. The detector and method card must be frozen before the owner reveals
the holdout. Report raw cell states and coverage; do not compute Precision/Recall
or claim zero false positives/negatives from this small corpus.