# Contract change proposal: evidence identity and coverage sidecar

Status: proposal only. No public schema, `src/`, CLI, provider, IR or report
module is changed by teammate A in this round.

## Problem

Current historical evidence needs to distinguish source identity, analysis
scope, execution state, parsing coverage and benchmark interpretation without
treating a warning as a vulnerability or a failed run as a miss. The existing
`ToolRunResult` v1 is a report bridge, but it does not expose all of these
fields in one stable public structure.

## Proposed additions

1. `control_role`: `vulnerable`, `fixed` or `safe`. This prevents safe controls
   from being substituted for a fixed-pair result.
2. `analysis_unit_id` and `scope_kind`, with scoped `files`, `symbols` and
   `line_ranges`. This prevents different symbols/files in the same file and
   commit from sharing evidence.
3. `source_artifact`: repository path, canonical exact-commit URL, retrieval
   method, `source_file_sha256`, `git_blob_sha1`, byte count and line count.
4. Separate `execution_status`, `parsing_coverage.status` and benchmark
   `result_status`; benchmark status remains evaluator-owned.
5. Tool identity including name, version and configuration/query/artifact
   hashes.
6. Stable `run_id`, logical normalized/native artifact references and artifact
   SHA-256 with an explicit `sha256_status` when unavailable.
7. `provenance`, source license, attribution, originality review and
   `third_party_source_committed`.
8. Stable `binding_sha256` over the identity fields, plus validator rejection
   of mixed revisions/roles, wrong commits/scopes and invalid miss semantics.

## PR #5 identity projection used by this research package

This package projects the `ScanRequest` / `SourceUnit` / `ScanContext` field
names from PR #5 head `108494bfe392ae62394ea82cd44d28cc03ebb163`; it does not
introduce another manifest schema. Every evidence unit binds:

- `ScanRequest`: `request_id`, `repository`, full 40-character `commit`,
  `snapshot_sha256`, `target_id`, `profile_id`, `provenance`.
- `SourceUnit`: `path`, `language`, `sha256`, `parse_status`, `parse_issues`.
- `ScanContext.shared_facts`: `sample_id`, `revision`, `control_role`,
  `analysis_unit_id`, `scope` and `source_artifact`.

For real Git inputs, `target_id="current-component:" + repository`,
`profile_id="light-ast"` and `provenance="git_object"`. The source artifact
also binds full `git_commit`, `git_tree_sha1`, `git_blob_sha1` and
`source_file_sha256`. `SourceUnit.text` is intentionally omitted because
third-party source bytes are not committed; the source hash binds those bytes.
M1 `ohscan-index` may later produce a real fixed-Git source/AST index, but this
historical package does not claim that a detector ran.

## Known report bridge gap

`src/benchmark/report_inputs.py` currently requires normalized
`target_id == sample_id`, while the PR #5 target identity is
`current-component:<repository>`. Teammate A does not change that public report
module. The regression test records the incompatibility explicitly and
constructs `SampleToolRun` directly from the evidence request/run bindings for
research reporting.

A contract v2 proposal should preserve both identities, for example by carrying
`sample_id` as benchmark-local correlation data while `target_id` remains the
component identity. Owner integration must add migration behavior and tests
before any public bridge is considered runnable or frozen.

## Compatibility approach

Add these fields to a versioned research evidence sidecar first. A core-owned
bridge can map unchanged `ToolRunResult` v1 fields and carry the sidecar by
reference. Do not reinterpret existing values: `completed` is not safe,
`possible_hit` is not confirmed, and query-style CodeQL output is not labeled
dataflow. Preserve original build/macro/parse scope.

A public contract change should be reviewed as contract v2 with migration notes
and owner-written integration tests. Teammate A does not implement or freeze
that public contract.

## Acceptance tests for the proposal

- Vulnerable/fixed evidence cannot share one unit or run ID.
- Safe controls cannot enter the fixed pair or baseline counts.
- Wrong commit, repository, PR #5 request identity, source/tree/blob/file hash,
  analysis-unit scope or tool configuration invalidates the binding.
- Failed, blocked, partial, missing and unexecuted states cannot map to `miss`.
- `not_applicable` is distinct from `unknown` and requires an explicit reason.
- Report rendering preserves revision, scope and status boundaries and leaves
  `validated_vulnerability=0`.
- Missing raw artifact hashes remain unknown and are never synthesized.## Interface baseline binding

The generated `evidence_units.json` and `baseline_status.json` packages carry a
top-level `interface_baseline` object bound to PR #5
`feat/ohscanner-core` at
`108494bfe392ae62394ea82cd44d28cc03ebb163`. The binding also pins
`src/ohscanner/contracts.py` at SHA-256
`b1a9658d700b73604ca358e80a65e04df4dd1bb8c5edbb85307f1038af865aeb`.
Validation rejects a missing/mismatched baseline object or a changed local
contract file. This is metadata provenance for the proposed research sidecar;
it does not freeze the detector contract or make the proposal an implemented
public API.
