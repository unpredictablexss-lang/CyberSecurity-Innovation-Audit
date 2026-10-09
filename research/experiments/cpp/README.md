# Teammate A C/C++ historical baseline evidence

Status: deterministic metadata reconstruction of the existing historical
static baseline. This is not a complete OHScanner implementation and does not
make vulnerability verdicts.

## Checked-in and generated files

Checked in:

- `build_evidence_package.py`: deterministic generator/checker.
- `validate_evidence_package.py`: evidence binding and status validator.
- `reproduction_2026-10-09.md`: exact environment, commands, hashes and
  limitations.

Generated and intentionally ignored by Git:

- `outputs/reports/static_baselines/evidence_units.json`: 80 isolated units:
  64 baseline cells (4 samples x 2 revisions x 8 tools) plus 16
  safe-control/not-run cells.
- `outputs/reports/static_baselines/baseline_status.json`: the 64 baseline
  cells as a compact projection.

The checked-in corpus metadata and generator are the reproducible source
material. `evidence_units.json` is the generated source of truth for validation
and reporting runs. Validation checks exact commit/scope/source/tool/run
bindings, PR #5 request/source identity, status semantics, unique IDs and
projection consistency. No generated JSON is committed.

Each unit binds repository, full commit, revision, sample ID, analysis-unit
scope, source artifact, source/tree/blob/file hashes, tool/version/configuration
and run ID. `scan_context_identity` uses PR #5 `ScanRequest`/`SourceUnit`/
`ScanContext` names, not a new manifest schema. `SourceUnit.text` is
deliberately absent because third-party source bytes are not committed.

## Status semantics

| Dimension | Values used here | Meaning |
|---|---|---|
| execution | `completed`, `failed`, `blocked`, `not_run` | Whether a tool process completed |
| parsing coverage | `complete`, `partial_*`, `complete_unresolved_symbol`, `failed`, `not_applicable_*`, `not_run` | Whether the pinned analysis unit was fully parsed/extracted |
| result | `possible_hit`, `miss`, `unknown`, `not_applicable` | Historical benchmark cell interpretation |

`possible_hit` is only candidate/rule/region overlap. `miss` requires completed
execution and adequate parsing with no match. Failed, partial or missing
analysis is `unknown`; an unexecuted scanner is `not_run` and never a miss.
`not_applicable` requires a recorded incompatible-analysis-unit reason.

File coverage uses five explicit, mutually exclusive counters:
`files_complete`, `files_partial`, `files_failed`, `files_not_applicable` and
`files_not_run`. They must sum to `scope_files` and exactly match the parsing
status. In particular, `not_applicable_*` increments only
`files_not_applicable`, while an unexecuted safe control increments only
`files_not_run`; neither is a parsing failure.

No cell is a confirmed vulnerability and no Precision/Recall is computed.
The current report loader requires `target_id == sample_id`, while PR #5 binds
`target_id="current-component:<repository>"`. This is a documented contract-change
proposal; research report integration tests use direct `SampleToolRun` bindings and
assert the loader incompatibility rather than modifying `src/`.

## Tool capability matrix

| Tool | Version/configuration | Execution and parsing coverage | Baseline result cells |
|---|---|---|---|
| own_text | `text-v1`, `own-text-dangerous-api-v1` | 8 completed / complete | 8 miss |
| own_ast | exact Tree-sitter version not retained | 6 completed/complete; 2 failed/partial | 6 miss, 2 unknown |
| Semgrep vendor | Semgrep CE 1.179.0; MIT raptor mirror `dae50da6` | 6 completed/complete; 2 failed/partial | 6 miss, 2 unknown |
| Semgrep OH | Semgrep CE 1.179.0; two project-authored research rules | 6 completed/complete; 2 failed/partial | 2 possible_hit, 4 miss, 2 unknown |
| Cppcheck | 2.7 | 4 complete; 2 unresolved symbol; 2 pinned-AST partial | 2 possible_hit, 2 miss, 4 unknown |
| Clang SA | Clang 14.0.0 | 8 blocked before translation-unit formation | 8 not_applicable |
| CodeQL | 2.27.1 with cpp-queries 1.9.0 | 2 header-only extraction failures; 6 partial missing includes | 6 unknown, 2 not_applicable |
| Joern | 4.0.649 with project structural query | 4 complete; 4 parser/CAST partial or failed | 1 possible_hit, 3 miss, 4 unknown |

Aggregate 64-cell projection:
`possible_hit=5`, `miss=29`, `unknown=20`, `not_applicable=10`. These are
execution/analysis cells, not vulnerabilities, false positives or false
negatives.

## Reproduce

Run from the repository root in WSL Ubuntu 22.04 with Python 3.10.12:

```bash
python3 research/experiments/cpp/build_evidence_package.py --write
python3 research/experiments/cpp/build_evidence_package.py
python3 research/experiments/cpp/validate_evidence_package.py
python3 -m unittest discover -s tests -v
```

With `--write`, the generator writes both ignored sidecars. Without `--write`,
it checks that those generated files match deterministic reconstruction. See
`reproduction_2026-10-09.md` for exact commands, input/output hashes and the
actual full-suite test result. No historical scanner is rerun by these
commands.

## Boundaries and limitations

- Historical affected-file snapshots only; no full product build or runtime
  validation.
- Existing raw tool outputs are not committed. Their hashes were not retained
  in the checked-in historical summary, so those artifact hash fields remain
  explicitly unknown rather than fabricated.
- Source/config identities, run IDs and stable logical output references are
  bound per cell. A future rerun must retain native and normalized output
  hashes.
- This round does not modify `src/`, public schemas, CLI, providers, public IR
  or report modules. Missing public fields are recorded in
  `research/corpus/native/contract_change_proposal.md`.

- Top-level `interface_baseline` metadata pins PR #5 `feat/ohscanner-core`
  head `108494bfe392ae62394ea82cd44d28cc03ebb163` and the SHA-256 of
  `src/ohscanner/contracts.py`; validator tests reject an incorrect head or
  contract hash.
