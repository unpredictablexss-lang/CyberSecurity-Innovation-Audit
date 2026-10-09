# Reproduction record: teammate A historical corpus and static baseline

Date: 2026-10-09 (Asia/Shanghai)

Scope: reproducible metadata/evidence reconstruction for four existing
historical samples and the `lifetime_uaf` / `oob_write` priority families. This
record does not implement OHScanner and does not rerun any historical scanner.

## Environment

Commands were executed from the repository root
`C:\Users\work_work\.codex\worktrees\4b98\CyberSecurity-Innovation-Audit`
through WSL Ubuntu 22.04:

```text
Python 3.10.12
git version 2.34.1
```

The Windows host printed a localized WSL localhost-proxy warning on stderr for
each `wsl.exe` launch. It is outside the Python command logs; every command
below exited 0 and its captured Python output is the authoritative result.

## Evidence identity and output policy

`build_evidence_package.py` emits two deterministic files under the ignored
`outputs/reports/static_baselines/` directory. The checked-in source material is
the corpus metadata, generator, validator and regression tests. Generated JSON,
logs and experiment outputs are not committed.

Every generated evidence unit binds:

- `sample_id`, `revision`, `control_role` and `analysis_unit_id`;
- repository, full 40-character commit and scope;
- source artifact path/URL/retrieval, source SHA-256, Git blob SHA-1, Git tree
  SHA-1, byte and line counts;
- tool name/version/configuration identity and `run_id`;
- PR #5 `ScanRequest`/`SourceUnit`/`ScanContext` identity projection and a
  complete-record `binding_sha256`.

Both sidecars include a top-level `interface_baseline` binding to PR #5
`feat/ohscanner-core` head
`108494bfe392ae62394ea82cd44d28cc03ebb163` and contract SHA-256
`b1a9658d700b73604ca358e80a65e04df4dd1bb8c5edbb85307f1038af865aeb`.
The validator checks both package objects and reads the pinned contract file
from the repository root. Wrong interface heads and contract hashes are
rejected by regression tests; changing the expected baseline is not treated as
a silent schema upgrade.

`SourceUnit.text` is intentionally omitted because third-party target source is
not committed. The `scan_context_identity` projection is not a new manifest
schema. Real Git requests bind `target_id="current-component:<repository>"`,
`profile_id="light-ast"` and `provenance="git_object"`.

## Key input hashes

| SHA-256 | Input |
|---|---|
| `7fa22aebec893345204d1324d1fffe7585dcdc7ad534281e10feb24dbfa82224` | `research/corpus/native/lifetime_uaf.json` |
| `bc40abde8655bbd2acba841bca77c0b6c984f984215c17348a07defcd484a410` | `research/corpus/native/oob_write.json` |
| `3aaffd7f99742a707d17b87e417d7b2d425dc0dd1880092a74dba5e3bc1a6934` | `benchmarks/historical/c_utils_singleton_uaf.json` |
| `b61714186ccc9a0d5f14f1a08f2b214b077ccb480cbec5b4ed87eb577b7c4edd` | `benchmarks/historical/kernel_liteos_a_getgroups_oob.json` |
| `2e1d411e2869738d5d4605b0a42de1b93b22e66e1f74f9609659bc4f80f5fea9` | `benchmarks/historical/communication_dsoftbus_null_deref.json` |
| `f9b3f331a3592c57f851142f762ca13a98d731b80964a1043cb467f44e24f329` | `benchmarks/historical/arkcompiler_ets_runtime_jsarray_sort_oob.json` |
| `3d4dc2864cca097e4934547bd37166332b1283ceb719d1d4d30222ddca182346` | `research/experiments/cpp/build_evidence_package.py` |
| `fdaa5f4f4dc6689389aaedfa8c5d55e61ffb30dc669fac93447089224af27c09` | `research/experiments/cpp/validate_evidence_package.py` |
| `e168464dafe640fca18b74f7a5fc679f15c57e773558f9547a98962cb6b3b6e7` | `tests/test_teammate_a_evidence_package.py` |

Project input manifest SHA-256:
`492b0bee5929aeb76e39fac665e5413b39473681ed65ff9345ebb915ced4d55e`.
It is the SHA-256 of `outputs/logs/teammate_a_input_manifest_2026-10-09.txt`,
which contains sorted `sha256sum` records for all files under `src`, `tests`,
`benchmarks/historical`, `research/corpus/native`,
`research/experiments/cpp`, `rules` and `scripts`, excluding `__pycache__`,
`README.md` and `reproduction_2026-10-09.md`. The exact composition command
was:

```bash
find src tests benchmarks/historical research/corpus/native \
  research/experiments/cpp rules scripts -type f \
  ! -path '*__pycache__*' ! -name 'README.md' \
  ! -name 'reproduction_2026-10-09.md' -print0 |
  sort -z | xargs -0 sha256sum \
  > outputs/logs/teammate_a_input_manifest_2026-10-09.txt
```

## Exact execution record

### 1. Generate deterministic sidecars

```bash
python3 research/experiments/cpp/build_evidence_package.py --write \
  > outputs/logs/teammate_a_build_write_2026-10-09.txt 2>&1
```

Input binding: project input manifest
`492b0bee5929aeb76e39fac665e5413b39473681ed65ff9345ebb915ced4d55e`.

Result:

```text
[OK] wrote outputs/reports/static_baselines/evidence_units.json and outputs/reports/static_baselines/baseline_status.json
```

### 2. Check deterministic reconstruction

```bash
python3 research/experiments/cpp/build_evidence_package.py \
  > outputs/logs/teammate_a_build_check_2026-10-09.txt 2>&1
```

Input binding: the same project input manifest and the two generated sidecars.

Result:

```text
[OK] deterministic evidence sidecars match
```

### 3. Validate evidence bindings and status boundaries

```bash
python3 research/experiments/cpp/validate_evidence_package.py \
  > outputs/logs/teammate_a_validate_2026-10-09.txt 2>&1
```

Input binding: project input manifest plus the generated sidecar hashes below.

Result:

```text
[OK] evidence package valid: {"baseline_cell_count": 64, "counts": {"miss": 29, "not_applicable": 10, "possible_hit": 5, "unknown": 20}, "safe_control_cell_count": 16, "unit_count": 80}
```

### 4. Run the full test suite

The required full discovery command was used, not a reduced test list:

```bash
python3 -m unittest discover -s tests -v \
  > outputs/logs/teammate_a_unittest_2026-10-09.txt 2>&1
```

Input binding: project input manifest.

Real result:

```text
Ran 205 tests in 15.210s

OK
```

The log covers evidence identity/mixing, wrong commit and scope, source
tree/blob/file hash mismatches, SourceUnit path/hash and ordering, failed or
partial analysis not being `miss`, `not_run`/`unknown`/`not_applicable`
boundaries, exact parsing coverage buckets, safe/baseline isolation, duplicate
run IDs, report integration and the report-loader `target_id` contract gap.

## Output hashes

| SHA-256 | Output |
|---|---|
| `d277bff261493d558caa705f27c1a51d9f0f1ebc1dc7e6e074a626a38b1aac84` | `outputs/reports/static_baselines/evidence_units.json` |
| `f461c102fefd946a2f82f68df30a9bad74a4a72c308615e8f4ba2590473cd188` | `outputs/reports/static_baselines/baseline_status.json` |
| `85a457be9a3e76b09f108145f2673da2bfbe293fd545df2b7ad82a7838a05b84` | `outputs/logs/teammate_a_build_write_2026-10-09.txt` |
| `bd97088daac09c3b107514c0dbe5cdc942f23f619212825960ee9ddf86a89168` | `outputs/logs/teammate_a_build_check_2026-10-09.txt` |
| `50161d589407baaa7c9b58f85d4086e76776618b62a673d17876f6f334ae80bf` | `outputs/logs/teammate_a_validate_2026-10-09.txt` |
| `0ba0507c5b133bf2ff6b542d4e3eb751f2c9852d631798402f7607c03e2fc87a` | `outputs/logs/teammate_a_unittest_2026-10-09.txt` |
| `492b0bee5929aeb76e39fac665e5413b39473681ed65ff9345ebb915ced4d55e` | `outputs/logs/teammate_a_input_manifest_2026-10-09.txt` |
| `2c225ca09b89d87bfa4f3bb042cc12ab3ab7c37a7eb9bb5be97ecacaa481d82d` | `outputs/logs/teammate_a_key_input_hashes_2026-10-09.txt` |

## Baseline state reconstruction

Across all 80 evidence units, execution states are
`completed=50`, `failed=6`, `blocked=8`, `not_run=16`. Parsing states are
`complete=34`, `complete_unresolved_symbol=2`,
`not_applicable_no_source_files=2`,
`not_applicable_no_translation_unit=8`, `not_run=16`,
`partial_cast_problem=2`, `partial_macro_context=8`,
`partial_missing_includes=6`, `partial_parser_problems=2`. Exact parsing file
coverage is `files_complete=34`, `files_partial=20`, `files_failed=0`,
`files_not_applicable=10` and `files_not_run=16`. The five buckets are mutually
exclusive and sum to 80 scoped files; `not_applicable_*` is not a parsing
failure.

The 64 vulnerable/fixed baseline cells project to
`possible_hit=5`, `miss=29`, `unknown=20`, `not_applicable=10`. The 16 safe
control cells are isolated `not_run` execution / `unknown` result cells. These
are analysis cells, not vulnerabilities, TP/FP/FN or accuracy metrics.

## Limitations and exclusions

- No historical scanner was rerun. This round reconstructs checked-in baseline
  metadata and validates its evidence identity.
- Raw native/normalized scanner artifacts were not retained with hashes by the
  earlier summary. Those per-unit hashes remain `unknown` and are not
  synthesized. The exact CodeQL suite hash and exact Tree-sitter version are
  also not retained.
- Affected-file snapshots do not provide complete product builds, macros,
  template instantiation, dependency context or runtime behavior.
- `miss` only denotes completed/complete analysis with no match in the pinned
  unit. It is not a false negative or proof of safety. Missing or failed
  analysis is `unknown`; an unexecuted scanner is `not_run`, never `miss`.
- `not_applicable` is used only where the recorded analysis unit is explicitly
  incompatible, such as no translation unit or no source files. No diagnostic
  alone establishes safety.
- Vulnerable/fixed/safe units, commits, scopes and runs are isolated. Safe
  controls are `not_run` and do not enter vulnerable/fixed baseline counts.
- The report loader currently requires `target_id == sample_id`, conflicting
  with PR `current-component:<repository>`. This remains a contract-change
  proposal; `src/` and report modules were not changed.
- No independent holdout has run. The four samples and two safe controls are
  design/evaluation inputs. No Precision/Recall, zero-false-positive or
  zero-false-negative result is computed or claimed.
- License/provenance: repository metadata is Apache-2.0; target source bytes are
  not committed. The existing MIT Semgrep vendor mirror retains its upstream
  provenance and license. No third-party code or rule text was copied by this
  change.
