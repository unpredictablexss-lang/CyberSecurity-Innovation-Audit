# Reproduction record: teammate A historical corpus and static baseline

Date: 2026-10-09 (Asia/Shanghai)

Scope: reproducible metadata/evidence reconstruction for four existing
historical samples and the `lifetime_uaf` / `oob_write` priority families. This
record does not implement OHScanner and does not rerun any historical scanner.

## Environment

Commands were executed from the repository root
`C:\Users\work_work\.codex\worktrees\0afd\CyberSecurity-Innovation-Audit`
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
- tool name/version/configuration identity, explicit `config_sha256_status` and `run_id`;
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

Configuration hashes are marked `verified_sha256` only when an exact
lowercase SHA-256 is retained. CodeQL uses `config_sha256=null` with
`not_retained_in_checked_in_replay_summary`; this is missing evidence, not a
synthesized configuration identity.

`SourceUnit.text` is intentionally omitted because third-party target source is
not committed. The `scan_context_identity` projection is not a new manifest
schema. Real Git requests bind `target_id="current-component:<repository>"`,
`profile_id="light-ast"` and `provenance="git_object"`.

## Key input hashes

| SHA-256 | Input |
|---|---|
| `bc09d8ead34e196552ade4e9f9b6236ab704ec9f9e60db108bf4ae13a0dc5218` | `research/corpus/native/lifetime_uaf.json` |
| `d13675bac558070d8c7bec0cbfc2de9e73974f50384cd8fd96a8d677c64500c5` | `research/corpus/native/oob_write.json` |
| `3aaffd7f99742a707d17b87e417d7b2d425dc0dd1880092a74dba5e3bc1a6934` | `benchmarks/historical/c_utils_singleton_uaf.json` |
| `b61714186ccc9a0d5f14f1a08f2b214b077ccb480cbec5b4ed87eb577b7c4edd` | `benchmarks/historical/kernel_liteos_a_getgroups_oob.json` |
| `2e1d411e2869738d5d4605b0a42de1b93b22e66e1f74f9609659bc4f80f5fea9` | `benchmarks/historical/communication_dsoftbus_null_deref.json` |
| `f9b3f331a3592c57f851142f762ca13a98d731b80964a1043cb467f44e24f329` | `benchmarks/historical/arkcompiler_ets_runtime_jsarray_sort_oob.json` |
| `3bc50b05db36a19324a14a47af3a73d1f8e2d92eeafe5d51bfa18d68ec7abb54` | `research/experiments/cpp/build_evidence_package.py` |
| `2c901eacec8528a861106454c4c8f9cd7bc7ea93da2a146b453025b4f504c07a` | `research/experiments/cpp/validate_evidence_package.py` |
| `ae4301e3df92b13dd28eb85a091bcd068a89fb21a9cfc7b44b1bffb3e1b42232` | `tests/test_teammate_a_evidence_package.py` |

Project input manifest SHA-256:
`f8cd7634cb6505f7a0e1391ef4168e1d8fc95b9d0c05fe53c832d978e18c07d3`.
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
`f8cd7634cb6505f7a0e1391ef4168e1d8fc95b9d0c05fe53c832d978e18c07d3`.

Result:

```text
[OK] wrote outputs/reports/static_baselines/evidence_units.json and outputs/reports/static_baselines/baseline_status.json
```

### 2. Check deterministic reconstruction

```bash
python3 research/experiments/cpp/build_evidence_package.py --check \
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
Ran 208 tests in 15.679s

OK
```

The log covers evidence identity/mixing, wrong commit and scope, source
tree/blob/file hash mismatches, SourceUnit path/hash and ordering, failed or
partial analysis not being `miss`, `not_run`/`unknown`/`not_applicable`
boundaries, strict parsing status/detail mapping and file buckets,
artifact hash/path state contradictions, fabricated missing hashes and unsafe
`logical_path` values, safe/baseline isolation, duplicate
run IDs, report integration and the report-loader `target_id` contract gap.

## Output hashes

| SHA-256 | Output |
|---|---|
| `ede8e0e0f3292a7062305cd90fffd90a430e463aa2b5ada31d09df3510c66c7a` | `outputs/reports/static_baselines/evidence_units.json` |
| `646bc6fca553b196d5deba2dd6607065477c232bd425a5b7bcfc8142ff068606` | `outputs/reports/static_baselines/baseline_status.json` |
| `85a457be9a3e76b09f108145f2673da2bfbe293fd545df2b7ad82a7838a05b84` | `outputs/logs/teammate_a_build_write_2026-10-09.txt` |
| `bd97088daac09c3b107514c0dbe5cdc942f23f619212825960ee9ddf86a89168` | `outputs/logs/teammate_a_build_check_2026-10-09.txt` |
| `50161d589407baaa7c9b58f85d4086e76776618b62a673d17876f6f334ae80bf` | `outputs/logs/teammate_a_validate_2026-10-09.txt` |
| `e0702fa69ca6b473e78db0ea0c47c57aa0f86ef1ee743fb208e076bdefc9b93d` | `outputs/logs/teammate_a_unittest_2026-10-09.txt` |
| `f8cd7634cb6505f7a0e1391ef4168e1d8fc95b9d0c05fe53c832d978e18c07d3` | `outputs/logs/teammate_a_input_manifest_2026-10-09.txt` |
| `9d8937b2d68ba5ec485b8655fb073317c7d1d211e9a5b6e9d7eab8bd91262e2e` | `outputs/logs/teammate_a_key_input_hashes_2026-10-09.txt` |

## Baseline state reconstruction

Across all 80 evidence units, execution states are
`completed=50`, `failed=6`, `blocked=8`, `not_run=16`. Strict parsing states are
`complete=34`, `partial=20`, `failed=0`, `not_run=26`. The preserved parsing
`status_detail` counts are `complete=34`,
`complete_unresolved_symbol=2`, `partial_cast_problem=2`,
`partial_macro_context=8`, `partial_missing_includes=6`,
`partial_parser_problems=2`, `not_applicable_no_source_files=2`,
`not_applicable_no_translation_unit=8` and `not_run=16`. Exact parsing file
coverage uses only `files_complete=34`, `files_partial=20`, `files_failed=0`
and `files_not_run=26`. These four buckets are mutually exclusive and sum to 80
scoped files; `not_applicable_*` maps to strict `not_run` without claiming
applicability or safety.

The 64 vulnerable/fixed baseline cells project to
`possible_hit=5`, `miss=29`, `unknown=20`, `not_applicable=10`. The 16 safe
control cells are isolated `not_run` execution / `unknown` result cells. Across
all 80 units, results are `possible_hit=5`, `miss=29`, `unknown=36`,
`not_applicable=10`. Artifact references are explicitly stateful: for each of
the raw and normalized references, 64 executed cells retain a logical path but
have no fabricated hash, and 16 `not_run` cells retain neither path nor hash.
Tool configuration states are 70 `verified_sha256` and 10
`not_retained_in_checked_in_replay_summary`. These are analysis cells, not
vulnerability counts, TP, FP, FN or accuracy metrics.

## Limitations and exclusions

- No historical scanner was rerun. This round reconstructs checked-in baseline
  metadata and validates its evidence identity.
- Raw native/normalized scanner artifacts were not retained with hashes by the
  earlier summary. Those per-unit hashes remain `unknown` and are not
  synthesized. The exact CodeQL suite hash and exact Tree-sitter version are
  also not retained; the corresponding tool configuration state is explicitly
  `not_retained_in_checked_in_replay_summary`, never `verified_sha256`.
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
